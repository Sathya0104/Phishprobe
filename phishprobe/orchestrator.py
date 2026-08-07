#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    Orchestrator: wires parser -> authentication -> IOC extraction -> threat
    intelligence (VirusTotal) -> scoring into a single analysis run.

    `analyze(raw_email, with_lookup=True)` returns the full report dict
    consumed by the web UI; `analyze_header_only(raw_header)` is the lightweight
    path behind the "/" header analyzer.  Network lookups run concurrently in a
    thread pool (bounded by a rate pacer) so a full scan stays fast while
    respecting VirusTotal's request budget.

Dependencies:
    Python standard library only: re, threading, time, concurrent.futures.
    Imports ``core`` plus every pipeline module in this package.

Related Files:
    core.py          (normalize_header, basic info extraction)
    parser.py        (parse_raw_email, extract_basic_info)
    authentication.py, iocs.py, scoring.py, typosquat.py, virustotal.py
    report.py        (build_report / build_header_report)
    app.py           (the HTTP handlers that call analyze())
"""

import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from . import core

from . import authentication as authz
from . import config
from . import iocs as ioc
from . import parser
from . import scoring
from . import typosquat as tsq
from . import virustotal as ti

LOOKUP_ORDER = ("urls", "domains", "ips", "files")
# Seconds between request STARTS (a global pacer).  Lookups run concurrently so
# the network latency overlaps, but the request budget stays the same.
RATE_LIMIT_SLEEP = 0.5
LOOKUP_WORKERS = 5
REPUTATION_ACTIVE = config.is_vt_configured()

_PACE = threading.Lock()


def _mismatch_checks(basic, return_path, msgid_domain):
    """Severity-labelled From / Reply-To / Return-Path / Message-ID checks."""
    findings = []
    from_addr = core.extract_email_address(basic.get("From"))
    reply_addr = core.extract_email_address(basic.get("Reply-To"))
    from_domain = core.extract_domain(from_addr)
    reply_domain = core.extract_domain(reply_addr)
    return_path_domain = core.extract_domain(return_path)

    if reply_addr and from_addr and reply_domain != from_domain:
        findings.append({
            "severity": "medium",
            "message": (f"Reply-To domain ('{reply_domain}') does not match "
                        f"From domain ('{from_domain}')."),
        })
    if return_path and from_domain and return_path_domain != from_domain:
        findings.append({
            "severity": "medium",
            "message": (f"Return-Path domain ('{return_path_domain}') does not match "
                        f"From domain ('{from_domain}')."),
        })
    if msgid_domain and from_domain and msgid_domain != from_domain:
        findings.append({
            "severity": "low",
            "message": (f"Message-ID domain ('{msgid_domain}') differs from From domain "
                        f"('{from_domain}') - common with legitimate bulk senders, verify "
                        f"the sender is a known mail service."),
        })

    no_mismatches = bool(from_addr) and not any(f["severity"] == "medium" for f in findings)
    return findings, no_mismatches


def _build_lookup_item(kind, value):
    item = {
        "type": {"urls": "URL", "domains": "Domain", "ips": "IP", "files": "File"}[kind],
        "value": value,
        "engine": "VirusTotal",
        "verdict": "Unknown",
        "risk_score": 0,
        "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
        "detection_ratio": "0/0",
        "detection": "",
        "reputation": None, "community_score": None,
        "last_analysis": None,
        "vendor_detections": [],
        "categories": [],
        "whois": None, "asn": None, "country": None, "malware_family": None,
        "note": "",
    }
    if kind == "files":
        item["filename"] = value.get("filename", "")
        hashes = value.get("hashes", {})
        item["value"] = hashes.get("sha256", "")
        item["md5"], item["sha1"], item["sha256"] = (
            hashes.get("md5", ""), hashes.get("sha1", ""), hashes.get("sha256", ""))
        item["extension"] = value.get("extension", "")
    return item


def _threat_lookup(kind, value):
    """One VirusTotal lookup.

    A global lock paces request *starts* (RATE_LIMIT_SLEEP) so running many
    lookups concurrently does not raise the request rate - only the wall-clock
    time drops, because the network waits now overlap.
    """
    item = _build_lookup_item(kind, value)
    if not item["value"]:
        return item
    with _PACE:
        time.sleep(RATE_LIMIT_SLEEP)
    try:
        result, _was_hit = ti.lookup_cached(kind[:-1], item["value"])
        if result:
            item.update(result)
    except Exception as exc:
        item["note"] = f"Threat intelligence error: {exc}"
    return item


def _run_all_lookups(kinds_values):
    """Run (kind, value) lookups together in one thread pool, in input order."""
    if not kinds_values:
        return []
    with ThreadPoolExecutor(max_workers=LOOKUP_WORKERS) as pool:
        return list(pool.map(lambda kv: _threat_lookup(kv[0], kv[1]),
                             kinds_values))


def _host_of_url(url):
    """Extract a lowercase host from a URL (None if it cannot be parsed)."""
    try:
        return urllib.parse.urlparse(url).hostname.lower()
    except (ValueError, AttributeError):
        return None


def _propagate_url_verdicts(ti_results):
    """A domain whose URL was flagged must not be reported as clean.

    VirusTotal's URL scan and domain record are separate stores, so a URL can
    be flagged while its domain still shows 0 detections.  Clicking the domain
    is just as dangerous as clicking the URL, so inherit the URL verdict onto
    the domain record (the summary counts and tables then stay consistent).
    """
    flagged_by_host = {}
    for u in ti_results["urls"]:
        host = _host_of_url(u["value"])
        if host and u["verdict"] in ("Malicious", "Suspicious"):
            flagged_by_host.setdefault(host, []).append(u)
    if not flagged_by_host:
        return ti_results
    for d in ti_results["domains"]:
        hits = flagged_by_host.get((d["value"] or "").lower())
        if not hits or d["verdict"] in ("Malicious", "Suspicious"):
            continue
        top = max(hits, key=lambda u: u.get("risk_score") or 0)
        d["verdict"] = top["verdict"]
        d["risk_score"] = max(d.get("risk_score") or 0, top.get("risk_score") or 0)
        d["malicious"] = max(d.get("malicious", 0),
                             top.get("malicious", 0) or 1)
        d["note"] = ("Verdict inherited from URL {} - flagged by multiple "
                     "security engines.".format(top["value"]))
        d["sources"] = ["VirusTotal"]
    return ti_results


def _content_payload(content, mismatches, link_anomalies, no_mismatches,
                     typosquat_findings):
    """Common content section shared by the full and header-only analyzers."""
    return {
        "urgency_phrases": content.get("urgency_or_credential_phrases", []),
        "malware_keywords": content.get("malware_related_keywords", []),
        "generic_greeting": content.get("generic_greeting", False),
        "mismatches": mismatches,
        "link_anomalies": link_anomalies,
        "no_mismatches": no_mismatches,
        "typosquatting": typosquat_findings,
    }


def analyze(raw_email, with_lookup=True):
    parsed = parser.parse_raw_email(raw_email)
    header_text = parsed["header_text"]
    header_norm = core.normalize_header(header_text)
    plain_body = parsed["plain_body"]
    html_body = parsed["html_body"]
    attachments = parsed["attachments"]

    basic = parser.extract_basic_info(header_text)
    received = core.extract_received_lines(header_norm)
    auth = authz.analyze_authentication(header_norm)
    return_path = core.extract_return_path(header_norm)
    msgid_domain = core.extract_message_id_domain(header_norm)
    mismatches, no_mismatches = _mismatch_checks(basic, return_path, msgid_domain)

    content = core.check_content_red_flags(plain_body)
    link_anomalies = ioc.inspect_urls_locally(parsed["text_corpus"])

    emails = ioc.extract_emails(parsed["text_corpus"])
    urls = ioc.extract_urls(parsed["text_corpus"])
    domains = ioc.extract_domains(parsed["text_corpus"])
    # Only the SENDER's IP is checked - relay hops in the Received chain are
    # not looked up (per product decision).
    ips = ioc.extract_sender_ip(header_text)

    # Deterministic brand-typosquatting check over every domain seen.
    typosquat_findings = tsq.detect(domains)

    ti_results = {"urls": [], "domains": [], "ips": [], "files": []}
    if with_lookup:
        # Empty (0-byte) parts are not real attachments - skip their hash
        # lookups (they are meaningless and slow the analysis down).
        file_values = [{
            "filename": a["filename"],
            "extension": a.get("extension", ""),
            "hashes": {"md5": a["md5"], "sha1": a["sha1"], "sha256": a["sha256"]},
        } for a in attachments if (a.get("size") or 0) > 0]
        tasks = ([("urls", u) for u in urls]
                 + [("domains", d) for d in domains]
                 + [("ips", ip) for ip in ips]
                 + [("files", fv) for fv in file_values])
        results = _run_all_lookups(tasks)
        cursor = 0
        for kind, values in (("urls", urls), ("domains", domains),
                             ("ips", ips), ("files", file_values)):
            ti_results[kind] = results[cursor:cursor + len(values)]
            cursor += len(values)

    _propagate_url_verdicts(ti_results)

    payload = {
        "authentication": auth,
        "content": _content_payload(content, mismatches, link_anomalies,
                                    no_mismatches, typosquat_findings),
        "attachments": attachments,
        "threat_intel": ti_results,
        "reputation_active": REPUTATION_ACTIVE,
    }
    verdict_details = scoring.score_email(payload)

    from .report import build_report
    report = build_report(
        parsed=parsed,
        header_norm=header_norm,
        basic=basic,
        received=received,
        auth=auth,
        return_path=return_path,
        msgid_domain=msgid_domain,
        emails=emails,
        urls=urls,
        domains=domains,
        ips=ips,
        content=content,
        mismatches=mismatches,
        link_anomalies=link_anomalies,
        ti_results=ti_results,
        verdict_details=verdict_details,
        reputation_active=REPUTATION_ACTIVE,
        typosquatting=typosquat_findings,
    )
    return report


def analyze_header_only(header_text, url=None, with_lookup=True):
    """
    Analyze just the raw email header (the header-analyzer page).

    ``url`` is the optional URL the user typed in - it is folded into the text
    corpus so its host/domain is checked for reputation (the "pre-scan") and
    typosquatting, and its verdict counts like any other indicator.

    Returns a header-focused report (no body / attachment sections).
    """
    header_norm = core.normalize_header(header_text)
    basic = parser.extract_basic_info(header_text)
    received = core.extract_received_lines(header_norm)
    auth = authz.analyze_authentication(header_norm)
    return_path = core.extract_return_path(header_norm)
    msgid_domain = core.extract_message_id_domain(header_norm)
    mismatches, no_mismatches = _mismatch_checks(basic, return_path, msgid_domain)

    # Build the corpus: header + the optional URL the user supplied.
    corpus = header_text
    if url and url.strip():
        corpus += "\n" + url.strip()
    urls = ioc.extract_urls(corpus)
    domains = ioc.extract_domains(corpus)
    # Only the SENDER's IP is checked - the rest of the Received chain is not
    # looked up (per product decision).
    ips = ioc.extract_sender_ip(header_text)
    typosquat_findings = tsq.detect(domains)

    ti_results = {"urls": [], "domains": [], "ips": [], "files": []}
    if with_lookup:
        tasks = ([("urls", u) for u in urls]
                 + [("domains", d) for d in domains]
                 + [("ips", ip) for ip in ips])
        results = _run_all_lookups(tasks)
        cursor = 0
        for kind, values in (("urls", urls), ("domains", domains),
                             ("ips", ips)):
            ti_results[kind] = results[cursor:cursor + len(values)]
            cursor += len(values)

    _propagate_url_verdicts(ti_results)

    payload = {
        "authentication": auth,
        "content": _content_payload({}, mismatches, [], no_mismatches,
                                    typosquat_findings),
        "attachments": [],
        "threat_intel": ti_results,
        "reputation_active": REPUTATION_ACTIVE,
    }
    verdict_details = scoring.score_email(payload)

    from .report import build_header_report
    report = build_header_report(
        header_norm=header_norm,
        basic=basic,
        received=received,
        auth=auth,
        return_path=return_path,
        msgid_domain=msgid_domain,
        urls=urls,
        domains=domains,
        ips=ips,
        mismatches=mismatches,
        typosquatting=typosquat_findings,
        ti_results=ti_results,
        verdict_details=verdict_details,
        reputation_active=REPUTATION_ACTIVE,
    )
    return report
