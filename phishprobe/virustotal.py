#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    VirusTotal v3 reputation client - the ONLY threat-intelligence source.

    Every indicator (URL, domain, IP, file hash) is checked against VirusTotal's
    multi-engine scan.  A free API key is required and is loaded by config.py
    from the environment (VT_API_KEY) or vt_config.json.  The key stays on the
    server and is never sent to the browser.

    Every lookup returns the same normalized record schema used across the
    orchestrator, scorer and UI:

      verdict / malicious / suspicious / harmless / undetected / total
      detection_ratio / detection / risk_score / reputation / community_score
      last_analysis / vendor_detections / categories / threat_labels
      malware_family / whois / asn / country / sources / note

    API notes
    ---------
    * Free tier is limited to 4 requests/minute.  A global pacing lock enforces
      a minimum interval between HTTP calls (set VT_RATE_LIMIT_SECONDS to tune
      it) and HTTP 429 responses are retried with a back-off.
    * URL lookups first try GET /urls/{id}; on a miss they POST the URL and poll
      the resulting analysis until it completes.
    * A clean scan reports "Safe" (a real detection count exists) - a far
      stronger clean signal than a blocklist absence.
    * Results are cached in cache.py so repeated lookups cost nothing.

Dependencies:
    Python standard library only: base64, datetime, json, os, threading, time,
    urllib.parse, urllib.request.  Uses ``cache`` (cached_lookup) and
    ``config`` (get_vt_api_key) from this package.

Related Files:
    config.py       (loads the API key)
    cache.py        (TTL caching of lookup results)
    orchestrator.py (calls lookup_indicator() for every extracted indicator)
    report.py       (renders the per-indicator reputation records)
"""

import base64
import datetime
import json
import os
import threading
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError

from .cache import cached_lookup
from .config import get_vt_api_key

SOURCE_NAME = "VirusTotal"
SOURCES = ["VirusTotal"]

_API = "https://www.virustotal.com/api/v3"

# Respect the free-tier quota (4 req/min) by default.
_MIN_INTERVAL = float(os.environ.get("VT_RATE_LIMIT_SECONDS") or "15.0")
_RETRY_AFTER = 60
_HTTP_TIMEOUT = 30

_pace_lock = threading.Lock()
_last_request_ts = [0.0]


def _pace():
    """Enforce a minimum interval between VirusTotal HTTP requests."""
    with _pace_lock:
        now = time.time()
        wait = _MIN_INTERVAL - (now - _last_request_ts[0])
        if wait > 0:
            time.sleep(wait)
        _last_request_ts[0] = time.time()


def _headers():
    key = get_vt_api_key()
    if not key:
        raise RuntimeError("VirusTotal API key not configured")
    return {"x-apikey": key, "Accept": "application/json"}


def _http_json(url, data=None, method="GET", tries=4):
    last = None
    for _ in range(tries):
        _pace()
        req = urllib.request.Request(url, data=data, headers=_headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            if e.code == 401:
                raise RuntimeError("Reputation service rejected the API key (HTTP 401)")
            if e.code == 403:
                raise RuntimeError("Reputation service denied access (HTTP 403) - check quota")
            if e.code == 429:
                last = "rate_limited"
                time.sleep(_RETRY_AFTER)
                continue
            raise RuntimeError(f"Reputation HTTP {e.code}")
        except (URLError, TimeoutError, OSError) as e:
            last = str(e)
            time.sleep(3)
    raise RuntimeError(f"Reputation request failed: {last or 'unknown error'}")


def _empty_record(value, kind):
    return {
        "verdict": "Unknown",
        "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
        "total": 0, "detection_ratio": "0/0", "detection": "",
        "risk_score": 0, "reputation": None, "community_score": None,
        "last_analysis": None, "vendor_detections": [], "categories": [],
        "threat_labels": [], "malware_family": None, "whois": None,
        "asn": None, "country": None, "sources": [], "note": "",
    }


def _from_stats(stats):
    m = int(stats.get("malicious", 0) or 0)
    s = int(stats.get("suspicious", 0) or 0)
    h = int(stats.get("harmless", 0) or 0)
    u = int(stats.get("undetected", 0) or 0)
    return m, s, h, u


def _finalize(rec, attributes):
    """Populate a record from a VirusTotal attributes object."""
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    m, s, h, u = _from_stats(stats)
    total = m + s + h + u

    rec["malicious"] = m
    rec["suspicious"] = s
    rec["harmless"] = h
    rec["undetected"] = u
    rec["total"] = total
    rec["detection_ratio"] = f"{m}/{total}" if total else "0/0"

    if total:
        rec["detection"] = (f"{m} malicious / {s} suspicious / {h} harmless / "
                            f"{u} undetected")
        rec["risk_score"] = min(100, m * 30 + s * 12)
        if m:
            rec["verdict"] = "Malicious"
        elif s:
            rec["verdict"] = "Suspicious"
        elif h:
            rec["verdict"] = "Safe"
        else:
            rec["verdict"] = "Unknown"
        rec["sources"] = [SOURCE_NAME]
        if m or s:
            rec["note"] = "Flagged by multiple security engines."
        elif h:
            rec["note"] = "No engines flagged this indicator as suspicious."
        else:
            rec["note"] = ("No security engine has actively evaluated this indicator "
                           "yet - treat it as unverified.")
    else:
        rec["verdict"] = "Unknown"
        rec["detection"] = "No reputation record available"
        rec["note"] = "No reputation record was found for this indicator."

    rec["reputation"] = attributes.get("reputation")
    rec["community_score"] = attributes.get("community_score")
    ts = attributes.get("last_analysis_date")
    if ts:
        try:
            rec["last_analysis"] = datetime.datetime.utcfromtimestamp(
                int(ts)).strftime("%Y-%m-%d")
        except (ValueError, OSError, OverflowError):
            rec["last_analysis"] = None

    results = attributes.get("last_analysis_results") or {}
    rec["vendor_detections"] = [
        {"engine": d.get("engine_name") or engine, "category": d.get("category", ""),
         "result": d.get("result", "")}
        for engine, d in results.items()
        if d.get("category") in ("malicious", "suspicious")
    ][:20]

    pc = attributes.get("popular_threat_category")
    if isinstance(pc, dict) and pc.get("value"):
        rec["threat_labels"] = [pc["value"]]
        rec["malware_family"] = pc["value"]
    rec["categories"] = list(attributes.get("tags") or [])

    rec["whois"] = attributes.get("whois")
    rec["asn"] = attributes.get("asn")
    rec["country"] = attributes.get("country")
    return rec


def _lookup_url(url):
    rec = _empty_record(url, "url")
    if not url:
        rec["note"] = "Empty URL - lookup skipped."
        return rec
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        r = _http_json(f"{_API}/urls/{url_id}")
        return _finalize(rec, (r.get("data") or {}).get("attributes") or {})
    except RuntimeError as e:
        if "HTTP 404" not in str(e):
            rec["note"] = f"Reputation URL lookup error: {e}"
            return rec
    data = urllib.parse.urlencode({"url": url}).encode()
    r = _http_json(f"{_API}/urls", data=data, method="POST")
    analysis_id = (r.get("data") or {}).get("id")
    if not analysis_id:
        rec["note"] = "Reputation service did not return an analysis id for the URL."
        return rec
    for _ in range(20):
        time.sleep(4)
        try:
            r2 = _http_json(f"{_API}/analyses/{analysis_id}")
            attrs = (r2.get("data") or {}).get("attributes") or {}
            if (attrs.get("status") or "").lower() == "completed":
                return _finalize(rec, attrs)
        except RuntimeError as e:
            rec["note"] = f"Reputation analysis poll error: {e}"
            return rec
    rec["note"] = "Reputation analysis did not complete in time."
    return rec


def _lookup_domain(domain):
    rec = _empty_record(domain, "domain")
    if not domain:
        rec["note"] = "Empty domain - lookup skipped."
        return rec
    try:
        r = _http_json(f"{_API}/domains/{urllib.parse.quote(domain, safe='')}")
    except RuntimeError as e:
        rec["note"] = f"Reputation domain lookup error: {e}"
        return rec
    if not r.get("data"):
        rec["note"] = "No reputation record found for this domain."
        return rec
    return _finalize(rec, (r.get("data") or {}).get("attributes") or {})


def _lookup_ip(ip):
    rec = _empty_record(ip, "ip")
    if not ip:
        rec["note"] = "Empty IP - lookup skipped."
        return rec
    try:
        r = _http_json(f"{_API}/ip_addresses/{urllib.parse.quote(ip, safe='')}")
    except RuntimeError as e:
        rec["note"] = f"Reputation IP lookup error: {e}"
        return rec
    if not r.get("data"):
        rec["note"] = "No reputation record found for this IP."
        return rec
    return _finalize(rec, (r.get("data") or {}).get("attributes") or {})


def _lookup_file(hash_value):
    rec = _empty_record(hash_value, "file")
    if not hash_value:
        rec["note"] = "Empty hash - lookup skipped."
        return rec
    try:
        r = _http_json(f"{_API}/files/{urllib.parse.quote(hash_value, safe='')}")
    except RuntimeError as e:
        rec["note"] = f"Reputation file lookup error: {e}"
        return rec
    if not r.get("data"):
        rec["note"] = "No VirusTotal record found for this file hash."
        return rec
    return _finalize(rec, (r.get("data") or {}).get("attributes") or {})


def lookup_cached(kind, value):
    """Cached lookup; returns (result, cache_hit)."""
    value = (value or "").strip().lower()
    return cached_lookup(kind, value, _uncached(kind, value))


def lookup(kind, value):
    """Uncached convenience dispatch (used by tests / CLI)."""
    value = (value or "").strip().lower()
    return cached_lookup(kind, value, _uncached(kind, value))[0]


def _uncached(kind, value):
    def fn():
        if kind == "url":
            return _lookup_url(value)
        if kind == "domain":
            return _lookup_domain(value)
        if kind == "ip":
            return _lookup_ip(value)
        if kind == "file":
            return _lookup_file(value)
        raise ValueError(f"Unknown indicator kind: {kind}")
    return fn
