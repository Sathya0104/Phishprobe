#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    Indicator (IOC) extraction.  Pulls URLs, domains, IP addresses, email
    addresses and attachment hashes out of the parsed message.  Local URL
    inspection flags shorteners, raw-IP links, '@' redirect tricks and
    mismatched anchor text without claiming they are malicious on their own.
    The extracted indicators are later sent to VirusTotal for reputation
    lookups and shown in the report's "Indicators" section.

Dependencies:
    Python standard library only: re, urllib.parse.  Imports ``core`` for
    extract_urls() and the shortener domain list.

Related Files:
    core.py          (extract_urls, SHORTENER_DOMAINS)
    parser.py        (produces the text corpus this module scans)
    orchestrator.py  (calls extract_indicators() on the parsed message)
    virustotal.py    (receives the extracted indicators for lookup)
    report.py        (renders the indicators + sender-IP analysis)
"""

import re
import urllib.parse

from . import core

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

IMAGE_EXTS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico"}


def valid_ipv4(ip):
    try:
        return all(0 <= int(o) <= 255 for o in ip.split("."))
    except ValueError:
        return False


def netloc_of(url):
    if "://" not in url:
        url = "http://" + url
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except ValueError:
        return ""


def clean_url(url):
    return url.rstrip(".,;:!?)")


def _url_key(url):
    """Normalised identity of a URL for de-duplication.

    Treats a missing scheme, a leading 'www.' and trailing slashes as the
    same resource, so 'https://www.conduent.com/', 'www.conduent.com' and
    'www.conduent.com/' collapse to one indicator (and one lookup).
    """
    key = clean_url(url).lower().lstrip()
    key = re.sub(r"^https?://", "", key)
    return key.rstrip("/")


def extract_urls(text):
    """Return de-duplicated, cleaned URLs from a text corpus."""
    seen, out = set(), []
    plain, anchors = core.extract_urls(text)
    urls = list(plain) + [href for href, _ in anchors]
    for u in urls:
        u = clean_url(u)
        key = _url_key(u)
        if key and key not in seen:
            seen.add(key)
            out.append(u)
    return out


def extract_anchor_pairs(text):
    return core.extract_urls(text)[1]


def extract_domains(text):
    # Join Quoted-Printable soft line breaks ('=' + newline) so wrapped URLs
    # yield their real domain instead of a fragment or nothing.
    text = re.sub(r"=\r\n", "", text)
    text = re.sub(r"=\n", "", text)
    domains = set()
    for m in EMAIL_RE.findall(text):
        domains.add(m.split("@")[1].lower())
    for url in re.findall(r"https?://[^\s<>\"')\]]+", text):
        dom = netloc_of(url).split(":")[0]
        if dom:
            domains.add(dom)
    for url in re.findall(r"\bwww\.[^\s<>\"')\]]+", text, re.IGNORECASE):
        dom = netloc_of(url).split(":")[0]
        if dom:
            domains.add(dom)
    return sorted(
        d for d in domains
        if "." in d and "=" not in d and not re.match(r"^\d+(\.\d+){2,}$", d))


def extract_ips(header_text, body_text):
    ips = []
    for ip in core.extract_ip_addresses(header_text):
        if ip not in ips:
            ips.append(ip)
    for ip in IPV4_RE.findall(body_text):
        if valid_ipv4(ip) and ip not in ips:
            ips.append(ip)
    return ips


def extract_sender_ip(header_text):
    """
    Return ONLY the sender's IP address (the origin of the message), never the
    full list of relay hops from the Received chain.

    Order of preference:
      1. Received-SPF 'client-ip=...'   (the IP SPF evaluated - most accurate)
      2. X-Originating-IP
      3. the 'from ...' IP of the LAST (originating) Received header

    Returns [] (a list) when no valid sender IP can be determined, so callers
    can treat it exactly like the old all-IP list.
    """
    def _ok(ip):
        return ip if valid_ipv4(ip) else None

    header = core.normalize_header(header_text)

    m = re.search(r"^Received-SPF:\s*(.+)$", header,
                  re.MULTILINE | re.IGNORECASE)
    if m:
        c = re.search(r"client-ip=([0-9.]+)", m.group(1), re.IGNORECASE)
        if c and _ok(c.group(1)):
            return [c.group(1)]

    m = re.search(r"^X-Originating-IP:\s*([^\s,;]+)", header,
                  re.MULTILINE | re.IGNORECASE)
    if m and _ok(m.group(1)):
        return [m.group(1)]

    received = core.extract_received_lines(header)
    if received:
        # Received headers are newest-first; the LAST one is the first hop,
        # i.e. the originating sender.
        for ip in IPV4_RE.findall(received[-1]):
            if _ok(ip):
                return [ip]
    return []


def extract_emails(text):
    out = set()
    for m in EMAIL_RE.findall(text):
        m = m.lower()
        if m.rsplit(".", 1)[-1] in IMAGE_EXTS:
            continue
        out.add(m)
    return sorted(out)


def inspect_urls_locally(text):
    """
    Local (non-reputation) URL inspection.  Returns a list of
    {severity, message} findings.  Severity stays low/medium so these never
    force a Suspicious verdict by themselves.
    """
    findings = []
    plain, anchors = core.extract_urls(text)
    all_urls = list(plain) + [href for href, _ in anchors]

    for url in set(all_urls):
        domain = netloc_of(url)
        if any(domain == s or domain.endswith("." + s)
               for s in core.SHORTENER_DOMAINS):
            findings.append({
                "severity": "low",
                "message": f"Shortened URL detected (hides the real destination): {url}",
            })
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            findings.append({
                "severity": "medium",
                "message": f"URL uses a raw IP address instead of a domain: {url}",
            })
        if "@" in url.split("//", 1)[-1].split("/")[0]:
            findings.append({
                "severity": "medium",
                "message": f"URL contains '@' (possible redirect trick): {url}",
            })

    for href, text in anchors:
        text_clean = re.sub(r"<[^>]+>", "", text).strip()
        text_url_match = re.search(
            r"(?:https?://|www\.)[^\s<>\"')\]]+", text_clean, re.IGNORECASE)
        if text_url_match:
            displayed = netloc_of(text_url_match.group(0))
            actual = netloc_of(href)
            if displayed and actual and displayed != actual:
                findings.append({
                    "severity": "medium",
                    "message": (f"Link text shows '{displayed}' but the link actually "
                                f"points to '{actual}'"),
                })

    return findings
