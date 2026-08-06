#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    Authentication engine: SPF / DKIM / DMARC / ARC verdicts extracted from the
    Authentication-Results / ARC-Seal headers a receiving mail server stamped
    on the message.

    Rules
    -----
    * Only an EXPLICIT result token counts.  `pass` stays pass, explicit
      `fail|softfail|hardfail` is a failure, `neutral|none|permerror|temperror|
      policy|bestguesspass` is reported as "Not verified" (not a failure) and a
      completely missing result is "Not found" (also not a failure).
    * Multiple Authentication-Results blocks are all parsed.  A protocol is
      reported Pass if ANY of its explicit results is pass, Fail if any is an
      explicit failure, otherwise Not verified / Not found.  This prevents a
      stale or unrelated result from downgrading a legitimately passing check.
    * ARC results are shown in the report for transparency.

Dependencies:
    Python standard library only: re.  Imports ``core`` for the header
    normalizer and the known-header-name table.

Related Files:
    core.py          (normalize_header, KNOWN_HEADER_NAMES)
    orchestrator.py  (calls check_authentication() during a full run)
    report.py        (renders the SPF / DKIM / DMARC / ARC verdict table)
"""

import re

from . import core

PROTOCOLS = ("spf", "dkim", "dmarc", "arc")

# Explicit result tokens, in the order of severity used for aggregation.
PASS_TOKENS = {"pass", "bestguesspass"}
FAIL_TOKENS = {"fail", "softfail", "hardfail"}
SOFT_TOKENS = {"neutral", "none", "permerror", "temperror", "policy"}

AUTH_TOKEN_RE = re.compile(
    r"\b(spf|dkim|dmarc|arc)\s*=\s*(pass|fail|softfail|neutral|none|hardfail|"
    r"permerror|temperror|policy|bestguesspass)\b", re.IGNORECASE)

RECEIVED_SPF_RE = re.compile(
    r"^Received-SPF:\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b",
    re.MULTILINE | re.IGNORECASE)

HEADER_PRESENT_RE = re.compile(
    r"^(Authentication-Results|Received-SPF|DKIM-Signature|ARC-Seal|"
    r"ARC-Message-Signature|ARC-Authentication-Results):",
    re.MULTILINE | re.IGNORECASE)


def extract_auth_blocks(header_text):
    """Return every Authentication-Results block, unfolded."""
    header = core.normalize_header(header_text)
    blocks = re.findall(
        r"^Authentication-Results:\s*(.+(?:\n[ \t]+.+)*)",
        header, re.MULTILINE | re.IGNORECASE)
    return [re.sub(r"\s+", " ", b).strip() for b in blocks]


def _aggregate(values):
    """Reduce a list of raw result tokens to a single status string."""
    if not values:
        return None
    low = [v.lower() for v in values]
    if any(v in PASS_TOKENS for v in low):
        return "pass"
    if any(v in FAIL_TOKENS for v in low):
        return "fail"
    return "not_verified"


def analyze_authentication(header_text):
    """
    Analyze all authentication evidence in a header.

    Returns:
      {
        "spf":   {"status": "Pass", "value": "pass"|"fail"|...|None, "sources": [...]},
        "dkim":  {...},
        "dmarc": {...},
        "arc":   {...},
        "has_authentication_results": bool,
        "present_headers": [names...],
        "raw_blocks": [block text...],
        "explicit_fail": bool,
        "any_pass": bool,
      }
    """
    header = core.normalize_header(header_text)

    blocks = extract_auth_blocks(header)
    raw_tokens = AUTH_TOKEN_RE.findall(header)
    by_proto = {p: [] for p in PROTOCOLS}
    sources = {p: [] for p in PROTOCOLS}
    for proto, value in raw_tokens:
        proto = proto.lower()
        by_proto[proto].append(value)
        sources[proto].append(value)

    # Standalone Received-SPF fallback when no spf= token exists.
    if not by_proto["spf"]:
        m = RECEIVED_SPF_RE.search(header)
        if m:
            by_proto["spf"].append(m.group(1).lower())

    # Presence of signing headers that carry no explicit verdict.
    present = [m.group(1) for m in HEADER_PRESENT_RE.finditer(header)]

    results = {}
    for proto in PROTOCOLS:
        aggregated = _aggregate(by_proto[proto])
        results[proto] = {
            "status": status_label(aggregated),
            "value": aggregated,
            "sources": sources[proto] or None,
        }

    explicit_fail = any(
        v in FAIL_TOKENS for v in by_proto["spf"] + by_proto["dkim"] + by_proto["dmarc"])
    any_pass = any(v in PASS_TOKENS for v in by_proto["spf"] + by_proto["dkim"] + by_proto["dmarc"])

    return {
        "spf": results["spf"],
        "dkim": results["dkim"],
        "dmarc": results["dmarc"],
        "arc": results["arc"],
        "has_authentication_results": bool(blocks) or bool(re.search(
            r"^Authentication-Results:", header, re.MULTILINE | re.IGNORECASE)),
        "present_headers": present,
        "raw_blocks": blocks,
        "explicit_fail": explicit_fail,
        "any_pass": any_pass,
    }


def status_label(value):
    """Map a raw token to a stable human label."""
    if value is None:
        return "Not found"
    if value in PASS_TOKENS:
        return "Pass"
    if value in FAIL_TOKENS:
        return "Fail"
    return "Not verified"


def status_chip(value):
    """Map a raw token to a UI chip class."""
    if value is None:
        return "unknown"
    if value in PASS_TOKENS:
        return "safe"
    if value in FAIL_TOKENS:
        return "malicious"
    return "moderate"
