#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    Report assembly.  Builds the JSON document rendered by the web UI: email
    summary, full header table, authentication results, body, every indicator
    group, local findings, the reputation (VirusTotal) aggregate, the final
    verdict with transparent reasons, and plain-language recommendations.

Dependencies:
    Python standard library only.  Uses ``parser`` for clean address formatting
    and the header-row table, and ``core`` for normalized header rows.

Related Files:
    orchestrator.py  (builds the inputs, calls build_report / build_header_report)
    app.py           (serialises the returned dict as the /api/analyze JSON)
    web/app.js       (renders this JSON in the browser)
"""

RECOMMENDATIONS = {
    "Malicious": ("Do not open any links or attachments. Report the email as "
                  "phishing and delete it immediately."),
    "Suspicious": ("Treat with caution. Verify the sender and the content through "
                   "an independent channel before taking any action."),
    "Moderate": ("Review carefully. Confirm the sender and the message with the "
                 "organisation directly before responding or clicking."),
    "Safe": ("No indicators of compromise were detected. Still verify unusual "
             "requests independently before acting."),
    "Unknown": ("Not enough evidence to judge. Paste the complete raw email header "
                "(View > Show original in Gmail) and run the analysis again."),
}

SEVERITY_LABEL = {
    "high": "High confidence",
    "medium": "Medium confidence",
    "low": "Low confidence",
    "safe": "Safe signal",
    "info": "Information",
}


def format_address(value):
    from .parser import format_address_field
    return format_address_field(value)


def build_report(parsed, header_norm, basic, received, auth, return_path,
                 msgid_domain, emails, urls, domains, ips, content,
                 mismatches, link_anomalies, ti_results, verdict_details,
                 reputation_active, typosquatting=None):
    s = verdict_details
    v = s["verdict"]

    checked = {
        "urls": len(urls),
        "domains": len(domains),
        "ips": len(ips),
        "files": len(parsed["attachments"]),
        "emails": len(emails),
        "attachments": len(parsed["attachments"]),
        "sources": ["VirusTotal"],
    }

    all_indicators = (ti_results["urls"] + ti_results["domains"] +
                      ti_results["ips"] + ti_results["files"])
    dangerous_attachments = sum(1 for a in parsed["attachments"] if a.get("dangerous"))

    counts = {
        "malicious": sum(1 for r in all_indicators if r["verdict"] == "Malicious")
                     + dangerous_attachments,
        "suspicious": sum(1 for r in all_indicators if r["verdict"] == "Suspicious")
                      + int(auth.get("explicit_fail", False)),
        "safe": sum(1 for r in all_indicators if r["verdict"] == "Safe")
                + int(auth.get("any_pass", False))
                + int(not mismatches and bool(basic.get("From"))),
        "unknown": sum(1 for r in all_indicators if r["verdict"] == "Unknown"),
    }

    result = {
        "summary": {
            "verdict": v,
            "confidence": s["confidence"],
            "explanation": s["explanation"],
            "recommendation": RECOMMENDATIONS.get(v, RECOMMENDATIONS["Unknown"]),
            "reasons": s["reasons"],
            "counts": counts,
            "evidence": s["evidence"],
            "checked": checked,
        },
        "email": {
            "from": format_address(basic.get("From", "N/A")),
            "to": format_address(basic.get("To", "N/A")),
            "subject": basic.get("Subject", "N/A"),
            "reply_to": format_address(basic.get("Reply-To", "N/A")),
            "return_path": return_path or "N/A",
            "message_id_domain": msgid_domain or "N/A",
        },
        "header": {
            "pairs": parser_header_pairs(parsed),
            "received": received,
            "auth": auth_result_for_ui(auth),
            "raw_blocks": auth.get("raw_blocks", []),
            "has_auth_header": auth.get("has_authentication_results", False),
        },
        "indicators": {
            "emails": emails,
            "urls": ti_results["urls"],
            "domains": ti_results["domains"],
            "ips": ti_results["ips"],
            "files": ti_results["files"],
        },
        "attachments": parsed["attachments"],
        "local": {
            "mismatches": mismatches,
            "link_anomalies": link_anomalies,
            "typosquatting": typosquatting or [],
            "content": {
                "urgency": content["urgency_or_credential_phrases"],
                "malware": content["malware_related_keywords"],
                "generic_greeting": content["generic_greeting"],
            },
        },
        "verdict_details": {
            "verdict": v,
            "confidence": s["confidence"],
            "explanation": s["explanation"],
            "reasons": s["reasons"],
            "evidence": s["evidence"],
        },
    }
    return result


def parser_header_pairs(parsed):
    from .parser import parse_header_pairs
    return parse_header_pairs(parsed["header_text"])


def auth_result_for_ui(auth):
    out = {}
    for proto in ("spf", "dkim", "dmarc", "arc"):
        entry = auth.get(proto) or {}
        out[proto] = {
            "status": entry.get("status", "Not found"),
            "value": entry.get("value"),
            "sources": entry.get("sources") or [],
        }
    return out


def header_pairs_from_text(header_text):
    """Turn raw header text into an ordered list of {name, value} rows."""
    from .parser import parse_header_pairs
    return parse_header_pairs(header_text)


def build_header_report(header_norm, basic, received, auth, return_path,
                        msgid_domain, urls, domains, ips, mismatches,
                        typosquatting, ti_results, verdict_details,
                        reputation_active):
    """
    Build the report for the header-only page (no body / attachments).

    The optional URL the user typed is merged into the domain/URL lookups, so
    the "pre-scan" of a suspicious link is reflected in the verdict like any
    other indicator.
    """
    s = verdict_details
    v = s["verdict"]

    checked = {
        "urls": len(urls),
        "domains": len(domains),
        "ips": len(ips),
        "files": 0,
        "emails": 0,
        "attachments": 0,
        "sources": ["VirusTotal"],
    }

    all_indicators = (ti_results["urls"] + ti_results["domains"] +
                      ti_results["ips"])
    counts = {
        "malicious": sum(1 for r in all_indicators if r["verdict"] == "Malicious"),
        "suspicious": sum(1 for r in all_indicators if r["verdict"] == "Suspicious")
                      + int(auth.get("explicit_fail", False)),
        "safe": sum(1 for r in all_indicators if r["verdict"] == "Safe")
                + int(auth.get("any_pass", False))
                + int(not mismatches and bool(basic.get("From"))),
        "unknown": sum(1 for r in all_indicators if r["verdict"] == "Unknown"),
    }

    result = {
        "summary": {
            "verdict": v,
            "confidence": s["confidence"],
            "explanation": s["explanation"],
            "recommendation": RECOMMENDATIONS.get(v, RECOMMENDATIONS["Unknown"]),
            "reasons": s["reasons"],
            "counts": counts,
            "evidence": s["evidence"],
            "checked": checked,
        },
        "email": {
            "from": format_address(basic.get("From", "N/A")),
            "to": format_address(basic.get("To", "N/A")),
            "subject": basic.get("Subject", "N/A"),
            "reply_to": format_address(basic.get("Reply-To", "N/A")),
            "return_path": return_path or "N/A",
            "message_id_domain": msgid_domain or "N/A",
        },
        "header": {
            "pairs": header_pairs_from_text(header_norm),
            "received": received,
            "auth": auth_result_for_ui(auth),
            "raw_blocks": auth.get("raw_blocks", []),
            "has_auth_header": auth.get("has_authentication_results", False),
        },
        "indicators": {
            "emails": [],
            "urls": ti_results["urls"],
            "domains": ti_results["domains"],
            "ips": ti_results["ips"],
            "files": [],
        },
        "attachments": [],
        "local": {
            "mismatches": mismatches,
            "link_anomalies": [],
            "typosquatting": typosquatting or [],
            "content": {
                "urgency": [],
                "malware": [],
                "generic_greeting": False,
            },
        },
        "verdict_details": {
            "verdict": v,
            "confidence": s["confidence"],
            "explanation": s["explanation"],
            "reasons": s["reasons"],
            "evidence": s["evidence"],
        },
    }
    return result
