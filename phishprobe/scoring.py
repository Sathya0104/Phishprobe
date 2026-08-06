#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    Weighted, confidence-based threat scoring and final verdict engine.

    Design principles
    -----------------
    * Only HIGH-confidence evidence (blocklist malicious detections, dangerous
      attachments, explicit SPF/DKIM/DMARC failures) can force a Suspicious or
      Malicious verdict.
    * Low-confidence signals (URL shorteners, urgency phrases, generic greetings,
      Message-ID mismatches) only raise the score a little and can never produce
      a Suspicious verdict on their own.
    * Reputation (VirusTotal) is a detection source: a multi-engine detection is
      strong evidence, while a clean scan is a positive signal, weighted
      accordingly.
    * Every verdict comes with a transparent list of reasons and an explanation
      so the reader can see exactly why the score was reached.

Dependencies:
    Python standard library only: re.

Related Files:
    orchestrator.py  (calls score_report() on the assembled evidence)
    report.py        (renders verdict, reasons and recommendations)
"""

import re

EVIDENCE_WEIGHTS = {"high": 40, "medium": 18, "low": 7}

# Accumulated medium evidence above this forces Suspicious even without a
# single high-confidence trigger.
MEDIUM_SUSPICIOUS_THRESHOLD = 36
MODERATE_THRESHOLD = 14

SEVERITY_LABEL = {"high": "High confidence", "medium": "Medium confidence", "low": "Low confidence"}


def _learning(severity, source):
    """A short, educational note explaining why a signal matters."""
    notes = {
        "auth_fail": "An explicit SPF/DKIM/DMARC failure means the message failed sender "
                     "validation. Legitimate mail from that domain would normally pass.",
        "reputation_malicious": "When VirusTotal's multi-engine scan flags an "
                                "indicator as malicious, it is a strong sign the "
                                "email is part of an attack.",
        "reputation_suspicious": "A VirusTotal suspicious detection is not proof, "
                                 "but it raises the risk that the destination is "
                                 "untrusted.",
        "dangerous_attachment": "Executable, script or macro-enabled files can run code on "
                                "your machine when opened.",
        "link_anomaly": "Links that hide their destination or use a raw IP are common in "
                        "phishing because they bypass the address a user thinks they see.",
        "mismatch": "A Reply-To or Return-Path that differs from the From address is a "
                    "classic impersonation technique.",
        "typosquatting": "Typosquatting registers domains that look like a famous brand "
                         "(e.g. 'paypa1.com' or 'workday.xyz') to lure you into entering "
                         "your password on a lookalike login page. Always compare the real "
                         "domain character by character before clicking.",
        "shortener": "Shortened URLs obscure the real destination and are widely abused, "
                     "though they are also used by legitimate marketing mail.",
        "urgency": "Pressure tactics ('act now', 'account suspended') are the most common "
                   "persuasion trigger in social engineering.",
        "generic_greeting": "Mass phishing rarely addresses you by name; generic greetings "
                            "are a tell-tale sign of a bulk campaign.",
        "malware_keyword": "Mentions of malware, hacking or security alerts are frequently "
                           "used to panic a recipient into acting.",
        "missing_auth": "Without Authentication-Results data the message could not be "
                        "verified end-to-end. Paste the full raw header to check.",
        "safe": "Passing authentication and clean reputation results are positive "
                "indicators that the message is legitimate.",
    }
    return notes.get(source, "")


def _severity_of(message, default="low"):
    return message.get("severity", default)


def build_evidence(payload):
    """Turn raw analysis data into a list of {severity, message, source} dicts."""
    evidence = []
    auth = payload.get("authentication") or {}
    content = payload.get("content") or {}
    attachments = payload.get("attachments") or []
    ti = payload.get("threat_intel") or {}

    # Authentication
    for proto in ("spf", "dkim", "dmarc"):
        result = auth.get(proto) or {}
        value = result.get("value")
        if value in ("fail", "softfail", "hardfail"):
            evidence.append({
                "severity": "high",
                "source": "auth_fail",
                "message": f"{proto.upper()} authentication explicitly failed ({value}).",
            })
    if not auth.get("any_pass") and not auth.get("has_authentication_results"):
        evidence.append({
            "severity": "low",
            "source": "missing_auth",
            "message": "No Authentication-Results header was found, so sender "
                       "authentication could not be verified.",
        })

    # Content / local findings
    for find in content.get("mismatches") or []:
        evidence.append({
            "severity": find.get("severity", "low"),
            "source": "mismatch",
            "message": find.get("message", ""),
        })
    # Deterministic typosquatting findings (brand lookalike domains).  High
    # severity because impersonating a known brand is a strong social-engineering
    # signal, but it cannot alone force a Malicious verdict (only VT malicious
    # detections and dangerous attachments can do that).
    for find in content.get("typosquatting") or []:
        evidence.append({
            "severity": "high",
            "source": "typosquatting",
            "message": (f"Domain '{find.get('domain')}' looks like a typosquat of "
                        f"{find.get('brand')}: {find.get('reason')}. Did you mean "
                        f"'{find.get('did_you_mean')}'?"),
        })
    for find in content.get("link_anomalies") or []:
        evidence.append({
            "severity": find.get("severity", "low"),
            "source": "link_anomaly" if find.get("severity") == "medium" else "shortener",
            "message": find.get("message", ""),
        })
    for phrase in content.get("urgency_phrases") or []:
        evidence.append({
            "severity": "low",
            "source": "urgency",
            "message": f"Urgency / credential-related phrase in body: '{phrase}'.",
        })
    if content.get("generic_greeting"):
        evidence.append({
            "severity": "low",
            "source": "generic_greeting",
            "message": "Generic greeting detected (common in mass-phishing campaigns).",
        })
    for word in content.get("malware_keywords") or []:
        evidence.append({
            "severity": "low",
            "source": "malware_keyword",
            "message": f"Malware-related keyword mentioned in body: '{word}'.",
        })

    # Attachments
    for att in attachments:
        if att.get("dangerous"):
            evidence.append({
                "severity": "high",
                "source": "dangerous_attachment",
                "message": (f"Attachment '{att.get('filename')}' has a high-risk extension "
                            f"({att.get('extension') or 'unknown'})."),
            })

    # Reputation (blocklist) results
    for rtype in ("urls", "domains", "ips", "files"):
        for r in ti.get(rtype) or []:
            verdict = (r.get("verdict") or "Unknown").lower()
            label = {"urls": "URL", "domains": "domain", "ips": "IP", "files": "file"}[rtype]
            if verdict == "malicious":
                evidence.append({
                    "severity": "high",
                    "source": "reputation_malicious",
                    "message": (f"VirusTotal flags {label} '{r.get('value')}' as malicious "
                                f"({r.get('detection_ratio')} engines)."),
                })
            elif verdict == "suspicious":
                evidence.append({
                    "severity": "medium",
                    "source": "reputation_suspicious",
                    "message": (f"VirusTotal flags {label} '{r.get('value')}' as suspicious "
                                f"({r.get('detection_ratio')} engines)."),
                })
            # Clean (Safe) VirusTotal results are still counted as positive
            # signals for the verdict/confidence, but are NOT shown as reasons.
            # Unknown indicators (skipped / lookup failed / no record available)
            # carry no weight: they are informational only.

    return evidence


def _weight(sev):
    return EVIDENCE_WEIGHTS.get(sev, 0)


def score_email(payload):
    """Compute the final verdict, confidence and transparent explanation."""
    evidence = build_evidence(payload)

    high_evidence = [e for e in evidence if e["severity"] == "high"]
    medium_evidence = [e for e in evidence if e["severity"] == "medium"]
    low_evidence = [e for e in evidence if e["severity"] == "low"]
    safe_evidence = [e for e in evidence if e["severity"] == "safe"]

    # Malicious triggers: high-confidence independent detections only.
    malicious_triggers = sum(
        1 for e in high_evidence
        if e.get("source") in ("reputation_malicious", "dangerous_attachment"))
    # Suspicious triggers: explicit auth failure or blocklist suspicious hits.
    auth_fail = any(e.get("source") == "auth_fail" for e in high_evidence)
    rep_suspicious = sum(1 for e in medium_evidence if e.get("source") == "reputation_suspicious")

    total = sum(_weight(e["severity"]) for e in high_evidence + medium_evidence + low_evidence)
    medium_score = sum(_weight(e["severity"]) for e in medium_evidence)

    auth = payload.get("authentication") or {}
    ti = payload.get("threat_intel") or {}
    clean_count = sum(
        1 for rtype in ("urls", "domains", "ips", "files")
        for r in ti.get(rtype) or [] if (r.get("verdict") or "") == "Safe")
    auth_any_pass = bool(auth.get("any_pass"))

    positive_signals = (int(auth_any_pass) + clean_count
                        + int(bool(payload.get("content", {}).get("no_mismatches", False))))

    # ---- verdict selection ----
    if malicious_triggers > 0:
        verdict = "Malicious"
    elif auth_fail or rep_suspicious > 0 or medium_score >= MEDIUM_SUSPICIOUS_THRESHOLD:
        verdict = "Suspicious"
    elif total >= MODERATE_THRESHOLD:
        verdict = "Moderate"
    elif positive_signals > 0 and total == 0 and auth_any_pass:
        verdict = "Safe"
    elif positive_signals > 0 and total < MODERATE_THRESHOLD and auth_any_pass:
        # Weak negative signals exist but strong positive authentication and
        # clean reputation results outweigh them.
        verdict = "Safe"
    elif total == 0:
        verdict = "Unknown"
    else:
        verdict = "Unknown"

    # ---- confidence ----
    if verdict == "Malicious":
        confidence = min(99, 62 + 12 * malicious_triggers + 5 * rep_suspicious + 4 * len(low_evidence))
    elif verdict == "Suspicious":
        confidence = min(94, 46 + 8 * (int(auth_fail) + rep_suspicious) + 5 * len(medium_evidence) + 3 * len(low_evidence))
    elif verdict == "Moderate":
        confidence = min(82, 42 + 5 * len(medium_evidence) + 3 * len(low_evidence))
    elif verdict == "Safe":
        confidence = min(92, 55 + 4 * positive_signals + 2 * len(safe_evidence))
        if not auth_any_pass:
            confidence = min(confidence, 55)
    else:
        confidence = 25

    # ---- reasons / explanation ----
    reasons = []
    ordered = high_evidence + medium_evidence + low_evidence
    for e in ordered:
        reasons.append({
            "severity": e["severity"],
            "label": SEVERITY_LABEL.get(e["severity"], "Safe signal"),
            "message": e["message"],
            "learn": _learning(e["severity"], e.get("source", "")),
        })
    for e in safe_evidence:
        reasons.append({
            "severity": "safe",
            "label": "Safe signal",
            "message": e["message"],
            "learn": _learning("safe", "safe"),
        })

    if not reasons:
        reasons.append({
            "severity": "info",
            "label": "No findings",
            "message": "No malicious or suspicious indicators were detected across all checks.",
            "learn": "This means nothing tripped the analyser, but always verify unexpected "
                     "requests through an independent channel.",
        })

    explanation = _explanation(verdict, confidence, reasons, auth)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "explanation": explanation,
        "reasons": reasons,
        "counts": {
            "malicious": malicious_triggers,
            "suspicious": int(auth_fail) + rep_suspicious,
            "moderate": total,
            "low": len(low_evidence),
            "safe": positive_signals + len(safe_evidence),
            "high": len(high_evidence),
            "medium": len(medium_evidence),
            "low_signals": len(low_evidence),
        },
        "evidence": {
            "high": len(high_evidence),
            "medium": len(medium_evidence),
            "low": len(low_evidence),
        },
    }


def _explanation(verdict, confidence, reasons, auth):
    top = [r["message"] for r in reasons if r["severity"] in ("high", "medium")]
    auth_state = "sending domains passed authentication" if auth.get("any_pass") else \
                 ("some authentication checks failed" if auth.get("explicit_fail") else
                  "authentication was not fully verified")

    if verdict == "Malicious":
        lead = (f"Multiple high-confidence indicators point to a malicious message. "
                f"The verdict is Malicious with {confidence}% confidence.")
    elif verdict == "Suspicious":
        lead = (f"At least one high- or medium-confidence indicator was found. "
                f"The verdict is Suspicious with {confidence}% confidence.")
    elif verdict == "Moderate":
        lead = (f"A small number of cautionary signals were found. The verdict is "
                f"Moderate risk with {confidence}% confidence.")
    elif verdict == "Safe":
        lead = (f"No meaningful threat indicators were found and {auth_state}. "
                f"The verdict is Safe with {confidence}% confidence.")
    else:
        lead = (f"Not enough evidence was available to judge this message. "
                f"The verdict is Unknown with {confidence}% confidence.")

    if top:
        lead += " Key drivers: " + "; ".join(top[:3]) + "."
    return lead
