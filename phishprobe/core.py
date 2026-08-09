"""
Author: Sathyanarayana

Description:
    PhishProbe core parsing utilities. This is the low-level engine that the
    rest of the package builds on. It normalises pasted email headers, extracts
    header fields (From / To / Return-Path / Message-ID), pulls IP addresses
    out of the routing chain, finds URLs, flags urgency wording in the body and
    runs a legacy command-line analysis (python -m phishprobe.core).

    Every other module imports this as ``core``:
      * parser / authentication / orchestrator use normalize_header(),
        extract_email_address(), extract_domain(), check_content_red_flags().
      * iocs uses extract_urls(), extract_ip_addresses(), SHORTENER_DOMAINS.

Dependencies:
    Python standard library only: re, sys, urllib.parse.

Related Files:
    parser.py          (Message-object + regex header parsing, folded headers)
    authentication.py  (SPF / DKIM / DMARC / ARC verdicts)
    iocs.py            (indicator extraction, sender-IP detection)
    orchestrator.py    (wires everything into one analysis run)
"""

import re
import sys
from urllib.parse import urlparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ---------------------------------------------------------------------------
# HEADER NORMALIZATION
# ---------------------------------------------------------------------------

KNOWN_HEADER_NAMES = {
    "received", "return-path", "from", "to", "cc", "bcc", "subject", "date",
    "reply-to", "message-id", "references", "in-reply-to", "sender",
    "x-sender", "envelope-from", "delivered-to", "mime-version",
    "content-type", "content-transfer-encoding", "content-disposition",
    "content-language", "accept-language", "dkim-signature",
    "authentication-results", "received-spf", "domainkey-signature",
    "list-unsubscribe", "auto-submitted", "x-mailer", "x-originating-ip",
    "x-original-to", "x-forwarded-for", "x-ms-has-attach", "x-originating-email",
    "thread-topic", "thread-index", "importance", "priority", "x-priority",
    "sensitivity", "x-originatororg", "x-authority-analysis",
    "x-exchange-routingpolicychecked", "x-ms-tnef-correlator",
}


def normalize_header(header):
    """
    Rebuild proper header lines when the pasted text lost its newlines
    (some clients collapse the whole header onto one physical line, which
    breaks every '^Name:' regex). Only the whitespace after the colon and a
    known/custom (X-) header name are treated as a boundary, so values like
    'https://', 'BCL:0' or 'Re: hello' are not mis-split.
    """
    text = header.replace("\r\n", "\n").replace("\r", "\n")
    if "\n" not in text.strip():
        names = "|".join(re.escape(n) for n in sorted(KNOWN_HEADER_NAMES, key=len, reverse=True))
        parts = re.split(r'(?i)(?=(?:' + names + r'|x-[a-z0-9-]+): )', text)
        return "\n".join(p.strip() for p in parts if p.strip())
    return text


# ---------------------------------------------------------------------------
# HEADER EXTRACTION
# ---------------------------------------------------------------------------

def extract_ip_addresses(header):
    """
    Only trust IPs that appear in routing/anti-spam headers (Received,
    X-Originating-IP) and only keep structurally valid IPv4 addresses.
    Scanning the whole header picks up dotted dates/times/base64 by mistake.
    """
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    candidates = []
    for line in extract_received_lines(header):
        candidates.extend(re.findall(ip_pattern, line))
    candidates.extend(re.findall(r'^X-Originating-IP:\s*([^\s]+)', header,
                                 re.MULTILINE | re.IGNORECASE))
    return [ip for ip in candidates
            if all(0 <= int(octet) <= 255 for octet in ip.split("."))]


def extract_received_lines(header):
    # Received headers can span multiple physical lines (continuation lines
    # start with whitespace). Join continuations before splitting.
    header = normalize_header(header)
    unfolded = re.sub(r'\n[ \t]+', ' ', header)
    return [line.strip() for line in unfolded.splitlines()
            if re.match(r'^Received:', line, re.IGNORECASE)]


def extract_basic_info(header):
    from_ = re.search(r'^From:\s*(.+)', header, re.MULTILINE)
    to = re.search(r'^To:\s*(.+)', header, re.MULTILINE)
    subject = re.search(r'^Subject:\s*(.+)', header, re.MULTILINE)
    reply_to = re.search(r'^Reply-To:\s*(.+)', header, re.MULTILINE)
    return {
        "From": from_.group(1).strip() if from_ else "N/A",
        "To": to.group(1).strip() if to else "N/A",
        "Subject": subject.group(1).strip() if subject else "N/A",
        "Reply-To": reply_to.group(1).strip() if reply_to else "N/A",
    }


def extract_email_address(field_value):
    """Pull the bare email address out of a 'Display Name <addr>' string."""
    if not field_value or field_value == "N/A":
        return None
    match = re.search(r'[\w\.\-\+]+@[\w\.\-]+', field_value)
    return match.group(0).lower() if match else None


def extract_domain(email_address):
    if not email_address or "@" not in email_address:
        return None
    return email_address.split("@")[-1].lower()


# ---------------------------------------------------------------------------
# 4. RETURN-PATH CHECK
# ---------------------------------------------------------------------------

def extract_return_path(header):
    match = re.search(r'^Return-Path:\s*[<]?([^>\s]+)[>]?', header,
                       re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip().lower() if match else None


# ---------------------------------------------------------------------------
# 5. MESSAGE-ID DOMAIN CHECK
# ---------------------------------------------------------------------------

def extract_message_id_domain(header):
    match = re.search(r'^Message-ID:\s*<[^@]+@([^>]+)>', header,
                       re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip().lower() if match else None


# ---------------------------------------------------------------------------
# 1. SPF / DKIM / DMARC PARSING
# ---------------------------------------------------------------------------

def extract_auth_results(header):
    """
    Parses Authentication-Results header(s) for spf/dkim/dmarc verdicts.
    Falls back to standalone Received-SPF header if present.
    """
    results = {"spf": None, "dkim": None, "dmarc": None}

    auth_blocks = re.findall(
        r'^Authentication-Results:\s*(.+(?:\n[ \t]+.+)*)',
        header, re.MULTILINE | re.IGNORECASE
    )
    combined = " ".join(b.replace("\n", " ") for b in auth_blocks)

    for key in results:
        m = re.search(rf'{key}=(\w+)', combined, re.IGNORECASE)
        if m:
            results[key] = m.group(1).lower()

    if results["spf"] is None:
        spf_alt = re.search(r'^Received-SPF:\s*(\w+)', header,
                             re.MULTILINE | re.IGNORECASE)
        if spf_alt:
            results["spf"] = spf_alt.group(1).lower()

    return results


def evaluate_auth_results(auth):
    verdicts = []
    for protocol, result in auth.items():
        if result is None:
            verdicts.append(f"{protocol.upper()}: not found (⚠️ cannot verify)")
        elif result == "pass":
            verdicts.append(f"{protocol.upper()}: pass (✅)")
        else:
            verdicts.append(f"{protocol.upper()}: {result} (❌ suspicious)")
    return verdicts


# ---------------------------------------------------------------------------
# 2. FROM / REPLY-TO / RETURN-PATH MISMATCH LOGIC
# ---------------------------------------------------------------------------

def check_mismatches(basic_info, return_path, msgid_domain):
    flags = []

    from_addr = extract_email_address(basic_info.get("From"))
    reply_addr = extract_email_address(basic_info.get("Reply-To"))
    from_domain = extract_domain(from_addr)
    reply_domain = extract_domain(reply_addr)
    return_path_domain = extract_domain(return_path)

    if reply_addr and from_addr and reply_domain != from_domain:
        flags.append(
            f"⚠️ Reply-To domain ('{reply_domain}') does not match "
            f"From domain ('{from_domain}')"
        )

    if return_path and from_domain and return_path_domain != from_domain:
        flags.append(
            f"⚠️ Return-Path domain ('{return_path_domain}') does not match "
            f"From domain ('{from_domain}')"
        )

    if msgid_domain and from_domain and msgid_domain != from_domain:
        # Message-ID domain differing from From is common with legit ESPs
        # (e.g. mailchimp, sendgrid), so treat as a softer notice.
        flags.append(
            f"ℹ️ Message-ID domain ('{msgid_domain}') differs from From "
            f"domain ('{from_domain}') — verify if a known mail service"
        )

    if not flags:
        if not from_addr:
            flags.append("ℹ️ Cannot verify mismatches — no From address was "
                         "found (the pasted header is likely incomplete).")
        else:
            flags.append("✅ No From/Reply-To/Return-Path/Message-ID mismatches detected")

    return flags


# ---------------------------------------------------------------------------
# 3 & 8. URL EXTRACTION AND LINK INSPECTION FROM BODY
# ---------------------------------------------------------------------------

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"
}


def extract_urls(body):
    # Quoted-Printable mailers wrap long lines with '=' + newline.  Join those
    # soft breaks first so a wrapped URL is recovered whole instead of yielding
    # a truncated fragment like 'https://uber.co1.qualtrics.co='.
    body = re.sub(r"=\r\n", "", body)
    body = re.sub(r"=\n", "", body)

    # Plain URLs (with scheme, or a bare www. domain)
    url_pattern = r'https?://[^\s<>"\')\]]+'
    plain_urls = re.findall(url_pattern, body)
    www_pattern = r'\bwww\.[^\s<>"\')\]]+'
    plain_urls += re.findall(www_pattern, body, re.IGNORECASE)

    # HTML anchor tags: <a href="...">display text</a>
    anchor_pattern = r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>'
    anchors = re.findall(anchor_pattern, body, re.IGNORECASE | re.DOTALL)

    return plain_urls, anchors


def netloc_of(url):
    """Return the domain of a URL, tolerating missing scheme (e.g. www.x.com)."""
    if "://" not in url:
        url = "http://" + url
    return urlparse(url).netloc.lower()


def inspect_urls(plain_urls, anchors):
    findings = []

    all_urls = list(plain_urls) + [href for href, _ in anchors]
    if not all_urls:
        findings.append("No URLs found in body.")
        return findings

    for url in set(all_urls):
        try:
            domain = netloc_of(url)
        except ValueError:
            domain = ""
        if any(domain == s or domain.endswith("." + s) for s in SHORTENER_DOMAINS):
            findings.append(f"⚠️ Shortened URL detected (hides real destination): {url}")
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            findings.append(f"⚠️ URL uses raw IP address instead of domain: {url}")
        if "@" in url.split("//", 1)[-1].split("/")[0]:
            findings.append(f"⚠️ URL contains '@' (possible redirect trick): {url}")

    # Anchor text vs actual href mismatch
    for href, text in anchors:
        text_clean = re.sub(r'<[^>]+>', '', text).strip()
        # If the displayed text itself looks like a URL, compare domains
        text_url_match = re.search(r'(?:https?://|www\.)[^\s<>"\')\]]+', text_clean,
                                   re.IGNORECASE)
        if text_url_match:
            displayed_domain = netloc_of(text_url_match.group(0))
            actual_domain = netloc_of(href)
            if displayed_domain and actual_domain and displayed_domain != actual_domain:
                findings.append(
                    f"⚠️ Link text shows '{displayed_domain}' but actually "
                    f"points to '{actual_domain}'"
                )

    if not findings:
        findings.append("✅ No obviously suspicious URL patterns detected "
                         "(still verify destinations manually before clicking)")

    return findings


# ---------------------------------------------------------------------------
# 6. CONTENT RED FLAGS (urgency, credential requests, etc.)
# ---------------------------------------------------------------------------

CONTENT_RED_FLAG_PHRASES = [
    "verify your account", "account suspended", "account will be suspended",
    "confirm your password", "click here", "act now", "urgent action required",
    "limited time", "immediate action", "update your payment",
    "your account has been locked", "unusual activity", "gift card",
    "wire transfer", "confirm your identity", "unauthorized login",
    "reset your password", "security alert", "final notice",
    "failure to comply", "log in immediately", "claim your reward",
]

MALWARE_KEYWORDS = [
    'malware', 'virus', 'trojan', 'ransomware', 'phishing', 'exploit', 'attack'
]


def check_content_red_flags(email_body):
    body_lower = email_body.lower()
    found_phrases = [p for p in CONTENT_RED_FLAG_PHRASES if p in body_lower]
    found_keywords = [w for w in MALWARE_KEYWORDS if w in body_lower]

    generic_greeting = bool(re.search(
        r'\b(dear customer|dear user|dear valued customer|dear account holder)\b',
        body_lower))

    return {
        "urgency_or_credential_phrases": found_phrases,
        "malware_related_keywords": found_keywords,
        "generic_greeting": generic_greeting,
    }


# ---------------------------------------------------------------------------
# 7. ATTACHMENT CHECK
# ---------------------------------------------------------------------------

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jar", ".msi", ".ps1", ".hta", ".zip", ".rar", ".7z", ".iso",
    ".docm", ".xlsm", ".pptm", ".html", ".htm"
}


def check_attachments(header, body):
    """
    Header/body text alone can't fully represent binary attachments, but we
    can flag filenames referenced via Content-Disposition / Content-Type
    (from raw MIME source) or plainly mentioned in the body.
    """
    findings = []
    combined_text = header + "\n" + body

    if re.search(r'^X-MS-Has-Attach:\s*yes', header, re.IGNORECASE | re.MULTILINE):
        findings.append("⚠️ X-MS-Has-Attach: yes — message carries an attachment "
                        "(filename is not visible in the pasted text). Open with caution.")

    filename_matches = re.findall(
        r'(?:filename|name)\s*=\s*"?([^"\r\n;]+)"?', combined_text, re.IGNORECASE
    )

    if not filename_matches:
        findings.append("No attachment filenames detected in provided text "
                         "(note: this script only sees text you pasted, not "
                         "real binary attachments).")
        return findings

    for fname in set(f.strip() for f in filename_matches):
        ext = "." + fname.split(".")[-1].lower() if "." in fname else ""
        if ext in DANGEROUS_EXTENSIONS:
            findings.append(f"⚠️ Potentially dangerous attachment: {fname} ({ext})")
        else:
            findings.append(f"Attachment referenced: {fname}")

    return findings


# ---------------------------------------------------------------------------
# MAIN ANALYSIS
# ---------------------------------------------------------------------------

def analyze_email(header, body):
    header = normalize_header(header)

    print("=== Email Basic Info ===")
    basic_info = extract_basic_info(header)
    for k, v in basic_info.items():
        print(f"{k}: {v}")

    if basic_info["From"] == "N/A":
        print("⚠️ Could not find a From header — did you paste the COMPLETE raw "
              "header? The From/Received/Authentication-Results lines are at the "
              "very top of 'Show original / View source' and drive most checks.")

    print("\n=== Received Headers ===")
    received = extract_received_lines(header)
    if received:
        for i, line in enumerate(received, start=1):
            print(f"{i}. {line}")
    else:
        print("No Received headers found.")

    print("\n=== IP Addresses Found ===")
    ips = extract_ip_addresses(header)
    unique_ips = set(ips)
    if unique_ips:
        for ip in unique_ips:
            print(f"- {ip}")
    else:
        print("No IP addresses found in header.")

    print("\n=== SPF / DKIM / DMARC Authentication ===")
    auth = extract_auth_results(header)
    for line in evaluate_auth_results(auth):
        print(line)

    print("\n=== Return-Path Check ===")
    return_path = extract_return_path(header)
    print(f"Return-Path: {return_path if return_path else 'N/A'}")

    print("\n=== Message-ID Domain Check ===")
    msgid_domain = extract_message_id_domain(header)
    print(f"Message-ID domain: {msgid_domain if msgid_domain else 'N/A'}")

    print("\n=== From / Reply-To / Return-Path / Message-ID Mismatch Checks ===")
    for line in check_mismatches(basic_info, return_path, msgid_domain):
        print(line)

    print("\n=== URL Extraction & Link Inspection (Body) ===")
    plain_urls, anchors = extract_urls(body)
    all_found = set(plain_urls) | {href for href, _ in anchors}
    if all_found:
        print("URLs found:")
        for u in all_found:
            print(f"- {u}")
    else:
        print("No URLs found in body.")
    print()
    for line in inspect_urls(plain_urls, anchors):
        print(line)

    print("\n=== Content Red Flags ===")
    content = check_content_red_flags(body)
    if content["urgency_or_credential_phrases"]:
        print("⚠️ Urgency/credential-related phrases found:",
              ", ".join(content["urgency_or_credential_phrases"]))
    else:
        print("No urgency/credential-related phrases detected.")

    if content["malware_related_keywords"]:
        print("⚠️ Malware-related keywords found:",
              ", ".join(content["malware_related_keywords"]))
    else:
        print("No malware-related keywords detected.")

    if content["generic_greeting"]:
        print("⚠️ Generic greeting detected (e.g. 'Dear Customer') — common in mass phishing.")
    else:
        print("No generic greeting pattern detected.")

    print("\n=== Attachment Check ===")
    for line in check_attachments(header, body):
        print(line)

    print("\n=== Overall Risk Summary ===")
    risk_score = 0
    if auth.get("spf") not in ("pass",):
        risk_score += 1
    if auth.get("dkim") not in ("pass",):
        risk_score += 1
    if auth.get("dmarc") not in ("pass",):
        risk_score += 1
    if any("⚠️" in f for f in check_mismatches(basic_info, return_path, msgid_domain)):
        risk_score += 1
    if any("⚠️" in f for f in inspect_urls(plain_urls, anchors)):
        risk_score += 1
    if content["urgency_or_credential_phrases"]:
        risk_score += 1
    if content["generic_greeting"]:
        risk_score += 1
    if any("⚠️" in f for f in check_attachments(header, body)):
        risk_score += 1

    if risk_score == 0:
        print("Risk Level: LOW — no major red flags detected. Still verify independently.")
    elif risk_score <= 2:
        print(f"Risk Level: MODERATE ({risk_score} flags) — review carefully before acting.")
    else:
        print(f"Risk Level: HIGH ({risk_score} flags) — treat as likely phishing. Do not click links or open attachments.")


if __name__ == "__main__":
    print("Paste the full email header. End input with a blank line:\n")
    header_lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        header_lines.append(line)
    header_text = "\n".join(header_lines)

    print("\nPaste the email body. End input with a blank line:\n")
    body_lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        body_lines.append(line)
    body_text = "\n".join(body_lines)

    print("\nAnalyzing email...\n")
    analyze_email(header_text, body_text)
