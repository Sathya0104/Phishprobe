#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    RFC 822 / .eml parsing pipeline. Separates a raw message into its header
    and body, walks the MIME tree to find plain / HTML text parts and
    attachments, computes attachment hashes, and keeps a flattened text corpus
    that the indicator extractor (iocs.py) scans.

    It also extracts the four "basic envelope" fields shown on every report
    (From / To / Subject / Reply-To). Real-world pasted headers are messy, so
    this module merges two parsers:
      * a stdlib Message-object parser  (unfolds folded headers, RFC 2047)
      * a regex fallback                (survives pastes that lost whitespace)
    and picks the more complete result per field. Clean address display is
    handled by format_address_field() so the UI never shows raw "<>"/quotes.

Dependencies:
    Python standard library only: hashlib, re, email (Message, policy, parser).
    Imports ``core`` (core.py) for header normalisation and known header names.

Related Files:
    core.py           (normalize_header, KNOWN_HEADER_NAMES)
    orchestrator.py   (calls parse_raw_email / extract_basic_info)
    report.py         (uses extract_basic_info + format_address_field)
    iocs.py           (scans the text_corpus this module produces)
"""

import hashlib
import re
from email import message_from_string, policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses

from . import core

# Extensions that are flagged anywhere in a message (macro-enabled Office docs
# are included because they can run code on open).
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jar", ".msi", ".ps1", ".hta", ".zip", ".rar", ".7z", ".iso",
    ".docm", ".xlsm", ".pptm", ".html", ".htm",
}

# A stricter subset: files that are essentially always executable code.
HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jar", ".msi", ".ps1", ".hta",
}

ATTACHMENT_EXTENSION_RE = re.compile(r"\.([a-zA-Z0-9]{1,8})$")


def normalize_raw(raw):
    """Normalise Windows / legacy line endings to plain '\\n' for parsing."""
    return raw.replace("\r\n", "\n").replace("\r", "\n")


def split_header_body(raw):
    """Return (header_text, body_text) from a raw message source."""
    norm = normalize_raw(raw)
    if "\n\n" in norm:
        header_text, body_text = norm.split("\n\n", 1)
        return header_text, body_text
    return norm, ""


def decode_bytes(data):
    """
    Decode a MIME payload with a tolerant charset fallback.

    Many emails arrive with a broken or missing charset declaration; trying
    utf-8 -> cp1252 -> latin-1 in order recovers almost everything.
    """
    if data is None:
        return ""
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", "replace")


def _extension_of(filename):
    """Return the lower-cased file extension (with dot) of an attachment name."""
    if not filename:
        return ""
    m = ATTACHMENT_EXTENSION_RE.search(filename.strip().lower())
    return m.group(0) if m else ""


def parse_attachments(message):
    """Walk a MIME tree collecting attachment metadata (including hashes)."""
    attachments = []
    for part in message.walk():
        cd = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        ctype = part.get_content_type()
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""

        # A real attachment either declares a filename or an attachment
        # disposition.  Inline images / signature banners are skipped.
        if filename or cd == "attachment":
            ext = _extension_of(filename or "")
            attachments.append({
                "filename": filename or "(unnamed attachment)",
                "content_type": ctype,
                "size": len(payload),
                "md5": hashlib.md5(payload).hexdigest(),
                "sha1": hashlib.sha1(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "extension": ext,
                "dangerous": ext in HIGH_RISK_EXTENSIONS,
            })
    return attachments


def parse_raw_email(raw):
    """
    Parse raw email source into the structures the rest of the pipeline uses.

    Returns a dict with header_text, plain_body, html_body, attachments and a
    combined text corpus for downstream indicator extraction.
    """
    header_text, body_text = split_header_body(raw)

    # The stdlib parser (with the "default" policy) is the most accurate way to
    # separate headers/body and walk the MIME tree; any parse failure falls
    # back to an empty Message so the app never crashes on malformed input.
    parser = BytesParser(policy=policy.default)
    try:
        msg = parser.parsebytes(normalize_raw(raw).encode("utf-8", "replace"))
    except Exception:
        msg = Message()

    plain_body, html_body = "", ""
    for part in msg.walk():
        ctype = part.get_content_type()
        cd = (part.get_content_disposition() or "").lower()
        if part.get_filename() or cd == "attachment":
            continue
        payload = part.get_payload(decode=True)
        if ctype == "text/plain" and not plain_body:
            plain_body = decode_bytes(payload)
        elif ctype == "text/html" and not html_body:
            html_body = decode_bytes(payload)

    # If the MIME parse found nothing, fall back to the raw text split so a
    # plain-text paste still shows a body.
    if not plain_body and not html_body:
        plain_body = body_text

    attachments = parse_attachments(msg)
    all_text = "\n".join([header_text, plain_body, html_body or ""])
    html_stripped = re.sub(r"<[^>]+>", " ", html_body or "")

    return {
        "header_text": header_text,
        "plain_body": plain_body,
        "html_body": html_body,
        "attachments": attachments,
        "all_text": all_text,
        "text_corpus": header_text + "\n" + plain_body + "\n" + html_stripped,
    }


def _repair_header_splits(header_text):
    """
    Rejoin header names that the single-line normalizer cut in half.

    ``core.normalize_header`` splits on every 'KnownName:' boundary with no
    word-start check, so 'Reply-To:' collapses to 'Reply-' + 'To:' (and
    'In-Reply-To:', 'x-original-to:' alike). Rebuild the name whenever a line
    ending in '-' is followed by a name continuation that forms a known header.
    """
    lines = header_text.splitlines()
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        m = re.match(r"^([A-Za-z][A-Za-z0-9-]*):", nxt) if nxt else None
        if (
            line.endswith("-")
            and line != "-"
            and m
            and (line[:-1] + "-" + m.group(1)).lower() in core.KNOWN_HEADER_NAMES
        ):
            out.append(line[:-1] + "-" + nxt)
            i += 2
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


def _normalized(header_text):
    """Normalize a header and repair the split-name artefact from collapse."""
    return _repair_header_splits(core.normalize_header(header_text))


def parse_header_pairs(header_text):
    """Turn header text into an ordered list of {name, value} rows."""
    header = _normalized(header_text)
    pairs = []
    for line in header.splitlines():
        if not line.strip():
            continue
        # A continuation line (starts with whitespace) belongs to the header
        # above it, so append it to the previous row's value.
        if line[0] in (" ", "\t") and pairs:
            pairs[-1]["value"] += " " + line.strip()
            continue
        m = re.match(r"^([^:]+):\s*(.*)$", line)
        if m:
            pairs.append({"name": m.group(1).strip(), "value": m.group(2).strip()})
        else:
            pairs.append({"name": "(misc)", "value": line.strip()})
    return pairs


def header_rows_named(header_text, name):
    """Return all values for a (possibly repeated) header name."""
    header = _normalized(header_text)
    unfolded = re.sub(r"\n[ \t]+", " ", header)
    pattern = re.compile(r"^" + re.escape(name) + r":\s*(.*)$", re.IGNORECASE | re.MULTILINE)
    return [m.group(1).strip() for m in pattern.finditer(unfolded)]


def basic_info_from_message(header_text):
    """
    Parse From / To / Subject / Reply-To straight from a Message object.

    Using the stdlib email parser (instead of raw regexes) means folded
    headers - continuation lines that start with whitespace, very common for
    long To / Cc / Reply-To lists - are unfolded automatically, so these fields
    no longer come back empty or truncated.
    """
    try:
        header = _normalized(header_text)
        msg = message_from_string(header, policy=policy.default)
        fields = {
            "From": msg.get("From"),
            "To": msg.get("To"),
            "Subject": msg.get("Subject"),
            "Reply-To": msg.get("Reply-To"),
        }
        # Normalise every field: None -> "N/A", internal whitespace collapsed.
        for key, value in fields.items():
            if value is None:
                fields[key] = "N/A"
            else:
                fields[key] = re.sub(r"\s+", " ", str(value)).strip() or "N/A"
        return fields
    except Exception:
        return None


def _regex_basic_info(header_text):
    """Regex-based fallback that also unfolds continuation lines.

    Also absorbs a following line that lost its leading whitespace (a common
    paste artefact) when it still looks like part of the address list.
    """
    header = _normalized(header_text)
    lines = header.splitlines()
    out = {}
    for key in ("From", "To", "Subject", "Reply-To"):
        value = "N/A"
        for i, line in enumerate(lines):
            m = re.match(r"^" + key + r":\s*(.*)$", line, re.IGNORECASE)
            if not m:
                continue
            value = m.group(1).strip()
            # Absorb following lines that lost their fold-indent but still
            # contain an address (e.g. "To: a@x.com\nb@x.com").
            j = i + 1
            while j < len(lines):
                nxt = lines[j].strip()
                if not nxt:
                    break
                if re.match(r"^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.]+:", nxt):
                    break
                if "@" in nxt:
                    value += " " + nxt
                j += 1
            break
        out[key] = re.sub(r"\s+", " ", value) or "N/A"
    return out


def _pick(field_a, field_b):
    """Choose the more complete of two parsed field values.

    Prefer the Message-object parser normally, but when both are present the
    one that captured more recipients ('@' occurrences) wins - that fixes
    pasted headers where folding whitespace was lost and only the regex fallback
    saw every recipient.
    """
    if not field_a or field_a == "N/A":
        return field_b if field_b and field_b != "N/A" else "N/A"
    if not field_b or field_b == "N/A":
        return field_a
    return field_a if field_a.count("@") >= field_b.count("@") else field_b


def format_address_field(value):
    """Render an RFC 5322 address field as clean, readable text.

    '"John" <j@x.com>' -> 'John (j@x.com)',
    '"j@x.com" <j@x.com>' -> 'j@x.com' (no doubled address, no quotes/brackets),
    'a@x.com, b@x.com' -> 'a@x.com, b@x.com'.
    """
    if not value or value == "N/A":
        return "N/A"
    seen, parts = set(), []
    for name, addr in getaddresses([value]):
        addr = (addr or "").strip()
        name = re.sub(r"\s+", " ", (name or "").strip().strip('"')).strip()
        token = (addr or name).lower()
        # Drop empty parts and duplicate addresses so the summary never shows
        # "a@x.com" twice or raw "<>"/quote artefacts.
        if not token or token in seen:
            continue
        seen.add(token)
        if not addr:
            parts.append(name)
        elif name and name.lower() == addr.lower():
            parts.append(addr)
        elif name:
            parts.append(f"{name} ({addr})")
        else:
            parts.append(addr)
    return ", ".join(parts) if parts else "N/A"


def extract_basic_info(header_text):
    """
    Extract the four basic envelope fields.

    Uses both the Message-object parser (handles folded headers and RFC 2047)
    and a regex fallback, then merges them so a To / Reply-To that is present
    in the raw header never shows up as N/A in the report.
    """
    fields = basic_info_from_message(header_text)
    regex_fields = _regex_basic_info(header_text)

    if not fields:
        return regex_fields

    merged = {}
    for key in ("From", "To", "Subject", "Reply-To"):
        merged[key] = _pick(fields.get(key), regex_fields.get(key))

    # Bulk mail sent Bcc (interview invites, newsletters) often has no To
    # header at all - the recipient only appears in the MTA's Delivered-To /
    # X-Original-To. Fall back to those so the report is not blank.
    if merged["To"] == "N/A":
        for fallback in ("Delivered-To", "X-Original-To", "X-Envelope-To"):
            vals = header_rows_named(header_text, fallback)
            if vals:
                merged["To"] = re.sub(r"\s+", " ", vals[0]).strip()
                break
    return merged
