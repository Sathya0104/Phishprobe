#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    Deterministic brand typosquatting detector (no network, no ML).

    Typosquatting = registering a domain that looks like a well-known brand
    (paypa1.com, microsoft-verify.com, workday.xyz, paypal.com.evil.net) to
    trick people into typing their password on a lookalike login page.

    This module compares extracted domains against a small list of frequently
    impersonated brands using simple, explainable rules:

      1. Exact match or a genuine subdomain of the brand -> NOT a typosquat.
      2. Same brand name on a "suspicious" TLD (.xyz, .top, .tk, ...) -> flag.
      3. Brand name split by a separator (microsoft-verify.com) -> flag.
      4. Brand name with a few extra characters (microsofteu.com) -> flag.
      5. Small edit distance (<= 2) from the brand name -> flag.
      6. Homoglyph lookalikes (paypa1 -> paypal) are normalised first.

    It is heuristic: a hit is strong suspicion, never proof.  The brand list is
    curated and includes each brand's known legitimate domains so genuine
    sub-brands (googleapis.com, microsoft365.com) are not flagged.

Dependencies:
    Python standard library only: re.

Related Files:
    orchestrator.py  (runs typosquatting checks against the domains iocs.py found)
    report.py        (renders typosquat findings)
"""

import re

# Brands people actually get phished as, with their real domains.
# The first domain in each list is the "did you mean" suggestion.  Extra
# entries are the brand's other / sub-brand domains that must never be flagged.
BRANDS = [
    {"name": "Microsoft", "domains": ["microsoft.com", "microsoft365.com",
                                      "live.com", "outlook.com", "office.com",
                                      "microsoftonline.com", "msn.com",
                                      "bing.com", "azure.com", "onedrive.com"]},
    {"name": "Google", "domains": ["google.com", "gmail.com", "youtube.com",
                                   "googlemail.com", "googleapis.com",
                                   "googleusercontent.com", "googleanalytics.com",
                                   "googlesyndication.com", "googleadservices.com",
                                   "gstatic.com", "blogspot.com", "goo.gl"]},
    {"name": "Apple", "domains": ["apple.com", "icloud.com", "me.com",
                                  "mac.com", "itunes.com"]},
    {"name": "Amazon", "domains": ["amazon.com", "amazon.co.uk", "amazon.de",
                                   "amazon.fr", "aws.amazon.com",
                                   "primevideo.com"]},
    {"name": "PayPal", "domains": ["paypal.com", "paypal.me", "paypalobjects.com"]},
    {"name": "Netflix", "domains": ["netflix.com", "nflxext.com", "nflximg.net"]},
    {"name": "Facebook", "domains": ["facebook.com", "fb.com", "fbcdn.net",
                                     "instagram.com", "whatsapp.com",
                                     "messenger.com", "whatsapp.net"]},
    {"name": "Meta", "domains": ["meta.com"]},
    {"name": "Workday", "domains": ["workday.com", "myworkday.com",
                                    "wd5.myworkday.com", "workdaycdn.com"]},
    {"name": "LinkedIn", "domains": ["linkedin.com", "licdn.com"]},
    {"name": "X (Twitter)", "domains": ["twitter.com", "x.com",
                                        "twimg.com", "t.co"]},
    {"name": "Bank of America", "domains": ["bankofamerica.com",
                                            "ml.com", "merrilledge.com"]},
    {"name": "Chase", "domains": ["chase.com", "jpmorgan.com"]},
    {"name": "Wells Fargo", "domains": ["wellsfargo.com", "wf.com"]},
    {"name": "Coinbase", "domains": ["coinbase.com"]},
    {"name": "Dropbox", "domains": ["dropbox.com"]},
    {"name": "Adobe", "domains": ["adobe.com", "adobe.io"]},
    {"name": "Docusign", "domains": ["docusign.com", "docusign.net"]},
    {"name": "Uber", "domains": ["uber.com", "uber-internal.com"]},
    {"name": "eBay", "domains": ["ebay.com", "ebay.de", "ebay.co.uk"]},
    {"name": "GitHub", "domains": ["github.com", "github.io",
                                   "githubusercontent.com"]},
    {"name": "Slack", "domains": ["slack.com"]},
    {"name": "Zoom", "domains": ["zoom.us", "zoom.com", "zoom.us.com"]},
    {"name": "Telegram", "domains": ["telegram.org", "telegram.me", "t.me"]},
]

# TLDs that are almost never used by legitimate big brands but are cheap to
# register and commonly abused for lookalike domains.  Stored WITHOUT the dot.
SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "tk", "ml", "ga", "cf", "gq", "click", "link",
    "online", "site", "club", "shop", "buzz", "live", "zip", "mom", "lol",
    "fun", "bond", "country", "loan", "gdn", "rest", "work", "website",
}

# Country-code "zones" that appear as the last two labels of regional domains
# (google.com.mx, amazon.co.uk).  When the second-last label is one of these
# the real name sits three labels back, so name matching must skip the zone.
ZONE_WORDS = {"com", "co", "org", "net", "ac", "edu", "gov", "gob", "gen",
              "priv", "id", "web"}

# Characters that are commonly swapped for a letter to spoof a name.
HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
              "8": "b", "@": "a", "|": "l", "!": "i", "$": "s", "9": "g"}


def _homoglyph(text):
    """Replace lookalike characters so paypa1 == paypal for comparisons."""
    return "".join(HOMOGLYPHS.get(c, c) for c in text.lower())


def _edit_distance(a, b):
    """Levenshtein distance (fine for the short strings compared here)."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _name_and_tld(domain):
    """
    Return the (name, tld) a brand comparison should use for a domain.

    For a normal domain this is the second-level name + TLD (paypa1, com).
    For a regional domain (google.com.mx, amazon.co.uk) the zone is skipped so
    the brand name (google, amazon) is compared against the brand's name.
    """
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in ZONE_WORDS:
        return labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return domain, ""


def _is_legit(domain, brand):
    """True when the candidate IS the brand (exact match / subdomain / name)."""
    for real in brand["domains"]:
        real = real.lower()
        if domain == real or domain.endswith("." + real):
            return True
        name, tld = _name_and_tld(real)
        cand_name, cand_tld = _name_and_tld(domain)
        if cand_name == name and cand_tld == tld:
            return True
    return False


def _match_reason(domain, brand):
    """
    Return (did_you_mean, reason) if ``domain`` looks like a typosquat of the
    brand, else None.  Rules are ordered from strongest to weakest signal.
    """
    name, tld = _name_and_tld(domain)

    for real in brand["domains"]:
        real = real.lower()
        bname, _btld = _name_and_tld(real)

        # 1) Same brand name on a suspicious TLD (workday.xyz).
        if name == bname and tld in SUSPICIOUS_TLDS:
            return real, "uses '%s' on a lookalike TLD ('.%s')" % (bname, tld)

        # 2) Brand name separated by a hyphen / underscore (microsoft-verify,
        #    g00gle-login).  Tokens are homoglyph-normalised before comparing.
        tokens = [t for t in re.split(r"[^a-z0-9]+", name) if t]
        if name != bname and any(_homoglyph(t) == _homoglyph(bname)
                                 for t in tokens):
            return real, "splits the brand name '%s' with extra text" % bname

        # 3) Brand name embedded with only a little extra text (microsofteu).
        #    Skip very short brand names ('x', 'goo') to avoid noise, and skip
        #    exact name matches (handled by rule 1 / regional domains).
        if (len(bname) >= 4 and name != bname and bname in name
                and len(name) - len(bname) <= 4):
            return real, "looks like '%s' with extra characters" % bname

        # 4) Fuzzy match: <= 2 typos / homoglyphs away (paypa1, g00gle).
        if (len(bname) >= 4 and name != bname
                and _edit_distance(_homoglyph(name), _homoglyph(bname)) <= 2):
            return real, "closely resembles '%s'" % bname

    # 5) Brand's real domain embedded inside the candidate, but NOT as the
    #    final suffix (paypal.com.evil.net).  Regional domains such as
    #    google.com.mx are excluded because what follows is a single label.
    for real in brand["domains"]:
        real = real.lower()
        if real in domain and not domain.endswith(real):
            after = domain.split(real, 1)[1].lstrip(".")
            if after and "." in after:
                return real, "embeds the real domain '%s' to look legitimate" % real

    return None


def detect(domains):
    """
    Check a list of domains against the brand list.

    Returns a list of findings:
      {"brand", "domain", "did_you_mean", "reason"}
    One finding per domain, matched against the first brand it resembles.
    """
    findings = []
    seen = set()

    # Normalise candidates: lower-case, strip dots, drop email prefixes.
    candidates = set()
    for d in domains:
        if not d:
            continue
        text = str(d).strip().lower().rstrip(".")
        if "@" in text:
            text = text.rsplit("@", 1)[1]
        if "." in text:
            candidates.add(text)

    for domain in sorted(candidates):
        for brand in BRANDS:
            if _is_legit(domain, brand):
                continue
            match = _match_reason(domain, brand)
            if match and domain not in seen:
                did_you_mean, reason = match
                findings.append({
                    "brand": brand["name"],
                    "domain": domain,
                    "did_you_mean": did_you_mean,
                    "reason": reason,
                })
                seen.add(domain)
                break  # report the first matching brand only

    return findings
