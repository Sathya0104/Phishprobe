# PhishProbe

> **Author: Sathyanarayana**

**PhishProbe** is a phishing email analyzer. Paste a raw email header — or a
complete raw email / `.eml` source — and get an instant, explainable verdict
backed by SPF/DKIM/DMARC authentication checks, VirusTotal reputation lookups,
brand typosquatting detection, and content red-flag analysis.

---

## Live demo

**[phishprobe.onrender.com](https://phishprobe.onrender.com)** — open the link
and try it in your browser. No signup needed.

---

## Screenshots

![Home page](screenshots/home.png)

![Analysis report](screenshots/report.png)

![Full email analyzer](screenshots/full.png)

---

## Features

| Area | What PhishProbe does |
| --- | --- |
| Header Analyzer | Paste the raw email header for a quick, compact verdict. |
| Full Email Analyzer | Paste the whole raw email / `.eml` and get the complete report. |
| Sender authentication | SPF / DKIM / DMARC / ARC status, aggregating multiple `Authentication-Results` blocks. |
| VirusTotal v3 | URL, domain, IP and file-hash reputation with detection ratios and risk scores. |
| Typosquatting | Lookalike-domain detection for 20+ major brands (Microsoft, PayPal, Apple, Google, ...). |
| Content checks | Urgency/credential phrases, malware keywords, generic greetings. |
| Link inspection | Shorteners, raw-IP links, `@`-redirect tricks, mismatched anchor text. |
| Mismatch checks | From vs Reply-To / Return-Path / Message-ID domain comparisons. |
| Attachments | MIME extraction with MD5 / SHA-1 / SHA-256 hashes and high-risk extension flags. |
| Verdicts | Malicious / Suspicious / Moderate / Safe / Unknown with confidence % and reasons. |
| Privacy | Your VirusTotal API key stays on the backend; results are never stored. |

---

## How to use it

### 1. Analyze an email header

1. Open the email you want to check.
2. In **Gmail**: open the message → **⋮ (More)** → **Show original** → copy the
   entire header block.
3. Open **PhishProbe** → paste the header into the **Header Analyzer**.
4. Click **Analyze header** and read the verdict.

### 2. Analyze a complete email

1. In **Gmail**: open the message → **⋮** → **Show original** → **Download
   original** (a `.eml` file).
2. Open **PhishProbe** → **Full Email Analyzer**, paste the full raw source.
3. Click **Analyze email** and read the complete report.

### 3. Reading the report

- **Verdict banner** — overall verdict, confidence %, the explanation and a
  plain-language recommendation.
- **Email summary** — From / To / Subject / Reply-To / Return-Path / Message-ID.
- **Authentication** — SPF / DKIM / DMARC / ARC status per header.
- **Indicators** — every URL, domain, IP and file with its VirusTotal verdict.
- **Local findings** — mismatches, link anomalies, typosquats, content flags.
- **Attachments** — name, MIME type, size, hashes, risk.
- **Full header & Received chain** — the normalized header table and routing hops.
- **Why this verdict** — the evidence list with an educational note per signal.

---

## Why PhishProbe is useful

- **Instant triage** for suspicious mail before opening links.
- **Transparent and explainable** — every verdict lists its exact reasons.
- **Private** — runs on your own infrastructure; only indicator lookups leave it.
- **Zero dependencies** — Python standard library only.
- **Educational** — each reason includes a short "why this matters" note,
  making it a training tool as much as a scanner.

---

## Author

**Sathyanarayana**

*PhishProbe — email threat analysis, made simple and explainable.*
