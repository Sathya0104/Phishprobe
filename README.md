# PhishProbe

> **Author: Sathyanarayana**

**PhishProbe** is a phishing email analyzer built for SOC analysts. Paste a raw
email header — or a complete raw email / `.eml` source — and get an instant,
explainable verdict backed by SPF/DKIM/DMARC authentication checks, VirusTotal
reputation lookups, brand typosquatting detection, and content red-flag analysis.

---

## Live demo

**[phishprobe.onrender.com](https://phishprobe.onrender.com)** — open the link
and try it in your browser. No signup needed.

---

## Why SOC analysts should use PhishProbe

[![MTTD](https://img.shields.io/badge/MTTD-%7E30%20seconds-blue)](https://phishprobe.onrender.com)
[![MTTR](https://img.shields.io/badge/MTTR-%7E15%20minutes-green)](https://phishprobe.onrender.com)
[![Verdicts](https://img.shields.io/badge/Verdicts-5%20levels-orange)](https://phishprobe.onrender.com)
[![IOC Extraction](https://img.shields.io/badge/IOC%20Extraction-URL%20%7C%20Domain%20%7C%20IP%20%7C%20Hash-blueviolet)](https://phishprobe.onrender.com)
[![Authentication](https://img.shields.io/badge/Auth-SPF%20%7C%20DKIM%20%7C%20DMARC%20%7C%20ARC-success)](https://phishprobe.onrender.com)
[![Typosquatting](https://img.shields.io/badge/Typosquatting-20%2B%20brands-critical)](https://phishprobe.onrender.com)

Phishing remains the most common initial-access vector in modern breach
investigations. Every reported phishing email a SOC handles must go through
triage, investigation and containment — and each minute that email sits in an
inbox is a minute of exposure. PhishProbe attacks this problem directly: it
turns a raw email into a structured, explainable risk verdict in seconds.

### Cut MTTD — Mean Time To Detect

MTTD measures how long it takes to *discover* that a phishing email exists.
Manual triage can take minutes per message: opening the raw header, reading the
Received chain, checking SPF/DKIM/DMARC, and searching domain/IP reputation —
all by hand.

PhishProbe collapses that into a single paste:

- Runs SPF / DKIM / DMARC / ARC authentication checks automatically.
- Resolves every URL, domain, IP and attachment hash against reputation feeds.
- Detects typosquatted brand domains, link tricks (shorteners, raw-IP links,
  mismatched anchor text) and mismatched Reply-To/From addresses.
- Flags urgency/credential language and malware keywords.
- Returns one verdict with confidence % and plain-language reasoning.

**Result:** what used to take minutes now takes seconds — **MTTD drops from
minutes to seconds** per message.

### Cut MTTR — Mean Time To Respond

MTTR measures how long it takes to *contain and resolve* an incident after
detection. Slow MTTR usually means analysts are re-deriving evidence by hand
instead of acting on it.

PhishProbe shortens the response loop by delivering actionable output:

- A clear verdict (Malicious / Suspicious / Moderate / Safe) with confidence %.
- The exact list of flagged IOCs: domains, URLs, IPs and file hashes.
- One-click verification links to independent threat-intel platforms.
- SHA-256 (and MD5/SHA-1) hashes for attachment files, ready to block or share.
- An educational "why this matters" note per signal, so the analyst can explain
  the conclusion to stakeholders without extra research.

**Result:** analysts go straight from *"this email is bad"* to *"block these
IOCs"* — **MTTR drops from hours to minutes**.

---

## What a SOC analyst can achieve with PhishProbe

- **Faster phishing triage** — a verdict in seconds for every reported email,
  so the queue stops piling up.
- **Reproducible investigations** — the same email always produces the same
  structured, explainable report, so any analyst reaches the same conclusion.
- **Immediate IOC extraction** — domains, URLs, IPs and file hashes come out
  labelled with their risk, ready to feed into blocking or detection rules.
- **Confident escalation** — a documented, evidence-backed verdict makes it
  easy to justify escalation to incident response or end-user remediation.
- **Defensible metrics** — verdict counts, detected IOCs and per-campaign
  results can be reported to management as measurable improvements in
  detection and response (lower MTTD / MTTR).
- **On-the-job training** — the built-in explanations teach junior analysts why
  each signal matters, turning every investigation into practice.
- **Reduced alert fatigue** — clear verdicts and confidence % help prioritise
  which reported emails need immediate action and which can be cleared.
- **Privacy-aware workflow** — no analysis history is stored; you decide what
  to do with the results.

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
