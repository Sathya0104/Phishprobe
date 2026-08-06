# PhishProbe

> **Author: Sathyanarayana**

**PhishProbe** is a self-hosted email phishing/threat analyzer. Paste a raw
email header (or a complete raw email / `.eml` source) and get back an instant,
explainable verdict backed by:

- **SPF / DKIM / DMARC / ARC** authentication analysis
- **VirusTotal v3** reputation lookups for every URL, domain, IP and file hash
- **Brand typosquatting** detection (Microsoft, PayPal, Apple, Google, ...)
- **Content red flags** (urgency phrases, generic greetings, malware keywords)
- **Link anomaly checks** (shorteners, raw-IP links, mismatched anchor text)
- A **confidence-weighted verdict** with every reason spelled out

It runs entirely in your browser + a local server. Nothing is uploaded to a
shared store, and your VirusTotal API key stays on the backend.

---

## Overview

Phishing emails share a handful of reusable fingerprints. PhishProbe turns
those fingerprints into an automated, transparent checklist:

1. Parse the email (headers, body, attachments).
2. Verify the sender with SPF / DKIM / DMARC / ARC.
3. Extract every indicator (URLs, domains, IPs, file hashes, addresses).
4. Cross-check indicators against VirusTotal and check for brand typosquats.
5. Score the evidence and produce a verdict with plain-language reasons.

The verdict is **advisory**: it is a decision aid, not proof. Every result
links back to the specific evidence that produced it.

---

## Features

| Area | What PhishProbe does |
| --- | --- |
| Header Analyzer (`/`) | Paste the raw header (+ an optional URL) for a quick, compact verdict. |
| Full Email Analyzer (`/full`) | Paste the whole raw email / `.eml` and get the complete report. |
| Sender authentication | SPF / DKIM / DMARC / ARC status, aggregating multiple `Authentication-Results` blocks. |
| VirusTotal v3 | URL, domain, IP and file-hash reputation with detection ratios and risk scores. |
| Typosquatting | Deterministic, offline lookalike-domain detection for 20+ major brands. |
| Content checks | Urgency/credential phrases, malware keywords, generic greetings. |
| Link inspection | Shorteners, raw-IP links, `@`-redirect tricks, mismatched anchor text. |
| Mismatch checks | From vs Reply-To / Return-Path / Message-ID domain comparisons. |
| Attachments | MIME extraction with MD5/SHA-1/SHA-256 hashes and high-risk extension flags. |
| Verdicts | Malicious / Suspicious / Moderate / Safe / Unknown with confidence % and reasons. |
| Privacy | API key stays backend-only; results are never sent to third-party storage. |

---

## Technology

- **Python 3.12** — standard library only, zero third-party packages required.
- **`http.server`** (`ThreadingHTTPServer`) for the web application.
- **VirusTotal v3 API** as the single threat-intelligence source.
- Plain **HTML / CSS / JavaScript** frontend (no framework, no build step).

---

## Installation

### 1. Requirements

- Windows, macOS or Linux
- Python 3.12 or newer (3.9+ should work, 3.12 recommended)
- (Optional) A free VirusTotal API key for reputation lookups

### 2. Get the code

```bash
git clone <your-repository-url> phishprobe
cd phishprobe
```

Or simply place the `phishprobe/` package and `run_analyzer.py` wherever you
want to keep it.

### 3. Verify Python

```bash
python --version
```

You should see `Python 3.12.x` (or newer). No `pip install` is needed.

### 4. Configure the VirusTotal key (optional but recommended)

PhishProbe works without a key, but reputation lookups are the strongest
signal, so add one:

- Create a free account at <https://www.virustotal.com>, then copy your API key
  from the account settings page.
- Save it in `vt_config.json` at the project root:

```json
{
  "virustotal_api_key": "YOUR_KEY_HERE"
}
```

Or set the `VT_API_KEY` environment variable instead. The environment variable
wins if both exist.

> **Security:** the key is read on the backend only and is never included in
> API responses or sent to the browser.

---

## Running

```bash
python run_analyzer.py
```

Then open <http://127.0.0.1:8000> in your browser.

| Flag | Default | Purpose |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Bind address (use `0.0.0.0` to expose on your LAN). |
| `--port` | `8000` | Port to listen on. |

```bash
python run_analyzer.py --host 0.0.0.0 --port 9000
```

### What you get

- **Header Analyzer** at `http://127.0.0.1:8000/`
- **Full Email Analyzer** at `http://127.0.0.1:8000/full`
- **API status** at `http://127.0.0.1:8000/api/status`

Stop the server with `Ctrl+C` in the terminal.

---

## Usage

### Analyze an email header

1. Open the email you want to check.
2. In **Gmail**: open the message → **⋮ (More)** → **Show original** → copy the
   entire header block.
3. Open **PhishProbe** → **Header Analyzer**, paste the header, click
   **Analyze header**.
4. Optionally paste a suspicious URL into the *"Optional suspicious URL to
   pre-scan"* box to include it in the reputation and typosquatting checks.

### Analyze a complete email

1. In **Gmail**: open the message → **⋮** → **Show original** → **Download
   original** (a `.eml` file).
2. Open **PhishProbe** → **Full Email Analyzer**, paste the full raw source,
   click **Analyze email**.

### Reading the report

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

- **Instant triage** for forwarded/suspicious mail before opening links.
- **Transparent and explainable** — every verdict lists its exact reasons.
- **Private** — runs on your own machine; nothing leaves your control except
  the indicator lookups to VirusTotal.
- **Zero dependencies** — standard library only; runs anywhere Python 3 runs.
- **Educational** — each reason includes a short "why this matters" note,
  making it a training tool as much as a scanner.

---

## Project structure

```
phishprobe/
├── run_analyzer.py            Entry point - starts the web server
├── vt_config.json             Optional local VirusTotal key (backend only)
├── phishprobe/                The Python package
│   ├── __init__.py            Package version + public analyze() import
│   ├── core.py                Header normalization + legacy analysis utilities
│   ├── parser.py              .eml / header parsing (MIME, attachments)
│   ├── authentication.py      SPF / DKIM / DMARC / ARC verdicts
│   ├── iocs.py                Indicator (IOC) extraction
│   ├── typosquat.py           Brand lookalike-domain detection
│   ├── virustotal.py          VirusTotal v3 client
│   ├── cache.py               Thread-safe TTL cache for lookups
│   ├── scoring.py             Confidence-weighted verdict engine
│   ├── orchestrator.py        Wires the whole pipeline together
│   ├── report.py              Report JSON assembly
│   ├── app.py                 HTTP server + routing
│   ├── config.py              Backend secrets loader
│   └── web/                   HTML / CSS / JS / logo
└── README.md
```

---

## API endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/status` | Reputation state, data sources and version. |
| `POST` | `/api/analyze-header` | Body: `{"header": "...", "url": "..."}` → header report. Either field alone is accepted (a URL-only request still analyzes). |
| `POST` | `/api/analyze` | Body: `{"raw": "..."}` → full report. A bare URL is also accepted. |

---

## Documentation

- **`ARCHITECTURE.md`** / **`ARCHITECTURE.pdf`** - detailed technical
  documentation for team members: system diagram, module map, request lifecycle,
  report JSON contract, scoring model and extension points.

---

## Troubleshooting

| Problem | Likely cause / fix |
| --- | --- |
| `Address already in use` on start | Another process owns the port; use `--port` to pick another one. |
| "No Authentication-Results found" | The pasted text is only part of the header; copy the **full** header (View → Show original). |
| VirusTotal shows `inactive` | No API key configured, or the `VT_API_KEY` variable is empty. Add a key to `vt_config.json`. |
| Lookups are slow | VirusTotal free tier is rate-limited (~4 req/min). The app paces requests; full emails with many indicators take longer. |
| Unicode looks wrong in the console | Modern Python forces UTF-8 output; if not, set `PYTHONIOENCODING=utf-8`. |
| `python` not found | Install Python 3.12 and check the PATH, or call the full interpreter path. |

---

## FAQ

**Is PhishProbe free?**
Yes. It is open source and uses only the free VirusTotal tier (4 requests /
minute). A premium key removes the rate limit.

**Does PhishProbe store my email anywhere?**
No. Analysis happens in memory on your own machine. The only outbound network
calls are the indicator lookups to VirusTotal.

**Can it tell me with 100% certainty that an email is phishing?**
No scanner can. PhishProbe scores evidence and explains its reasoning; use the
result as input to your own judgment, especially for high-stakes emails.

**Why do legitimate emails get flagged?**
Marketing and bulk mail frequently use shorteners, urgency wording and a
different Reply-To domain. Those are low-weight signals, which is why PhishProbe
treats them as warnings rather than proof.

---

## Future work

- Clickable "pre-scan" of any URL without pasting the full email.
- Batch / folder analysis of `.eml` files.
- Exportable PDF/CSV reports.
- Community-sourced brand and indicator feeds.
- Optional SMTP integration for automatic quarantine suggestions.

---

## Credits

PhishProbe uses the **VirusTotal API key** to search domains, IPs and IOCs
during analysis, and was built using the VirusTotal API. The API key is read on
the backend only and is never sent to the browser or included in responses.

---

## Author

**Sathyanarayana**

*PhishProbe — email threat analysis, made simple and explainable.*
