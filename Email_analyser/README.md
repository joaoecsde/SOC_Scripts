# Phishing Email Header Analyser

A Python script that analyses the **headers, attachments and links** of a suspicious email and gives a **risk score** with the reasons behind it. It works **offline by default**, so no API keys are needed. An optional `--online` flag checks the extracted IPs against [AbuseIPDB](https://www.abuseipdb.com) and attachment hashes against [VirusTotal](https://www.virustotal.com).

---

## Requirements

- Python 3.x
- `requests` library

---

## Installation

Only needed if you plan to use `--online`. Open a terminal and run:

```bash
py -m pip install requests
```

---

## API Keys (optional, `--online` only)

| Service | Where to get it |
|---|---|
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com) → Account → API → Create Key |
| VirusTotal | [virustotal.com](https://www.virustotal.com) → Profile → API Key |

### Add your keys to the shared keys file

Open `api_keys.py` in the main `Scripts_SOC` folder and paste your keys between the quotes:

```python
ABUSEIPDB_API_KEY = "your_abuseipdb_key_here"
VIRUSTOTAL_API_KEY = "your_virustotal_key_here"
```

If `api_keys.py` doesn't exist yet, copy `api_keys.example.py` to `api_keys.py` first. Save the file. All scripts in this repo read from it, and you won't need to pass keys on the command line anymore.

You can also use environment variables (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`) or the `--abusekey` / `--vtkey` flags, which take priority over the file.

---

## How to Get the Email

| Source | What to do |
|---|---|
| Outlook | Open the email → File → Save As → `.eml` (or drag it to the desktop) |
| Gmail | Open the email → ⋮ menu → **Download message** |
| Headers only | Copy the raw headers ("Show original" / "View message source") into a `.txt` file |

A full `.eml` file is best, because it also lets the script inspect attachments and links.

---

## Running the Script

### Analyse an email file
```bash
python email_header_analyser.py suspicious.eml
```

### Analyse raw headers saved in a text file
```bash
python email_header_analyser.py headers.txt
```

### Pipe headers in from another command
```bash
cat headers.txt | python email_header_analyser.py -
```

### Add online checks (AbuseIPDB and VirusTotal)
```bash
python email_header_analyser.py suspicious.eml --online
```

### Save results to JSON
```bash
python email_header_analyser.py suspicious.eml --json results.json
```

You can combine any of these:
```bash
python email_header_analyser.py suspicious.eml --online --json results.json
```

---

## What It Checks

| Section | What the script does |
|---|---|
| Key headers | Extracts From, Reply-To, Return-Path, To, Subject, Date, Message-ID, X-Mailer and the originating IP |
| Received chain | Rebuilds the delivery path from oldest to newest hop, with IPs, hostnames, timestamps and delays |
| Authentication | Reads SPF, DKIM and DMARC results, and checks that the signing/envelope domains match the From domain |
| Spoofing detection | Looks for Reply-To / Return-Path / Message-ID mismatches, brand impersonation in the display name, lookalike or punycode domains, suspicious TLDs and bulk-mail clients |
| Indicators | Collects IPs, domains and URLs, all shown **defanged** so they are safe to copy |
| Attachments | Calculates MD5, SHA1 and SHA256, and flags risky or double extensions and disguised executables |
| Risk score | Adds up points for each finding and gives a verdict |
| Report | Colour-coded terminal report, plus optional JSON export |

Attachments are only hashed and inspected as bytes. They are **never opened or executed**.

---

## Risk Score

Each finding adds points to the total (capped at 100):

| Score | Verdict |
|---|---|
| 0 – 29 | 🟢 **LOW** risk |
| 30 – 59 | 🟡 **MEDIUM** risk |
| 60 – 100 | 🔴 **HIGH** risk |

The score is a **heuristic**. Always confirm the findings manually before closing or escalating a case.

---

## All Available Options

| Flag | Description | Default |
|---|---|---|
| `input` | Path to a `.eml` or headers file, or `-` for stdin | required |
| `--online` | Also check public IPs (AbuseIPDB) and attachment hashes (VirusTotal) | off |
| `--abusekey` | AbuseIPDB API key (if not hardcoded) | — |
| `--vtkey` | VirusTotal API key (if not hardcoded) | — |
| `--json` | Save results to a JSON file | — |
| `--delay` | Seconds between VirusTotal calls when using `--online` | `15` |

---

## Output Colors

- 🟢 **Green**: Passed / clean
- 🟡 **Yellow**: Suspicious / medium finding
- 🔴 **Red**: Failed / high risk finding
- ⚪ **Gray**: Missing or low importance

---

## API Rate Limits (`--online` only)

| Service | Free tier limit |
|---|---|
| AbuseIPDB | 1,000 requests / day |
| VirusTotal | 4 requests / minute |

The default `--delay` of 15 seconds keeps you under the VirusTotal limit when an email has several attachments.

---

## Troubleshooting

**"No Received headers found"**
The headers may have been stripped or copied incompletely. Try saving the email as a full `.eml` file.

**"No Authentication-Results header present"**
Some mail systems don't add this header, or it was removed when the email was forwarded. SPF, DKIM and DMARC can't be verified in that case.

**"Hash not found in VirusTotal" (with `--online`)**
The file hasn't been submitted to VirusTotal before. This is normal for new or targeted malware, so it doesn't mean the file is safe.

**HTTP 401 error (with `--online`)**
Your API key is incorrect or not set. Check the key in the script or pass it with `--abusekey` / `--vtkey`.

**HTTP 429 error (with `--online`)**
You've hit the rate limit. Wait a minute and try again, or increase `--delay`.
