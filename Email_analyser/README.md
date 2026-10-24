# Phishing Email Header Analyser (v2)

A Python tool that analyses the **headers, links and attachments** of a suspicious email and gives a **risk score** with the reasons behind it. It works **offline by default**. An optional `--online` flag checks IPs against [AbuseIPDB](https://www.abuseipdb.com) and attachment hashes against [VirusTotal](https://www.virustotal.com).

Version 2 splits the analysis into the `email_analyser_lib` package and fixes the false positives and blind spots of v1 (see below). The command-line options are the same as v1, so existing commands keep working.

---

## What changed from v1

| Area | v1 | v2 |
|---|---|---|
| Structure | One 550-line file | Short entry script + `email_analyser_lib` package, one module per stage |
| Brand lookalikes | `secure-paypal.com` passed as genuine | Compared against each brand's real domains |
| Newsletters | Legit Mailchimp mail scored MEDIUM (40) | DMARC-verified third-party senders are noted as info (0) |
| DKIM | Only the first signature checked | Every signature checked; any aligned pass counts |
| Message-ID | Google Workspace / Microsoft 365 flagged | Known mail providers ignored |
| Links | Listed, never scored | Scored: text/href mismatch, `@` trick, IP links, forms, lookalikes, shorteners, risky downloads |
| Link extraction | Regex over raw HTML (`&amp;`, `w3.org` noise) | Real HTML parsing; Microsoft Safe Links and Google redirects unwrapped |
| Display name | "John @ Home" = +25 | Only real `user@domain.tld` addresses count |
| Attached emails | Hashed as empty files | Hashed properly, summarised, and searched for files inside |
| Input | `.msg`, PDFs, blank-line files silently analysed as empty | Detected with a clear message; leading blank lines fixed |
| Terminal safety | Headers printed raw (escape codes) | Control characters removed; everything defanged |
| Errors | Python tracebacks | Clean messages, exit code 3 |
| Score | One problem could max the score | Each category is capped |
| IPs | IPv4 only | IPv4 and IPv6 |

---

## Requirements

- Python 3.8 or newer
- `requests`, only for `--online`:

```bash
python3 -m pip install requests
```

---

## API Keys (optional, `--online` only)

| Service | Where to get it |
|---|---|
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com) → Account → API → Create Key |
| VirusTotal | [virustotal.com](https://www.virustotal.com) → Profile → API Key |

Open `api_keys.py` in the main folder and paste your keys between the quotes:

```python
ABUSEIPDB_API_KEY = "your_abuseipdb_key_here"
VIRUSTOTAL_API_KEY = "your_virustotal_key_here"
```

You can also use environment variables (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`) or the `--abusekey` / `--vtkey` flags, which take priority over the file.

---

## How to Get the Email

| Source | What to do |
|---|---|
| New Outlook / Outlook on the web | Open the email → **...** → Save / Download (`.eml`) |
| Classic Outlook (Windows) | Save As gives a `.msg`, which is **not supported**. Use File → Properties and copy the **Internet headers** into a `.txt` file, or use Outlook on the web |
| Gmail | Open the email → ⋮ menu → **Download message** |
| Headers only | Copy the raw headers ("Show original" / "View message source") into a `.txt` file |

A full `.eml` file is best, because it also lets the tool check links and attachments.

---

## Running the Script

Run it from the `Email_analyser` folder (the script finds its package next to it).

```bash
python3 email_header_analyser.py suspicious.eml
python3 email_header_analyser.py headers.txt
cat headers.txt | python3 email_header_analyser.py -
python3 email_header_analyser.py suspicious.eml --online --json results.json
```

### Use in scripts

```bash
python3 email_header_analyser.py suspicious.eml --exit-code
```

| Exit code | Meaning |
|---|---|
| 0 | Finished (LOW verdict when `--exit-code` is used) |
| 1 | MEDIUM verdict (`--exit-code` only) |
| 2 | HIGH verdict (`--exit-code` only) |
| 3 | Error: file missing, not an email, `.msg`, JSON not writable... |

---

## All Available Options

| Flag | Description | Default |
|---|---|---|
| `input` | Path to a `.eml` or headers file, or `-` for stdin | required |
| `--online` | Also check public IPs (AbuseIPDB) and attachment hashes (VirusTotal) | off |
| `--abusekey` | AbuseIPDB API key | from env / `api_keys.py` |
| `--vtkey` | VirusTotal API key | from env / `api_keys.py` |
| `--json` | Save full results to a JSON file (raw values, not defanged) | — |
| `--delay` | Seconds between VirusTotal calls when using `--online` | `15` |
| `--exit-code` | Exit with 0/1/2 for LOW/MEDIUM/HIGH | off |
| `--version` | Show the version | — |

---

## What It Checks

| Category (cap) | Checks |
|---|---|
| Authentication (45) | SPF, every DKIM signature, DMARC; SPF/DKIM alignment with From when DMARC did not pass |
| Sender (40) | Reply-To, Return-Path and Message-ID vs From; missing Message-ID / Date. Collapsed into one info note when DMARC passes |
| Impersonation (50) | Address in display name, brand in display name (medium when sent from the brand's own free mail, e.g. "Microsoft" from a personal `@outlook.com`), lookalike / digit-swapped / punycode From domains, suspicious TLDs |
| Relay (20) | Missing Received headers, long chains, big delays, timestamps going backwards, no public origin IP |
| Mailer (10) | Bulk-mail / script X-Mailer |
| Links (40) | Text shows one domain but links to another, `@` in URL, bare-IP links, HTML forms, lookalike / punycode link domains, shorteners, suspicious TLDs, direct downloads of risky files |
| Attachments (60) | Risky / double extensions, hidden RTL characters, renamed executables (MZ), HTML/SVG with forms or smuggling code, files inside attached emails |
| Reputation (50) | `--online` only: AbuseIPDB score, VirusTotal detections |

Attachments are only hashed and inspected as bytes. They are **never opened or executed**.

**Origin IP.** Each mail server adds its Received header on top, so the newest hops were written by the recipient's own servers and cannot be forged by the sender. The tool reads the chain from the top down while the receiving (`by`) server stays in the same organisation (Microsoft 365's `outlook.com` / `office365.com` names count as one, see `RELAY_ORG_GROUPS` in `config.py`). The origin IP is the server that handed the email to the first of those hops, as recorded by the receiving server (not an IP the sender put in its HELO name, such as `from [8.8.8.8] (unknown [real IP])`). The IPs of the recipient's own receiving (`by`) servers are listed as "Receiving IPs": they are not indicators and are not sent to AbuseIPDB. Every IP of a sending (`from`) server stays an indicator, even on the recipient's internal hops, so a forged hop cannot hide the real sender from the lookups. `X-Originating-IP` is shown separately as unverified, because anyone can add it.

---

## Risk Score

Each finding adds points. Each category is capped (numbers above), then the total is capped at 100.

| Score | Verdict |
|---|---|
| 0 – 29 | 🟢 **LOW** risk |
| 30 – 59 | 🟡 **MEDIUM** risk |
| 60 – 100 | 🔴 **HIGH** risk |

`INFO` findings (0 points) give context, such as "sent through Mailchimp, DMARC passed".

The score is a **heuristic**. Always confirm the findings manually before closing or escalating a case.

---

## Tuning

All lists live in `email_analyser_lib/config.py`: brands and their real domains, free-mail providers, mail providers, email service providers, suspicious TLDs, link shorteners, risky extensions, category caps and verdict thresholds. Add the brands, banks and suppliers relevant to your organisation to `BRAND_DOMAINS`.

---

## File Layout

```
Email_analyser/
├── email_header_analyser.py          command line only
├── email_analyser_lib/
│   ├── config.py        lists and scoring settings
│   ├── utils.py         defang, domains, brands, IPs, safe printing
│   ├── loader.py        input reading and validation
│   ├── headers.py       key headers, Received chain, origin IP
│   ├── auth.py          SPF / DKIM / DMARC and alignment
│   ├── links.py         link extraction and checks
│   ├── attachments.py   hashing and static checks
│   ├── rules.py         findings and scoring
│   ├── online.py        AbuseIPDB / VirusTotal
│   ├── pipeline.py      runs every stage in order
│   └── report.py        terminal report and JSON
└── tests/
    └── test_email_header_analyser.py
```

---

## Tests

From the `Email_analyser` folder:

```bash
python3 -m unittest discover tests -v
```

The tests build sample emails in memory (no files or network needed). Run them after changing any rule or list, to check that clean mail stays clean and phishing is still caught.

---

## Known Limitations

- `.msg` files are not supported (save as `.eml` or copy the headers).
- `root_domain()` is a heuristic, not the full Public Suffix List. Shared hosting such as `*.github.io` is treated as one organisation.
- Only Microsoft Safe Links and Google redirect links are unwrapped. Other gateways (e.g. Proofpoint URL Defense) show the gateway's domain.
- A display name like "Microsoft Outlook" on internal Exchange system messages is flagged as brand impersonation.
- Authentication-Results is only trustworthy when your own mail server added it.
- The origin IP can still be misled by a sender who forges Received hops naming the recipient's own servers, or when the recipient's hops only show IPs or single-word server names. Each hop is read up to its last " by ", so a sender address containing " by " (Exim writes it after its own `by`, as `envelope-from <...>`) can also mislead it. The real sending IP is still listed and looked up as an indicator. When no Received header names a receiving server, the origin falls back to the oldest public IP, which is the easiest to forge.
