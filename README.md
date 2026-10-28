# Scripts_SOC

Lightweight Python tools for SOC analysts: triage a suspicious email, check IPs and hashes against threat intelligence, and look inside a PDF without opening it. Use them from the command line or from one local web page.

## Table of Contents

- [How it works](#how-it-works)
- [What's Inside](#whats-inside)
- [Quick Start](#quick-start)
- [The Basic Workflow](#the-basic-workflow)
- [Safety](#safety)
- [Project Layout](#project-layout)
- [Running the Tests](#running-the-tests)
- [Roadmap](#roadmap)

## How it works

Each tool is a small, self-contained Python script with its own README, its own tests and almost no dependencies. Everything runs on your machine. Nothing leaves it unless you ask for an online lookup, and then only the IP or hash goes to AbuseIPDB or VirusTotal, never the file itself.

The tools turn a sample into a **verdict with reasons**: not just "HIGH", but which checks fired and why. That makes it quick to decide whether to escalate, and easy to paste the result into a ticket.

You can run any tool on its own from the terminal, or start the **web UI** and use all three from tabs in your browser. Both run the same analysis code, so the results match.

## What's Inside

| Tool | What it does | Online? |
|---|---|---|
| [**Email analyser**](Email_analyser/README.md) | Reads the headers, links and attachments of an `.eml` (or pasted raw headers) and gives a 0–100 risk score. It checks SPF/DKIM/DMARC, finds the real origin IP, spots lookalike and brand-impersonating senders, scores links (text/href mismatch, shorteners, IP links, forms) and hashes attachments. | Optional (`--online`) |
| [**IP and hash check**](IP_Hash_Check/README.md) | Checks IPs against AbuseIPDB and file hashes (MD5, SHA1, SHA256) against VirusTotal. Mix both in one run, pass them on the command line or from a file, and paste defanged values like `1[.]2[.]3[.]4` as they are. | Yes |
| [**PDF analyser**](PDF_analyser/README.md) | Looks for JavaScript, auto-run actions, launch and form-submit actions, embedded files and obfuscation, and gives a LOW / MEDIUM / HIGH verdict. It can extract the hidden content into a password-protected zip. | No, fully offline |
| [**Web UI**](web/README.md) | A local page at `http://127.0.0.1:8765` with one tab per tool. Upload a file or paste indicators, watch the progress, read the result and download it as JSON. | Only the lookups you ask for |

## Quick Start

You need **Python 3.9 or newer**.

1. **Install the two dependencies.** `requests` is used for the online lookups and `flask` for the web UI. The PDF analyser needs neither.

   ```bash
   python3 -m pip install requests flask
   ```

2. **Add your API keys (optional).** Only needed for online lookups. Get a free key from [AbuseIPDB](https://www.abuseipdb.com) (Account → API) and [VirusTotal](https://www.virustotal.com) (Profile → API Key), then put them in `api_keys.py` in this folder:

   ```python
   ABUSEIPDB_API_KEY = "your_abuseipdb_key_here"
   VIRUSTOTAL_API_KEY = "your_virustotal_key_here"
   ```

   `api_keys.py` is in `.gitignore`, so your keys are never committed. The CLIs also read the environment variables `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY`. The web UI uses neither: you type the keys into the page, and they stay in that browser tab.

3. **Run a tool.**

   ```bash
   python3 web/app.py                                            # web UI, then open http://127.0.0.1:8765
   python3 Email_analyser/email_header_analyser.py suspicious.eml
   python3 IP_Hash_Check/threat_lookup.py --indicators '1[.]2[.]3[.]4' <SHA256>
   python3 PDF_analyser/pdf_analyser.py suspicious.pdf
   ```

Each tool's README lists every option, such as JSON output, `--exit-code` for scripts, and bulk lookups from a file.

## The Basic Workflow

A typical phishing triage, from a reported email to a ticket note:

1. **Get the email** - Save the reported message as `.eml` (or copy its raw headers). The [email analyser README](Email_analyser/README.md#how-to-get-the-email) shows how for Outlook and Gmail.

2. **Analyse the email** - Run the email analyser (or use the Email tab). It gives a risk score with every reason, the real origin IP and a defanged list of indicators.

3. **Check reputation** - Add `--online` (or tick it in the web UI) to look up the origin IPs on AbuseIPDB and the attachment hashes on VirusTotal. To check indicators found elsewhere, paste them into the IP and hash check.

4. **Look inside PDF attachments** - Save the attachment and run the PDF analyser. It flags active content without ever opening the file. Use `-out` (or "Extract hidden content") to get any JavaScript and embedded files in a zip with the password `infected`.

5. **Record the result** - Copy the verdict and reasons into the ticket, or save the full result as JSON (`--json`, or the download button in the web UI).

**Samples are never opened.** Every tool reads the file as bytes and parses it statically. Nothing is executed or rendered, and no link from a sample is ever fetched.

## Safety

- Files are only read as bytes. The PDF analyser never hands a PDF to a reader, and email attachments are only hashed and inspected, never opened or saved.
- Terminal output, reports and web pages are defanged (`hxxp://evil[.]com`) and control characters are stripped, so nothing from a sample becomes clickable or messes up your terminal. JSON output keeps raw values, so handle it with care.
- The web UI listens on `127.0.0.1` only. It deletes each upload as soon as its analysis ends, and deletes every job folder when the server stops. It has no login, so don't expose it to a network as it is.
- Extracted payloads are always zipped with the password `infected`, so antivirus doesn't quarantine them and nobody opens them by accident.
- `.eml` and `.pdf` files are in `.gitignore`, so samples are not committed by accident.

## Project Layout

```
Scripts_SOC/
├── api_keys.py          # your API keys (git-ignored), shared by the CLIs
├── Email_analyser/      # email_header_analyser.py + email_analyser_lib/ package
├── IP_Hash_Check/       # threat_lookup.py
├── PDF_analyser/        # pdf_analyser.py + pdf_analyser_lib/, vendored pdf-parser
└── web/                 # Flask web UI (app.py, templates, static)
```

Each tool folder has its own `README.md` and `tests/`. Start with the README of the tool you need: it covers every option, the full list of checks, how the score is built, and known limitations.

## Running the Tests

Every folder has its own unittest suite. Network calls are mocked, so no API keys are needed.

```bash
cd Email_analyser && python3 -m unittest discover tests -v
cd IP_Hash_Check  && python3 -m unittest discover tests -v
cd PDF_analyser   && python3 -m unittest discover tests -v
cd web            && python3 -m unittest discover tests -v
```

## Roadmap

Done:

- [x] Email header analyser
- [x] IP and hash reputation check
- [x] PDF static analyser
- [x] Local web UI for the three tools

Ideas for next:

- [ ] Web UI: history of past analyses
- [ ] Web UI: accounts with encrypted stored API keys
