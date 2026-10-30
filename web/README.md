# Investigation Tools (web UI)

A small local web page for the three command-line tools in this repo: the **email header analyser**, the **IP and hash check** and the **PDF analyser**. It runs the same analysis code as the CLIs, so results match. Nothing is sent anywhere except the optional AbuseIPDB and VirusTotal lookups you ask for.

---

## Requirements

- Python 3.9 or newer
- `flask` and `requests`:

```bash
python3 -m pip install flask requests
```

---

## Running It

From the repo root:

```bash
python3 web/app.py
```

Then open <http://127.0.0.1:8765> in your browser. Stop it with Ctrl+C. Open forms again after a restart: each server run has a new CSRF token, so a page left open from the last run is refused until you reload it.

The server listens on `127.0.0.1` only, port `8765`. Both are set at the top of `web/app.py`, as is the upload size limit (`MAX_UPLOAD_MB`, default 25). `HOST` must be a specific address: only `HOST` and `localhost` are accepted as hostnames, so with `0.0.0.0` a request to the machine's own IP, or to `127.0.0.1`, is refused. Restart the server after changing any of them.

---

## What Each Tab Does

### Email

Upload an `.eml` or a `.txt` file of raw headers (up to 25 MB by default, see `MAX_UPLOAD_MB`). Any other file type, or a file with no `From:` or `Received:` header, is refused before analysis starts.

| Option | What it does |
|---|---|
| Look up IPs and attachments online | Checks public IPs with AbuseIPDB and attachment hashes with VirusTotal. Needs at least one key: AbuseIPDB for IPs, VirusTotal for attachment hashes. The email itself is never uploaded |
| Wait N seconds between VirusTotal lookups | Pause between hash lookups. Default 15, because the free tier allows 4 a minute. 0 to 300 seconds; only checked when online lookups are on |

### IP and hash

Paste one IP or hash per line. Defanged values such as `185[.]220[.]101[.]4` work. If any line is something else, the whole list is refused: nothing is looked up, the error gives only the line numbers, and the box is cleared.

| Option | What it does |
|---|---|
| AbuseIPDB API key | Needed when the list contains IPs |
| VirusTotal API key | Needed when the list contains hashes |
| Report window (days) | AbuseIPDB `maxAgeInDays`: only reports from the last N days count. 1 to 365, default 90 |
| Wait N seconds between VirusTotal lookups | Pause between hash lookups. Default 15, 0 to 300 seconds |

If one lookup fails (bad key, rate limit, timeout), that row shows a plain message and the rest still finish.

### PDF

Upload a PDF (up to 25 MB by default, see `MAX_UPLOAD_MB`). Only `.pdf` files with a `%PDF-` header in the first 1024 bytes are accepted, and programs or scripts renamed to `.pdf` are refused before analysis starts.

| Option | What it does |
|---|---|
| Extract hidden content | Saves any JavaScript, embedded files and media as `payloads.zip`, password `infected`. Needs the `zip` command (standard on macOS and Linux) |

---

## Keys and Privacy

- API keys are typed into the page and kept **only in the browser tab** (`sessionStorage`). They disappear when the tab closes.
- The server uses a key for that one analysis and never saves or logs it. It never uses `api_keys.py` or environment variables (importing the IP and hash module reads them, but the web app does not use them).
- The uploaded file (and, for PDFs, the raw extracted payloads) is deleted as soon as the analysis ends. `payloads.zip` stays downloadable until the result expires (30 minutes) or the server stops; all job files are removed when the server stops (Ctrl+C, `kill`, or closing the terminal). Folders left by a server that was force-killed (`kill -9`) or crashed are removed the next time it starts.
- Browsers may offer to save the API key fields in their password manager. Decline it if you don't want keys stored.
- Results are kept in memory and **expire after 30 minutes**. Reopening an expired result shows a "run the analysis again" page.
- Values from the analysed file are escaped and IPs, domains, URLs and addresses are defanged. The JSON download keeps raw values.

---

## Limits

- **Localhost only.** There is no login. Forms carry a CSRF token, and requests whose Host is not `HOST` or `localhost` are refused.
- Running two hash batches at once can exceed VirusTotal's free-tier limit; the affected rows show HTTP 429. Run batches one at a time.
- Uploads over `MAX_UPLOAD_MB` (25 MB by default) are rejected with a message on the landing page. To raise it, change `MAX_UPLOAD_MB` at the top of `web/app.py`. Larger files take more memory and time to analyse, and each upload runs at the same time as any others. Raising it does not change the PDF analyser's separate 64 MB cap on each decompressed stream (`MAX_STREAM_BYTES` in `PDF_analyser/pdf_analyser_lib/config.py`), which protects against decompression bombs.

---

## Running the Tests

```bash
cd web
python3 -m unittest discover tests -v
```

All network calls are mocked. The three tool folders have their own test suites.
