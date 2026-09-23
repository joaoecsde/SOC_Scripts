# IP and Hash Lookup Tool

A Python script that checks **IP addresses** against [AbuseIPDB](https://www.abuseipdb.com) and **file hashes** against [VirusTotal](https://www.virustotal.com). It auto-detects what type of indicator you pass in, so you can mix IPs and hashes in the same command.

---

## Requirements

- Python 3.x
- `requests` library

---

## Installation

### 1. Install the requests library

Open a terminal (VS Code terminal or CMD) and run:

```bash
py -m pip install requests
```

---

## API Keys

You need two free API keys:

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

## Running the Script

### Check a single IP
```bash
python threat_lookup.py --indicators 1[.]2[.]3[.]4
```

### Check multiple IPs
```bash
python threat_lookup.py --indicators 1[.]2[.]3[.]4 8[.]8[.]8[.]8
```

### Check a single hash
```bash
python threat_lookup.py --indicators <SHA256>
```

### Check multiple hashes
```bash
python threat_lookup.py --indicators <SHA256> <MD5>
```

### Mix IPs and hashes in the same command
```bash
python threat_lookup.py --indicators 1[.]2[.]3[.]4 <SHA256>
```

---

## Supported Hash Formats

| Format | Character length | Example |
|---|---|---|
| MD5 | 32 | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 | 40 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 | 64 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The script detects the format automatically based on length.

---

## Using a File for Bulk Lookups

Create a plain `.txt` file with one IP or hash per line. Lines starting with `#` are treated as comments and ignored.

**Example `indicators.txt`:**
```
# Suspicious IPs
1.2.3.4
8.8.8.8

# Malware hashes
d41d8cd98f00b204e9800998ecf8427e
44d88612fea8a8f36de82e1278abb02f
```

Then run:
```bash
python threat_lookup.py --file indicators.txt
```

---

## Save Results to JSON

Add `--json` followed by a filename to export results:

```bash
python threat_lookup.py --indicators <IP> <Hash> --json results.json
```

You can combine it with any other option:
```bash
python threat_lookup.py --file indicators.txt --json results.json
```

---

## All Available Options

| Flag | Description | Default |
|---|---|---|
| `--indicators` | One or more IPs or hashes | — |
| `--file` | Path to a `.txt` file with indicators | — |
| `--abusekey` | AbuseIPDB API key (if not hardcoded) | — |
| `--vtkey` | VirusTotal API key (if not hardcoded) | — |
| `--json` | Save results to a JSON file | — |
| `--max-age` | Max age of AbuseIPDB reports in days | `90` |
| `--delay` | Delay in seconds between API calls | `0.5` |

---

## Output Colors

Results are color-coded in the terminal:

- 🟢 **Green** — Low risk / clean
- 🟡 **Yellow** — Suspicious / moderate risk
- 🔴 **Red** — High risk / malicious

---

## API Rate Limits

| Service | Free tier limit |
|---|---|
| AbuseIPDB | 1,000 requests / day |
| VirusTotal | 4 requests / minute |

If you're checking many indicators, increase the delay between calls with `--delay`:
```bash
python threat_lookup.py --file indicators.txt --delay 15
```

---

## Troubleshooting

**Hash not found error**
The hash doesn't exist in VirusTotal's database yet. This is normal for files that haven't been submitted before.

**HTTP 401 error**
Your API key is incorrect or not set. Double-check the key in the script or pass it via `--abusekey` / `--vtkey`.

**HTTP 429 error**
You've hit the rate limit. Wait a minute and try again, or increase `--delay`.