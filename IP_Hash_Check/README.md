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
python3 -m pip install requests
```

---

## API Keys

You need two free API keys:

| Service | Where to get it |
|---|---|
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com) → Account → API → Create Key |
| VirusTotal | [virustotal.com](https://www.virustotal.com) → Profile → API Key |

### Add your keys to the shared keys file

Open `api_keys.py` in the main folder and paste your keys between the quotes:

```python
ABUSEIPDB_API_KEY = "your_abuseipdb_key_here"
VIRUSTOTAL_API_KEY = "your_virustotal_key_here"
```

You can also use environment variables (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`), which take priority over the file. Keys left as `your_..._here` are treated as missing.

`--abusekey` / `--vtkey` flags also exist and take priority over both, but a key typed on the command line is saved in your shell history and visible in the process list, so prefer the file or environment variables.

---

## Running the Script

### Check a single IP
```bash
python3 threat_lookup.py --indicators '1[.]2[.]3[.]4'
```

### Check multiple IPs
```bash
python3 threat_lookup.py --indicators '1[.]2[.]3[.]4' '8[.]8[.]8[.]8'
```

### Check a single hash
```bash
python3 threat_lookup.py --indicators <SHA256>
```

### Check multiple hashes
```bash
python3 threat_lookup.py --indicators <SHA256> <MD5>
```

### Mix IPs and hashes in the same command
```bash
python3 threat_lookup.py --indicators '1[.]2[.]3[.]4' <SHA256>
```

---

## Supported Hash Formats

| Format | Character length | Example |
|---|---|---|
| MD5 | 32 | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 | 40 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 | 64 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The script detects the format automatically based on length.

## Supported IP Formats

IPv4 and IPv6 addresses are both supported, plain or defanged (`1[.]2[.]3[.]4`, `1(.)2(.)3(.)4`, `1[dot]2[dot]3[dot]4`, `2001[:]db8::1`), on the command line and in files. On the command line, put defanged values in quotes (`'1[.]2[.]3[.]4'`): the shell treats `[.]` as a file-name pattern (zsh, the macOS default, stops with `no matches found`; bash can replace it with a matching file name), and `(.)` is a syntax error in both. Private and reserved addresses (e.g. `10.x.x.x`, `192.168.x.x`, `127.0.0.1`, `::1`) are skipped with a message, since they belong to internal networks and have no AbuseIPDB reputation.

---

## Using a File for Bulk Lookups

Create a plain `.txt` file with one IP or hash per line. Lines starting with `#` are treated as comments and ignored.

**Example `indicators.txt`:**
```
# Suspicious IPs
1[.]2[.]3[.]4 
8[.]8[.]8[.]8

# Malware hashes
d41d8cd98f00b204e9800998ecf8427e
44d88612fea8a8f36de82e1278abb02f
```

Then run:
```bash
python3 threat_lookup.py --file indicators.txt
```

---

## Save Results to JSON

Add `--json` followed by a filename to export results:

```bash
python3 threat_lookup.py --indicators <IP> <Hash> --json results.json
```

You can combine it with any other option:
```bash
python3 threat_lookup.py --file indicators.txt --json results.json
```

---

## All Available Options

| Flag | Description | Default |
|---|---|---|
| `--indicators` | One or more IPs or hashes | — |
| `--file` | Path to a `.txt` file with indicators | — |
| `--abusekey` | AbuseIPDB API key (prefer `api_keys.py` / env var) | — |
| `--vtkey` | VirusTotal API key (prefer `api_keys.py` / env var) | — |
| `--json` | Save results to a JSON file | — |
| `--max-age` | Max age of AbuseIPDB reports in days | `90` |
| `--delay` | Delay in seconds between VirusTotal calls | `15` |

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

The script waits 15 seconds between VirusTotal calls to stay within the free tier. IP lookups are not delayed. With a paid VirusTotal key you can lower it:
```bash
python3 threat_lookup.py --file indicators.txt --delay 1
```

---

## Troubleshooting

**Hash not found error**
The hash doesn't exist in VirusTotal's database yet. This is normal for files that haven't been submitted before.

**HTTP 401 error**
Your API key is incorrect. Double-check the key in `api_keys.py` or your environment variables.

**HTTP 429 error**
You've hit the rate limit. Wait a minute and try again, or increase `--delay`.

---

## Running the Tests

From the `IP_Hash_Check` folder:
```bash
python3 -m unittest discover tests -v
```
The API calls are faked, so no keys or network access are needed.