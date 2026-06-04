# IPIntel

A CLI tool for extracting and enriching IP addresses from log files using **IPInfo**, **AbuseIPDB**, and **Scamalytics** — outputting results to a structured CSV for further investigation.

Built for DFIR analysts, threat hunters, and security researchers who need fast, automated IP intelligence from raw logs.

```
╔══════════════════════════════════════════════════════════╗
║     Extract  >>>  Analyze  >>>  Enrich  >>>  Export      ║
╚══════════════════════════════════════════════════════════╝
```

---

## Features

- **Quick single-IP lookup** with formatted terminal output (`--ip`)
- Extracts **IPv4 and IPv6** addresses from `.txt`, `.csv`, `.log`, and `.json` files
- **Deduplicates IPs** and tracks occurrence counts
- Automatically **filters private/reserved ranges** (configurable)
- Enriches IPs via **three threat intelligence APIs**
- **Caches results** locally — repeated runs never waste API quota
- Clean **CSV output** with one column group per API, ready for Excel/investigation
- **Prompts for missing API keys** on first run and saves them automatically

---

## Installation

### Prerequisites

- Python 3.8 or higher
- `pip` (comes with Python)

Check your version:
```bash
python --version
```

### Steps

**1. Clone the repository**
```bash
git clone https://github.com/bhaviimalhotra/ipintel.git
cd ipintel
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

That's it — one dependency (`requests`). No complex setup.

---

## API Keys Setup

IPIntel uses three free threat intelligence APIs. You need to register for each one and get an API key. **All three have a free tier** — no credit card required.

> **First-time tip:** If you don't want to edit `config.json` manually, just run IPIntel and it will prompt you to enter each key interactively and save them automatically.

---

### 1. IPInfo

IPInfo gives you geolocation, hostname, ASN, and organisation info for any IP.

**Free tier:** 50,000 requests/month

**Steps:**
1. Go to [https://ipinfo.io/dashboard/token](https://ipinfo.io/dashboard/token)
2. Create a free account
3. Your API token is shown on that page — copy it

**Where to put it:** `config.json` → `"ipinfo_key"`

---

### 2. AbuseIPDB

AbuseIPDB tells you if an IP has been reported for malicious activity, its abuse confidence score, ISP, and whether it's a known Tor exit node.

**Free tier:** 1,000 requests/day

**Steps:**
1. Go to [https://www.abuseipdb.com/account/api/keys](https://www.abuseipdb.com/account/api/keys)
2. Register for a free account and verify your email
3. On the API Keys page, click **Create Key** — copy the key shown

**Where to put it:** `config.json` → `"abuseipdb_key"`

---

### 3. Scamalytics

Scamalytics scores IPs for fraud risk and flags VPNs, Tor nodes, datacenters, and blacklisted addresses. Unlike the others, you request access via a form and they email you your credentials.

**Free tier:** Available (you choose your plan on the form)

**Steps:**
1. Go to [https://scamalytics.com/ip/api/enquiry2?monthly_api_calls=5000](https://scamalytics.com/ip/api/enquiry2?monthly_api_calls=5000)
2. Fill in the enquiry form with your name, email, and intended use
3. Wait for their reply email — it will contain both your **API key** and **username**
4. Both values go into `config.json`

**Where to put it:**
- Email API key → `"scamalytics_key"`
- Email username → `"scamalytics_username"`

---

### Adding Keys to config.json

Open `config.json` in the project folder and fill in your keys:

```json
{
  "ipinfo_key":           "paste_your_ipinfo_token_here",
  "abuseipdb_key":        "paste_your_abuseipdb_key_here",
  "scamalytics_key":      "paste_your_scamalytics_key_here",
  "scamalytics_username": "paste_your_scamalytics_username_here"
}
```

Save the file. IPIntel will read it automatically on every run.

> **Note:** `config.json` is in `.gitignore` — your keys will never be accidentally committed to Git.

---

### Don't want to edit config.json?

Just run IPIntel — it will detect missing or placeholder keys and prompt you:

```
[!] IPInfo Key is not set.
    Enter your IPInfo Key: ▌
```

Enter the key and press Enter. It saves automatically for all future runs.

---

## Usage

### Quick Single-IP Lookup

The fastest way to check one IP — results print directly to the terminal, no file needed:

```bash
python ipintel.py --ip 8.8.8.8
```

Combine with API flags to limit which sources are queried:

```bash
python ipintel.py --ip 1.2.3.4 --abuseipdb
python ipintel.py --ip 1.2.3.4 --ipinfo --scamalytics
```

Example output:
```
  IP Intel Report — 8.8.8.8
  ════════════════════════════════════════════════════

  ── IPInfo ──────────────────────────────────────────
    Hostname        dns.google
    City            Mountain View
    Region          California
    Country         US
    Organisation    AS15169 Google LLC
    Anycast         N/A

  ── AbuseIPDB ───────────────────────────────────────
    Abuse Score     0
    Country         US
    ISP             Google LLC
    Total Reports   0
    Is Tor          False

  ── Scamalytics ─────────────────────────────────────
    Score           0
    Risk Level      low
    ISP Score       0
    ISP Risk        low
    Is Datacenter   false
    Is VPN          false
    Is Tor          false
    Blacklisted     false
    Report URL      https://scamalytics.com/ip/8.8.8.8
```

---

### File Mode — Bulk Analysis

Point IPIntel at a log file and it extracts every unique IP, enriches them all, and exports a CSV:

```bash
python ipintel.py -i access.log --all -o results.csv
```

---

## All Flags

| Flag | Description |
|------|-------------|
| `--ip <ADDRESS>` | Quick single-IP lookup — prints results to terminal |
| `-i, --input` | Input file path (`.txt`, `.csv`, `.log`, `.json` — auto-detected) |
| `--ipv4` | Extract IPv4 addresses only |
| `--ipv6` | Extract IPv6 addresses only |
| `--include-private` | Include private/reserved IPs (skipped by default) |
| `--all` | Use all APIs (default when no API flag is specified) |
| `--ipinfo` | Use IPInfo only |
| `--abuseipdb` | Use AbuseIPDB only |
| `--scamalytics` | Use Scamalytics only |
| `-o, --output` | Output CSV path (default: `output/ip_enriched.csv`) |
| `--count` | Print IPs with occurrence count before enriching |
| `--extract-only` | Extract IPs to CSV — no API calls |
| `--delay` | Seconds between API calls (default: `1.5`) |
| `--dry-run` | Parse only — show what would run, no API calls, no file written |
| `--clear-cache` | Wipe the entire IP cache |
| `--clear-ip <IP> [IP ...]` | Remove specific IPs from cache |
| `--reset-keys` | Reset all API keys in `config.json` back to placeholders |
| `--version` | Show version and exit |

---

## Examples

```bash
# Quick terminal lookup — all APIs
python ipintel.py --ip 8.8.8.8

# Quick lookup — AbuseIPDB only
python ipintel.py --ip 8.8.8.8 --abuseipdb

# See all unique IPs and occurrence counts without API calls
python ipintel.py -i access.log --dry-run

# Enrich all IPs using all APIs, export to CSV
python ipintel.py -i access.log --all -o results.csv

# IPv4 only, two specific APIs
python ipintel.py -i access.log --ipv4 --ipinfo --abuseipdb

# Extract unique IPs to CSV only — no API calls
python ipintel.py -i access.log --extract-only

# Slower delay to stay within rate limits
python ipintel.py -i access.log --all --delay 2.0

# Remove specific IPs from cache
python ipintel.py --clear-ip 1.2.3.4 5.6.7.8
```

---

## CSV Output

Results are saved with one row per unique IP:

| IP | Count | IPInfo_Country | IPInfo_Org | AbuseIPDB_Score | AbuseIPDB_TotalReports | AbuseIPDB_IsTor | Scamalytics_Score | Scamalytics_Risk | Scamalytics_IsVPN |
|----|-------|----------------|------------|-----------------|------------------------|-----------------|-------------------|------------------|-------------------|
| 1.2.3.4 | 14 | US | AS13335 Cloudflare | 97 | 523 | False | 88 | high | true |

If an API call fails for any reason, the row's columns show `ERROR` and a warning is printed — the run never crashes mid-way.

---

## Caching

After the first lookup, results are stored in `ip_cache.json`. On the next run, cached IPs are skipped — saving API quota and time.

Cache is **per-API**: if you previously ran with `--ipinfo` only and now run `--all`, only the missing APIs are fetched for each IP.

```bash
# Wipe everything and start fresh
python ipintel.py --clear-cache

# Remove specific IPs only
python ipintel.py --clear-ip 1.2.3.4
```

---

## Project Structure

```
ipintel/
├── ipintel.py          # CLI entry point
├── config.py           # Key management and config.json handling
├── parser.py           # IP extraction and deduplication
├── enricher.py         # API orchestration and caching
├── exporter.py         # CSV export
├── apis/
│   ├── base.py         # Abstract base class for all APIs
│   ├── ipinfo.py
│   ├── abuseipdb.py
│   └── scamalytics.py
├── config.json         # Your API keys (gitignored — never committed)
├── requirements.txt
└── README.md
```

---

## API Rate Limits

| API | Free Tier | Link |
|-----|-----------|------|
| IPInfo | 50,000 req/month | [ipinfo.io/dashboard/token](https://ipinfo.io/dashboard/token) |
| AbuseIPDB | 1,000 req/day | [abuseipdb.com/account/api/keys](https://www.abuseipdb.com/account/api/keys) |
| Scamalytics | Request-based free tier | [scamalytics.com/ip/api](https://scamalytics.com/ip/api/enquiry2?monthly_api_calls=5000) |

Use `--delay` to control the pace of requests. Default is `1.5` seconds between calls. Increase to `2.0` or higher if you are hitting rate limits on large files.

---

## Contributing

Pull requests are welcome. Please open an issue first to discuss any significant changes.

---

## License

[MIT](LICENSE)
