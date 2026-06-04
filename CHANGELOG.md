# Changelog

## v1.0.0 — Initial Release

### Features
- Extract IPv4 and IPv6 addresses from `.txt`, `.csv`, `.log`, and `.json` files (including nested JSON and NDJSON)
- Deduplicate IPs and track occurrence counts
- Filter private/reserved IP ranges by default (`--include-private` to override)
- Enrich IPs via IPInfo, AbuseIPDB, and Scamalytics
- `--ip <ADDRESS>` for quick single-IP terminal lookup — no file needed
- Per-API caching (`ip_cache.json`) — only fetch what isn't already cached, even across mixed API runs
- CSV export with one column group per API
- `--extract-only` mode — export unique IPs to CSV without any API calls
- `--dry-run` mode — parse and preview IPs without making any API calls or writing files
- `--count` — print IP occurrence table before enriching
- `--delay` — configurable rate limiting between API calls (default: 1.5s)
- `--clear-cache` / `--clear-ip` — cache management commands
- `--reset-keys` — wipe API keys back to placeholders
- Interactive API key prompts on first run with automatic save to `config.json`
- ETA estimate during bulk enrichment runs
- Failed API calls print a visible warning and fill `ERROR` — the run never crashes
