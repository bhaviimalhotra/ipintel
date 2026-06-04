import argparse
import sys
import os
import json
import time
import ipaddress

from config import load_config, ensure_keys
from parser import parse_input, _is_private
from apis import AbuseIPDB, IPInfo, Scamalytics
from enricher import enrich, load_cache, save_cache, CACHE_FILE
from exporter import export_csv

BANNER = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ██╗██████╗     ██╗███╗   ██╗████████╗███████╗██╗       ║
║   ██║██╔══██╗    ██║████╗  ██║╚══██╔══╝██╔════╝██║       ║
║   ██║██████╔╝    ██║██╔██╗ ██║   ██║   █████╗  ██║       ║
║   ██║██╔═══╝     ██║██║╚██╗██║   ██║   ██╔══╝  ██║       ║
║   ██║██║         ██║██║ ╚████║   ██║   ███████╗███████╗  ║
║   ╚═╝╚═╝         ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝  ║
║                    IP INTEL v1.0.0                       ║
║                                                          ║
║     Extract  >>>  Analyze  >>>  Enrich  >>>  Export      ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""

VERSION = "1.0.0"

# Friendly label maps for the single-IP terminal display
_DISPLAY_LABELS = {
    "IPInfo": {
        "IPInfo_Hostname": "Hostname",
        "IPInfo_City":     "City",
        "IPInfo_Region":   "Region",
        "IPInfo_Country":  "Country",
        "IPInfo_Org":      "Organisation",
        "IPInfo_Anycast":  "Anycast",
    },
    "AbuseIPDB": {
        "AbuseIPDB_Score":        "Abuse Score",
        "AbuseIPDB_Country":      "Country",
        "AbuseIPDB_ISP":          "ISP",
        "AbuseIPDB_TotalReports": "Total Reports",
        "AbuseIPDB_IsTor":        "Is Tor",
    },
    "Scamalytics": {
        "Scamalytics_Score":         "Score",
        "Scamalytics_Risk":          "Risk Level",
        "Scamalytics_ISP_Score":     "ISP Score",
        "Scamalytics_ISP_Risk":      "ISP Risk",
        "Scamalytics_IsDatacenter":  "Is Datacenter",
        "Scamalytics_IsVPN":         "Is VPN",
        "Scamalytics_IsTor":         "Is Tor",
        "Scamalytics_IsBlacklisted": "Blacklisted",
        "Scamalytics_URL":           "Report URL",
    },
}


# =========================
# HELPERS
# =========================

def _determine_apis(args):
    use_all = args.all or not any([args.ipinfo, args.abuseipdb, args.scamalytics])

    config = load_config()

    use_ipinfo      = args.ipinfo or use_all
    use_abuseipdb   = args.abuseipdb or use_all
    use_scamalytics = args.scamalytics or use_all

    required_keys = []
    if use_ipinfo:
        required_keys.append("ipinfo_key")
    if use_abuseipdb:
        required_keys.append("abuseipdb_key")
    if use_scamalytics:
        required_keys += ["scamalytics_username", "scamalytics_key"]

    config = ensure_keys(config, required_keys)

    instances = []
    if use_ipinfo:
        instances.append(IPInfo(config["ipinfo_key"]))
    if use_abuseipdb:
        instances.append(AbuseIPDB(config["abuseipdb_key"]))
    if use_scamalytics:
        instances.append(Scamalytics(config["scamalytics_key"], config["scamalytics_username"]))

    return instances


def _print_count_table(ip_count_map):
    print(f"\n  {'IP Address':<42} {'Occurrences':>11}")
    print("  " + "-" * 55)
    for ip, count in sorted(ip_count_map.items(), key=lambda x: -x[1]):
        print(f"  {ip:<42} {count:>11}")
    print()


def _clear_cache(ips=None):
    """
    If ips is None  -> wipe the entire cache file.
    If ips is a list -> remove only those IPs from the cache.
    """
    if not os.path.exists(CACHE_FILE):
        print("[i] No cache file found — nothing to clear.")
        return

    if ips is None:
        os.remove(CACHE_FILE)
        print(f"[✓] Cache cleared — {CACHE_FILE} deleted.")
    else:
        with open(CACHE_FILE, "r") as f:
            cache = json.load(f)

        removed = []
        for ip in ips:
            if ip in cache:
                del cache[ip]
                removed.append(ip)

        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)

        if removed:
            print(f"[✓] Removed {len(removed)} IP(s) from cache:")
            for ip in removed:
                print(f"    - {ip}")
        else:
            print("[i] None of the specified IPs were found in cache.")


def _reset_keys():
    """Reset all API keys in config.json back to placeholders."""
    from config import save_config, DEFAULT_CONFIG

    if not os.path.exists("config.json"):
        print("[i] No config.json found — nothing to reset.")
        return

    confirm = input("[!] This will clear ALL saved API keys. Are you sure? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[i] Cancelled — no changes made.")
        return

    save_config(DEFAULT_CONFIG)
    print("[✓] All API keys have been reset in config.json.")
    print("    Run IPIntel again to re-enter your keys.")


def _print_ip_report(ip, api_data, api_instances):
    """Pretty-print enriched data for a single IP to the terminal."""
    SEP = 52
    LABEL_W = 14

    print(f"\n  IP Intel Report — {ip}")
    print("  " + "═" * SEP)

    for api in api_instances:
        api_name = api.__class__.__name__
        labels = _DISPLAY_LABELS.get(api_name, {})

        header = f"  ── {api_name} "
        print(f"\n{header}" + "─" * max(2, SEP - len(header) + 2))

        for col, label in labels.items():
            value = api_data.get(col, "N/A")
            print(f"    {label:<{LABEL_W}}  {value}")

    print("\n  " + "═" * SEP + "\n")


def _query_single_ip(args):
    """Handle --ip mode: enrich one IP and print results to the terminal."""
    ip_str = args.ip.strip()

    # Validate
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        print(f"[!] Invalid IP address: {ip_str!r}")
        sys.exit(1)

    # Warn about private ranges
    if _is_private(ip_str):
        print(f"[!] Warning: {ip_str} is a private/reserved address.")
        print("    Threat intel APIs may return no data or an error for private IPs.\n")

    print(f"[~] Querying: {ip_str}\n")

    api_instances = _determine_apis(args)

    # Check cache first, fetch only what's missing
    cache     = load_cache()
    ip_cache  = cache.get(ip_str, {})
    api_data  = {}
    fetched   = []
    from_cache = []

    for idx, api in enumerate(api_instances):
        api_name = api.__class__.__name__
        cached_cols = {h: ip_cache[h] for h in api.headers() if h in ip_cache}

        if len(cached_cols) == len(api.headers()):
            api_data.update(cached_cols)
            from_cache.append(api_name)
        else:
            result = api.safe_query(ip_str)
            api_data.update(result)
            ip_cache.update(result)
            fetched.append(api_name)
            # Delay between calls (skip after the last one)
            if idx < len(api_instances) - 1:
                time.sleep(args.delay)

    cache[ip_str] = ip_cache
    save_cache(cache)

    # Source summary line
    status_parts = []
    if from_cache:
        status_parts.append(f"cache: {', '.join(from_cache)}")
    if fetched:
        status_parts.append(f"fetched: {', '.join(fetched)}")
    if status_parts:
        print(f"  [{' | '.join(status_parts)}]")

    _print_ip_report(ip_str, api_data, api_instances)


# =========================
# MAIN
# =========================

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="ipintel",
        description="IPIntel — Extract and enrich IP addresses from logs",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Single IP quick-query
    parser.add_argument("--ip", metavar="ADDRESS",
                        help="Quick single-IP lookup — prints results to terminal\n"
                             "Example: --ip 1.2.3.4")

    # Input (file mode)
    inp = parser.add_argument_group("Input (file mode)")
    inp.add_argument("-i", "--input",
                     help="Input file path (.txt, .csv, .log or .json — auto-detected)")
    inp.add_argument("--ipv4", action="store_true",
                     help="Extract IPv4 addresses only")
    inp.add_argument("--ipv6", action="store_true",
                     help="Extract IPv6 addresses only")
    inp.add_argument("--include-private", action="store_true",
                     help="Include private/reserved IPs (skipped by default)")

    # APIs
    apis = parser.add_argument_group("APIs (default: all)")
    apis.add_argument("--all", action="store_true",
                      help="Use all available APIs (default when none specified)")
    apis.add_argument("--ipinfo",      action="store_true", help="Use IPInfo API")
    apis.add_argument("--abuseipdb",   action="store_true", help="Use AbuseIPDB API")
    apis.add_argument("--scamalytics", action="store_true", help="Use Scamalytics API")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output", default="output/ip_enriched.csv",
                     help="Output CSV path (default: output/ip_enriched.csv)")
    out.add_argument("--count", action="store_true",
                     help="Print IP addresses with occurrence count before enriching")
    out.add_argument("--extract-only", action="store_true",
                     help="Extract and export IPs only — no API calls")

    # Cache
    cache_grp = parser.add_argument_group("Cache")
    cache_grp.add_argument("--clear-cache", action="store_true",
                            help="Clear the entire cache and exit")
    cache_grp.add_argument("--clear-ip", metavar="IP", nargs="+",
                            help="Remove one or more specific IPs from cache and exit\n"
                                 "Example: --clear-ip 1.2.3.4 5.6.7.8")

    # Config
    config_grp = parser.add_argument_group("Config")
    config_grp.add_argument("--reset-keys", action="store_true",
                             help="Reset all saved API keys in config.json and exit")

    # Misc
    parser.add_argument("--delay", type=float, default=1.5,
                        help="Seconds between API calls (default: 1.5)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse IPs and show what would run — no API calls, no export")
    parser.add_argument("--version", action="version", version=f"IPIntel {VERSION}")

    # Show help if no arguments given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # =========================
    # CACHE COMMANDS (no input file needed)
    # =========================
    if args.clear_cache:
        _clear_cache()
        return

    if args.clear_ip:
        _clear_cache(ips=args.clear_ip)
        return

    if args.reset_keys:
        _reset_keys()
        return

    # =========================
    # SINGLE IP QUICK QUERY
    # =========================
    if args.ip:
        _query_single_ip(args)
        return

    # =========================
    # FILE MODE — input required
    # =========================
    if not args.input:
        print("[!] --input is required for file mode.")
        print("    For a quick single-IP lookup, use --ip <address>.")
        print("    Run with -h for full help.")
        sys.exit(1)

    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    if args.ipv4 and args.ipv6:
        print("[!] --ipv4 and --ipv6 cannot be used together.")
        sys.exit(1)

    # =========================
    # STEP 1 — Parse IPs
    # =========================
    print(f"[~] Parsing IPs from: {args.input}")
    ip_count = parse_input(
        args.input,
        ipv4_only=args.ipv4,
        ipv6_only=args.ipv6,
        include_private=args.include_private
    )

    if not ip_count:
        print("[!] No valid public IPs found in input file.")
        print("    Tip: use --include-private to include private ranges.")
        sys.exit(0)

    print(f"[✓] Found {len(ip_count)} unique IP(s)  "
          f"({sum(ip_count.values())} total occurrences)")

    if args.count:
        _print_count_table(ip_count)

    if args.dry_run:
        _print_count_table(ip_count)
        print("[i] Dry run — no API calls made, no files written.")
        return

    # =========================
    # STEP 2 — Extract only
    # =========================
    if args.extract_only:
        rows = [{"IP": ip, "Count": cnt} for ip, cnt in ip_count.items()]
        out_path = args.output.replace("ip_enriched", "unique_ips")
        export_csv(rows, out_path)
        return

    # =========================
    # STEP 3 — Enrich
    # =========================
    api_instances = _determine_apis(args)
    api_names = [a.__class__.__name__ for a in api_instances]
    print(f"\n[~] Enriching {len(ip_count)} IP(s) using: {', '.join(api_names)}\n")

    rows = enrich(ip_count, api_instances, delay=args.delay)

    # =========================
    # STEP 4 — Export
    # =========================
    export_csv(rows, args.output)


if __name__ == "__main__":
    main()
