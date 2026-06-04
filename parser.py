import re
import csv
import json
import ipaddress

# =========================
# REGEX
# =========================

IPV4_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

IPV6_RE = re.compile(
    r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'
    r'|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b'
    r'|\b:(?::[A-Fa-f0-9]{1,4}){1,7}\b'
    r'|\b(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}\b'
    r'|\b(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}\b'
    r'|\b(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}\b'
)

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


# =========================
# HELPERS
# =========================

def _is_valid(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _is_private(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def _extract_from_text(text, ipv4_only=False, ipv6_only=False, include_private=False):
    candidates = []

    if not ipv6_only:
        candidates += IPV4_RE.findall(text)
    if not ipv4_only:
        candidates += IPV6_RE.findall(text)

    result = []
    for ip in candidates:
        ip = ip.strip()
        if not _is_valid(ip):
            continue
        if not include_private and _is_private(ip):
            continue
        result.append(ip)

    return result


# =========================
# JSON FLATTENER
# Recursively walks any JSON structure (nested dicts, arrays)
# and collects all string values into one big text blob for scanning
# =========================

def _flatten_json(obj):
    """Recursively extract all string values from a JSON object."""
    parts = []

    if isinstance(obj, dict):
        for v in obj.values():
            parts.append(_flatten_json(v))
    elif isinstance(obj, list):
        for item in obj:
            parts.append(_flatten_json(item))
    elif isinstance(obj, str):
        parts.append(obj)
    else:
        # int, float, bool — convert to string so IPs stored as numbers are caught
        parts.append(str(obj))

    return " ".join(parts)


# =========================
# FILE READERS
# =========================

def _read_txt_or_log(filepath, **kwargs):
    """Handles .txt and .log — both are plain text, line by line."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return _extract_from_text(f.read(), **kwargs)


def _read_csv(filepath, **kwargs):
    ips = []
    with open(filepath, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            ips += _extract_from_text(" ".join(row), **kwargs)
    return ips


def _read_json(filepath, **kwargs):
    """
    Handles .json files — flattens the entire structure into a text blob
    so IPs nested at any depth are caught.
    Works with:
      - Single JSON object  {}
      - JSON array          [{}, {}, ...]
      - NDJSON / JSON Lines (one JSON object per line)
    """
    ips = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read().strip()

    # Try standard JSON first (object or array)
    try:
        data = json.loads(raw)
        text = _flatten_json(data)
        return _extract_from_text(text, **kwargs)
    except json.JSONDecodeError:
        pass

    # Fall back to NDJSON — one JSON object per line (AWS CloudTrail, Azure Stream)
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            text = _flatten_json(data)
            ips += _extract_from_text(text, **kwargs)
        except json.JSONDecodeError:
            # If a line isn't valid JSON, scan it as plain text anyway
            ips += _extract_from_text(line, **kwargs)

    return ips


# =========================
# PUBLIC INTERFACE
# =========================


def parse_input(filepath, ipv4_only=False, ipv6_only=False, include_private=False):
    """
    Reads a .txt, .csv, .log, or .json file.
    Extracts and validates IPs, filters private ranges unless include_private=True.
    Returns a dict of {ip: occurrence_count}.
    """
    kwargs = {
        "ipv4_only": ipv4_only,
        "ipv6_only": ipv6_only,
        "include_private": include_private
    }

    ext = "." + filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""

    if ext == ".csv":
        raw = _read_csv(filepath, **kwargs)
    elif ext == ".json":
        raw = _read_json(filepath, **kwargs)
    elif ext in (".txt", ".log"):
        raw = _read_txt_or_log(filepath, **kwargs)
    else:
        # Unknown extension — try plain text as a best effort
        print(f"[!] Unknown file extension '{ext}' — attempting plain text read.")
        raw = _read_txt_or_log(filepath, **kwargs)

    # Deduplicate and count
    count_map = {}
    for ip in raw:
        count_map[ip] = count_map.get(ip, 0) + 1

    return count_map
