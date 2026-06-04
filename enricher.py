import json
import os
import time

CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_cache.json")


# =========================
# CACHE
# =========================

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


# =========================
# ENRICH
# =========================

def enrich(ip_count_map, api_instances, delay=1.5):
    """
    ip_count_map : {ip: occurrence_count}
    api_instances: list of BaseAPI subclass instances

    Cache is per-API — if an IP was previously queried with IPInfo only,
    and you now run with AbuseIPDB, it will fetch AbuseIPDB fresh and
    merge it into the cache entry. Only APIs already cached are skipped.
    """
    cache = load_cache()
    rows = []
    total = len(ip_count_map)
    start_time = time.time()
    fetched_count = 0

    for i, (ip, count) in enumerate(ip_count_map.items(), 1):
        prefix = f"  [{i}/{total}] {ip:<40}"

        ip_cache = cache.get(ip, {})
        api_data = {}
        fetched = []
        from_cache = []

        for api in api_instances:
            api_name = api.__class__.__name__
            cached_columns = {h: ip_cache[h] for h in api.headers() if h in ip_cache}

            if len(cached_columns) == len(api.headers()):
                api_data.update(cached_columns)
                from_cache.append(api_name)
            else:
                result = api.safe_query(ip)
                api_data.update(result)
                ip_cache.update(result)
                fetched.append(api_name)

        cache[ip] = ip_cache

        # ETA — only meaningful once we have real fetch timing data
        eta_str = ""
        if fetched:
            fetched_count += 1
            elapsed = time.time() - start_time
            if fetched_count > 1 and (total - i) > 0:
                avg_per_fetch = elapsed / fetched_count
                eta_secs = int(avg_per_fetch * (total - i))
                if eta_secs >= 5:
                    eta_str = f"  (~{eta_secs // 60}m {eta_secs % 60}s left)"

        status_parts = []
        if from_cache:
            status_parts.append(f"cache: {', '.join(from_cache)}")
        if fetched:
            status_parts.append(f"fetched: {', '.join(fetched)}")
        print(f"{prefix} ({' | '.join(status_parts)}){eta_str}")

        if fetched:
            time.sleep(delay)

        row = {"IP": ip, "Count": count}
        row.update(api_data)
        rows.append(row)

    save_cache(cache)
    return rows
