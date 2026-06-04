import json
import os

CONFIG_FILE = "config.json"

PLACEHOLDERS = {"your_key_here", "", "your_username_here"}

DEFAULT_CONFIG = {
    "ipinfo_key":           "your_key_here",
    "abuseipdb_key":        "your_key_here",
    "scamalytics_key":      "your_key_here",
    "scamalytics_username": "your_username_here"
}

API_LABELS = {
    "ipinfo_key":           "IPInfo",
    "abuseipdb_key":        "AbuseIPDB",
    "scamalytics_key":      "Scamalytics Key",
    "scamalytics_username": "Scamalytics Username"
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"[i] config.json created -> {os.path.abspath(CONFIG_FILE)}")
        print("    Fill in your API keys or enter them below when prompted.\n")

    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def _is_placeholder(value):
    return not value or value.strip() in PLACEHOLDERS


def ensure_keys(config, required_keys):
    updated = False

    for key_name in required_keys:
        label = API_LABELS[key_name]
        current = config.get(key_name, "").strip()

        if _is_placeholder(current):
            print(f"\n[!] {label} is not set.")
            new_val = input(f"    Enter your {label}: ").strip()

            if new_val and not _is_placeholder(new_val):
                config[key_name] = new_val
                updated = True
                print(f"    [+] {label} saved to config.json")
            else:
                print(f"    [!] No valid value entered -- {label} results may show ERROR.")

    if updated:
        save_config(config)

    return config
