import requests
from .base import BaseAPI


class Scamalytics(BaseAPI):

    def __init__(self, api_key: str, username: str):
        super().__init__(api_key)
        self.username = username

    def headers(self):
        return [
            "Scamalytics_Score",
            "Scamalytics_Risk",
            "Scamalytics_ISP_Score",
            "Scamalytics_ISP_Risk",
            "Scamalytics_IsDatacenter",
            "Scamalytics_IsVPN",
            "Scamalytics_IsTor",
            "Scamalytics_IsBlacklisted",
            "Scamalytics_URL",
        ]

    def query(self, ip):
        url = f"https://api11.scamalytics.com/v3/{self.username}/"
        r = requests.get(
            url,
            params={"key": self.api_key, "ip": ip},
            timeout=10
        )
        r.raise_for_status()
        raw = r.json()
        d = raw.get("scamalytics", {})

        if d.get("status") == "error":
            raise Exception(f"Scamalytics error: {d.get('error', 'unknown')}")

        proxy = d.get("scamalytics_proxy", {})

        return {
            "Scamalytics_Score":         d.get("scamalytics_score", "N/A"),
            "Scamalytics_Risk":          d.get("scamalytics_risk", "N/A"),
            "Scamalytics_ISP_Score":     d.get("scamalytics_isp_score", "N/A"),
            "Scamalytics_ISP_Risk":      d.get("scamalytics_isp_risk", "N/A"),
            "Scamalytics_IsDatacenter":  proxy.get("is_datacenter", "N/A"),
            "Scamalytics_IsVPN":         proxy.get("is_vpn", "N/A"),
            "Scamalytics_IsTor":         proxy.get("is_tor", "N/A"),
            "Scamalytics_IsBlacklisted": d.get("is_blacklisted_external", "N/A"),
            "Scamalytics_URL":           d.get("scamalytics_url", "N/A"),
        }
