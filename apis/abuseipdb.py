import requests
from .base import BaseAPI


class AbuseIPDB(BaseAPI):

    def headers(self):
        return [
            "AbuseIPDB_Score",
            "AbuseIPDB_Country",
            "AbuseIPDB_ISP",
            "AbuseIPDB_TotalReports",
            "AbuseIPDB_IsTor",
        ]

    def query(self, ip):
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "AbuseIPDB_Score":        d.get("abuseConfidenceScore", "N/A"),
            "AbuseIPDB_Country":      d.get("countryCode", "N/A"),
            "AbuseIPDB_ISP":          d.get("isp", "N/A"),
            "AbuseIPDB_TotalReports": d.get("totalReports", "N/A"),
            "AbuseIPDB_IsTor":        d.get("isTor", "N/A"),
        }
