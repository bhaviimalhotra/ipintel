import requests
from .base import BaseAPI


class IPInfo(BaseAPI):

    def headers(self):
        return [
            "IPInfo_Hostname",
            "IPInfo_City",
            "IPInfo_Region",
            "IPInfo_Country",
            "IPInfo_Org",
            "IPInfo_Anycast",
        ]

    def query(self, ip):
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            params={"token": self.api_key},
            timeout=10
        )
        r.raise_for_status()
        d = r.json()
        return {
            "IPInfo_Hostname": d.get("hostname", "N/A"),
            "IPInfo_City":     d.get("city", "N/A"),
            "IPInfo_Region":   d.get("region", "N/A"),
            "IPInfo_Country":  d.get("country", "N/A"),
            "IPInfo_Org":      d.get("org", "N/A"),
            "IPInfo_Anycast":  d.get("anycast", "N/A"),
        }
