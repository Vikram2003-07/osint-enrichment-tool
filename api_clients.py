"""
api_clients.py
--------------
Handles all external API calls:
  - VirusTotal (file/URL/IP reputation)
  - AbuseIPDB   (IP abuse confidence score)
  - IPGeolocation.io (geographic location of IP)
"""

import requests
import time
import re


# ---------------------------------------------------------------------------
#  Helper: decide if an IOC is an IP address or a URL / domain
# ---------------------------------------------------------------------------
def is_ip_address(ioc: str) -> bool:
    """Return True if the IOC looks like an IPv4 address."""
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, ioc.strip()))


def extract_domain(url: str) -> str:
    """
    Pull the bare domain out of a URL string.
    e.g.  https://evil.example.com/path?q=1  →  evil.example.com
    """
    url = url.strip()
    # Remove scheme
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    # Remove path / query
    domain = url.split("/")[0].split("?")[0].split(":")[0]
    return domain


# =========================================================================
#  VirusTotal  (API v3)
#  Free tier: 4 requests / minute, 500 requests / day
# =========================================================================
class VirusTotalClient:
    """Query VirusTotal for IP or domain reputation."""

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.headers = {"x-apikey": api_key}

    # ----- public ---------------------------------------------------------
    def lookup(self, ioc: str) -> dict:
        """
        Return a normalised dict:
          malicious  : int  – engines that flagged the IOC
          suspicious : int
          harmless   : int
          undetected : int
          reputation : int  – VT community score (can be negative)
          raw        : dict – full JSON for debugging
          error      : str | None
        """
        if is_ip_address(ioc):
            return self._lookup_ip(ioc)
        return self._lookup_domain(ioc)

    # ----- private --------------------------------------------------------
    def _lookup_ip(self, ip: str) -> dict:
        url = f"{self.BASE}/ip_addresses/{ip}"
        return self._request(url)

    def _lookup_domain(self, domain_or_url: str) -> dict:
        domain = extract_domain(domain_or_url)
        url = f"{self.BASE}/domains/{domain}"
        return self._request(url)

    def _request(self, url: str) -> dict:
        """Fire the request and normalise the response."""
        try:
            resp = requests.get(url, headers=self.headers, timeout=30)

            if resp.status_code == 429:
                # Rate‑limited – wait and retry once
                time.sleep(60)
                resp = requests.get(url, headers=self.headers, timeout=30)

            if resp.status_code != 200:
                return self._error_result(
                    f"HTTP {resp.status_code}: {resp.text[:200]}"
                )

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})

            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", 0),
                "raw":        data,
                "error":      None,
            }
        except requests.RequestException as exc:
            return self._error_result(str(exc))

    @staticmethod
    def _error_result(msg: str) -> dict:
        return {
            "malicious": 0, "suspicious": 0,
            "harmless": 0, "undetected": 0,
            "reputation": 0, "raw": {}, "error": msg,
        }


# =========================================================================
#  AbuseIPDB  (API v2)
#  Free tier: 1 000 checks / day
# =========================================================================
class AbuseIPDBClient:
    """Query AbuseIPDB for an IP abuse confidence score."""

    BASE = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str):
        self.headers = {
            "Key": api_key,
            "Accept": "application/json",
        }

    def lookup(self, ioc: str) -> dict:
        """
        Return:
          abuse_confidence : int (0‑100)
          total_reports    : int
          country_code     : str
          isp              : str
          usage_type       : str
          error            : str | None
        """
        # AbuseIPDB only works with IPs
        ip = ioc if is_ip_address(ioc) else None
        if ip is None:
            return self._empty("AbuseIPDB only supports IP addresses")

        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            resp = requests.get(
                self.BASE, headers=self.headers,
                params=params, timeout=30
            )
            if resp.status_code != 200:
                return self._empty(f"HTTP {resp.status_code}")

            d = resp.json().get("data", {})
            return {
                "abuse_confidence": d.get("abuseConfidenceScore", 0),
                "total_reports":    d.get("totalReports", 0),
                "country_code":     d.get("countryCode", "N/A"),
                "isp":              d.get("isp", "N/A"),
                "usage_type":       d.get("usageType", "N/A"),
                "error":            None,
            }
        except requests.RequestException as exc:
            return self._empty(str(exc))

    @staticmethod
    def _empty(msg: str) -> dict:
        return {
            "abuse_confidence": 0, "total_reports": 0,
            "country_code": "N/A", "isp": "N/A",
            "usage_type": "N/A", "error": msg,
        }


# =========================================================================
#  IP Geolocation  (ipgeolocation.io — free 1 000 / day)
# =========================================================================
class GeoIPClient:
    """Get geographic details for an IP or domain."""

    BASE = "https://api.ipgeolocation.io/ipgeo"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup(self, ioc: str) -> dict:
        """
        Return:
          country  : str
          city     : str
          lat      : float
          lon      : float
          isp      : str
          org      : str
          error    : str | None
        """
        # If it's a URL, resolve to domain (the API accepts domains too)
        target = ioc if is_ip_address(ioc) else extract_domain(ioc)
        params = {"apiKey": self.api_key, "ip": target}
        try:
            resp = requests.get(self.BASE, params=params, timeout=30)
            if resp.status_code != 200:
                return self._empty(f"HTTP {resp.status_code}")
            d = resp.json()
            return {
                "country": d.get("country_name", "N/A"),
                "city":    d.get("city", "N/A"),
                "lat":     d.get("latitude", 0),
                "lon":     d.get("longitude", 0),
                "isp":     d.get("isp", "N/A"),
                "org":     d.get("organization", "N/A"),
                "error":   None,
            }
        except requests.RequestException as exc:
            return self._empty(str(exc))

    @staticmethod
    def _empty(msg: str) -> dict:
        return {
            "country": "N/A", "city": "N/A",
            "lat": 0, "lon": 0, "isp": "N/A",
            "org": "N/A", "error": msg,
        }