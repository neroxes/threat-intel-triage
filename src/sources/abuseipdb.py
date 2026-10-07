"""AbuseIPDB IP lookup."""
import requests

from src import config


def lookup(ip):
    """Return a dict of results, or {"error": "..."} if something went wrong."""
    if not config.ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY is missing from .env"}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": config.ABUSEIPDB_MAX_AGE_DAYS},
            timeout=config.REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"error": f"request failed: {exc}"}

    if response.status_code == 429:
        return {"error": "rate limited (HTTP 429), try again later"}
    if response.status_code != 200:
        return {"error": f"HTTP {response.status_code}"}

    data = response.json()["data"]
    return {
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
        "abuse_confidence_score": data.get("abuseConfidenceScore") or 0,
        "total_reports": data.get("totalReports") or 0,
        "last_reported_at": data.get("lastReportedAt"),
        "is_tor": data.get("isTor"),
    }
