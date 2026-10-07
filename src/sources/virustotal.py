"""VirusTotal IP lookup."""
import time

import requests

from src import config

_last_call = 0.0


def lookup(ip):
    """Return a dict of results, or {"error": "..."} if something went wrong."""
    global _last_call

    if not config.VT_API_KEY:
        return {"error": "VT_API_KEY is missing from .env"}

    # Respect the free-tier rate limit.
    if _last_call:
        wait = config.VT_DELAY_SECONDS - (time.time() - _last_call)
        if wait > 0:
            time.sleep(wait)

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(
            url,
            headers={"x-apikey": config.VT_API_KEY},
            timeout=config.REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"error": f"request failed: {exc}"}
    finally:
        _last_call = time.time()

    if response.status_code == 429:
        return {"error": "rate limited (HTTP 429), try again later"}
    if response.status_code != 200:
        return {"error": f"HTTP {response.status_code}"}

    data = response.json()["data"]["attributes"]
    return {
        "country": data.get("country"),
        "asn": data.get("asn"),
        "as_owner": data.get("as_owner"),
        "reputation": data.get("reputation"),
        "analysis_stats": data.get("last_analysis_stats") or {},
    }
