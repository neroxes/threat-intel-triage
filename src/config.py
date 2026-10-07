"""Central place for settings and API keys."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

REQUEST_TIMEOUT = 10          # seconds before giving up on a slow API
CACHE_DB_PATH = ROOT / "cache.db"
CACHE_TTL_HOURS = 24          # how long a cached result stays fresh
VT_DELAY_SECONDS = 15         # VirusTotal free tier: ~4 requests per minute
ABUSEIPDB_MAX_AGE_DAYS = 90
BRUTE_FORCE_THRESHOLD = 5     # failed logins from one IP before we call it brute force
