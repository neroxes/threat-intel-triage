import csv
import json

from src.cache import Cache
from src.report import export


def test_cache_roundtrip(tmp_path):
    c = Cache(path=tmp_path / "c.db")
    assert c.get("8.8.8.8") is None
    c.set("8.8.8.8", {"vt": {"a": 1}, "abuse": {"b": 2}})
    assert c.get("8.8.8.8") == {"vt": {"a": 1}, "abuse": {"b": 2}}
    c.close()


def test_cache_expiry(tmp_path):
    c = Cache(path=tmp_path / "c.db", ttl_hours=1)
    c.set("1.1.1.1", {"x": 1})
    c.conn.execute("UPDATE lookups SET checked_at = checked_at - 7200")
    assert c.get("1.1.1.1") is None
    c.close()


ENTRY = {
    "ip": "8.8.8.8", "times_seen": 3, "from_cache": False,
    "vt": {"analysis_stats": {"malicious": 0}, "country": "US", "as_owner": "Google LLC", "reputation": 5},
    "abuse": {"abuse_confidence_score": 0, "total_reports": 2, "isp": "Google LLC"},
    "risk": {"score": 0, "level": "LOW", "reasons": ["a", "b"]},
}


def test_export_csv(tmp_path):
    out = tmp_path / "r.csv"
    export([ENTRY], out)
    rows = list(csv.DictReader(open(out)))
    assert rows[0]["ip"] == "8.8.8.8" and rows[0]["risk_level"] == "LOW"


def test_export_json(tmp_path):
    out = tmp_path / "r.json"
    export([ENTRY], out)
    assert json.load(open(out))[0]["ip"] == "8.8.8.8"
