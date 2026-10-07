"""Flatten results and export them as CSV or JSON."""
import csv
import json

CSV_COLUMNS = [
    "ip", "final_level", "action", "summary",
    "failed_logins", "usernames_tried", "failures_per_minute", "success_after_failures", "is_tor",
    "times_seen", "risk_level", "risk_score", "reasons",
    "vt_malicious", "vt_suspicious", "vt_harmless", "vt_reputation",
    "vt_country", "vt_as_owner",
    "abuse_score", "abuse_reports", "abuse_last_reported",
    "isp", "usage_type", "from_cache", "errors",
]


def flatten(entry):
    """Turn one result entry into a flat dict that fits in a CSV row."""
    vt = entry.get("vt") or {}
    ab = entry.get("abuse") or {}
    stats = vt.get("analysis_stats", {}) if "error" not in vt else {}
    errors = [
        f"{name}: {r['error']}"
        for name, r in (("VirusTotal", vt), ("AbuseIPDB", ab))
        if "error" in r
    ]
    risk = entry["risk"]
    verdict = entry.get("verdict") or {}
    beh = entry.get("behavior") or {}
    return {
        "ip": entry["ip"],
        "final_level": verdict.get("final_level", risk["level"]),
        "action": verdict.get("action"),
        "summary": verdict.get("summary"),
        "failed_logins": beh.get("failed_logins"),
        "usernames_tried": ", ".join(beh.get("usernames", [])) or None,
        "failures_per_minute": beh.get("failures_per_minute"),
        "success_after_failures": beh.get("success_after_failures"),
        "is_tor": ab.get("is_tor"),
        "times_seen": entry["times_seen"],
        "risk_level": risk["level"],
        "risk_score": risk["score"],
        "reasons": " | ".join(risk["reasons"]),
        "vt_malicious": stats.get("malicious"),
        "vt_suspicious": stats.get("suspicious"),
        "vt_harmless": stats.get("harmless"),
        "vt_reputation": vt.get("reputation"),
        "vt_country": vt.get("country"),
        "vt_as_owner": vt.get("as_owner"),
        "abuse_score": ab.get("abuse_confidence_score"),
        "abuse_reports": ab.get("total_reports"),
        "abuse_last_reported": ab.get("last_reported_at"),
        "isp": ab.get("isp"),
        "usage_type": ab.get("usage_type"),
        "from_cache": entry.get("from_cache", False),
        "errors": "; ".join(errors),
    }


def write_csv(entries, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for entry in entries:
            writer.writerow(flatten(entry))


def write_json(entries, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def export(entries, path):
    """Pick the format from the file extension (.csv or .json)."""
    if str(path).lower().endswith(".json"):
        write_json(entries, path)
    else:
        write_csv(entries, path)
