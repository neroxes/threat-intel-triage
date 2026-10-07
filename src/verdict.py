"""Verdict engine: combines REPUTATION (what the internet says) with BEHAVIOR (what the IP did
on our server) into one final level, a recommended action, and a plain-English summary."""
from src.scoring import LEVEL_ORDER

BLOCK = "BLOCK at firewall"
INVESTIGATE = "INVESTIGATE NOW: possible compromise"
MONITOR = "MONITOR"
CLOSE_WATCH = "Monitor closely, consider blocking"
REVIEW = "Review manually (no reputation data)"
NONE = "No action needed"


def _higher(a, b):
    return a if LEVEL_ORDER[a] >= LEVEL_ORDER[b] else b


def assess(entry, behavior=None):
    """Return {"final_level", "action", "summary"} for one result entry."""
    rep = entry["risk"]["level"]
    level = rep
    compromised = bool(behavior and behavior["success_after_failures"])
    brute = bool(behavior and behavior["brute_force"])

    if compromised:
        level, action = "CRITICAL", INVESTIGATE
    elif brute:
        level = "CRITICAL" if rep in ("HIGH", "CRITICAL") else _higher(rep, "HIGH")
        action = BLOCK
    else:
        level = rep
        action = {"CRITICAL": BLOCK, "HIGH": CLOSE_WATCH, "MEDIUM": MONITOR,
                  "LOW": NONE, "UNKNOWN": REVIEW}[rep]

    # ---- plain-English summary ----
    parts = []
    abuse = entry.get("abuse") or {}
    vt = entry.get("vt") or {}
    if abuse.get("is_tor"):
        parts.append("Tor exit node (traffic is anonymized, so judge by what it did).")
    if "error" not in vt and vt:
        mal = (vt.get("analysis_stats") or {}).get("malicious", 0)
        if mal:
            parts.append(f"Flagged malicious by {mal} VirusTotal scanner(s).")
    if "error" not in abuse and abuse:
        if abuse.get("abuse_confidence_score"):
            parts.append(f"AbuseIPDB confidence {abuse['abuse_confidence_score']}/100.")
        if abuse.get("usage_type") and "data center" in abuse["usage_type"].lower():
            parts.append("Hosted in a data center.")
    if rep == "UNKNOWN":
        parts.append("Reputation lookups failed, so this verdict relies on log behavior only.")

    if behavior and behavior["failed_logins"]:
        users = ", ".join(behavior["usernames"][:4])
        speed = ""
        if behavior["duration_seconds"] > 0:
            speed = f" in {int(behavior['duration_seconds'])}s ({behavior['failures_per_minute']}/min)"
        parts.append(f"{behavior['failed_logins']} failed SSH login(s){speed}; tried usernames: {users}.")
    if compromised:
        parts.append(f"Then LOGGED IN SUCCESSFULLY after {behavior['failures_before_success']} failures.")
    elif behavior and behavior["successful_logins"]:
        parts.append(f"{behavior['successful_logins']} successful login(s), no failure pattern.")
    if not parts:
        parts.append("No reputation flags and no suspicious behavior found.")

    return {"final_level": level, "action": action, "summary": " ".join(parts)}


def rank_key(entry):
    """Sort key: worst first. Suspected compromises beat everything else at the same level."""
    v = entry.get("verdict")
    b = entry.get("behavior") or {}
    level = v["final_level"] if v else entry["risk"]["level"]
    return (LEVEL_ORDER[level], bool(b.get("success_after_failures")),
            b.get("failed_logins", 0), entry["risk"]["score"], entry.get("times_seen", 0))


def apply(entries, behavior_map=None):
    """Attach behavior + verdict to every entry, then sort worst-first."""
    behavior_map = behavior_map or {}
    for e in entries:
        e["behavior"] = behavior_map.get(e["ip"])
        e["verdict"] = assess(e, e["behavior"])
    entries.sort(key=rank_key, reverse=True)
    return entries
