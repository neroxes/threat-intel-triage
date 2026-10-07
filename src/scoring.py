"""Risk engine: turns raw API results into a score, a level, and the reasons why."""

LEVEL_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _ok(result):
    return bool(result) and "error" not in result


def calculate_risk(vt_result, abuse_result):
    """Return {"score": int, "level": str, "reasons": [str]}."""
    score = 0
    reasons = []
    
    if not _ok(vt_result) and not _ok(abuse_result):
        vt_err = (vt_result or {}).get("error", "no data")
        ab_err = (abuse_result or {}).get("error", "no data")
        return {
            "score": 0,
            "level": "UNKNOWN",
            "reasons": [f"VirusTotal: {vt_err}", f"AbuseIPDB: {ab_err}"],
        }

    # --- VirusTotal (max 60 points) ---
    if _ok(vt_result):
        stats = vt_result.get("analysis_stats", {})
        malicious = stats.get("malicious", 0)
        if malicious == 0:
            points = 0
        elif malicious <= 5:
            points = 20
        elif malicious <= 20:
            points = 40
        else:
            points = 60
        score += points
        reasons.append(f"VirusTotal: {malicious} scanner(s) flagged it malicious (+{points})")
    else:
        reasons.append(f"VirusTotal unavailable ({vt_result.get('error') if vt_result else 'no data'})")

    # --- AbuseIPDB (max 40 points) ---
    if _ok(abuse_result):
        abuse_score = abuse_result.get("abuse_confidence_score") or 0
        if abuse_score <= 20:
            points = 0
        elif abuse_score <= 50:
            points = 15
        elif abuse_score <= 80:
            points = 30
        else:
            points = 40
        score += points
        reasons.append(f"AbuseIPDB: confidence score {abuse_score}/100 (+{points})")
    else:
        reasons.append(f"AbuseIPDB unavailable ({abuse_result.get('error') if abuse_result else 'no data'})")

    # --- Final level ---
    if score <= 20:
        level = "LOW"
    elif score <= 50:
        level = "MEDIUM"
    elif score <= 75:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {"score": score, "level": level, "reasons": reasons}
