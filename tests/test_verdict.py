from src.verdict import BLOCK, INVESTIGATE, NONE, apply, assess


def entry(level, ip="1.2.3.4", score=0, tor=False):
    return {"ip": ip, "times_seen": 1,
            "vt": {"analysis_stats": {"malicious": 0}}, "abuse": {"abuse_confidence_score": 0, "is_tor": tor},
            "risk": {"level": level, "score": score, "reasons": []}}


def beh(failed=0, brute=False, success=False):
    return {"failed_logins": failed, "usernames": ["root"], "duration_seconds": 60.0,
            "failures_per_minute": float(failed), "successful_logins": 1 if success else 0,
            "failures_before_success": failed if success else 0,
            "brute_force": brute, "success_after_failures": success}


def test_clean_ip_no_action():
    v = assess(entry("LOW"))
    assert v["final_level"] == "LOW" and v["action"] == NONE


def test_brute_force_on_clean_ip_is_raised_to_high_and_blocked():
    v = assess(entry("LOW"), beh(40, brute=True))
    assert v["final_level"] == "HIGH" and v["action"] == BLOCK


def test_brute_force_plus_bad_reputation_is_critical():
    assert assess(entry("HIGH"), beh(40, brute=True))["final_level"] == "CRITICAL"


def test_success_after_failures_is_critical_investigate():
    v = assess(entry("LOW"), beh(12, brute=True, success=True))
    assert v["final_level"] == "CRITICAL" and v["action"] == INVESTIGATE
    assert "LOGGED IN SUCCESSFULLY" in v["summary"]


def test_unknown_reputation_with_brute_force_is_high():
    assert assess(entry("UNKNOWN"), beh(20, brute=True))["final_level"] == "HIGH"


def test_tor_is_labeled():
    assert "Tor exit" in assess(entry("CRITICAL", tor=True))["summary"]


def test_ranking_puts_compromise_first():
    entries = [entry("CRITICAL", "1.1.1.1", 80), entry("LOW", "2.2.2.2")]
    apply(entries, {"2.2.2.2": beh(12, brute=True, success=True)})
    assert entries[0]["ip"] == "2.2.2.2"
