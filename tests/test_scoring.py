from src.scoring import calculate_risk


def vt(malicious):
    return {"analysis_stats": {"malicious": malicious}}


def abuse(score):
    return {"abuse_confidence_score": score}


def test_clean_ip_is_low():
    r = calculate_risk(vt(0), abuse(0))
    assert (r["score"], r["level"]) == (0, "LOW")


def test_example_from_readme_is_critical():
    r = calculate_risk(vt(8), abuse(90))
    assert (r["score"], r["level"]) == (80, "CRITICAL")


def test_medium_and_high_boundaries():
    assert calculate_risk(vt(3), abuse(30))["level"] == "MEDIUM"   # 20 + 15 = 35
    assert calculate_risk(vt(10), abuse(60))["level"] == "HIGH"    # 40 + 30 = 70


def test_max_score_is_100():
    assert calculate_risk(vt(50), abuse(100))["score"] == 100


def test_one_source_failing_still_scores():
    r = calculate_risk({"error": "HTTP 429"}, abuse(90))
    assert r["score"] == 40
    assert any("VirusTotal unavailable" in x for x in r["reasons"])


def test_both_failing_is_unknown():
    r = calculate_risk({"error": "x"}, {"error": "y"})
    assert r["level"] == "UNKNOWN"


def test_reasons_are_explained():
    r = calculate_risk(vt(8), abuse(90))
    assert len(r["reasons"]) == 2
