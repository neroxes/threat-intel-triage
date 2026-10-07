from src.behavior import analyze_log, parse_time

BRUTE = "\n".join(
    f"Oct  6 02:14:{i:02d} server sshd[1]: Failed password for invalid user admin{i % 3} from 5.5.5.5 port {4000 + i} ssh2"
    for i in range(10)
)


def test_parse_syslog_time():
    t = parse_time("Oct  6 02:14:01 server sshd[1]: x", 2026)
    assert (t.month, t.day, t.hour, t.minute, t.second) == (10, 6, 2, 14, 1)


def test_parse_iso_time():
    t = parse_time("2026-10-06T02:14:01.123+00:00 host sshd: x", 2000)
    assert (t.year, t.month, t.day) == (2026, 10, 6)


def test_detects_brute_force():
    b = analyze_log(BRUTE, year=2026)["5.5.5.5"]
    assert b["failed_logins"] == 10 and b["brute_force"]
    assert not b["success_after_failures"]
    assert b["duration_seconds"] == 9 and b["failures_per_minute"] > 50


def test_below_threshold_is_not_brute_force():
    log = "\n".join(f"Oct  6 02:14:0{i} h sshd[1]: Failed password for admin from 6.6.6.6 port 1 ssh2" for i in range(3))
    b = analyze_log(log, year=2026)["6.6.6.6"]
    assert b["failed_logins"] == 3 and not b["brute_force"]


def test_success_after_failures_is_flagged():
    log = BRUTE.replace("5.5.5.5", "7.7.7.7") + "\nOct  6 02:15:00 h sshd[1]: Accepted password for root from 7.7.7.7 port 9 ssh2"
    b = analyze_log(log, year=2026)["7.7.7.7"]
    assert b["success_after_failures"] and b["failures_before_success"] == 10


def test_success_first_then_failures_is_not_compromise():
    log = ("Oct  6 02:00:00 h sshd[1]: Accepted publickey for bob from 8.8.4.4 port 1 ssh2\n" +
           BRUTE.replace("5.5.5.5", "8.8.4.4"))
    b = analyze_log(log, year=2026)["8.8.4.4"]
    assert b["brute_force"] and not b["success_after_failures"]


def test_normal_login_is_not_flagged():
    b = analyze_log("Oct  6 02:00:00 h sshd[1]: Accepted publickey for bob from 9.9.9.9 port 1 ssh2", year=2026)["9.9.9.9"]
    assert b["successful_logins"] == 1 and not b["brute_force"] and not b["success_after_failures"]


def test_invalid_ip_ignored():
    assert analyze_log("Failed password for root from 999.1.1.1 port 1 ssh2") == {}
