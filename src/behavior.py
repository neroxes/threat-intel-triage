"""Behavior analysis: what did each IP actually DO in the log?

Reads SSH auth logs (syslog style, e.g. /var/log/auth.log) and, for every IP, works out:
  - how many failed logins, against which usernames, and how fast
  - whether it later logged in successfully (success after failures = possible compromise)
"""
import ipaddress
import re
from datetime import datetime

from src import config

IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
FAILED = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from " + IP)
INVALID = re.compile(r"Invalid user (\S+) from " + IP)
ACCEPTED = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from " + IP)

SYSLOG_TIME = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
ISO_TIME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def parse_time(line, year):
    """Return a datetime for the start of a log line, or None if it has no timestamp.
    Syslog lines have no year, so we assume `year`."""
    m = ISO_TIME.match(line)
    if m:
        return datetime(*(int(x) for x in m.groups()))
    m = SYSLOG_TIME.match(line)
    if m and m.group(1) in MONTHS:
        mon, day, hh, mm, ss = m.group(1), *(int(x) for x in m.groups()[1:])
        try:
            return datetime(year, MONTHS[mon], day, hh, mm, ss)
        except ValueError:
            return None
    return None


def _valid(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def analyze_log(text, year=None, threshold=None):
    """Return {ip: behavior_dict} for every IP that failed or succeeded a login."""
    year = year or datetime.now().year
    threshold = threshold or config.BRUTE_FORCE_THRESHOLD
    raw = {}

    def rec(ip):
        return raw.setdefault(ip, {"failed": 0, "users": {}, "times": [], "accepted": 0,
                                   "failures_before_success": 0})

    for line in text.splitlines():
        when = parse_time(line, year)

        m = FAILED.search(line)
        if m and _valid(m.group(2)):
            r = rec(m.group(2))
            r["failed"] += 1
            r["users"][m.group(1)] = r["users"].get(m.group(1), 0) + 1
            if when:
                r["times"].append(when)
            continue

        m = INVALID.search(line)
        if m and _valid(m.group(2)):
            r = rec(m.group(2))
            r["users"].setdefault(m.group(1), 0)
            continue

        m = ACCEPTED.search(line)
        if m and _valid(m.group(2)):
            r = rec(m.group(2))
            r["accepted"] += 1
            # Remember how many failures came before the FIRST successful login.
            if r["accepted"] == 1:
                r["failures_before_success"] = r["failed"]
            if when:
                r["times"].append(when)

    results = {}
    for ip, r in raw.items():
        times = sorted(r["times"])
        duration = (times[-1] - times[0]).total_seconds() if len(times) >= 2 else 0.0
        per_minute = round(r["failed"] * 60 / max(duration, 1.0), 1) if r["failed"] else 0.0
        users = sorted(r["users"], key=lambda u: -r["users"][u])
        results[ip] = {
            "failed_logins": r["failed"],
            "usernames": users[:8],
            "unique_usernames": len(users),
            "first_seen": times[0].isoformat() if times else None,
            "last_seen": times[-1].isoformat() if times else None,
            "duration_seconds": duration,
            "failures_per_minute": per_minute,
            "successful_logins": r["accepted"],
            "failures_before_success": r["failures_before_success"],
            "brute_force": r["failed"] >= threshold,
            "success_after_failures": r["accepted"] > 0 and r["failures_before_success"] >= threshold,
        }
    return results
