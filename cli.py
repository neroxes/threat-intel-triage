"""Threat Intel Triage Tool - command line interface.

Examples:
    python cli.py 8.8.8.8
    python cli.py 8.8.8.8 1.1.1.1 -o results.csv
    python cli.py -f sample_logs/auth.log -o report.csv     (also analyzes SSH behavior)
    python cli.py -f ips.txt -o report.json --no-cache
"""
import argparse
import sys

from src import behavior as behavior_mod
from src import parser as ip_parser
from src import report, scoring, verdict
from src.cache import Cache
from src.sources import abuseipdb, virustotal


def check_ip(ip, cache=None):
    """Look up one IP (using the cache if possible) and score its reputation."""
    from_cache = False
    cached = cache.get(ip) if cache else None

    if cached:
        vt_result, abuse_result = cached["vt"], cached["abuse"]
        from_cache = True
    else:
        vt_result = virustotal.lookup(ip)
        abuse_result = abuseipdb.lookup(ip)
        # Only cache clean results, so failed lookups get retried next time.
        if cache and "error" not in vt_result and "error" not in abuse_result:
            cache.set(ip, {"vt": vt_result, "abuse": abuse_result})

    return {
        "ip": ip,
        "vt": vt_result,
        "abuse": abuse_result,
        "risk": scoring.calculate_risk(vt_result, abuse_result),
        "from_cache": from_cache,
    }


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Check IP addresses against VirusTotal and AbuseIPDB, analyze SSH log behavior, "
                    "and rank everything by risk."
    )
    p.add_argument("ips", nargs="*", help="one or more IP addresses")
    p.add_argument("-f", "--file", help="text file or log file to extract IPs from")
    p.add_argument("-o", "--output", help="save results to this file (.csv or .json)")
    p.add_argument("--no-cache", action="store_true", help="ignore and do not update the cache")
    return p


def main():
    args = build_arg_parser().parse_args()

    # 1. Gather text to search for IPs.
    text = " ".join(args.ips)
    file_text = ""
    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="ignore") as f:
                file_text = f.read()
        except OSError as exc:
            print(f"Could not read {args.file}: {exc}")
            return 1
        text += "\n" + file_text
    if not text.strip():
        text = input("Enter an IP address: ")

    # 2. Extract and filter.
    ip_counts = ip_parser.extract_ips(text)
    if not ip_counts:
        print("No valid IP addresses found.")
        return 1
    public, skipped = ip_parser.split_public_private(ip_counts)

    # 3. Behavior analysis (only meaningful when the input is a log).
    behavior_map = behavior_mod.analyze_log(file_text) if file_text else {}

    print(f"Found {len(ip_counts)} unique IP(s): {len(public)} public, {len(skipped)} skipped (private/reserved).")
    for ip in skipped:
        b = behavior_map.get(ip)
        note = ""
        if b and (b["brute_force"] or b["success_after_failures"]):
            note = f"  <-- WARNING: internal IP with {b['failed_logins']} failed logins"
        print(f"  skipped {ip}{note}")
    if not public:
        return 0

    # 4. Look up and score each public IP.
    cache = None if args.no_cache else Cache()
    entries = []
    for i, (ip, count) in enumerate(public.items(), start=1):
        print(f"[{i}/{len(public)}] Checking {ip} ...")
        entry = check_ip(ip, cache)
        entry["times_seen"] = count
        entries.append(entry)
    if cache:
        cache.close()

    # 5. Combine reputation + behavior into a verdict, worst first.
    verdict.apply(entries, behavior_map)

    # 6. Show results.
    print("\n" + "=" * 70)
    print(" RESULTS (highest risk first)")
    print("=" * 70)
    for e in entries:
        v, r = e["verdict"], e["risk"]
        tag = " (cached)" if e["from_cache"] else ""
        print(f"\n[{v['final_level']:<8}] {e['ip']}  seen {e['times_seen']}x{tag}")
        print(f"    ACTION : {v['action']}")
        print(f"    WHY    : {v['summary']}")
        print(f"    Reputation score {r['score']}/100 ({r['level']})")
        for reason in r["reasons"]:
            print(f"      - {reason}")

    suspects = [e["ip"] for e in entries if e["behavior"] and e["behavior"]["success_after_failures"]]
    brutes = [e["ip"] for e in entries if e["behavior"] and e["behavior"]["brute_force"]]
    if behavior_map:
        print("\n" + "-" * 70)
        print(f" Log analysis: {len(brutes)} IP(s) with brute-force behavior, "
              f"{len(suspects)} possible compromise(s).")
        if suspects:
            print(f" !! CHECK IMMEDIATELY: {', '.join(suspects)}")

    # 7. Export.
    if args.output:
        report.export(entries, args.output)
        print(f"\nSaved report to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
