# Threat Intel Triage Tool

Feed it an SSH log. It extracts every IP, checks each one's **reputation** (VirusTotal, AbuseIPDB),
analyzes its **behavior** in your own log (failed logins, usernames tried, success after failures),
and combines both into a **verdict with a recommended action**, ranked worst first.

> **185.220.101.1: CRITICAL, BLOCK at firewall.** Tor exit node, flagged by 13 scanners. 40 failed SSH
> logins in 78s (30.8/min) against root, admin, oracle, test.
>
> **91.240.118.172: CRITICAL, INVESTIGATE NOW.** 12 failed logins, then **logged in successfully**.

Reputation alone answers "is this IP known to be bad?". Behavior answers "what did it actually do to *my* server?"
Combining them catches things reputation misses (a brand-new attacker nobody has reported yet).

## Features
- **Behavior analysis of SSH logs:** failed-login counts, speed (per minute), usernames tried
- **Detects success after failures** (possible compromise), the pattern a SOC analyst most needs to catch
- **Verdict engine:** final level + recommended action (Block / Investigate / Monitor / No action) + plain-English summary
- Tor exit detection (via AbuseIPDB) and data-center labelling
- Warns about **internal** IPs that show brute-force behavior, even though they are not looked up online
- Extracts IPs from plain lists or real logs (SSH `auth.log`, Apache, firewall logs)
- Skips private / loopback / reserved addresses automatically
- Respects the VirusTotal free-tier rate limit (about 4 requests/minute)
- SQLite cache (24h) so repeat IPs cost zero API calls
- Explains every score ("8 scanners flagged it, abuse score 90")
- Ranks results worst-first, using how often each IP appears in the log as a tie-breaker
- Exports to CSV or JSON
- Unit tests with `pytest`

## Setup
```bash
pip install -r requirements.txt
cp .env.example .env      # then paste your real API keys into .env
```
Free keys: [VirusTotal](https://www.virustotal.com) and [AbuseIPDB](https://www.abuseipdb.com).
**Never commit your real `.env`.**

## Dashboard (Streamlit)
```bash
streamlit run app.py
```
Paste IPs or upload a log, click **Check IPs**, and get a color-coded ranked table, risk breakdown chart, per-IP explanations, and CSV/JSON downloads.

## Command-line usage
```bash
python cli.py 8.8.8.8                          # one IP
python cli.py 8.8.8.8 1.1.1.1 -o results.csv   # several IPs, save CSV
python cli.py -f sample_logs/auth.log -o report.csv
python cli.py -f ips.txt -o report.json --no-cache
python cli.py                                  # interactive prompt
```

## How the verdict works
| Situation | Final level | Action |
|---|---|---|
| Failed repeatedly, then logged in successfully | CRITICAL | Investigate now: possible compromise |
| Brute force + bad reputation (HIGH/CRITICAL) | CRITICAL | Block at firewall |
| Brute force + clean or unknown reputation | at least HIGH | Block at firewall |
| No suspicious behavior | reputation level | Block (CRITICAL) / Monitor closely (HIGH) / Monitor (MEDIUM) / None (LOW) |

Brute force = 5+ failed logins from one IP (change `BRUTE_FORCE_THRESHOLD` in `src/config.py`).
Failures that happen *after* a successful login do not count as "success after failures".

## How reputation scoring works
| Source | Signal | Points |
|---|---|---|
| VirusTotal | 0 malicious detections | 0 |
| | 1-5 | 20 |
| | 6-20 | 40 |
| | 21+ | 60 |
| AbuseIPDB | confidence 0-20 | 0 |
| | 21-50 | 15 |
| | 51-80 | 30 |
| | 81-100 | 40 |

Total (max 100): 0-20 LOW, 21-50 MEDIUM, 51-75 HIGH, 76-100 CRITICAL.
If both sources fail, the result is UNKNOWN. If one fails, the other is still used.

## Project layout
```
cli.py              command-line interface
app.py              Streamlit dashboard
src/config.py       settings and API keys
src/parser.py       IP extraction and private-IP filtering
src/sources/        one module per threat-intel provider
src/scoring.py      reputation scoring
src/behavior.py     SSH log behavior analysis
src/verdict.py      combines reputation + behavior into a verdict
src/cache.py        SQLite cache
src/report.py       CSV / JSON export
tests/              pytest unit tests
```

## Limitations
- A LOW score is not a guarantee: brand-new attackers may not be reported yet.
- Shared IPs (VPNs, university or office NAT, cloud providers) can score high without every user being malicious.
- IPv4 only for now, and behavior analysis supports SSH (sshd) logs only.
- Assumes log lines are in chronological order; syslog timestamps have no year, so the current year is assumed.
- Free API tiers limit how many IPs you can check per day.

## Roadmap
- Done: log parsing, caching, CSV/JSON export, Streamlit dashboard, SSH behavior analysis, verdicts
- Next: Apache/web-log behavior (scanners, 404 floods), firewall block-list export, Slack/email alerts, GreyNoise
