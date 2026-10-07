"""Threat Intel Triage - Streamlit dashboard.

Run with:  python -m streamlit run app.py
"""
import csv
import io
import json

import altair as alt
import pandas as pd
import streamlit as st

from cli import check_ip
from src import behavior as behavior_mod
from src import config, parser as ip_parser, report, verdict
from src.cache import Cache

LEVEL_COLORS = {
    "CRITICAL": "#d32f2f",
    "HIGH": "#f57c00",
    "MEDIUM": "#fbc02d",
    "LOW": "#388e3c",
    "UNKNOWN": "#757575",
}

st.set_page_config(page_title="Threat Intel Triage", page_icon="🛡️", layout="wide")


# ---------- helpers ----------
def to_csv_bytes(entries):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=report.CSV_COLUMNS)
    writer.writeheader()
    for e in entries:
        writer.writerow(report.flatten(e))
    return buf.getvalue().encode("utf-8")


def color_level(value):
    color = LEVEL_COLORS.get(value, "#757575")
    text = "black" if value == "MEDIUM" else "white"
    return f"background-color: {color}; color: {text}; font-weight: bold"


def run_checks(ip_counts, use_cache, behavior_map):
    """Look up every IP, updating a progress bar, then combine reputation + behavior."""
    cache = Cache() if use_cache else None
    entries = []
    bar = st.progress(0.0)
    status = st.empty()
    total = len(ip_counts)
    for i, (ip, count) in enumerate(ip_counts.items(), start=1):
        status.write(f"Checking **{ip}** ({i} of {total})...")
        entry = check_ip(ip, cache)
        entry["times_seen"] = count
        entries.append(entry)
        bar.progress(i / total)
    if cache:
        cache.close()
    bar.empty()
    status.empty()
    return verdict.apply(entries, behavior_map)


# ---------- sidebar ----------
with st.sidebar:
    st.header("Settings")
    use_cache = st.checkbox("Use cache (24h)", value=True, help="Skips IPs you already checked recently.")
    max_ips = st.number_input("Max IPs per run", min_value=1, max_value=200, value=25,
                              help="Protects your free API limits.")
    st.divider()
    st.caption("API keys")
    st.write(("✅" if config.VT_API_KEY else "❌") + " VirusTotal key")
    st.write(("✅" if config.ABUSEIPDB_API_KEY else "❌") + " AbuseIPDB key")
    if not (config.VT_API_KEY and config.ABUSEIPDB_API_KEY):
        st.warning("Add missing keys to your .env file and restart the app.")
    st.divider()
    st.caption(f"Brute force = {config.BRUTE_FORCE_THRESHOLD}+ failed logins from one IP.")

# ---------- input ----------
st.title("🛡️ Threat Intel Triage")
st.write("Paste IPs or upload an SSH log. The tool checks each IP's **reputation** (VirusTotal, AbuseIPDB), "
         "analyzes its **behavior** in your log (failed logins, success after failures), and gives a "
         "verdict with a recommended action.")

col_paste, col_upload = st.columns(2)
with col_paste:
    pasted = st.text_area("Paste IPs or log lines", height=160, placeholder="8.8.8.8\n1.1.1.1\n45.33.32.156")
with col_upload:
    uploaded = st.file_uploader("...or upload a file (try sample_logs/auth.log)", type=["txt", "log", "csv"])

text = pasted
if uploaded is not None:
    text += "\n" + uploaded.getvalue().decode("utf-8", errors="ignore")

ip_counts = ip_parser.extract_ips(text) if text.strip() else {}
public, skipped = ip_parser.split_public_private(ip_counts)
behavior_map = behavior_mod.analyze_log(text) if text.strip() else {}

if ip_counts:
    st.info(f"Found **{len(ip_counts)}** unique IP(s): **{len(public)}** public, "
            f"**{len(skipped)}** private/reserved (skipped).")
    for ip in skipped:
        b = behavior_map.get(ip)
        if b and (b["brute_force"] or b["success_after_failures"]):
            st.warning(f"Internal IP **{ip}** shows {b['failed_logins']} failed logins. "
                       "It was not looked up online, but it may be worth investigating.")
    if len(public) > max_ips:
        st.warning(f"Only the first {int(max_ips)} IPs will be checked (change this in the sidebar).")
        public = dict(list(public.items())[: int(max_ips)])

    if public:
        fresh = len(public)
        if use_cache:
            probe = Cache()
            fresh = sum(1 for ip in public if probe.get(ip) is None)
            probe.close()
        if fresh:
            st.caption(f"About {fresh} new lookup(s), roughly {fresh * config.VT_DELAY_SECONDS // 60 + 1} minute(s) "
                       "because of the VirusTotal free-tier limit.")

        if st.button("Check IPs", type="primary"):
            st.session_state["entries"] = run_checks(public, use_cache, behavior_map)

# ---------- results ----------
entries = st.session_state.get("entries")
if entries:
    st.divider()
    st.subheader("Results (highest risk first)")

    suspects = [e["ip"] for e in entries if e["behavior"] and e["behavior"]["success_after_failures"]]
    brutes = [e["ip"] for e in entries if e["behavior"] and e["behavior"]["brute_force"]]
    if suspects:
        st.error("🚨 **Possible compromise:** " + ", ".join(suspects) +
                 " failed repeatedly and then logged in successfully. Investigate immediately.")
    if brutes:
        st.warning(f"⚠️ {len(brutes)} IP(s) show brute-force behavior: " + ", ".join(brutes))

    levels = [e["verdict"]["final_level"] for e in entries]
    counts = {lvl: levels.count(lvl) for lvl in LEVEL_COLORS}
    cols = st.columns(len(LEVEL_COLORS))
    for col, (lvl, n) in zip(cols, counts.items()):
        col.metric(lvl, n)

    df = pd.DataFrame([report.flatten(e) for e in entries])
    show = df[["ip", "final_level", "action", "failed_logins", "usernames_tried", "risk_score",
               "abuse_score", "vt_malicious", "is_tor", "vt_country", "isp"]].rename(
        columns={"risk_score": "reputation_score"})
    styler = show.style
    styler = styler.map(color_level, subset=["final_level"]) if hasattr(styler, "map") \
        else styler.applymap(color_level, subset=["final_level"])
    st.dataframe(styler, width="stretch", hide_index=True)

    chart_col, country_col = st.columns(2)
    with chart_col:
        st.caption("Final risk level breakdown")
        data = pd.DataFrame({"level": list(counts), "count": list(counts.values())})
        data = data[data["count"] > 0]
        pie = alt.Chart(data).mark_arc(innerRadius=50).encode(
            theta="count:Q",
            color=alt.Color("level:N", scale=alt.Scale(domain=list(LEVEL_COLORS), range=list(LEVEL_COLORS.values()))),
            tooltip=["level", "count"],
        )
        st.altair_chart(pie, width="stretch")
    with country_col:
        st.caption("Top countries")
        countries = df["vt_country"].dropna()
        if len(countries):
            st.bar_chart(countries.value_counts())
        else:
            st.write("No country data.")

    attackers = df[df["failed_logins"].fillna(0) > 0].sort_values("failed_logins", ascending=False)
    if len(attackers):
        st.caption("Failed SSH logins per IP")
        st.bar_chart(attackers.set_index("ip")["failed_logins"])

    st.subheader("Verdict details")
    for e in entries:
        v, r, b = e["verdict"], e["risk"], e["behavior"]
        with st.expander(f"[{v['final_level']}] {e['ip']}  -  {v['action']}"):
            st.write(v["summary"])
            st.write(f"**Reputation score:** {r['score']}/100 ({r['level']})")
            for reason in r["reasons"]:
                st.write("- " + reason)
            if b:
                st.write(f"**Behavior:** {b['failed_logins']} failed logins, "
                         f"{b['failures_per_minute']}/min, {b['unique_usernames']} unique username(s), "
                         f"{b['successful_logins']} successful login(s).")

    d1, d2, _ = st.columns([1, 1, 4])
    d1.download_button("Download CSV", to_csv_bytes(entries), "threat_report.csv", "text/csv")
    d2.download_button("Download JSON", json.dumps(entries, indent=2), "threat_report.json", "application/json")

    st.caption("A LOW score is not a guarantee of safety, and a high score can hit shared IPs such as VPNs "
               "or Tor exits. Treat results as one piece of evidence.")
