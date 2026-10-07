"""Find IP addresses inside any text (a plain list, an auth.log, an Apache log...)."""
import ipaddress
import re
from collections import Counter

# Matches things that look like IPv4 addresses. We validate each match afterwards,
# so something like 999.1.1.1 is thrown away.
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ips(text):
    """Return {ip: times_seen} for every valid IPv4 address in the text,
    sorted from most to least frequent."""
    counts = Counter()
    for candidate in IPV4_PATTERN.findall(text):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        counts[candidate] += 1
    return dict(counts.most_common())


def is_public(ip):
    """True if the IP lives on the public internet (so online lookups make sense).
    Private (192.168.x.x), loopback, link-local and reserved ranges return False."""
    return ipaddress.ip_address(ip).is_global


def split_public_private(ip_counts):
    """Split {ip: count} into (public, skipped) dictionaries."""
    public = {ip: n for ip, n in ip_counts.items() if is_public(ip)}
    skipped = {ip: n for ip, n in ip_counts.items() if not is_public(ip)}
    return public, skipped
