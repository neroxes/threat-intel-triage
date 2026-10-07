from src.parser import extract_ips, is_public, split_public_private


def test_extracts_ips_from_log_line():
    line = "Failed password for root from 45.33.32.156 port 22 ssh2"
    assert extract_ips(line) == {"45.33.32.156": 1}


def test_counts_repeats_and_sorts_by_frequency():
    text = "1.1.1.1 8.8.8.8 8.8.8.8 8.8.8.8"
    assert list(extract_ips(text).items()) == [("8.8.8.8", 3), ("1.1.1.1", 1)]


def test_rejects_invalid_ips():
    assert extract_ips("999.1.1.1 and 300.300.300.300") == {}


def test_private_and_reserved_are_not_public():
    for ip in ["192.168.1.10", "10.0.0.5", "172.16.0.1", "127.0.0.1", "169.254.1.1"]:
        assert not is_public(ip)


def test_public_ip_is_public():
    assert is_public("8.8.8.8")


def test_split_public_private():
    public, skipped = split_public_private({"8.8.8.8": 2, "192.168.1.1": 5})
    assert public == {"8.8.8.8": 2}
    assert skipped == {"192.168.1.1": 5}
