"""Tests for string extraction, entropy, and indicators."""

from sleuth import strings as strings_mod


def test_extract_strings_basic():
    data = b"\x00\x01hello\x00world!!\xff\xfe"
    assert strings_mod.extract_strings(data) == ["hello", "world!!"]


def test_extract_strings_min_length():
    data = b"abc\x00abcdef\x00"
    assert strings_mod.extract_strings(data, min_len=4) == ["abcdef"]
    assert strings_mod.extract_strings(data, min_len=3) == ["abc", "abcdef"]


def test_extract_strings_empty():
    assert strings_mod.extract_strings(b"") == []
    assert strings_mod.extract_strings(b"\x00\x01\x02") == []


def test_entropy_known_values():
    # All identical bytes -> 0 entropy.
    assert strings_mod.shannon_entropy(b"\x00" * 100) == 0.0
    # Empty -> 0.
    assert strings_mod.shannon_entropy(b"") == 0.0
    # Two equally likely bytes -> 1 bit.
    assert abs(strings_mod.shannon_entropy(b"\x00\xff" * 50) - 1.0) < 1e-9
    # 256 equally likely bytes -> 8 bits (max).
    assert abs(strings_mod.shannon_entropy(bytes(range(256))) - 8.0) < 1e-9


def test_find_indicators():
    found = strings_mod.find_indicators(
        ["visit http://example.com/x", "server 10.0.0.5 down", "no secrets here",
         "bad 999.999.1.1 not an ip"]
    )
    assert found["ips"] == ["10.0.0.5"]
    assert found["urls"] == ["http://example.com/x"]


def test_find_indicators_dedup():
    found = strings_mod.find_indicators(["ip 1.2.3.4", "again 1.2.3.4"])
    assert found["ips"] == ["1.2.3.4"]
