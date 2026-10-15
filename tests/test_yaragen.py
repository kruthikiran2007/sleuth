"""Tests for sleuth.yara_gen (Feature 4: YARA rule auto-generator).

Never executes any target: fixtures are crafted byte blobs with
distinctive-but-harmless marker strings. Compile/match tests are skipped
when yara-python is unavailable.
"""

import pytest

from sleuth import cli, yara_gen
from sleuth.yara_gen import (
    pick_distinctive_strings,
    build_rule_text,
    generate_rule,
)

needs_yara = pytest.mark.skipif(
    not yara_gen._YARA_AVAILABLE, reason="yara-python not installed"
)

# Distinctive marker strings (long, mixed-case, high entropy) plus
# boilerplate that the rarity heuristic should deprioritize.
MARKERS = [
    "Xq9#Mutex_Global_7f3a9c2e1b5d",
    "C2_Endpoint_alpha_bravo_99182",
    "PdbLeftover_CryptEngine_v9_release",
    "the quick brown fox",  # boilerplate-ish, should rank lower
    "error failed",         # boilerplate, should rank lower
]


def _blob(strings):
    return b"\x00".join(s.encode() for s in strings) + b"\x00"


def test_pick_distinctive_prefers_unique():
    chosen = pick_distinctive_strings(MARKERS, top_n=3)
    assert "Xq9#Mutex_Global_7f3a9c2e1b5d" in chosen
    assert "error failed" not in chosen


def test_pick_distinctive_filters_short():
    chosen = pick_distinctive_strings(["ab", "cd", "Xq9#Mutex_Global_7f3a9c2e1b5d"])
    assert chosen == ["Xq9#Mutex_Global_7f3a9c2e1b5d"]


def test_pick_distinctive_dedupes():
    chosen = pick_distinctive_strings(
        ["Xq9#Mutex_Global_7f3a9c2e1b5d"] * 5)
    assert chosen.count("Xq9#Mutex_Global_7f3a9c2e1b5d") == 1


def test_build_rule_text_shape():
    text = build_rule_text(["alpha123_XZ", "beta456_QW"], "deadbeef")
    assert text.startswith("rule sleuth_gen_deadbeef {")
    assert '$s0 = "alpha123_XZ"' in text
    assert "of them" in text


def test_build_rule_text_escapes_quotes():
    text = build_rule_text(['say "hi" \\ ok_path'], "aabbccdd")
    assert '\\"hi\\"' in text
    assert "\\\\" in text


@needs_yara
def test_generate_rule_compiles_and_matches(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(_blob(MARKERS * 2))
    result = generate_rule(str(p))
    assert result["ok"] is True
    assert result["rule_text"].startswith("rule sleuth_gen_")
    assert result["string_count"] >= 3


@needs_yara
def test_generate_rule_writes_file(tmp_path):
    src = tmp_path / "sample.bin"
    src.write_bytes(_blob(MARKERS * 2))
    out = tmp_path / "rule.yar"
    result = generate_rule(str(src), output_path=str(out))
    assert result["ok"] is True
    assert result["written_to"] == str(out)
    assert out.read_text().startswith("rule sleuth_gen_")


@needs_yara
def test_generate_rule_too_few_strings(tmp_path):
    p = tmp_path / "tiny.bin"
    p.write_bytes(b"\x00hi\x00ok\x00")
    result = generate_rule(str(p))
    assert result["ok"] is False
    assert "too few distinctive strings" in result["reason"]
    assert result["written_to"] is None


@needs_yara
def test_generate_rule_missing_file():
    result = generate_rule("/no/such/file.bin")
    assert result["ok"] is False


def test_generate_rule_graceful_without_yara(tmp_path, monkeypatch):
    monkeypatch.setattr(yara_gen, "_YARA_AVAILABLE", False)
    p = tmp_path / "sample.bin"
    p.write_bytes(_blob(MARKERS))
    result = generate_rule(str(p))
    assert result["ok"] is False
    assert "yara-python" in result["reason"]


@needs_yara
def test_gen_yara_cli(tmp_path, capsys):
    p = tmp_path / "sample.bin"
    p.write_bytes(_blob(MARKERS * 2))
    assert cli.main(["gen-yara", str(p)]) == 0
    out = capsys.readouterr().out
    assert "rule sleuth_gen_" in out
    assert "OK:" in out


@needs_yara
def test_gen_yara_cli_output_file(tmp_path, capsys):
    p = tmp_path / "sample.bin"
    p.write_bytes(_blob(MARKERS * 2))
    out = str(tmp_path / "hunt.yar")
    assert cli.main(["gen-yara", str(p), "-o", out]) == 0
    assert "rule written to" in capsys.readouterr().out
    with open(out) as f:
        assert f.read().startswith("rule sleuth_gen_")


def test_gen_yara_cli_missing_file(capsys):
    assert cli.main(["gen-yara", "/no/such/file.bin"]) == 1
    assert "error" in capsys.readouterr().err.lower()
