"""Tests for sleuth._paths: bundled rules resolve in any install layout."""

import os

from sleuth._paths import capa_rules_dir, rules_dir


def test_rules_dir_exists_and_has_starter_rules():
    d = rules_dir()
    assert os.path.isdir(d), "rules dir missing: %s" % d
    assert any(f.endswith(".yar") for f in os.listdir(d)), \
        "no .yar starter rules in %s" % d


def test_capa_rules_dir_exists_and_has_rules():
    d = capa_rules_dir()
    assert os.path.isdir(d), "capa rules dir missing: %s" % d
    ymls = [f for f in os.listdir(d) if f.endswith(".yml")]
    assert len(ymls) >= 1, "no capa .yml rules in %s" % d


def test_rules_dir_inside_package():
    # Bundled as package data: must live under the installed sleuth package.
    import sleuth
    pkg = os.path.dirname(os.path.abspath(sleuth.__file__))
    assert os.path.commonpath([rules_dir(), pkg]) == pkg
