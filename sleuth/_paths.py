"""Resolve bundled data files (rules) in any install layout.

When Sleuth is pip-installed, the rules ship as package data inside the
``sleuth`` package; when running from the source tree, they sit next to
this file. ``rules_dir()`` handles both, so engines never hard-code a path.
"""

import os
from importlib import resources


def rules_dir():
    """Absolute path to the bundled ``rules/`` directory."""
    # 1) Installed package (wheel/sdist): importlib.resources.
    try:
        p = resources.files("sleuth") / "rules"
        if p.is_dir():
            return str(p)
    except Exception:
        pass
    # 2) Source-tree layouts: <pkg>/rules or <repo>/rules (pre-packaging).
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (
        os.path.join(here, "rules"),
        os.path.join(os.path.dirname(here), "rules"),
    ):
        if os.path.isdir(cand):
            return cand
    # 3) Last resort: let the caller report a clean "missing rules" message.
    return os.path.join(here, "rules")


def capa_rules_dir():
    """Absolute path to the bundled ``rules/capa/`` directory."""
    return os.path.join(rules_dir(), "capa")
