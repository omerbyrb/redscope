"""Every finding from modules with stable check ids must carry one, and docs must list them all.

The checks are static (AST-based) so they cover every code path without running network scans.
"""

import ast
import re
from pathlib import Path

import pytest

from redscope.core.base_module import CHECK_ID_PATTERN

ROOT = Path(__file__).resolve().parents[2]
MODULES_DIR = ROOT / "redscope" / "modules"
DOCS = ROOT / "docs" / "check-ids.md"

# Modules whose findings carry check ids. Add a module here once it is migrated.
MODULES_WITH_CHECK_IDS = {
    "portscan": "recon/portscan.py",
    "banner": "network/banner.py",
    "cvelookup": "network/cvelookup.py",
    "serviceenum": "network/serviceenum.py",
    "ssltls": "network/ssltls.py",
    "headers": "web/headers.py",
}


def _finding_calls(path: Path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Finding":
            yield node


def _check_id_of(call: ast.Call):
    for kw in call.keywords:
        if kw.arg == "check_id":
            return kw.value.value if isinstance(kw.value, ast.Constant) else kw.value
    return None


def _ids_in_code():
    return {_check_id_of(call) for rel in MODULES_WITH_CHECK_IDS.values() for call in _finding_calls(MODULES_DIR / rel)}


@pytest.mark.parametrize("module,rel", sorted(MODULES_WITH_CHECK_IDS.items()))
def test_every_finding_has_a_literal_check_id_for_its_module(module, rel):
    calls = list(_finding_calls(MODULES_DIR / rel))
    assert calls, f"{rel} has no Finding calls"

    for call in calls:
        check_id = _check_id_of(call)
        where = f"{rel}:{call.lineno}"
        assert isinstance(check_id, str), f"{where}: missing or non-literal check_id"
        assert CHECK_ID_PATTERN.match(check_id), f"{where}: malformed check_id {check_id!r}"
        assert check_id.startswith(f"{module}."), f"{where}: {check_id!r} should start with '{module}.'"


def test_docs_list_exactly_the_check_ids_in_code():
    documented = set(re.findall(r"^\| `([a-z0-9_]+\.[a-z0-9_]+)` \|", DOCS.read_text(), flags=re.M))

    assert documented == _ids_in_code()
