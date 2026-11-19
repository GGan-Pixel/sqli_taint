"""Tests for Stage 2 intra-procedural taint analysis (intraproc mode)."""

from __future__ import annotations

import ast
from pathlib import Path
import pytest

from sqli_taint.config import load_config
from sqli_taint.intraproc import analyze_intraproc
from sqli_taint.models import AnalysisContext, Config
from sqli_taint.scanner import scan_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_FIXTURES = sorted((FIXTURES_DIR / "vulnerable").glob("*.py"))
SAFE_FIXTURES = sorted((FIXTURES_DIR / "safe").glob("*.py"))


def _parse_expectations(file_path: Path) -> tuple[set[int], set[int]]:
    sqli_lines: set[int] = set()
    safe_lines: set[int] = set()
    for idx, line in enumerate(file_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if "# EXPECT: SQLI" in line:
            sqli_lines.add(idx)
        elif "# EXPECT: SAFE" in line:
            safe_lines.add(idx)
    return sqli_lines, safe_lines


def _analyze_code(code: str, config: Config | None = None) -> list:
    tree = ast.parse(code)
    ctx = AnalysisContext(config=config or load_config(), mode="intraproc")
    return analyze_intraproc(tree, "snippet.py", ctx)


@pytest.mark.parametrize("fixture_path", VULN_FIXTURES, ids=lambda p: p.stem)
def test_intraproc_vulnerable_fixtures(fixture_path: Path) -> None:
    """Assert intraproc mode detects all vulnerable fixtures with multi-step trace."""
    sqli_lines, safe_lines = _parse_expectations(fixture_path)
    context = AnalysisContext(config=load_config(), mode="intraproc")
    findings = scan_file(fixture_path, context)

    found_lines = {f.line for f in findings}
    assert sqli_lines.issubset(found_lines), f"Missing SQLI lines in {fixture_path.name}"
    assert not (safe_lines & found_lines)
    for f in findings:
        assert f.rule_id == "SQLI001"
        assert f.mode == "intraproc"
        assert len(f.trace) >= 2


@pytest.mark.parametrize("fixture_path", SAFE_FIXTURES, ids=lambda p: p.stem)
def test_intraproc_safe_fixtures(fixture_path: Path) -> None:
    """Assert intraproc mode produces zero findings across all safe fixtures."""
    context = AnalysisContext(config=load_config(), mode="intraproc")
    findings = scan_file(fixture_path, context)
    assert findings == [], f"Unexpected findings in {fixture_path.name}: {findings}"


def test_intraproc_tracks_deferred_sql_variable() -> None:
    """Assert intraproc catches multi-line SQL construction passed as a plain variable (missed by baseline)."""
    code = """
def fetch(cursor, user_id):
    sql = "SELECT * FROM users WHERE id = "
    sql += user_id
    cursor.execute(sql)
"""
    findings = _analyze_code(code)
    assert len(findings) == 1
    assert findings[0].line == 5
    assert findings[0].confidence == "medium"
    assert len(findings[0].trace) >= 3


def test_intraproc_flask_and_django_high_confidence_sources() -> None:
    """Assert configured Flask and Django web sources yield high-confidence findings."""
    flask_code = """
def view(cursor):
    uid = request.args.get("id")
    sql = f"SELECT * FROM users WHERE id = '{uid}'"
    cursor.execute(sql)
"""
    flask_findings = _analyze_code(flask_code)
    assert len(flask_findings) == 1
    assert flask_findings[0].confidence == "high"
    assert "request.args" in flask_findings[0].source_description

    django_code = """
def view(cursor):
    payload = request.POST["name"]
    query = "SELECT * FROM users WHERE name = '" + payload + "'"
    cursor.execute(query)
"""
    django_findings = _analyze_code(django_code)
    assert len(django_findings) == 1
    assert django_findings[0].confidence == "high"
    assert "request.POST" in django_findings[0].source_description


def test_intraproc_builtin_sources_respect_config_flag() -> None:
    """Assert builtin sources (input, os.environ, sys.argv) are gated by enable_builtin_sources."""
    code = """
def run(cursor):
    val = input("enter id: ")
    sql = "SELECT * FROM users WHERE id = " + val
    cursor.execute(sql)
"""
    default_cfg = load_config()
    assert default_cfg.enable_builtin_sources is False
    assert _analyze_code(code, default_cfg) == []

    default_cfg.enable_builtin_sources = True
    findings = _analyze_code(code, default_cfg)
    assert len(findings) == 1
    assert findings[0].confidence == "high"


def test_intraproc_sanitizers_kill_taint() -> None:
    """Assert built-in and custom sanitizers clear taint before reaching a sink."""
    code = """
import uuid

def fetch(cursor, user_id, token):
    safe_id = int(user_id)
    safe_tok = uuid.UUID(token)
    cursor.execute(f"SELECT * FROM users WHERE id = {safe_id} AND tok = '{safe_tok}'")
"""
    assert _analyze_code(code) == []


def test_intraproc_reassignment_kills_taint() -> None:
    """Assert overwriting a tainted variable with a constant clears taint."""
    code = """
def fetch(cursor, user_id):
    target = user_id
    target = "static_value"
    sql = "SELECT * FROM users WHERE name = '" + target + "'"
    cursor.execute(sql)
"""
    assert _analyze_code(code) == []


def test_intraproc_key_sensitive_dict_and_index_sensitive_list() -> None:
    """Assert dict key lookup and list index lookup distinguish clean vs tainted entries."""
    safe_code = """
def fetch(cursor, payload):
    filters = {"id": payload, "status": "active"}
    st = filters["status"]
    st2 = filters.get("status", "ok")
    items = ["verified", payload]
    first = items[0]
    cursor.execute(f"SELECT * FROM users WHERE s = '{st}' AND s2 = '{st2}' AND f = '{first}'")
"""
    assert _analyze_code(safe_code) == []

    vuln_code = """
def fetch(cursor, payload):
    filters = {"id": payload, "status": "active"}
    uid = filters.get("id")
    sql = f"SELECT * FROM users WHERE id = '{uid}'"
    cursor.execute(sql)
"""
    findings = _analyze_code(vuln_code)
    assert len(findings) == 1


def test_intraproc_branch_join_and_early_return_guard() -> None:
    """Assert if/else joins taint conservatively and handles early-return guards."""
    branch_vuln = """
def fetch(cursor, flag, user_id):
    if flag:
        val = user_id
    else:
        val = "guest"
    sql = "SELECT * FROM users WHERE name = '" + val + "'"
    cursor.execute(sql)
"""
    assert len(_analyze_code(branch_vuln)) == 1

    branch_both_sanitized = """
def fetch(cursor, flag, user_id):
    if flag:
        val = int(user_id)
    else:
        val = 0
    sql = f"SELECT * FROM users WHERE id = {val}"
    cursor.execute(sql)
"""
    assert _analyze_code(branch_both_sanitized) == []


def test_intraproc_loop_and_join_propagation() -> None:
    """Assert taint propagates through loops and str.join on container variables."""
    code = """
def fetch(cursor, user_inputs):
    parts = ["SELECT * FROM users WHERE id IN ("]
    for item in user_inputs:
        parts.append(item)
    sql = ",".join(parts)
    cursor.execute(sql)
"""
    findings = _analyze_code(code)
    assert len(findings) == 1

