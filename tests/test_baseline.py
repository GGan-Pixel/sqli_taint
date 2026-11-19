"""Tests for baseline syntactic pattern matcher using fixtures and edge cases."""

from __future__ import annotations

import ast
from pathlib import Path
import pytest

from sqli_taint.baseline import analyze_baseline, is_baseline_vulnerable
from sqli_taint.config import load_config
from sqli_taint.models import AnalysisContext
from sqli_taint.scanner import scan_file


def _parse_expectations(file_path: Path) -> tuple[set[int], set[int]]:
    """Parse # EXPECT: SQLI and # EXPECT: SAFE annotations with their line numbers."""
    sqli_lines: set[int] = set()
    safe_lines: set[int] = set()

    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for idx, line in enumerate(lines, start=1):
        if "# EXPECT: SQLI" in line:
            sqli_lines.add(idx)
        elif "# EXPECT: SAFE" in line:
            safe_lines.add(idx)

    return sqli_lines, safe_lines


FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_FIXTURES = sorted((FIXTURES_DIR / "vulnerable").glob("*.py"))
SAFE_FIXTURES = sorted((FIXTURES_DIR / "safe").glob("*.py"))


@pytest.mark.parametrize("fixture_path", VULN_FIXTURES, ids=lambda p: p.stem)
def test_baseline_vulnerable_fixtures(fixture_path: Path) -> None:
    """Assert all vulnerable fixtures produce findings on the annotated sink line."""
    sqli_lines, safe_lines = _parse_expectations(fixture_path)
    assert len(sqli_lines) > 0, f"No '# EXPECT: SQLI' annotation found in {fixture_path.name}"

    context = AnalysisContext(config=load_config(), mode="baseline")
    findings = scan_file(fixture_path, context)

    found_lines = {f.line for f in findings}

    missing = sqli_lines - found_lines
    assert not missing, f"Expected SQLI on lines {missing} in {fixture_path.name}, but none found."

    forbidden = safe_lines & found_lines
    assert not forbidden, f"Unexpected finding on SAFE lines {forbidden} in {fixture_path.name}"

    for finding in findings:
        assert finding.rule_id == "SQLI001"
        assert finding.mode == "baseline"
        assert finding.line in sqli_lines


@pytest.mark.parametrize("fixture_path", SAFE_FIXTURES, ids=lambda p: p.stem)
def test_baseline_safe_fixtures(fixture_path: Path) -> None:
    """Assert all safe fixtures produce zero findings."""
    sqli_lines, safe_lines = _parse_expectations(fixture_path)
    assert len(safe_lines) > 0, f"No '# EXPECT: SAFE' annotation found in {fixture_path.name}"
    assert len(sqli_lines) == 0, f"Safe fixture should not have SQLI expectations: {fixture_path.name}"

    context = AnalysisContext(config=load_config(), mode="baseline")
    findings = scan_file(fixture_path, context)

    assert len(findings) == 0, f"Expected 0 findings in safe fixture {fixture_path.name}, got: {findings}"


def _scan_snippet(code: str) -> list:
    tree = ast.parse(code)
    ctx = AnalysisContext(config=load_config(), mode="baseline")
    return analyze_baseline(tree, "snippet.py", ctx)


def test_baseline_dict_unpacking_detected() -> None:
    """Assert % formatting with {**user_dict} is detected as vulnerable (not constant)."""
    expr = ast.parse('"SELECT * FROM users WHERE id = %(id)s" % {**user_dict}', mode="eval").body
    assert is_baseline_vulnerable(expr) is True
    assert len(_scan_snippet('cursor.execute("SELECT * FROM u WHERE id = %(id)s" % {**d})')) == 1


def test_baseline_django_extra_select_dict_detected() -> None:
    """Assert Django extra(select={...}) dict SQL injection is detected."""
    findings = _scan_snippet('User.objects.extra(select={"cnt": f"SELECT COUNT(*) FROM t WHERE id = {uid}"})')
    assert len(findings) == 1
    assert findings[0].sink_name == "User.objects.extra"


def test_baseline_chained_methods_join_and_ifexp_detected() -> None:
    """Assert method chains, str.join, .replace, and ternary expressions are detected."""
    assert len(_scan_snippet('cursor.execute(f"SELECT * FROM u WHERE id = {x}".strip())')) == 1
    assert len(_scan_snippet('cursor.execute("".join(["SELECT * FROM u WHERE id = ", x]))')) == 1
    assert len(_scan_snippet('cursor.execute("SELECT * FROM u WHERE id = __ID__".replace("__ID__", x))')) == 1
    assert len(_scan_snippet('cursor.execute(f"SELECT {x}" if cond else "SELECT 1")')) == 1


def test_baseline_constant_folded_expressions_safe() -> None:
    """Assert constant-only folded concat, static f-strings, and constant joins do not false-positive."""
    assert len(_scan_snippet('cursor.execute(("SELECT * FROM u " + "WHERE a = %s") % "ok")')) == 0
    assert len(_scan_snippet('cursor.execute(f"SELECT * FROM u " + "WHERE active = 1")')) == 0
    assert len(_scan_snippet('cursor.execute(" ".join(["SELECT 1", "FROM dual"]))')) == 0


def test_baseline_import_alias_resolution_and_false_positive_reduction() -> None:
    """Assert aliased DB imports match and unrelated imports named 'text' do not false-positive."""
    assert len(_scan_snippet('import pandas as p\np.read_sql("SELECT * FROM " + tbl, conn)')) == 1
    assert len(_scan_snippet('from sqlalchemy import text as sql_text\nsql_text(f"SELECT {col}")')) == 1
    assert len(_scan_snippet('from tkinter import text\ntext(f"Hello {user_name}")')) == 0


def test_baseline_additional_configured_sinks() -> None:
    """Assert executescript, RawSQL, and read_sql_query sinks are detected."""
    assert len(_scan_snippet('conn.executescript(f"DELETE FROM users WHERE id = {uid}")')) == 1
    assert len(_scan_snippet('RawSQL("SELECT * FROM u WHERE name = " + name, [])')) == 1
    assert len(_scan_snippet('import pandas as pd\npd.read_sql_query(f"SELECT * FROM {tbl}", conn)')) == 1
