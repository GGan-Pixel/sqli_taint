"""Tests for text, JSON, and SARIF report formatters and release packaging."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import zipfile

from sqli_taint.models import Finding, Location, ScanSummary, TraceStep
from sqli_taint.report import format_json_report, format_sarif_report, format_text_report


def _sample_summary(sample_file: Path) -> ScanSummary:
    loc_src = Location(file=sample_file.name, line=1, column=20, end_line=1, end_column=27)
    loc_sink = Location(file=sample_file.name, line=2, column=5, end_line=2, end_column=55)
    finding = Finding(
        rule_id="SQLI001",
        message="Possible SQL injection in cursor.execute",
        file=sample_file.name,
        line=2,
        column=5,
        end_line=2,
        sink_name="cursor.execute",
        source_description="function parameter 'user_id'",
        trace=[
            TraceStep(location=loc_src, description="untrusted parameter 'user_id'"),
            TraceStep(location=loc_sink, description="reaches sink cursor.execute"),
        ],
        mode="intraproc",
        confidence="medium",
    )
    return ScanSummary(
        files_discovered=2,
        files_scanned=1,
        files_skipped=[("broken.py", "SyntaxError: invalid syntax")],
        findings=[finding],
        suppressed_count=1,
        elapsed_seconds=0.01234,
    )


def test_text_report_includes_source_snippet_and_skipped(tmp_path: Path) -> None:
    """Assert text report renders source description, code snippet + caret, skipped files, and suppressed count."""
    sample_file = tmp_path / "app.py"
    sample_file.write_text(
        'def run(cursor, user_id):\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n',
        encoding="utf-8",
    )
    summary = _sample_summary(sample_file)
    report = format_text_report(summary, root_path=tmp_path)

    assert "Source:     function parameter 'user_id'" in report
    assert 'Code:       2 |     cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")' in report
    assert " |     ^" in report
    assert "Files scanned:   1" in report
    assert "Files skipped:   1" in report
    assert "broken.py (reason: SyntaxError: invalid syntax)" in report
    assert "Suppressed:      1" in report


def test_json_report_structure(tmp_path: Path) -> None:
    """Assert JSON report serializes summary, skipped files, findings, and trace steps."""
    sample_file = tmp_path / "app.py"
    sample_file.write_text("x = 1\n", encoding="utf-8")
    summary = _sample_summary(sample_file)

    data = json.loads(format_json_report(summary))
    assert data["tool"] == "sqli-taint"
    assert data["summary"]["files_discovered"] == 2
    assert data["summary"]["files_scanned"] == 1
    assert data["summary"]["suppressed"] == 1
    assert data["summary"]["files_skipped"] == [
        {"file": "broken.py", "reason": "SyntaxError: invalid syntax"}
    ]
    assert len(data["findings"]) == 1
    assert len(data["findings"][0]["trace"]) == 2


def test_sarif_report_schema_and_code_flows(tmp_path: Path) -> None:
    """Assert SARIF 2.1.0 report contains valid runs, CWE-89 rule metadata, and codeFlows."""
    sample_file = tmp_path / "app.py"
    sample_file.write_text("x = 1\n", encoding="utf-8")
    summary = _sample_summary(sample_file)

    sarif = json.loads(format_sarif_report(summary))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "sqli-taint"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "SQLI001"
    assert "external/cwe/cwe-89" in rule["properties"]["tags"]

    result = run["results"][0]
    assert result["ruleId"] == "SQLI001"
    assert result["level"] == "warning"  # medium confidence maps to warning
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
    assert len(result["codeFlows"][0]["threadFlows"][0]["locations"]) == 2


def test_package_release_script_excludes_bloat(tmp_path: Path) -> None:
    """Assert scripts/package_release.py produces a clean ZIP without venv/cache/egg-info."""
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "package_release.py"
    spec = importlib.util.spec_from_file_location("package_release", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Create a mini fake project with bloat
    proj = tmp_path / "proj"
    (proj / "sqli_taint" / "rules").mkdir(parents=True)
    (proj / "sqli_taint" / "models.py").write_text("# models\n", encoding="utf-8")
    (proj / "sqli_taint" / "rules" / "default.toml").write_text("[sinks]\n", encoding="utf-8")
    for bloat in (".venv", ".pytest_cache", "__pycache__", "sqli_taint.egg-info"):
        (proj / bloat).mkdir()
        (proj / bloat / "junk.txt").write_text("bloat\n", encoding="utf-8")

    out_zip = tmp_path / "release.zip"
    count = mod.build_release_zip(proj, out_zip)
    assert count == 2
    with zipfile.ZipFile(out_zip) as zf:
        names = sorted(zf.namelist())
    assert names == ["sqli_taint/models.py", "sqli_taint/rules/default.toml"]

