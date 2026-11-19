"""Tests for CLI arguments, execution paths, formats, and exit codes."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from sqli_taint import __version__
from sqli_taint.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_cli_scan_vulnerable_without_fail_on_findings(capsys: pytest.CaptureFixture[str]) -> None:
    """Assert exit code 0 when findings exist but --fail-on-findings is omitted."""
    vuln_path = FIXTURES_DIR / "vulnerable" / "vuln01_cursor_fstring.py"
    ret = main(["scan", str(vuln_path), "--mode", "baseline"])
    assert ret == 0

    captured = capsys.readouterr()
    assert "SQLI001" in captured.out
    assert "Files scanned:   1" in captured.out
    assert "Findings:        1" in captured.out


def test_cli_scan_vulnerable_with_fail_on_findings() -> None:
    """Assert exit code 1 when findings exist and --fail-on-findings is provided."""
    vuln_path = FIXTURES_DIR / "vulnerable" / "vuln01_cursor_fstring.py"
    ret = main(["scan", str(vuln_path), "--mode", "baseline", "--fail-on-findings"])
    assert ret == 1


def test_cli_scan_safe_fixtures(capsys: pytest.CaptureFixture[str]) -> None:
    """Assert exit code 0 and 0 findings when scanning safe fixtures."""
    safe_path = FIXTURES_DIR / "safe" / "safe01_parameterized_qmark.py"
    ret = main(["scan", str(safe_path), "--mode", "baseline", "--fail-on-findings"])
    assert ret == 0

    captured = capsys.readouterr()
    assert "Findings:        0" in captured.out
    assert "No SQL injection vulnerabilities found." in captured.out


def test_cli_zero_files_found(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Assert exit code 0 and informative message when no python files match."""
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    ret = main(["scan", str(empty_dir)])
    assert ret == 0

    captured = capsys.readouterr()
    assert "No Python files found to scan." in captured.out


def test_cli_nonexistent_path_returns_error(capsys: pytest.CaptureFixture[str]) -> None:
    """Assert exit code 2 when a scan target path does not exist (never silently pass CI)."""
    ret = main(["scan", "nonexistent_dir_xyz_999", "--fail-on-findings"])
    assert ret == 2

    captured = capsys.readouterr()
    assert "Path does not exist" in captured.err


def test_cli_missing_command() -> None:
    """Assert exit code 2 when no subcommand is specified."""
    ret = main([])
    assert ret == 2


def test_cli_unsupported_mode(capsys: pytest.CaptureFixture[str]) -> None:
    """Assert exit code 2 when unimplemented 'interproc' mode is requested."""
    safe_path = FIXTURES_DIR / "safe" / "safe01_parameterized_qmark.py"
    ret = main(["scan", str(safe_path), "--mode", "interproc"])
    assert ret == 2
    captured = capsys.readouterr()
    assert "not yet available" in captured.err


def test_cli_intraproc_mode(capsys: pytest.CaptureFixture[str]) -> None:
    """Assert --mode intraproc runs cleanly and flags vulnerable code."""
    vuln_path = FIXTURES_DIR / "vulnerable" / "vuln11_multiline_reassignment.py"
    ret = main(["scan", str(vuln_path), "--mode", "intraproc", "--fail-on-findings"])
    assert ret == 1

    captured = capsys.readouterr()
    assert "Mode:       intraproc" in captured.out
    assert "Findings:        1" in captured.out


def test_cli_json_format(capsys: pytest.CaptureFixture[str]) -> None:
    """Assert --format json emits valid structured JSON output."""
    vuln_path = FIXTURES_DIR / "vulnerable" / "vuln01_cursor_fstring.py"
    ret = main(["scan", str(vuln_path), "--mode", "intraproc", "--format", "json"])
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["tool"] == "sqli-taint"
    assert data["summary"]["files_scanned"] == 1
    assert data["summary"]["findings"] == 1
    assert data["findings"][0]["rule_id"] == "SQLI001"
    assert data["findings"][0]["mode"] == "intraproc"


def test_cli_sarif_format(capsys: pytest.CaptureFixture[str]) -> None:
    """Assert --format sarif emits valid SARIF 2.1.0 JSON output."""
    vuln_path = FIXTURES_DIR / "vulnerable" / "vuln01_cursor_fstring.py"
    ret = main(["scan", str(vuln_path), "--mode", "intraproc", "--format", "sarif"])
    assert ret == 0

    captured = capsys.readouterr()
    sarif = json.loads(captured.out)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SQLI001"


def test_cli_missing_config_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Assert exit code 2 when custom config file does not exist."""
    missing_config = tmp_path / "absent.toml"
    safe_path = FIXTURES_DIR / "safe" / "safe01_parameterized_qmark.py"
    ret = main(["scan", str(safe_path), "--config", str(missing_config)])
    assert ret == 2

    captured = capsys.readouterr()
    assert "Configuration error" in captured.err


def test_cli_malformed_config_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Assert exit code 2 when custom config file contains invalid TOML."""
    bad_toml = tmp_path / "bad.toml"
    bad_toml.write_text("sinks = [incomplete", encoding="utf-8")
    safe_path = FIXTURES_DIR / "safe" / "safe01_parameterized_qmark.py"
    ret = main(["scan", str(safe_path), "--config", str(bad_toml)])
    assert ret == 2

    captured = capsys.readouterr()
    assert "Configuration error" in captured.err


def test_cli_output_file(tmp_path: Path) -> None:
    """Assert --output writes report to the specified file with trailing newline."""
    vuln_path = FIXTURES_DIR / "vulnerable" / "vuln01_cursor_fstring.py"
    out_file = tmp_path / "report.txt"
    ret = main(["scan", str(vuln_path), "--mode", "baseline", "--output", str(out_file)])
    assert ret == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "SQLI001" in content
    assert "Scan Summary" in content
    assert content.endswith("\n")


def test_cli_output_file_write_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Assert exit code 2 when --output points to an unwritable path (e.g. a directory)."""
    vuln_path = FIXTURES_DIR / "vulnerable" / "vuln01_cursor_fstring.py"
    ret = main(["scan", str(vuln_path), "--output", str(tmp_path)])
    assert ret == 2
    captured = capsys.readouterr()
    assert "Error writing output file" in captured.err


def test_cli_exclude_glob(capsys: pytest.CaptureFixture[str]) -> None:
    """Assert --exclude ignores matching files."""
    vuln_dir = FIXTURES_DIR / "vulnerable"
    ret = main(["scan", str(vuln_dir), "--mode", "baseline", "--exclude", "*vuln01*"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "vuln01_cursor_fstring.py" not in captured.out


def test_cli_max_file_size_and_validation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Assert --max-file-size skips oversized files and rejects negative values."""
    sample = tmp_path / "sample.py"
    sample.write_text("cursor.execute(f'SELECT {x}')\n" * 20, encoding="utf-8")

    assert main(["scan", str(sample), "--max-file-size", "-1"]) == 2
    assert main(["scan", str(sample), "--max-file-size", "10", "--fail-on-findings"]) == 0
    captured = capsys.readouterr()
    assert "Files skipped:   1" in captured.out


def test_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """Assert --version displays package version and exits with code 0."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert __version__ in captured.out
