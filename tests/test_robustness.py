"""Tests for scanner robustness, encoding, exclusions, suppressions, and crash prevention."""

from __future__ import annotations

import logging
from pathlib import Path
import pytest

from sqli_taint.config import load_config
from sqli_taint.models import AnalysisContext
from sqli_taint.scanner import discover_files, scan_file, scan_project


def test_syntax_error_handling(tmp_path: Path) -> None:
    """Assert scanner skips files with syntax errors without crashing."""
    bad_py = tmp_path / "syntax_error.py"
    bad_py.write_text("def broken_func(:\n    pass", encoding="utf-8")

    context = AnalysisContext(config=load_config(), mode="baseline")
    findings = scan_file(bad_py, context)

    assert findings == []
    assert context.summary.files_scanned == 0
    assert len(context.summary.files_skipped) == 1
    assert "SyntaxError" in context.summary.files_skipped[0][1]


def test_python2_syntax_handling(tmp_path: Path) -> None:
    """Assert scanner skips Python 2 syntax (e.g. print statement) gracefully."""
    py2_file = tmp_path / "py2.py"
    py2_file.write_text("print 'Hello from Python 2'\n", encoding="utf-8")

    context = AnalysisContext(config=load_config(), mode="baseline")
    findings = scan_file(py2_file, context)

    assert findings == []
    assert len(context.summary.files_skipped) == 1
    assert "SyntaxError" in context.summary.files_skipped[0][1]


def test_null_bytes_handling(tmp_path: Path) -> None:
    """Assert scanner skips files containing null bytes."""
    null_py = tmp_path / "null_bytes.py"
    null_py.write_bytes(b"cursor.execute('SELECT \x00 FROM users')\n")

    context = AnalysisContext(config=load_config(), mode="baseline")
    findings = scan_file(null_py, context)

    assert findings == []
    assert len(context.summary.files_skipped) == 1
    assert "null bytes" in context.summary.files_skipped[0][1]


def test_empty_file_handling(tmp_path: Path) -> None:
    """Assert scanner skips completely empty files."""
    empty_py = tmp_path / "empty.py"
    empty_py.write_text("   \n\n\t", encoding="utf-8")

    context = AnalysisContext(config=load_config(), mode="baseline")
    findings = scan_file(empty_py, context)

    assert findings == []
    assert len(context.summary.files_skipped) == 1
    assert "empty file" in context.summary.files_skipped[0][1]


def test_comments_only_file_handling(tmp_path: Path) -> None:
    """Assert scanner skips files containing only comments."""
    comment_py = tmp_path / "comments_only.py"
    comment_py.write_text("# This is a comment\n# Another comment\n", encoding="utf-8")

    context = AnalysisContext(config=load_config(), mode="baseline")
    findings = scan_file(comment_py, context)

    assert findings == []
    assert len(context.summary.files_skipped) == 1
    assert "file contains only comments" in context.summary.files_skipped[0][1]


def test_huge_file_analyzed_with_log(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Assert files > 1MB are analyzed without aborting and emit an info log."""
    large_py = tmp_path / "large_file.py"
    chunk = "x = 1\n" * 1000
    large_py.write_text(chunk * 180, encoding="utf-8")
    assert large_py.stat().st_size > 1_000_000

    context = AnalysisContext(config=load_config(), mode="baseline")
    with caplog.at_level(logging.INFO, logger="sqli_taint.scanner"):
        findings = scan_file(large_py, context)

    assert findings == []
    assert len(context.summary.files_skipped) == 0
    assert context.summary.files_scanned == 1
    assert any("exceeds 1 MB" in record.message for record in caplog.records)


def test_max_file_size_guard_skips_oversized_file(tmp_path: Path) -> None:
    """Assert files exceeding max_file_size are skipped cleanly."""
    big_py = tmp_path / "big.py"
    big_py.write_text("x = 1\n" * 500, encoding="utf-8")

    context = AnalysisContext(config=load_config(), mode="baseline", max_file_size=100)
    findings = scan_file(big_py, context)

    assert findings == []
    assert context.summary.files_scanned == 0
    assert len(context.summary.files_skipped) == 1
    assert "exceeds max size" in context.summary.files_skipped[0][1]


def test_utf8_bom_file_parsed_and_scanned(tmp_path: Path) -> None:
    """Assert Python files with a UTF-8 BOM are parsed normally and vulnerabilities detected."""
    bom_py = tmp_path / "bom_vuln.py"
    bom_py.write_bytes(b'\xef\xbb\xbfdef q(cursor, uid):\n    cursor.execute(f"SELECT {uid}")\n')

    context = AnalysisContext(config=load_config(), mode="baseline")
    findings = scan_file(bom_py, context)

    assert len(findings) == 1
    assert len(context.summary.files_skipped) == 0


def test_pep263_latin1_cookie_parsed(tmp_path: Path) -> None:
    """Assert Python files with PEP 263 encoding cookies are parsed accurately."""
    pep_py = tmp_path / "pep263.py"
    pep_py.write_bytes(
        b'# -*- coding: latin-1 -*-\n# Ren\xe9\ndef q(cursor, uid):\n    cursor.execute("SELECT " + uid)\n'
    )

    context = AnalysisContext(config=load_config(), mode="baseline")
    findings = scan_file(pep_py, context)

    assert len(findings) == 1
    assert len(context.summary.files_skipped) == 0


def test_non_utf8_encoding_handled(tmp_path: Path) -> None:
    """Assert files with non-UTF-8 bytes lacking a PEP 263 cookie fall back safely."""
    latin_py = tmp_path / "latin.py"
    content_bytes = b"# Author: Ren\xe9\ndef run(cursor, x):\n    cursor.execute('SELECT 1')\n"
    latin_py.write_bytes(content_bytes)

    context = AnalysisContext(config=load_config(), mode="baseline")
    findings = scan_file(latin_py, context)
    assert findings == []
    assert context.summary.files_scanned == 1


def test_unsupported_mode_raises_explicit_error(tmp_path: Path) -> None:
    """Assert library API never silently returns [] for unimplemented or unknown modes."""
    sample = tmp_path / "sample.py"
    sample.write_text("cursor.execute(f'SELECT {x}')\n", encoding="utf-8")

    with pytest.raises(NotImplementedError):
        scan_file(sample, AnalysisContext(config=load_config(), mode="interproc"))

    with pytest.raises(ValueError):
        scan_project([sample], AnalysisContext(config=load_config(), mode="nonexistent_mode"))


def test_discover_files_prunes_excluded_directories_and_bare_excludes(tmp_path: Path) -> None:
    """Assert discover_files skips default excluded dirs, egg-info, and custom dir excludes."""
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    for excluded_dir in (".venv", "__pycache__", ".pytest_cache", "foo.egg-info", "ignored_dir"):
        d = tmp_path / excluded_dir
        d.mkdir()
        (d / "hidden.py").write_text("x = 1\n", encoding="utf-8")

    discovered = discover_files([tmp_path], exclude_globs=["ignored_dir"])
    assert discovered == [tmp_path / "app.py"]


def test_files_scanned_excludes_skipped_files(tmp_path: Path) -> None:
    """Assert scan_project counts only analyzed files in files_scanned, not skipped files."""
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "empty.py").write_text("", encoding="utf-8")

    ctx = AnalysisContext(config=load_config(), mode="baseline")
    summary = scan_project([tmp_path], ctx)

    assert summary.files_discovered == 3
    assert summary.files_scanned == 1
    assert len(summary.files_skipped) == 2


def test_inline_suppression_comments_only(tmp_path: Path) -> None:
    """Assert # sqli-taint: ignore and # nosec suppress findings, but strings containing them do not."""
    code = (
        "def run(cursor, uid):\n"
        '    cursor.execute(f"SELECT * FROM a WHERE id = {uid}")  # sqli-taint: ignore\n'
        '    cursor.execute(f"SELECT * FROM b WHERE id = {uid}")  # nosec\n'
        '    cursor.execute(f"SELECT \'# sqli-taint: ignore\' FROM c WHERE id = {uid}")\n'
    )
    target = tmp_path / "suppressed.py"
    target.write_text(code, encoding="utf-8")

    ctx = AnalysisContext(config=load_config(), mode="intraproc")
    findings = scan_file(target, ctx)

    assert ctx.summary.suppressed_count == 2
    assert len(findings) == 1
    assert findings[0].line == 4


def test_symlink_cycle_avoidance(tmp_path: Path) -> None:
    """Assert directory traversals do not infinite-loop on symlink cycles."""
    scan_dir = tmp_path / "cycle_test"
    scan_dir.mkdir()
    sub_dir = scan_dir / "subdir"
    sub_dir.mkdir()
    sample_file = sub_dir / "sample.py"
    sample_file.write_text("x = 1\n", encoding="utf-8")

    try:
        link_dir = sub_dir / "loop"
        link_dir.symlink_to(scan_dir, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlink creation not permitted in this environment: {exc}")

    discovered = discover_files([scan_dir])
    assert discovered == [sample_file]
