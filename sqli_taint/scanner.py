"""File discovery, inline suppression, and scan orchestration for sqli-taint."""

from __future__ import annotations

import ast
import fnmatch
import io
import logging
import os
from pathlib import Path
import re
import time
import tokenize
from typing import Sequence

from sqli_taint.baseline import analyze_baseline
from sqli_taint.intraproc import analyze_intraproc
from sqli_taint.models import AnalysisContext, Finding, ScanSummary

logger = logging.getLogger(__name__)

SUPPORTED_MODES = frozenset({"baseline", "intraproc"})
UNIMPLEMENTED_MODES = frozenset({"interproc"})

DEFAULT_EXCLUDES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".eggs",
        "build",
        "dist",
        "site-packages",
    }
)

MAX_WARN_FILE_SIZE = 1_000_000  # 1 MB

_SUPPRESSION_RE = re.compile(
    r"#.*\b(?:sqli-taint:\s*ignore|nosec(?:\s*:\s*SQLI001)?)\b",
    re.IGNORECASE,
)


def _validate_mode(mode: str) -> None:
    """Validate that the requested analysis mode is supported."""
    if mode in SUPPORTED_MODES:
        return
    if mode in UNIMPLEMENTED_MODES:
        raise NotImplementedError(
            f"Analysis mode '{mode}' is not implemented yet. "
            f"Supported modes: {', '.join(sorted(SUPPORTED_MODES))}."
        )
    raise ValueError(
        f"Unknown analysis mode '{mode}'. "
        f"Supported modes: {', '.join(sorted(SUPPORTED_MODES))}."
    )


def _should_skip_dir(dir_name: str) -> bool:
    """Check if a directory name is in the default exclude list or is egg-info metadata."""
    return dir_name in DEFAULT_EXCLUDES or dir_name.endswith(".egg-info")


def _matches_exclude(rel_path: str, exclude_globs: Sequence[str] | None) -> bool:
    """Check if a relative/posix path matches any user-specified exclusion glob."""
    if not exclude_globs:
        return False
    posix_path = rel_path.replace("\\", "/")
    if posix_path.startswith("./"):
        posix_path = posix_path[2:]
    path_parts = [part for part in posix_path.split("/") if part]
    file_name = path_parts[-1] if path_parts else posix_path

    for pattern in exclude_globs:
        norm_pattern = pattern.replace("\\", "/").strip()
        if norm_pattern.startswith("./"):
            norm_pattern = norm_pattern[2:]
        norm_no_trailing = norm_pattern.rstrip("/")
        if not norm_no_trailing:
            continue

        if fnmatch.fnmatch(posix_path, norm_no_trailing) or fnmatch.fnmatch(
            file_name, norm_no_trailing
        ):
            return True
        if fnmatch.fnmatch(posix_path, f"*/{norm_no_trailing.lstrip('/')}"):
            return True
        # Match bare directory name or directory glob against any path segment
        if "/" not in norm_no_trailing and any(
            fnmatch.fnmatch(part, norm_no_trailing) for part in path_parts[:-1]
        ):
            return True
    return False


def discover_files(
    paths: Sequence[Path],
    exclude_globs: Sequence[str] | None = None,
) -> list[Path]:
    """Recursively discover Python files using pruned os.walk, avoiding symlink cycles and excluded dirs."""
    collected: list[Path] = []
    visited_real_files: set[Path] = set()
    visited_real_dirs: set[Path] = set()

    for input_path in paths:
        if not input_path.exists():
            continue

        try:
            resolved_root = input_path.resolve()
        except OSError:
            continue

        if input_path.is_file():
            if input_path.suffix == ".py" and resolved_root not in visited_real_files:
                visited_real_files.add(resolved_root)
                if not _matches_exclude(input_path.as_posix(), exclude_globs):
                    collected.append(input_path)
            continue

        if resolved_root in visited_real_dirs:
            continue

        for root, dirnames, filenames in os.walk(input_path, followlinks=False):
            root_path = Path(root)
            try:
                resolved_dir = root_path.resolve()
            except OSError:
                dirnames[:] = []
                continue

            if resolved_dir in visited_real_dirs:
                dirnames[:] = []
                continue
            visited_real_dirs.add(resolved_dir)

            # Prune excluded directories and directory symlinks in-place
            kept_dirs: list[str] = []
            for d in sorted(dirnames):
                if _should_skip_dir(d):
                    continue
                candidate_dir = root_path / d
                if candidate_dir.is_symlink():
                    continue
                if _matches_exclude(candidate_dir.as_posix(), exclude_globs):
                    continue
                kept_dirs.append(d)
            dirnames[:] = kept_dirs

            for fname in sorted(filenames):
                if not fname.endswith(".py"):
                    continue
                file_path = root_path / fname
                try:
                    real_file = file_path.resolve()
                except OSError:
                    continue

                if real_file in visited_real_files:
                    continue
                visited_real_files.add(real_file)

                if _matches_exclude(file_path.as_posix(), exclude_globs):
                    continue
                collected.append(file_path)

    collected.sort()
    return collected


def _is_empty_or_comments_only(content: str) -> tuple[bool, str]:
    """Check if file content is empty or contains comments only."""
    stripped = content.strip()
    if not stripped:
        return True, "empty file"
    non_comment_lines = [
        line.strip()
        for line in stripped.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not non_comment_lines:
        return True, "file contains only comments"
    return False, ""


def _collect_suppressed_lines(source_text: str) -> set[int]:
    """Extract line numbers containing an inline suppression comment token."""
    suppressed: set[int] = set()
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source_text).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT and _SUPPRESSION_RE.search(tok.string):
                suppressed.add(tok.start[0])
    except (tokenize.TokenError, IndentationError):
        # Fallback if tokenization fails on edge-case formatting
        for idx, line in enumerate(source_text.splitlines(), start=1):
            if _SUPPRESSION_RE.search(line):
                suppressed.add(idx)
    return suppressed


def _parse_python_source(raw_bytes: bytes, text_preview: str, file_path: Path) -> ast.AST:
    """Parse Python source bytes (preserving UTF-8 BOM and PEP 263 cookies) with safe fallback."""
    try:
        return ast.parse(raw_bytes, filename=str(file_path))
    except SyntaxError:
        # If raw_bytes failed because of invalid non-UTF-8 bytes lacking a PEP 263 cookie,
        # retry parsing using the replacement-decoded text preview.
        try:
            raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            return ast.parse(text_preview, filename=str(file_path))
        raise


def scan_file(file_path: Path, context: AnalysisContext) -> list[Finding]:
    """Analyze a single Python file, safely capturing parsing and execution errors."""
    _validate_mode(context.mode)

    try:
        rel_path = file_path.relative_to(context.root_path).as_posix()
    except ValueError:
        rel_path = file_path.as_posix()

    try:
        size = file_path.stat().st_size
        if context.max_file_size is not None and size > context.max_file_size:
            logger.warning(
                "Skipping %s: file size (%d bytes) exceeds limit (%d bytes)",
                rel_path,
                size,
                context.max_file_size,
            )
            context.summary.files_skipped.append(
                (rel_path, f"file exceeds max size ({context.max_file_size} bytes)")
            )
            return []

        if size > MAX_WARN_FILE_SIZE:
            logger.info("File %s exceeds 1 MB (%d bytes); analyzing with caution", rel_path, size)

        raw_bytes = file_path.read_bytes()

        if b"\x00" in raw_bytes:
            logger.warning("Skipping %s: null bytes detected", rel_path)
            context.summary.files_skipped.append((rel_path, "null bytes in source file"))
            return []

        text_preview = raw_bytes.decode("utf-8-sig", errors="replace")

        empty_or_comment, reason = _is_empty_or_comments_only(text_preview)
        if empty_or_comment:
            logger.warning("Skipping %s: %s", rel_path, reason)
            context.summary.files_skipped.append((rel_path, reason))
            return []

        tree = _parse_python_source(raw_bytes, text_preview, file_path)

    except SyntaxError as e:
        logger.warning("SyntaxError in %s at line %s: %s", rel_path, e.lineno, e.msg)
        context.summary.files_skipped.append((rel_path, f"SyntaxError: {e.msg}"))
        return []
    except RecursionError:
        logger.warning("RecursionError parsing %s", rel_path)
        context.summary.files_skipped.append((rel_path, "RecursionError during AST parsing"))
        return []
    except Exception as e:
        logger.warning("Error reading %s: %s", rel_path, e)
        context.summary.files_skipped.append((rel_path, f"{type(e).__name__}: {e}"))
        return []

    try:
        if context.mode == "baseline":
            findings = analyze_baseline(tree, rel_path, context)
        elif context.mode == "intraproc":
            findings = analyze_intraproc(tree, rel_path, context)
        else:  # pragma: no cover - guarded by _validate_mode above
            raise NotImplementedError(f"Unsupported mode: {context.mode}")

        context.summary.files_scanned += 1
    except RecursionError:
        logger.warning("RecursionError analyzing %s", rel_path)
        context.summary.files_skipped.append((rel_path, "RecursionError during analysis"))
        return []
    except Exception as e:
        logger.warning("Unexpected error analyzing %s: %s", rel_path, e)
        context.summary.files_skipped.append((rel_path, f"{type(e).__name__}: {e}"))
        return []

    if findings:
        suppressed_lines = _collect_suppressed_lines(text_preview)
        if suppressed_lines:
            kept: list[Finding] = []
            for finding in findings:
                if finding.line in suppressed_lines:
                    context.summary.suppressed_count += 1
                else:
                    kept.append(finding)
            findings = kept

    return findings


def scan_project(
    paths: Sequence[Path],
    context: AnalysisContext,
    exclude_globs: Sequence[str] | None = None,
) -> ScanSummary:
    """Orchestrate scan over multiple paths and compile results."""
    _validate_mode(context.mode)

    start_time = time.perf_counter()
    files = discover_files(paths, exclude_globs)

    context.summary.files_discovered = len(files)
    all_findings: list[Finding] = []

    for file_path in files:
        file_findings = scan_file(file_path, context)
        all_findings.extend(file_findings)

    all_findings.sort(key=lambda f: f.sort_key)
    context.summary.findings = all_findings
    context.summary.elapsed_seconds = time.perf_counter() - start_time

    return context.summary
