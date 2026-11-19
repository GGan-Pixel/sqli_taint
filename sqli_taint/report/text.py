"""Text report formatter for sqli-taint findings."""

from __future__ import annotations

from pathlib import Path

from sqli_taint.models import ScanSummary


def _read_source_line(file_str: str, line_no: int, root_path: Path | None = None) -> str | None:
    """Safely read a single 1-indexed line from a source file for display context."""
    if line_no < 1:
        return None
    candidate = Path(file_str)
    if not candidate.is_absolute() and root_path is not None:
        candidate = root_path / candidate
    if not candidate.is_file():
        return None
    try:
        lines = candidate.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return None
    if line_no > len(lines):
        return None
    return lines[line_no - 1]


def format_text_report(summary: ScanSummary, root_path: Path | None = None) -> str:
    """Format a ScanSummary into a human-readable text report."""
    lines: list[str] = []

    if summary.findings:
        lines.append("Detected Findings:")
        lines.append("-" * 72)
        for idx, finding in enumerate(summary.findings, start=1):
            lines.append(f"[{idx}] {finding.rule_id}: Possible SQL injection in {finding.sink_name}")
            lines.append(f"    File:       {finding.file}:{finding.line}:{finding.column}")
            lines.append(f"    Confidence: {finding.confidence}")
            lines.append(f"    Mode:       {finding.mode}")
            if finding.source_description:
                lines.append(f"    Source:     {finding.source_description}")
            lines.append(f"    Message:    {finding.message}")

            source_line = _read_source_line(finding.file, finding.line, root_path)
            if source_line is not None:
                line_label = str(finding.line)
                lines.append(f"    Code:       {line_label} | {source_line}")
                caret_pad = max(finding.column - 1, 0)
                lines.append(f"                {' ' * len(line_label)} | {' ' * caret_pad}^")

            if finding.trace:
                lines.append("    Trace:")
                for step_idx, step in enumerate(finding.trace, start=1):
                    lines.append(
                        f"      {step_idx}. {step.description} at {step.location.file}:{step.location.line}:{step.location.column}"
                    )
            lines.append("-" * 72)
    else:
        lines.append("No SQL injection vulnerabilities found.")
        lines.append("")

    lines.append("=" * 72)
    lines.append("Scan Summary")
    lines.append("-" * 72)
    lines.append(f"Files scanned:   {summary.files_scanned}")
    lines.append(f"Files skipped:   {len(summary.files_skipped)}")
    if summary.files_skipped:
        for skipped_file, reason in summary.files_skipped:
            lines.append(f"  - {skipped_file} (reason: {reason})")
    lines.append(f"Findings:        {len(summary.findings)}")
    lines.append(f"Suppressed:      {summary.suppressed_count}")
    lines.append(f"Elapsed time:    {summary.elapsed_seconds:.3f}s")
    lines.append("=" * 72)

    return "\n".join(lines)
