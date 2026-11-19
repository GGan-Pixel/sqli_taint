"""JSON report formatter for sqli-taint findings."""

from __future__ import annotations

import json
from typing import Any

from sqli_taint import __version__
from sqli_taint.models import Finding, ScanSummary


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "message": finding.message,
        "file": finding.file,
        "line": finding.line,
        "column": finding.column,
        "end_line": finding.end_line,
        "sink_name": finding.sink_name,
        "source_description": finding.source_description,
        "mode": finding.mode,
        "confidence": finding.confidence,
        "trace": [
            {
                "file": step.location.file,
                "line": step.location.line,
                "column": step.location.column,
                "end_line": step.location.end_line,
                "end_column": step.location.end_column,
                "description": step.description,
            }
            for step in finding.trace
        ],
    }


def format_json_report(summary: ScanSummary) -> str:
    """Format a ScanSummary into a deterministic JSON string."""
    payload: dict[str, Any] = {
        "tool": "sqli-taint",
        "version": __version__,
        "summary": {
            "files_discovered": summary.files_discovered,
            "files_scanned": summary.files_scanned,
            "files_skipped": [
                {"file": file_path, "reason": reason}
                for file_path, reason in summary.files_skipped
            ],
            "findings": len(summary.findings),
            "suppressed": summary.suppressed_count,
            "elapsed_seconds": round(summary.elapsed_seconds, 6),
        },
        "findings": [_serialize_finding(f) for f in summary.findings],
    }
    return json.dumps(payload, indent=2)

