"""SARIF 2.1.0 report formatter for sqli-taint findings."""

from __future__ import annotations

import json
from typing import Any

from sqli_taint import __version__
from sqli_taint.models import Finding, Location, ScanSummary

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _confidence_to_sarif_level(confidence: str) -> str:
    if confidence == "high":
        return "error"
    if confidence == "medium":
        return "warning"
    return "note"


def _physical_location(loc: Location) -> dict[str, Any]:
    region: dict[str, Any] = {
        "startLine": loc.line,
        "startColumn": loc.column,
    }
    if loc.end_line is not None and loc.end_line >= loc.line:
        region["endLine"] = loc.end_line
    if loc.end_column is not None and loc.end_column >= 1:
        region["endColumn"] = loc.end_column
    return {
        "artifactLocation": {"uri": loc.file},
        "region": region,
    }


def _serialize_result(finding: Finding) -> dict[str, Any]:
    primary_loc = Location(
        file=finding.file,
        line=finding.line,
        column=finding.column,
        end_line=finding.end_line,
    )
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _confidence_to_sarif_level(finding.confidence),
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": _physical_location(primary_loc)}],
        "properties": {
            "mode": finding.mode,
            "confidence": finding.confidence,
            "sinkName": finding.sink_name,
            "sourceDescription": finding.source_description,
        },
    }

    if finding.trace:
        thread_locations = [
            {
                "location": {
                    "physicalLocation": _physical_location(step.location),
                    "message": {"text": step.description},
                }
            }
            for step in finding.trace
        ]
        result["codeFlows"] = [
            {"threadFlows": [{"locations": thread_locations}]}
        ]

    return result


def format_sarif_report(summary: ScanSummary) -> str:
    """Format a ScanSummary as a SARIF 2.1.0 JSON document."""
    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sqli-taint",
                        "version": __version__,
                        "rules": [
                            {
                                "id": "SQLI001",
                                "name": "SqlInjection",
                                "shortDescription": {
                                    "text": "Possible SQL injection vulnerability"
                                },
                                "fullDescription": {
                                    "text": (
                                        "Untrusted or dynamically constructed SQL reaches a database "
                                        "execution sink without parameterized queries or sanitization."
                                    )
                                },
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-89"],
                                    "security-severity": "8.8",
                                },
                            }
                        ],
                    }
                },
                "results": [_serialize_result(f) for f in summary.findings],
                "properties": {
                    "filesScanned": summary.files_scanned,
                    "filesSkipped": len(summary.files_skipped),
                    "suppressedCount": summary.suppressed_count,
                    "elapsedSeconds": round(summary.elapsed_seconds, 6),
                },
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)

