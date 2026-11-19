"""Data models and structures for sqli-taint."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Location:
    """Represents a source code location."""

    file: str
    line: int
    column: int
    end_line: int | None = None
    end_column: int | None = None


@dataclass
class TraceStep:
    """A single step in a vulnerability propagation trace."""

    location: Location
    description: str


@dataclass
class Finding:
    """A detected security finding."""

    rule_id: str
    message: str
    file: str
    line: int
    column: int
    end_line: int | None = None
    sink_name: str = ""
    source_description: str = ""
    trace: list[TraceStep] = field(default_factory=list)
    mode: str = "baseline"
    confidence: str = "high"

    @property
    def sort_key(self) -> tuple[str, int, int, str]:
        """Return deterministic sort key tuple."""
        return (self.file, self.line, self.column, self.rule_id)


@dataclass
class SinkDef:
    """Definition of a database execution sink."""

    name: str
    receivers: list[str] = field(default_factory=list)
    arg_index: int = 0
    kwarg_names: list[str] = field(default_factory=list)
    allow_bare_call: bool = False


@dataclass
class SourceDef:
    """Definition of taint source patterns."""

    attributes: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)


@dataclass
class Config:
    """Configuration loaded from TOML."""

    sinks: list[SinkDef] = field(default_factory=list)
    enable_builtin_sources: bool = False
    flask_sources: SourceDef = field(default_factory=SourceDef)
    django_sources: SourceDef = field(default_factory=SourceDef)
    builtin_sources: SourceDef = field(default_factory=SourceDef)
    sanitizers: list[str] = field(default_factory=list)
    propagator_methods: list[str] = field(default_factory=list)
    propagator_functions: list[str] = field(default_factory=list)


@dataclass
class FunctionSummary:
    """Inter-procedural summary of a function or method."""

    name: str
    params: list[str] = field(default_factory=list)
    param_to_return: set[str] = field(default_factory=set)
    param_to_sink: dict[str, list[Location]] = field(default_factory=dict)
    returns_tainted: bool = False


@dataclass
class ScanSummary:
    """Aggregated scan outcome metrics."""

    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped: list[tuple[str, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    suppressed_count: int = 0
    elapsed_seconds: float = 0.0


@dataclass
class AnalysisContext:
    """Execution context passed through analyzers to avoid global mutable state."""

    config: Config
    mode: str = "baseline"
    summary: ScanSummary = field(default_factory=ScanSummary)
    root_path: Path = field(default_factory=Path.cwd)
    max_file_size: int | None = 10_000_000
