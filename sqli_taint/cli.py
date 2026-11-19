"""Command line interface for sqli-taint."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys
import tomllib
from typing import Sequence

from sqli_taint import __version__
from sqli_taint.config import load_config
from sqli_taint.models import AnalysisContext
from sqli_taint.report import format_json_report, format_sarif_report, format_text_report
from sqli_taint.scanner import SUPPORTED_MODES, scan_project


def _configure_logging(verbose: bool, quiet: bool) -> None:
    """Configure sqli_taint package logging without interfering with root/test handlers."""
    pkg_logger = logging.getLogger("sqli_taint")
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    pkg_logger.setLevel(level)
    if not logging.getLogger().handlers and not pkg_logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        pkg_logger.addHandler(handler)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for sqli-taint."""
    parser = argparse.ArgumentParser(
        prog="sqli-taint",
        description="Static analyzer detecting SQL injection vulnerabilities in Python code.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    scan_parser = subparsers.add_parser(
        "scan", help="Scan Python files for SQL injection vulnerabilities"
    )
    scan_parser.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="One or more directory or file paths to scan",
    )
    scan_parser.add_argument(
        "--mode",
        choices=["baseline", "intraproc", "interproc"],
        default="baseline",
        help="Analysis mode ('baseline' or 'intraproc'; 'interproc' planned for Stage 4)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output report format ('text', 'json', or 'sarif')",
    )
    scan_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write report output to specified file instead of stdout",
    )
    scan_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to custom TOML configuration file",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob pattern to exclude from scan (can be specified multiple times)",
    )
    scan_parser.add_argument(
        "--max-file-size",
        type=int,
        default=10_000_000,
        help="Skip files larger than N bytes (0 to disable limit; default: 10000000)",
    )
    scan_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with return code 1 if any vulnerabilities are found",
    )
    verbosity = scan_parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic logging to stderr",
    )
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-error warnings on stderr",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help(sys.stderr)
        return 2

    _configure_logging(verbose=args.verbose, quiet=args.quiet)

    # Validate mode availability
    if args.mode not in SUPPORTED_MODES:
        supported = ", ".join(sorted(SUPPORTED_MODES))
        sys.stderr.write(
            f"Error: Mode '{args.mode}' is not yet available. Supported modes: {supported}.\n"
        )
        return 2

    # Validate max-file-size
    if args.max_file_size < 0:
        sys.stderr.write("Error: --max-file-size must be >= 0.\n")
        return 2

    # Validate target paths exist so typos never silently pass CI gates
    missing_paths = [p for p in args.paths if not p.exists()]
    if missing_paths:
        for missing in missing_paths:
            sys.stderr.write(f"Error: Path does not exist: {missing}\n")
        return 2

    # Load configuration
    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        sys.stderr.write(f"Configuration error: {e}\n")
        return 2
    except tomllib.TOMLDecodeError as e:
        sys.stderr.write(f"Configuration error: Malformed TOML file: {e}\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"Configuration error: {e}\n")
        return 2

    root_path = Path.cwd()
    max_file_size = None if args.max_file_size == 0 else args.max_file_size
    context = AnalysisContext(
        config=config,
        mode=args.mode,
        root_path=root_path,
        max_file_size=max_file_size,
    )

    # Single-pass discovery and scan
    summary = scan_project(args.paths, context, exclude_globs=args.exclude)
    if summary.files_discovered == 0 and args.format == "text" and not args.output:
        sys.stdout.write("No Python files found to scan.\n")
        return 0

    if args.format == "json":
        report_output = format_json_report(summary)
    elif args.format == "sarif":
        report_output = format_sarif_report(summary)
    else:
        report_output = format_text_report(summary, root_path=root_path)

    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report_output + "\n", encoding="utf-8")
        except OSError as e:
            sys.stderr.write(f"Error writing output file: {e}\n")
            return 2
    else:
        sys.stdout.write(report_output + "\n")

    if args.fail_on_findings and summary.findings:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
