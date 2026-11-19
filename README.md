# sqli-taint

A static analyzer in Python that detects SQL injection vulnerabilities in Python source code using AST analysis and taint tracking.

## Overview

`sqli-taint` performs static security analysis to detect untrusted data sources flowing into database execution sinks without passing through sanitizers or parameterized queries.

Analysis modes:
- **`baseline`**: Syntactic pattern matching on query arguments (no variable data flow; reference baseline)
- **`intraproc`**: Intra-procedural taint tracking within functions and modules (assignments, reassignments, container lookups, propagators, sanitizers, branches, loops, and multi-step traces)
- **`interproc`**: Inter-procedural taint tracking across function calls and modules *(planned for Stage 4)*

Report formats:
- **`text`**: Human-readable findings with source snippets, carets, traces, and scan summary
- **`json`**: Structured JSON output for scripting and CI pipelines
- **`sarif`**: SARIF 2.1.0 output for GitHub Code Scanning and IDE integrations

## Setup (PowerShell / Windows)

Prerequisites: Python 3.11+ installed.

### 1. Create and Activate Virtual Environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

*(If script execution is disabled in PowerShell, enable it for the current session via `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### 2. Install Package in Editable Mode with Dev Dependencies

```powershell
pip install -e ".[dev]"
```

### 3. Run the Test Suite

```powershell
pytest
```

### 4. Run the Analyzer

```powershell
# Scan fixture files using intra-procedural taint analysis
sqli-taint scan tests/fixtures --mode intraproc

# Scan using baseline syntactic mode and fail CI if findings exist
sqli-taint scan tests/fixtures/vulnerable --mode baseline --fail-on-findings

# Export SARIF 2.1.0 or JSON report to a file
sqli-taint scan tests/fixtures --mode intraproc --format sarif --output results.sarif
sqli-taint scan tests/fixtures --mode intraproc --format json --output results.json
```

## Inline Suppressions

Verified false positives can be suppressed on the sink line using `# sqli-taint: ignore` or `# nosec`:

```python
cursor.execute(f"SELECT * FROM {trusted_table}")  # sqli-taint: ignore
```

Suppressed findings are excluded from results and counted under `Suppressed` in the scan summary.

## CLI Usage

```text
sqli-taint [--version]
sqli-taint scan PATH [PATH...] [--mode baseline|intraproc|interproc]
                               [--format text|json|sarif]
                               [--output FILE]
                               [--config FILE]
                               [--exclude GLOB ...]
                               [--max-file-size BYTES]
                               [--fail-on-findings]
                               [-v|--verbose | -q|--quiet]
```

Exit codes:
- `0`: Scan completed with no findings (or findings without `--fail-on-findings`)
- `1`: Vulnerabilities found with `--fail-on-findings`
- `2`: Usage error, missing target path, unsupported mode, invalid config, or I/O error

## Custom Configuration

Pass `--config custom.toml` to extend or override [default.toml](sqli_taint/rules/default.toml). Nested tables (such as `[sources.flask]`) are deep-merged, and `[[sinks.calls]]` entries extend the built-in sinks by default (set `replace_defaults = true` under `[sinks]` to replace them).

## Packaging Releases

Avoid zipping the working directory directly (which includes `.venv/`, `.pytest_cache/`, `__pycache__/`, and `sqli_taint.egg-info/`). Use either `git archive` or the clean packaging script:

```powershell
# Option 1: Using git archive (inside a git repository)
git archive --format=zip --output=dist/sqli-taint.zip HEAD

# Option 2: Using the clean build script
python scripts/package_release.py --output dist/sqli-taint.zip
```
