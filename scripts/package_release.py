"""Create a clean release ZIP archive excluding local environments and build/cache bloat."""

from __future__ import annotations

import argparse
from pathlib import Path
import zipfile

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
    ".vscode",
}

EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".zip",
}


def _is_excluded(rel_path: Path) -> bool:
    """Return True if any path segment or suffix should be omitted from release archives."""
    for part in rel_path.parts:
        if part in EXCLUDED_DIRS or part.endswith(".egg-info"):
            return True
    return rel_path.suffix in EXCLUDED_SUFFIXES


def build_release_zip(root_dir: Path, output_path: Path) -> int:
    """Package clean project files under root_dir into output_path."""
    root_dir = root_dir.resolve()
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(root_dir.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path.resolve() == output_path:
                continue
            rel_path = file_path.relative_to(root_dir)
            if _is_excluded(rel_path):
                continue
            zf.write(file_path, arcname=rel_path.as_posix())
            count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a clean release ZIP for sqli-taint.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("dist/sqli-taint.zip"),
        help="Output ZIP file path (default: dist/sqli-taint.zip)",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    file_count = build_release_zip(project_root, args.output)
    print(f"Created {args.output} ({file_count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

