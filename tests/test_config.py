"""Tests for configuration parsing, deep merging, and schema validation."""

from __future__ import annotations

import logging
from pathlib import Path
import tomllib
import pytest

from sqli_taint.config import load_config


def test_load_default_config() -> None:
    """Assert default config loads successfully with expected sinks and options."""
    config = load_config()

    sink_names = {s.name for s in config.sinks}
    expected_sinks = {
        "execute",
        "executemany",
        "executescript",
        "raw",
        "extra",
        "text",
        "read_sql",
        "read_sql_query",
        "RawSQL",
    }
    assert expected_sinks.issubset(sink_names)
    assert not config.enable_builtin_sources
    assert "int" in config.sanitizers
    assert "format" in config.propagator_methods
    text_sink = next(s for s in config.sinks if s.name == "text")
    assert text_sink.allow_bare_call is True


def test_missing_config_file(tmp_path: Path) -> None:
    """Assert loading a nonexistent config file raises FileNotFoundError."""
    missing = tmp_path / "nonexistent.toml"
    with pytest.raises(FileNotFoundError):
        load_config(missing)


def test_malformed_toml_file(tmp_path: Path) -> None:
    """Assert loading a malformed TOML file raises TOMLDecodeError."""
    bad_toml = tmp_path / "bad.toml"
    bad_toml.write_text("sinks = [unterminated", encoding="utf-8")
    with pytest.raises(tomllib.TOMLDecodeError):
        load_config(bad_toml)


def test_custom_config_override(tmp_path: Path) -> None:
    """Assert user configuration can override or extend default settings."""
    custom_toml = tmp_path / "custom.toml"
    custom_toml.write_text(
        """
        [sources]
        enable_builtin_sources = true

        [sanitizers]
        functions = ["custom_clean"]
        """,
        encoding="utf-8",
    )
    config = load_config(custom_toml)
    assert config.enable_builtin_sources is True
    assert config.sanitizers == ["custom_clean"]
    sink_names = {s.name for s in config.sinks}
    assert "execute" in sink_names


def test_deep_merge_preserves_nested_sources_and_default_sinks(tmp_path: Path) -> None:
    """Assert partial overrides in [sources.flask] and [[sinks.calls]] do not wipe defaults."""
    custom_toml = tmp_path / "extend.toml"
    custom_toml.write_text(
        """
        [sources.flask]
        calls = ["request.get_data"]

        [[sinks.calls]]
        name = "custom_exec"
        receivers = ["mydb"]
        arg_index = 0
        kwarg_names = ["stmt"]
        """,
        encoding="utf-8",
    )
    config = load_config(custom_toml)
    # Default flask attributes must survive when only calls is overridden
    assert "request.args" in config.flask_sources.attributes
    assert config.flask_sources.calls == ["request.get_data"]
    # Built-in sinks must survive when adding a custom sink
    sink_names = {s.name for s in config.sinks}
    assert {"execute", "raw", "read_sql", "custom_exec"}.issubset(sink_names)


def test_replace_default_sinks_flag(tmp_path: Path) -> None:
    """Assert sinks.replace_defaults = true explicitly replaces built-in sinks."""
    custom_toml = tmp_path / "replace.toml"
    custom_toml.write_text(
        """
        [sinks]
        replace_defaults = true

        [[sinks.calls]]
        name = "only_sink"
        receivers = []
        arg_index = 0
        """,
        encoding="utf-8",
    )
    config = load_config(custom_toml)
    assert [s.name for s in config.sinks] == ["only_sink"]


def test_config_rejects_string_for_list_fields(tmp_path: Path) -> None:
    """Assert passing a string instead of a list raises ValueError instead of splitting characters."""
    bad_sink = tmp_path / "bad_sink.toml"
    bad_sink.write_text(
        """
        [[sinks.calls]]
        name = "my_exec"
        receivers = "mydb"
        """,
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Expected a list for 'receivers'"):
        load_config(bad_sink)

    bad_source = tmp_path / "bad_source.toml"
    bad_source.write_text(
        """
        [sources.flask]
        attributes = "request.args"
        """,
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Expected a list for 'attributes'"):
        load_config(bad_source)


def test_config_rejects_invalid_scalar_types(tmp_path: Path) -> None:
    """Assert invalid arg_index and allow_bare_call types raise ValueError."""
    bad_idx = tmp_path / "bad_idx.toml"
    bad_idx.write_text(
        """
        [[sinks.calls]]
        name = "my_exec"
        arg_index = true
        """,
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Expected an integer for 'arg_index'"):
        load_config(bad_idx)


def test_empty_config_sections(tmp_path: Path) -> None:
    """Assert empty sections in user configuration do not cause errors."""
    empty_toml = tmp_path / "empty.toml"
    empty_toml.write_text(
        """
        [sinks]
        [sources]
        [sanitizers]
        [propagators]
        """,
        encoding="utf-8",
    )
    config = load_config(empty_toml)
    assert config is not None


def test_bom_prefixed_custom_config(tmp_path: Path) -> None:
    """Assert custom TOML files with UTF-8 BOM load cleanly."""
    bom_toml = tmp_path / "bom.toml"
    bom_toml.write_bytes(b"\xef\xbb\xbf[sources]\nenable_builtin_sources = true\n")
    config = load_config(bom_toml)
    assert config.enable_builtin_sources is True


def test_unknown_keys_warning(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Assert unknown configuration keys (including inside [[sinks.calls]]) log a warning."""
    unknown_toml = tmp_path / "unknown.toml"
    unknown_toml.write_text(
        """
        [unknown_section]
        foo = "bar"

        [sinks]
        unknown_sink_key = 123

        [[sinks.calls]]
        name = "custom_sink"
        kwarg_name = ["sql"]
        """,
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        load_config(unknown_toml)

    assert any(
        "Unknown top-level config section: 'unknown_section'" in record.message
        for record in caplog.records
    )
    assert any(
        "Unknown key in [sinks]: 'unknown_sink_key'" in record.message
        for record in caplog.records
    )
    assert any(
        "Unknown key in [[sinks.calls]] (custom_sink): 'kwarg_name'" in record.message
        for record in caplog.records
    )
