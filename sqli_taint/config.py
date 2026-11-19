"""Configuration loader and validator for sqli-taint."""

from __future__ import annotations

from importlib import resources
import logging
from pathlib import Path
import tomllib
from typing import Any

from sqli_taint.models import Config, SinkDef, SourceDef

logger = logging.getLogger(__name__)

KNOWN_SECTIONS = {"sinks", "sources", "sanitizers", "propagators"}
KNOWN_SINKS_KEYS = {"calls", "replace_defaults"}
KNOWN_SINK_ITEM_KEYS = {"name", "receivers", "arg_index", "kwarg_names", "allow_bare_call"}
KNOWN_SOURCES_KEYS = {"enable_builtin_sources", "flask", "django", "builtins"}
KNOWN_SOURCE_DEF_KEYS = {"attributes", "calls"}
KNOWN_SANITIZERS_KEYS = {"functions"}
KNOWN_PROPAGATORS_KEYS = {"methods", "functions"}


def _require_str_list(raw: dict[str, Any], key: str, context: str) -> list[str]:
    """Validate and extract a list of strings from a TOML dictionary."""
    if key not in raw:
        return []
    val = raw[key]
    if not isinstance(val, list):
        raise ValueError(f"Expected a list for '{key}' in {context}, got {type(val).__name__}")
    return [str(item) for item in val]


def _parse_sink_def(raw: dict[str, Any]) -> SinkDef:
    """Parse and validate a single sink definition dictionary."""
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Each [[sinks.calls]] entry must specify a non-empty string 'name'")

    context = f"[[sinks.calls]] ({name})"
    for key in raw:
        if key not in KNOWN_SINK_ITEM_KEYS:
            logger.warning("Unknown key in %s: '%s'", context, key)

    arg_index = raw.get("arg_index", 0)
    if isinstance(arg_index, bool) or not isinstance(arg_index, int):
        raise ValueError(f"Expected an integer for 'arg_index' in {context}, got {type(arg_index).__name__}")

    allow_bare_call = raw.get("allow_bare_call", False)
    if not isinstance(allow_bare_call, bool):
        raise ValueError(
            f"Expected a boolean for 'allow_bare_call' in {context}, got {type(allow_bare_call).__name__}"
        )

    return SinkDef(
        name=name,
        receivers=_require_str_list(raw, "receivers", context),
        arg_index=arg_index,
        kwarg_names=_require_str_list(raw, "kwarg_names", context),
        allow_bare_call=allow_bare_call,
    )


def _parse_source_def(raw: Any, section_name: str) -> SourceDef:
    """Parse and validate a source definition section."""
    if raw is None:
        return SourceDef()
    if not isinstance(raw, dict):
        raise ValueError(f"Expected a table for [{section_name}], got {type(raw).__name__}")
    return SourceDef(
        attributes=_require_str_list(raw, "attributes", f"[{section_name}]"),
        calls=_require_str_list(raw, "calls", f"[{section_name}]"),
    )


def _validate_keys(data: dict[str, Any]) -> None:
    """Validate keys in TOML data and issue warnings on unknown keys."""
    for key in data:
        if key not in KNOWN_SECTIONS:
            logger.warning("Unknown top-level config section: '%s'", key)
    if "sinks" in data and isinstance(data["sinks"], dict):
        for key in data["sinks"]:
            if key not in KNOWN_SINKS_KEYS:
                logger.warning("Unknown key in [sinks]: '%s'", key)
    if "sources" in data and isinstance(data["sources"], dict):
        for key in data["sources"]:
            if key not in KNOWN_SOURCES_KEYS:
                logger.warning("Unknown key in [sources]: '%s'", key)
        for sub in ("flask", "django", "builtins"):
            if sub in data["sources"] and isinstance(data["sources"][sub], dict):
                for k in data["sources"][sub]:
                    if k not in KNOWN_SOURCE_DEF_KEYS:
                        logger.warning("Unknown key in [sources.%s]: '%s'", sub, k)
    if "sanitizers" in data and isinstance(data["sanitizers"], dict):
        for key in data["sanitizers"]:
            if key not in KNOWN_SANITIZERS_KEYS:
                logger.warning("Unknown key in [sanitizers]: '%s'", key)
    if "propagators" in data and isinstance(data["propagators"], dict):
        for key in data["propagators"]:
            if key not in KNOWN_PROPAGATORS_KEYS:
                logger.warning("Unknown key in [propagators]: '%s'", key)


def _merge_config_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge user TOML overrides into default TOML data without clobbering nested defaults."""
    merged: dict[str, Any] = dict(base)
    for key, value in override.items():
        if key == "sinks" and isinstance(value, dict) and isinstance(merged.get("sinks"), dict):
            merged_sinks = dict(merged["sinks"])
            replace_defaults = bool(value.get("replace_defaults", False))
            for sub_key, sub_val in value.items():
                if sub_key == "calls" and isinstance(sub_val, list):
                    if replace_defaults:
                        merged_sinks["calls"] = list(sub_val)
                    else:
                        existing_calls = [
                            dict(item) for item in merged_sinks.get("calls", []) if isinstance(item, dict)
                        ]
                        by_name: dict[str, int] = {
                            str(item["name"]): idx
                            for idx, item in enumerate(existing_calls)
                            if "name" in item
                        }
                        for new_item in sub_val:
                            if isinstance(new_item, dict) and "name" in new_item and str(new_item["name"]) in by_name:
                                existing_calls[by_name[str(new_item["name"])]] = dict(new_item)
                            else:
                                existing_calls.append(new_item)
                        merged_sinks["calls"] = existing_calls
                else:
                    merged_sinks[sub_key] = sub_val
            merged["sinks"] = merged_sinks
        elif isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_config_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def _build_config_from_dict(data: dict[str, Any]) -> Config:
    """Convert validated TOML dictionary into Config object."""
    _validate_keys(data)

    sinks: list[SinkDef] = []
    sinks_section = data.get("sinks")
    if sinks_section is not None:
        if not isinstance(sinks_section, dict):
            raise ValueError(f"Expected a table for [sinks], got {type(sinks_section).__name__}")
        calls = sinks_section.get("calls")
        if calls is not None:
            if not isinstance(calls, list):
                raise ValueError(f"Expected a list for 'calls' in [sinks], got {type(calls).__name__}")
            for item in calls:
                if not isinstance(item, dict):
                    raise ValueError(f"Each [[sinks.calls]] entry must be a table, got {type(item).__name__}")
                sinks.append(_parse_sink_def(item))

    sources_section = data.get("sources")
    enable_builtin = False
    flask_src = SourceDef()
    django_src = SourceDef()
    builtin_src = SourceDef()

    if sources_section is not None:
        if not isinstance(sources_section, dict):
            raise ValueError(f"Expected a table for [sources], got {type(sources_section).__name__}")
        raw_enable = sources_section.get("enable_builtin_sources", False)
        if not isinstance(raw_enable, bool):
            raise ValueError(
                f"Expected a boolean for 'enable_builtin_sources' in [sources], got {type(raw_enable).__name__}"
            )
        enable_builtin = raw_enable
        flask_src = _parse_source_def(sources_section.get("flask"), "sources.flask")
        django_src = _parse_source_def(sources_section.get("django"), "sources.django")
        builtin_src = _parse_source_def(sources_section.get("builtins"), "sources.builtins")

    sanitizers: list[str] = []
    sanitizers_section = data.get("sanitizers")
    if sanitizers_section is not None:
        if not isinstance(sanitizers_section, dict):
            raise ValueError(f"Expected a table for [sanitizers], got {type(sanitizers_section).__name__}")
        sanitizers = _require_str_list(sanitizers_section, "functions", "[sanitizers]")

    propagator_methods: list[str] = []
    propagator_functions: list[str] = []
    propagators_section = data.get("propagators")
    if propagators_section is not None:
        if not isinstance(propagators_section, dict):
            raise ValueError(f"Expected a table for [propagators], got {type(propagators_section).__name__}")
        propagator_methods = _require_str_list(propagators_section, "methods", "[propagators]")
        propagator_functions = _require_str_list(propagators_section, "functions", "[propagators]")

    return Config(
        sinks=sinks,
        enable_builtin_sources=enable_builtin,
        flask_sources=flask_src,
        django_sources=django_src,
        builtin_sources=builtin_src,
        sanitizers=sanitizers,
        propagator_methods=propagator_methods,
        propagator_functions=propagator_functions,
    )


def _read_default_rules_text() -> str:
    """Read the bundled default.toml rules file using importlib.resources."""
    return resources.files("sqli_taint").joinpath("rules/default.toml").read_text(encoding="utf-8")


def load_config(config_path: Path | None = None) -> Config:
    """Load configuration from default.toml merged with an optional custom TOML file."""
    default_text = _read_default_rules_text()
    merged_data: dict[str, Any] = tomllib.loads(default_text)

    if config_path is not None:
        if not config_path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        user_text = config_path.read_text(encoding="utf-8-sig", errors="replace")
        user_data = tomllib.loads(user_text)
        merged_data = _merge_config_dicts(merged_data, user_data)

    return _build_config_from_dict(merged_data)
