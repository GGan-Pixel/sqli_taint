"""Shared AST sink matching and import-alias resolution utilities."""

from __future__ import annotations

import ast

from sqli_taint.models import SinkDef


def collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Build a mapping of local imported names to their canonical dotted paths."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                if alias.asname:
                    aliases[local_name] = alias.name
                else:
                    aliases[local_name] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                canonical = f"{module}.{alias.name}" if module else alias.name
                aliases[local_name] = canonical
    return aliases


def get_dotted_name(node: ast.AST) -> str:
    """Extract a dotted name from nested Attribute/Name AST nodes."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = get_dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def resolve_dotted_name(dotted: str, import_aliases: dict[str, str] | None) -> str:
    """Resolve the leading identifier of a dotted name through import aliases."""
    if not dotted or not import_aliases:
        return dotted
    parts = dotted.split(".")
    root = parts[0]
    if root in import_aliases:
        resolved_root = import_aliases[root]
        return ".".join([resolved_root, *parts[1:]])
    return dotted


def match_sink_call(
    node: ast.Call,
    sink_def: SinkDef,
    import_aliases: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Determine whether an AST Call matches a configured SinkDef."""
    if isinstance(node.func, ast.Attribute):
        if node.func.attr != sink_def.name:
            return False, ""
        rec_name = get_dotted_name(node.func.value)
        if not sink_def.receivers:
            full_name = f"{rec_name}.{node.func.attr}" if rec_name else node.func.attr
            return True, full_name

        resolved_rec = resolve_dotted_name(rec_name, import_aliases)
        candidate_parts = set(rec_name.split(".")) | set(resolved_rec.split("."))
        candidate_parts.discard("")
        if any(r in candidate_parts for r in sink_def.receivers):
            return True, f"{rec_name}.{node.func.attr}" if rec_name else node.func.attr
        return False, ""

    if isinstance(node.func, ast.Name):
        local_name = node.func.id
        if import_aliases and local_name in import_aliases:
            resolved = import_aliases[local_name]
            resolved_parts = resolved.split(".")
            symbol_name = resolved_parts[-1]
            module_parts = set(resolved_parts[:-1])
            if symbol_name != sink_def.name:
                return False, ""
            if not sink_def.receivers or any(r in module_parts for r in sink_def.receivers):
                return True, local_name
            return False, ""

        if local_name != sink_def.name:
            return False, ""
        if not sink_def.receivers or sink_def.allow_bare_call:
            return True, local_name

    return False, ""


def extract_sink_arguments(node: ast.Call, sink_def: SinkDef) -> list[ast.AST]:
    """Extract AST nodes that correspond to the vulnerable query parameter position."""
    vulnerable_args: list[ast.AST] = []

    if sink_def.arg_index >= 0 and len(node.args) > sink_def.arg_index:
        vulnerable_args.append(node.args[sink_def.arg_index])

    for kw in node.keywords:
        if kw.arg in sink_def.kwarg_names:
            vulnerable_args.append(kw.value)

    return vulnerable_args

