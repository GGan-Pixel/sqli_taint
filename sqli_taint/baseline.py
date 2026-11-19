"""Baseline syntactic pattern matcher for SQL injection detection."""

from __future__ import annotations

import ast
from collections.abc import Collection

from sqli_taint.models import AnalysisContext, Finding, Location, TraceStep
from sqli_taint.sinks import collect_import_aliases, extract_sink_arguments, match_sink_call

DEFAULT_PROPAGATOR_METHODS = frozenset(
    {"strip", "lstrip", "rstrip", "lower", "upper", "replace"}
)


def _is_constant_node(node: ast.AST) -> bool:
    """Check if an AST expression represents a compile-time constant value."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_constant_node(node.left) and _is_constant_node(node.right)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_constant_node(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (_is_constant_node(k) if k is not None else True) and _is_constant_node(v)
            for k, v in zip(node.keys, node.values)
        )
    return False


def _collect_add_leaves(node: ast.AST) -> list[ast.AST]:
    """Flatten an addition tree into its leaf operands."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _collect_add_leaves(node.left) + _collect_add_leaves(node.right)
    return [node]


def is_baseline_vulnerable(
    expr: ast.AST,
    propagator_methods: Collection[str] | None = None,
) -> bool:
    """Check if an expression syntactically constructs SQL dynamically without parameterization."""
    methods = (
        set(propagator_methods)
        if propagator_methods is not None
        else set(DEFAULT_PROPAGATOR_METHODS)
    )

    if isinstance(expr, (ast.List, ast.Tuple)):
        return any(is_baseline_vulnerable(elt, methods) for elt in expr.elts)

    if isinstance(expr, ast.Dict):
        return any(
            (k is not None and is_baseline_vulnerable(k, methods))
            or is_baseline_vulnerable(v, methods)
            for k, v in zip(expr.keys, expr.values)
        )

    if isinstance(expr, ast.IfExp):
        return is_baseline_vulnerable(expr.body, methods) or is_baseline_vulnerable(
            expr.orelse, methods
        )

    # 1. f-strings with interpolation
    if isinstance(expr, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in expr.values)

    # 2. String concatenation (+) with non-constants
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        leaves = _collect_add_leaves(expr)
        return any(not _is_constant_node(leaf) for leaf in leaves)

    # 3. % formatting with non-constants
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        return not _is_constant_node(expr.left) or not _is_constant_node(expr.right)

    # 4. String formatting / joining / chained propagator methods
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        attr = expr.func.attr
        if attr == "format":
            receiver_non_const = not _is_constant_node(expr.func.value)
            args_non_const = any(not _is_constant_node(arg) for arg in expr.args)
            kwargs_non_const = any(not _is_constant_node(kw.value) for kw in expr.keywords)
            return receiver_non_const or args_non_const or kwargs_non_const

        if attr == "join":
            if not _is_constant_node(expr.func.value):
                return True
            return any(not _is_constant_node(arg) for arg in expr.args)

        if attr in methods:
            if is_baseline_vulnerable(expr.func.value, methods):
                return True
            if attr == "replace" and any(not _is_constant_node(arg) for arg in expr.args):
                return True

    # 5. str(...) wrapping a dynamically constructed query
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id == "str"
        and expr.args
    ):
        return is_baseline_vulnerable(expr.args[0], methods)

    return False


def analyze_baseline(tree: ast.AST, rel_path: str, context: AnalysisContext) -> list[Finding]:
    """Scan an AST tree for syntactic pattern-based SQL injection at sink calls."""
    findings: list[Finding] = []
    seen_locations: set[tuple[int, int]] = set()
    import_aliases = collect_import_aliases(tree)
    propagator_methods = set(context.config.propagator_methods) | set(DEFAULT_PROPAGATOR_METHODS)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        for sink_def in context.config.sinks:
            matched, sink_display_name = match_sink_call(node, sink_def, import_aliases)
            if not matched:
                continue

            query_nodes = extract_sink_arguments(node, sink_def)
            for query_expr in query_nodes:
                if is_baseline_vulnerable(query_expr, propagator_methods):
                    line = node.lineno
                    col = node.col_offset + 1
                    loc_key = (line, col)
                    if loc_key in seen_locations:
                        continue
                    seen_locations.add(loc_key)

                    end_line = getattr(node, "end_lineno", line)
                    end_col = getattr(node, "end_col_offset", col)
                    if end_col is not None:
                        end_col += 1

                    loc = Location(
                        file=rel_path,
                        line=line,
                        column=col,
                        end_line=end_line,
                        end_column=end_col,
                    )
                    trace = [
                        TraceStep(
                            location=loc,
                            description=f"reaches sink {sink_display_name}",
                        )
                    ]
                    finding = Finding(
                        rule_id="SQLI001",
                        message=f"Possible SQL injection in {sink_display_name}: query constructed using string formatting/concatenation without parameterized queries",
                        file=rel_path,
                        line=line,
                        column=col,
                        end_line=end_line,
                        sink_name=sink_display_name,
                        source_description="syntactic string construction in query argument",
                        trace=trace,
                        mode="baseline",
                        confidence="high",
                    )
                    findings.append(finding)
                    break

    findings.sort(key=lambda f: f.sort_key)
    return findings
