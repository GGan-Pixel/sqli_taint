"""Intra-procedural taint analyzer (Stage 2) for SQL injection detection."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from sqli_taint.models import AnalysisContext, Finding, Location, TraceStep
from sqli_taint.sinks import (
    collect_import_aliases,
    extract_sink_arguments,
    get_dotted_name,
    match_sink_call,
    resolve_dotted_name,
)

# Builtin functions whose return values are guaranteed primitive/non-injectable values.
SAFE_BUILTIN_FUNCTIONS = frozenset(
    {"len", "isinstance", "issubclass", "callable", "id", "hash", "ord", "abs", "round"}
)

# Conventional receiver parameter names that are not user data.
SKIPPED_PARAM_NAMES = frozenset({"self", "cls"})


@dataclass(frozen=True)
class _TaintValue:
    """Immutable taint metadata propagated along intra-procedural data flows."""

    source_description: str
    confidence: str  # "high" for explicit sources, "medium" for function parameters
    trace: tuple[TraceStep, ...]

    def with_step(self, location: Location, description: str) -> _TaintValue:
        """Return a new _TaintValue with an appended trace step (deduplicating identical adjacent steps)."""
        if self.trace:
            last = self.trace[-1]
            if (
                last.location.line == location.line
                and last.location.column == location.column
                and last.description == description
            ):
                return self
        return _TaintValue(
            source_description=self.source_description,
            confidence=self.confidence,
            trace=(*self.trace, TraceStep(location=location, description=description)),
        )


def _prefer_taint(a: _TaintValue | None, b: _TaintValue | None) -> _TaintValue | None:
    """Choose the higher-confidence taint when merging two taint values."""
    if a is None:
        return b
    if b is None:
        return a
    if a.confidence == "high":
        return a
    if b.confidence == "high":
        return b
    return a


class _TaintEnv:
    """Mutable variable and container taint state within a single function or module scope."""

    def __init__(
        self,
        vars_map: dict[str, _TaintValue] | None = None,
        dict_keys: dict[str, dict[str, _TaintValue]] | None = None,
        seq_items: dict[str, dict[int, _TaintValue]] | None = None,
    ) -> None:
        self.vars: dict[str, _TaintValue] = dict(vars_map) if vars_map else {}
        self.dict_keys: dict[str, dict[str, _TaintValue]] = (
            {k: dict(v) for k, v in dict_keys.items()} if dict_keys else {}
        )
        self.seq_items: dict[str, dict[int, _TaintValue]] = (
            {k: dict(v) for k, v in seq_items.items()} if seq_items else {}
        )

    def copy(self) -> _TaintEnv:
        return _TaintEnv(self.vars, self.dict_keys, self.seq_items)

    def set_var(self, name: str, taint: _TaintValue) -> None:
        self.vars[name] = taint
        self.dict_keys.pop(name, None)
        self.seq_items.pop(name, None)

    def clear_var(self, name: str) -> None:
        self.vars.pop(name, None)
        self.dict_keys.pop(name, None)
        self.seq_items.pop(name, None)

    def set_dict_literal(
        self,
        name: str,
        key_taints: dict[str, _TaintValue],
        fallback_taint: _TaintValue | None = None,
    ) -> None:
        self.seq_items.pop(name, None)
        self.dict_keys[name] = dict(key_taints)
        if fallback_taint is not None:
            self.vars[name] = fallback_taint
        else:
            self.vars.pop(name, None)

    def set_seq_literal(
        self,
        name: str,
        index_taints: dict[int, _TaintValue],
        fallback_taint: _TaintValue | None = None,
    ) -> None:
        self.dict_keys.pop(name, None)
        self.seq_items[name] = dict(index_taints)
        if fallback_taint is not None:
            self.vars[name] = fallback_taint
        else:
            self.vars.pop(name, None)

    def any_container_taint(self, name: str) -> _TaintValue | None:
        result = self.vars.get(name)
        if name in self.dict_keys:
            for val in self.dict_keys[name].values():
                result = _prefer_taint(result, val)
        if name in self.seq_items:
            for val in self.seq_items[name].values():
                result = _prefer_taint(result, val)
        return result

    def join(self, other: _TaintEnv) -> _TaintEnv:
        """Conservative union join across control-flow branches."""
        joined = _TaintEnv()
        for name in set(self.vars) | set(other.vars):
            merged = _prefer_taint(self.vars.get(name), other.vars.get(name))
            if merged is not None:
                joined.vars[name] = merged

        for name in set(self.dict_keys) | set(other.dict_keys):
            d1 = self.dict_keys.get(name, {})
            d2 = other.dict_keys.get(name, {})
            merged_dict: dict[str, _TaintValue] = {}
            for k in set(d1) | set(d2):
                m = _prefer_taint(d1.get(k), d2.get(k))
                if m is not None:
                    merged_dict[k] = m
            if merged_dict or (name in self.dict_keys and name in other.dict_keys):
                joined.dict_keys[name] = merged_dict

        for name in set(self.seq_items) | set(other.seq_items):
            s1 = self.seq_items.get(name, {})
            s2 = other.seq_items.get(name, {})
            merged_seq: dict[int, _TaintValue] = {}
            for idx in set(s1) | set(s2):
                m = _prefer_taint(s1.get(idx), s2.get(idx))
                if m is not None:
                    merged_seq[idx] = m
            if merged_seq or (name in self.seq_items and name in other.seq_items):
                joined.seq_items[name] = merged_seq

        return joined

    def replace_with(self, other: _TaintEnv) -> None:
        self.vars = other.vars
        self.dict_keys = other.dict_keys
        self.seq_items = other.seq_items


def _always_terminates(stmts: list[ast.stmt]) -> bool:
    """Return True if a statement block unconditionally exits via return or raise."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If) and last.orelse:
        return _always_terminates(last.body) and _always_terminates(last.orelse)
    return False


class _IntraProcAnalyzer:
    """AST-based intra-procedural taint engine for a single Python module."""

    def __init__(self, tree: ast.AST, rel_path: str, context: AnalysisContext) -> None:
        self.tree = tree
        self.rel_path = rel_path
        self.context = context
        self.config = context.config
        self.import_aliases = collect_import_aliases(tree)
        self.findings: list[Finding] = []
        self.seen_locations: set[tuple[int, int]] = set()

        # Precompute configured source, sanitizer, and propagator lookup sets
        self.source_attributes: set[str] = set(self.config.flask_sources.attributes) | set(
            self.config.django_sources.attributes
        )
        self.source_calls: set[str] = set(self.config.flask_sources.calls) | set(
            self.config.django_sources.calls
        )
        if self.config.enable_builtin_sources:
            self.source_attributes |= set(self.config.builtin_sources.attributes)
            self.source_calls |= set(self.config.builtin_sources.calls)

        self.sanitizers: set[str] = set(self.config.sanitizers) | set(SAFE_BUILTIN_FUNCTIONS)
        self.propagator_methods: set[str] = set(self.config.propagator_methods)
        self.propagator_functions: set[str] = set(self.config.propagator_functions)

    def _loc(self, node: ast.AST) -> Location:
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        end_line = getattr(node, "end_lineno", line)
        end_col = getattr(node, "end_col_offset", None)
        if end_col is not None:
            end_col += 1
        return Location(
            file=self.rel_path,
            line=line,
            column=col,
            end_line=end_line,
            end_column=end_col,
        )

    def _is_source_attribute(self, node: ast.AST) -> str | None:
        """Return matched source attribute name if node references a configured taint source."""
        dotted = get_dotted_name(node)
        if not dotted:
            return None
        resolved = resolve_dotted_name(dotted, self.import_aliases)
        for candidate in (dotted, resolved):
            for src in self.source_attributes:
                if candidate == src or candidate.startswith(f"{src}."):
                    return src
        return None

    def _is_source_call(self, node: ast.Call) -> str | None:
        """Return matched source call name if call invokes a configured taint source."""
        dotted = get_dotted_name(node.func)
        if not dotted:
            return None
        resolved = resolve_dotted_name(dotted, self.import_aliases)
        for candidate in (dotted, resolved):
            if candidate in self.source_calls:
                return candidate
        # Method calls on a source attribute (e.g., request.args.get("id"), os.environ.get("K"))
        if isinstance(node.func, ast.Attribute):
            src_attr = self._is_source_attribute(node.func.value)
            if src_attr is not None:
                return f"{src_attr}.{node.func.attr}"
        return None

    def _is_sanitizer_call(self, node: ast.Call) -> bool:
        """Return True if call invokes a configured sanitizer or safe primitive builtin."""
        dotted = get_dotted_name(node.func)
        if not dotted:
            return False
        resolved = resolve_dotted_name(dotted, self.import_aliases)
        for candidate in (dotted, resolved):
            if candidate in self.sanitizers:
                return True
        return False

    def _record_finding(
        self,
        call_node: ast.Call,
        sink_display_name: str,
        taint: _TaintValue,
    ) -> None:
        line = call_node.lineno
        col = call_node.col_offset + 1
        loc_key = (line, col)
        if loc_key in self.seen_locations:
            return
        self.seen_locations.add(loc_key)

        sink_loc = self._loc(call_node)
        final_taint = taint.with_step(sink_loc, f"reaches sink {sink_display_name}")

        self.findings.append(
            Finding(
                rule_id="SQLI001",
                message=(
                    f"Possible SQL injection in {sink_display_name}: "
                    f"tainted data from {taint.source_description} reaches database sink without sanitization"
                ),
                file=self.rel_path,
                line=line,
                column=col,
                end_line=sink_loc.end_line,
                sink_name=sink_display_name,
                source_description=taint.source_description,
                trace=list(final_taint.trace),
                mode="intraproc",
                confidence=taint.confidence,
            )
        )

    def _check_sink_call(self, node: ast.Call, env: _TaintEnv) -> None:
        """Check whether a Call node is a configured SQL sink receiving tainted arguments."""
        for sink_def in self.config.sinks:
            matched, sink_display_name = match_sink_call(node, sink_def, self.import_aliases)
            if not matched:
                continue
            query_nodes = extract_sink_arguments(node, sink_def)
            for query_expr in query_nodes:
                taint = self._eval_expr(query_expr, env)
                if taint is not None:
                    self._record_finding(node, sink_display_name, taint)
                    break

    def _eval_expr(self, node: ast.AST, env: _TaintEnv) -> _TaintValue | None:
        """Evaluate an AST expression, returning its _TaintValue if tainted, and checking embedded sinks."""
        if isinstance(node, ast.Constant):
            return None

        if isinstance(node, ast.Name):
            src = self._is_source_attribute(node)
            if src is not None:
                return _TaintValue(
                    source_description=f"source '{src}'",
                    confidence="high",
                    trace=(TraceStep(self._loc(node), f"tainted source {src}"),),
                )
            return env.any_container_taint(node.id)

        if isinstance(node, ast.Attribute):
            src = self._is_source_attribute(node)
            if src is not None:
                return _TaintValue(
                    source_description=f"source '{src}'",
                    confidence="high",
                    trace=(TraceStep(self._loc(node), f"tainted source {src}"),),
                )
            return self._eval_expr(node.value, env)

        if isinstance(node, ast.Subscript):
            src = self._is_source_attribute(node.value)
            if src is not None:
                self._eval_expr(node.slice, env)
                return _TaintValue(
                    source_description=f"source '{src}'",
                    confidence="high",
                    trace=(TraceStep(self._loc(node), f"tainted source {src}"),),
                )

            self._eval_expr(node.slice, env)
            if isinstance(node.value, ast.Name):
                var_name = node.value.id
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    if var_name in env.dict_keys:
                        key_taint = env.dict_keys[var_name].get(node.slice.value)
                        if key_taint is not None:
                            return key_taint.with_step(
                                self._loc(node),
                                f"retrieved from dict '{var_name}[{node.slice.value!r}]'",
                            )
                        return env.vars.get(var_name)
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int):
                    if var_name in env.seq_items:
                        idx_taint = env.seq_items[var_name].get(node.slice.value)
                        if idx_taint is not None:
                            return idx_taint.with_step(
                                self._loc(node),
                                f"retrieved from sequence '{var_name}[{node.slice.value}]'",
                            )
                        return env.vars.get(var_name)
                return env.any_container_taint(var_name)

            return self._eval_expr(node.value, env)

        if isinstance(node, ast.JoinedStr):
            result: _TaintValue | None = None
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    t = self._eval_expr(value.value, env)
                    result = _prefer_taint(result, t)
            if result is not None:
                return result.with_step(self._loc(node), "interpolated into f-string")
            return None

        if isinstance(node, ast.BinOp):
            left_t = self._eval_expr(node.left, env)
            right_t = self._eval_expr(node.right, env)
            merged = _prefer_taint(left_t, right_t)
            if merged is None:
                return None
            if isinstance(node.op, ast.Add):
                return merged.with_step(self._loc(node), "propagated via string concatenation")
            if isinstance(node.op, ast.Mod):
                return merged.with_step(self._loc(node), "propagated via '%' formatting")
            return merged

        if isinstance(node, ast.IfExp):
            self._eval_expr(node.test, env)
            body_t = self._eval_expr(node.body, env)
            else_t = self._eval_expr(node.orelse, env)
            return _prefer_taint(body_t, else_t)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            result = None
            for elt in node.elts:
                t = self._eval_expr(elt, env)
                result = _prefer_taint(result, t)
            return result

        if isinstance(node, ast.Dict):
            result = None
            for k, v in zip(node.keys, node.values):
                if k is not None:
                    result = _prefer_taint(result, self._eval_expr(k, env))
                result = _prefer_taint(result, self._eval_expr(v, env))
            return result

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            comp_env = env.copy()
            for gen in node.generators:
                iter_t = self._eval_expr(gen.iter, comp_env)
                self._bind_taint_to_target(gen.target, iter_t, comp_env)
                for cond in gen.ifs:
                    self._eval_expr(cond, comp_env)
            return self._eval_expr(node.elt, comp_env)

        if isinstance(node, ast.DictComp):
            comp_env = env.copy()
            for gen in node.generators:
                iter_t = self._eval_expr(gen.iter, comp_env)
                self._bind_taint_to_target(gen.target, iter_t, comp_env)
                for cond in gen.ifs:
                    self._eval_expr(cond, comp_env)
            k_t = self._eval_expr(node.key, comp_env)
            v_t = self._eval_expr(node.value, comp_env)
            return _prefer_taint(k_t, v_t)

        if isinstance(node, ast.Starred):
            return self._eval_expr(node.value, env)

        if isinstance(node, ast.UnaryOp):
            return self._eval_expr(node.operand, env)

        if isinstance(node, ast.BoolOp):
            result = None
            for val in node.values:
                result = _prefer_taint(result, self._eval_expr(val, env))
            return result

        if isinstance(node, ast.Compare):
            self._eval_expr(node.left, env)
            for comp in node.comparators:
                self._eval_expr(comp, env)
            return None

        if isinstance(node, ast.Call):
            return self._eval_call(node, env)

        if isinstance(node, ast.Await):
            return self._eval_expr(node.value, env)

        if isinstance(node, ast.NamedExpr):
            val_t = self._eval_expr(node.value, env)
            if isinstance(node.target, ast.Name):
                if val_t is not None:
                    env.set_var(
                        node.target.id,
                        val_t.with_step(self._loc(node), f"assigned to '{node.target.id}'"),
                    )
                else:
                    env.clear_var(node.target.id)
            return val_t

        return None

    def _eval_call(self, node: ast.Call, env: _TaintEnv) -> _TaintValue | None:
        """Evaluate a Call expression for sinks, sources, sanitizers, and propagation."""
        # 1. Check if this call is a SQL sink
        self._check_sink_call(node, env)

        # 2. Check if this call is a configured taint source
        src_call = self._is_source_call(node)
        if src_call is not None:
            for arg in node.args:
                self._eval_expr(arg, env)
            for kw in node.keywords:
                self._eval_expr(kw.value, env)
            return _TaintValue(
                source_description=f"source '{src_call}'",
                confidence="high",
                trace=(TraceStep(self._loc(node), f"tainted source {src_call}()"),),
            )

        # 3. Check if this call is a sanitizer (kills taint)
        if self._is_sanitizer_call(node):
            for arg in node.args:
                self._eval_expr(arg, env)
            for kw in node.keywords:
                self._eval_expr(kw.value, env)
            return None

        # 4. Key-sensitive dict.get("key", default) lookup on tracked dict variable
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in env.dict_keys
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            dict_name = node.func.value.id
            key = node.args[0].value
            default_t = self._eval_expr(node.args[1], env) if len(node.args) > 1 else None
            key_t = env.dict_keys[dict_name].get(key) or env.vars.get(dict_name)
            merged = _prefer_taint(key_t, default_t)
            if merged is not None:
                return merged.with_step(
                    self._loc(node), f"retrieved via '{dict_name}.get({key!r})'"
                )
            return None

        # 5. Evaluate receiver, positional args, and keyword args
        receiver_t: _TaintValue | None = None
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and (
                node.func.value.id in env.dict_keys or node.func.value.id in env.seq_items
            ):
                receiver_t = env.any_container_taint(node.func.value.id)
            else:
                receiver_t = self._eval_expr(node.func.value, env)
        else:
            self._eval_expr(node.func, env)

        args_t: _TaintValue | None = None
        for arg in node.args:
            args_t = _prefer_taint(args_t, self._eval_expr(arg, env))
        for kw in node.keywords:
            args_t = _prefer_taint(args_t, self._eval_expr(kw.value, env))

        merged = _prefer_taint(receiver_t, args_t)
        if merged is None:
            return None

        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if method in self.propagator_methods or method in {"format", "join"}:
                return merged.with_step(self._loc(node), f"propagated via '.{method}()'")
            return merged.with_step(self._loc(node), f"propagated via method '.{method}()'")

        func_name = get_dotted_name(node.func)
        if func_name:
            return merged.with_step(self._loc(node), f"propagated via '{func_name}()'")
        return merged

    def _assign_target(self, target: ast.AST, value_node: ast.AST, env: _TaintEnv) -> None:
        """Bind taint from value_node to an assignment target (Name, Tuple/List, Subscript)."""
        if isinstance(target, ast.Name) and isinstance(value_node, ast.Dict):
            key_taints: dict[str, _TaintValue] = {}
            fallback: _TaintValue | None = None
            for k, v in zip(value_node.keys, value_node.values):
                val_t = self._eval_expr(v, env)
                if k is None:
                    fallback = _prefer_taint(fallback, val_t)
                elif isinstance(k, ast.Constant) and isinstance(k.value, str):
                    if val_t is not None:
                        key_taints[k.value] = val_t.with_step(
                            self._loc(v), f"stored in '{target.id}[{k.value!r}]'"
                        )
                else:
                    key_t = self._eval_expr(k, env)
                    fallback = _prefer_taint(fallback, _prefer_taint(key_t, val_t))
            env.set_dict_literal(target.id, key_taints, fallback)
            return

        if isinstance(target, ast.Name) and isinstance(value_node, (ast.List, ast.Tuple)):
            idx_taints: dict[int, _TaintValue] = {}
            fallback = None
            for idx, elt in enumerate(value_node.elts):
                elt_t = self._eval_expr(elt, env)
                if isinstance(elt, ast.Starred):
                    fallback = _prefer_taint(fallback, elt_t)
                elif elt_t is not None:
                    idx_taints[idx] = elt_t.with_step(
                        self._loc(elt), f"stored in '{target.id}[{idx}]'"
                    )
            env.set_seq_literal(target.id, idx_taints, fallback)
            return

        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value_node, (ast.Tuple, ast.List)):
            if len(target.elts) == len(value_node.elts) and not any(
                isinstance(e, ast.Starred) for e in (*target.elts, *value_node.elts)
            ):
                for sub_t, sub_v in zip(target.elts, value_node.elts):
                    self._assign_target(sub_t, sub_v, env)
                return

        val_t = self._eval_expr(value_node, env)
        self._bind_taint_to_target(target, val_t, env)

    def _bind_taint_to_target(
        self,
        target: ast.AST,
        taint: _TaintValue | None,
        env: _TaintEnv,
    ) -> None:
        if isinstance(target, ast.Name):
            if taint is not None:
                env.set_var(
                    target.id,
                    taint.with_step(self._loc(target), f"assigned to '{target.id}'"),
                )
            else:
                env.clear_var(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                if isinstance(elt, ast.Starred):
                    self._bind_taint_to_target(elt.value, taint, env)
                else:
                    self._bind_taint_to_target(elt, taint, env)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            var_name = target.value.id
            if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                bucket = env.dict_keys.setdefault(var_name, {})
                if taint is not None:
                    bucket[target.slice.value] = taint.with_step(
                        self._loc(target),
                        f"assigned to '{var_name}[{target.slice.value!r}]'",
                    )
                else:
                    bucket.pop(target.slice.value, None)
            elif isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, int):
                seq_bucket = env.seq_items.setdefault(var_name, {})
                if taint is not None:
                    seq_bucket[target.slice.value] = taint.with_step(
                        self._loc(target),
                        f"assigned to '{var_name}[{target.slice.value}]'",
                    )
                else:
                    seq_bucket.pop(target.slice.value, None)
            elif taint is not None:
                env.vars[var_name] = taint.with_step(
                    self._loc(target), f"stored in container '{var_name}'"
                )

    def _exec_block(self, stmts: list[ast.stmt], env: _TaintEnv) -> None:
        for stmt in stmts:
            self._exec_stmt(stmt, env)

    def _exec_stmt(self, stmt: ast.stmt, env: _TaintEnv) -> None:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                self._assign_target(target, stmt.value, env)
            return

        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._assign_target(stmt.target, stmt.value, env)
            return

        if isinstance(stmt, ast.AugAssign):
            rhs_t = self._eval_expr(stmt.value, env)
            if isinstance(stmt.target, ast.Name):
                lhs_t = env.vars.get(stmt.target.id)
                merged = _prefer_taint(lhs_t, rhs_t)
                if merged is not None:
                    env.set_var(
                        stmt.target.id,
                        merged.with_step(
                            self._loc(stmt), f"updated '{stmt.target.id}' via augmented assignment"
                        ),
                    )
            return

        if isinstance(stmt, ast.Expr):
            if isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute):
                attr = stmt.value.func.attr
                if attr in {"append", "extend", "insert", "update"} and isinstance(
                    stmt.value.func.value, ast.Name
                ):
                    container_name = stmt.value.func.value.id
                    arg_t: _TaintValue | None = None
                    for arg in stmt.value.args:
                        arg_t = _prefer_taint(arg_t, self._eval_expr(arg, env))
                    for kw in stmt.value.keywords:
                        arg_t = _prefer_taint(arg_t, self._eval_expr(kw.value, env))
                    if arg_t is not None:
                        env.vars[container_name] = _prefer_taint(
                            env.vars.get(container_name),
                            arg_t.with_step(
                                self._loc(stmt),
                                f"mutated container '{container_name}' via '.{attr}()'",
                            ),
                        )
                    return
            self._eval_expr(stmt.value, env)
            return

        if isinstance(stmt, ast.If):
            self._eval_expr(stmt.test, env)
            then_env = env.copy()
            else_env = env.copy()
            self._exec_block(stmt.body, then_env)
            self._exec_block(stmt.orelse, else_env)

            then_exits = _always_terminates(stmt.body)
            else_exits = _always_terminates(stmt.orelse)
            if then_exits and not else_exits:
                env.replace_with(else_env)
            elif else_exits and not then_exits:
                env.replace_with(then_env)
            else:
                env.replace_with(then_env.join(else_env))
            return

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            iter_t = self._eval_expr(stmt.iter, env)
            loop_env = env.copy()
            for _ in range(2):
                self._bind_taint_to_target(stmt.target, iter_t, loop_env)
                self._exec_block(stmt.body, loop_env)
                loop_env = env.join(loop_env)
            if stmt.orelse:
                self._exec_block(stmt.orelse, loop_env)
            env.replace_with(loop_env)
            return

        if isinstance(stmt, ast.While):
            self._eval_expr(stmt.test, env)
            loop_env = env.copy()
            for _ in range(2):
                self._eval_expr(stmt.test, loop_env)
                self._exec_block(stmt.body, loop_env)
                loop_env = env.join(loop_env)
            if stmt.orelse:
                self._exec_block(stmt.orelse, loop_env)
            env.replace_with(loop_env)
            return

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                ctx_t = self._eval_expr(item.context_expr, env)
                if item.optional_vars is not None:
                    self._bind_taint_to_target(item.optional_vars, ctx_t, env)
            self._exec_block(stmt.body, env)
            return

        if isinstance(stmt, (ast.Try, ast.TryStar)):
            pre_env = env.copy()
            body_env = env.copy()
            self._exec_block(stmt.body, body_env)
            merged = body_env
            for handler in stmt.handlers:
                h_env = pre_env.join(body_env)
                self._exec_block(handler.body, h_env)
                merged = merged.join(h_env)
            if stmt.orelse:
                else_env = body_env.copy()
                self._exec_block(stmt.orelse, else_env)
                merged = merged.join(else_env)
            if stmt.finalbody:
                self._exec_block(stmt.finalbody, merged)
            env.replace_with(merged)
            return

        if isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self._eval_expr(stmt.value, env)
            return

        if isinstance(stmt, ast.Raise):
            if stmt.exc is not None:
                self._eval_expr(stmt.exc, env)
            if stmt.cause is not None:
                self._eval_expr(stmt.cause, env)
            return

        if isinstance(stmt, ast.Assert):
            self._eval_expr(stmt.test, env)
            if stmt.msg is not None:
                self._eval_expr(stmt.msg, env)
            return

        if isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    env.clear_var(target.id)
            return

        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._analyze_function(stmt, outer_env=env)
            return

        if isinstance(stmt, ast.ClassDef):
            for class_stmt in stmt.body:
                if isinstance(class_stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._analyze_function(class_stmt, outer_env=env)
                elif isinstance(class_stmt, ast.ClassDef):
                    self._exec_stmt(class_stmt, env)
            return

    def _analyze_function(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        outer_env: _TaintEnv | None = None,
    ) -> None:
        func_env = outer_env.copy() if outer_env is not None else _TaintEnv()

        all_args: list[ast.arg] = [
            *func_node.args.posonlyargs,
            *func_node.args.args,
            *func_node.args.kwonlyargs,
        ]
        if func_node.args.vararg is not None:
            all_args.append(func_node.args.vararg)
        if func_node.args.kwarg is not None:
            all_args.append(func_node.args.kwarg)

        for arg in all_args:
            if arg.arg in SKIPPED_PARAM_NAMES:
                continue
            param_loc = self._loc(arg)
            func_env.set_var(
                arg.arg,
                _TaintValue(
                    source_description=f"function parameter '{arg.arg}'",
                    confidence="medium",
                    trace=(
                        TraceStep(
                            location=param_loc,
                            description=f"untrusted parameter '{arg.arg}'",
                        ),
                    ),
                ),
            )

        self._exec_block(func_node.body, func_env)

    def run(self) -> list[Finding]:
        if isinstance(self.tree, ast.Module):
            module_env = _TaintEnv()
            self._exec_block(self.tree.body, module_env)
        self.findings.sort(key=lambda f: f.sort_key)
        return self.findings


def analyze_intraproc(tree: ast.AST, rel_path: str, context: AnalysisContext) -> list[Finding]:
    """Run intra-procedural taint analysis on a parsed Python AST."""
    analyzer = _IntraProcAnalyzer(tree, rel_path, context)
    return analyzer.run()
