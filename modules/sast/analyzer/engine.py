from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from modules.sast.analyzer.taint import (
    TaintParticle,
    TraceEvent,
    append_event,
    empty_taint,
    filter_rule,
    merge_taints,
    strip_rule,
    with_propagation_note,
)
from modules.sast.rules.models import SastRule, SinkPattern, SourcePattern
from modules.sast.symbols.map import FileSymbolMap, FunctionSymbol


@dataclass
class RawFinding:
    rule: SastRule
    sink_node: ast.AST
    particles: frozenset[TaintParticle]


def _trace_event(
    kind: str,
    node: ast.AST,
    *,
    label: str | None = None,
    symbol: str | None = None,
    note: str | None = None,
) -> TraceEvent:
    ln = getattr(node, "lineno", 1) or 1
    col = getattr(node, "col_offset", None)
    return TraceEvent(kind=kind, line=ln, column=col, symbol=symbol, label=label, note=note)


def _qualified_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _qualified_name(node.value)
        if inner is None:
            return None
        return f"{inner}.{node.attr}"
    return None


def _match_subprocess_shell(call: ast.Call) -> bool:
    fn = call.func
    if not isinstance(fn, ast.Attribute):
        return False
    if not isinstance(fn.value, ast.Name) or fn.value.id != "subprocess":
        return False
    if fn.attr not in ("run", "call", "check_call", "check_output", "Popen"):
        return False
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _match_os_system(call: ast.Call) -> bool:
    fn = call.func
    return (
        isinstance(fn, ast.Attribute)
        and fn.attr == "system"
        and isinstance(fn.value, ast.Name)
        and fn.value.id == "os"
    )


def _match_eval(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Name) and call.func.id == "eval"


def _match_exec(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Name) and call.func.id == "exec"


def _match_sql_execute(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Attribute) and call.func.attr == "execute"


def _sql_is_parameterized(call: ast.Call) -> bool:
    if len(call.args) < 2:
        return False
    return isinstance(call.args[1], (ast.Tuple, ast.List))


def _match_open_path(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Name) and call.func.id == "open"


def _match_weak_hash(call: ast.Call) -> bool:
    fn = call.func
    if isinstance(fn, ast.Attribute) and fn.attr in ("md5", "sha1"):
        if isinstance(fn.value, ast.Name) and fn.value.id == "hashlib":
            return True
    return False


def _sink_matches(sink: SinkPattern, call: ast.Call) -> bool:
    t = sink.type
    if t == "subprocess_shell":
        return _match_subprocess_shell(call)
    if t == "os_system":
        return _match_os_system(call)
    if t == "eval_call":
        return _match_eval(call)
    if t == "exec_call":
        return _match_exec(call)
    if t == "sql_execute":
        return _match_sql_execute(call)
    if t == "open_path":
        return _match_open_path(call)
    if t == "weak_hash_md5_sha1":
        return _match_weak_hash(call)
    return False


def _source_particles(
    expr: ast.expr,
    rule: SastRule,
    *,
    max_events: int,
) -> frozenset[TaintParticle]:
    out: set[TaintParticle] = set()
    for sp in rule.sources:
        if _source_matches(sp, expr):
            ev = _trace_event("source", expr, label=f"Source ({sp.type})", symbol=_expr_symbol(expr))
            p = TaintParticle(rule_id=rule.id, events=(_sanitize_trace_event(ev),))
            out.add(p)
    return frozenset(out)


def _sanitize_trace_event(ev: TraceEvent) -> TraceEvent:
    """TraceEvent kind must be a V1 TraceKind; normalize unknown."""
    allowed = frozenset({"source", "propagation", "sanitizer", "sink", "call", "return"})
    if ev.kind in allowed:
        return ev
    return TraceEvent(
        kind="propagation",
        line=ev.line,
        column=ev.column,
        symbol=ev.symbol,
        label=ev.label,
        note=ev.note,
    )


def _expr_symbol(expr: ast.expr) -> str | None:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
        return expr.func.id
    if isinstance(expr, ast.Attribute):
        return _qualified_name(expr)
    return None


def _source_matches(sp: SourcePattern, expr: ast.expr) -> bool:
    if sp.type == "call_name":
        return (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == sp.name
        )
    if sp.type == "attribute":
        return (
            isinstance(expr, ast.Attribute)
            and isinstance(expr.value, ast.Name)
            and expr.value.id == sp.base
            and expr.attr == sp.attr
        )
    if sp.type == "sys_argv_subscript":
        return (
            isinstance(expr, ast.Subscript)
            and isinstance(expr.value, ast.Attribute)
            and isinstance(expr.value.value, ast.Name)
            and expr.value.value.id == "sys"
            and expr.value.attr == "argv"
        )
    if sp.type == "qualified_call":
        q = sp.qname or ""
        return _qualified_name(expr) == q if isinstance(expr, ast.Call) else False
    return False


def _sanitizer_applies(rule: SastRule, call: ast.Call) -> bool:
    for san in rule.sanitizers:
        if san.type != "qualified_call" or not san.qname:
            continue
        qn = _qualified_name(call.func)
        if qn == san.qname:
            return True
    return False


def _apply_sanitizer(rule: SastRule, call: ast.Call, taint: frozenset[TaintParticle]) -> frozenset[TaintParticle]:
    if not _sanitizer_applies(rule, call):
        return taint
    return strip_rule(taint, rule.id)


def _propagator_builtin(rule: SastRule, call: ast.Call) -> bool:
    names: set[str] = set()
    for pr in rule.propagators:
        if pr.type == "call_name":
            names.update(pr.names)
    if isinstance(call.func, ast.Name) and call.func.id in names:
        return True
    return False


def _default_propagators(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Name) and call.func.id in ("str", "repr", "bytes", "format"):
        return True
    if isinstance(call.func, ast.Attribute) and call.func.attr in ("format", "encode", "decode"):
        return True
    return False


class _IntrafileEngine:
    def __init__(
        self,
        *,
        file_path: Path,
        source_text: str,
        symap: FileSymbolMap,
        rules: list[SastRule],
        max_trace_events: int,
        max_call_depth: int,
    ) -> None:
        self._file_path = file_path
        self._source_text = source_text
        self._symap = symap
        self._rules = rules
        self._max_trace = max_trace_events
        self._max_call_depth = max_call_depth
        self._findings: list[RawFinding] = []
        self._call_depth = 0

    def run(self, tree: ast.Module) -> list[RawFinding]:
        env: dict[str, frozenset[TaintParticle]] = {}
        self._analyze_stmts(tree.body, env, function_name=None, ret_bucket=None)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_stmts(
                    node.body,
                    {},
                    function_name=node.name,
                    ret_bucket=None,
                )
        self._sink_only_pass(tree)
        return list(self._findings)

    def _merge_env(self, a: dict[str, frozenset[TaintParticle]], b: dict[str, frozenset[TaintParticle]]):
        keys = set(a) | set(b)
        return {k: merge_taints(a.get(k, empty_taint()), b.get(k, empty_taint())) for k in keys}

    def _analyze_stmts(
        self,
        stmts: list[ast.stmt],
        env: dict[str, frozenset[TaintParticle]],
        *,
        function_name: str | None,
        ret_bucket: list[frozenset[TaintParticle]] | None = None,
    ) -> None:
        for stmt in stmts:
            if self._deadline and self._deadline():
                return
            if isinstance(stmt, ast.Assign):
                value_t = self._taint_of_expr(stmt.value, env, function_name=function_name)
                for t in stmt.targets:
                    self._assign_target(t, value_t, env)
            elif isinstance(stmt, ast.AnnAssign):
                if stmt.value is not None:
                    value_t = self._taint_of_expr(stmt.value, env, function_name=function_name)
                    self._assign_target(stmt.target, value_t, env)
            elif isinstance(stmt, ast.AugAssign):
                if isinstance(stmt.target, ast.Name):
                    cur = env.get(stmt.target.id, empty_taint())
                    rhs = self._taint_of_expr(stmt.value, env, function_name=function_name)
                    merged = merge_taints(cur, rhs)
                    env[stmt.target.id] = with_propagation_note(
                        merged,
                        max_events=self._max_trace,
                        line=stmt.lineno,
                        column=stmt.col_offset,
                        label="Augmented assignment",
                        symbol=stmt.target.id,
                    )
            elif isinstance(stmt, ast.Expr):
                self._taint_of_expr(stmt.value, env, function_name=function_name)
            elif isinstance(stmt, ast.Return) and stmt.value is not None:
                rt = self._taint_of_expr(stmt.value, env, function_name=function_name)
                if ret_bucket is not None:
                    ret_bucket.append(rt)
            elif isinstance(stmt, ast.If):
                env_then = dict(env)
                self._analyze_stmts(
                    stmt.body, env_then, function_name=function_name, ret_bucket=ret_bucket
                )
                env_else = dict(env)
                self._analyze_stmts(
                    stmt.orelse, env_else, function_name=function_name, ret_bucket=ret_bucket
                )
                merged = self._merge_env(env_then, env_else)
                env.clear()
                env.update(merged)
            elif isinstance(stmt, (ast.For, ast.While)):
                env_body = dict(env)
                for _ in range(2):
                    self._analyze_stmts(
                        stmt.body, env_body, function_name=function_name, ret_bucket=ret_bucket
                    )
                merged = self._merge_env(env, env_body)
                env.clear()
                env.update(merged)
                if isinstance(stmt, ast.For):
                    after_loop = dict(env)
                    orelse_env = dict(after_loop)
                    self._analyze_stmts(
                        stmt.orelse, orelse_env, function_name=function_name, ret_bucket=ret_bucket
                    )
                    env.clear()
                    env.update(self._merge_env(after_loop, orelse_env))
            elif isinstance(stmt, ast.Try):
                body_e = dict(env)
                self._analyze_stmts(stmt.body, body_e, function_name=function_name, ret_bucket=ret_bucket)
                handlers_e = dict(body_e)
                for h in stmt.handlers:
                    self._analyze_stmts(h.body, handlers_e, function_name=function_name, ret_bucket=ret_bucket)
                final_e = dict(handlers_e)
                self._analyze_stmts(stmt.finalbody, final_e, function_name=function_name, ret_bucket=ret_bucket)
                orelse_e = dict(handlers_e)
                self._analyze_stmts(stmt.orelse, orelse_e, function_name=function_name, ret_bucket=ret_bucket)
                env.clear()
                env.update(self._merge_env(self._merge_env(body_e, handlers_e), self._merge_env(orelse_e, final_e)))
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            elif isinstance(stmt, ast.With):
                self._analyze_stmts(stmt.body, env, function_name=function_name, ret_bucket=ret_bucket)
            elif isinstance(stmt, ast.Match):
                snapshot = dict(env)
                acc = dict(snapshot)
                for case in stmt.cases:
                    ce = dict(snapshot)
                    self._analyze_stmts(case.body, ce, function_name=function_name, ret_bucket=ret_bucket)
                    acc = self._merge_env(acc, ce)
                env.clear()
                env.update(acc)

    def _assign_target(self, target: ast.expr, value_t: frozenset[TaintParticle], env: dict[str, frozenset[TaintParticle]]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = with_propagation_note(
                value_t,
                max_events=self._max_trace,
                line=target.lineno,
                column=target.col_offset,
                label="Assignment",
                symbol=target.id,
            )
        elif isinstance(target, ast.Tuple):
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    env[elt.id] = with_propagation_note(
                        value_t,
                        max_events=self._max_trace,
                        line=elt.lineno,
                        column=elt.col_offset,
                        label="Unpacking (conservative whole-value taint)",
                        symbol=elt.id,
                    )

    def _taint_of_expr(
        self,
        expr: ast.expr,
        env: dict[str, frozenset[TaintParticle]],
        *,
        function_name: str | None,
    ) -> frozenset[TaintParticle]:
        if isinstance(expr, ast.Constant):
            return empty_taint()
        if isinstance(expr, ast.Name):
            return env.get(expr.id, empty_taint())
        if isinstance(expr, ast.JoinedStr):
            parts: list[frozenset[TaintParticle]] = []
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    parts.append(self._taint_of_expr(v.value, env, function_name=function_name))
                elif isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(empty_taint())
            return merge_taints(*parts) if parts else empty_taint()
        if isinstance(expr, ast.BinOp):
            return merge_taints(
                self._taint_of_expr(expr.left, env, function_name=function_name),
                self._taint_of_expr(expr.right, env, function_name=function_name),
            )
        if isinstance(expr, ast.UnaryOp):
            return self._taint_of_expr(expr.operand, env, function_name=function_name)
        if isinstance(expr, ast.IfExp):
            return merge_taints(
                self._taint_of_expr(expr.body, env, function_name=function_name),
                self._taint_of_expr(expr.orelse, env, function_name=function_name),
            )
        if isinstance(expr, ast.Call):
            return self._taint_of_call(expr, env, function_name=function_name)
        if isinstance(expr, ast.Subscript):
            base_t = self._taint_of_expr(expr.value, env, function_name=function_name)
            rule_sources = empty_taint()
            for rule in self._rules:
                if rule.analysis != "taint":
                    continue
                rule_sources = merge_taints(
                    rule_sources,
                    _source_particles(expr, rule, max_events=self._max_trace),
                )
            return merge_taints(base_t, rule_sources)
        if isinstance(expr, ast.Attribute):
            base_t = self._taint_of_expr(expr.value, env, function_name=function_name)
            rule_sources = empty_taint()
            for rule in self._rules:
                if rule.analysis != "taint":
                    continue
                fake = expr
                rule_sources = merge_taints(rule_sources, _source_particles(fake, rule, max_events=self._max_trace))
            return merge_taints(base_t, rule_sources)
        if isinstance(expr, ast.Subscript):
            return self._taint_of_expr(expr.value, env, function_name=function_name)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            elts = [self._taint_of_expr(e, env, function_name=function_name) for e in expr.elts]
            return merge_taints(*elts) if elts else empty_taint()
        if isinstance(expr, ast.Dict):
            parts = []
            for k, v in zip(expr.keys, expr.values):
                if k is not None:
                    parts.append(self._taint_of_expr(k, env, function_name=function_name))
                parts.append(self._taint_of_expr(v, env, function_name=function_name))
            return merge_taints(*parts) if parts else empty_taint()
        return empty_taint()

    _deadline: Callable[[], bool] | None = None

    def _emit_sink(self, rule: SastRule, call: ast.Call, particles: frozenset[TaintParticle]) -> None:
        relevant = filter_rule(particles, rule.id)
        if not relevant:
            return
        ev = _trace_event("sink", call, label=f"Sink ({rule.id})", symbol=_qualified_name(call.func))
        ev_ok = _sanitize_trace_event(ev)
        enriched: set[TaintParticle] = set()
        for p in relevant:
            enriched.add(TaintParticle(rule_id=p.rule_id, events=p.events + (ev_ok,)))
        self._findings.append(RawFinding(rule=rule, sink_node=call, particles=frozenset(enriched)))

    def _check_sinks(self, rule: SastRule, call: ast.Call, arg_taints: list[frozenset[TaintParticle]]) -> None:
        for sink in rule.sinks:
            if not _sink_matches(sink, call):
                continue
            if sink.type == "sql_execute" and _sql_is_parameterized(call):
                continue
            if sink.type in ("subprocess_shell", "os_system", "eval_call", "exec_call"):
                tainted_args = merge_taints(*arg_taints) if arg_taints else empty_taint()
                self._emit_sink(rule, call, tainted_args)
            elif sink.type == "open_path":
                if arg_taints:
                    self._emit_sink(rule, call, arg_taints[0])
            elif sink.type == "sql_execute":
                if arg_taints:
                    self._emit_sink(rule, call, arg_taints[0])

    def _taint_of_call(
        self,
        call: ast.Call,
        env: dict[str, frozenset[TaintParticle]],
        *,
        function_name: str | None,
    ) -> frozenset[TaintParticle]:
        arg_taints = [self._taint_of_expr(a, env, function_name=function_name) for a in call.args]
        kw_taints = [self._taint_of_expr(kw.value, env, function_name=function_name) for kw in call.keywords]
        arg_combo = merge_taints(*arg_taints, *kw_taints)

        local_sources = empty_taint()
        for rule in self._rules:
            if rule.analysis == "taint":
                local_sources = merge_taints(
                    local_sources,
                    _source_particles(call, rule, max_events=self._max_trace),
                )

        merged_in = merge_taints(arg_combo, local_sources)

        for rule in self._rules:
            if rule.analysis == "taint":
                self._check_sinks(rule, call, arg_taints)

        sanitized = merged_in
        for rule in self._rules:
            if rule.analysis == "taint":
                sanitized = _apply_sanitizer(rule, call, sanitized)

        if isinstance(call.func, ast.Name) and call.func.id in self._symap.functions_by_name:
            if self._call_depth < self._max_call_depth:
                sym = self._symap.functions_by_name[call.func.id]
                self._call_depth += 1
                try:
                    ret_t = self._inline_call(sym, arg_taints)
                finally:
                    self._call_depth -= 1
                call_ev = _sanitize_trace_event(
                    _trace_event(
                        "call",
                        call,
                        label=f"Call {call.func.id}",
                        symbol=call.func.id,
                        note="Intrafile call (V1: top-level functions only; no closure capture)",
                    )
                )
                ret_tagged = frozenset(append_event(p, call_ev, self._max_trace) for p in ret_t)
                return ret_tagged

        if _default_propagators(call) or any(_propagator_builtin(rule, call) for rule in self._rules if rule.analysis == "taint"):
            return sanitized

        if local_sources:
            ls = local_sources
            for rule in self._rules:
                if rule.analysis == "taint":
                    ls = _apply_sanitizer(rule, call, ls)
            return ls

        return empty_taint()

    def _inline_call(
        self,
        sym: FunctionSymbol,
        arg_taints: list[frozenset[TaintParticle]],
    ) -> frozenset[TaintParticle]:
        fn = sym.node
        params = list(fn.args.args)
        if len(params) != len(arg_taints):
            return empty_taint()
        inner: dict[str, frozenset[TaintParticle]] = {}
        for p, t in zip(params, arg_taints, strict=True):
            inner[p.arg] = t
        ret_bucket: list[frozenset[TaintParticle]] = []
        self._analyze_stmts(
            list(fn.body),
            inner,
            function_name=sym.name,
            ret_bucket=ret_bucket,
        )
        ret_acc = merge_taints(*ret_bucket) if ret_bucket else empty_taint()
        ret_ev = _sanitize_trace_event(
            _trace_event(
                "return",
                fn,
                label=f"Return from {sym.name}",
                symbol=sym.name,
                note=None,
            )
        )
        return frozenset(append_event(p, ret_ev, self._max_trace) for p in ret_acc)

    def _sink_only_pass(self, tree: ast.Module) -> None:
        for rule in self._rules:
            if rule.analysis != "sink_only":
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for sink in rule.sinks:
                        if _sink_matches(sink, node):
                            p = TaintParticle(
                                rule_id=rule.id,
                                events=(
                                    _sanitize_trace_event(
                                        _trace_event(
                                            "sink",
                                            node,
                                            label="Sink-only rule match",
                                            symbol=_qualified_name(node.func),
                                            note="No dataflow required (weak primitive detection).",
                                        )
                                    ),
                                ),
                            )
                            self._findings.append(RawFinding(rule=rule, sink_node=node, particles=frozenset({p})))


def analyze_file(
    file_path: Path,
    tree: ast.Module,
    source_text: str,
    symap: FileSymbolMap,
    rules: list[SastRule],
    *,
    max_taint_depth: int,
    deadline: Callable[[], bool] | None = None,
) -> list[RawFinding]:
    max_trace = max(4, int(max_taint_depth) * 3)
    eng = _IntrafileEngine(
        file_path=file_path,
        source_text=source_text,
        symap=symap,
        rules=rules,
        max_trace_events=max_trace,
        max_call_depth=int(max_taint_depth),
    )
    eng._deadline = deadline
    return eng.run(tree)
