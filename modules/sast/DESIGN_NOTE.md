# SAST module (V1) — internal design

This note summarizes how the Python SAST analyzer in `modules/sast` works and what V1 intentionally does **not** promise. The authoritative product spec is `docs/master_spec.md` §11.

## Taint representation

- A **taint particle** (`TaintParticle`) is a `(rule_id, ordered_trace_events)` pair.
- Particles are grouped in a **taint set** (`frozenset[TaintParticle]`) attached to each tracked name (locals and, during inline analysis, parameters).
- Each **trace event** records a V1 `kind` (`source`, `propagation`, `sanitizer`, `sink`, `call`, `return`), line/column, optional symbol, label, and note.
- The trace chain length is **bounded** by a function of `max_taint_depth` from config (profile defaults in `core/config/defaults.py`, overridable under `sast.max_taint_depth`).

Particles are **per rule**: a source for rule R only contributes particles with `rule_id == R`. Sinks emit findings only for matching `rule_id`.

## Module vs function bodies

- The pipeline runs dataflow on **module-level statements**, then on each **top-level** `async def` / `def` body (fresh local environment per function). **Class bodies and nested functions** are not entered from the module pass (closures / methods: out of scope for V1).

## Source patterns

- `sys.argv[n]` is matched as **`sys_argv_subscript`** on the `Subscript` AST node (a bare `sys.argv` `Attribute` is also listed for completeness).

## Propagation

- **Assignments**, **augmented assignments**, and conservative **tuple unpacking** copy taint sets and append lightweight `propagation` trace steps (best-effort).
- **Expressions**: `BinOp`, `UnaryOp`, `IfExp`, `JoinedStr`/`FormattedValue`, `List`/`Tuple`/`Set`/`Dict` entries merge child taint (no per-element container sensitivity).
- **Attributes**: base expression taint is merged with any **source patterns** that match the full attribute expression (e.g. `sys.argv`).
- **Calls**:
  - Arguments are analyzed first (so inner calls like `shlex.quote(x)` sanitize before outer sinks see tainted values).
  - **Modeled sanitizers** (YAML, per rule) strip particles for that **rule** from the call’s abstract return value (`strip_rule`).
  - **Propagators** (`str`, `repr`, plus rule-declared names, and a small built-in allowlist such as `format`/`encode`/`decode` on attributes) return merged taint from arguments and sources on the call.
  - **Top-level same-file functions** with arity match may be **inlined**; parameters bind to argument taint sets, the body is analyzed with the shared statement engine, and `return` values are merged. Nesting depth is capped by `max_taint_depth`. Nested `def` targets are **not** registered for resolution (closures unsupported).
  - Calls to **unknown** callees do **not** propagate argument taint into their return value (except via explicit propagator/builtin rules above). This avoids false “return tainted” claims for unmodeled APIs.

## Traces

- Internal ordered `TraceEvent` lists are mapped to schema `TraceStep` objects with monotonic `step_index`. AST `col_offset` is 0-based; export uses **1-based** `column` to satisfy schema validation (`ge=1`) and align with `CodeLocation` handling in the mapper.
- Taint findings use `evidence_type: code_trace` and include `trace`. Sink-only rules (weak hash) use `evidence_type: code_match` and omit multi-step taint traces.

## Supported vs unsupported (V1)

**Supported (bounded):** intrafile AST, top-level function symbol map, sequential and approximate branch/loop merging, argument-to-parameter transfer for resolved calls, simple expression forms, YAML rules with sources/sinks/sanitizers/propagators, subprocess `shell=True`, `os.system`, `eval`/`exec`, single-arg `execute`, `open` first argument, `hashlib.md5`/`sha1` pattern.

**Not supported:** inter-file propagation, decorators, closures / nested function calls, dynamic attribute access and reflective dispatch, advanced aliases, exception-sensitive control flow, container element sensitivity, generators/async flow fidelity, whole-program soundness, framework-agnostic “request is tainted” modeling.

## Framework request sources

- **None** are enabled in the bundled `v1_baseline.yaml`. Per master spec §11.7.1, `request.args` / `request.form` / `request.json` are **not** automatic sources until an explicitly documented adapter or rule pack adds them.

## Core integration

- `PythonSastPlugin` implements `AppSecPlugin` (`core/plugins/base.py`), registers as `python_sast` (`core/orchestration/constants.py`).
- `scan()` returns `ModuleScanResult` with normalized `Finding` rows (`core/findings/models.py`); fingerprints are assigned by `normalize_finding` in the orchestration runner.
- Suppressions (`core/policy/suppression.py`) apply in core after module results merge — the SAST module emits `suppressed: false` findings only.
