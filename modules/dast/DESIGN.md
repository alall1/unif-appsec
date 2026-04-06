# DAST module internal design (V1)

Authoritative requirements: `docs/master_spec.md` §12 and §13 (DAST-related limits and config).

## How discovery works

1. **Explicit target** — A `GET` endpoint is always seeded for `dast.target_url` / CLI `--target-url` (merged in `targeting.models.build_dast_target_config`).
2. **OpenAPI** — If `openapi_path` resolves to a file, `discovery/openapi.py` expands `servers` + `paths` into `DiscoveredEndpoint` rows with `InsertionPoint` entries for `query`, `path`, and `header` parameters.
3. **Endpoint seeds** — `dast.endpoint_seeds` adds explicit methods/paths/URLs plus optional parameter metadata (`discovery/engine.py:endpoints_from_seeds`).
4. **Optional crawl** — When `dast.crawl.enabled` is true, `discovery/crawl.py` performs same-origin, depth-limited HTML link and form extraction only (stdlib `html.parser`, no JavaScript).

After OpenAPI + seeds are merged and deduplicated, discovery issues a **single GET** to the primary URL when HTML is plausible, parses forms, and merges discovered field names into matching GET endpoints (observed-response parameter hints). Endpoints are deduplicated by `(method, URL without fragment)`.

## How audit works

`audit/engine.py` walks each in-scope `DiscoveredEndpoint`, builds a **baseline** HTTP exchange (benign query defaults for declared query parameters, `{param}` templates materialized with `1`), then:

- Runs **passive** checks against the baseline response (headers/body/cookies).
- For **GET** endpoints only, runs **active** checks that issue additional requests via the shared `HttpClient` (rate-limited, timeout-bound).

Scan profile (`fast` / `balanced` / `deep`) maps to an **active depth** integer consumed by checks (payload count / probe breadth). `ScanContext.timed_out()` aborts further work.

## How checks are registered

`checks/registry.py` defines `CheckRegistry` with `register_passive`, `register_active`, and bulk `extend_*` helpers. `default_check_registry()` wires the shipped V1 checks. `checks_for_config()` applies `checks.disabled`, `checks.passive.enabled`, and `checks.active.enabled` from `DastTargetConfig`.

Passive checks implement `analyze(ctx, endpoint, baseline_response)`; active checks implement `probe(...)`. Both yield `RawDastFinding` objects converted to normalized `Finding` models in `findings/mapper.py`.

## How baseline comparison is used

Active families (XSS/SQLi/path traversal) take a **benign baseline request/response** for the same insertion point, then compare status, body length, marker presence, or context heuristics against **probed** responses. Evidence stores a short human-readable delta in `dast_evidence.baseline_comparison` plus summarized request/response pairs where applicable.

This is intentionally **honest**: reflected substrings alone do not yield high-confidence XSS; SQL errors that appear identically on baseline and probe downgrade confidence.

## Auth/session (V1)

`auth/session.py` merges static headers, optional bearer token, and a simple cookie map into each request. `Set-Cookie` on responses updates the map (first cookie only — V1 limitation). `auth.reauth_hook` is accepted in config, surfaced as a **warning** only (`dast_reauth_hook_reserved`); no hook execution in V1.

## What V1 supports vs does not

**Supports:** HTTP/API-first scanning; discovery/audit separation; OpenAPI 3.x path expansion (swagger 2 with `paths` best-effort); same-origin HTML crawl; passive header/CORS/cookie/info checks; active XSS/SQLi/path-traversal/debug-trace style probes scoped as documented; profiles affecting depth; `ModuleScanResult` with `requests_sent` metric; normalized `http` locations and `http_exchange` evidence.

**Does not support:** Browser automation, JS execution, OAST/blind collaborators, full SPA routing, SSO/MFA, authorization or multi-role testing, reliable complete route discovery, or robust multi-step business logic testing — per master spec non-goals.
