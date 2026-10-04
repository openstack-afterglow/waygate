## Context

This change follows candidate `29f28cdcb572660fc3f693457b007435c0da81ef`, service 0.3.0 / SDK 0.2.0. Parent artifacts `local://release-waygate-advisory-triage.md` and `local://release-waygate-candidate.md` were read; their observations describe the earlier candidate, not a verified updated runtime.

[Published FastAPI 0.136.3 metadata](https://pypi.org/pypi/fastapi/0.136.3/json) requires Python >=3.10, Starlette >=0.46.0, Pydantic >=2.9.0, typing-extensions >=4.8.0, typing-inspection >=0.4.2 and annotated-doc >=0.0.2. Waygate remains Python >=3.11, with Pydantic 2.13.4 and typing-inspection 0.4.2 already locked. [Starlette 1.3.1 metadata](https://pypi.org/pypi/starlette/1.3.1/json) requires Python >=3.10 and AnyIO >=3.6.2,<5; current AnyIO 4.14.2 is retained. Neither framework's optional full/standard extras are added.

## Goals / Non-Goals

**Goals:** Select a metadata-compatible framework pair outside the five known Starlette affected ranges, without changing Waygate structure or public contracts. Record implementation and remaining verification separately.

**Non-Goals:** FastAPI 0.137+ included-router trees; shims; new Host-domain allowlists; middleware, rate-limit, auth, logging, SDK, schema or deployment redesign; unrelated package upgrades; tests/build/lint/formatters, runtime checks, architecture stamping, commit/push or production actions in this slice.

## Decisions

1. Set the service extra to FastAPI `==0.136.3` and Starlette `>=1.3.1`. FastAPI 0.125.0's Starlette <0.51 constraint cannot coexist with the patched floor. The selected pre-0.137 flat-router version is the requested established sibling baseline, not a reason to import sibling modules or change sibling files.
2. Run only `uv lock --upgrade-package fastapi==0.136.3 --upgrade-package starlette==1.3.1`. Observed: 83 packages resolved; only FastAPI 0.125.0 -> 0.136.3 and Starlette 0.50.0 -> 1.3.1 changed versions. No packages added/removed; only those package entries and Waygate's dependency metadata changed. FastAPI gains an edge to the already-locked typing-inspection. Service/SDK versions remain 0.3.0/0.2.0; SDK source and lock are untouched.
3. Retain existing application source. `waygate/main.py` includes five routers under `/v1/servers` and admin policy routes under `/v1/admin`, then registers discovery/health directly. Middleware registration remains SlowAPI, ProxyHeaders, SafeAccessLog (outermost user middleware). The only application `scope.get("route")` / `.path` consumer found is `SafeAccessLog` in `waygate/observability.py`; no included-router introspection adapter is introduced.
4. Source compatibility evidence: [tagged FastAPI routing implementation](https://github.com/fastapi/fastapi/blob/0.136.3/fastapi/routing.py#L1719-L1778) copies included routes with `add_api_route(prefix + route.path, ...)`; `APIRoute` stores `.path` and its `matches()` puts itself in `child_scope["route"]`. This supports keeping SafeAccessLog unchanged but does not prove executed middleware behavior. INFO route templates, unmatched requests, sanitized 429 warnings and DEBUG count-only metadata require Main smoke.
5. Do not change Host policy. Framework URL-construction fixes are not a deployment-specific domain allowlist. Discovery `request.base_url` and implicit slash-redirect Location are reconstructed-URL sinks; Main must exercise malformed Host/path behavior without claiming ingress normalization or production exploitability was proven here.

### Known advisory version boundaries

The following reviewed GitHub records were read. Locked Starlette 1.3.1 lies outside each recorded affected range; this is a version-selection statement, not runtime/security acceptance or proof that GitHub alerts are closed.

| Advisory | Recorded affected range | First patched |
|---|---|---|
| [GHSA-86qp-5c8j-p5mr](https://github.com/advisories/GHSA-86qp-5c8j-p5mr), Host/path poisoning | <=1.0.0 | 1.0.1 |
| [GHSA-x746-7m8f-x49c](https://github.com/advisories/GHSA-x746-7m8f-x49c), HTTPEndpoint reflection | <1.1.0 | 1.1.0 |
| [GHSA-wqp7-x3pw-xc5r](https://github.com/advisories/GHSA-wqp7-x3pw-xc5r), Windows StaticFiles UNC SSRF | <1.1.0 | 1.1.0 |
| [GHSA-jp82-jpqv-5vv3](https://github.com/advisories/GHSA-jp82-jpqv-5vv3), malformed-path authority poisoning | <1.3.0 | 1.3.0 |
| [GHSA-82w8-qh3p-5jfq](https://github.com/advisories/GHSA-82w8-qh3p-5jfq), URL-encoded form DoS | >=0.4.1,<1.3.1 | 1.3.1 |

Earlier triage identified explicit function routes, Linux/no StaticFiles mounts and JSON/header-auth rather than form consumers. Keep those scoped observations distinct from the dependency update; no new form/static/class endpoint surface is added to manufacture a test.

## Risks / Trade-offs

- Metadata resolution is not runtime compatibility -> Main owns frozen sync, existing suites and actual Uvicorn/SDK/logging/image checks; prior candidate passes do not verify this pair.
- Upstream parsing behavior may affect unusual clients -> FastAPI 0.136.3 defaults `strict_content_type=True` and skips JSON decoding when Content-Type is absent. Main was notified. Exercise supported JSON clients (`application/json` and `application/*+json`) and missing/wrong Content-Type behavior; no setting override or compatibility shim is added. A required contract/policy break must be reported before widening the design.
- Starlette's floor does not pin future unlocked resolution -> this candidate's existing uv lock pins exactly 1.3.1; release and images must consume that frozen lock.
- Architecture fingerprint becomes stale -> preserve its existing marker; Main performs a fresh reviewed stamp/check after all slices, not a manual marker update.

## Migration Plan

No new database migration, route, SDK operation or configuration field. Main verified the updated checkout using the selectors and actual runtime plan in [repository workflow](../../../specs/repository-workflow/spec.md#framework-remediation-handoff) and recorded outcomes in the completed checklist. API/worker images were rebuilt from the final reviewed source. Production rollout and rollback remain Main/owner-controlled under existing release procedures; nothing is deployed here.

## Open Questions

At dependency-slice handoff, actual API/SDK/middleware compatibility, missing-Content-Type behavior and both-architecture runtime behavior were unverified. Parent subsequently completed those isolated checks and final suites; see [acceptance](tasks.md). No demonstrated required policy change was found. Production ingress, deployed prebuilt-agent compatibility and final default-branch dependency-alert closure remain unverified.
