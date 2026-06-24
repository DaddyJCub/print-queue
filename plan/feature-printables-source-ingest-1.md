---
goal: Printables Link Fetch and File Selection Integration for Request Submission
version: 1.0
date_created: 2026-06-23
last_updated: 2026-06-24
owner: Print Queue App Team
status: Implemented (code complete; pending commit/deploy + staging QA per TASK-026)
tags: [feature, integration, printables, request-form, ingestion]
---

# Introduction

![Status: Implemented](https://img.shields.io/badge/status-Implemented-brightgreen)

Add a request-form feature that accepts a Printables link, fetches model metadata and associated downloadable assets, lets the requester select multiple assets, and carries selected files plus metadata into the submitted request. Initial scope is Printables only. The plan includes a feasibility gate for direct file download behavior and a fallback behavior when only package-level downloads are available.

## 1. Requirements & Constraints

- **REQ-001**: Add a new user action in the request form UI next to the existing link field to fetch model files from a provided Printables URL.
- **REQ-002**: Parse and validate Printables URLs in format `/model/{id}-{slug}` and reject unsupported hosts.
- **REQ-003**: Retrieve and display model metadata (title, summary/description) before submit.
- **REQ-004**: Retrieve and display selectable file candidates; support multi-select.
- **REQ-005**: Provide per-selected-item quantity input with integer range 1-50, default 1.
- **REQ-006**: Persist selected external files and metadata with the request at submit time.
- **REQ-007**: Preserve existing behavior for manual file uploads and link-only submissions.
- **REQ-008**: Provide clear error states for invalid links, provider unavailability, and zero-file results.
- **REQ-009**: Scope initial provider support to Printables only; design provider abstraction for future providers.
- **REQ-010**: Restrict fetch-provider functionality to authenticated users only (registered, logged-in account required).
- **LEG-001**: Before enabling direct binary import, confirm provider terms permit automated retrieval for user-initiated requests.
- **LEG-002**: If terms status is unknown or disallowed, operate in metadata plus reference mode (no binary fetch/re-host).
- **LEG-003**: Persist source attribution and license string (when available) with each selected external item.
- **LEG-004**: Display end-user notice that model rights and commercial permissions remain governed by original creator license.
- **SEC-001**: Perform strict URL allowlist validation (`printables.com`, `www.printables.com`).
- **SEC-002**: Enforce HTTP timeout (10s connect, 20s read) and max response size checks for external provider calls.
- **SEC-003**: Sanitize HTML description content before rendering/storing; store plain text summary for email/admin fallback.
- **SEC-004**: Do not execute remote scripts or client-side provider JS in backend.
- **SEC-005**: Enforce rate limiting on fetch endpoint (per IP + per requester email).
- **SEC-006**: Enforce server-side authentication and return `401/403` for unauthenticated calls to provider fetch endpoint.
- **INT-001**: Use Printables public GraphQL endpoint `https://api.printables.com/graphql/` for metadata retrieval.
- **INT-002**: Prefer stable GraphQL fields from `print(id: ID!)` query (`id`, `name`, `summary`, `description`, `filesCount`, `fileUploads`, `otherFiles`, `downloadPacks`).
- **CON-001**: Existing app uses FastAPI routes in [app/public.py](app/public.py) and request template in [app/templates/request_form_new.html](app/templates/request_form_new.html).
- **CON-002**: Existing submit flow already supports chunk uploads and hidden prepared upload IDs; new flow must not break this path.
- **CON-003**: Existing DB migrations are executed in [app/main.py](app/main.py) with additive `ALTER TABLE` style; new schema must follow that style.
- **GUD-001**: Keep feature rollout behind a new feature flag key `printables_fetch`.
- **GUD-002**: Keep provider logic in dedicated module to avoid coupling provider parsing into route handlers.
- **PAT-001**: Implement deterministic JSON contract between frontend and backend for fetched file candidates and selected entries.
- **PAT-002**: Use optimistic UI for fetch action with explicit loading, success, and retry states.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Establish provider contract and validate Printables feasibility path with deterministic query fields.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Create provider module [app/integrations/printables_client.py](app/integrations/printables_client.py) with function `fetch_printables_model(print_id: str) -> dict` using `httpx` and fixed GraphQL query shape. | ✅ | 2026-06-24 |
| TASK-002 | Create parser module [app/integrations/printables_parser.py](app/integrations/printables_parser.py) with functions `parse_printables_url(url: str) -> str` and `normalize_file_candidates(model_payload: dict) -> list[dict]`. | ✅ | 2026-06-24 |
| TASK-003 | Add integration tests in [tests/test_printables_integration.py](tests/test_printables_integration.py) with mocked GraphQL responses for: fileUploads present, otherFiles present, downloadPacks only, and empty file results. | ✅ | 2026-06-24 |
| TASK-004 | Add feasibility gate check function `supports_direct_asset_download(candidate: dict) -> bool` and classify candidates as `direct`, `package`, or `reference-only` in [app/integrations/printables_parser.py](app/integrations/printables_parser.py). | ✅ | 2026-06-24 |
| TASK-005 | Document provider contract and JSON response examples in [docs/printables-integration.md](docs/printables-integration.md). | ✅ | 2026-06-24 |
| TASK-005A | Add compliance decision matrix in [docs/printables-integration.md](docs/printables-integration.md) with explicit runtime modes: `metadata_only`, `reference_only`, `direct_import`. | ✅ | 2026-06-24 |

### Implementation Phase 2

- GOAL-002: Add backend endpoint(s) for fetch-preview and request persistence of selected external files.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-006 | Add route `POST /submit/fetch-provider-files` in [app/public.py](app/public.py) accepting `link_url`, validating host/id, and returning normalized payload `{provider, model, candidates}`. | ✅ | 2026-06-24 |
| TASK-007 | Add pydantic request/response schemas in [app/public.py](app/public.py) for strict contract validation and consistent error payloads. | ✅ | 2026-06-24 |
| TASK-007A | Add mandatory auth guard in [app/public.py](app/public.py) for `POST /submit/fetch-provider-files` using current account/session resolver and deny guest access with deterministic error payload. | ✅ | 2026-06-24 |
| TASK-008 | Add submission form field `selected_external_files_json` parsing in `submit()` in [app/public.py](app/public.py) with schema validation and quantity bounds enforcement. | ✅ | 2026-06-24 |
| TASK-009 | Add table creation + migration blocks in `init_db()` in [app/main.py](app/main.py): `external_sources` and `external_source_files` with indexes on `request_id`, `provider`, `source_id`. | ✅ | 2026-06-24 |
| TASK-010 | Persist external source metadata and selected candidates inside submit transaction in [app/public.py](app/public.py), linked to created request ID. | ✅ | 2026-06-24 |
| TASK-011 | Add feature flag definition `printables_fetch` in [app/models.py](app/models.py) feature map and default off in production. | ✅ | 2026-06-24 |

### Implementation Phase 3

- GOAL-003: Add request form UX for fetch, multi-select, and quantity/options capture.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-012 | Update link section in [app/templates/request_form_new.html](app/templates/request_form_new.html) to include a `Fetch Files` button, loading spinner, and status message region. | ✅ | 2026-06-24 |
| TASK-012A | Show `Fetch Files` button only for authenticated users in [app/templates/request_form_new.html](app/templates/request_form_new.html); show sign-in CTA for guests. | ✅ | 2026-06-24 |
| TASK-013 | Add candidate list UI block in [app/templates/request_form_new.html](app/templates/request_form_new.html) with checkbox per candidate, file metadata, and quantity input per selected item. | ✅ | 2026-06-24 |
| TASK-014 | Add hidden field `selected_external_files_json` to [app/templates/request_form_new.html](app/templates/request_form_new.html) and serialize selection state before submit. | ✅ | 2026-06-24 |
| TASK-015 | Add client-side JS functions in [app/templates/request_form_new.html](app/templates/request_form_new.html): `fetchProviderFiles()`, `renderFetchedCandidates()`, `collectSelectedExternalFiles()`, `syncSelectedExternalFilesHiddenInput()`. | ✅ | 2026-06-24 |
| TASK-016 | Integrate with existing submit handler in [app/templates/request_form_new.html](app/templates/request_form_new.html) so chunk-upload behavior and external-file selection both submit correctly. | ✅ | 2026-06-24 |
| TASK-017 | Add user-facing copy for package/reference candidates in [app/templates/request_form_new.html](app/templates/request_form_new.html) to explain when files are attached as references vs imported binaries. | ✅ | 2026-06-24 |

### Implementation Phase 4

- GOAL-004: Surface imported metadata in request views and admin review flows.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-018 | Extend request detail query and context in [app/my_requests.py](app/my_requests.py) and [app/public.py](app/public.py) to include `external_sources` and `external_source_files`. | ✅ | 2026-06-24 |
| TASK-019 | Update requester view template [app/templates/my_request.html](app/templates/my_request.html) to show fetched model title, selected files, and quantities. | ✅ | 2026-06-24 |
| TASK-020 | Update admin request template [app/templates/admin_request.html](app/templates/admin_request.html) to display source provider block, selected files, and attachment mode (`direct`/`package`/`reference-only`). | ✅ | 2026-06-24 |
| TASK-021 | Include external source summary in submit notification payload generation in [app/public.py](app/public.py) without breaking existing email row format. | ✅ | 2026-06-24 |

### Implementation Phase 5

- GOAL-005: Complete quality gates, rollout controls, and operational safeguards.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-022 | Add route-level tests in [tests/test_public_routes.py](tests/test_public_routes.py) for `POST /submit/fetch-provider-files` success, invalid URL, unsupported host, provider timeout, and empty candidates. | ✅ | 2026-06-24 |
| TASK-023 | Add submit-flow tests in [tests/test_public_routes.py](tests/test_public_routes.py) for mixed upload + external selection and selection-only submit. | ✅ | 2026-06-24 |
| TASK-024 | Add migration safety test in [tests/test_smoke_routes.py](tests/test_smoke_routes.py) validating table creation on fresh DB and additive migration on existing DB. | ✅ | 2026-06-24 |
| TASK-025 | Add structured logs and metrics in [app/public.py](app/public.py): fetch attempts, provider latency, candidate counts, error classes. | ✅ (logs incl. latency_ms/candidate counts/error classes; no separate metrics backend exists) | 2026-06-24 |
| TASK-026 | Enable feature flag in staging, run manual QA checklist, then progressively enable in production. | ⛔ Operational — not done (requires deploy + operator action; code is ready behind `printables_fetch`, off by default) |  |
| TASK-027 | Add config flag `PRINTABLES_FETCH_MODE` (allowed values: `metadata_only`, `reference_only`, `direct_import`) and set default to `reference_only` until terms review is completed. | ⚠️ Done, but default is `direct_import` per operator decision (overrides the `reference_only` default in this task) | 2026-06-24 |

## 3. Alternatives

- **ALT-001**: HTML scraping of Printables pages only. Not chosen because pages are Svelte-rendered and file lists are not consistently present in static HTML.
- **ALT-002**: Browser automation (headless) for every fetch. Not chosen due high latency, complexity, and operational overhead.
- **ALT-003**: Require users to manually upload all files and ignore provider APIs. Not chosen because it does not satisfy automatic file discovery requirement.
- **ALT-004**: Immediate multi-provider rollout (Thingiverse, MakerWorld, Cults3D). Not chosen because provider-specific data contracts differ; Printables-first reduces delivery risk.

## 4. Dependencies

- **DEP-001**: External endpoint availability for Printables GraphQL API (`https://api.printables.com/graphql/`).
- **DEP-002**: Existing HTTP client dependency (`httpx`) in backend runtime.
- **DEP-003**: Existing FastAPI/Jinja request flow in [app/public.py](app/public.py) and [app/templates/request_form_new.html](app/templates/request_form_new.html).
- **DEP-004**: Existing DB migration mechanism in [app/main.py](app/main.py).
- **DEP-005**: Existing feature-flag infrastructure in [app/models.py](app/models.py).

## 5. Files

- **FILE-001**: [app/public.py](app/public.py) - Add fetch endpoint, submit parsing, persistence, telemetry.
- **FILE-002**: [app/templates/request_form_new.html](app/templates/request_form_new.html) - Add fetch button, candidate selector UI, quantity controls, client JS.
- **FILE-003**: [app/main.py](app/main.py) - Add DB schema/migrations for external source tables.
- **FILE-004**: [app/models.py](app/models.py) - Add feature flag metadata entry.
- **FILE-005**: [app/my_requests.py](app/my_requests.py) - Extend requester view data hydration.
- **FILE-006**: [app/templates/my_request.html](app/templates/my_request.html) - Display selected external files and quantities.
- **FILE-007**: [app/templates/admin_request.html](app/templates/admin_request.html) - Display provider/source metadata to admins.
- **FILE-008**: [app/integrations/printables_client.py](app/integrations/printables_client.py) - New Printables API client.
- **FILE-009**: [app/integrations/printables_parser.py](app/integrations/printables_parser.py) - New URL parser and candidate normalizer.
- **FILE-010**: [tests/test_printables_integration.py](tests/test_printables_integration.py) - New provider contract tests.
- **FILE-011**: [tests/test_public_routes.py](tests/test_public_routes.py) - Extend route and submit-flow tests.
- **FILE-012**: [docs/printables-integration.md](docs/printables-integration.md) - Integration behavior and operational notes.

## 6. Testing

- **TEST-001**: Unit test `parse_printables_url` with valid/invalid host, path, and ID edge cases.
- **TEST-002**: Unit test GraphQL normalization for payload variants: `fileUploads`, `otherFiles`, `downloadPacks`, and empty files.
- **TEST-003**: API test `POST /submit/fetch-provider-files` returns deterministic schema and status codes.
- **TEST-003A**: API test verifies guest call to `POST /submit/fetch-provider-files` is denied with `401/403` and authenticated call succeeds.
- **TEST-004**: API test submit with selected external files only creates request + external source rows and no local file rows.
- **TEST-005**: API test submit with both local uploads and selected external files creates all expected records.
- **TEST-006**: UI test (manual or automated) verifies multi-select and quantity values survive submit.
- **TEST-007**: Migration test validates additive schema upgrade from existing production-like DB snapshot.
- **TEST-008**: Regression test confirms existing chunked upload flow still works without provider usage.
- **TEST-009**: Configuration test verifies `PRINTABLES_FETCH_MODE=reference_only` prevents binary download code paths.
- **TEST-010**: UI test verifies attribution and license notice rendering for fetched external models.

## 7. Risks & Assumptions

- **RISK-001**: Printables GraphQL schema may change field names or access policy without notice.
- **RISK-002**: Some models expose package-level downloads only, not per-file direct URLs.
- **RISK-003**: Provider rate limiting or anti-bot controls can intermittently block fetch attempts.
- **RISK-004**: Storing rich description HTML without strict sanitization can create XSS risk in internal views.
- **RISK-005**: Provider terms may restrict automated binary retrieval even for user-supplied links.
- **ASSUMPTION-001**: Public GraphQL `print(id: ID!)` remains accessible for non-authenticated metadata retrieval.
- **ASSUMPTION-002**: Existing request flow accepts additional hidden JSON field without breaking form validation.
- **ASSUMPTION-003**: Initial release can treat package downloads as selectable units when individual files are unavailable.
- **ASSUMPTION-004**: Production direct-import mode will only be enabled after a documented terms/compliance review.

## 8. Related Specifications / Further Reading

https://www.printables.com/model/258431-rugged-box-parametric/files
https://api.printables.com/graphql/
[Local submit route flow](app/public.py#L530)
[Local request form template](app/templates/request_form_new.html#L633)
[Local DB initialization and migrations](app/main.py#L907)