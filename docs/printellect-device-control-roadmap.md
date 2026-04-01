# Printellect Device Control Roadmap

> Owner: Printellect Platform Team  
> Last Updated: 2026-04-01

This roadmap tracks the multi-phase Printellect device-control and firmware expansion so scope is explicit and nothing is missed.

---

## Phase 1 — Controls, Diagnostics, Testing, Cleanup

### Checklist
- [x] Add structured light control actions (`light-color`, `light-effect`).
- [x] Extend `test-lights` for structured effect + optional color while keeping compatibility.
- [x] Canonicalize color payloads to RGB and accept `#RRGGBB` input.
- [x] Persist optional command execution `result` metadata in DB.
- [x] Expose command result metadata in device detail/list responses.
- [x] Fix legacy table-name mismatches in rename and shipping notification paths.
- [x] Add schema migration for `commands.result_json`.
- [x] Extend firmware runner/hardware adapter for light color/effect commands and result reporting.
- [x] Improve diagnostics UI with color picker, effect controls, and result badges.
- [x] Add API + firmware + smoke + regression tests.
- [x] Update Printellect API docs and local QA docs.
- [x] Enforce OTA target/report version consistency checks (`boot-ok`, `update/status`, heartbeat drift guard).

### Acceptance Gates
- [x] New action APIs return validated payloads and reject bad color/effect values with `422`.
- [x] Device command status accepts optional `result` object and persists it.
- [x] Diagnostics UI displays recent pass/fail command outcomes with remediation guidance.
- [x] Regression tests pass for rename and shipping-triggered device notifications.

---

## Phase 2 — Hybrid Low-Latency Delivery

### Checklist
- [x] Add optional long-poll endpoint: `GET /api/printellect/device/v1/commands/stream`.
- [x] Keep existing queue polling endpoint (`/commands/next`) unchanged as fallback path.
- [x] Update firmware runtime to prefer stream and fallback to polling when unavailable.
- [x] Document stream contract in Device API docs.
- [x] Add API tests for stream behavior.

### Acceptance Gates
- [x] Command state machine remains single-source-of-truth in `commands`.
- [x] Stream endpoint delivers queued commands and returns `204` when empty/inflight.
- [x] Firmware remains functional if stream endpoint is unavailable.

---

## Notes
- Printellect app scope in this repo means current Web/PWA surfaces under `/printellect/*`.
- Backward compatibility is maintained for existing command and OTA workflows.
