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

---

## Phase 3 — OTA Hardening + Device Functionality

### Checklist
- [x] Add OTA preflight checks on device (writable FS, free-space estimate, required-path verification).
- [x] Add post-apply and post-boot runtime verification gates before final OTA success confirmation.
- [x] Add legacy layout migrator hooks (`/main.py` shim + `/current/lib/__init__.py` safety).
- [x] Add structured OTA diagnostics `result` payload support on `POST /api/printellect/device/v1/update/status`.
- [x] Persist OTA result metadata (`device_update_status.last_result_json`) and expose it in list/detail/admin status APIs.
- [x] Add release manifest safety metadata (`manifest.safety`) with validated `required_paths`.
- [x] Add canary rollout mode (`mode=canary`, `limit`, `online_only`) for release push endpoint.
- [x] Add one-click support bundle downloads (owner and admin endpoints).
- [x] Add device functionality commands: `self_test` and `identify_device`.
- [x] Add diagnostics UI actions for Self-Test + Identify and support-bundle download button.
- [x] Add in-app OTA checklist guidance for safer rollout/remediation flow.

### Acceptance Gates
- [x] OTA failures surface actionable diagnostics (`result` + `last_error`) in admin and device views.
- [x] Canary push can target a small online subset before global rollout.
- [x] Support bundle exports include state, update status, and recent commands.
- [x] Self-test/identify actions are enqueueable and visible in diagnostics results.

---

## Phase 4 — UX Diagnostics + Telemetry Deepening

### Checklist
- [x] Add speaker validation command (`speaker_validate`) with structured result reporting.
- [x] Add button snapshot command (`button_snapshot`) for live button state + press counters.
- [x] Add firmware heartbeat telemetry payload (uptime/memory/temp/optional VSYS).
- [x] Persist heartbeat telemetry on backend and expose it in owner/admin device payloads.
- [x] Surface telemetry warning badges in device detail UI.
- [x] Add button diagnostics panel in device detail UI.
- [x] Add API/firmware tests for speaker/button diagnostics and heartbeat telemetry visibility.
- [x] Update API and firmware docs for new diagnostics/telemetry contracts.

### Acceptance Gates
- [x] Speaker/button diagnostics are enqueueable from UI and visible in recent command results.
- [x] Device detail API includes `heartbeat` telemetry and `telemetry_warnings`.
- [x] UI shows warning-highlighted telemetry cards for temp/voltage/memory conditions.
