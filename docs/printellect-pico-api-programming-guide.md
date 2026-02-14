# Printellect Pico 2 W Programming Guide

This is the full Pico-side implementation and integration contract for Printellect.
It is written for firmware development and validation.

Account-side note:
- User-facing claim/control pages are gated by feature flag `printellect_device_control`.
- Device endpoints are not feature-gated and continue to authenticate by claim code/token.

Quick handoff summary:
- `docs/printellect-pico-integration-handoff.md`
- Final implementation guide (latest rollout notes first):
- `docs/printellect-pico-final-implementation-guide.md`

## 1) Scope

This guide covers:
- Device identity and persisted files on Pico storage.
- Wi-Fi onboarding via local AP + setup page at `http://192.168.4.1/`.
- Claim/provision token flow with backend.
- Normal authenticated command/state loop.
- Reset state machine and LED timing behavior.
- OTA app-code update flow and rollback guard.
- Local bring-up and acceptance checklist.

This guide does not cover web app internals except where Pico behavior depends on backend API responses.

## 2) Required Device Artifacts

Factory/programming time files:
- `/device.json` (required, never deleted by reset flows)

Runtime-generated files:
- `/wifi.json` (created by setup page, deleted by Wi-Fi reset/factory reset)
- `/token.json` (created by provision success, deleted by factory reset)
- `/app_state.json` (runtime metadata: dedupe ring, OTA flags/counters)

Optional config override:
- `/config.json` (timing and endpoint overrides)

Reference files:
- `device/pico2w/device.json.example`
- `device/pico2w/config.example.json`

Manufacturing expectation (required for current cloud flow):
- Backend admin must create each device record first (auto-generated IDs supported).
- Printed label QR and flashed `/device.json` must carry the same `device_id` + `claim_code`.
- Device ships without `/wifi.json` and `/token.json`.
- QR fallback URL should be `/pair?device_id=...&claim=...&name=...` so the PWA can auto-claim for logged-in users.
- Admin registry provides automated downloads for `device.json` and QR SVG during create/rotate flows.

Identity decisions (current and future):
- Current production path: server-assigned identity at manufacturing (`device_id` + `claim_code`), then hash stored server-side.
- Not in current contract: first-boot random self-registration from Pico.
- If self-registration is ever added, it must use a manufacturing trust credential and a dedicated bootstrap endpoint.

## 3) File Contract

### 3.1 `/device.json` (required)
```json
{
  "device_id": "perkbase-001",
  "claim_code": "random-printed-secret",
  "hw_model": "pico2w"
}
```

Rules:
- `device_id` and `claim_code` are mandatory.
- Never delete this file during reset flows.
- `claim_code` must match the printed QR/label and backend hash source.

### 3.2 `/wifi.json`
```json
{
  "ssid": "HomeWifi",
  "password": "secret"
}
```

Rules:
- Must only be written after local setup page claim code validation.
- Delete on Wi-Fi reset and factory reset.

### 3.3 `/token.json`
```json
{
  "device_token": "backend-issued-long-token"
}
```

Rules:
- Write only after `status=provisioned` from `/device/v1/provision`.
- Delete on `401` from bearer endpoints.
- Delete on factory reset.

### 3.4 `/app_state.json`
Example:
```json
{
  "last_cmd_ids": ["cmd-1", "cmd-2"],
  "pending_version": "0.3.0",
  "last_good_version": "0.2.9",
  "boot_fail_count": 1
}
```

Used for:
- Duplicate command dedupe ring.
- OTA pending/healthy tracking.
- Crash-loop rollback guard.

## 4) Runtime Config (`/config.json`)

Supported keys (defaults from `device/pico2w/main.py`):
- `api_base` default `https://print.jcubhub.com`
- `heartbeat_interval_s` default `20`
- `command_poll_interval_s` default `1`
- `provision_poll_interval_s` default `3`
- `sta_connect_timeout_s` default `10`
- `sta_connect_retries` default `3`
- `wifi_reset_hold_s` default `10`
- `factory_reset_hold_s` default `20`

## 5) Network and Setup Portal

## 5.1 Enter AP setup mode when any is true
- `/wifi.json` missing.
- STA connection fails after configured retries/timeouts.
- Wi-Fi reset or factory reset committed.

## 5.2 AP setup behavior
- Start open AP SSID:
  - `PRINTELLECT-SETUP-<last4(device_id).upper()>`
- Start local HTTP setup server on AP interface (`0.0.0.0:80`).
- User accesses:
  - `http://192.168.4.1/`

Endpoints:
- `GET /` renders setup form.
- `POST /save` reads form fields `claim_code`, `ssid`, `password`.

Validation on `POST /save`:
- `claim_code` must exactly match local `/device.json` claim code.
- `ssid` must be non-empty.
- On success write `/wifi.json`, return success page, reboot.

Implementation:
- `device/pico2w/lib/setup_portal.py`

## 6) Security Model on Pico

- Pico never accepts inbound internet traffic.
- Cloud calls are outbound HTTPS only.
- Pre-provision identity is `device_id + claim_code`.
- Post-provision identity is bearer token from `/token.json`.
- Do not log token plaintext in debug output.
- AP is open by design; setup is gated by local claim code check.

## 7) Device API Contract (Pico Consumption)

Base path:
- `https://<host>/api/printellect/device/v1`
- Debug contract:
  - `GET /debug` (compact device-focused API map)
- Full schema:
  - `GET https://<host>/openapi.json`
- `GET https://<host>/docs`

Factory/admin discovery endpoints useful during bring-up:
- `GET /api/printellect/device/v1/debug` (firmware contract map)
- `POST /api/printellect/admin/devices` (admin creates device identity + claim code)
- `POST /api/printellect/admin/devices/{device_id}/claim-code/rotate` (admin rotates and reprints label)

Client implementation:
- `device/pico2w/lib/api_client.py`

## 7.1 Provision (no bearer)
`POST /provision`

Request:
```json
{
  "device_id": "perkbase-001",
  "claim_code": "printed-secret",
  "fw_version": "1.0.0",
  "app_version": "1.0.0"
}
```

Responses:
- `200` unclaimed:
```json
{
  "status": "unclaimed",
  "legacy_status": "waiting",
  "message": "Device not yet claimed",
  "poll_interval_ms": 1000
}
```
- `200` provisioned:
```json
{
  "status": "provisioned",
  "legacy_status": "claimed",
  "device_token": "plaintext-token",
  "poll_interval_ms": 1000
}
```
- `403` invalid claim code.
- `429` too many failed claim attempts.
- `404` unknown device.

Firmware behavior:
- `unclaimed`: sleep 2-5 seconds and retry.
- `provisioned`: write `/token.json`, enter bearer flow.
- `403`: stop aggressive retries; surface local warning.
- `429`: exponential backoff before retry.

Provisioning identity source of truth:
- Backend stores only `claim_code_hash`.
- Firmware cannot recover a lost claim code from backend.
- If label is lost, admin must rotate claim code and update/reflash `/device.json` to match.

## 7.2 Heartbeat (bearer)
`POST /heartbeat`

Request:
```json
{
  "fw_version": "1.0.0",
  "app_version": "1.0.0",
  "rssi": -58,
  "reset_event": "wifi_reset"
}
```

Response:
```json
{ "ok": true }
```

## 7.3 Poll command (bearer)
`GET /commands/next`

Responses:
- `204` no command.
- `200` command payload:
```json
{
  "cmd_id": "uuid",
  "action": "play_perk",
  "payload": {"perk_id": "juggernog"},
  "created_at": "2026-02-14T20:10:02Z"
}
```
- `429` poll too frequent.

## 7.4 Command status (bearer)
`POST /commands/{cmd_id}/status`

Request:
```json
{ "status": "executing" }
```
or
```json
{ "status": "completed" }
```
or
```json
{ "status": "failed", "error": "speaker init failed" }
```

## 7.5 Device state (bearer)
`POST /state`

Request example:
```json
{
  "playing": true,
  "perk_id": "juggernog",
  "track_id": "juggernog",
  "volume": 15,
  "brightness": 30,
  "idle_mode": "default"
}
```

## 7.6 OTA endpoints (bearer)
- `GET /releases/latest?channel=stable`
- `GET /releases/{version}/manifest`
- `GET /releases/{version}/files/{file_path}`
- `GET /releases/{version}/bundle`
- `POST /update/status`
- `POST /boot-ok`

## 8) Action Execution Contract

Server action -> Pico hardware call mapping:
- `play_perk` -> `play_perk(perk_id)`
- `stop_audio` -> `stop_audio()`
- `set_idle` -> `set_idle(mode)`
- `set_brightness` -> `set_brightness(level)`
- `set_volume` -> `set_volume(level)`
- `test_lights` -> `test_lights(pattern, duration_ms)`
- `test_audio` -> `test_audio(track_id)`
- `reboot` -> `reboot()`
- `ota_apply` -> OTA manager apply + reboot

Implementation:
- `device/pico2w/lib/command_runner.py`
- `device/pico2w/lib/hardware.py`

Idempotency:
- Keep last command IDs ring buffer in `/app_state.json`.
- Skip duplicate `cmd_id` without re-executing side effects.

## 9) Pico State Machine

Implemented in:
- `device/pico2w/main.py`

States:
- `BOOT`
- `TRY_STA_CONNECT`
- `START_AP_SETUP`
- `BACKEND_PROVISION_OR_RUN`
- `NORMAL_RUN`

### 9.1 `BOOT`
- Load `device.json`, `wifi.json`, `token.json`.
- If `device.json` missing/invalid: hard fail.
- Run OTA boot guard (pending-version failure counter).

### 9.2 `TRY_STA_CONNECT`
- If no `wifi.json`: transition to `START_AP_SETUP`.
- Attempt STA connect (timeout + retries from config).
- Success -> `BACKEND_PROVISION_OR_RUN`.
- Failure -> `START_AP_SETUP`.

### 9.3 `START_AP_SETUP`
- Start AP SSID.
- Serve setup portal until `/save` success.
- On success: reboot.

### 9.4 `BACKEND_PROVISION_OR_RUN`
- Require active STA connection.
- If no token: call `/provision` on interval until provisioned.
- Save token, then transition to `NORMAL_RUN`.

### 9.5 `NORMAL_RUN`
- Heartbeat every configured interval.
- Poll commands every configured interval.
- Execute command lifecycle:
  - `executing` -> perform action -> `completed` or `failed`
- Push state changes (remote command and local button paths).
- OTA pending confirmation:
  - if `pending_version` exists and cloud reachable, call `/boot-ok`, clear pending.
- On bearer `401`:
  - delete `/token.json`, clear token, return to provision state.

## 10) Reset and LED Contract

Controller:
- `device/pico2w/lib/reset_controller.py`

Events:
- Hold 10s -> `wifi_reset`
- Hold 20s -> `factory_reset`
- Triple press within 3s -> `soft_reset`

Actions:
- `wifi_reset`: delete `/wifi.json`, keep `/token.json`, reboot.
- `factory_reset`: delete `/wifi.json` and `/token.json`, reboot.
- `soft_reset`: reboot only.

LED phase labels:
- `slow_blink` (0-7s)
- `fast_blink` (7-10s)
- `alt_blink` (10-15s)
- `alt_very_fast` (15-20s)
- `commit` (>= commit threshold)

Hardware adapter must map these symbolic phases to real LED output.

## 11) OTA Flow and Rollback

Manager:
- `device/pico2w/lib/ota_manager.py`

Directory model:
- `/current` active app
- `/next` staging app
- `/prev` rollback copy

Apply flow:
1. Resolve release manifest (`latest` or explicit version).
2. Download each file from `/releases/{version}/files/{path}`.
3. Verify `sha256` for each file.
4. Write staged files to `/next`.
5. Rotate directories:
   - remove `/prev`
   - move `/current` -> `/prev`
   - move `/next` -> `/current`
6. Set `pending_version` in `/app_state.json`.
7. Reboot (command runner path for `ota_apply`).

Boot guard:
- On boot, if `pending_version` exists:
  - increment `boot_fail_count`.
  - if `boot_fail_count >= 3`, rollback (`/prev` -> `/current`), clear pending.
- On successful normal run/cloud contact:
  - call `/boot-ok` with version.
  - clear `pending_version`, reset fail count, set `last_good_version`.

## 12) Error Handling and Backoff

Required behavior:
- Any bearer endpoint `401`:
  - delete `/token.json`
  - transition back to provision loop
- `commands/next` `429`:
  - apply backoff using `Retry-After` if present
- Provision `429`:
  - exponential backoff (do not hammer)
- Network exceptions:
  - keep local button functionality
  - retry loop; do not crash firmware

## 13) Manufacturing and Provisioning Inputs

Per device, backend/manufacturing must provide:
- `device_id`
- `claim_code` (printed in QR/label)
- backend row with `claim_code_hash`
- optional `name` (friendly label; not required by firmware)

Recommended QR payload:
- `printellect://pair?device_id=<id>&claim=<claim_code>`
- optional: append `&name=<friendly_name>`

Fallback URL QR payload:
- `https://print.jcubhub.com/pair?device_id=<id>&claim=<claim_code>`
- optional: append `&name=<friendly_name>`

OTA publishing input for backend/admin:
- You can upload either:
  - one full firmware folder zip (`package` mode), or
  - legacy `manifest.json` + `app_bundle.zip`.
- Pico consumption is unchanged: it still reads cloud manifest/files endpoints only.

## 14) Local Bring-Up Steps

1. Flash MicroPython.
2. Copy firmware files:
   - `device/pico2w/boot.py`
   - `device/pico2w/main.py`
   - `device/pico2w/lib/*`
3. Write `/device.json` with real `device_id` and `claim_code`.
4. Optional `/config.json` override.
5. Boot device with no `/wifi.json`:
   - verify AP appears and setup page works.
6. Save Wi-Fi credentials through setup page:
   - verify reboot and STA connect.
7. Claim device in Printellect UI.
8. Verify `/provision` loop gets token and writes `/token.json`.
9. Verify heartbeat + command execution + state updates.
10. Verify reset flows (10s/20s/triple press).
11. Verify OTA apply and boot guard behavior.

## 15) Acceptance Checklist (Pico Focus)

- Missing `wifi.json` always enters AP setup mode.
- Wrong claim code on setup page is rejected.
- Valid setup save writes `wifi.json` then reboots.
- Unclaimed cloud state keeps provision loop in waiting mode.
- Claimed cloud state returns token and enters normal run.
- Revoked/invalid token causes `401` recovery to provision loop.
- Duplicate command IDs are not re-executed.
- 10s reset deletes only `wifi.json`.
- 20s reset deletes `wifi.json` + `token.json`.
- Triple press performs reboot without deleting files.
- OTA apply verifies hashes and stages files.
- Repeated failed boots on pending OTA trigger rollback.

## 16) Source References

Core runtime:
- `device/pico2w/main.py`

Subsystems:
- `device/pico2w/lib/api_client.py`
- `device/pico2w/lib/wifi_manager.py`
- `device/pico2w/lib/setup_portal.py`
- `device/pico2w/lib/reset_controller.py`
- `device/pico2w/lib/command_runner.py`
- `device/pico2w/lib/ota_manager.py`
- `device/pico2w/lib/file_store.py`
- `device/pico2w/lib/hardware.py`

Backend contracts used by Pico:
- `app/printellect.py`
- `app/printellect_service.py`
- `docs/printellect-device-api.md`
