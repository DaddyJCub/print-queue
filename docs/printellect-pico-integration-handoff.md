# Printellect Pico Integration Handoff

This is the implementation contract for Pico firmware engineers integrating with Printellect cloud.

## 1) Required config on device

- Cloud base URL: `https://print.jcubhub.com/api/printellect/device/v1`
- Device identity file (`/device.json`, never delete):
  - `device_id`
  - `claim_code`
  - `hw_model` (for example `pico2w`)
- Wi-Fi file (`/wifi.json`, delete on Wi-Fi reset):
  - `ssid`
  - `password`
- Token file (`/token.json`, delete on factory reset/unpair):
  - `device_token`

## 2) Required runtime state flow

1. Boot -> load `/device.json`, `/wifi.json`, `/token.json`.
2. If Wi-Fi missing or STA connect fails -> start AP setup mode (`PRINTELLECT-SETUP-xxxx`) at `http://192.168.4.1/`.
3. If token missing -> call `/provision` loop until `status=provisioned`.
4. With token -> normal run loop:
   - heartbeat every 15-30s
   - poll commands every ~1s
   - execute command and post status + state
5. If any bearer endpoint returns `401` -> delete `/token.json` and go back to provision loop.

## 3) Device API endpoints

Auth model:
- `/provision`: claim-code auth (no bearer)
- all others: `Authorization: Bearer <device_token>`

### 3.1 Discovery/debug

- `GET /debug`
  - Returns action list, status enums, endpoint map, timing defaults, and links to OpenAPI.
- Full API schema:
  - `GET /openapi.json`
  - `GET /docs`

### 3.2 Provision

- `POST /provision`
- Request:
```json
{
  "device_id": "perkbase-001",
  "claim_code": "printed-secret",
  "fw_version": "1.0.0",
  "app_version": "1.0.0"
}
```
- Responses:
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
  "device_token": "<plaintext token>",
  "poll_interval_ms": 1000
}
```
  - `403` invalid claim code
  - `404` unknown device
  - `429` too many failed claim attempts

Firmware behavior:
- `unclaimed`: wait and retry (2-5s)
- `provisioned`: persist token and switch to bearer endpoints
- `403`: slow down and surface local warning

### 3.3 Heartbeat

- `POST /heartbeat` (Bearer)
- Request example:
```json
{
  "fw_version": "1.0.0",
  "app_version": "1.0.0",
  "rssi": -58,
  "reset_event": "wifi_reset"
}
```
- Response:
```json
{ "ok": true }
```

### 3.4 Poll command queue

- `GET /commands/next` (Bearer)
- Responses:
  - `204` no command
  - `200` command:
```json
{
  "cmd_id": "uuid",
  "action": "play_perk",
  "payload": { "perk_id": "juggernog" },
  "created_at": "2026-02-14T20:10:02Z"
}
```
  - `429` polled too quickly; honor `Retry-After`

### 3.5 Command lifecycle status

- `POST /commands/{cmd_id}/status` (Bearer)
- Allowed statuses: `executing`, `completed`, `failed`
- Request examples:
```json
{ "status": "executing" }
```
```json
{ "status": "completed" }
```
```json
{ "status": "failed", "error": "speaker init failed" }
```

### 3.6 State push

- `POST /state` (Bearer)
- Request example:
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

### 3.7 OTA endpoints

- `GET /releases/latest?channel=stable`
- `GET /releases/{version}/manifest`
- `GET /releases/{version}/files/{file_path}`
- `GET /releases/{version}/bundle`
- `POST /update/status`
- `POST /boot-ok`

## 4) Commands device must support

Actions and payload contract from queue:

- `play_perk` -> `{ "perk_id": "<id>" }`
- `stop_audio` -> `{}`
- `set_idle` -> `{ "mode": "<mode>" }`
- `set_brightness` -> `{ "level": 0..100 }`
- `set_volume` -> `{ "level": 0..30 }`
- `test_lights` -> `{ "pattern": "<pattern>", "duration_ms": <positive int> }`
- `test_audio` -> `{ "track_id": "<id>" }`
- `reboot` -> `{}`
- `ota_apply` -> `{ "version": "<version|latest>" }`

## 5) Error handling rules (mandatory)

- `401` on any bearer endpoint:
  - clear `/token.json`
  - return to `/provision` loop
- `429` on command polling:
  - back off using `Retry-After` if present
- Network failure:
  - keep local controls working
  - retry loop, do not hard-crash app

## 6) Security requirements

- Do not expose token in serial logs.
- Do not store token in source.
- Never accept inbound internet traffic on Pico.
- AP setup is open; enforce local claim-code validation before writing `/wifi.json`.

## 7) Quick validation checklist

1. New device with no `/wifi.json` enters AP setup mode.
2. Save Wi-Fi with valid local claim code.
3. Device reaches `/provision` and waits as `unclaimed`.
4. User claims device in app.
5. Device receives `provisioned`, stores token, switches to bearer mode.
6. Heartbeat appears in backend (`last_seen_at` updates).
7. Command queue roundtrip works: delivered -> executing -> completed.
8. `401` simulation forces reprovision behavior.

## 8) Useful docs

- Final implementation guide (latest changes first): `docs/printellect-pico-final-implementation-guide.md`
- Full Pico guide: `docs/printellect-pico-api-programming-guide.md`
- Device API spec: `docs/printellect-device-api.md`
- Device state machine: `docs/printellect-device-state-machine.md`
- User setup guide: `docs/setup-my-printellect-base.md`

## 9) Firmware implementation expectations (explicit)

This is the minimum expected from Pico firmware for production readiness.

### 9.1 Scheduler and timing

- Main loop should be non-blocking (no long global sleeps).
- Command poll cadence:
  - target every 1.0-1.2s
  - enforce minimum 1.0s between polls
  - on `429`, read `Retry-After` and defer only command polling
- Heartbeat cadence:
  - every 15-30s on a separate timer
  - must continue even when command poll is rate-limited
- Provision cadence:
  - every 2-5s while unclaimed

### 9.2 Network and recovery behavior

- If bearer endpoints return `401`, clear token and reprovision.
- For transport errors (`status=0` or request exception):
  - retry with bounded backoff
  - keep local button controls active
  - reconnect STA if repeated failures
- Device must never hard-lock due to temporary cloud loss.

### 9.3 Command execution contract

For each remote command:
1. POST `executing`
2. Execute hardware action
3. POST state update (if changed)
4. POST `completed` or `failed` with error string

Duplicate command defense:
- Keep a short ring buffer of recent command IDs in `/app_state.json` and skip re-execution if replayed.

### 9.4 Local controls parity

- Physical button actions should use the same action code paths as remote commands.
- Local state changes should still attempt state push best-effort.
- Remote and local controls must not fight over shared hardware state (audio/LED lock discipline).

### 9.5 Required local file semantics

- `/device.json`: immutable identity (except factory reflash).
- `/wifi.json`: rewritten only by setup portal after claim-code check.
- `/token.json`: written only after `status=provisioned`.
- `/app_state.json`: persisted for dedupe, settings defaults, OTA pending/rollback counters.

### 9.6 OTA safety baseline

- Validate downloaded file hashes before activation.
- Stage update, set pending flag, reboot, then require boot-ok confirmation.
- If pending version fails repeatedly, roll back to previous app set and report failure.

### 9.7 Observability

Serial logs should include:
- current runtime state (`BOOT`, `TRY_STA`, `PROVISION_LOOP`, `NORMAL_RUN`)
- API result status codes
- command IDs and actions
- reset events

Security:
- never print bearer token plaintext
- avoid logging full claim code in production logs

## 10) Provisioning model for production (what gets set before shipping)

Recommended model (current backend contract):

1. In admin registry, create device entry (or bulk create) with auto-generated:
   - `device_id`
   - `claim_code`
2. Print label/QR from admin registry output:
   - QR encodes `printellect://pair?device_id=...&claim=...`
   - fallback URL encodes same values at `/pair` and can include `name`
   - `/pair` flow auto-fills claim details in the signed-in account and redirects to device control when online
3. Flash Pico with matching `/device.json`:
   - same `device_id`
   - same `claim_code`
4. Ship device with no `/wifi.json` and no `/token.json`.

Why this is the default:
- Claim code is never stored plaintext in backend (hash-only), so the printed label and flashed `/device.json` are the source of truth.
- Device can self-provision token only after owner claim; no USB token copy required.

Alternative model (not current default):
- Device generates random ID/claim at first boot and tries to self-register upstream.
- This requires a separate bootstrap trust model (manufacturing key/cert) and extra backend API for secure registration.
- Do not implement this in production without a signed manufacturing credential flow.

Friendly names:
- `name` is optional metadata and can be set at manufacturing time or during user claim.
- Pico firmware should not depend on `name`; only `device_id` and `claim_code` are identity inputs.
