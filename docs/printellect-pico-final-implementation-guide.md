# Printellect Pico Final Implementation Guide

## NEW INFO (v0.17.0) - Read First

1. QR fallback links now target `https://print.jcubhub.com/pair?...` (not only `/printellect/add-device`).
2. `/pair` is account-native and supports:
   - prefilled `device_id`, `claim`, optional `name`
   - claim into signed-in account
   - auto-redirect to `/printellect/devices/{device_id}` when device is online
3. Admin registry now supports printable QR labels directly from UI.
4. Admin OTA upload now supports single `package` zip (full firmware folder zip) in addition to legacy manifest+bundle upload.
5. Pico identity model is unchanged: preassigned `device_id + claim_code`, then device self-provisions token from backend after claim.
6. Admin Device Registry now auto-generates and allows download of:
   - `device.json` (ready to copy to Pico)
   - QR SVG label

---

## 1) Firmware Identity and Files

Required files on Pico filesystem:

- `/device.json` (required; never deleted by reset flows)
```json
{
  "device_id": "perkbase-001",
  "claim_code": "TEST01",
  "hw_model": "pico2w"
}
```
- `/wifi.json` (created by setup portal; deleted on Wi-Fi reset/factory reset)
- `/token.json` (created after cloud provision; deleted on factory reset or bearer `401`)
- `/app_state.json` (dedupe ring, OTA pending info, boot fail counters, defaults)

Identity rules:
- Firmware identity is only `device_id + claim_code`.
- Friendly name is optional metadata from backend/UI; firmware should not depend on it.

---

## 2) Manufacturing / Provisioning Contract

Current production contract (must follow):

1. Admin creates device in backend registry.
2. System generates `device_id`, `claim_code`, QR payload, fallback URL.
3. Same `device_id` + `claim_code` is flashed into Pico `/device.json`.
4. QR label with same values is printed and attached to device.
5. Device ships with no `/wifi.json` and no `/token.json`.

No random self-registration in production:
- Do not generate random IDs on first boot expecting backend assignment.
- That would require a separate secure bootstrap credential model not in current API contract.

---

## 3) User Onboarding Flow (What Pico Must Support)

1. Pico boots; if no Wi-Fi config, enters AP mode.
2. AP SSID: `PRINTELLECT-SETUP-<last4_device_id>`.
3. Local setup page at `http://192.168.4.1/` accepts:
   - claim code (must match local `/device.json`)
   - home SSID/password
4. Pico saves `/wifi.json`, reboots, connects to home Wi-Fi.
5. Pico calls cloud provision endpoint repeatedly:
   - until user claims device in app/PWA
6. After user claim, provision returns `device_token`; Pico stores `/token.json` and enters normal run.

---

## 4) Runtime State Machine (Required)

`BOOT` -> load files  
`TRY_STA_CONNECT` -> connect Wi-Fi (3 retries, timeout each)  
`START_AP_SETUP` -> AP + setup web server at `192.168.4.1`  
`BACKEND_PROVISION_OR_RUN`:
- no token: poll `/provision`
- token exists: move to normal run  
`NORMAL_RUN`:
- heartbeat timer (15-30s)
- command poll loop (~1s, rate-limit aware)
- command execute/status/state reporting
- local buttons always active  
`RESET_DETECTED`:
- 10s hold: delete `/wifi.json`, reboot
- 20s hold: delete `/wifi.json` + `/token.json`, reboot

---

## 5) Cloud API Contract for Pico

Base URL:
- `https://print.jcubhub.com/api/printellect/device/v1`

Debug/discovery:
- `GET /debug`
- OpenAPI: `GET /openapi.json`

### 5.1 Provision (no bearer)
`POST /provision`
```json
{
  "device_id": "perkbase-001",
  "claim_code": "TEST01",
  "fw_version": "1.0.0",
  "app_version": "1.0.0"
}
```
Responses:
- `200 {"status":"unclaimed",...}` -> keep polling
- `200 {"status":"provisioned","device_token":"..."}` -> persist token and switch to bearer endpoints
- `403` invalid claim
- `429` too many failures (backoff)
- `404` unknown device

### 5.2 Heartbeat (bearer)
`POST /heartbeat`
```json
{"fw_version":"1.0.0","app_version":"1.0.0","rssi":-52}
```

### 5.3 Commands (bearer)
- `GET /commands/next`
- `POST /commands/{cmd_id}/status` with `executing|completed|failed`

### 5.4 State (bearer)
- `POST /state`
```json
{
  "playing": false,
  "perk_id": null,
  "track_id": null,
  "volume": 20,
  "brightness": 80,
  "idle_mode": "off"
}
```

### 5.5 OTA (bearer)
- `GET /releases/latest`
- `GET /releases/{version}/manifest`
- `GET /releases/{version}/files/{path}`
- `GET /releases/{version}/bundle`
- `POST /update/status`
- `POST /boot-ok`

---

## 6) Commands Pico Must Execute

Queue actions:
- `play_perk` `{perk_id}`
- `stop_audio` `{}`
- `set_idle` `{mode}`
- `set_brightness` `{level:0..100}`
- `set_volume` `{level:0..30}`
- `test_lights` `{pattern,duration_ms}`
- `test_audio` `{track_id}`
- `reboot` `{}`
- `ota_apply` `{version:"latest"|"<semver>"}`

Execution contract for each command:
1. POST `executing`
2. Execute action
3. POST updated state (if changed)
4. POST `completed` or `failed` (+ error)

Use recent command ID ring buffer to avoid replay duplicates.

---

## 7) Backoff / Reliability Rules

- Keep heartbeat independent from command polling.
- On `429` from `/commands/next`:
  - honor `Retry-After` and defer command polling only.
- On transport failure (`status=0`):
  - bounded backoff and reconnect strategy.
- On bearer `401`:
  - delete `/token.json`, return to provision flow.
- Never block local hardware actions because cloud is down.

---

## 8) OTA Packaging Expectations

Admin upload now supports:
1. **Package mode (preferred)**: single full firmware zip upload.
2. Legacy mode: `manifest.json` + `app_bundle.zip`.

Pico behavior is unchanged:
- consume release manifest/files endpoints
- verify hashes
- stage update
- reboot with pending flag
- send boot-ok on healthy startup
- rollback after repeated failed boots

---

## 9) End-to-End Validation Checklist

1. New board with only `/device.json` enters AP mode.
2. Wrong claim code on local setup page is rejected.
3. Correct setup writes `/wifi.json` and reboots.
4. Provision returns `unclaimed` before account claim.
5. User claims via QR (`/pair` flow).
6. Provision returns token; `/token.json` created.
7. Device appears online and opens control page.
8. Command lifecycle works end-to-end.
9. 10s reset clears only Wi-Fi.
10. 20s reset clears Wi-Fi + token.
11. OTA apply + boot-ok + rollback guard verified.

---

## 10) Canonical References

- Full programming guide: `docs/printellect-pico-api-programming-guide.md`
- Integration handoff: `docs/printellect-pico-integration-handoff.md`
- Device API spec: `docs/printellect-device-api.md`
- State machine details: `docs/printellect-device-state-machine.md`
