# Printellect User API

> See also: [Device API](printellect-device-api.md) · [Admin API](printellect-admin-api.md) · [Docs Index](README.md)

## Feature gate

- All endpoints require feature flag `printellect_device_control` for the signed-in account.
- If not assigned, API returns `403`: `{ "detail": "Printellect feature is not enabled for this account" }`.
- Bypass: set env `PRINTELLECT_DEMO_OPEN_ACCESS=1` (dev/demo only).

## Error response format

All errors use a standard JSON envelope:

```json
{ "detail": "Human-readable error message" }
```

| Code | Meaning |
|------|---------|
| `400` | Invalid JSON payload |
| `403` | Feature flag not enabled, or not device owner |
| `404` | Device or session not found |
| `409` | Conflict (device already claimed, already playing, or device offline) |
| `410` | Pairing session expired |
| `422` | Missing required fields |
| `429` | Too many failed claim attempts |

---

## Start pairing session (optional)
`POST /api/printellect/pairing/start`

Auth: logged-in account session.

Response (`200`):
```json
{
  "ok": true,
  "session_id": "uuid",
  "expires_at": "2026-02-14T21:30:00Z"
}
```

Sessions expire after 10 minutes (configurable via `PAIRING_SESSION_MINUTES`).

---

## Claim device
`POST /api/printellect/pairing/claim`

Auth: logged-in account session.

Request:
```json
{
  "device_id": "perkbase-001",
  "claim_code": "printed-secret"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `device_id` | string | Yes | Lowercased automatically |
| `claim_code` | string | Yes | Matches device's stored claim code |
| `name` | string | No | Custom device name, max 64 chars |
| `session_id` | string | No | UUID from `/pairing/start` |

Response (`200`):
```json
{
  "status": "claimed",
  "device_id": "perkbase-001",
  "name": "Living Room Base",
  "next": "wait_for_online",
  "online": false,
  "device_url": "/printellect/devices/perkbase-001",
  "fw_version": "1.0.0",
  "app_version": "1.0.0"
}
```

Error responses:
- `409` — device already claimed by another account.
- `403` — invalid claim code.
- `410` — pairing session expired (if `session_id` provided).
- `429` — too many failed claim attempts (8 per 5-minute window per IP × device).

---

## Device list
`GET /api/printellect/devices`

Auth: logged-in account session + feature flag.

Response (`200`):
```json
{
  "ok": true,
  "devices": [
    {
      "device_id": "perkbase-001",
      "name": "Living Room Base",
      "last_seen_at": "2026-03-22T10:30:00Z",
      "online": true,
      "fw_version": "1.0.0",
      "app_version": "1.0.0",
      "rssi": -55,
      "state": {
        "playing": false,
        "volume": 15,
        "brightness": 30,
        "idle_mode": "default"
      },
      "update_status": {
        "status": "idle",
        "target_version": null,
        "progress": 0,
        "last_error": null
      },
      "last_command": {
        "action": "test_lights",
        "status": "completed",
        "updated_at": "2026-04-01T12:00:00Z",
        "error": null,
        "result": { "effect": "pulse", "duration_ms": 1200, "hex": "#34C759" }
      }
    }
  ]
}
```

Only returns devices owned by the authenticated account.

---

## Device detail
`GET /api/printellect/devices/{device_id}`

Auth: logged-in account session + feature flag + device ownership.

Response (`200`):
```json
{
  "ok": true,
  "device": {
    "device_id": "perkbase-001",
    "name": "Living Room Base",
    "last_seen_at": "2026-03-22T10:30:00Z",
    "online": true,
    "fw_version": "1.0.0",
    "app_version": "1.0.0",
    "rssi": -55,
    "state": { "playing": false, "volume": 15 },
    "state_updated_at": "2026-03-22T10:29:50Z",
    "update_status": {
      "status": "idle",
      "target_version": null,
      "progress": 0,
      "last_error": null,
      "updated_at": null
    },
    "recent_commands": [
      {
        "cmd_id": "uuid",
        "action": "play_perk",
        "payload": { "perk_id": "juggernog" },
        "result": { "ok": true },
        "status": "completed",
        "created_at": "2026-03-22T10:25:00Z",
        "updated_at": "2026-03-22T10:25:05Z",
        "error": null
      }
    ]
  }
}
```

`recent_commands` returns the last 30 commands, newest first.

Error: `403` if device is not owned by the account, `404` if device not found.

---

## Rename device
`PUT /api/printellect/devices/{device_id}/name`

Auth: logged-in account session + feature flag + device ownership.

Request:
```json
{ "name": "Kitchen Base" }
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | Yes | Max 64 characters |

Response (`200`):
```json
{ "ok": true, "name": "Kitchen Base" }
```

---

## Action enqueue endpoints

All actions: `POST /api/printellect/devices/{device_id}/actions/{action}`

Auth: logged-in account session + feature flag + device ownership.

### Success response (`200`)
```json
{
  "ok": true,
  "cmd_id": "uuid",
  "action": "play_perk",
  "payload": { "perk_id": "juggernog" }
}
```

### Common error responses
- `403` — not device owner or feature flag disabled.
- `404` — device not found.
- `409` — device is offline, or (for `play`) device is already playing.
- `422` — invalid payload for action.

### Action reference

| Action | Path | Payload | Validation |
|--------|------|---------|------------|
| Play perk | `/actions/play` | `{ "perk": "juggernog" }` | `perk` required, non-empty |
| Stop audio | `/actions/stop` | `{}` | — |
| Set idle mode | `/actions/idle` | `{ "mode": "default" }` | `mode` required, non-empty |
| Set brightness | `/actions/brightness` | `{ "level": 50 }` | `level` required, int 0-100 |
| Set volume | `/actions/volume` | `{ "level": 15 }` | `level` required, int 0-30 |
| Set light color | `/actions/light-color` | `{ "color": "#0A84FF" }` or `{ "color": {"r":10,"g":132,"b":255} }` | Color required; server canonicalizes to RGB |
| Set light effect | `/actions/light-effect` | `{ "effect": "pulse", "color": "#34C759", "speed_ms": 250 }` | `effect` required; allowed: `ambient`, `chase`, `off`, `pulse`, `rainbow`, `solid`, `strobe` |
| Test lights | `/actions/test-lights` | `{ "effect": "pulse", "duration_ms": 1200, "speed_ms": 250, "color": "#34C759" }` | `effect` (or legacy `pattern`) + `duration_ms` required |
| Test audio | `/actions/test-audio` | `{ "track_id": "..." }` | `track_id` required, non-empty |
| Reboot | `/actions/reboot` | `{}` | — |
| OTA update | `/actions/update` | `{ "version": "0.3.0" }` | `version` required, non-empty |
