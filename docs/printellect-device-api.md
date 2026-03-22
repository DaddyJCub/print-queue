# Printellect Device API (Pico Contract)

> See also: [User API](printellect-user-api.md) · [Admin API](printellect-admin-api.md) · [Docs Index](README.md)

Base path: `/api/printellect/device/v1`

All endpoints use JSON unless noted. All timestamps are ISO 8601 UTC.

---

## Auth model

| Endpoint | Auth |
|----------|------|
| `GET /debug` | None |
| `POST /provision` | Claim code (no bearer) |
| All other endpoints | `Authorization: Bearer <device_token>` |

### Bearer token flow
1. Device receives token from `POST /provision` on successful claim.
2. Token is stored in `/token.json` on device filesystem.
3. On `401` from any bearer endpoint, device deletes `/token.json` and re-enters provision loop.

---

## Error response format

All errors use a standard JSON envelope:

```json
{ "detail": "Human-readable error message" }
```

| Code | Meaning |
|------|---------|
| `400` | Invalid JSON payload |
| `401` | Missing/invalid/revoked bearer token, or unknown device |
| `403` | Invalid claim code |
| `404` | Resource not found |
| `409` | Conflict (e.g. device already in requested state) |
| `422` | Validation error (missing/invalid fields) |
| `429` | Rate limited — check `Retry-After` header |

---

## 1) Debug / API discovery

### 1.1 Device-focused contract
`GET /debug`

Returns a compact contract payload the Pico can fetch for debugging, including:
- supported actions
- status enums
- auth mode
- endpoint list
- links to full FastAPI OpenAPI docs

### 1.2 Full server OpenAPI
- JSON schema: `GET /openapi.json`
- Swagger UI: `GET /docs`

---

## 2) Provision (claim code)

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

- Device exists but not yet account-claimed (`200`):
```json
{
  "status": "unclaimed",
  "legacy_status": "waiting",
  "message": "Device not yet claimed",
  "poll_interval_ms": 1000
}
```

- Claimed, token issued (`200`):
```json
{
  "status": "provisioned",
  "legacy_status": "claimed",
  "device_token": "plaintext-token",
  "poll_interval_ms": 1000
}
```

- Invalid claim code (`403`):
```json
{ "detail": "Invalid claim code" }
```

Rate limit:
- 8 failed claim attempts per IP × device × claim-hash within 5 minutes → `429`.
- Configurable via `PRINTELLECT_MAX_CLAIM_FAILURES` and `PRINTELLECT_CLAIM_FAIL_WINDOW_S`.

Firmware rule:
- `unclaimed`: sleep 2-5 seconds and retry.
- `provisioned`: store token in `/token.json`, switch to bearer mode.
- `403`: pause and require operator check (wrong label/config).

---

## 3) Heartbeat

`POST /heartbeat` (Bearer)

All request fields are **optional**:
```json
{
  "fw_version": "1.0.0",
  "app_version": "1.0.0",
  "rssi": -55,
  "reset_event": "wifi_reset"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `fw_version` | string | Will not overwrite existing value with null |
| `app_version` | string | Will not overwrite existing value with null |
| `rssi` | int or string | Coerced to int; Wi-Fi signal strength |
| `reset_event` | string | Logged if present (e.g. `wifi_reset`, `factory_reset`) |

Response:
```json
{ "ok": true }
```

Device is considered **online** if last heartbeat was within `DEVICE_ONLINE_WINDOW_SECONDS` (default: 60).

---

## 4) Command poll and status

### 4.1 Get next command
`GET /commands/next` (Bearer)

Responses:
- `204` — no queued command.
- `200` — command payload:
```json
{
  "cmd_id": "uuid",
  "action": "play_perk",
  "payload": { "perk_id": "juggernog" },
  "created_at": "2026-02-14T20:10:02Z"
}
```

Rate limit:
- Minimum 1 second between polls per device (configurable via `DEVICE_MIN_POLL_SECONDS`).
- If polled too fast: `204` with `Retry-After` header (seconds).

Command state machine: `queued → delivered → executing → completed | failed`

### 4.2 Command lifecycle updates
`POST /commands/{cmd_id}/status` (Bearer)

Request:
```json
{ "status": "executing" }
```

```json
{ "status": "completed" }
```

```json
{ "status": "failed", "error": "speaker init failed" }
```

| Field | Type | Required |
|-------|------|----------|
| `status` | string | Yes — one of `executing`, `completed`, `failed` |
| `error` | string | Optional — included when `status` is `failed` |

Response:
```json
{ "ok": true }
```

---

## 5) Device state push

`POST /state` (Bearer)

Accepts **any** JSON object. The entire payload replaces the stored device state.

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

Response:
```json
{ "ok": true }
```

Error: `400` if body is not valid JSON.

---

## 6) OTA endpoints

### 6.1 Latest release lookup
`GET /releases/latest?channel=stable` (Bearer)

Responses:
- `204` — none available for channel.
- `200`:
```json
{
  "version": "0.3.0",
  "channel": "stable",
  "manifest": {
    "version": "0.3.0",
    "channel": "stable",
    "entrypoint": "main.py",
    "files": [
      { "path": "main.py", "sha256": "...", "size": 1234 }
    ]
  },
  "endpoints": {
    "manifest_url": "/api/printellect/device/v1/releases/0.3.0/manifest",
    "file_base_url": "/api/printellect/device/v1/releases/0.3.0/files",
    "bundle_url": "/api/printellect/device/v1/releases/0.3.0/bundle"
  }
}
```

### 6.2 Release manifest
`GET /releases/{version}/manifest` (Bearer)

Response:
```json
{
  "version": "0.3.0",
  "manifest": {
    "version": "0.3.0",
    "channel": "stable",
    "entrypoint": "main.py",
    "bundle_sha256": "hex-digest",
    "bundle_size": 9803,
    "files": [
      { "path": "main.py", "sha256": "hex-digest", "size": 1234 }
    ]
  }
}
```

### 6.3 Individual file download
`GET /releases/{version}/files/{file_path}` (Bearer)

Response:
- `200` — file bytes with inferred content type.
- `404` — file or version not found.

### 6.4 Whole bundle download
`GET /releases/{version}/bundle` (Bearer)

Response:
- `200` — zip bytes (`application/zip`).
- `404` — version not found.

### 6.5 Device update progress
`POST /update/status` (Bearer)

Request:
```json
{
  "status": "downloading",
  "progress": 40,
  "version": "0.3.0"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `status` | string | Yes | One of: `idle`, `available`, `downloading`, `applying`, `success`, `rollback`, `failed` |
| `progress` | int | No | 0-100, clamped to range, default 0 |
| `version` | string | No | Alternative field name: `target_version` (both accepted) |
| `error` | string | No | Stored as text when status is `failed` or `rollback` |

Response:
```json
{ "ok": true }
```

Error: `422` if `status` is not in the allowed set.

### 6.6 Boot success ack
`POST /boot-ok` (Bearer)

Request:
```json
{ "version": "0.3.0" }
```

Response:
```json
{ "ok": true }
```

Sets update status to `success` with `progress: 100`.

---

## 7) Common firmware behavior rules

- `401` on any bearer endpoint:
  - delete `/token.json`
  - re-enter provision loop
- `429` or `204` with `Retry-After` on command polling:
  - delay using `Retry-After` header value (or fallback backoff)
- Network failures:
  - keep local controls working
  - retry in loop with exponential backoff

---

## 8) Constants reference

| Constant | Env var | Default |
|----------|---------|---------|
| Online window | `DEVICE_ONLINE_WINDOW_SECONDS` | 60 |
| Min poll interval | `DEVICE_MIN_POLL_SECONDS` | 1.0 |
| Provision poll interval | `DEVICE_PROVISION_POLL_MS` | 1000 |
| Max claim failures | `PRINTELLECT_MAX_CLAIM_FAILURES` | 8 |
| Claim failure window | `PRINTELLECT_CLAIM_FAIL_WINDOW_S` | 300 |
