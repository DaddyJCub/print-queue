# Printellect Device API (Pico Contract)

Base path: `/api/printellect/device/v1`

All endpoints use JSON unless noted.

## Auth model

- Pre-token only: `POST /provision` (claim code based)
- Bearer required: all other device endpoints
  - Header: `Authorization: Bearer <device_token>`
- Debug contract endpoint (no bearer): `GET /debug`

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
- Too many failed claim attempts: `429` with `detail`.

Firmware rule:
- `unclaimed`: sleep 2-5 seconds and retry.
- `provisioned`: store token, switch to bearer mode.
- `403`: pause and require operator check (wrong label/config).

## 3) Heartbeat

`POST /heartbeat` (Bearer)

Request:
```json
{
  "fw_version": "1.0.0",
  "app_version": "1.0.0",
  "rssi": -55,
  "reset_event": "wifi_reset"
}
```

Response:
```json
{ "ok": true }
```

## 4) Command poll and status

### 3.1 Get next command
`GET /commands/next` (Bearer)

Responses:
- `204` no queued command
- `200` command payload:
```json
{
  "cmd_id": "uuid",
  "action": "play_perk",
  "payload": { "perk_id": "juggernog" },
  "created_at": "2026-02-14T20:10:02Z"
}
```

Rate limit:
- If polled too fast: `429` with `Retry-After`.

### 3.2 Command lifecycle updates
`POST /commands/{cmd_id}/status` (Bearer)

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

Response:
```json
{ "ok": true }
```

## 5) Device state push

`POST /state` (Bearer)

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

## 6) OTA endpoints

### 5.1 Latest release lookup
`GET /releases/latest?channel=stable` (Bearer)

Responses:
- `204` none available
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

### 5.2 Release manifest
`GET /releases/{version}/manifest` (Bearer)

Response:
```json
{
  "version": "0.3.0",
  "manifest": {
    "version": "0.3.0",
    "channel": "stable",
    "files": []
  }
}
```

### 5.3 Individual file download
`GET /releases/{version}/files/{file_path}` (Bearer)

Response:
- File bytes (`200`) with inferred content type.

### 5.4 Whole bundle download
`GET /releases/{version}/bundle` (Bearer)

Response:
- Zip bytes (`200`, `application/zip`)

### 5.5 Device update progress
`POST /update/status` (Bearer)

Request:
```json
{
  "status": "downloading",
  "progress": 40,
  "version": "0.3.0"
}
```

Allowed `status`:
- `idle`, `available`, `downloading`, `applying`, `success`, `rollback`, `failed`

Response:
```json
{ "ok": true }
```

### 5.6 Boot success ack
`POST /boot-ok` (Bearer)

Request:
```json
{ "version": "0.3.0" }
```

Response:
```json
{ "ok": true }
```

## 7) Common firmware behavior rules

- `401` on any bearer endpoint:
  - delete `/token.json`
  - re-enter provision loop
- `429` on command polling:
  - delay using `Retry-After` (or fallback backoff)
- network failures:
  - keep local controls working
  - retry in loop
