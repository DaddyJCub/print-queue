# Printellect Admin API

> See also: [Device API](printellect-device-api.md) · [User API](printellect-user-api.md) · [Device Control Roadmap](printellect-device-control-roadmap.md) · [Docs Index](README.md)

All endpoints require admin authentication via `require_admin()` — admin session cookie or unified account with admin role.

Base paths:
- API: `/api/printellect/admin/`
- HTML pages: `/admin/printellect/`

All timestamps are ISO 8601 UTC.

---

## Error response format

```json
{ "detail": "Human-readable error message" }
```

| Code | Meaning |
|------|---------|
| `401` | Admin login required |
| `404` | Resource not found |
| `409` | Conflict (duplicate device, release is current, claimed device) |
| `422` | Validation error |
| `500` | Server error (e.g. missing source directory) |
| `503` | Service unavailable (e.g. QR library missing) |

---

## Device management

### Create device
`POST /api/printellect/admin/devices`

All request fields are **optional** — device ID and claim code auto-generate if omitted:

```json
{
  "device_id": "perkbase-001",
  "name": "Living Room Base",
  "claim_code": "custom-claim-code"
}
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `device_id` | string | Auto: `perkbase-XXXX` | Must be unique, lowercased |
| `name` | string | Same as `device_id` | Display name |
| `claim_code` | string | Auto: 16-char URL-safe token | Printed on device label |

Response (`200`):
```json
{
  "ok": true,
  "device": {
    "device_id": "perkbase-001",
    "name": "Living Room Base",
    "claim_code": "abc123def456ghij",
    "qr_payload": "printellect://pair?d=perkbase-001&c=abc123def456ghij&n=Living+Room+Base",
    "fallback_url": "https://print.jcubhub.com/pair?device_id=perkbase-001&claim=abc123def456ghij",
    "device_json": {
      "device_id": "perkbase-001",
      "claim_code": "abc123def456ghij",
      "hw_model": "pico2w"
    }
  }
}
```

The `claim_code` is **only returned on creation** — it is hashed for storage.
The `device_json` object is the exact content to write to the device's `/device.json` file.

Errors: `409` if `device_id` already exists.

Audit: `printellect_device_created`

---

### List all devices
`GET /api/printellect/admin/devices`

Response (`200`):
```json
{
  "ok": true,
  "devices": [
    {
      "device_id": "perkbase-001",
      "name": "Living Room Base",
      "owner_user_id": "user-uuid-or-null",
      "claimed": true,
      "created_at": "2026-03-20T12:00:00Z",
      "claimed_at": "2026-03-21T08:00:00Z",
      "last_seen_at": "2026-03-22T10:30:00Z",
      "online": true,
      "fw_version": "1.0.0",
      "app_version": "1.0.0",
      "rssi": -55,
      "notes": "Test unit #1",
      "state": {},
      "update": {
        "status": "idle",
        "target_version": null,
        "progress": 0,
        "last_error": null,
        "result": {}
      }
    }
  ]
}
```

Ordered by `created_at` descending.

---

### Update device
`PATCH /api/printellect/admin/devices/{device_id}`

At least one field required:
```json
{
  "name": "New Name",
  "notes": "Internal testing unit",
  "owner_user_id": "user-uuid"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `name` | string | Max 64 chars |
| `notes` | string or null | Set to `null` to clear |
| `owner_user_id` | string or null | Set to `null` to unassign; validated against accounts table |

Changing `owner_user_id` revokes all existing device tokens.

Response: same device object as in list endpoint. `200` on success.

Errors: `404` not found, `422` no valid fields or invalid `owner_user_id`.

Audit: `printellect_device_updated`

---

### Rotate claim code
`POST /api/printellect/admin/devices/{device_id}/claim-code/rotate`

No request body.

Response (`200`):
```json
{
  "ok": true,
  "device_id": "perkbase-001",
  "claim_code": "new-random-token",
  "qr_payload": "printellect://pair?d=perkbase-001&c=new-random-token&n=...",
  "fallback_url": "https://print.jcubhub.com/pair?...",
  "device_json": {
    "device_id": "perkbase-001",
    "claim_code": "new-random-token",
    "hw_model": "pico2w"
  }
}
```

The old claim code is invalidated immediately. The new claim code is returned once.

Errors: `404` not found.

Audit: `printellect_claim_code_rotated`

---

### Download device support bundle
`GET /api/printellect/admin/devices/{device_id}/support-bundle`

Returns `application/zip` with structured troubleshooting artifacts (`summary.json`, command/state snapshots).

Use this when OTA or diagnostics fail and you need reproducible evidence without direct device shell access.

---

### Unclaim device
`POST /api/printellect/admin/devices/{device_id}/unclaim`

No request body.

Clears owner, revokes all device tokens, and returns device to factory-ready state.

Response (`200`):
```json
{
  "ok": true,
  "device": { "...same shape as list..." }
}
```

Errors: `404` not found.

Audit: `printellect_device_unclaimed` (includes `previous_owner`)

---

### Delete device
`DELETE /api/printellect/admin/devices/{device_id}`

Query params:
- `force=1` — required to delete a claimed device.

Response (`200`):
```json
{
  "ok": true,
  "deleted_device_id": "perkbase-001"
}
```

Cascade-deletes: device tokens, commands, device state, update status.

Errors: `404` not found, `409` device is claimed and `force` not set.

Audit: `printellect_device_deleted`

---

## Release management

### Build from source
`POST /api/printellect/admin/releases/build`

Packages `device/pico2w/` source into a versioned firmware release. This is the primary workflow — firmware files live in the repo alongside the app, and this endpoint builds them into a deployable release.

```json
{
  "channel": "stable",
  "notes": "Added volume control fix",
  "entrypoint": "main.py"
}
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `channel` | string | `"stable"` | `"stable"` or `"beta"` |
| `notes` | string | — | Release notes |
| `entrypoint` | string | `"main.py"` | MicroPython entry point |

Auto-versioning: increments minor version from latest release (e.g. `0.1.0` → `0.2.0`).

Files excluded from build: `__pycache__`, `.git`, `.DS_Store`, `*.example*`, `README.md`, `device.json.example`, `config.example.json`.

Response (`200`):
```json
{
  "ok": true,
  "version": "0.2.0",
  "channel": "stable",
  "bundle_sha256": "hex-digest",
  "mode": "build",
  "file_count": 10,
  "safety": {
    "schema_version": 1,
    "entrypoint": "main.py",
    "required_paths": ["main.py", "lib/api_client.py"],
    "supports_layouts": ["legacy-current", "current-rooted"]
  }
}
```

Errors: `422` invalid channel or no firmware files found, `500` device source directory missing.

Audit: `printellect_release_uploaded` (mode: `build`)

---

### Upload release
`POST /api/printellect/admin/releases/upload`

Multipart form upload. Two modes (mutually exclusive):

**Mode A — Package zip** (preferred): single `package` file (zip with optional embedded `manifest.json`).

**Mode B — Legacy**: separate `manifest` (JSON file) + `bundle` (zip file).

Form fields:
| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `version` | string | From manifest | Semantic version |
| `channel` | string | `"stable"` | `"stable"` or `"beta"` |
| `entrypoint` | string | `"main.py"` | Entry point |
| `notes` | string | — | Release notes |

Response: same shape as build endpoint with `mode: "package"` or `"manifest_bundle"`.

Safety metadata:
- Server ensures `manifest.safety` exists and validates `required_paths` against bundle contents.
- Firmware uses this metadata during OTA preflight and post-apply verification.

Errors: `422` on invalid input (missing files, empty bundle, bad JSON, hash mismatch).

Audit: `printellect_release_uploaded`

---

### List all releases
`GET /api/printellect/admin/releases`

Response (`200`):
```json
{
  "ok": true,
  "releases": [
    {
      "version": "0.2.0",
      "channel": "stable",
      "created_at": "2026-03-22T10:00:00Z",
      "created_by_user_id": "admin-id",
      "notes": "Added volume fix",
      "is_current": true,
      "manifest": {
        "version": "0.2.0",
        "channel": "stable",
        "entrypoint": "main.py",
        "bundle_sha256": "hex-digest",
        "bundle_size": 9803,
        "files": [
          { "path": "main.py", "sha256": "hex-digest", "size": 1234 }
        ]
      }
    }
  ]
}
```

Ordered by `created_at` descending.

---

### Promote release
`POST /api/printellect/admin/releases/{version}/promote`

Makes the specified release current for a channel. Demotes any previous current release in that channel.

```json
{
  "channel": "stable"
}
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `channel` | string | Release's current channel | `"stable"` or `"beta"` |

Response (`200`):
```json
{
  "ok": true,
  "version": "0.2.0",
  "channel": "stable",
  "is_current": true
}
```

Errors: `404` release not found, `422` invalid channel.

Audit: `printellect_release_promoted`

---

### Push OTA to devices
`POST /api/printellect/admin/releases/{version}/push`

Enqueues `ota_apply` commands to devices. Devices receive the update via their next command poll.

```json
{
  "mode": "canary",
  "limit": 1,
  "online_only": true
}
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `device_ids` | array of strings | All claimed devices | Optional — filter to specific devices |
| `mode` | string | `"all"` | `"all"` or `"canary"` |
| `limit` | integer | `0` (`all`) / `1` (`canary`) | Max devices to enqueue |
| `online_only` | boolean | `false` (`all`) / `true` (`canary`) | Restrict selection to currently online devices |

Response (`200`):
```json
{
  "ok": true,
  "version": "0.2.0",
  "mode": "canary",
  "online_only": true,
  "devices_pushed": 1,
  "device_ids": ["perkbase-001"]
}
```

Each target device gets:
1. A queued `ota_apply` command with `payload: { "version": "0.2.0" }`.
2. Update status set to `available` with `progress: 0`.

Errors: `404` release not found.

Audit: `printellect_release_pushed`

---

### Delete release
`DELETE /api/printellect/admin/releases/{version}`

Removes a release from the database and disk.

Response (`200`):
```json
{
  "ok": true,
  "version": "0.2.0",
  "deleted": true
}
```

Errors: `404` not found, `409` release is currently active (`is_current = 1`) — demote first.

Audit: `printellect_release_deleted`

---

### OTA update status dashboard
`GET /api/printellect/admin/update-status`

Response (`200`):
```json
{
  "ok": true,
  "devices": [
    {
      "device_id": "perkbase-001",
      "name": "Living Room Base",
      "owner_user_id": "user-uuid",
      "fw_version": "fw-1.0.0",
      "app_version": "0.2.0",
      "target_version": "0.2.0",
      "status": "downloading",
      "progress": 40,
      "last_error": null,
      "result": { "stage": "preflight", "checks": { "required_paths_ok": true } },
      "updated_at": "2026-03-22T10:35:00Z"
    }
  ]
}
```

Ordered by `device_id`.

`status = failed` may include version mismatch enforcement errors when the device-reported version differs from the OTA target.

---

### Generate QR code
`GET /api/printellect/admin/qr.svg?payload=...`

| Param | Type | Notes |
|-------|------|-------|
| `payload` | string (query) | QR content, max 1024 chars |

Response: `image/svg+xml` body.

Errors: `422` invalid payload, `503` QR library unavailable.

---

## Admin HTML pages

| Path | Description |
|------|-------------|
| `GET /admin/printellect/devices` | Device registry and management UI |
| `GET /admin/printellect/releases` | Firmware release management UI |
| `GET /admin/printellect/ota-status` | Per-device OTA progress dashboard |
