# Printellect User API

Feature gate:
- Endpoints in this doc require feature flag `printellect_device_control` for the signed-in account.
- If not assigned, API returns `403`.

## Start pairing session (optional)
`POST /api/printellect/pairing/start`

Auth: logged-in account session.

Response:
```json
{
  "ok": true,
  "session_id": "uuid",
  "expires_at": "2026-02-14T21:30:00Z"
}
```

## Claim device
`POST /api/printellect/pairing/claim`

Auth: logged-in account session.

Request:
```json
{
  "device_id": "perkbase-001",
  "claim_code": "..."
}
```

Response:
```json
{
  "status": "claimed",
  "device_id": "perkbase-001",
  "next": "wait_for_online"
}
```

Optional request field:
- `session_id` (from `/pairing/start`)

## Device list + detail
- `GET /api/printellect/devices`
- `GET /api/printellect/devices/{device_id}`

## Action enqueue endpoints
- `POST /api/printellect/devices/{device_id}/actions/play` `{ "perk": "juggernog" }`
- `POST /api/printellect/devices/{device_id}/actions/stop`
- `POST /api/printellect/devices/{device_id}/actions/idle` `{ "mode": "default" }`
- `POST /api/printellect/devices/{device_id}/actions/brightness` `{ "level": 0-100 }`
- `POST /api/printellect/devices/{device_id}/actions/volume` `{ "level": 0-30 }`
- `POST /api/printellect/devices/{device_id}/actions/test-lights` `{ "pattern": "pulse", "duration_ms": 500 }`
- `POST /api/printellect/devices/{device_id}/actions/test-audio` `{ "track_id": "..." }`
- `POST /api/printellect/devices/{device_id}/actions/reboot`
- `POST /api/printellect/devices/{device_id}/actions/update` `{ "version": "latest" }`

Notes:
- Actions reject when device is offline.
- `play` rejects if current state is already `playing=true`.
