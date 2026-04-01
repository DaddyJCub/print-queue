# Firmware Development Workflow

> See also: [Flashing Guide](printellect-flashing-guide.md) · [Device API](printellect-device-api.md) · [Docs Index](README.md)

Printellect device firmware lives in `device/pico2w/` alongside the server application. This means firmware changes are part of the normal app development cycle — committed, reviewed, and deployed through the same repo.

---

## Source layout

```
device/pico2w/
├── boot.py                    # Minimal boot hook (keep small and stable)
├── main.py                    # Main runtime state machine
├── lib/
│   ├── api_client.py          # Server API communication
│   ├── command_runner.py      # Command execution logic
│   ├── file_store.py          # Persistent file storage helpers
│   ├── hardware.py            # LED, speaker, button hardware abstraction
│   ├── ota_manager.py         # OTA download, staging, rollback
│   ├── reset_controller.py    # Reset button (10s/20s/triple press)
│   ├── setup_portal.py        # Wi-Fi AP setup portal
│   └── wifi_manager.py        # Wi-Fi STA connection management
├── device.json.example        # Template for device identity
└── config.example.json        # Template for optional config overrides
```

---

## Development cycle

### 1. Edit firmware source

Make changes directly in `device/pico2w/`. These files are normal repo files — commit and PR them like any other code.

### 2. Test locally on a Pico

For rapid iteration, copy changed files directly to a connected Pico:

```bash
# Using mpremote (fastest for single-file changes):
mpremote connect auto cp device/pico2w/lib/command_runner.py :lib/command_runner.py
mpremote connect auto reset

# Using rshell:
rshell -p /dev/ttyACM0 cp device/pico2w/lib/command_runner.py /pyboard/lib/command_runner.py
```

Use Thonny's REPL to see print output and debug errors in real time.

### 3. Build a release

Once changes are committed, build a firmware release from the admin panel or API:

**Admin UI:** Go to `/admin/printellect/releases` → click **Build from Source**.

**API:**
```bash
curl -X POST https://print.jcubhub.com/api/printellect/admin/releases/build \
  -H "Cookie: admin_session=..." \
  -H "Content-Type: application/json" \
  -d '{"channel": "beta", "notes": "Added volume control fix"}'
```

This packages `device/pico2w/` (excluding example files, `__pycache__`, etc.) into a versioned release with SHA256 checksums. Version auto-increments from the latest release.

### 4. Test via OTA

Promote the release to the beta channel and push to a test device:

```bash
# Promote
curl -X POST .../api/printellect/admin/releases/0.2.0/promote \
  -d '{"channel": "beta"}'

# Push to specific test device
curl -X POST .../api/printellect/admin/releases/0.2.0/push \
  -d '{"device_ids": ["perkbase-test-001"]}'
```

Or use the admin UI at `/admin/printellect/releases` and `/admin/printellect/ota-status` to promote, push, and monitor.

### 5. Roll out to production

Once validated on beta:

```bash
# Promote to stable
curl -X POST .../api/printellect/admin/releases/0.2.0/promote \
  -d '{"channel": "stable"}'

# Push to all devices
curl -X POST .../api/printellect/admin/releases/0.2.0/push
```

---

## OTA safety model

Firmware updates are protected by a multi-layer safety system:

1. **SHA256 verification** — every file is hash-checked during download.
2. **Staged rollout** — files download to `/next`, then rotate: `/current → /prev`, `/next → /current`.
3. **Boot guard** — tracks boot failures. After 3 consecutive failed boots, auto-rolls back to `/prev`.
4. **Boot confirmation** — device calls `POST /boot-ok` after successful startup to confirm the update.
5. **Version consistency check** — backend rejects mismatched boot/update success versions (`409`) and marks OTA as failed.
5. **Progress reporting** — device reports download/apply progress to the server in real-time.
6. **Admin monitoring** — OTA status dashboard at `/admin/printellect/ota-status` shows per-device progress.

If an OTA update bricks a device, [wired recovery](printellect-flashing-guide.md#wired-recovery) is always available as a fallback.

---

## File persistence on device

| File | Created by | Survives Wi-Fi reset | Survives factory reset |
|------|-----------|---------------------|----------------------|
| `/device.json` | Manufacturing (manual) | Yes | Yes |
| `/wifi.json` | Setup portal | **No** | **No** |
| `/token.json` | Provision endpoint | Yes | **No** |
| `/app_state.json` | Runtime | Yes | Yes |
| `/config.json` | Manufacturing (optional) | Yes | Yes |
| `/current/` | OTA update | Yes | Yes |
| `/prev/` | OTA update | Yes | Yes |

---

## Key implementation notes

- **State machine**: `main.py` runs a loop: `BOOT → TRY_STA_CONNECT → START_AP_SETUP → BACKEND_PROVISION_OR_RUN → NORMAL_RUN`.
- **All API calls** go through `lib/api_client.py` which handles bearer auth and base URL config.
- Firmware reports versions from `/config.json` (`fw_version`, `app_version`) and OTA runtime state (`pending_version`/`last_good_version`).
- **Hybrid command delivery**: firmware prefers `/commands/stream` long-poll and falls back to `/commands/next` if stream is unavailable.
- **Reset button** is handled by `lib/reset_controller.py`: 10s hold = Wi-Fi reset, 20s hold = factory reset, triple press = soft reboot.
- **OTA manager** (`lib/ota_manager.py`) handles the full download → stage → rotate → boot-guard → rollback cycle.
- **Setup portal** (`lib/setup_portal.py`) serves a local web page on `192.168.4.1` for Wi-Fi config + claim code validation.
