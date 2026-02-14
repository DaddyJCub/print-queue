# Printellect OTA and Recovery

## OTA model
- Backend stores app releases with `manifest_json` and `bundle_path`.
- Device checks `/api/printellect/device/v1/releases/latest`.
- Device downloads manifest-listed files from `/api/printellect/device/v1/releases/{version}/files/{path}`.
- Device reports progress via `/api/printellect/device/v1/update/status`.
- Device stages update in `/next`, rotates `/current -> /prev`, then reboots.

## Safety
- Keep one previous app bundle for rollback.
- Confirm healthy boot with `/api/printellect/device/v1/boot-ok`.
- Boot-failure counter and rollback trigger logic should call `rollback_to_previous()` and report `rollback` after 3 failed boots.

## Wired recovery (guaranteed path)
1. Hold BOOTSEL and connect USB.
2. Drag/drop MicroPython UF2.
3. Restore `/device.json` and run setup flow.
4. Reconnect Wi-Fi and re-claim if token was factory-reset.
