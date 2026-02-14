# Printellect Pico State Machine

## Persistent files
- `/device.json` (never deleted): `device_id`, `claim_code`, `hw_model`
- `/wifi.json` (deleted by Wi-Fi reset)
- `/token.json` (deleted by factory reset/unpair)
- `/app_state.json` (ring buffer + runtime metadata)

## States
- `BOOT`
- `TRY_STA_CONNECT`
- `START_AP_SETUP`
- `BACKEND_PROVISION_OR_RUN`
- `NORMAL_RUN`

### Flow
1. Boot reads device/wifi/token files.
2. If Wi-Fi missing or connect fails, start AP setup (`PRINTELLECT-SETUP-xxxx`) and serve `http://192.168.4.1/`.
3. Setup page requires local claim code before writing Wi-Fi.
4. Once connected to internet:
   - If no token: call `/device/v1/provision` until claimed+provisioned.
   - With token: heartbeat + command poll + state updates.
   - If `/app_state.json` has `pending_version`, call `/device/v1/boot-ok` and clear pending on success.
5. If device API returns `401`, delete token and return to provision state.
6. On boot, if `pending_version` exists, increment boot fail count and roll back after N failures.

## Reset hold behavior
- Hold 0-7s: slow blink
- Hold 7-10s: fast blink
- Commit at 10s: Wi-Fi reset (`/wifi.json` delete)
- Hold 10-15s: alternate blink
- Hold 15-20s: very fast alternate blink
- Commit at 20s: factory reset (`/wifi.json` + `/token.json` delete)
- Triple press within 3s: soft reboot (no deletes)

After commit, reboot into AP setup mode.
