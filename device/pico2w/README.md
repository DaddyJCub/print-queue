# Printellect Pico 2 W Runtime

## Files to copy to Pico

- `boot.py`
- `main.py`
- `lib/` folder
- `/device.json` (from `device.json.example`, with real values)
- optional `/config.json` (from `config.example.json`)

Do not ship with `/wifi.json` or `/token.json`.

## First boot behavior

- If `/wifi.json` is missing, Pico starts AP setup mode:
  - SSID: `PRINTELLECT-SETUP-<last4(device_id)>`
  - setup URL: `http://192.168.4.1/`
- User enters claim code + home Wi-Fi.
- Device reboots, connects to STA, calls `/api/printellect/device/v1/provision`.

## Runtime loops

- Heartbeat every configured interval.
- Command poll every configured interval.
- Posts state and command status transitions.
- On bearer `401`, deletes `/token.json` and re-provisions.

## Reset button mapping

- Hold 10s: delete `/wifi.json` and reboot.
- Hold 20s: delete `/wifi.json` + `/token.json` and reboot.
