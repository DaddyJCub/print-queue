# Printellect Pico Deploy (Legacy `/current` Layout)

This folder is a ready-to-upload firmware layout for devices that use:
- root `/boot.py` + root `/main.py` shims
- app code in `/current`
- libs in `/current/lib`

It does **not** include `device.json`, `wifi.json`, or `token.json` so you do not accidentally overwrite identity/Wi-Fi auth.

## Exact on-device layout after upload

```
/boot.py
/main.py
/current/main.py
/current/lib/__init__.py
/current/lib/api_client.py
/current/lib/command_runner.py
/current/lib/file_store.py
/current/lib/hardware.py
/current/lib/ota_manager.py
/current/lib/reset_controller.py
/current/lib/setup_portal.py
/current/lib/versioning.py
/current/lib/wifi_manager.py
```

Plus your existing root files:
- `/device.json`
- `/wifi.json`
- `/token.json`
- `/app_state.json`

## LED behavior

- Boot: blue status flashes.
- Wi-Fi connect attempt: amber flashes.
- Wi-Fi connect success: green flashes.
- Wi-Fi connect failure: red flashes.
- AP setup mode: purple flashes.
- Provisioning loop: cyan flash.

Optional `config.json` fields:
- `reset_pin` (default `null`)
- `status_led_pin` (default `"LED"`)
- `status_led_inverted` (default `false`)
- `neopixel_pin` (default `15`)
- `neopixel_count` (default `28`)
- `startup_light_effect` (default `"off"`)
- `startup_light_color` (default white RGB)
- `audio_driver` (`dfplayer` or `pwm`)
- `dfplayer_enabled` (bool)
- `dfplayer_uart_id`, `dfplayer_tx`, `dfplayer_rx`, `dfplayer_busy`
- `dfplayer_track_map` (`perk_id` to track number)
- `speaker_pin` (optional PWM pin when `audio_driver="pwm"`)
- `speaker_default_freq` (default `880`)
- `speaker_test_duration_ms` (default `600`)
- `speaker_track_freqs` (`track_id` to frequency map)
- `button_active_low` (default `true`)
- `button_debounce_ms` (default `250`)
- `perk_buttons` (button pin to perk mapping)

For your legacy working hardware map, use:
- [config.from-backup.json](config.from-backup.json) -> copy to Pico as `/config.json`

This applies:
- NeoPixel `GP15`
- DFPlayer `UART0` (`TX=GP0`, `RX=GP1`, `BUSY=GP6`)
- Perk buttons `GP14`, `GP16`, `GP17`, `GP18`
- No dedicated reset GPIO (`reset_pin: null`)

## Preserve setup before flashing UF2

If you can still access the board in Thonny, back up these root files to your PC first:
- `/device.json`
- `/wifi.json`
- `/token.json`
- `/app_state.json`

If you cannot access REPL/filesystem, a UF2 reflash may wipe these files and you will need to re-enter Wi-Fi and re-provision.

## UF2 flash steps (Pico 2 W)

1. Unplug Pico.
2. Hold `BOOTSEL`, plug USB in, release `BOOTSEL`.
3. Pico mounts as `RPI-RP2`.
4. Copy the **Pico 2 W MicroPython UF2** onto `RPI-RP2`.
5. Wait for auto reboot.

## Upload firmware files (Thonny)

1. Connect Thonny to the Pico interpreter.
2. On device, create directories:
   - `/current`
   - `/current/lib`
3. Upload files from this folder to matching device paths.
4. Restore your backed-up root identity files if needed:
   - `/device.json`, `/wifi.json`, `/token.json`, `/app_state.json`
5. In shell, clear stale OTA pending state and reboot:

```python
import json, machine
try:
    st = json.load(open("/app_state.json", "r"))
except:
    st = {}
st.pop("pending_version", None)
st["boot_fail_count"] = 0
json.dump(st, open("/app_state.json", "w"))
machine.reset()
```
