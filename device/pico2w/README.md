# Printellect Pico 2 W Runtime

## Files to copy to Pico

- `boot.py`
- `main.py`
- `lib/` folder
- `/device.json` (from `device.json.example`, with real values)
- optional `/config.json` (from `config.example.json`)

Do not ship with `/wifi.json` or `/token.json`.

Set `fw_version` and `app_version` in `config.json` so heartbeat/provision calls report concrete versions.

Optional LED output settings in `config.json`:
- `status_led_pin` (default `"LED"`).
- `status_led_inverted` (default `false`).
- `neopixel_pin` (optional; set to a GPIO number to drive WS2812).
- `neopixel_count` (default `1`).
- `startup_light_effect` (default `"off"`).
- `startup_light_color` (default white RGB object).

Optional local control/audio settings:
- `reset_pin` (default `null`; set if you have a dedicated reset button pin).
- `audio_driver` (`"dfplayer"` or `"pwm"`).
- `dfplayer_enabled` (bool).
- `dfplayer_uart_id`, `dfplayer_tx`, `dfplayer_rx`, `dfplayer_busy`.
- `dfplayer_track_map` (`perk_id` to DFPlayer track number map).
- `speaker_pin` (optional PWM pin for speaker/buzzer when `audio_driver="pwm"`).
- `speaker_default_freq` (default `880`).
- `speaker_test_duration_ms` (default `600`).
- `speaker_track_freqs` (map `track_id -> frequency`).
- `button_active_low` (default `true`).
- `button_debounce_ms` (default `250`).
- `perk_buttons` (list of button pin to perk mapping).

Legacy prototype defaults now supported out of the box:
- NeoPixel on `GP15`
- DFPlayer on `UART0` (`TX=GP0`, `RX=GP1`, `BUSY=GP6`)
- Perk buttons on `GP14`, `GP16`, `GP17`, `GP18`

Legacy config compatibility keys are also recognized:
- LED: `led_pin`, `led_inverted`
- NeoPixel: `rgb_pin`, `rgb_count`, `ws2812_pin`
- Speaker: `speaker_pwm_pin`, `audio_pin`, `buzzer_pin`
- Reset: `reset_button_pin`

## First boot behavior

- If `/wifi.json` is missing, Pico starts AP setup mode:
  - SSID: `PRINTELLECT-SETUP-<last4(device_id)>`
  - setup URL: `http://192.168.4.1/`
- User enters claim code + home Wi-Fi.
- Device reboots, connects to STA, calls `/api/printellect/device/v1/provision`.

## Runtime loops

- Heartbeat every configured interval.
- Command stream long-poll with fallback to command poll.
- Posts state and command status transitions.
- On bearer `401`, deletes `/token.json` and re-provisions.
- Boot/connect/provision states flash status LEDs for visual diagnostics.

## Reset button mapping

- Hold 10s: delete `/wifi.json` and reboot.
- Hold 20s: delete `/wifi.json` + `/token.json` and reboot.
