# Flashing a New Printellect Pico 2W

> See also: [Setup My Printellect Base](setup-my-printellect-base.md) · [OTA & Recovery](printellect-ota-and-recovery.md) · [Docs Index](README.md)

This guide covers going from a blank Raspberry Pi Pico 2W to a working Printellect device.

---

## Prerequisites

**Hardware:**
- Raspberry Pi Pico 2W
- USB micro-B cable (data-capable, not charge-only)
- Computer (Windows, macOS, or Linux)

**Software (install one):**
- [Thonny IDE](https://thonny.org/) — recommended for beginners (built-in MicroPython installer + file manager)
- [rshell](https://github.com/dhylands/rshell) — command-line tool (`pip install rshell`)
- [mpremote](https://docs.micropython.org/en/latest/reference/mpremote.html) — official MicroPython tool (`pip install mpremote`)

**From the admin panel:**
- A pre-registered device with `device_id` and `claim_code` (created via admin at `/admin/printellect/devices` or `POST /api/printellect/admin/devices`)

---

## Step 1: Flash MicroPython firmware

1. Download the latest MicroPython UF2 for **Pico 2W** from:
   https://micropython.org/download/RPI_PICO2W/

2. Hold the **BOOTSEL** button on the Pico and connect the USB cable to your computer.

3. The Pico appears as a USB drive named `RPI-RP2`.

4. Drag and drop the `.uf2` file onto the `RPI-RP2` drive.

5. The Pico reboots automatically. The USB drive disappears — this is normal.

---

## Step 2: Copy firmware files

The firmware source lives in `device/pico2w/` in the repo. Copy these files to the Pico's filesystem:

```
device/pico2w/boot.py       →  /boot.py
device/pico2w/main.py       →  /main.py
device/pico2w/lib/           →  /lib/
```

The `lib/` directory contains:
- `api_client.py` — server communication
- `command_runner.py` — command execution
- `file_store.py` — persistent file storage
- `hardware.py` — LED/speaker/button control
- `ota_manager.py` — over-the-air updates
- `reset_controller.py` — reset button handling
- `setup_portal.py` — Wi-Fi setup AP
- `wifi_manager.py` — Wi-Fi connection

### Using Thonny

1. Open Thonny → **Run** → **Configure interpreter** → select **MicroPython (Raspberry Pi Pico)** and the correct port.
2. In the file browser (View → Files), navigate to `device/pico2w/` on your computer.
3. Right-click each file/folder → **Upload to /**.

### Using rshell

```bash
rshell -p /dev/ttyACM0   # Linux — use /dev/tty.usbmodem* on macOS, COM3 on Windows

# Inside rshell:
cp device/pico2w/boot.py /pyboard/boot.py
cp device/pico2w/main.py /pyboard/main.py
mkdir /pyboard/lib
cp device/pico2w/lib/*.py /pyboard/lib/
```

### Using mpremote

```bash
mpremote connect auto cp device/pico2w/boot.py :boot.py
mpremote connect auto cp device/pico2w/main.py :main.py
mpremote connect auto mkdir :lib
mpremote connect auto cp device/pico2w/lib/*.py :lib/
```

---

## Step 3: Write device identity

Create `/device.json` on the Pico with the device's registered identity. Get the `device_id` and `claim_code` from the admin panel (shown once when the device is created) or from a printed label.

```json
{
  "device_id": "perkbase-001",
  "claim_code": "replace-with-actual-claim-code",
  "hw_model": "pico2w"
}
```

Using Thonny: create a new file, paste the JSON, save as `device.json` on the Pico.

Using rshell:
```bash
# Create the file locally, then copy:
cp device.json /pyboard/device.json
```

### Optional: config override

For non-default server URLs or timing tweaks, create `/config.json`:

```json
{
  "api_base": "https://print.jcubhub.com",
  "heartbeat_interval_s": 20,
  "command_poll_interval_s": 1,
  "provision_poll_interval_s": 3,
  "sta_connect_timeout_s": 10,
  "sta_connect_retries": 3,
  "wifi_reset_hold_s": 10,
  "factory_reset_hold_s": 20
}
```

Only include fields you want to override. All fields are optional.

---

## Step 4: Important — do NOT include these files

The device should ship with **no** pre-existing:
- `/wifi.json` — created by the setup portal when the user enters Wi-Fi credentials
- `/token.json` — created automatically during provisioning after claim

If either file exists from testing, delete them before handing off the device.

---

## Step 5: First boot

1. Disconnect and reconnect the Pico (or press the reset button).
2. The device enters **AP setup mode** because `/wifi.json` is missing.
3. An access point appears: `PRINTELLECT-SETUP-xxxx` (where `xxxx` is the last 4 chars of `device_id`).

Continue with the [end-user setup guide](setup-my-printellect-base.md) from here.

---

## Verification checklist

After completing setup and claiming the device:

- [ ] AP SSID `PRINTELLECT-SETUP-xxxx` appears within 30 seconds of power-on
- [ ] Setup portal loads at `http://192.168.4.1/`
- [ ] Wi-Fi credentials save and device reboots
- [ ] Device connects to home Wi-Fi
- [ ] Device appears online in the Printellect app
- [ ] Can send a command (e.g. play, volume) and device responds
- [ ] Reset hold 10s: Wi-Fi clears, AP reappears
- [ ] Reset hold 20s: Wi-Fi + token clear, device returns to unclaimed state
- [ ] Triple press: soft reboot, no settings lost

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Pico doesn't appear as USB drive | Use a data-capable USB cable (not charge-only). Try a different USB port. |
| UF2 file doesn't copy | Ensure BOOTSEL was held *before* plugging in. Re-try. |
| Thonny can't find the Pico | Check the port in **Run → Configure interpreter**. On Linux, you may need `sudo usermod -aG dialout $USER` then log out/in. |
| rshell `No MicroPython boards connected` | Check port name: `ls /dev/tty*` (Linux/Mac) or Device Manager (Windows). |
| AP doesn't appear after boot | Verify `boot.py`, `main.py`, and `lib/` were all copied. Check for errors via Thonny REPL. |
| Setup portal won't load | Wait 10-15 seconds after joining the AP Wi-Fi. Try `http://192.168.4.1/` (not https). |
| Device stays "offline" after Wi-Fi setup | Verify Wi-Fi SSID and password are correct. Check that the server URL in `/config.json` is reachable. |
| Claim code rejected | Verify the claim code matches exactly. Check if it was rotated in the admin panel. |

---

## Wired recovery

If a device becomes unresponsive or OTA leaves it in a bad state:

1. Hold **BOOTSEL** and connect USB.
2. Drag/drop the MicroPython UF2 onto the `RPI-RP2` drive.
3. Re-copy firmware files (Step 2).
4. Restore `/device.json` (Step 3) — use the same `device_id` and `claim_code`.
5. If the device was previously claimed and you didn't factory-reset, the existing `/token.json` may still work. Otherwise, re-claim through the app.
