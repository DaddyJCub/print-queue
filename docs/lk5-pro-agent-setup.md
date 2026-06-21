# LK5 Pro agent — setup guide (Raspberry Pi & Windows)

Step-by-step setup for the print agent that drives a **Longer LK5 Pro** over USB
from a host on a separate network. For the architecture and security model, see
[LK5 Pro agent integration](lk5-pro-agent-integration.md).

The agent runs on either a **Raspberry Pi** (recommended) or the **Windows PC**.
Same code; pick one.

---

## 0. Before you start — the 5 V back-power gotcha

The LK5 Pro mainboard **back-powers the USB port**. When connecting it to a Pi
(or any always-on host), put a small piece of **electrical tape over the 5 V pin**
of the USB‑A connector going to the printer (the pin on one outer edge), so the
printer and the host each stay on their own power. Longer calls this out in their
own docs. The data pins are untouched, so printing/monitoring still work.

Power the Pi from its **own** power supply and the printer from **its own** — never
rely on one back-powering the other.

---

## 1. Register the agent in the app

1. Admin → **🛰️ Print Agents**.
2. **Register a new agent** → name it (e.g. "LK5 Pro – Garage"), printer = Longer LK5 Pro.
3. Copy the **Agent ID** and the one-time **Claim code** (shown once).
4. Note the **Cura ingest token** at the top (for the Cura plugin later).

---

## 2a. Raspberry Pi (recommended)

**Hardware:** Pi 4 (2 GB is plenty) / Pi 3B / Zero 2 W, its official power supply,
a 32 GB microSD, and the USB cable you use today (A → micro‑USB‑B).

1. **Flash the OS.** Use **Raspberry Pi Imager** → *Raspberry Pi OS Lite (64‑bit)*.
   In the gear/⚙ settings, enable **SSH**, set a username/password, and configure
   **Wi‑Fi**.
2. **Boot & SSH in**, then update:
   ```bash
   sudo apt update && sudo apt -y upgrade
   sudo apt -y install python3-pip git
   ```
3. **Serial access** — let the agent open the USB port:
   ```bash
   sudo usermod -aG dialout $USER
   ```
   (log out/in, or reboot, for it to take effect)
4. **Install the agent:**
   ```bash
   git clone <your-repo-url> printqueue
   cd printqueue/agent
   pip install -r requirements.txt --break-system-packages
   cp config.example.json config.json
   ```
5. **Configure** `config.json` — set `server_url`, `agent_id`, `claim_code`.
   Leave `serial_port` as `"auto"` (or run `python3 -m printqueue_agent --list-ports`
   to find it, e.g. `/dev/ttyUSB0`).
6. **Run on boot** as a service:
   ```bash
   sudo cp install/printqueue-agent.service /etc/systemd/system/
   # edit the User/WorkingDirectory paths in that file if needed
   sudo systemctl daemon-reload
   sudo systemctl enable --now printqueue-agent
   sudo systemctl status printqueue-agent     # verify it's running
   ```
7. **(Optional) allow the "Reboot Pi" remote command:**
   ```bash
   echo "$USER ALL=(ALL) NOPASSWD: /sbin/reboot" | sudo tee /etc/sudoers.d/printqueue-agent
   ```
8. **(Optional) firmware flashing** — install avrdude and opt in:
   ```bash
   sudo apt -y install avrdude
   ```
   then set `"firmware": { "enabled": true }` in `config.json` and restart the agent.

The agent should now appear **online** in Print Agents within ~15 s.

## 2b. Windows PC

1. Install **Python 3** (check *Add python.exe to PATH*).
2. In the `agent` folder:
   ```
   py -m pip install -r requirements.txt
   copy config.example.json config.json
   ```
   Edit `config.json` (`server_url`, `agent_id`, `claim_code`). Find the COM port
   with `py -m printqueue_agent --list-ports` or Device Manager.
3. **Run on boot** via Task Scheduler or NSSM — see
   [`agent/install/windows-service.md`](../agent/install/windows-service.md).
4. **Firmware flashing (optional):** install avrdude (bundled with the Arduino
   IDE), set its path in `config.json` `firmware.avrdude_path`, and
   `firmware.enabled: true`.

> While the agent owns the port, **Cura cannot be *connected* to the printer at
> the same time** — you still slice in Cura, but the agent does the printing. The
> agent steps aside automatically if the port is busy.

---

## 3. One-click sending from Cura

Install the **Send to Print Queue** plugin so slicing → sending is one click:

1. Cura → **Help → Show Configuration Folder** → copy the `PrintQueuePlugin`
   folder (from `agent/cura/`) into the `plugins` subfolder.
2. In the copied folder, copy `config.example.json` to `config.json` and set
   `server_url`, the **ingest token** (from Print Agents), and `printer_code`.
3. Restart Cura. Slice, then pick **Send to LK5 Pro** in the print button.

Details: [`agent/cura/PrintQueuePlugin/README.md`](../agent/cura/PrintQueuePlugin/README.md).

---

## 3b. Device page on the Pi + Orca Slicer (ZMOD-style)

The agent also serves a **local device page** right on the Pi — a web UI for
live status, camera, the file list, and full manual control (start/pause/cancel,
temps, jog/home). It's on by default:

```
http://<pi-ip>:7130        (or http://printer.local:7130)
```

Set `local_ui.api_key` in `config.json` if you want to require a key (recommended
if your LAN isn't fully trusted); leave it blank to keep the page open like
Fluidd/Mainsail. You can change the port with `local_ui.port`.

**Send from Orca Slicer** — the agent speaks the **OctoPrint** upload protocol, so
Orca uploads straight to the Pi and can start the print, then you manage it on the
device page:

1. Orca → **Printer settings → Connection** (or the printer's *Physical Printer*
   dialog) → **Host Type: OctoPrint**.
2. **Hostname/IP:** `<pi-ip>:7130`. **API Key:** whatever you set in
   `local_ui.api_key` (any non-empty value if you left it blank).
3. Slice, then **Print** / **Send** — tick *“Upload and print”* to start
   immediately, or just upload and press **Print** on the device page.
4. Open `http://<pi-ip>:7130` to watch/manage it.

> **Single-color note:** unlike the AD5X (which has a material station, hence its
> color-assignment screen), the LK5 Pro is a **single-extruder** printer — there
> are no spools/colors to map, so the device page goes straight from file → print.

## 4. Camera (optional)

Plug a USB webcam into the Pi (auto-detected) or use a Pi Camera Module. Then in
`config.json` set `camera.enabled: true` and either a `snapshot_url`
(e.g. a local `ustreamer`/`mjpg-streamer` at `http://localhost:8080/?action=snapshot`)
or a `device_index` (with `pip install opencv-python`). Frames push out to the app
and appear in the dashboard.

---

## 5. Managing & updating from the app

Once online, everything is in **Print Agents → Manage**:

- **View logs / Identify / Reload config / Restart agent / Reboot Pi.**
- **Update agent** (OTA): build a bundle with `python build_bundle.py`, upload it
  under *Agent software updates*, then click **Update agent**.
- **Flash firmware** (opt-in): upload a Marlin `.hex` under *Printer firmware*,
  then click **Flash firmware**. ⚠️ This can brick the board — only the first
  time, watch it closely.

---

## Troubleshooting

| Symptom | Fix |
|--------|-----|
| Agent shows **offline** | Check `sudo systemctl status printqueue-agent` / logs; confirm `server_url`, `agent_id`, `claim_code`. |
| "Could not open port … in use" | Cura (or OctoPrint) is connected — disconnect it; the agent needs the port. |
| Can't open `/dev/ttyUSB0` (permission denied) | Add the user to `dialout` and re-login. |
| Connects but no temps/progress | Try `baud_rate: 250000` (some community firmware). |
| Pi reboots/brownouts | Use the official PSU; don't power the Pi from the printer (tape the 5 V pin). |
| Flash firmware fails: "avrdude not found" | `sudo apt install avrdude`, or set `firmware.avrdude_path`. |
