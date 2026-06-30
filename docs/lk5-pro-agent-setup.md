# LK5 Pro agent — setup guide (Raspberry Pi & Windows)

Step-by-step setup for the print agent that drives a **Longer LK5 Pro** over USB
from a host on a separate network. For the architecture and security model, see
[LK5 Pro agent integration](lk5-pro-agent-integration.md).

The agent runs on either a **Raspberry Pi** (recommended) or the **Windows PC**.
Same code; pick one.

> **⚡ Fastest path — the Guided setup wizard.** On the **Print Agents** admin page,
> click **🧭 Guided setup**. It creates the agent, fills in your `config.json`, and
> gives you a **single copy-paste install command** for the Pi (it downloads the
> agent, writes the config, and starts the service for you), plus the exact Orca
> settings — then watches for the agent to come online. The manual steps below are
> the reference if you'd rather do it by hand or need to customise.

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

## 1b. Network access (how the agent reaches the server)

The agent only makes **outbound** calls, so no inbound ports are ever needed.
Pick whichever path matches your network — the wizard's *"How does the agent reach
the server?"* choice maps to these:

### Option A (simplest) — through your router / pfSense subnet router

If you already run **Tailscale on pfSense** as a subnet router, the agent needs
**nothing installed**. Requirements:

1. pfSense advertises a route to the server's network into the tailnet
   (`--advertise-routes`), approved in Headscale. If the server is a pure tailnet
   host, advertise `100.64.0.0/10`.
2. The agent's host uses pfSense as its gateway (normal on a home LAN).
3. Set `server_url` to an address reachable through that route (the server's LAN
   IP, its Tailscale `100.x`, or a DNS name).

That's it — slimmest footprint on the Pi.

### Option B — install Tailscale on the agent itself

If the agent can't route to the server via your router, join it to the tailnet
directly:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --login-server https://headscale.jcubhub.com --hostname pq-<name>
#   add --authkey <KEY> for an unattended join (generate it on Headscale:
#   `headscale preauthkeys create --user <user> --reusable --expiration 24h`)
```

Without a key, `tailscale up` prints a URL — approve the node in Headscale, then
continue. The agent's tailnet address (`tailscale ip -4`) is also how you'd reach
its device page (`http://<tailscale-ip>:7130`) from other tailnet devices.

> The **Guided setup wizard** handles both: pick *Through my network / router*
> (nothing to install) or *Install Tailscale on the agent* and the generated
> install command does the right thing.

## 2a. Raspberry Pi (recommended)

**Hardware:** Pi 4 (2 GB is plenty) / Pi 3B / Zero 2 W, its official power supply,
a 32 GB microSD, and the USB cable you use today (A → micro‑USB‑B).

1. **Flash the OS.** Use **Raspberry Pi Imager** → *Raspberry Pi OS Lite (64‑bit)*.
   In the gear/⚙ settings, enable **SSH**, set a username/password, and configure
   **Wi‑Fi**.
2. **Boot & SSH in**, then update:
   ```bash
   sudo apt update && sudo apt -y upgrade
   sudo apt -y install python3-venv python3-pip curl
   ```
3. **Serial access** — let the agent open the USB port:
   ```bash
   sudo usermod -aG dialout $USER
   ```
   (log out/in, or reboot, for it to take effect)
4. **Install the agent** into an isolated virtualenv (download the source from
   your server — `‹TOKEN›` is the Cura ingest token on the Print Agents page):
   ```bash
   mkdir -p ~/printqueue && cd ~/printqueue
   curl -fL --retry 3 -o agent.tgz "https://print.jcubhub.com/api/printer-agent/v1/agent-package.tar.gz?token=<TOKEN>"
   tar xzf agent.tgz && rm -f agent.tgz && cd agent
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   cp config.example.json config.json
   ```
   > Using a **venv** avoids the bare-`pip`/`--break-system-packages` pitfalls on
   > Pi OS and guarantees the service finds its dependencies.
5. **Configure** `config.json` — set `server_url`, `agent_id`, `claim_code`.
   Leave `serial_port` as `"auto"` (or run `.venv/bin/python -m printqueue_agent --list-ports`
   to find it, e.g. `/dev/ttyUSB0`).
6. **Run on boot** as a service (note `ExecStart` uses the **venv** Python):
   ```bash
   INSTALL_DIR="$PWD"
   sudo tee /etc/systemd/system/printqueue-agent.service >/dev/null <<UNIT
   [Unit]
   Description=Print Queue Printer Agent
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=$USER
   WorkingDirectory=$INSTALL_DIR
   ExecStart=$INSTALL_DIR/.venv/bin/python -m printqueue_agent --config $INSTALL_DIR/config.json
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   UNIT
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
