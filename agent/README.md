# Print Queue Printer Agent

A small, cross-platform agent that lets the print-queue drive a **USB Marlin
printer** (e.g. **Longer LK5 Pro**) that lives on a **separate network** from the
print-queue server — securely, with no inbound ports.

It runs on a **Raspberry Pi** *or* a **Windows PC** (same code). See
[`docs/lk5-pro-agent-integration.md`](../docs/lk5-pro-agent-integration.md) for
the architecture and security model.

## How it works

```
Cura (slice)  ──upload .gcode──▶  Print Queue server  ◀──poll jobs / push status & camera──  Agent ──USB──▶  LK5 Pro
```

1. You slice in Cura as usual, then click **Send to LK5 Pro** (added by the Cura
   plugin — sits next to Cura's Save/Print button). One click; no file export.
2. That uploads the gcode and queues it in a single call.
3. The agent (next to the printer) claims the job, **uploads the gcode to the
   printer's SD card**, and **starts an SD print**.
4. The printer then prints **autonomously** — the host PC/Pi can even power off.
   The agent keeps reporting live status + camera while connected.

The agent only makes **outbound** HTTPS calls, so the printer's network needs no
inbound ports or port-forwarding. The channel is authenticated with a per-agent
bearer token over TLS.

## Quick start

1. **Register the agent** in the print-queue admin panel
   (`Admin > Printer Agents > New`). Copy the `agent_id` and one-time
   `claim_code`.
2. **Install** on the Pi or PC:
   ```
   pip install -r requirements.txt
   cp config.example.json config.json   # then edit it
   ```
3. **Configure** `config.json`: set `server_url`, `agent_id`, `claim_code`, and
   the `serial_port` (or leave `"auto"`).
4. **Run**:
   ```
   python -m printqueue_agent --config config.json
   ```
   List serial ports with `python -m printqueue_agent --list-ports`.
5. **Run on boot**: Raspberry Pi → [`install/printqueue-agent.service`](install/printqueue-agent.service);
   Windows → [`install/windows-service.md`](install/windows-service.md).

## Camera (optional)

Set `camera.enabled` to `true` and either:
- `snapshot_url` — a local JPEG endpoint (ustreamer / mjpg-streamer / OctoPrint),
  e.g. `http://localhost:8080/?action=snapshot`; or
- `device_index` — a capture device index for direct OpenCV capture
  (`pip install opencv-python`).

Frames are pushed outbound to the server and shown in the dashboard — so a
camera on the printer's network is viewable remotely with no inbound ports.

## One-click send from Cura (recommended)

Install the [`cura/PrintQueuePlugin`](cura/PrintQueuePlugin/) plugin (see its
README). It adds a **"Send to LK5 Pro"** button to Cura's print button — slice,
click, done. No exporting G-code, no second app.

If you'd rather auto-upload on every slice (upload only, then dispatch from the
admin panel), use the post-processing script
[`cura/PrintQueueUploader.py`](cura/PrintQueueUploader.py) instead.

## Device page on the Pi (ZMOD-style local UI)

The agent serves a local web UI on the host at `http://<host-ip>:7130` (configurable
under `local_ui` in `config.json`): live status, camera, file list, and full manual
control — start/pause/resume/cancel, set temps, jog/home, fan. It also exposes an
**OctoPrint-compatible** upload API, so **Orca Slicer** (Host Type: OctoPrint,
`<host-ip>:7130`) can "Send to printer" straight to the Pi and optionally start the
print. Set `local_ui.api_key` to require a key; leave blank for an open LAN page.
Disable the whole thing with `local_ui.enabled: false`.

## Remote management & updates (from the app)

Once an agent is registered, the **Print Agents** admin page can manage it
remotely over the same outbound channel:

- **Manage panel**: view logs, identify, reload config, restart the agent, reboot
  the Pi (reboot/restart are refused while a print is running).
- **OTA app updates**: build a bundle with `python build_bundle.py`, upload the
  resulting `.zip` under "Agent software updates", then click **Update agent** —
  the agent downloads it, verifies the checksum, swaps its package, and restarts.
  (Requires the service manager — systemd/NSSM — to auto-restart the process.)
- **Printer firmware flashing** (advanced, opt-in, can brick the board): set
  `firmware.enabled: true` in `config.json` and install `avrdude`
  (`sudo apt install avrdude` on a Pi). Upload a Marlin `.hex` under "Printer
  firmware", then click **Flash firmware** on the agent. The agent releases the
  serial port and runs avrdude (`-c wiring -p atmega2560` for the LK5 Pro). It
  refuses to flash while a print is running.

## Print mode: SD vs stream

`print_mode` in `config.json` controls how prints run:

- **`"sd"`** (default) — the agent uploads the sliced file to the printer's SD
  card, then prints from it. The print survives an agent/host restart, but the
  SD-over-serial upload is **slow** (~1 KB/s: minutes for a small file, much more
  for a big one) because Marlin writes each line to the card one round-trip at a
  time.
- **`"stream"`** — the agent host-streams the gcode straight to the printer, so
  **printing starts in seconds** (no upfront upload), like OctoPrint/Cura direct
  print. You keep full visibility and control from the device page while it runs
  (live temps, progress, pause/resume/cancel, set-temp). Trade-off: the **agent
  must stay connected for the whole print** — if the Pi/agent drops, the print
  stops (there's no SD copy to fall back on).

Set `"print_mode": "stream"` for speed on a dedicated always-on Pi; keep `"sd"`
if resilience to a host restart matters more than upload speed.

## Seeing what's sent over serial

Set `"serial_debug": true` in `config.json` and restart. Every command sent and
reply received is logged (`TX> …` / `RX< …`) — visible in
`journalctl -u printqueue-agent -f` and the admin **View logs** panel. It's
noisy during a print (one line per command); turn it off when you're done.

## Where prints show up

Prints started from the **device page** or **Orca** ("Send to printer") are
**local** to the agent — they don't appear in the central Printellect *queue*
(only admin "Send file" jobs do). The agent's live status (state, temps,
progress) still shows on its **Print Agents** card and the device page. During a
stream print, temps come from Marlin's ~3s auto-reports (shown only while fresh),
so nothing stale is displayed.

## Important notes

- **Cura and the agent can't both be connected to the printer at once** (a USB
  port has one owner). The agent *replaces* Cura as the print driver; you still
  slice in Cura. If the port is busy, the agent waits instead of interfering.
- **Print accuracy is unchanged**: the agent uploads the exact bytes Cura
  produced and prints from SD — identical to printing that file from the
  printer's own menu (and more reliable than USB host-streaming).
- **Firmware**: SD upload (`M28`/`M29`), SD print (`M23`/`M24`) and status
  reports (`M27`/`M105`) are standard Marlin and work on the stock LK5 Pro
  (Marlin 1.1.9) and community Marlin 2.x builds. **Job cancel** uses `M524`,
  which is **Marlin 2.0+ only**; on stock 1.1.9 the agent falls back to pausing
  + cooling, and a full stop may need the printer's screen.
- **Baud rate**: default `115200` (stock). Some community firmware uses
  `250000` — if the agent can't connect, set `"baud_rate": 250000` in
  `config.json`.
- **Dispatch latency**: with `long_poll: true` (default) the agent holds one
  connection open and the server returns commands/print jobs the instant they're
  queued — sub-second, with far fewer requests than polling. Set
  `long_poll: false` to fall back to plain polling every `poll_interval_s`.
  (Heartbeats stay on `heartbeat_interval_s`; the on-Pi device page is always
  instant regardless.)
