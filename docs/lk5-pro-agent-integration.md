# LK5 Pro (cross-network) agent integration

> See also: [Docs Index](README.md) · Agent code: [`agent/`](../agent/) ·
> Server module: `app/printer_agent.py`

This document describes how the print-queue drives a **Longer LK5 Pro** (or any
USB Marlin printer) that is **on a different network** from the print-queue
container — for example, a printer connected by USB to a Windows PC or a
Raspberry Pi in another building, while the server runs in a Docker container
elsewhere.

## Why a different model than FlashForge / Moonraker

The existing FlashForge / Moonraker integrations have the **server reach into
the printer's LAN** (`get_printer_api()` opens a socket to `printer_ip:8899` or
Moonraker `:7125`). That only works when the container and printer share a
network. Across networks it would require VPNs or inbound port-forwarding —
fragile and a security risk.

Instead, a small **agent** runs next to the printer and makes only **outbound**
HTTPS calls to the server. This is the same poll-based pattern as the Printellect
device contract, scoped to print jobs.

```
┌─────────────┐    slice + upload .gcode     ┌────────────────────┐
│   Cura PC   │ ───────────────────────────▶ │  Print Queue server │
└─────────────┘                              │  (Docker container) │
                                             └─────────┬──────────┘
       outbound HTTPS only (no inbound ports)          │
┌──────────────────────────────┐   poll jobs / push status+camera   │
│  Agent (Raspberry Pi or PC)  │ ◀──────────────────────────────────┘
│  • pyserial USB to printer   │
│  • optional webcam snapshots │
└──────────────┬───────────────┘
               │ USB serial (Marlin)
        ┌──────▼───────┐
        │  LK5 Pro     │  prints autonomously from SD once started
        └──────────────┘
```

## Print flow

1. **Slice** in Cura (unchanged).
2. **Send — one click.** The Cura **output-device plugin**
   (`agent/cura/PrintQueuePlugin/`) adds a **"Send to LK5 Pro"** button next to
   Cura's Save/Print button. Clicking it uploads the sliced gcode to
   `POST /api/printer-agent/v1/print`, which stores it and enqueues a job in one
   call — no export, no second app.
   - *Alternatives:* the post-processing uploader (`PrintQueueUploader.py`)
     auto-uploads on every slice (upload only), or an admin can enqueue from the
     panel (`POST /api/printer-agent/admin/agents/{agent_id}/jobs`).
3. **Claim & upload**: the agent claims the job, downloads the gcode, and
   streams it to the printer's **SD card** using Marlin's line-numbered +
   checksummed protocol (`M28`/`M29`) — a verified, byte-accurate transfer.
4. **Print**: the agent starts an SD print (`M23`/`M24`). The printer now runs
   **autonomously**; the host can disconnect or power off and the print still
   completes.
5. **Monitor**: while connected, the agent reads `M105` (temps) and `M27` (SD
   progress) and forwards them in its heartbeat. The dashboard renders this just
   like Moonraker/FlashForge status.

### Reliability vs. the old "print from Cura over USB"

| Event | Old (Cura USB host-streaming) | Agent (SD print) |
|-------|------------------------------|------------------|
| PC powers off mid-print | Print **dies** | Print **continues** to completion |
| Host stutter / buffer underrun | Possible blobs/zits | None (printer reads from SD) |
| Cura crash | Print dies | Print continues |
| Remote monitoring | None | Live status + camera in queue |

## Security model

- **No inbound ports** on the printer's network — the agent only dials out.
- **Per-agent bearer token**, issued once via a **claim code** the admin
  generates. Only the SHA-256 hash of the claim code and token is stored.
- Re-provisioning **rotates** the token and revokes the old one; an admin can
  **revoke** an agent at any time (kills its tokens immediately).
- Brute-force protection on the claim code (8 failures / 5 min per agent).
- The **Cura ingest** endpoint uses a separate static ingest token (Cura can't
  hold an admin session); rotate it from the admin panel if leaked.
- Job file downloads are scoped to the owning agent (an agent can't read another
  agent's files).

## Server API

Base path: `/api/printer-agent/v1` (agent) and `/api/printer-agent/admin` (admin).

### Agent endpoints (bearer token, except provision)

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/debug` | Contract discovery (no auth) |
| `POST` | `/provision` | Claim code → bearer token |
| `POST` | `/heartbeat` | Report printer status/telemetry |
| `GET`  | `/jobs/next` | Claim the next queued job (204 if none) |
| `GET`  | `/jobs/stream?timeout_s=` | Long-poll variant of `/jobs/next` |
| `GET`  | `/jobs/{job_id}/file` | Download the sliced gcode |
| `POST` | `/jobs/{job_id}/status` | Lifecycle/progress updates |
| `POST` | `/snapshot` | Upload latest webcam frame (JPEG) |
| `POST` | `/print` | One-click upload **and** dispatch from Cura (`X-Ingest-Token`) |
| `POST` | `/ingest/gcode` | Upload-only ingest for the Cura post-processing script (`X-Ingest-Token`) |

Job lifecycle: `queued → claimed → uploading → printing → completed | failed | canceled`.

### Admin endpoints (admin session)

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/agents` | List agents + the Cura ingest token |
| `POST` | `/agents` | Create an agent (returns one-time claim code) |
| `POST` | `/agents/{agent_id}/revoke` | Revoke agent + its tokens |
| `POST` | `/agents/{agent_id}/jobs` | Enqueue a gcode file ("Send to LK5") |
| `GET`  | `/agents/{agent_id}/jobs` | List the agent's jobs |
| `POST` | `/jobs/{job_id}/cancel` | Cancel a job (agent aborts the print) |
| `GET`  | `/agents/{agent_id}/snapshot.jpg` | Latest webcam frame |

### Heartbeat `printer` payload

The agent reports a flat status object; the dashboard adapter
(`AgentPrinterAPI`) maps it onto the standard printer-status shape:

```json
{
  "state": "printing",          // idle | printing | paused | offline
  "progress": 42,                // 0-100 (SD byte progress)
  "nozzle_temp": 205.0,
  "nozzle_target": 210.0,
  "bed_temp": 60.0,
  "bed_target": 60.0,
  "current_file": "PQPRINT.GCO"
}
```

## Hosting options

| Host | Notes |
|------|-------|
| **Raspberry Pi** (3B/4B/Zero 2 W/5) | Recommended. Frees the PC; native USB/CSI camera; runs the agent as a systemd service. Optionally also run OctoPrint for a local web UI + live MJPEG. |
| **Windows PC** | The existing Cura PC. Run the agent via Task Scheduler or NSSM. |

A **Raspberry Pi Pico** is **not** suitable — it's a microcontroller with no OS
and limited USB-host support; use a full Raspberry Pi.

See [`agent/README.md`](../agent/README.md) for install steps.
