# Send to Print Queue — Cura plugin

Adds a **"Send to LK5 Pro"** option to Cura's print button so that slicing and
sending is **one click** — no exporting G-code, no second app.

```
Slice in Cura  ─▶  click "Send to LK5 Pro"  ─▶  print starts
```

## Install

1. In Cura: **Help → Show Configuration Folder**.
2. Copy the whole `PrintQueuePlugin` folder into the `plugins` subfolder there.
3. In that copied folder, copy `config.example.json` to `config.json` and fill in:
   - `server_url` — your print-queue URL.
   - `ingest_token` — from **Admin → Printer Agents** (shown at the top).
   - `printer_code` — `LK5_PRO` (default).
   - `agent_id` — optional; leave blank to target the newest online agent for
     that printer.
4. Restart Cura.

## Use

1. Load a model and **Slice** as usual.
2. Click the dropdown arrow on the bottom-right action button and choose
   **Send to LK5 Pro** (it sits next to "Save to Disk" / "Print via USB").
3. The G-code uploads and the print is queued; the agent next to the printer
   starts it. You'll get a confirmation toast.

## Notes

- This sends to the queue, which dispatches to the printer's **SD card** for an
  autonomous print — your PC does not need to stay on.
- Nothing prints on a plain **Slice**; the print only starts when you click
  **Send to LK5 Pro**.
- If you prefer auto-upload on every slice instead of a button, use the
  post-processing script `../PrintQueueUploader.py` (uploads only; you then
  dispatch from the admin panel).
