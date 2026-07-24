# Changelog

All notable changes to Printellect are documented in this file.

This project follows the repository versioning policy in [VERSIONING.md](VERSIONING.md):
- `0.x.y` indicates active pre-`1.0.0` development
- `0.X.0` is used for feature releases
- `0.x.Y` is used for patches and fixes

> Note: The project originally shipped under `1.x.x`. In December 2025, versioning was reset to `0.x.y` to better reflect pre-`1.0.0` status. Earlier `1.x.x` entries are preserved below as historical releases.

## 0.34.6
### Performance
- **Fixed the intermittent site-wide freeze.** Measuring live revealed the real cause of the "sometimes slow" loads was not the queue page at all — it hit *every* route (even the near-static changelog). A single blocking operation was stalling the whole server: FlashForge printer status is read over a raw socket, and that blocking socket call ran directly on the async event loop. Whenever a FlashForge printer was slow or offline (e.g. during the admin dashboard's 15-second auto-refresh), the socket's timeout froze the entire process — so every visitor's request stalled for several seconds at once.
  - The blocking socket exchange now runs in a background thread pool, so it can never stall request handling. A slow or offline printer no longer freezes the site.
- **Added lightweight performance instrumentation** to catch regressions like this: an event-loop stall monitor that logs when the server is blocked, slow-request logging, and `X-Instance` / `X-Elapsed` response headers for measuring server time and per-replica behaviour from the outside.

## 0.34.5
### Performance
- **Queue pages no longer wait on printers at all.** Even after the 0.34.4 parallelization, a live measurement showed cold loads of the public queue taking 3–7 seconds while warm loads took ~0.5s: every page render still made live printer network calls in the request path, so any time the in-memory cache was cold (right after a redeploy, or once it expired between visits) the visitor paid the full printer round-trip — and a redeploy wipes that cache.
  - A **background status warmer** now polls every printer out-of-band (every ~8s) and stores the result in a shared cache. Page renders read that cache directly and **never block on printer I/O** — the only exception is the brief moment right after startup before the warmer's first pass, and even then only for printers with nothing cached yet.
  - Net effect: the admin dashboard and public `/queue` render from memory in roughly their database-and-template time regardless of whether printers are online, slow, or offline. An offline printer can no longer stall a page load.

## 0.34.4
### Performance
- **The admin and public queue pages now load much faster, especially when a printer is offline.** Live printer status was fetched one printer at a time, and the "cache" only kicked in after a printer had already failed — so each render waited on every printer in series, and an offline or slow printer stalled the whole page for its full timeout (repeatedly, since the same printer was polled several times per render).
  - Printer statuses are now fetched **in parallel** on both the admin dashboard and the public `/queue`, so total wait is roughly one printer's response time instead of the sum of all of them.
  - A short **freshness window** (5s for a live result, 3s for an offline one) reuses the last status instead of re-hitting the printer, which collapses the duplicate polls a single render made, absorbs rapid auto-refreshes and concurrent viewers, and stops a permanently-offline printer (e.g. an agent printer that's powered down) from costing a network timeout on every load.
  - The admin dashboard no longer polls every printer twice per render — the status cards and the "Printing Now" ETA calculations now share one set of results.

## 0.34.3
### Bug Fixes
- **Fixed the "Set aside" button on the admin Queue dashboard.** It was the last action still using the raw browser `confirm()` pop-up; after a later change added the app's own confirmation modal everywhere else, clicking **OK** on that native pop-up no longer submitted the form, so setting a job aside appeared to do nothing. It now uses the same styled confirmation modal as the rest of the app.
- **Set-aside now gives immediate feedback while the current build finishes.** When a job is set aside mid-print, its current build is allowed to finish first, so the request correctly stays under *Printing Now* rather than jumping straight to *Set Aside* — which looked like nothing had happened. The card now shows a **⏸ Set aside pending** badge so it's clear the request has been set aside and will stop before its next build.

## 0.34.2
### Bug Fixes
- **Reverted the 0.34.1 agent-printer poll change to stop a production crash loop.** Adding `is_printing()`/`is_complete()` to `AgentPrinterAPI` let the LK5_PRO agent printer flow through the full status-poll and camera/AI print-monitor pipeline for the first time; under that concurrent load the process began aborting with native heap corruption (`malloc_consolidate(): invalid chunk size`). Reverting restores the prior stable behavior (the agent printer's build poll is skipped rather than auto-completing). The underlying concurrency bug is still under investigation.

## 0.34.0
### Overview / Highlights
- **Agent-backed printers now appear on the admin Queue dashboard.** The Longer LK5 Pro (and any printer connected through a Printellect agent) now gets its own live status card on *Admin → Queue*, alongside the directly-connected printers — so an active print is visible at a glance instead of only showing on the public queue.

### Enhancements
- New status card shows the printer's state, current file, progress bar, layer count and nozzle/bed temperatures, with a camera button when a camera is attached.
- Each agent printer card links to **Manage** (the Printer Agents remote panel) for pause, resume, cancel, jog and temperature controls.

### Bug Fixes
- The admin Queue dashboard was hardcoded to two printers, so an agent-backed printer that was actively printing had no card and no visibility there. It now lists every printer, matching the public queue.

## 0.33.0
### Overview / Highlights
- **Watch quiet-hours failsafe, richer failure alerts, and multi-build names.** Three improvements to AI print monitoring so an overnight failure doesn't run for hours, alerts are more actionable, and multi-build jobs are easy to tell apart.

### Enhancements
- **Quiet-hours failsafe (auto-pause overnight).** Set an overnight window (default 22:00–07:00, configurable timezone) in *Admin → Print Monitor*. During that window a confirmed failure is paused automatically on pause-capable printers — even if the per-printer auto-pause toggle is off — so a spaghetti print doesn't run all night while you're asleep. You still get the alert.
- **Failure alerts now include a live camera image preview and quick actions.** Push notifications for a confirmed failure carry a snapshot of the printer plus **View print** and **Pause** buttons that deep-link straight to the printer's controls.
- **Multi-build names in monitoring.** Frames, alerts and CM sessions for a multi-build request are now labeled `Name (build 2/3)` instead of showing the same name for every build, so you can tell which build is failing.

### Bug Fixes
- Print-monitor frame images are now stored on a persistent Docker volume in JCubHub CM, so captured frames survive a redeploy instead of disappearing.

## 0.32.0
### Overview / Highlights
- **Printer error alerts.** Printellect now watches every Klipper/Moonraker (ZMod) printer for faults and alerts you the moment the machine reports one — so a jam, runout, or a printer that emergency-stopped no longer sits unnoticed on the bed.

### Enhancements
- New background fault watcher polls each Moonraker-backed printer (default every 20s) and detects **any** reported error via Klipper's own signals: MCU/board shutdowns, thermal runaway, a disconnected thermistor ("ADC out of range"), "Lost communication with MCU", Klipper config/startup errors, prints aborted with an error, and filament **runout/jam** pauses from the IFS/runout sensor.
- Alerts go out as an **admin push notification and (optionally) email**, with a friendly plain-English headline plus the printer's raw error text so nothing is lost.
- **Edge-triggered with a cooldown**: one alert when a fault first appears, a reminder every N minutes while it persists, and a "recovered" notice when the printer returns to normal — no per-poll spam.
- Configurable on the **Printellect Watch** admin page (enable, poll interval, reminder cooldown, email on/off, recovery notice on/off), with a rolling log of recent printer errors. Off by default; runs independently of the AI camera monitor. Per-replica env gate `ENABLE_PRINTER_ERROR_ALERTS`.

## 0.31.1
### Bug Fixes
- **Watch stops watching once a print is actually done.** Previously, if a build stayed marked as "printing" after it finished or was cancelled at the machine, Watch kept grabbing the (now idle) camera every minute and sending empty-bed frames to the AI — so a session appeared to keep "monitoring" a print that wasn't running. Watch now cross-checks the printer's live status and stops capturing (and ends the session) when the printer clearly isn't printing, while staying safe when the live status is briefly unknown.

## 0.31.0
### Overview / Highlights
- **Set aside a multi-build request**: when you stop a multi-build job after one build to print something else, you can now formally set it aside instead of leaving it stuck "in progress" forever. Set-aside requests move to their own **Set Aside** section on the admin queue with a one-click **Resume**, and their remaining builds are preserved.

### Enhancements
- New **Set aside** button on multi-build cards in *Printing Now*. If a build is still running, it finishes first; the queue then stops instead of auto-starting the next build, and the request moves to *Set Aside* (new `PAUSED` status).
- **Resume** returns a set-aside request to the active queue so its remaining builds can be started (manually or by auto-match). Starting any build also implicitly resumes it.
- Requesters see set-aside jobs stay visible in *My Prints* (labeled Paused) rather than disappearing.

### Fixes
- **Unknown prints are no longer masked.** Printer "occupancy" is now based on a build that is actually printing — not merely a request left `IN_PROGRESS` between builds. Previously, a request stuck in progress on a printer would hide a different/unknown print started on that same machine (and steal its live progress in *Printing Now*). That job is now correctly detected and surfaced as an Unknown Print.

## 0.30.2
### Bug Fixes
- **Watch now monitors one print per printer per cycle.** When several jobs are queued as PRINTING on the same printer, Watch was capturing and analyzing the same camera view once per job (e.g. 7 near-identical frames a minute for one printer), needlessly loading the AI model. It now picks the single most-recently-started job per printer — matching physical reality (one camera, one active print).

## 0.30.1
### Bug Fixes
- The **Watch** page is now reachable from the admin menu: added to the More → System section (the v0.30.0 link was added to a legacy nav component that the current UI doesn't render). Also surfaced the existing **Bug Reporting** page there, which had the same problem.

## 0.30.0
### Overview / Highlights
- **Printellect Watch**: AI camera monitoring of active prints. While a print is running, the printer camera is checked about once a minute and each frame is sent to JCubHub Central Management, where the local Ollama vision model looks for failures (spaghetti, bed detachment, blobs, layer shifts, and more). Confirmed failures alert admins by push and email with a snapshot — and can optionally pause the print.

### Enhancements
- New background monitoring worker that watches every actively printing build. It skips the first layers (configurable warm-up), skips frozen camera feeds, and stays completely out of the way when Central Management is unreachable — monitoring problems never disturb a print.
- New **Watch** admin page (`/admin/print-monitor`): enable/disable, CM endpoint + secret (reuses the Bug Reporting secret by default), check interval (30s–10min), warm-up delay, alert cooldown, email toggle, and per-printer auto-pause opt-ins — every setting is editable in the UI, no environment variables needed.
- The Live Camera Feed card on a request now shows the latest AI verdict badge (OK / warning / failure with confidence) and a **Mute AI** button to silence alerts for a known-ugly-but-fine print.
- Per-printer **auto-pause** (off by default): when the AI confirms a failure, the print is paused — never canceled — so you can inspect and decide. Supported on Moonraker-backed printers; FlashForge printers are alerts-only (their API cannot pause).
- Recent monitoring sessions with verdicts, confidence, and frame counts are listed on the Watch page.

### Notes / Things to Know
- Requires JCubHub Central Management with print monitoring enabled and a vision model pulled on the Ollama host (default `qwen2.5vl:7b`).
- Alerts only fire on **confirmed** failures (CM's escalation policy — optionally verified by a second AI), with a per-print cooldown, so a single glitchy frame won't page you.
- Frames are only captured while something is printing; nothing is sent when printers are idle.

## 0.29.0
### Overview / Highlights
- A big pass on the on-printer device page: clear connection indicators, a friendly printer name, safety/convenience controls, and self-updates that actually refresh — plus canceling a queued print now truly stops the printer.

### Enhancements
- Added two live **connection indicators** to the device-page header — **Printer** (USB link) and **Printellect** (server link) — as colored status chips, so you can tell at a glance what's reachable.
- The device page now shows a **friendly printer name** ("Longer LK5 Pro") instead of the internal agent id. An optional `local_ui.display_name` overrides it.
- Added an **Emergency Stop** button to the device page that halts the printer immediately (Marlin `M112`).
- Added a **fan-speed slider** (0–100%) with an Off shortcut on the device page.
- The device page now shows **elapsed and estimated-remaining time** for a running print, not just a byte-percentage.
- Added **PLA / PETG / All-off temperature quick-presets** so operators don't have to type target temps.
- Added a **Restart agent** button to the device page, and the page now **auto-reloads whenever the agent restarts to a new version** (update or restart) so newly-shipped UI appears without a manual refresh — detected from the live agent version, so it no longer depends on the update-verification poll completing.
- When the device is **offline from Printellect**, the page now shows a clear notice of what still works locally (printing, controls) and what's paused (updates, remote jobs, dashboard camera).
- **Mobile touch-ups** on the device page — larger tap targets and a cleaner header/layout on phones.

### Bug Fixes
- The **Printellect connection indicator no longer reads "online" while the Pi can't reach the server**. A full network outage previously left the indicator stuck on its last state; network failures now correctly flip the agent to offline (and the long-poll keeps it accurate between heartbeats).
- Canceling a print job from the admin queue now actually **aborts the print on the printer**. Previously "Cancel job" only marked the job canceled in the database — the physical print ran to completion, and a late status update from the agent could even resurrect the canceled job. The agent now observes the cancellation and stops the SD print, and the server ignores stale updates to a terminal (finished/canceled) job.
- The admin **"Device page" button now opens the correct URL**. The agent reports its LAN IP and device-UI port in every heartbeat, so the button no longer points at a placeholder address.
- The Print Agents **command-output panel no longer scrolls back to the top** every couple of seconds while you read output — it only redraws when something actually changed.
- The agent version shown on the device page is no longer stuck at **1.0.0** (it was hardcoded and never bumped); it now reports its real version.

### Notes / Things to Know
- Emergency Stop requires a printer reset or power-cycle to recover afterward (standard Marlin `M112` behavior).
- Cancel/E-Stop from the on-device page already worked; this fixes the central admin-queue cancel path specifically.
- Applying updated agent **code** requires an agent restart; over-the-air updates restart the agent automatically, and the device page reloads once it's back. The agent package advanced to `1.1.0` and tracks its own version line, independent of the app's `0.x`.

## 0.28.0
### Overview / Highlights
- The print agent becomes fully manageable from the app: configure the host, push over-the-air updates from the device itself, detect firmware versions, and manage agents end-to-end.

### Enhancements
- Remote host configuration for the agent's Raspberry Pi: set **hostname, timezone, and Wi-Fi** (SSID/password) from the admin panel, and pull live host/network info on demand.
- **Over-the-air self-update from the on-device page**: check for agent/firmware updates, apply them with one click, and verify the result — no admin session needed on the Pi.
- **Automatic firmware-version detection** from agent heartbeats, with a one-click "update agent (and firmware if newer)" flow and deterministic verification.
- Admins can **delete a revoked agent** and its history; the command log now shows full lifecycle timestamps (queued → delivered → completed) and redacts secrets.
- The agent management panel **remembers which panel/agent was open** across background refreshes and links straight to the on-device page.

### Bug Fixes
- Fixed the guided device install wizard (the agent package is bundled correctly and the virtualenv setup is more robust).
- Consistent UTC handling when parsing ISO timestamps in the admin UI.

### Notes / Things to Know
- Host configuration (hostname/timezone/Wi-Fi) applies on Linux agent hosts (Raspberry Pi); it is not available on Windows hosts.
- Firmware flashing remains opt-in per agent and can brick the board — use with care.

## 0.27.0
### Overview / Highlights
- New bug/error reporting pipeline so problems surface automatically, configurable entirely from the admin UI.

### Enhancements
- Application errors and bug reports are now sent to the **JCubHub CM (Sentinel) collector** for centralized tracking and AI triage.
- Bug reporting is **configured from the admin UI** — no environment variables required — and is reachable from the mobile admin menu.
- Added a **Support link** (home.jcubhub.com/support).
- The admin **feedback view now supports pagination and bulk actions**.
- Database connections use a **busy-timeout** for better resilience under concurrent access.

### Bug Fixes
- Bug-reporter delivery failures are now surfaced as **warnings** instead of being silently swallowed, so a misconfigured collector is visible.

### Notes / Things to Know
- If the collector isn't configured, reporting is simply skipped and the app continues normally.

## 0.26.6
### Overview / Highlights
- The remaining standalone pages now get fresh styles on each release like the rest of the app.

### Bug Fixes
- The 3D file-preview pages, the "Open in App" page, and the changelog page linked the stylesheet without a version, so they could show stale styling after an update. They now use the same cache-busted stylesheet link as every other page.

## 0.26.5
### Overview / Highlights
- Admin pages now use the same card surface as the rest of the app, completing the visual unification.

### Enhancements
- Applied the canonical card surface (matching the dashboard and user-facing pages) to every admin page, so admin and the public app look like one product end-to-end.

### Bug Fixes
- None.

### Notes / Things to Know
- Visual-only: verified no form, input, button, link, or handler changed on any admin page (every interactive element byte-for-byte identical across 25 admin pages).

## 0.26.4
### Overview / Highlights
- Unified the card look across all user-facing pages so the whole app matches the dashboard.

### Enhancements
- Every user-facing page (queue, request detail, my prints, store, sign-in/up, profile, credits, devices, trips, legal pages, etc.) now uses the same card surface as the dashboard, for a consistent feel across the app.
- The Store now uses the shared page header and category pills from the design-system component library.

### Bug Fixes
- None.

### Notes / Things to Know
- This is a visual-consistency pass only — verified that no form, button, link, or behavior changed on any page (every interactive element is byte-for-byte identical; only card background/border styling was updated).

## 0.26.3
### Overview / Highlights
- Admin navigation no longer scrolls sideways on desktop.

### Bug Fixes
- The admin nav pill-bar overflowed and required horizontal scrolling (awkward/impossible with a mouse on desktop). The primary sections now stay on one row and the system/hardware sections (Settings, Features, Admins, Audit, File Sync, Debug, Printers, Print Agents, Devices, Releases, OTA, Docs) live in a grouped "More" dropdown.

### Notes / Things to Know
- "More" highlights when you're on one of its sections, and closes on outside-click or Escape.

## 0.26.2
### Overview / Highlights
- Restored admin navigation links that went missing in the 0.26.0 admin redesign.

### Bug Fixes
- The unified admin nav was missing several sections — File Sync, OTA Status, Printellect Docs, and the Design queue view. All admin sections are reachable again from the admin pill-bar.

### Notes / Things to Know
- The admin pill-bar scrolls horizontally; the new sections appear at the end of the system group.

## 0.26.1
### Overview / Highlights
- Easier submitting on mobile: a sticky "Submit Request" button follows you down the request form.

### Enhancements
- On phones, once the main submit button scrolls out of view, a sticky Submit Request bar appears above the bottom navigation so you can submit from anywhere on the form. It reuses the normal submit flow (including rush checkout), so nothing about submitting changes.

### Bug Fixes
- None.

### Notes / Things to Know
- The sticky bar is mobile-only and hides itself whenever the main submit button is on screen.

## 0.26.0
### Overview / Highlights
- Unified the admin area into the same look and feel as the rest of the app — it no longer feels like a separate product.
- Dashboard fixes: active requests now open correctly, and the Live Printers card shows live print detail.

### Enhancements
- Admin pages now share the same header, navigation, and mobile bottom-nav as the user-facing app, with an admin section pill-bar under the header. Every admin screen (queue, shipping, store, analytics, payments, users, settings, features, audit, devices, and all the rest) was moved onto a single shared shell.
- Introduced a shared UI component library (cards, page headers, stat tiles, pills, buttons) so pages stop re-implementing the same patterns and stay visually consistent.
- The dashboard Live Printers card is now clickable (opens the queue) and, while printing, shows the current file, layer progress, and nozzle temperature alongside the progress bar.
- Admin pages now get cache-busted CSS, so style updates apply without a hard refresh.

### Bug Fixes
- Fixed a 404 when opening one of your active requests from the dashboard — it now links to the correct request page.

### Notes / Things to Know
- This is an internal/visual refactor; admin functionality is unchanged. The de-duplicated admin shell reuses the app's shared toast and confirm/alert dialogs.
- Admin still uses a wider layout for dense tables.

## 0.25.1
### Overview / Highlights
- Surface the new Printables import toggle in the admin Feature Flags page.

### Bug Fixes
- The `printables_fetch` feature flag was registered but did not appear on the admin Feature Flags page, because that page only renders a curated, hardcoded list of flags. Added it to the "Private Features (User-Gated)" section so admins can enable it and manage the allowed-email list from the UI.

### Notes / Things to Know
- Behavior is unchanged; this only makes the existing flag manageable in the UI. Runtime mode is still controlled by the `PRINTABLES_FETCH_MODE` env var.

## 0.25.0
### Overview / Highlights
- Import 3D files directly from a Printables model link on the request form.

### Enhancements
- Added a "Fetch Files" action to the request form: paste a Printables model link, fetch its metadata (title, description, license, author) and file list, then multi-select files with a per-file quantity (1–50). The selection is persisted with the request.
- Individual files (`stl`/`gcode`/`sla`/`other`) are imported automatically and attached to the request; multi-file download packs and premium/paid models are recorded as reference links instead of binaries.
- The selected model, files, quantities, attachment mode, and license now render on both the requester's request page and the admin request view.
- New provider abstraction under `app/integrations/` (Printables client + parser) designed to support additional providers later.

### Bug Fixes
- Fixed an `UnboundLocalError` in the database migration step that could occur (via a redundant local `import secrets`) when backfilling request access tokens on certain databases.

### Notes / Things to Know
- The feature is gated behind the new `printables_fetch` feature flag (off by default in production) and requires a signed-in account.
- Runtime behavior is controlled by `PRINTABLES_FETCH_MODE` (`metadata_only`, `reference_only`, or `direct_import`). See [docs/printables-integration.md](docs/printables-integration.md) for the compliance matrix; model rights remain governed by the original creator's license.
- New `external_sources` and `external_source_files` tables are created additively on startup; no manual migration is needed.

## 0.24.5
### Overview / Highlights
- Redesigned the home dashboard into a modern, at-a-glance layout.
- Admins can now delete announcements.

### Enhancements
- Redesigned the home dashboard with a responsive "bento" layout: a prominent New Request action, an at-a-glance metrics band (Printing Now, In Queue, Completed with a this-week count), a live Printers panel with real-time progress bars, your active requests with build progress, and recent activity shown as a timeline. It fills the screen on desktop and reflows to a single column on mobile.
- Admins now get dashboard shortcuts: a "Pending Review" count and a Manage Queue quick action.
- Added a delete button to each past broadcast on the Broadcast page. Deleting one removes it from the broadcast history and from the dashboard Announcements feed.

### Bug Fixes
- None.

### Notes / Things to Know
- The dashboard appears at `/` when the `dashboard_home` feature is enabled; the request form remains at `/new-request`.
- The stylesheet is now cache-busted per release, so style updates apply without a hard refresh.
- Deleting an announcement does not recall push or email notifications that were already delivered.

## 0.24.4
### Overview / Highlights
- Added a way to put a completed build back in the queue.

### Enhancements
- Admins can re-queue a completed build from the request page, reversing its completion and returning it to the queue — useful for recovering builds that were marked done without actually printing.

### Bug Fixes
- None; this is a small addition.

### Notes / Things to Know
- Re-queuing a build re-syncs the parent request so its progress and status reflect the change.

## 0.24.3
### Overview / Highlights
- Stopped multi-build prints from marking later builds "done" before they actually printed.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- A build now only auto-completes after the printer has actually been seen running it. Previously, a printer that holds its "finished" state (such as the Adventurer 4 staying at 100% until OK is pressed) could rapidly mark several queued builds complete without printing them.

### Notes / Things to Know
- Hands-free queue progression still works; the operator still starts each physical print as before.
- A very short print that starts and finishes within a single status check may need to be marked done manually.

## 0.24.2
### Overview / Highlights
- Reliability fixes so builds can always be started and finished prints clear themselves from the queue.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- Starting a build no longer fails when the printer still shows a leftover "printing" job from an earlier print — a stale job can no longer wedge the printer.
- Multi-build prints on Moonraker printers (e.g. AD5X) now auto-complete when the printer finishes and returns to standby, instead of staying stuck in progress.

### Notes / Things to Know
- Finished prints clear automatically and the next queued build starts on its own.

## 0.24.1
### Overview / Highlights
- Stabilization patch following the print-agent remote-management release.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- Kept admin and user sessions in sync to stop admins from being logged out prematurely.
- Sent the correct token on logout so single sign-out completes cleanly.
- Fixed an oversized setup-wizard window so it scrolls internally and keeps its buttons reachable.
- Preserved the submit button's state and improved feedback while uploads are in progress.

### Notes / Things to Know
- No configuration changes.

## 0.24.0
### Overview / Highlights
- Turned the print agent into a fully remote-managed device: send commands and jobs, push software and firmware updates, and walk through a guided on-device setup — all from the admin dashboard.

### Enhancements
- Remote command lane so admins can send actions and print jobs to a networked printer and have them picked up almost instantly.
- Near-real-time dispatch so agents receive new commands and jobs immediately instead of waiting for the next check-in.
- Over-the-air agent self-update, so agent software can be upgraded remotely without re-imaging the device.
- Printer firmware flashing and restore directly from the admin update screen.
- Local device page on the printer's mini-computer for on-site control and monitoring.
- Guided, interactive setup wizard for new print agents with copy-paste-ready steps.
- Optional secure-networking onboarding built into the setup wizard, with standard local/router networking as the default so it works without extra software.
- In-app agent setup guide and an operator security/hardening guide.

### Bug Fixes
- None in this release; follow-up fixes shipped in 0.24.1.

### Notes / Things to Know
- Secure networking is optional; the default setup works on a standard local network or router subnet.

## 0.23.0
### Overview / Highlights
- Added the ability to print to an LK5 Pro printer that lives on a different network, using a lightweight on-site agent and a one-click slicer plugin.

### Enhancements
- Cross-network LK5 Pro printer integration through a dedicated print agent that runs next to the printer.
- One-click send-to-printer from Cura via a bundled slicer plugin.
- Admin interface for registering and managing print agents.
- "Send to LK5 Pro" action on the request page to dispatch a job straight to the printer.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- The print agent runs on a small always-on computer on the same network as the printer.

## 0.22.1
### Overview / Highlights
- Reliability patch for application logging.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- Enabled sensible log-rotation defaults to prevent runaway log files.

### Notes / Things to Know
- No configuration changes.

## 0.22.0
### Overview / Highlights
- Larger, more reliable file uploads for signed-in users, plus smarter automatic handling of incoming prints.

### Enhancements
- Upload size limits now scale with whether a user is signed in, with clearer messaging when a file is too large.
- Chunked, resumable file uploads so large models upload reliably, with validation of pre-uploaded files before submission.
- Automatic color detection and best-guess matching for unmatched incoming prints.
- Print handling now checks whether a printer is already busy and auto-completes finished jobs more reliably.
- Admin dashboard hides delivered shipping requests and shows clearer status.

### Bug Fixes
- None in this release; a follow-up fix shipped in 0.22.1.

### Notes / Things to Know
- Signed-in users get higher upload limits than guests.

## 0.21.0
### Overview / Highlights
- Cut down on spam submissions and made it easier for admins to tie a request to the right account.

### Enhancements
- Anti-spam protection on the request form, including a hidden honeypot field to catch bots.
- Admins can link a request to an existing account, with requester details auto-filled in the admin request form.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Legitimate requesters are unaffected by the new spam checks.

## 0.20.1
### Overview / Highlights
- Patch for admin build error reporting.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- Clearer error message when a device's source files are missing during an admin build.

### Notes / Things to Know
- No configuration changes.

## 0.20.0
### Overview / Highlights
- Expanded remote device operations with over-the-air updates, a remote reset, Wi-Fi onboarding, and richer live device control.

### Enhancements
- Over-the-air update management with a remote reset control and guided Wi-Fi setup for devices.
- Structured device-control actions, including light controls, with live command streaming.
- Richer over-the-air diagnostics and telemetry to make remote updates easier to troubleshoot.

### Bug Fixes
- None in this release; a follow-up fix shipped in 0.20.1.

### Notes / Things to Know
- Builds on the device-control foundation from earlier releases.

## 0.19.0
### Overview / Highlights
- Introduced the dashboard-driven home experience while hardening checkout and account flows for production rollout.

### Enhancements
- Added a dashboard landing page at `/` with quick actions, active request tracking, printer status, an activity feed, and announcements.
- Moved the request form to `/new-request` when the dashboard is active.
- Added staged, per-user rollout for the new dashboard home.
- Updated post-login redirects and submit links to adapt to the dashboard.
- Added controls to safely run background workers across multiple instances without duplicate credit grants or duplicate shipment polling.

### Bug Fixes
- Fixed the admin quote-setting flow to handle stored records correctly.
- Fixed embedded checkout (store, rush, quote) to resolve a unified account for both legacy and new sign-in sessions.
- Fixed credit checkout to resolve or create a unified account for legacy sessions.

### Notes / Things to Know
- The dashboard home rolls out in stages and supports both legacy and unified sign-in.

## 0.18.0
### Overview / Highlights
- Added single sign-on and account-linking support for unified authentication.

### Enhancements
- Added single sign-on (OpenID Connect) with account linking, so existing accounts can link or be created automatically on first sign-in.
- Added staged onboarding so sign-on can be enabled gradually.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Single sign-on rolls out in stages.

## 0.17.0
### Overview / Highlights
- Expanded production onboarding and device operations with better pairing, release management, and control workflows.

### Enhancements
- Production onboarding upgrades: pairing deep-link with auto-claim and redirect, admin device registry management, automated QR/device provisioning, package-zip over-the-air upload mode, and an expanded device control panel.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Focused on production provisioning readiness and smoother device operations.

## 0.16.1
### Overview / Highlights
- Introduced first-generation store commerce and rewards flows with card checkout and account credits.

### Enhancements
- Added store commerce foundations with card checkout for store items, rush fees, and quote payments.
- Added the credits and rewards system with earning, spending, and transaction history.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Store and rewards roll out in stages.

## 0.16.0
### Overview / Highlights
- Established the device-control foundation across user, admin, and API workflows.

### Enhancements
- Device-control foundation: user device flow, private feature management, a device debug view, and handoff docs.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Laid the groundwork for subsequent production device features.

## 0.15.2
### Overview / Highlights
- Added legal and compliance coverage and policy routes needed for shipping and payments rollout.

### Enhancements
- Added legal and compliance pages for Terms of Use, Privacy Policy, Acceptable Use, and Refund & Shipping policies.
- Added public policy routes to support the shipping and payments rollout.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Supports the shipping and payments rollout.

## 0.15.1
### Overview / Highlights
- Delivered a stability-focused patch for camera capture and shipping webhook handling.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- Camera fix: skip placeholder frames and use the printer's snapshot URL, harden shipping webhooks, and support a shipping from-address override.

### Notes / Things to Know
- Focused on reliability for active shipping and printing workflows.

## 0.15.0
### Overview / Highlights
- Added end-to-end shipping fulfillment with quoting, labeling, and tracking workflows.

### Enhancements
- Shipping fulfillment: carrier integration for rates, labels, and tracking, an admin shipping dashboard, a requester shipping portal, and webhook support.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Introduced shipping as a first-class fulfillment method.

## 0.14.0
### Overview / Highlights
- Improved ETA usability by presenting localized, timezone-aware times to users.

### Enhancements
- ETA local timezone support: the server defaults to Central time and the page converts to show each user's local time zone label.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Reduced timezone ambiguity for distributed users.

## 0.13.1
### Overview / Highlights
- Added automation for file ingestion and request matching via file sync workflows.

### Enhancements
- Added file sync automation with watched folders, fuzzy request matching, and archive workflows for incoming print files.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- File sync can be turned on when needed.

## 0.13.0
### Overview / Highlights
- Added live ETA intelligence and better file-linking workflows for print operations.

### Enhancements
- Live ETA integration, file linking (G-code ↔ STL/3MF), a card-based files view, and a send-to-printer flow.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Improved queue confidence through richer print metadata and ETA visibility.

## 0.12.1
### Overview / Highlights
- Delivered a stabilization patch for build progression and in-progress matching behavior.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- Auto-start the next build after completion, auto-match in-progress requests, and improve error logging.

### Notes / Things to Know
- Focused on queue state consistency.

## 0.12.0
### Overview / Highlights
- Improved guest-to-account conversion with contextual registration guidance in email flows.

### Enhancements
- Guest account creation tips in emails with pre-filled registration and auto-linking of existing requests.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Targeted smoother onboarding from guest workflows.

## 0.11.1
### Overview / Highlights
- Released a safety-focused patch for printer controls and admin notifications.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- Safer printer controls and admin progress alerts.

### Notes / Things to Know
- Focused on safer operational controls.

## 0.11.0
### Overview / Highlights
- Added a dedicated designer workflow for assignment and completion tracking.

### Enhancements
- Designer workflow with assignments and design completion tracking.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Established role-based design operations.

## 0.10.8
### Overview / Highlights
- Strengthened platform security controls and migration tooling for account evolution.

### Enhancements
- Added security hardening with CSRF protection, rate limiting, and security headers.
- Added account migration tooling for legacy users and admins, plus expanded demo-data support for local workflows.

### Bug Fixes
- None in this security-focused release.

### Notes / Things to Know
- Centered on middleware hardening and account migration utilities.

## 0.10.7
### Overview / Highlights
- Improved profile experience and notification reliability for user lifecycle events.

### Enhancements
- Profile photos, editable avatars, and sturdier notification delivery for print lifecycle and design flows.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Focused on account experience and communication quality.

## 0.10.6
### Overview / Highlights
- Introduced guarded designer-role workflows for request-level control.

### Enhancements
- Designer role and guarded design workflow with request-level assignment and completion checks.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Tightened workflow permissions around design tasks.

## 0.10.5
### Overview / Highlights
- Delivered a behavior-consistency patch for blocked-request handling across the app.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- Full blocked-status support across dashboard, notifications, and requester/admin UI cleanup.

### Notes / Things to Know
- Focused on status consistency and UX cleanup.

## 0.10.4
### Overview / Highlights
- Improved architecture and ETA behavior for multi-build request flows.

### Enhancements
- Modularized the application structure and improved ETA calculations for multi-build requests.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Emphasized maintainability and ETA accuracy.

## 0.10.3
### Overview / Highlights
- Expanded request intake and admin controls with stronger multi-file and user-management tooling.

### Enhancements
- Multi-file uploads and improved admin user management tools.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Improved intake flexibility and admin workflows.

## 0.10.2
### Overview / Highlights
- Released a usability patch for account preferences and password reset reliability.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- Hotfix for user account preference saving and password reset usability.

### Notes / Things to Know
- Focused on account workflow reliability.

## 0.10.1
### Overview / Highlights
- Released a UX consistency patch after the initial user-accounts launch.

### Enhancements
- None; this is a patch release.

### Bug Fixes
- Navigation and UX consistency improvements for the initial user accounts release.

### Notes / Things to Know
- Focused on post-launch polish.

## 0.10.0
### Overview / Highlights
- Introduced foundational user accounts, role-based admin support, and feature controls.

### Enhancements
- User accounts system: registration and login, profiles, multi-admin support, and user management.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Established the modern account and authentication architecture.

## 0.9.0
### Overview / Highlights
- Introduced admin app navigation unification and improved requester list usability.

### Enhancements
- Admin app navigation, unified admin/public navigation patterns, and My Prints pagination.

### Bug Fixes
- None in this release.

### Notes / Things to Know
- Focused on navigation consistency across app surfaces.

## Historical releases (`1.x.x`)
- `1.8.23` — Admin dashboard pagination with “show more” and collapsible Recently Closed.
- `1.8.22` — Admin request page UX cleanup with inline quick actions and collapsible edit forms.
- `1.8.21` — Flexible build reordering while other builds are already printing.
- `1.8.20` — Multi-build display fixes for labels, counts, and current build progress bars.
- `1.8.19` — Multi-build printer display fixes for simultaneous printers and auto-refresh stability.
- `1.8.18` — Printer connection conflict fixes with polling pause, locking, and retry logic.
- `1.8.17` — User 3D model viewer and richer build details with requester downloads.
- `1.8.16` — Progress milestone notifications, app broadcast system, and admin broadcast page.
- `1.8.15` — Multi-build UX improvements and clearer status labeling.
- `1.8.14` — Push notification robustness and a push health endpoint.
- `1.8.13` — Per-build photo gallery and push notification fixes.
- `1.8.12` — Build management with edit/delete actions and stronger printer validation.
- `1.8.10` — Admin session persistence fixes and smoke-check endpoint.
- `1.8.7` — Logging system improvements and requester portal DB connection fixes.
- `1.8.6` — In-progress state fixes in My Requests.
- `1.8.1` — Printer retry logic, per-status admin email controls, and duplicate request fixes.
- `1.8.0` — Store feature and requester-portal enhancements.
- `1.7.3` — Timelapse API.
- `1.7.2` — Request templates.
- `1.7.1` — Dynamic rush pricing.
- `1.7.0` — Auto-refresh queue, printer suggestions, repeat requests, rush priority, and changelog page.
- `1.6.0` — Smart ETA from print history.
- `1.5.0` — Extended status API with filename and layer-progress details.
- `1.4.0` — Camera streaming, auto-complete snapshots, and login redirect fix.
- `1.3.0` — FlashForge integration, ETA calculations, and analytics.
- `1.2.0` — Admin dashboard, priority system, and email notifications.
- `1.1.0` — File uploads, status tracking, and public queue.
- `1.0.0` — Initial release.
