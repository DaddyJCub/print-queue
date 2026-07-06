# Feature: Printellect Watch — AI Print-Failure Monitoring (app side)

Status: implemented (v0.30.0, branch `claude/printellect-camera-ai-monitoring-9ktnp6`)
Companion: `jcubhub-central-management` repo, same branch (AI analysis + review UI).

## Problem

Prints fail (spaghetti, detachment, blobs) with nobody watching. Printellect
already has camera access for every printer; JCubHub CM has the AI stack
(Ollama vision + Claude). Watch connects them.

## Design

A background worker (`app/print_monitor.py`, started from `_startup()` like the
other pollers, env gate `ENABLE_PRINT_MONITOR`) runs every
`print_monitor_interval_seconds` (default 60, UI range 30–600):

1. **Discover** active prints with the same dual query as the status pollers:
   `builds.status='PRINTING'` rows plus legacy single-build `requests`.
2. **Capture** a frame: `capture_camera_snapshot()` for LAN printers
   (Moonraker/FlashForge), or the latest `printer_agent_snapshots` BLOB for
   agent printers (skipped when older than 2× the interval).
3. **Skip** when it shouldn't judge: warm-up window after print start
   (`print_monitor_warmup_minutes`, first layers confuse the AI), polling
   paused for the printer, frame identical to the last one (sha256 dedup —
   frozen stream), frame over `print_monitor_max_frame_kb`, session muted.
4. **Submit** HMAC-signed (same scheme as `bug_reporter.py`; secret falls back
   to `bug_report_secret`) to CM `POST /api/print-monitor/frames`
   (Print Monitor Contract 1.0.0) and get the verdict synchronously.
5. **Act** only on *confirmed* failures (CM's session block — Claude-verified
   or CM's Ollama-streak rule): push to admins + optional email with the
   snapshot, per-build alert-once + `print_monitor_alert_cooldown_minutes`
   cooldown; opt-in per-printer auto-pause.

**Fail-open invariant:** any CM/AI problem logs and skips the cycle. Monitoring
can never disturb a print.

## Auto-pause (opt-in per printer, default off)

- AD5X (Moonraker): `MoonrakerAPI.pause_print()`.
- LK5_PRO (agent): new `pause_print` command in `AGENT_COMMAND_ACTIONS`,
  enqueued via `enqueue_pause_command()`; the agent executes
  `printer.pause_print()` over serial. Older agents report "Unsupported
  action" harmlessly. Requires an agent update to take effect.
- ADVENTURER_4 (FlashForge): **alerts only** — the FlashForge API has no
  pause/control methods; the toggle is disabled in the UI.
- Pause, never cancel; one attempt per build; a pause fires its own push.

## Storage

`print_monitor_sessions` (one per build: state watching|alerted|paused|muted|
ended, last_frame_hash, alerted_at, auto_paused, muted, cm_errors) and
`print_monitor_events` (verdict rows incl. CM frame id + action taken).
Created via `init_print_monitor_tables()` from `init_db()`.

## UI

- `/admin/print-monitor` ("Watch" in nav): every setting UI-editable — enable,
  CM URL/secret, interval, warm-up, cooldown, max frame size, email toggle,
  per-printer auto-pause — plus recent sessions with verdicts and Mute.
- Request page Live Camera card: latest AI verdict badge (with confidence and
  reasoning tooltip), "paused by Watch" indicator, Mute AI button.
- Deeper review (frame history, thumbs up/down feedback that tunes the AI,
  dataset export) lives in CM at `/print-monitor`.

## Settings (all seeded in DEFAULT_SETTINGS, all in the admin UI)

`print_monitor_enabled`, `print_monitor_url`, `print_monitor_secret`,
`print_monitor_interval_seconds`, `print_monitor_warmup_minutes`,
`print_monitor_max_frame_kb`, `print_monitor_alert_cooldown_minutes`,
`print_monitor_notify_email`, `print_monitor_autopause_<PRINTER_CODE>`.

## Verification

- `tests/test_print_monitor.py`: discovery dual-query, HMAC signing, fail-open
  (500/exception/unconfigured), alert state machine (confirm → alert once →
  cooldown → mute), Claude-source confirmation, auto-pause gating.
- E2E without printers: `scripts/dev/mock_moonraker.py` as a fake PRINTING
  AD5X + a local CM with `qwen2.5vl:7b` pulled; rotate a spaghetti test image
  into the snapshot URL to drive the full failure lifecycle.
