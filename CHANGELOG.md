# Changelog

All notable changes to Printellect are documented in this file.

This project follows the repository versioning policy in [VERSIONING.md](VERSIONING.md):
- `0.x.y` indicates active pre-`1.0.0` development
- `0.X.0` is used for feature releases
- `0.x.Y` is used for patches and fixes

> Note: The project originally shipped under `1.x.x`. In December 2025, versioning was reset to `0.x.y` to better reflect pre-`1.0.0` status. Earlier `1.x.x` entries are preserved below as historical releases.

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
