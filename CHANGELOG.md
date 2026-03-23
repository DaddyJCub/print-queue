# Changelog

All notable changes to Printellect are documented in this file.

This project follows the repository versioning policy in [VERSIONING.md](VERSIONING.md):
- `0.x.y` indicates active pre-`1.0.0` development
- `0.X.0` is used for feature releases
- `0.x.Y` is used for patches and fixes

> Note: The project originally shipped under `1.x.x`. In December 2025, versioning was reset to `0.x.y` to better reflect pre-`1.0.0` status. Earlier `1.x.x` entries are preserved below as historical releases.

## 0.19.0
### Overview / Highlights
- Introduced the dashboard-driven home experience while hardening checkout/account flows and startup worker behavior for production rollout.

### Enhancements
- Added a feature-flagged dashboard landing page at `/` with quick actions, active request tracking, printer status, activity feed, and announcements.
- Moved the request form to `/new-request` when the dashboard is active.
- Added per-user rollout support via the `dashboard_home` feature flag with email allow-list and wildcard support.
- Updated post-login redirects and submit links to dynamically adapt based on dashboard flag state.
- Added deployment controls for background workers to avoid duplicate credit grants and USPS polling in multi-replica environments.

### Bug Fixes
- Fixed admin quote-setting flow to correctly handle SQLite row objects and avoid sync/async auth misuse in the admin route.
- Fixed embedded Stripe checkout endpoints (`store`, `rush`, `quote`) to resolve unified `accounts.id` for both legacy and unified auth sessions.
- Fixed credit checkout endpoints to resolve/create unified account records for legacy sessions instead of falling back to legacy `users.id`.

### Notes / Things to Know
- Controlled by the `dashboard_home` feature flag for staged rollout.
- Supports both legacy User and unified Account authentication for identity detection.
- New env toggles for deployment orchestration:
  - `ENABLE_CREDIT_GRANT_SCHEDULER` (set to `1` on a single worker/replica, `0` elsewhere)
  - `ENABLE_USPS_TRACKING_POLLER` (set to `1` on a single worker/replica, `0` elsewhere)

## 0.18.0
### Overview / Highlights
- Added OpenID Connect (Authentik) sign-in and account-linking support for unified authentication rollout.

### Enhancements
- Added OpenID Connect / Authentik sign-in support with discovery, authorization-code flow, callback handling, JWKS token validation, and account linking.
- Added feature-flagged SSO onboarding so existing accounts can link or auto-create from first-time OIDC sign-in.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- Controlled by the `oidc_login` feature flag.
- Covered by the OIDC test suite in `tests/test_oidc.py`.

## 0.17.0
### Overview / Highlights
- Expanded Printellect production onboarding and device operations with better pairing, release management, and control workflows.

### Enhancements
- Printellect production flow upgrades: `/pair` deep-link auto-claim + redirect, admin registry management, admin QR/device.json automation, OTA package-zip upload mode, expanded device control panel, and finalized Pico provisioning contract docs.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release emphasized production provisioning readiness and smoother device operations.

## 0.16.1
### Overview / Highlights
- Introduced first-generation store commerce and rewards flows with Stripe checkout and account credits.

### Enhancements
- Added store commerce foundations with Stripe Checkout support for store items, rush fees, and quote payments.
- Added the credits / rewards system with grant, spend, transaction logging, and scheduled credit grants.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- Controlled by the `store_payments` and `store_rewards` feature flags.
- Backfilled release note based on implemented code and schema support.

## 0.16.0
### Overview / Highlights
- Established the Printellect device-control foundation across user, admin, and API workflows.

### Enhancements
- Printellect device control foundation: user/account modal flow, private feature toggle management, device debug endpoint, Pico handoff docs, and CI feature-flag fixes.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release laid the groundwork for subsequent production Printellect features.

## 0.15.2
### Overview / Highlights
- Added legal/compliance coverage and policy routes needed for shipping and payments rollout.

### Enhancements
- Added legal and compliance pages for Terms of Use, Privacy Policy, Acceptable Use, and Refund & Shipping policies.
- Added public policy routes to support the shipping and payments rollout.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- Backfilled release note based on implemented policy pages and effective dates.

## 0.15.1
### Overview / Highlights
- Delivered a stability-focused patch for camera capture and shipping webhook handling.

### Enhancements
- No major feature enhancements were recorded in this patch release.

### Bug Fixes
- Camera fix: skip ustreamer placeholder frames, use Moonraker snapshot URL, harden Shippo webhooks, and support shipping from-address override.

### Notes / Things to Know
- Patch release focused on reliability improvements for active shipping/printing workflows.

## 0.15.0
### Overview / Highlights
- Added end-to-end shipping fulfillment with quoting, labeling, and tracking workflows.

### Enhancements
- Shipping fulfillment: Shippo integration for rates, labels, tracking, admin shipping dashboard, requester shipping portal, and webhook support.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release introduced shipping as a first-class fulfillment method.

## 0.14.0
### Overview / Highlights
- Improved ETA usability by presenting localized timezone-aware times to users.

### Enhancements
- ETA local timezone support: server defaults to CST/CDT and client-side conversion shows each user's local time zone label.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release reduced timezone ambiguity for distributed users.

## 0.13.1
### Overview / Highlights
- Added automation for file ingestion and request matching via file sync workflows.

### Enhancements
- Added file sync automation with watched folders, fuzzy request matching, and archive workflows for incoming print files.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- Controlled by the `file_sync` feature flag.
- Backfilled release note based on implemented service and schema support.

## 0.13.0
### Overview / Highlights
- Added live ETA intelligence and better file-linking workflows for print operations.

### Enhancements
- Moonraker live ETA integration, file linking (`G-code ↔ STL/3MF`), card-based files UI, and send-to-printer flow.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release improved queue confidence through richer print metadata and ETA visibility.

## 0.12.1
### Overview / Highlights
- Delivered a stabilization patch for build progression and in-progress matching behavior.

### Enhancements
- No major feature enhancements were recorded in this patch release.

### Bug Fixes
- Auto-start next build after completion, auto-match `IN_PROGRESS` requests, and improve error logging.

### Notes / Things to Know
- Patch release focused on queue state consistency.

## 0.12.0
### Overview / Highlights
- Improved guest-to-account conversion with contextual registration guidance in email flows.

### Enhancements
- Guest account creation tips in emails with pre-filled registration and auto-linking of existing requests.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release targeted smoother onboarding from guest workflows.

## 0.11.1
### Overview / Highlights
- Released a safety-focused patch for printer controls and admin notifications.

### Enhancements
- No major feature enhancements were recorded in this patch release.

### Bug Fixes
- Safer printer controls and admin progress alerts.

### Notes / Things to Know
- Patch release focused on safer operational controls.

## 0.11.0
### Overview / Highlights
- Added a dedicated designer workflow for assignment and completion tracking.

### Enhancements
- Designer workflow with assignments and design completion tracking.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release established role-based design operations.

## 0.10.8
### Overview / Highlights
- Strengthened platform security controls and migration tooling for account evolution.

### Enhancements
- Added security hardening with CSRF protection, rate limiting, and security headers.
- Added account migration tooling for legacy users/admins and expanded demo-data support for local workflows.

### Bug Fixes
- No release-critical bug fixes were recorded in this security-focused release.

### Notes / Things to Know
- Backfilled release note based on implemented middleware and migration utilities.

## 0.10.7
### Overview / Highlights
- Improved profile experience and notification reliability for user lifecycle events.

### Enhancements
- Profile photos, editable avatars, and sturdier notification delivery for print lifecycle and design flows.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release focused on account UX and communication quality.

## 0.10.6
### Overview / Highlights
- Introduced guarded designer-role workflows for request-level control.

### Enhancements
- Designer role and guarded design workflow with request-level assignment and completion checks.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release tightened workflow permissions around design tasks.

## 0.10.5
### Overview / Highlights
- Delivered a behavior-consistency patch for `BLOCKED` request handling across the app.

### Enhancements
- No major feature enhancements were recorded in this patch release.

### Bug Fixes
- Full `BLOCKED` status support across dashboard, notifications, and requester/admin UI cleanup.

### Notes / Things to Know
- Patch release focused on status consistency and UX cleanup.

## 0.10.4
### Overview / Highlights
- Improved architecture and ETA behavior for multi-build request flows.

### Enhancements
- Modularized the application structure and improved ETA calculations for multi-build requests.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature/change release.

### Notes / Things to Know
- This release emphasized maintainability and ETA accuracy.

## 0.10.3
### Overview / Highlights
- Expanded request intake and admin controls with stronger multi-file and user-management tooling.

### Enhancements
- Multi-file uploads and improved admin user management tools.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release improved intake flexibility and admin workflows.

## 0.10.2
### Overview / Highlights
- Released a usability patch for account preferences and password reset reliability.

### Enhancements
- No major feature enhancements were recorded in this patch release.

### Bug Fixes
- Hotfix for user account preference saving and password reset usability.

### Notes / Things to Know
- Patch release focused on account workflow reliability.

## 0.10.1
### Overview / Highlights
- Released a UX consistency patch after the initial user-accounts launch.

### Enhancements
- No major feature enhancements were recorded in this patch release.

### Bug Fixes
- Navigation and UX consistency improvements for the initial user accounts release.

### Notes / Things to Know
- Patch release focused on post-launch polish.

## 0.10.0
### Overview / Highlights
- Introduced foundational user accounts, RBAC admin support, and feature flag controls.

### Enhancements
- User accounts system: registration/login, profiles, multi-admin support, feature flags, and user management.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release established the modern account/auth architecture.

## 0.9.0
### Overview / Highlights
- Introduced admin PWA navigation unification and improved requester list usability.

### Enhancements
- Admin PWA navigation, unified admin/public navigation patterns, and My Prints pagination.

### Bug Fixes
- No release-critical bug fixes were recorded in this feature release.

### Notes / Things to Know
- This release focused on navigation consistency across app surfaces.

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
- `1.8.14` — Push notification robustness and `/api/push/health` endpoint.
- `1.8.13` — Per-build photo gallery and push notification fixes.
- `1.8.12` — Build management with edit/delete actions and stronger printer validation.
- `1.8.10` — Admin session persistence fixes and smoke-check endpoint.
- `1.8.7` — Logging system improvements and requester portal DB connection fixes.
- `1.8.6` — `IN_PROGRESS` state fixes in My Requests.
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
