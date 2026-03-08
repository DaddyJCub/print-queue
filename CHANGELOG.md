# Changelog

All notable changes to Printellect are documented in this file.

This project follows the repository versioning policy in [VERSIONING.md](VERSIONING.md):
- `0.x.y` indicates active pre-`1.0.0` development
- `0.X.0` is used for feature releases
- `0.x.Y` is used for patches and fixes

> Note: The project originally shipped under `1.x.x`. In December 2025, versioning was reset to `0.x.y` to better reflect pre-`1.0.0` status. Earlier `1.x.x` entries are preserved below as historical releases.

## 0.19.0
### Added
- Added a feature-flagged dashboard landing page at `/` with quick actions, active request tracking, printer status, activity feed, and announcements.
- Request form moved to `/new-request` when the dashboard is active.
- Per-user rollout via the `dashboard_home` feature flag with email allow-list and wildcard support.
- All post-login redirects and submit links dynamically adapt based on the flag state.

### Notes
- Controlled by the `dashboard_home` feature flag for staged rollout.
- Supports both legacy User and unified Account authentication for identity detection.

## 0.18.0
### Added
- Added OpenID Connect / Authentik sign-in support with discovery, authorization-code flow, callback handling, JWKS token validation, and account linking.
- Added feature-flagged SSO onboarding so existing accounts can link or auto-create from first-time OIDC sign-in.

### Notes
- Controlled by the `oidc_login` feature flag.
- Covered by the OIDC test suite in `tests/test_oidc.py`.

## 0.17.0
### Added
- Printellect production flow upgrades: `/pair` deep-link auto-claim + redirect, admin registry management, admin QR/device.json automation, OTA package-zip upload mode, expanded device control panel, and finalized Pico provisioning contract docs.

## 0.16.1
### Added
- Added store commerce foundations with Stripe Checkout support for store items, rush fees, and quote payments.
- Added the credits / rewards system with grant, spend, transaction logging, and scheduled credit grants.

### Notes
- Controlled by the `store_payments` and `store_rewards` feature flags.
- Backfilled release note based on implemented code and schema support.

## 0.16.0
### Added
- Printellect device control foundation: user/account modal flow, private feature toggle management, device debug endpoint, Pico handoff docs, and CI feature-flag fixes.

## 0.15.2
### Added
- Added legal and compliance pages for Terms of Use, Privacy Policy, Acceptable Use, and Refund & Shipping policies.
- Added public policy routes to support the shipping and payments rollout.

### Notes
- Backfilled release note based on implemented policy pages and effective dates.

## 0.15.1
### Fixed
- Camera fix: skip ustreamer placeholder frames, use Moonraker snapshot URL, harden Shippo webhooks, and support shipping from-address override.

## 0.15.0
### Added
- Shipping fulfillment: Shippo integration for rates, labels, tracking, admin shipping dashboard, requester shipping portal, and webhook support.

## 0.14.0
### Added
- ETA local timezone support: server defaults to CST/CDT and client-side conversion shows each user's local time zone label.

## 0.13.1
### Added
- Added file sync automation with watched folders, fuzzy request matching, and archive workflows for incoming print files.

### Notes
- Controlled by the `file_sync` feature flag.
- Backfilled release note based on implemented service and schema support.

## 0.13.0
### Added
- Moonraker live ETA integration, file linking (`G-code ↔ STL/3MF`), card-based files UI, and send-to-printer flow.

## 0.12.1
### Fixed
- Auto-start next build after completion, auto-match `IN_PROGRESS` requests, and improve error logging.

## 0.12.0
### Added
- Guest account creation tips in emails with pre-filled registration and auto-linking of existing requests.

## 0.11.1
### Fixed
- Safer printer controls and admin progress alerts.

## 0.11.0
### Added
- Designer workflow with assignments and design completion tracking.

## 0.10.8
### Added
- Added security hardening with CSRF protection, rate limiting, and security headers.
- Added account migration tooling for legacy users/admins and expanded demo-data support for local workflows.

### Notes
- Backfilled release note based on implemented middleware and migration utilities.

## 0.10.7
### Added
- Profile photos, editable avatars, and sturdier notification delivery for print lifecycle and design flows.

## 0.10.6
### Added
- Designer role and guarded design workflow with request-level assignment and completion checks.

## 0.10.5
### Fixed
- Full `BLOCKED` status support across dashboard, notifications, and requester/admin UI cleanup.

## 0.10.4
### Changed
- Modularized the application structure and improved ETA calculations for multi-build requests.

## 0.10.3
### Added
- Multi-file uploads and improved admin user management tools.

## 0.10.2
### Fixed
- Hotfix for user account preference saving and password reset usability.

## 0.10.1
### Fixed
- Navigation and UX consistency improvements for the initial user accounts release.

## 0.10.0
### Added
- User accounts system: registration/login, profiles, multi-admin support, feature flags, and user management.

## 0.9.0
### Added
- Admin PWA navigation, unified admin/public navigation patterns, and My Prints pagination.

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
