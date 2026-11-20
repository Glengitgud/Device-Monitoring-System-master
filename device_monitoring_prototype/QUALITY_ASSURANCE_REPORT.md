# Quality Assurance Report

**System:** DevMonitor Device Monitoring System
**Review date:** 2026-11-21
**Scope:** Device registration, scanning, monitoring, administration, database, and user experience.

## Current QA status

The existing prototype supports verified QR enrollment, one-time Windows inventory collection, website-based saved health reports, periodic browser refresh, role-based administration, and database-backed audit events. The regression suite passes. The enhancements listed below are in scope for the current implementation and remain open until their feature-specific checks are completed; existing prototype behavior is not evidence that these requirements pass.

| Area | Existing baseline | Required validation / remaining work |
|---|---|---|
| Device Registration | QR-enrollment tokens are expiring, one-use, and owner-bound. MAC addresses are now collected, validated, stored on devices and enrollment records, and shown in device details. | Continue validating registration compatibility and the unified scanner in later stages. |
| Device Monitoring | Dashboard and device lists refresh periodically; the unified scanner now submits inventory and health in one authorized operation and refreshes the website data. | Validate live status indicators and automatic synchronization across all views. |
| Device Agent | The enrollment executable collects inventory; the Device Scanner executable collects inventory and health without a console or external result window. | Validate platform boundaries and packaging on supported production hosts. |
| Device Status Monitoring | Devices have persisted status and last-seen fields. Online devices without a successful scan/check-in for five minutes transition to offline with an audit record; status indicators refresh on dashboard, lists, and open details. | Validate maintenance workflows and status behavior under a production scheduler. |
| Dashboard Features | Database-backed fleet data and health summaries are available; successful scan completion refreshes data and redirects to the dashboard. | Verify live status, cross-platform results, and browser behavior in supported browsers. |
| Admin Features | Administrator-only user/device management and logs use server-side authorization. Excel export requires the current administrator's username/password and records denied, started, failed, and successful attempts. | Implement and verify admin-controlled schedules and agent delivery. |
| Cross-Platform Support | Endpoint collection and EXE packaging are Windows-specific. | Add platform-aware collection and validate Windows, macOS, and mobile capability limitations. |
| Audit Logs | Authentication, device, scan, status-transition, and export events use persisted audit records; export events omit credentials. | Verify schedule events after the persistent-agent model is implemented. |
| Database Integration | Flask-SQLAlchemy models, migrations, and SQLite-backed integration tests cover core workflows. MAC address columns are included in the schema and additive migration `011_device_mac_address.sql`. | Validate production database upgrade behavior; add schedule schema changes in a later stage. |
| Error Handling | Validation, token, SMTP, packaging, and database errors have explicit responses. | Verify useful website errors for scanner, schedule, export, and unsupported-platform failures. |
| User Experience Improvements | Responsive UI, status indicators, in-page scan results, data refresh, and the five-second dashboard redirect are implemented. | Validate browser download behavior and user acceptance; there is no separate download tab to close in the current flow. |

## Stage validation record

| Stage | Result |
|---|---|
| Baseline and report update | Existing authentication and device integration suite: 56 tests passed. This is baseline coverage only; it does not validate the enhancements above. |
| MAC address collection and persistence | Implemented and verified: collector, input validation, device/enrollment persistence, owner/admin details, specifications page, and registration status. Three focused enrollment/collector tests passed. Production MySQL migration execution remains unverified. |
| Scanner consolidation and removal of standalone diagnostics UI/executable | Implemented and verified: one My Devices scan action, one silent scanner executable, combined inventory/health submission, website-based history/results, and dashboard redirect; 58 tests passed. A production PyInstaller build and browser acceptance run remain unverified. |
| Live status and Excel export | Implemented and verified: stale status transition/audit and authenticated multi-sheet workbook export; denied credentials and successful exports are audited. |
| Scheduled monitoring | Pending the explicitly consented persistent agent, device credential lifecycle, startup/pause/stop controls, and scheduled scan delivery. |
| Cross-platform collection, accessibility, and user acceptance | Pending implementation and platform/browser tests; current executable collector/build is Windows-only. |

## Security and verification limits

Device ownership, administrator route protection, CSRF, one-use enrollment and scan tokens, and database constraints must remain server-enforced. Schedules must not run privileged endpoint code without an enrolled agent and an explicit, bounded monitoring policy. Excel exports contain sensitive user and device data and must require a fresh administrator credential check, be generated in memory, and never be written to a public/static directory.

Automated tests use an isolated SQLite database and mocked mail/build boundaries. They do not establish live MariaDB upgrade safety, real SMTP delivery, cross-platform endpoint collection, browser permission behavior, or a successful user acceptance session. Those checks must be reported separately and never inferred from unit tests.

## Run the regression suite

```powershell
python -m unittest discover -s device_monitoring_prototype\tests
```
