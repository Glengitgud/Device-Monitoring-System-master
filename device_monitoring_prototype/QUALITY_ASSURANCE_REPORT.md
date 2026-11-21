# Quality Assurance Report

**System:** DevMonitor Device Monitoring System
**Review date:** 2026-11-21
**Scope:** Device registration, scanning, monitoring, administration, database, and user experience.

## Current QA status

The existing prototype supports verified QR enrollment, one-time Windows inventory collection, website-based saved health reports, periodic browser refresh, re-verified role-based administration, consistent sensitive-data masking, and database-backed audit events. The automated regression suite passes; browser and production-host validations remain separate deployment checks.

| Area | Existing baseline | Required validation / remaining work |
|---|---|---|
| Device Registration | QR-enrollment tokens are expiring, one-use, and owner-bound. MAC addresses are now collected, validated, stored on devices and enrollment records, and shown in device details. | Continue validating registration compatibility and the unified scanner in later stages. |
| Device Monitoring | Dashboard and device lists refresh periodically; the unified scanner now submits inventory and health in one authorized operation and refreshes the website data. | Validate live status indicators and automatic synchronization across all views. |
| Device Agent | The enrollment executable collects inventory; the silent Device Scanner submits inventory and health, then opens the configured dashboard URL in the default browser. | Validate platform boundaries, packaging, and browser behavior on a supported Windows host. |
| Device Status Monitoring | Devices have persisted status and last-seen fields. Online devices without a successful scan/check-in for five minutes transition to offline with an audit record; status indicators refresh on dashboard, lists, and open details. | Validate maintenance workflows and status behavior under a production scheduler. |
| Dashboard Features | Database-backed fleet data and health summaries are available; the scanner opens the dashboard after a successful submission. | Verify live status, cross-platform results, and browser behavior in supported browsers. |
| Admin Features | Administrator-only user/device management and logs use server-side authorization. Excel export requires the current administrator's username/password and records denied, started, failed, and successful attempts. | Implement and verify admin-controlled schedules and agent delivery. |
| Cross-Platform Support | Endpoint collection and EXE packaging are Windows-specific. | Add platform-aware collection and validate Windows, macOS, and mobile capability limitations. |
| Audit Logs | Authentication, device, scan, status-transition, and export events use persisted audit records; export events omit credentials. | Verify schedule events after the persistent-agent model is implemented. |
| Database Integration | Flask-SQLAlchemy models, migrations, and SQLite-backed integration tests cover core workflows. MAC address columns are included in the schema and additive migration `011_device_mac_address.sql`. | Validate production database upgrade behavior; add schedule schema changes in a later stage. |
| Error Handling | Validation, token, SMTP, packaging, and database errors have explicit responses. | Verify useful website errors for scanner, schedule, export, and unsupported-platform failures. |
| User Experience Improvements | Responsive UI, status indicators, in-page scan results, data refresh, and the scanner dashboard redirect are implemented. | Complete a live Windows/browser acceptance pass; no code opens Explorer, Downloads, or a local directory. |

## Stage validation record

| Stage | Result |
|---|---|
| Baseline and report update | Existing authentication and device integration suite: 60 tests passed after the security enhancements. Unit coverage does not replace live browser or production database validation. |
| MAC address collection and persistence | Implemented and verified: collector, input validation, device/enrollment persistence, owner/admin details, specifications page, and registration status. Three focused enrollment/collector tests passed. Production MySQL migration execution remains unverified. |
| Scanner consolidation and removal of standalone diagnostics UI/executable | Implemented and verified: one My Devices scan action, one silent scanner executable, combined inventory/health submission, website-based history/results, and dashboard redirect; 58 tests passed. A production PyInstaller build and browser acceptance run remain unverified. |
| Live status and Excel export | Implemented and verified: stale status transition/audit and authenticated multi-sheet workbook export; denied credentials and successful exports are audited. |
| Scheduled monitoring | Pending the explicitly consented persistent agent, device credential lifecycle, startup/pause/stop controls, and scheduled scan delivery. |
| Cross-platform collection, accessibility, and user acceptance | Pending implementation and platform/browser tests; current executable collector/build is Windows-only. |
| Scanner dashboard redirect and sign-up refresh behavior | Implemented; full automated regression passed (61 tests). Live Windows/browser and SMTP acceptance remain pending. |

## Registration, Scanner, and Redirect Validation

| Area | Validation |
|---|---|
| Device Scanner Workflow | `device_agent.py:main()` submits its authorized report and inventory to `app.py:submit_agent_scan`; after success, it opens the configured `/dashboard` URL with `webbrowser.open()`. `app.py:scan_device()` only builds and serves the EXE. The agent contains no Explorer, Downloads-folder, shell, or local-directory launch command. Automated coverage verifies submission and URL selection; physical Windows/browser behavior still requires a workstation acceptance pass. |
| Redirect Validation | A successful scan opens the dashboard after submission; the dashboard loads persisted results. Scanner submission failures do not trigger this redirect. |
| Navigation Validation | Dashboard and device links remain server-routed; the scanner completion URL is the configured dashboard route. |
| Registration Workflow Validation | The public form contains only account fields, password confirmation, and CSRF protection. No Save Credentials control exists. Passwords are not restored from browser storage; login, authentication, and session behavior were not changed. |
| Verification Workflow Validation | The sign-up page no longer queries verification status on load or reopens the verification dialog after refresh. A successful registration submission and active server status are required before the dialog appears. Email-delivery and status errors remain on the sign-up form. Valid name, email, and username inputs may be restored from tab-scoped session storage. |
| Form State Management and Error Handling | Registration validation and verification stages remain intact. Verification errors are shown in the verification dialog; initial registration errors are shown on the sign-up form. A browser-launch failure is logged without undoing a successfully stored scan. |
| Regression Testing Results | Full automated regression: 61 tests passed, including scanner redirect target, registration form contents, page rendering, and staged verification APIs. Live scanner execution, SMTP delivery, and browser interaction are deployment acceptance checks, not inferred from unit tests. |

## Admin Panel Security Validation

| Check | Result | Evidence |
|---|---|---|
| Direct `/admin` access | Implemented; validated server-side | Normal login alone redirects administrators to `/admin/verify`; `/api/admin/*` rejects an unverified administrator. |
| Additional credentials | Implemented | Verification requires the signed-in username, password, active account status, and Administrator role. |
| Protected features | Implemented | User/device management, logs, database export, and system settings remain behind `admin_required`. |
| Access attempts | Implemented | Requested, succeeded, denied, credential-failed, and role-failed events include username, timestamp, IP address, and status. |

## Sensitive Data Protection Validation

User-facing and administrative email values use a shared server-side masking helper. Usernames, device names, dashboard labels, MAC addresses, and monitoring labels remain fully visible and operational. Verified administrator views may receive full account details; audit details are masked server-side before presentation.

| Location | Validation |
|---|---|
| User listings | Administrator access is re-verified; authorized listings receive full usernames and display masked emails when masking is required. |
| Dashboard/device views | Full usernames, device names, ownership labels, MAC addresses, and operational values remain visible. |
| Device details and monitoring | No username or operational label masking is applied. |
| Audit logs and exports | Audit details mask embedded email values. Export operations remain permission-gated and are audited. |

## Access Control and User Privacy Testing

- Standard users cannot open `/admin` or call `/api/admin/*`; they receive HTTP 403 for protected API resources.
- Administrator role checks are enforced independently of a successful password login.
- Sensitive device and account fields are masked before serialization where full access is not established.
- Phone and MAC masking helpers are retained for future fields and consistently use the same readable format.
- Browser-side rendering escapes values and does not grant authorization; all checks remain server-side.

## Audit Logging Validation

The audit trail now records administrator verification requests/success/failure, verified and denied panel access, sensitive user/list/audit/device viewing, and database export denied/start/success/failure events. Records include actor identity, event type, timestamp, IP address, and a success/failure or reason field. Passwords, submitted codes, and export credential values are not written to audit details.

## Session Persistence Validation

Administrator verification is session-bound to the signed-in user and is not an 15-minute frontend state. Entering `/admin` requires a fresh username/password/role check. Refreshing or reopening `/admin` invalidates the panel verification and redirects back to `/admin/verify`; browser restart or session reload has no verification marker and follows the same backend check. Protected `/api/admin/*` routes independently require the verification marker and role.

## Email Masking Validation

| Area | Expected behavior | Validation |
|---|---|---|
| Admin → User Accounts | Email addresses are masked server-side; usernames stay unchanged. | The `/api/users` response masks email values before rendering and uses the same value across refresh/navigation. |
| User Management/Edit | The masked email is shown without returning a full address through the listing endpoint. | New accounts accept a full email; editing requires entering a new email explicitly rather than re-submitting a masked value. |
| Dashboard/device views | Operational user and device fields remain unmasked. | Dashboard serialization retains device names and ownership/display values. |

Email example: `exampletesting@gmail.com` becomes `e*********g****.com`. Masking is produced during server serialization and is not restored or exposed by frontend state.

## Device Registration Navigation Validation

| Check | Result |
|---|---|
| My Devices Register Device link | The standard-user button now links directly to `/device-verification`. |
| Device Verification | Existing QR, token, confirmation, agent download, scan, registration, and dashboard routes remain unchanged. |
| Navigation labels | The add/register action no longer opens the legacy manual device modal. |
| Regression | Existing device list, detail, archive, restore, scan, and dashboard workflows remain covered. |

## Device Specification UI Validation

The Detected Device Specifications view no longer displays `Installed Network Adapters`. Server-rendered fields and browser detail rendering were both updated. Network adapter collection and database persistence remain unchanged so registration and monitoring behavior is not affected. CPU, RAM, storage, GPU, motherboard, operating system, IP, MAC, status, and health information remain available.

## Registration and Specification User Acceptance Testing

1. Sign in as a standard user and open My Devices.
2. Select Register Device and confirm navigation to Device Verification.
3. Generate or reuse the registration flow, download the scanner, complete a scan, and confirm redirect/dashboard behavior.
4. Open a registered device's Detected Device Specifications view.
5. Confirm Installed Network Adapters is absent and all remaining specification fields render correctly.

## Device Diagnostics Removal and Workflow Consolidation

| Area | Validation |
|---|---|
| Legacy diagnostics routes | `/api/device-agent/diagnostics/<run_id>` and `/api/devices/<id>/diagnostics` aliases are removed. Scanner submission remains available only through scanner routes. |
| Scanner UI | My Devices no longer renders a repeated Device Scan button or scanner modal. Scanner activity remains part of the verification and registration workflow. |
| Reports and navigation | Diagnostic/download/navigation labels and status polling components are removed; saved scanner results remain shown as Device Scan Results. |
| Database | Existing scanner run and check tables remain intact for database integrity and historical results. |
| User acceptance | Register a device through verification, run the approved scanner, confirm saved results and dashboard navigation. |

## System Cleanup and Regression Testing

- No diagnostic EXE download or diagnostics `/diagnostics` route remains.
- No Device Scan action remains in device cards or My Devices modals.
- Browser detail views and specifications retain inventory and scanner health fields without diagnostics navigation.
- The full regression suite must confirm registration, scanner submission, dashboard, and database history still pass.
- Final automated regression: 61 tests passed after diagnostics UI, route, modal, and module cleanup.

## User Acceptance Testing

Recommended acceptance pass:

1. Sign in as a standard user and attempt direct `/admin` and admin API URLs.
2. Sign in as an administrator, confirm `/admin` redirects to credential verification, and test wrong username/password/role states.
3. Verify that a successful administrator check opens user, device, monitoring, log, export, and settings areas.
4. Confirm email, username, phone, and MAC examples remain readable and are masked in listings, dashboard, details, logs, and previews.
5. Confirm an owner can view their own record while a non-owner cannot.
6. Review audit entries for verification, access, sensitive viewing, and export operations.
7. Download and run the Device Scanner on Windows; confirm its report is saved, the dashboard opens, and no local folder window appears.
8. Open Create Account and confirm there is no Save Credentials option; submit valid details and complete email and authenticator verification.
9. Refresh Sign Up before and after registration submission; confirm it stays on Sign Up and only opens verification after a successful submission.
10. Confirm failed registration or email delivery displays an error on the form and does not open the verification dialog.

**Acceptance status:** Automated workflow checks are covered by the regression suite. Browser, production database, SMTP, and live Windows workstation checks remain deployment validations.

## Security and verification limits

Device ownership, administrator route protection, CSRF, one-use enrollment and scan tokens, and database constraints must remain server-enforced. Schedules must not run privileged endpoint code without an enrolled agent and an explicit, bounded monitoring policy. Excel exports contain sensitive user and device data and must require a fresh administrator credential check, be generated in memory, and never be written to a public/static directory.

Automated tests use an isolated SQLite database and mocked mail/build boundaries. They do not establish live MariaDB upgrade safety, real SMTP delivery, cross-platform endpoint collection, browser permission behavior, or a successful user acceptance session. Those checks must be reported separately and never inferred from unit tests.

## Run the regression suite

```powershell
python -m unittest discover -s device_monitoring_prototype\tests
```
