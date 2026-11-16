# Quality Assurance Report

**System:** Centralized End-User Device Monitoring and Diagnostic System (DevMonitor)
**Review date:** 2026-11-16
**Result:** 20 application integration tests pass against isolated SQLite databases. The configured local MySQL database was reachable in the prior review with 15 tables and both RBAC roles; this feature's migration has not been applied or verified against that MySQL database. Browser-level and physical Windows hardware checks remain outstanding.

## System scope

This report covers the user-facing pages, Flask routes and services, and the ORM/MySQL schema described in `FEATURES_AND_FUTURE_WORK.md`. Items identified as future work are not treated as delivered or passing.

| Area | Implemented behavior | QA coverage and limits |
|---|---|---|
| Startup and configuration | Flask app, environment-file loading, database URL configuration, CLI initialization/seed-data commands, and setup guidance when the database or seed roles are unavailable. | Tests cover environment selection, default XAMPP/MySQL URL, initialization, sample data, and database/seed-data error responses. A prior read-only check verified the local MySQL connection and pre-feature schema; the new migration, other deployments, and recovery remain unverified. |
| Account creation and sign-in | Public registration creates standard-user accounts; passwords are Werkzeug hashes. New passwords must be 8–16 characters, include an A-Z uppercase letter and a special character, and match the confirmation field. Registration JavaScript shows validation and success alerts; the server independently enforces policy for public, administrator-created, and CLI-created accounts. | Integration tests cover registration, hashed-password login, policy boundaries, invalid passwords, confirmation mismatch, and registration feedback markup. Failed-login auditing and administrator account recovery are also covered. Browser automation has not been run. The reserved development `admin` / `admin123` bootstrap account is an explicit exception; replace its credential before deployment. |
| Sessions and request security | Flask-Login sessions, CSRF checks on writes, HttpOnly/SameSite cookies, configurable Secure cookies, and server-side authorization. | Integration tests exercise authenticated/unauthenticated routes and user/device access boundaries. This is not a penetration test; rate limiting, production HTTPS, and external security testing are not implemented or verified. |
| Roles and administration | Seeded Administrator/User roles and permissions; administrator account creation, editing, deactivation, and log search/filtering. User accounts, activity logs, and device logs are separate collapsed categories, fetched when opened, and display ten rows initially with a show-more control. The reserved admin and final active administrator are protected. | Integration tests cover initialization, administrator access, user management, paginated log queries, role/status protections, and collapsed category markup. An isolated JavaScript behavior check verified deferred requests and ten-row expansion; real-browser interaction is not automated. |
| QR device enrollment | Signed-in users generate account-linked QR codes containing random, expiring, single-use tokens. Scanning opens a registration page and starts a token-bound Windows agent download. | Integration tests verify authenticated creation, unique hashed tokens, QR SVG output, enrollment/download pages, expiration, and invalid/reused-token rejection. A real phone QR scan and browser download UX were not tested. |
| Endpoint agent and specification capture | A Windows Python agent collects only the requested 13 CPU, memory, storage, GPU, motherboard, OS, adapter, and IP values. It presents them locally and requires an explicit confirmation before submission. | A test exercises the collector/parser with mocked Windows command output and verifies the exact information field set. Live PowerShell hardware detection and actual Windows device compatibility were not run. |
| Device inventory and ownership | Owners/registrants register, edit, and view devices; administrators can manage all devices. QR-confirmed specifications, owner, registration/update timestamps, status, and registration history persist. Owners and administrators can open the dedicated specifications page through the View action; device search and status filtering remain available. | Integration tests cover QR-agent database persistence, device details/history, owner boundaries, token replay, API validation, and other device workflows. Existing integration tests cover administrator management and archive/restore/soft-delete. Browser UI interactions and client-side search/filter behavior are not automated. |
| Device lifecycle and history | Connectivity and lifecycle status are separate. Archive/restore and administrator soft-delete retain device records and history; account deactivation retains account records. | Tests verify lifecycle transitions, authorization, and retained rows/history. There is no application hard-delete route. |
| Dashboard and device UI | Database-backed fleet summary, device and archived-device views, browser-side search/sort/pagination, action dialogs, and feedback. Login/registration guidance, edit-device fields, and scan-result details use the dark-theme readable text and control styling. | Page/API integration checks run; targeted CSS review covers the requested readability states. Automated browser interaction, contrast measurement, accessibility, responsive-layout, and cross-browser checks have not run. |
| Host inventory and diagnostics | Manual registration retains its existing host snapshot. The Windows agent submits the explicitly reviewed inventory. A scan appends a placeholder diagnostic record; it does not execute hardware checks. | Existing tests verify deterministic host collector/history behavior; agent tests use mocked Windows output. Neither test represents continuous endpoint monitoring or real diagnostics. |
| Logs and audit trail | Device events and account/system activity are persisted separately; administrators can search and filter both. | Tests verify failed-login auditing without saving submitted passwords, log persistence/search, invalid input handling, and database/setup failures. These are application audit records, not OS or web-server logs. |
| Roadmap features | Live telemetry and alerts, reports/exports, managed/signed agent deployment and updates, real diagnostics, MFA/recovery, and production deployment are future work. | Not implemented or claimed as passing; see `FEATURES_AND_FUTURE_WORK.md`. |

### Security and error-handling coverage

Tests exercise password hashing and policy enforcement, login failure handling/auditing, session CSRF checks, role and ownership boundaries, protected administrator accounts, and retention behavior. Missing/invalid CSRF-token rejection is not separately asserted. Agent enrollment uses an account-bound, hashed, expiring bearer token, atomically consumed with the device transaction; tests cover expiry, replay, and rejection of malformed/out-of-range inventory. Database constraints protect specification values and foreign keys. Database unavailability or missing seeded roles returns setup guidance (503); invalid registration/API operations return validation errors. HTTPS, rate limiting, penetration testing, production configuration, browser security, and database migration execution have not been assessed.

## User workflows and validation

- **Account:** visit registration, enter identity fields, a compliant password, and its confirmation; submit only after browser checks pass. The server repeats validation before storing a Werkzeug hash. Sign in, access authorized pages, and sign out. Validation includes required/length/format checks for identity fields, reserved/duplicate account checks, password complexity and confirmation, account status, and CSRF on writes.
- **Device:** sign in and either enter device details manually or generate a QR code. On the Windows device, scan the QR code, download and run the Python agent, review the listed specifications, enter the device name/type, and confirm before submission. The server validates the one-use token and inventory and stores the device, owner, specification, network address, and event history in one transaction. View details/history, search/filter, edit, archive/restore, or administrator soft-delete under the existing access rules. A diagnostic scan still adds placeholder history only.
- **Administration:** initialize roles and bootstrap admin, then create/edit/deactivate users, manage devices, and query audit events. User/device authorization is checked by Flask routes, not trusted to the browser.

Integration coverage includes expected success and rejection paths, persisted state, access boundaries, malformed/invalid operations, and missing database/setup handling. Client-side checks are usability aids only; server-side validation and authorization are authoritative.

## Database scope

The SQLAlchemy models and `schema.sql` define all 16 application tables. The test suite verifies ORM table initialization and exercises representative persisted account, device, network, diagnostic, enrollment-token, and audit records:

| Table(s) | Responsibility |
|---|---|
| `users` | Account identity, unique username/email, password hash, status, and timestamps. |
| `roles`, `permissions` | Role and permission definitions. |
| `user_roles`, `role_permissions` | Many-to-many account-role and role-permission associations. |
| `devices` | Device identity, owner/registrant, connectivity status, lifecycle state, and timestamps. |
| `device_registration_tokens` | SHA-256 token hashes, issuing user, expiry, use/revocation timestamps; unique tokens are one-use. |
| `device_specifications` | One-to-one CPU, RAM capacity/usage, storage devices/capacity/availability, GPU, motherboard brand, OS, adapter, and IP inventory. |
| `network_interfaces`, `network_observations` | Interface inventory and timestamped address/connection observations. |
| `network_records` | Timestamped device IP, subnet, gateway, DNS, and connectivity snapshots. |
| `diagnostic_runs`, `diagnostic_checks` | Diagnostic history and per-run check results. |
| `device_metrics` | Historical CPU, memory, storage, and network metrics; collection is not enabled. |
| `activity_logs` | Timestamped account/system actions with optional actor and entity reference. |
| `logs` | Device-linked events such as registration, edits, archiving, and diagnostic history. |

The models and schema define primary/foreign keys, unique usernames/emails/asset tags and associations, status and metric range checks, and query indexes. Devices require an owner and can have one specification plus network history/interfaces, diagnostic runs, metrics, and device logs; diagnostic runs can have multiple checks. The account-role and role-permission association tables implement RBAC. Foreign-key delete behavior retains account ownership constraints, while device-owned history cascades only on physical deletion. Application account deactivation and device archive/restore/soft-delete preserve rows and history. Connectivity status is distinct from active/archived/deleted lifecycle state.

**Database verification boundary:** integration tests use isolated SQLite databases. A read-only connection check to the configured local MySQL instance succeeded in the prior review, before this migration; no claim is made that the new table/columns have been applied to MySQL. `db.create_all()` creates missing tables but does not update existing ones. Back up existing data and apply the migration path for the starting schema: earlier project schemas may need `001`, `002` (if device event logs are absent), `004`, then `005`; the original XAMPP prototype requires `003`, `004`, then `005`. See `README.md` and `DATABASE_DESIGN.md`.

## Test results

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s device_monitoring_prototype\tests -v
```

**Result:** 20 integration tests passed. Coverage includes page rendering; environment/database configuration; ORM schema and RBAC initialization; account creation/login, hash storage, password policy, and registration feedback; administrator and standard-user permissions; device inventory, history, lifecycle transitions, and retained deletion; log persistence/search/pagination; collapsed admin categories; QR generation/download; token expiration/replay protection; mocked agent inventory parsing; specification validation/persistence; device ownership and registration history; failure handling; and sample data. Automated agent tests do not run PowerShell against physical hardware. Integration tests use disposable SQLite databases; the MySQL migration, real phone scanning, real Windows collection, browser automation, visual, accessibility, and cross-browser checks were not performed.

## Release follow-up

- Configure private `.env` values and verify `init-db`, account creation, and data persistence using the target XAMPP/MySQL installation.
- Back up existing databases and apply the migration appropriate to their current schema before initializing the updated app.
- Apply `migrations\005_qr_device_enrollment.sql` to current MySQL databases and set `PUBLIC_BASE_URL` to the reachable HTTPS application origin before issuing QR codes for remote devices. The enrolled computer needs Python 3 and network access to DevMonitor.
- Run browser, accessibility, and responsive-layout checks before deployment.
- Complete managed/signed agent delivery, live metrics, real diagnostics, alerts, reports, MFA/recovery, rate limiting, and production serving before relying on the system for production monitoring.
- Before deployment, replace the bootstrap admin credential, configure a persistent random `SECRET_KEY`, enable Secure cookies over HTTPS, and set up database backup/restore.
