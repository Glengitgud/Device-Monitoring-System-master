# Quality Assurance Report

**System:** Centralized End-User Device Monitoring and Diagnostic System (DevMonitor)
**Review date:** 2026-11-16
**Result:** The application integration suite passes against isolated SQLite databases. The configured local MariaDB instance was reachable; migrations 005 and 006 have been applied and the live schema passes `check-db`. Browser-level, physical Windows hardware, user acceptance, and performance testing remain outstanding.

## System scope

This report covers the user-facing pages, Flask routes and services, and the ORM/MySQL schema described in `FEATURES_AND_FUTURE_WORK.md`. Items identified as future work are not treated as delivered or passing.

| Area | Implemented behavior | QA coverage and limits |
|---|---|---|
| Startup and database connection | The app loads `device_monitoring_prototype\.env` before SQLAlchemy configuration, accepts `DATABASE_URL` or MySQL settings, uses `pool_pre_ping`, and connects lazily on database use. | Local configuration resolved to MariaDB at `localhost:3306`, database `devmonitor`; TCP and SQL connection succeeded. `DATABASE_URL` was unset; the configured account authenticated. The cause was schema drift, not a MySQL outage: the running app expected enrollment columns/table not present in the database. |
| User authentication and registration | Flask-Login sessions, standard-user registration, hashed passwords, password confirmation and complexity policy, login/logout, and activity auditing. | Tests cover account creation, login success/failure, password hashing/policy, duplicate/reserved accounts, CSRF, inactive status, and error responses. Browser workflows and production security testing have not run. The bootstrap `admin` / `admin123` credential is for local setup only. |
| Administrator privileges | RBAC-backed administrator access to user management, all device records, device/event history, and activity logs. Reserved/final administrator protections remain active. | Integration tests cover admin access boundaries, account changes, device CRUD, archive/restore/soft-delete, and log search. Browser interaction is not automated. |
| Device registration and CRUD | Manual device registration remains available; users can view and update authorized devices, while administrators can manage all devices. | Integration tests cover create/read/update, ownership checks, input validation, and history persistence. Live MySQL reads pass after migration; a destructive CRUD exercise was not run against production-like records. |
| Device monitoring and dashboard | The dashboard shows database-backed fleet counts and registered device inventory/status. Search, sort, pagination, and status filtering apply to returned devices. | Dashboard and device APIs render and query in integration tests. This is not continuous endpoint monitoring: live telemetry, automatic online detection, and real diagnostics are future work. Browser and load tests were not performed. |
| QR device enrollment | Signed-in users create account-linked QR codes with random, expiring, single-use registration tokens. Scanning opens the enrollment page and initiates the token-bound Windows agent download. | Tests cover authenticated generation, unique hashed tokens, SVG output, expiry, replay rejection, and device ownership. Real phone scanning and browser auto-download behavior remain unverified. |
| Device detection agent | The Windows Python agent detects only the 13 requested CPU, RAM, storage, GPU, motherboard, OS, network adapter, and IP fields; it displays them for review and requires confirmation before submission. | Mocked PowerShell output verifies the allowlist and parser. Actual Windows hardware collection and compatibility are unverified. |
| Specifications and registration history | Agent-confirmed specifications, account/device links, registration/update timestamps, status, and device event history are persisted and shown to authorized users/admins. | SQLite integration tests verify persistence, access control, details/history rendering, and token replay protection. The live migrated database was checked read-only and currently has four devices/specification rows and zero enrollment-token rows. |
| Archive, restore, and delete | Archive/restore changes lifecycle state; administrator delete is a retained soft delete. Account deactivation and device event history preserve records. | Integration tests verify transitions and retention. There is no hard-delete API. The current MySQL dataset contains no archived devices. |
| Search, filter, and admin categories | Device search/status filtering; administrator user, activity, and device-log categories load on expansion and initially show ten rows with a show-more control. | API tests cover search/filter and pagination; markup and a JavaScript behavior check cover collapsed loading and expansion. Real-browser interaction is outstanding. |
| Database operations and integrity | SQLAlchemy models and `schema.sql` define 16 tables. `check-db` validates expected tables, columns, indexes, primary/unique keys, foreign keys, and check constraints, and reports key row counts without modifying data. | Migrations 005 and 006 were backed up, applied to the configured local MariaDB, and verified. `check-db` reports 16/16 tables, no schema mismatches, and 7 users, 4 devices, 4 specification rows, and 0 QR tokens; all prior user/device/specification counts were preserved. Foreign-key orphan checks returned zero. These results apply only to this local database. |
| Security and error handling | Password hashing, CSRF, session cookies, server-side role/ownership checks, expiring one-use tokens, inventory validation, and database error handling. Missing schema, rejected credentials, missing database, and general connection failures now receive distinct guidance without logging credentials. | Integration tests cover policy, permissions, token replay/expiry, malformed inventory, and database/setup errors. HTTPS deployment, rate limiting, penetration testing, and resilience under database downtime have not been independently assessed. |
| User acceptance testing | Intended workflows include account creation/sign-in, manual and QR registration, reviewing agent inventory, device search/detail, archive/restore, and administrator review. | **Not performed.** Requires representative users and browser/Windows hardware; integration tests are not a substitute for acceptance testing. |
| Performance testing | No throughput, response-time, concurrency, or large-fleet performance claims are made. | **Not performed.** Establish representative data volumes and response-time targets before a production benchmark. |
| Roadmap features | Continuous telemetry, real diagnostics, alerts, reports/exports, managed/signed agent updates, MFA/recovery, rate limiting, and production deployment remain future work. | Not implemented or claimed as passing; see `FEATURES_AND_FUTURE_WORK.md`. |

## Database outage investigation and recovery

The configured `.env` was loaded from the application directory before SQLAlchemy initialization. `DATABASE_URL` was unset; the effective local target was `localhost:3306/devmonitor`, using the configured `root` account with an empty password. The TCP listener and SQL login both succeeded against MariaDB 10.4.32. The password itself is not recorded here. This local XAMPP-style account is not appropriate for a shared or production deployment; configure a dedicated least-privilege MySQL account with a strong secret.

The outage message was misleading: MySQL was running, but the live database had only 15 tables and lacked the new QR token table and specification columns expected by the app. Existing device-list/specification queries therefore failed with missing-table/column errors. `init-db` could not repair this because `db.create_all()` does not alter existing tables. The database connection string format and `pool_pre_ping` were working as configured; connections are initialized lazily on the first database operation.

Before migration, a full database dump was stored outside the repository. The additive migrations `005_qr_device_enrollment.sql` and `006_account_and_device_status_checks.sql` were applied after verifying the existing account/device status values. Afterwards, `check-db` reported 16 expected tables and no missing columns, indexes, foreign keys, or check constraints. Users (7), devices (4), and device specifications (4) retained their pre-migration counts; no archived devices or QR tokens were present. Foreign-key orphan checks returned zero. The application now distinguishes common connection/credential/database-name errors from missing-schema errors and avoids logging credentials.

### Security and error-handling coverage

Tests exercise password hashing and policy enforcement, login failure handling/auditing, session CSRF checks, role and ownership boundaries, protected administrator accounts, and retention behavior. Agent enrollment uses an account-bound, hashed, expiring bearer token, atomically consumed with the device transaction; tests cover expiry, replay, and rejection of malformed/out-of-range inventory. Database constraints protect status/specification values and relationships. Database failures return 503 guidance that distinguishes connection problems from schema mismatch; `check-db` validates model structure and key counts without writes. HTTPS, rate limiting, penetration testing, production configuration, browser security, and full outage recovery remain unverified.

## User workflows and validation

- **Account:** visit registration, enter identity fields, a compliant password, and its confirmation; submit only after browser checks pass. The server repeats validation before storing a Werkzeug hash. Sign in, access authorized pages, and sign out. Validation includes required/length/format checks for identity fields, reserved/duplicate account checks, password complexity and confirmation, account status, and CSRF on writes.
- **Device:** sign in and either enter device details manually or generate a QR code. On the Windows device, scan the QR code, download and run the Python agent, review the listed specifications, enter the device name/type, and confirm before submission. The server validates the one-use token and inventory and stores the device, owner, specification, network address, and event history in one transaction. View details/history, search/filter, edit, archive/restore, or administrator soft-delete under the existing access rules. A diagnostic scan still adds placeholder history only.
- **Administration:** initialize roles and bootstrap admin, then create/edit/deactivate users, manage devices, and query audit events. User/device authorization is checked by Flask routes, not trusted to the browser.

Integration coverage includes expected success and rejection paths, persisted state, access boundaries, malformed/invalid operations, and missing database/setup handling. Client-side checks are usability aids only; server-side validation and authorization are authoritative.

## Database scope

The SQLAlchemy models and `schema.sql` define all 16 application tables. Integration tests verify ORM initialization and representative persisted account, device, network, diagnostic, enrollment-token, and audit records. On the configured local MariaDB, `check-db` verified all 16 tables, declared columns, indexes, primary/unique keys, foreign keys, and check constraints after migrations 005 and 006. A read-only orphan check found no broken foreign-key records:

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

**Database verification boundary:** integration tests use isolated SQLite. The local MariaDB migration preserved counts of 7 users, 4 devices, and 4 specification rows; there are currently no archived devices or QR-token rows. The migration backup was stored outside the repository. This does not establish that another machine's credentials, data, or schema are valid. `db.create_all()` creates missing tables but does not update existing ones. Back up existing data and apply the migration path for the starting schema: earlier project schemas may need `001`, `002` (if device event logs are absent), `004`, `005`, and `006`; the original XAMPP prototype requires `003`, `004`, `005`, and `006`. See `README.md` and `DATABASE_DESIGN.md`.

## Test results

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s device_monitoring_prototype\tests -v
```

**Result:** 23 integration tests passed. Coverage includes page rendering; environment/database configuration and URI escaping; schema, indexes, foreign keys, check constraints, and RBAC initialization; account creation/login, password hashing/policy, and feedback; administrator and standard-user permissions; device CRUD, history, lifecycle transitions, and retained deletion; log persistence/search/pagination; collapsed admin categories; QR generation/download; token expiration/replay protection; mocked agent inventory parsing; specification validation/persistence; and database failure guidance. The live MariaDB schema and row counts were also validated after migrations 005 and 006. Automated agent tests do not run PowerShell against physical hardware. Real phone scanning, live Windows collection, browser automation, accessibility/visual checks, user acceptance, and performance testing were not performed.

## Release follow-up

- Configure private `.env` values and run `python -m flask --app device_monitoring_prototype.app check-db` against each target database before use.
- Back up existing databases and apply the migration sequence appropriate to their current schema before initializing the updated app.
- Apply any unapplied migrations required by the target schema. Set `PUBLIC_BASE_URL` to the reachable HTTPS application origin before issuing QR codes for remote devices. The enrolled computer needs Python 3 and network access to DevMonitor.
- Run user acceptance, browser/accessibility, responsive-layout, and performance tests with representative users and data before deployment.
- Complete managed/signed agent delivery, live metrics, real diagnostics, alerts, reports, MFA/recovery, rate limiting, and production serving before relying on the system for production monitoring.
- Before deployment, replace the bootstrap admin credential, configure a persistent random `SECRET_KEY`, enable Secure cookies over HTTPS, and set up database backup/restore.
