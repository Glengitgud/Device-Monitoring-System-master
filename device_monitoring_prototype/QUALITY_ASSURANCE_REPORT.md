# Quality Assurance Report

**System:** Centralized End-User Device Monitoring and Diagnostic System (DevMonitor)
**Review date:** 2026-11-16
**Result:** 17 application integration tests pass against isolated SQLite databases. The configured local MySQL database was also reachable during this review, with all 15 tables and both RBAC roles present; a different deployment or intermittent connection failure may still require separate diagnosis. Browser-level checks remain to be verified.

## System scope

This report covers the user-facing pages, Flask routes and services, and the ORM/MySQL schema described in `FEATURES_AND_FUTURE_WORK.md`. Items identified as future work are not treated as delivered or passing.

| Area | Implemented behavior | QA coverage and limits |
|---|---|---|
| Startup and configuration | Flask app, environment-file loading, database URL configuration, CLI initialization/seed-data commands, and setup guidance when the database or seed roles are unavailable. | Tests cover environment selection, default XAMPP/MySQL URL, initialization, sample data, and database/seed-data error responses. The configured local MySQL connection and current schema were verified read-only; other credentials, deployments, migration paths, and recovery remain unverified. |
| Account creation and sign-in | Public registration creates standard-user accounts; passwords are Werkzeug hashes. New passwords must be 8–16 characters, include an A-Z uppercase letter and a special character, and match the confirmation field. Registration JavaScript shows validation and success alerts; the server independently enforces policy for public, administrator-created, and CLI-created accounts. | Integration tests cover registration, hashed-password login, policy boundaries, invalid passwords, confirmation mismatch, and registration feedback markup. Failed-login auditing and administrator account recovery are also covered. Browser automation has not been run. The reserved development `admin` / `admin123` bootstrap account is an explicit exception; replace its credential before deployment. |
| Sessions and request security | Flask-Login sessions, CSRF checks on writes, HttpOnly/SameSite cookies, configurable Secure cookies, and server-side authorization. | Integration tests exercise authenticated/unauthenticated routes and user/device access boundaries. This is not a penetration test; rate limiting, production HTTPS, and external security testing are not implemented or verified. |
| Roles and administration | Seeded Administrator/User roles and permissions; administrator account creation, editing, deactivation, and log search/filtering. User accounts, activity logs, and device logs are separate collapsed categories, fetched when opened, and display ten rows initially with a show-more control. The reserved admin and final active administrator are protected. | Integration tests cover initialization, administrator access, user management, paginated log queries, role/status protections, and collapsed category markup. An isolated JavaScript behavior check verified deferred requests and ten-row expansion; real-browser interaction is not automated. |
| Device inventory and ownership | Owners/registrants register, edit, and view devices; administrators can manage all devices. Standard-user detail responses expose approved fields only. | Tests cover device registration/persistence, owner boundaries, administrator access, details, and API error responses. |
| Device lifecycle and history | Connectivity and lifecycle status are separate. Archive/restore and administrator soft-delete retain device records and history; account deactivation retains account records. | Tests verify lifecycle transitions, authorization, and retained rows/history. There is no application hard-delete route. |
| Dashboard and device UI | Database-backed fleet summary, device and archived-device views, browser-side search/sort/pagination, action dialogs, and feedback. | Page/API integration checks run; automated browser interaction, accessibility, responsive-layout, and cross-browser checks have not run. |
| Host inventory and diagnostics | Registration records best-effort hardware/network details from the Flask host. A scan appends an explicitly placeholder diagnostic record. | Tests use deterministic collector values and verify history persistence. This is not remote endpoint collection; GPU/motherboard data may be unavailable, and scans do not run hardware checks. |
| Logs and audit trail | Device events and account/system activity are persisted separately; administrators can search and filter both. | Tests verify failed-login auditing without saving submitted passwords, log persistence/search, invalid input handling, and database/setup failures. These are application audit records, not OS or web-server logs. |
| Roadmap features | Live telemetry and alerts, reports/exports, endpoint agents, real diagnostics, MFA/recovery, and production deployment are future work. | Not implemented or claimed as passing; see `FEATURES_AND_FUTURE_WORK.md`. |

### Security and error-handling coverage

Tests exercise password hashing and policy enforcement, login failure handling/auditing, writes using valid CSRF tokens, role and ownership boundaries, protected administrator accounts, and retention behavior. Missing/invalid CSRF-token rejection is not separately asserted. Input-validation tests reject invalid password length/complexity, confirmation mismatch, duplicate/reserved usernames, invalid user/device data, and invalid log filters. Database unavailability or missing seeded roles returns setup guidance (503) rather than a generic 500; invalid registration/API operations return validation errors. No penetration, dependency, production-configuration, or browser security assessment has been performed.

## User workflows and validation

- **Account:** visit registration, enter identity fields, a compliant password, and its confirmation; submit only after browser checks pass. The server repeats validation before storing a Werkzeug hash. Sign in, access authorized pages, and sign out. Validation includes required/length/format checks for identity fields, reserved/duplicate account checks, password complexity and confirmation, account status, and CSRF on writes.
- **Device:** sign in, register a device (saving device, owner, host snapshot, network record, and event history), then view/edit it within owner/administrator access rules. Archive and restore retain the device; administrator soft-delete also retains it. A scan adds placeholder diagnostic history only.
- **Administration:** initialize roles and bootstrap admin, then create/edit/deactivate users, manage devices, and query audit events. User/device authorization is checked by Flask routes, not trusted to the browser.

Integration coverage includes expected success and rejection paths, persisted state, access boundaries, malformed/invalid operations, and missing database/setup handling. Client-side checks are usability aids only; server-side validation and authorization are authoritative.

## Database scope

The SQLAlchemy models and `schema.sql` define all 15 application tables. The current test suite verifies ORM table initialization and exercises representative persisted account, device, network, diagnostic, and audit records:

| Table(s) | Responsibility |
|---|---|
| `users` | Account identity, unique username/email, password hash, status, and timestamps. |
| `roles`, `permissions` | Role and permission definitions. |
| `user_roles`, `role_permissions` | Many-to-many account-role and role-permission associations. |
| `devices` | Device identity, owner/registrant, connectivity status, lifecycle state, and timestamps. |
| `device_specifications` | One-to-one hardware and operating-system snapshot. |
| `network_interfaces`, `network_observations` | Interface inventory and timestamped address/connection observations. |
| `network_records` | Timestamped device IP, subnet, gateway, DNS, and connectivity snapshots. |
| `diagnostic_runs`, `diagnostic_checks` | Diagnostic history and per-run check results. |
| `device_metrics` | Historical CPU, memory, storage, and network metrics; collection is not enabled. |
| `activity_logs` | Timestamped account/system actions with optional actor and entity reference. |
| `logs` | Device-linked events such as registration, edits, archiving, and diagnostic history. |

The models and schema define primary/foreign keys, unique usernames/emails/asset tags and associations, status and metric range checks, and query indexes. Devices require an owner and can have one specification plus network history/interfaces, diagnostic runs, metrics, and device logs; diagnostic runs can have multiple checks. The account-role and role-permission association tables implement RBAC. Foreign-key delete behavior retains account ownership constraints, while device-owned history cascades only on physical deletion. Application account deactivation and device archive/restore/soft-delete preserve rows and history. Connectivity status is distinct from active/archived/deleted lifecycle state.

**Database verification boundary:** integration tests use isolated SQLite databases. A read-only connection check to the configured local MySQL instance succeeded for this review and confirmed the expected tables and roles; this does not establish compatibility of every migration path, production permissions, or persistence after a MySQL restart. `db.create_all()` creates missing tables but does not update existing ones. Back up existing data and apply the migration path for the starting schema: earlier project schemas may need `001`, `002` (if device event logs are absent), and `004`; the original XAMPP prototype requires `003` and `004`. See `README.md` and `DATABASE_DESIGN.md`.

## Test results

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s device_monitoring_prototype\tests -v
```

**Result:** 17 integration tests passed. Coverage includes page rendering; environment/database configuration; ORM schema and RBAC initialization; account creation/login, hash storage, password policy, and registration feedback; administrator and standard-user permissions; device inventory, history, lifecycle transitions, and retained deletion; log persistence/search/pagination; collapsed admin categories; failure handling; and sample data. An isolated JavaScript check also verified that admin data is not fetched until a category opens and that each category reveals ten additional rows per action. Integration tests use disposable SQLite databases; real-browser automation, visual, accessibility, and cross-browser checks were not performed.

## Release follow-up

- Configure private `.env` values and verify `init-db`, account creation, and data persistence using the target XAMPP/MySQL installation.
- Back up existing databases and apply the migration appropriate to their current schema before initializing the updated app.
- Run browser, accessibility, and responsive-layout checks before deployment.
- Implement and verify endpoint agents, live metrics, real diagnostics, alerts, reports, MFA/recovery, rate limiting, and production serving before relying on the system for production monitoring.
- Before deployment, replace the bootstrap admin credential, configure a persistent random `SECRET_KEY`, enable Secure cookies over HTTPS, and set up database backup/restore.
