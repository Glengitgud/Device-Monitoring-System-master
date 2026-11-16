# Quality Assurance Report

**System:** Centralized End-User Device Monitoring and Diagnostic System (DevMonitor)
**Review date:** 2026-11-16
**Result:** Application integration tests pass against isolated SQLite databases. A live XAMPP/MySQL deployment and browser-level checks remain to be verified.

## System scope

This report covers the user-facing pages, Flask routes and services, and the ORM/MySQL schema described in `FEATURES_AND_FUTURE_WORK.md`. Items identified as future work are not treated as delivered or passing.

| Area | Implemented behavior | QA coverage and limits |
|---|---|---|
| Startup and configuration | Flask app, environment-file loading, database URL configuration, setup guidance for unavailable databases. | Tests check environment-file selection, the default XAMPP/MySQL URL, initialization, and database/seed-data error responses. Actual local MySQL credentials and connectivity were not tested. |
| Account creation and sign-in | Public registration creates standard-user accounts; passwords are Werkzeug hashes. New passwords must be 8–16 characters, include a capital letter and a special character, and match the confirmation field. Registration JavaScript shows validation alerts, while the server independently enforces the same policy for public, administrator-created, and CLI-created accounts. | Integration tests cover registration, hashed-password login, policy boundaries, invalid passwords, confirmation mismatch, and rendering the registration validator and confirmation input. Failed-login auditing and administrator account recovery are also covered. Browser automation has not been run. The reserved development `admin` / `admin123` bootstrap account is an explicit exception; replace its credential before deployment. |
| Sessions and request security | Flask-Login sessions, CSRF checks on writes, HttpOnly/SameSite cookies, configurable Secure cookies, and server-side authorization. | Route and access-boundary checks run in integration tests. Rate limiting and production HTTPS are not implemented or tested. |
| Roles and administration | Seeded Administrator/User roles and permissions; administrator account creation, editing, deactivation, and log search/filtering. The reserved admin and final active administrator are protected. | Tests cover initialization, administrator access, user management, log queries, and role/status protections. |
| Device inventory and ownership | Owners/registrants register, edit, view, archive, and restore devices; administrators can manage all devices. Standard-user detail responses expose approved fields only. | Tests cover registration and persistence, owner boundaries, role-specific details, and administrative device management. |
| Device lifecycle and history | Connectivity and lifecycle status are separate. Archive/restore and administrator soft-delete retain device records and history; account deactivation retains account records. | Tests verify lifecycle transitions, authorization, and retained rows/history. There is no application hard-delete route. |
| Dashboard and device UI | Database-backed fleet summary; device search, sorting, pagination, action dialogs, and feedback. | Routes and APIs are tested. Automated browser, accessibility, responsive-device, and cross-browser checks have not been run. |
| Host inventory and diagnostics | Registration records best-effort hardware/network details from the Flask host. A scan appends an explicitly placeholder diagnostic record. | Tests use deterministic collector values and verify history persistence. This is not remote endpoint collection; GPU/motherboard data may be unavailable, and scans do not run hardware checks. |
| Logs and audit trail | Device events are stored separately from account/system activity events. Administrators can search and filter application logs. | Persistence and search/filter behavior are tested. These are application audit records, not operating-system or web-server logs. |
| Roadmap features | Live telemetry and alerts, reports/exports, endpoint agents, real diagnostics, MFA/recovery, and production deployment are future work. | Not implemented or claimed as passing; see `FEATURES_AND_FUTURE_WORK.md`. |

## Database scope

The SQLAlchemy models and `schema.sql` define all 15 application tables:

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

The models and schema define the primary and foreign keys, uniqueness rules, status and metric checks, and lookup indexes. Devices belong to an account and can have specifications, network history and interfaces, diagnostic runs, metrics, and device logs; diagnostic runs can have multiple checks. The account-role and role-permission associations implement RBAC. Account deactivation and device lifecycle changes retain their records. Connectivity status is distinct from active/archived/deleted lifecycle state.

**Database verification boundary:** the test suite uses isolated SQLite databases. It does not establish XAMPP/MySQL connectivity, MySQL DDL or migration compatibility, database permissions, or persistence after a MySQL restart. `db.create_all()` creates missing tables but does not update existing ones. Back up existing data and apply the migration path for the starting schema: earlier project schemas may need `001`, `002` (if device event logs are absent), and `004`; the original XAMPP prototype requires `003` and `004`. See `README.md` and `DATABASE_DESIGN.md`.

## Test results

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s device_monitoring_prototype\tests -v
```

**Result:** 16 integration tests passed. Coverage includes page rendering, environment/database configuration, ORM schema and RBAC initialization, account creation/login and password policy, admin and standard-user permissions, device inventory and lifecycle transitions, history/log persistence and filtering, and sample data. Tests use disposable SQLite databases; no production database, browser automation, or visual/accessibility testing was performed.

## Release follow-up

- Configure private `.env` values and verify `init-db`, account creation, and data persistence using the target XAMPP/MySQL installation.
- Back up existing databases and apply the migration appropriate to their current schema before initializing the updated app.
- Run browser, accessibility, and responsive-layout checks before deployment.
- Implement and verify endpoint agents, live metrics, real diagnostics, alerts, reports, MFA/recovery, rate limiting, and production serving before relying on the system for production monitoring.
- Before deployment, replace the bootstrap admin credential, configure a persistent random `SECRET_KEY`, enable Secure cookies over HTTPS, and set up database backup/restore.
