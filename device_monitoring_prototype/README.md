# DevMonitor

DevMonitor is a Flask application for centralized end-user device inventory and diagnostics. It uses Flask-Login sessions, Werkzeug password hashes, Flask-SQLAlchemy, and the MySQL/MariaDB server included with XAMPP.

## Setup with XAMPP on Windows

1. Open the XAMPP Control Panel and start **Apache** and **MySQL**.
2. Open **http://localhost/phpmyadmin**, choose **New**, enter `devmonitor` as the database name, select `utf8mb4_unicode_ci`, and click **Create**. The app expects the database on `localhost:3306`.
3. From the repository root, copy `device_monitoring_prototype\.env.example` to `device_monitoring_prototype\.env`. The example uses XAMPP's common local default (`root` with no password); if your MySQL account differs, enter its credentials in `.env`. Set a long random `SECRET_KEY` and keep `.env` private.
4. From the repository root, create and activate a Python environment, then install the dependencies. The requirements file installs Flask, Flask-SQLAlchemy, PyMySQL, and the supporting packages:
   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r device_monitoring_prototype\requirements.txt
   ```
   To install the core database packages directly instead:
   ```powershell
   pip install Flask Flask-SQLAlchemy PyMySQL Flask-Login Werkzeug python-dotenv psutil cryptography qrcode
   ```
5. Create the tables and default RBAC roles/administrator, then start the app:
   ```powershell
   python -m flask --app device_monitoring_prototype.app init-db
   python -m flask --app device_monitoring_prototype.app run
   ```
6. Open **http://127.0.0.1:5000**. Public registration creates standard-user accounts only.

`init-db` calls `db.create_all()` for every SQLAlchemy model and is safe to rerun to create missing tables, but it does not alter existing tables. The read-only `check-db` command compares tables, columns, indexes, primary/unique keys, foreign keys, and check constraints with the application models and reports account/device/token row counts. The app also accepts a `DATABASE_URL`. Back up existing databases and apply the applicable migrations before initializing: use `migrations\001_database_integration.sql` for the older DevMonitor schema, or `migrations\003_upgrade_xampp_prototype.sql` for the original empty XAMPP prototype tables. Apply only the unapplied migrations appropriate to the existing schema: `004_device_lifecycle.sql`, `005_qr_device_enrollment.sql`, and `006_account_and_device_status_checks.sql`. Migration 006 is needed only when `check-db` reports missing status checks; fresh installs from `schema.sql` already include them. Migrations are one-time scripts, so do not reapply them. The current schema has a separate `activity_logs` table for broader account/system auditing.

`init-db` ensures the reserved `admin` account exists, is active, and has the Administrator role. Its bootstrap password is `admin123`; initialization resets it to that password so the system account remains recoverable. This development credential must be changed before deployment. The reserved account is excluded from user management and cannot be created through public registration. Use `create-admin` only when adding another administrator.

Active devices can be archived and restored from the **Archived Devices** page. The lifecycle state is stored separately from online/offline device status. Administrator delete actions mark a device as deleted without physically removing the device or its history; there is no hard-delete route.

Set `COOKIE_SECURE=true` when using HTTPS. The generated fallback session key is only suitable for local development; set a persistent `SECRET_KEY` for normal use. The app loads `device_monitoring_prototype\.env` before configuring SQLAlchemy, then connects lazily on the first database operation. `pool_pre_ping` checks pooled connections before reuse. Login and registration require a running MySQL server, valid credentials, an initialized schema, and seeded roles. Database errors return setup guidance; missing tables/columns are identified as schema/migration issues rather than reported as a network outage.

## Test sample data

After running `init-db`, add a sample user, device, network record, and linked device log. The command prompts twice for an 8-16 character password with at least one capital letter and one special character, and stores only its hash:

```powershell
python -m flask --app device_monitoring_prototype.app seed-sample-data
```

For code-based setup, the database initialization call is:

```python
from device_monitoring_prototype.app import app
from device_monitoring_prototype.models import db

with app.app_context():
    db.create_all()
```

## Features

- Account creation requires a matching confirmation and an 8-16 character password with at least one capital letter and one special character. Passwords are stored as Werkzeug hashes and Flask-Login manages sessions.
- RBAC roles are seeded by `init-db`; creating an administrator requires the CLI or another administrator.
- Device list and CRUD are owner-scoped; administrators can view/manage all accounts and devices.
- Signed-in users can create one-use QR codes for their account. Scanning starts a Python-based Windows device-agent download; the agent shows the exact requested hardware/software inventory and only submits it after the user confirms. Set `PUBLIC_BASE_URL` in `.env` to the reachable HTTPS origin when registering remote devices. The scanned computer needs Python 3 and network access to DevMonitor.
- QR tokens are random, expire after 30 minutes, are stored as SHA-256 hashes, and can register only one device. Treat QR codes and downloaded token-bound agents like temporary credentials. The agent does not run as a background service or collect continuous telemetry.
- Device registration saves a hardware specification and network snapshot; diagnostic actions save history entries. Deactivation and device removal are soft operations so historical records remain.
- Device changes and diagnostic requests create linked rows in `logs`; broader audit events are kept in `activity_logs`.
- API write requests use a session CSRF token.
- `python -m flask --app device_monitoring_prototype.app check-db` checks the live schema without changing data.

**Collection limitation:** manual device registration retains the existing best-effort Flask-host snapshot. QR enrollment performs a one-time, user-confirmed Windows inventory submission; it does not remotely execute code, run persistently, or perform real diagnostic checks. Real diagnostics and live monitoring remain future work.

## Database unavailable

If sign-in or registration fails, run `python -m flask --app device_monitoring_prototype.app check-db` from the repository root. Confirm MySQL is running, the `devmonitor` database and application user exist, and `device_monitoring_prototype\.env` contains valid settings. MySQL error 1045 means credentials were rejected; a missing table or column means the existing schema needs its documented migration. Back up existing data before migration. `init-db` creates missing tables and roles, but does not add columns or constraints to existing tables.

## Files

- `app.py` — Flask application, authentication, views, JSON CRUD endpoints, and CLI commands.
- `models.py` — SQLAlchemy tables and relationships.
- `services.py` — validated CRUD functions and history persistence.
- `device_agent.py` — Windows inventory script template personalized with a one-use enrollment token at download time.
- `system_info.py` — best-effort local host inventory.
- `schema.sql` — complete MySQL/MariaDB schema for new installations.
- `migrations\001_database_integration.sql` — one-time schema upgrade from the earlier design.
- `migrations\002_device_event_logs.sql` — device event log table for manual upgrades.
- `migrations\003_upgrade_xampp_prototype.sql` — upgrade the original empty XAMPP prototype tables.
- `migrations\004_device_lifecycle.sql` — add archive and retained soft-delete support to existing databases.
- `migrations\005_qr_device_enrollment.sql` — add QR tokens and extended specification storage to existing databases.
- `migrations\006_account_and_device_status_checks.sql` — add account and device status integrity checks.
- `DATABASE_DESIGN.md` — ERD summary, tables, relationships, and example SQL queries.
