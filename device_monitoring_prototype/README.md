# DevMonitor

DevMonitor is a Flask application for centralized end-user device inventory and diagnostics. It uses Flask-Login sessions, Werkzeug password hashes, Flask-SQLAlchemy, and the MySQL/MariaDB server included with XAMPP. Public account registration requires an email code and Google Authenticator code before the user record is created.

## Setup with XAMPP on Windows

1. Open the XAMPP Control Panel and start **Apache** and **MySQL**.
2. Open **http://localhost/phpmyadmin**, choose **New**, enter `devmonitor` as the database name, select `utf8mb4_unicode_ci`, and click **Create**. The app expects the database on `localhost:3306`.
3. From the repository root, copy `device_monitoring_prototype\.env.example` to `device_monitoring_prototype\.env`. The example uses XAMPP's common local default (`root` with no password); if your MySQL account differs, enter its credentials in `.env`. Set persistent random values for `SECRET_KEY` and `TOTP_ENCRYPTION_KEY` and keep `.env` private. For Gmail, use `smtp.gmail.com`, port `587`, `MAIL_USE_TLS=true`, the sender Gmail address as `MAIL_USERNAME` and `MAIL_DEFAULT_SENDER`, and a Google App Password (not the normal account password) as `MAIL_PASSWORD`. Never commit or share `.env`.
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
5. Create the tables and default RBAC roles/administrator, test Gmail SMTP configuration, then start the app:
   ```powershell
   python -m flask --app device_monitoring_prototype.app init-db
   python -m flask --app device_monitoring_prototype.app check-mail
   python -m flask --app device_monitoring_prototype.app run
   ```
6. Open **http://127.0.0.1:5000**. Public registration creates standard-user accounts only.

`init-db` calls `db.create_all()` for every SQLAlchemy model and is safe to rerun to create missing tables, but it does not alter existing tables. It adds any missing default roles/permissions and the reserved administrator account, while preserving existing account credentials and status. The read-only `check-db` command compares tables, columns, indexes, primary/unique keys, foreign keys, and check constraints with the application models, checks for orphaned foreign-key records, and reports account/device/token row counts without changing data. The app also accepts a `DATABASE_URL`. Back up existing databases before applying migrations. Use `migrations\001_database_integration.sql` for the older DevMonitor schema, or `migrations\003_upgrade_xampp_prototype.sql` for the original XAMPP prototype tables, then apply only the remaining migrations appropriate to the current schema through `010_gmail_email_verification.sql`. Migration 006 is needed only when `check-db` reports missing status checks; fresh installs from `schema.sql` already include them. Migrations 007-010 are additive and preserve existing records; migration 009 marks existing accounts as email-verified for compatibility, while 010 adds a hashed-code `email_verifications` table and changes only the default for new accounts to unverified. Migrations are one-time scripts; inspect the schema first and never reapply an already-applied `ALTER TABLE` migration. The current schema has a separate `activity_logs` table for broader account/system auditing.

For an existing XAMPP database, make a backup before applying a migration. Run these examples from **Command Prompt** (if MySQL requires a password, append `--password` to prompt securely):

```bat
C:\xampp\mysql\bin\mysqldump.exe --host=localhost --port=3306 --user=root --single-transaction --routines --triggers devmonitor > devmonitor-backup.sql
C:\xampp\mysql\bin\mysql.exe --host=localhost --port=3306 --user=root --database=devmonitor < device_monitoring_prototype\migrations\010_gmail_email_verification.sql
python -m flask --app device_monitoring_prototype.app check-db
```

On a new installation, `init-db` creates the reserved `admin` account with the bootstrap password `admin123` and the Administrator role. Re-running initialization does not reset an existing password or status; use the supported account-management process to change those values. This development credential must be changed before deployment. The reserved account is excluded from user management and cannot be created through public registration. Use `create-admin` only when adding another administrator.

Active devices can be archived and restored from the **Archived Devices** page. The lifecycle state is stored separately from online/offline device status. Administrator delete actions mark a device as deleted without physically removing the device or its history; there is no hard-delete route.

Set `COOKIE_SECURE=true` when using HTTPS. Set persistent random `SECRET_KEY` and `TOTP_ENCRYPTION_KEY` values; losing or rotating `TOTP_ENCRYPTION_KEY` makes stored authenticator secrets unreadable. The app loads `device_monitoring_prototype\.env` before configuring SQLAlchemy, then connects lazily on the first database operation. `pool_pre_ping` checks pooled connections before reuse. Login and registration require a running MySQL server, valid credentials, an initialized schema, and seeded roles. Database errors return setup guidance; missing tables/columns are identified as schema/migration issues rather than reported as a network outage. Public registration stores a bcrypt password hash and requires a six-digit Gmail verification code (5-minute expiry; hashed at rest; single-use; resend cooldown and rate limits) before Google Authenticator setup and account creation. Existing Werkzeug password hashes continue to verify, and existing verified accounts retain access. Standard users must complete QR-based device verification before dashboard access; administrator dashboard access is unaffected.

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

- Account creation requires a matching confirmation and an 8-16 character password with at least one capital letter and one special character. The flow sends a six-digit Gmail code (5-minute expiry, HMAC-hashed at rest, attempt limits, 60-second resend cooldown and per-hour limits), then shows a Google Authenticator QR and requires a valid TOTP code. No user account is created until both checks succeed. New passwords use bcrypt; existing Werkzeug hashes remain supported.
- RBAC roles are seeded by `init-db`; creating an administrator requires the CLI or another administrator.
- Device list and CRUD are owner-scoped; administrators can view/manage all accounts and devices.
- Account registration verifies email first, then displays a responsive TOTP QR in the required setup popup. The secret is stored encrypted and is not shown as text; after the current code is verified, the account is created and signed in. TOTP-enabled users must complete a second-factor challenge after password sign-in. Existing accounts remain compatible as verified, with 2FA enabled when configured.
- After successful account creation, standard users can issue a one-use 30-minute device-enrollment QR code from Device Verification. Scanning opens a verification page; the user explicitly verifies the account and confirms trust before the Windows Device Agent download is served. The agent displays detected specifications and submits them only after user approval. Successful QR enrollment links and verifies the device and unlocks dashboard access. Administrators retain dashboard access but cannot use user verification or device registration. Set `PUBLIC_BASE_URL` in `.env` to a reachable HTTPS origin for remote scans; `localhost` only works on the computer running DevMonitor. The target computer needs Windows, Python 3, and network access to DevMonitor.
- QR tokens are random, expire after 30 minutes, are stored as SHA-256 hashes, and can register only one device. Treat QR codes and downloaded token-bound agents like temporary credentials. The agent does not run as a background service or collect continuous telemetry.
- Device registration saves a hardware specification and network snapshot; diagnostic actions save history entries. Deactivation and device removal are soft operations so historical records remain.
- Device changes and diagnostic requests create linked rows in `logs`; broader audit events are kept in `activity_logs`.
- API write requests use a session CSRF token.
- `python -m flask --app device_monitoring_prototype.app check-db` checks the live schema without changing data.
- `python -m flask --app device_monitoring_prototype.app check-mail` validates SMTP TLS connectivity and authentication without sending a message.

**Collection limitation:** manual device registration retains the existing best-effort Flask-host snapshot. QR enrollment performs a one-time, user-confirmed Windows inventory submission; it does not remotely execute code, run persistently, or perform real diagnostic checks. Real diagnostics and live monitoring remain future work.

## Database unavailable

If sign-in or registration fails, run `python -m flask --app device_monitoring_prototype.app check-db` from the repository root. Confirm the MySQL-compatible server is running (for XAMPP, check the XAMPP MySQL module; a stopped Windows `MySQL80` service does not indicate that XAMPP MariaDB is stopped), the `devmonitor` database and application user exist, and `device_monitoring_prototype\.env` contains valid settings. Error 1045 means credentials were rejected; a missing table or column means the existing schema needs its documented migration. Back up existing data before migration, apply only migrations absent from the live schema, then rerun `check-db`. `init-db` creates missing tables and roles, but does not add columns or constraints to existing tables.

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
- `migrations\007_device_verification.sql` — add a default-false verification flag to existing devices.
- `migrations\008_registration_verification_steps.sql` — store QR account-verification and explicit agent-download confirmation timestamps.
- `migrations\009_email_and_totp_authentication.sql` — add verified-email/TOTP account fields and staged registration challenges.
- `migrations\010_gmail_email_verification.sql` — add hashed, single-use email verification records and default new accounts to unverified.
- `authentication.py` — email-code delivery, challenge validation, TOTP verification, QR provisioning, and secret encryption.
- `DATABASE_DESIGN.md` — ERD summary, tables, relationships, and example SQL queries.
