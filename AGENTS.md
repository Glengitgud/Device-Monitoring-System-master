# AGENTS.md

## Project layout
- Main application package: `device_monitoring_prototype/`
- Flask entrypoint and routes: `device_monitoring_prototype/app.py`
- Data model and RBAC tables: `device_monitoring_prototype/models.py`
- Validation and CRUD service layer: `device_monitoring_prototype/services.py`
- Auth/email/TOTP helpers: `device_monitoring_prototype/authentication.py`
- Windows enrollment/diagnostic agent build logic: `device_monitoring_prototype/agent_builder.py`
- SQL schema and upgrades: `device_monitoring_prototype/schema.sql`, `device_monitoring_prototype/migrations/*.sql`
- Tests: `device_monitoring_prototype/tests/`

## Setup and run (Windows PowerShell)
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r device_monitoring_prototype\requirements.txt
Copy-Item device_monitoring_prototype\.env.example device_monitoring_prototype\.env
```

- Configure `device_monitoring_prototype/.env` before running (`DATABASE_URL` or `MYSQL_*`, plus `SECRET_KEY`, `TOTP_ENCRYPTION_KEY`, and mail settings).
- Start app using Flask module mode (do not run `app.py` directly):

```powershell
python -m flask --app device_monitoring_prototype.app init-db
python -m flask --app device_monitoring_prototype.app run
```

Useful CLI commands in `device_monitoring_prototype/app.py`:
```powershell
python -m flask --app device_monitoring_prototype.app create-admin
python -m flask --app device_monitoring_prototype.app seed-sample-data
python -m flask --app device_monitoring_prototype.app check-db
python -m flask --app device_monitoring_prototype.app check-mail
```

## Database and migration workflow
- New installs: create schema from `device_monitoring_prototype/schema.sql` or use `init-db` for model-backed creation.
- Existing installs: apply SQL migrations in order from `device_monitoring_prototype/migrations/` and do not reapply already-run `ALTER TABLE` scripts.
- `check-db` is read-only and used to validate table/column/index/constraint parity against models.
- Current schema includes additive auth upgrades in `009_email_and_totp_authentication.sql` and `010_gmail_email_verification.sql`.

## Authentication and security patterns
- Account registration flow is staged: email verification code first, then TOTP verification, then user creation (see `authentication.py`, `app.py`).
- New passwords are bcrypt-hashed; legacy Werkzeug hashes are still accepted for compatibility.
- CSRF is enforced on API writes; keep token handling aligned with existing routes and JS clients.
- Device and account operations are owner-scoped with administrator override checks in server-side logic.
- `TOTP_ENCRYPTION_KEY` protects stored authenticator secrets; rotating/loss can invalidate existing secrets.

## Device enrollment and diagnostics flow
- Standard users complete QR-based device verification before dashboard access.
- Enrollment tokens are short-lived, one-use, and hashed in storage.
- Agent binaries are built per enrollment by PyInstaller on a 64-bit Windows host.
- The agent is user-confirmed and performs one-time collection/diagnostics, not continuous monitoring.
- Enrollment and scan activity is persisted in `logs` and broader audit records in `activity_logs`.

## Frontend integration points
- Templates live in `device_monitoring_prototype/templates/` with `base.html` layout inheritance.
- Main static assets: `device_monitoring_prototype/static/css/style.css` and `device_monitoring_prototype/static/js/*.js`.
- Registration-specific behavior is implemented in `device_monitoring_prototype/static/js/register.js`.

## Testing
- Test framework is Python `unittest` (`device_monitoring_prototype/tests/test_database_integration.py`, `device_monitoring_prototype/tests/test_agent_builder.py`).
- Typical run command:

```powershell
python -m unittest discover -s device_monitoring_prototype/tests
```

## Implementation conventions in this repo
- Keep business/data validation in `services.py` when extending routes.
- Add schema changes through SQL migration files and reflect corresponding ORM updates in `models.py`.
- Preserve soft-delete/archive lifecycle behavior for devices and account status checks.
- Follow existing naming style: `snake_case` for functions/variables, `PascalCase` for classes.
- Reuse existing custom exception patterns from `services.py`/`authentication.py` for predictable error handling.
