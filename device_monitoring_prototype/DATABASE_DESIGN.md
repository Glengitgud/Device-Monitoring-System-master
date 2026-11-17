# Database and backend design

## ERD and relationships

- `users` own zero or more `devices`; each device created by the application has exactly one owner.
- `registration_challenges` temporarily stage registration data before the `users` row exists; successful email and TOTP checks create the user and mark the challenge completed.
- `email_verifications` stores HMAC-digested, short-lived, single-use codes linked to a registration challenge.
- `users` may issue one-use `device_registration_tokens`; a successfully consumed token is linked to exactly one registered device through its owner and event history.
- `devices` have one `device_specifications` row and many `network_records` and `diagnostic_runs`.
- `devices` have many `logs`; deleting a device cascades to its device event history.
- Each `diagnostic_run` can have multiple detailed `diagnostic_checks`.
- `users` ↔ `roles` use `user_roles`; `roles` ↔ `permissions` use `role_permissions`.
- `activity_logs` retain the acting user when available and record account/device/diagnostic events.
- Account removal is a status change. Device lifecycle (`active`, `archived`, `deleted`) is separate from connectivity status; archive/restore and administrator soft delete preserve the device row and all history.

## Tables

| Table | Contents |
|---|---|
| `users` | Full name, unique username/email, Werkzeug password hash, email verification state, encrypted TOTP secret/state, status, timestamps |
| `registration_challenges` | Staged account data, password hash, HMAC-hashed email code, code/challenge expiry, verification timestamps, attempt counters, resend limit state |
| `email_verifications` | Email, HMAC-digested six-digit code, 5-minute expiry, verified/used state, creation and use timestamps |
| `roles`, `permissions` | RBAC roles and permission codes |
| `user_roles`, `role_permissions` | RBAC many-to-many associations |
| `devices` | Device identity, owner/registrant, connectivity status, active/archive/delete lifecycle, and lifecycle timestamps |
| `logs` | Device-linked event text and timestamp for registration, edits, archives, and diagnostic history |
| `device_registration_tokens` | Hashed one-use QR token, issuing account, expiration, use, and revocation timestamps |
| `device_specifications` | CPU/cores, RAM capacity/usage, storage devices/capacity/availability, GPU, motherboard brand, OS, adapter names, IP addresses |
| `network_records` | Timestamped IP, subnet mask, gateway, DNS server, connectivity status |
| `network_interfaces`, `network_observations` | Optional lower-level interface/observation inventory retained from the initial design |
| `diagnostic_runs` | Per-scan result, problem, recommendation, initiator, and timestamp |
| `diagnostic_checks` | Individual result records for checks within a diagnostic run |
| `device_metrics` | Historical CPU, memory, storage, and network metrics (not currently collected) |
| `activity_logs` | Auditable account and system actions for administrator oversight |

`schema.sql` creates the full MySQL/MariaDB schema from scratch. Existing databases created from the earlier project design must first be backed up and upgraded with `migrations/001_database_integration.sql`. The original XAMPP prototype schema has a separate upgrade, `migrations/003_upgrade_xampp_prototype.sql`; back up first and use it only when the legacy `users`, `devices`, and `logs` tables are empty. Apply only the unapplied migrations required by the current schema (`004_device_lifecycle.sql` through `010_gmail_email_verification.sql`), including `006_account_and_device_status_checks.sql` only when `check-db` reports missing status checks. Migration 009 preserves existing account access and adds the staged-registration and TOTP fields. Migration 010 creates `email_verifications` and changes the default for new `users.email_verified` values to false without changing existing rows. These are one-time scripts; fresh installs already contain the declared schema. Then run `flask --app device_monitoring_prototype.app init-db` to create missing tables and seed roles and permissions. `flask --app device_monitoring_prototype.app check-db` validates the live tables, columns, indexes, foreign keys, check constraints, and key record counts without changing data. `db.create_all()` does not alter existing tables.

## Authentication and authorization

Public registration rejects the reserved `admin` username and does not create a `User` row until both verification layers succeed. A six-digit email code is HMAC-hashed in `email_verifications`, expires after five minutes, and is single-use with attempt, resend-cooldown, and per-hour limits. Gmail SMTP uses STARTTLS and loads credentials from `.env`; `check-mail` verifies authentication without sending a message. After email verification, a unique TOTP secret is encrypted at rest and shown as an `otpauth://` QR; a valid 6-digit Google Authenticator code is required before account creation. TOTP login challenges are required for users with 2FA enabled and replayed counters are rejected. Password confirmation and the existing 8-16 character complexity policy are enforced. New passwords use bcrypt; existing Werkzeug hashes remain supported during migration. Flask-Login manages sessions. Admin-only account management is checked server-side, device data is limited to owners/registrants, write operations require the session CSRF token, and unverified or disabled users are rejected on subsequent requests (except the reserved Administrator).

Create the initial Administrator and RBAC tables:

```powershell
flask --app device_monitoring_prototype.app init-db
```

The bootstrap login is `admin` / `admin123`. Change it before deployment. `create-admin` can add additional administrator accounts.

Database credentials are read from `.env`/environment variables or `DATABASE_URL`. Set persistent random `SECRET_KEY` and `TOTP_ENCRYPTION_KEY` values; rotating or losing the latter makes encrypted authenticator secrets unreadable. Configure Gmail with `MAIL_SERVER=smtp.gmail.com`, `MAIL_PORT=587`, `MAIL_USE_TLS=true`, a Gmail sender/username, and a Google App Password in `MAIL_PASSWORD`. Never commit `.env`. Run `flask --app device_monitoring_prototype.app check-mail` to test SMTP TLS and authentication. Set `COOKIE_SECURE=true` when HTTPS is enabled.

## Database CRUD and backend operations

`python/services.py` implements validated account creation/update/deactivation, device creation/update/archive, and diagnostic history insertion. Device events are retained in `logs`; broader account and system audit events remain in `activity_logs`. Flask views in `app.py` expose:

| Method and path | Access | Operation |
|---|---|---|
| `POST /api/registration/start` | Public | Stage a registration and send the email code; creates no user |
| `POST /api/registration/verify-email` | Registration session | Verify the six-digit email code and return the authenticator QR |
| `POST /api/registration/resend-code`, `POST /api/registration/cancel` | Registration session | Resend within limits or abandon the pending registration |
| `POST /api/registration/verify-authenticator` | Registration session | Verify the TOTP code and atomically create the account |
| `POST /register` | Public | Compatibility form endpoint for starting the staged registration |
| `POST /login`, `POST /logout` | Public / signed-in | Verify password and, when enabled, TOTP; start/end a Flask-Login session |
| `POST /api/device-registration-tokens` | Signed-in | Create a hashed, expiring, account-linked QR enrollment token |
| `GET /enroll/<token>` | One-use token | Show enrollment/download page; reject invalid, used, or expired tokens |
| `GET /enroll/<token>/agent.py` | One-use token | Download the Windows Python agent bound to the token |
| `POST /api/device-agent/enroll` | Bearer enrollment token | Validate and atomically consume the token while saving confirmed inventory |
| `GET /devices/<id>/specifications` | Owner/registrant or admin | View collected device specifications and registration history |
| `GET/POST /api/devices` | Signed-in | List visible devices / register an owned device |
| `PATCH /api/devices/<id>` | Owner/registrant or admin | Update an active device |
| `POST /api/devices/<id>/archive` | Owner/registrant or admin | Archive without deleting the device row |
| `GET /api/archived-devices` | Owner/registrant or admin | List archived devices |
| `POST /api/devices/<id>/restore` | Owner/registrant or admin | Restore an archived device |
| `DELETE /api/devices/<id>` | Admin | Mark the device deleted; retain the device row and history |
| `POST /api/devices/<id>/diagnostics` | Owner or admin | Append a diagnostic history record |
| `GET /api/devices/<id>/history` | Owner or admin | Read diagnostic and network history |
| `GET/POST /api/users` | Admin | List or create accounts |
| `PATCH/DELETE /api/users/<id>` | Admin | Update role/status or deactivate an account |
| `GET /api/dashboard` | Signed-in | Return the authorized device summary |

## Example MySQL queries

```sql
-- Devices visible in the fleet with their assigned account.
SELECT d.id, d.device_name, d.hostname, d.operating_system, d.status,
       u.username, d.registered_at
FROM devices AS d
JOIN users AS u ON u.id = d.owner_user_id
WHERE d.status <> 'retired'
ORDER BY d.registered_at DESC;

-- Hardware specifications for one device.
SELECT d.device_name, s.cpu_model, s.cpu_cores, s.memory_bytes,
       s.storage_bytes, s.gpu_model, s.motherboard_model,
       s.operating_system_version
FROM devices AS d
JOIN device_specifications AS s ON s.device_id = d.id
WHERE d.id = 1;

-- Complete diagnostic history, newest first.
SELECT device_id, status, summary, detected_problem, recommendation, started_at
FROM diagnostic_runs
WHERE device_id = 1
ORDER BY started_at DESC;

-- Historical network information for one device.
SELECT ip_address, subnet_mask, default_gateway, dns_server,
       connectivity_status, recorded_at
FROM network_records
WHERE device_id = 1
ORDER BY recorded_at DESC;

-- Users and their RBAC roles.
SELECT u.username, u.email, r.name AS role_name
FROM users AS u
JOIN user_roles AS ur ON ur.user_id = u.id
JOIN roles AS r ON r.id = ur.role_id;
```

## Collection scope

The QR-delivered Windows agent collects a one-time inventory only after local review and explicit confirmation. Its allowlist is CPU name/cores, RAM capacity/usage, storage devices/capacity/available space, GPU information, motherboard brand, OS name/version, network adapter names, and IP addresses. The server validates and stores the report with the token owner; tokens are hashed, expire in 30 minutes, and are consumed once. Configure `PUBLIC_BASE_URL` with the HTTPS origin for remote use. The agent requires Python 3, does not persist in the background, and does not collect live metrics or run diagnostics. The manual form retains its existing Flask-host collector; the diagnostic action remains a clearly labelled placeholder.
