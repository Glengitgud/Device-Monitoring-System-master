# Quality Assurance Report

**System:** DevMonitor Device Monitoring System
**Review date:** 2026-11-18
**Result:** The original `devmonitor` data was recovered from `C:\xampp\mysql\data_old\devmonitor` and restored to the configured XAMPP MariaDB instance. All 18 application tables pass MariaDB `CHECK TABLE`; the application `check-db` reports the expected schema, keys, constraints, and no orphaned foreign-key records. Restored row counts match the recovered backup. QR enrollment now builds a token-bound, standalone Windows x64 EXE; the server-generated PE binary was verified, and all 45 automated tests pass. No client Python installation is needed.

## Scope and feature validation

Validation reflects the current implementation described in `FEATURES_AND_FUTURE_WORK.md`. Prototype behavior is not described as production-ready monitoring.

| Area | Implemented behavior | Validation and limits |
|---|---|---|
| User authentication | Sign-in accepts username or email; TOTP is required for accounts that have it enabled. | Integration tests cover password sign-in, email sign-in, MFA, failed attempts, and authorization. One encrypted TOTP secret in the restored data decrypted successfully with the current key. A live sign-in using an account password was not attempted because no test credentials were supplied. |
| User registration | Registration stages an account and creates the user only after email-code and authenticator verification. | Integration tests cover both verification steps, expiration, resend limits, duplicate addresses, and SMTP failure. No live registration was performed during recovery to avoid sending mail or adding a test account to restored data. |
| Email verification | Gmail-delivered six-digit codes are HMAC-hashed, short-lived, and single-use; TOTP verification is also required. | Automated tests cover delivery/error paths, expiration, replay, and throttling. Real inbox delivery was not re-tested during this review. |
| Password security | New passwords use bcrypt; existing Werkzeug hashes remain supported. Password policy and confirmation are validated server-side. | Restored data has 1 bcrypt hash and 8 legacy hashes; integration tests verify both hash formats and registration policy. Plaintext passwords are not stored or reported. |
| Admin access and management | RBAC protects user management, all-device administration, and administrative logs. Administrators cannot use public device registration. | Integration tests cover administrator and standard-user boundaries, user changes, and rejected registration paths. Restored roles and associations are present and pass schema/integrity checks. |
| Device registration | Authorized standard users can register devices manually or through the confirmed agent enrollment flow. | Integration tests cover registration, owner scoping, validation, and persistence. Four restored devices and four specification records remain accessible in the database. |
| Device monitoring | The prototype displays database-backed device status and history. It does not collect continuous telemetry or perform real diagnostics. | Dashboard and access-gating behavior are covered by integration tests. Continuous monitoring and real diagnostics remain future work. |
| Device information management | Authorized users can view and update device details and specifications; administrators can manage existing devices. | Integration tests cover CRUD, ownership, persisted specifications, and event history. The restored database has 4 devices, 4 specification rows, and 4 network records. |
| QR code features | Account setup uses an authenticator QR; device enrollment uses a separate, expiring, one-use QR token. | Integration tests cover QR creation, token expiry/revocation/replay protection, and enrollment. Physical phone scanning was not tested. |
| Device specification detection | The Windows agent collects CPU, core count, RAM and usage, storage and available capacity, GPU, motherboard, OS, network adapter, and IP information through PowerShell/CIM. | Mocked PowerShell output tests validate all expected fields and the allowlist. Physical hardware detection remains unverified. |
| Device agent integration | Confirmed QR enrollment downloads a personalized one-file Windows EXE that submits the existing allowlisted inventory to the existing enrollment API after user approval. | The agent builder produced a valid Windows x64 PE binary (8,403,901 bytes); token binding and cleanup are covered by builder tests. Route/API integration and single-use replay rejection pass automated tests. The EXE was not launched against physical hardware or used to write to the recovered live database. |
| EXE-based deployment | A verified QR scan and explicit trust confirmation lead to a per-enrollment EXE download; the dashboard links to Device Verification. The executable needs no Python or manual URL/token setup on the Windows client. | PyInstaller runs on the 64-bit Windows application host; automated tests cover successful build behavior, invalid tokens, unsupported hosts, build errors, download headers, remote HTTPS enforcement, and no Python-script fallback. The generated PE binary was inspected but not launched. Code signing, antivirus reputation, physical device collection, and deployed TLS remain unverified. |
| Dashboard features | Dashboard data is database-backed; standard users must have a verified device, while administrators bypass that gate. | Integration tests cover dashboard statistics and access gates. The restored schema is valid; live application routes were smoke-tested after restoration. |
| Device archiving and restoration | Archive/restore changes lifecycle state; administrator deletion is a retained soft delete. | Integration tests cover lifecycle transitions and history retention. No archived devices were present in the restored data. |
| Audit logs | Device events and broader activity events are persisted separately. | Integration tests cover event creation, authorization, filtering, and history. The restored database contains 20 device logs and 88 activity logs. |
| Database integration | Flask-SQLAlchemy connects to MariaDB; the app loads its private `.env`, supports `DATABASE_URL` overrides, and has a read-only `check-db` command. | The effective target is `localhost:3307/devmonitor`; `DATABASE_URL` is unset. `check-db`, row-count comparison, and all 18 MariaDB table checks passed after restore. |
| Error handling | Database connection, missing-database/schema, SMTP, and validation failures return actionable errors and are logged without passwords or verification codes. | Integration tests cover database/setup errors, malformed input, and SMTP failure paths. Before recovery, `check-db` correctly reported that the configured server did not contain `devmonitor`; it now passes. |
| Data recovery and backup | A full physical backup was isolated, inspected, and recovered through a disposable copy and logical export. | All expected DevMonitor table files were present; all recovered tables passed integrity checks. A final SQL backup was created and retained outside Git. See recovery details below. |
| Security features | CSRF checks, server-side RBAC/ownership, password hashing, bounded email verification, one-use tokens, encrypted TOTP secrets, and secure-cookie configuration are implemented. | Integration tests cover these controls. Production HTTPS, least-privilege database credentials, independent security review, browser security, and operational monitoring remain deployment work. |
| Testing coverage | The repository provides SQLite-backed integration tests for routes, auth, database behavior, device workflows, QR enrollment, executable packaging, and agent parsing. | All 45 tests pass. They validate application behavior but do not replace live credential, inbox, browser, or physical-device testing. |
| Feature validation against roadmap | The implemented and future-work boundary is recorded in `FEATURES_AND_FUTURE_WORK.md`. | Account and device workflows listed as implemented are covered by tests. Continuous telemetry, real diagnostics, alerts, reports, account recovery, managed agent updates, and production deployment are not implemented and are not claimed as passing. |

## EXE agent migration and validation

The migration keeps the existing one-time QR enrollment API, `devmonitor` schema, device ownership, audit events, and duplicate-registration protection. After account verification and an explicit trust confirmation, the Windows server builds a one-file EXE containing the short-lived enrollment token and configured submission URL. The database retains only the SHA-256 token hash; the existing API accepts it once. Inventory collection, user review/approval, validation, and persistence are unchanged.

This removes Python installation and manual agent configuration from the endpoint workflow. The project requirements install PyInstaller on the application host; the builder uses an isolated temporary directory and deletes its source/build files after producing the response. The build fails visibly on non-Windows hosts or packaging errors and never falls back to serving a Python script. The downloaded executable contains a temporary bearer token, so remote deployments must use HTTPS and users must treat it like a credential.

The actual built file was inspected as a valid AMD64 PE binary. Automated tests verify agent fields, packaging inputs, endpoint/download behavior, failure handling, database/API contracts, and token replay rejection. They do not prove physical-hardware collection or a live write to the recovered database; no executable was launched, and no real device was registered during this validation. Code signing, antivirus reputation, and production deployment remain unverified.

## Root-cause analysis

The application's database settings were not the current blocker. The private `.env` resolves to the same XAMPP MariaDB instance that is running on port `3307`, with database name `devmonitor`; `DATABASE_URL` is unset. The earlier port conflict with standalone MySQL 8.0 explains why XAMPP was moved off its default port, but the current app and XAMPP settings agree.

The active server used `C:\xampp\mysql\data`, which did not contain a `devmonitor` directory. The original database files were instead in `C:\xampp\mysql\data_old\devmonitor`. Accordingly, the app reached MariaDB but received error 1049 (“database does not exist”). This was a missing database in the active data directory, not an ORM, login-code, or credential error.

The underlying event that damaged or displaced the original data directory cannot be established from the available evidence. The backup contains all 18 expected `.frm` files and all 18 matching `.ibd` files for the current ORM models. However, its server log also reports missing InnoDB tablespaces for the unrelated `barangay_portal.requests` and `barangay_portal.request_services` tables, and damaged MariaDB Aria privilege tables (`mysql.db` and `mysql.tables_priv`). The backup also could not open `mysql.event`. These findings are not evidence of corruption in the DevMonitor tables and are not represented as recovered.

## Recovery and restoration

1. The backup was copied to a disposable working data directory; recovery attempts did not target or overwrite `data_old`.
2. The XAMPP MariaDB 10.4.32 binary started the disposable copy on port 3308 after its InnoDB paths were explicitly isolated. Normal crash recovery replayed the redo logs. Startup reported the unrelated missing tablespaces noted above.
3. On the disposable copy only, `aria_chk --recover` repaired the damaged `mysql.db` and `mysql.tables_priv` indexes. The recovered `mysql.db` reported zero records; those backup system privilege tables were not copied into the active server. MariaDB disabled its event scheduler in the disposable instance because `mysql.event` could not be opened.
4. The `devmonitor` schema on the recovered copy passed the application `check-db` command and `CHECK TABLE` for all 18 tables. A logical dump containing all 18 definitions and data was imported into the configured XAMPP MariaDB instance under the original database name, `devmonitor`. This restored the backup data; it did not initialize a blank application schema or apply migrations.
5. A final logical backup was created at `C:\xampp\mysql\backups\devmonitor_recovered_20261118.sql` (18 table definitions; 45,848 bytes). It contains account hashes and encrypted authenticator data, so keep it private and outside the repository.

The temporary recovery copy and intermediate dump were removed after validation. The physical source backup and final logical backup were retained. No DevMonitor `.ibd` files were copied individually into the active server’s unrelated InnoDB dictionary.

## Reconnection and data-integrity results

| Check | Result |
|---|---|
| Effective application target | `localhost:3307/devmonitor`; matches the running XAMPP MariaDB 10.4.32. |
| Application `check-db` | Passed: 18 tables, 16 model indexes, primary/unique keys, foreign keys, and check constraints; no orphaned foreign-key records. |
| MariaDB `CHECK TABLE` | All 18 restored DevMonitor tables returned `OK`. |
| Backup-to-restored comparison | Row counts matched for every table. |
| Restored account data | 9 users, 2 roles, 9 user-role links; password hashes retained. |
| Restored device and history data | 4 devices, 4 specifications, 4 network records, 16 enrollment tokens, 20 device logs, 9 diagnostic runs, 9 diagnostic checks, and 88 activity logs. |
| Authenticator key compatibility | The current encryption key decrypted the stored TOTP secret for the one TOTP-enabled account. |
| Web application | The existing Flask server returned HTTP 200 for `/`, `/login`, and `/register` after restoration. |
| Backup file | The final SQL dump contains 18 table definitions; SHA-256: `0A071235A2DA75BD3109A5D54BCF4BE644671F232D55CAC8A8A2FE49C257E96`. It was retained outside Git. |

No schema migrations or `init-db` command were run during recovery: the restored schema already matched the application models. No real user login, external-recipient email delivery, or write CRUD operation was performed against the restored records. Those workflows are covered by the isolated integration suite, but a live acceptance test with authorized credentials remains advisable.

## Testing and regression results

Run the integration suite from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s device_monitoring_prototype\tests -v
```

**Result:** 45 tests passed. Coverage includes registration/login, password hashing, email and TOTP verification, RBAC, database configuration and error handling, CRUD, dashboard access, device specifications/history, archive/restore/soft-delete, QR enrollment, audit logs, EXE build/download behavior, remote HTTPS enforcement, and mocked Windows-agent inventory parsing. The builder also produced and verified an actual Windows x64 PE executable. Google Authenticator phone scanning, real recipient inbox placement, browser/responsive behavior, running the EXE on a physical endpoint, user acceptance, and per-request build performance remain unverified.

## Backup, restore, and follow-up recommendations

- Keep the original `data_old` physical copy and the final logical SQL backup on separate protected storage. Test backups periodically and record checksums.
- Prefer regular logical backups of `devmonitor` (for example, `mysqldump --single-transaction`) and verify that each dump contains the expected schema and data. Restrict access because backups contain password hashes and encrypted TOTP secrets.
- For physical recovery, stop MariaDB first and preserve a complete copy of the matching-version data directory. Never mix individual `.ibd` files with a different `ibdata1`/InnoDB dictionary. Test crash recovery on a disposable copy before restoring.
- Preserve `SECRET_KEY` and `TOTP_ENCRYPTION_KEY` in a separate secure backup; changing or losing the TOTP key can make stored authenticator secrets unreadable.
- Keep the app's `MYSQL_PORT` aligned with XAMPP's configured port. `DATABASE_URL`, when set, overrides the separate `MYSQL_*` settings. Keep the database name `devmonitor`.
- Keep the agent-building host on 64-bit Windows and install the pinned project requirements. Use HTTPS for remote QR enrollment because the personalized EXE contains a short-lived bearer token. Code-sign the EXE and check server capacity/build latency before production use.
- Use a dedicated least-privilege database account rather than a global administrator account when the active MariaDB privilege tables are healthy. Do not copy the damaged `mysql` system schema from the recovery backup into the active server.
- Diagnose the unrelated `barangay_portal` tablespace and backup system-table issues separately if those databases are needed. Do not remove or repair files in the original backup in place.
- Before production use, complete authorized live login/registration and inbox checks, browser/accessibility and user-acceptance testing, and performance testing. Implement future roadmap work (continuous telemetry, actual diagnostics, alerts, reporting, account recovery, and managed/signed agent delivery) before claiming production monitoring.
