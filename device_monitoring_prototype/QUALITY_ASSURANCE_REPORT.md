# Quality Assurance Report

**System:** DevMonitor Device Monitoring System
**Review date:** 2026-11-18
**Result:** The original `devmonitor` data was recovered from `C:\xampp\mysql\data_old\devmonitor` and restored to the configured XAMPP MariaDB instance. All 18 application tables pass MariaDB `CHECK TABLE`; the application `check-db` reports the expected schema, keys, constraints, and no orphaned foreign-key records. Restored row counts match the recovered backup. The source backup remains available, and a verified logical backup was saved outside the repository.

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
| Device specification detection | The Windows agent requests CPU, core count, RAM and usage, storage and available capacity, GPU, motherboard, OS, network adapter, and IP information through PowerShell/CIM. | Mocked PowerShell output tests validate parsing and the field allowlist. Physical hardware detection remains unverified. |
| Device agent integration | The current QR enrollment downloads a token-bound Python agent; the planned migration packages that workflow as a standalone Windows executable. | The baseline confirms the API, one-use token, inventory approval, and database flow. The EXE build, download, Windows launch, and packaged end-to-end flow are pending implementation and validation; no continuous service is intended. |
| EXE-based deployment | Target workflow: verify the QR enrollment, explicitly confirm the trusted download, run a standalone EXE, review the detected inventory, and approve submission. | Acceptance checks will verify a Windows executable download, no Python requirement on the client, injected short-lived enrollment settings, all allowlisted inventory fields, API/database compatibility, and token replay rejection. Signing and managed distribution remain separate production-hardening work. |
| Dashboard features | Dashboard data is database-backed; standard users must have a verified device, while administrators bypass that gate. | Integration tests cover dashboard statistics and access gates. The restored schema is valid; live application routes were smoke-tested after restoration. |
| Device archiving and restoration | Archive/restore changes lifecycle state; administrator deletion is a retained soft delete. | Integration tests cover lifecycle transitions and history retention. No archived devices were present in the restored data. |
| Audit logs | Device events and broader activity events are persisted separately. | Integration tests cover event creation, authorization, filtering, and history. The restored database contains 20 device logs and 88 activity logs. |
| Database integration | Flask-SQLAlchemy connects to MariaDB; the app loads its private `.env`, supports `DATABASE_URL` overrides, and has a read-only `check-db` command. | The effective target is `localhost:3307/devmonitor`; `DATABASE_URL` is unset. `check-db`, row-count comparison, and all 18 MariaDB table checks passed after restore. |
| Error handling | Database connection, missing-database/schema, SMTP, and validation failures return actionable errors and are logged without passwords or verification codes. | Integration tests cover database/setup errors, malformed input, and SMTP failure paths. Before recovery, `check-db` correctly reported that the configured server did not contain `devmonitor`; it now passes. |
| Data recovery and backup | A full physical backup was isolated, inspected, and recovered through a disposable copy and logical export. | All expected DevMonitor table files were present; all recovered tables passed integrity checks. A final SQL backup was created and retained outside Git. See recovery details below. |
| Security features | CSRF checks, server-side RBAC/ownership, password hashing, bounded email verification, one-use tokens, encrypted TOTP secrets, and secure-cookie configuration are implemented. | Integration tests cover these controls. Production HTTPS, least-privilege database credentials, independent security review, browser security, and operational monitoring remain deployment work. |
| Testing coverage | The repository provides SQLite-backed integration tests for routes, auth, database behavior, device workflows, QR enrollment, and agent parsing. | All 38 integration tests passed after recovery. They validate application behavior but do not replace live credential, inbox, browser, or physical-device testing. |
| Feature validation against roadmap | The implemented and future-work boundary is recorded in `FEATURES_AND_FUTURE_WORK.md`. | Account and device workflows listed as implemented are covered by tests. Continuous telemetry, real diagnostics, alerts, reports, account recovery, managed agent updates, and production deployment are not implemented and are not claimed as passing. |

## EXE agent migration acceptance plan

The migration keeps the existing one-time QR enrollment API and database schema. The EXE must be issued only after account verification and an explicit trusted-download confirmation; its embedded token is short-lived, stored only as a hash by the server, and accepted once. The existing inventory allowlist, user review/approval, device ownership, audit events, and duplicate-registration protection remain required.

The server must build a token-bound Windows executable without asking the device user to install Python or configure a URL/token. The build/download path must fail visibly if packaging fails and must not silently return the old Python script. Validation will distinguish automated inventory/API tests from a real Windows launch, live recovered-database write, inbox delivery, code signing, or antivirus/reputation checks; only tests actually executed will be reported as passed.

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

**Result:** 38 tests passed. Coverage includes registration/login, password hashing, email and TOTP verification, RBAC, database configuration and error handling, CRUD, dashboard access, device specifications/history, archive/restore/soft-delete, QR enrollment, audit logs, and mocked Windows-agent inventory parsing. Live database validation separately passed as described above. Google Authenticator phone scanning, real recipient inbox placement, browser/responsive behavior, physical Windows hardware collection, user acceptance, and performance remain unverified.

## Backup, restore, and follow-up recommendations

- Keep the original `data_old` physical copy and the final logical SQL backup on separate protected storage. Test backups periodically and record checksums.
- Prefer regular logical backups of `devmonitor` (for example, `mysqldump --single-transaction`) and verify that each dump contains the expected schema and data. Restrict access because backups contain password hashes and encrypted TOTP secrets.
- For physical recovery, stop MariaDB first and preserve a complete copy of the matching-version data directory. Never mix individual `.ibd` files with a different `ibdata1`/InnoDB dictionary. Test crash recovery on a disposable copy before restoring.
- Preserve `SECRET_KEY` and `TOTP_ENCRYPTION_KEY` in a separate secure backup; changing or losing the TOTP key can make stored authenticator secrets unreadable.
- Keep the app's `MYSQL_PORT` aligned with XAMPP's configured port. `DATABASE_URL`, when set, overrides the separate `MYSQL_*` settings. Keep the database name `devmonitor`.
- Use a dedicated least-privilege database account rather than a global administrator account when the active MariaDB privilege tables are healthy. Do not copy the damaged `mysql` system schema from the recovery backup into the active server.
- Diagnose the unrelated `barangay_portal` tablespace and backup system-table issues separately if those databases are needed. Do not remove or repair files in the original backup in place.
- Before production use, complete authorized live login/registration and inbox checks, browser/accessibility and user-acceptance testing, and performance testing. Implement future roadmap work (continuous telemetry, actual diagnostics, alerts, reporting, account recovery, and managed/signed agent delivery) before claiming production monitoring.
