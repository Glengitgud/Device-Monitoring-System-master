# Quality Assurance Report

**System:** DevMonitor Device Monitoring System
**Review date:** 2026-11-18
**Result:** The original `devmonitor` data was recovered from `C:\xampp\mysql\data_old\devmonitor` and restored to the configured XAMPP MariaDB instance. All 18 application tables passed MariaDB `CHECK TABLE`; `check-db` reports the expected schema and no orphaned foreign-key records. The Windows Device Agent now performs a one-time health assessment and submits a report to the existing diagnostics tables. Automated tests cover report validation, bearer-token/replay protection, persistence, audit events, and health-score thresholds. The recovered live database and affected user's device were not used for diagnostic writes.

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
| Device monitoring | Dashboard status and history are database-backed; endpoint health scans are point-in-time only. | Dashboard and access gating are covered by integration tests. Continuous telemetry remains future work. |
| Device health assessment | The local Windows agent scores CPU, RAM, storage capacity, GPU presence, network, driver metadata, and OS/service signals. | Tests verify the 0–39 red, 40–59 orange, 60–79 yellow, and 80–100 green bands. Scores are guidance, not hardware warranties. |
| Device diagnostics | My Devices now builds a per-run diagnostic EXE, polls its status, and displays the saved report. | Integration tests cover run creation, completed report persistence, single-use bearer authorization, replay rejection, and report history without a schema change. |
| Hardware detection | Endpoint-local checks include utilization, capacity/free space, GPU presence, connectivity, and CPU temperature when available. | Unsupported CPU temperature, SMART/storage health, startup timing, and Device Manager problem codes are explicitly unavailable; capacity or driver-age signals are not represented as hardware fault detection. |
| Software detection | Checks inspect OS identity and selected critical services; findings include severity, cause, recommendation, and troubleshooting steps. | Platform-limited startup, event-log, and full security-configuration checks are not claimed. Missing signals are marked skipped/unavailable rather than guessed. |
| Driver analysis | The agent inspects available display/network driver metadata and calculates a cautious score. | Old metadata is a review signal only; missing/disabled PnP drivers and Device Manager warnings are not reliably detected and are not claimed as validated. |
| User experience improvements | The agent shows circular, color-coded health indicators. Successful QR registration presents a success message and Dashboard shortcut with a five-second redirect. | Health boundaries have automated tests; frontend rendering, keyboard interaction, responsive behavior, and live browser countdown were not browser-tested. |
| Device information management | Authorized users can view and update device details and specifications; administrators can manage existing devices. | Integration tests cover CRUD, ownership, persisted specifications, and event history. The restored database has 4 devices, 4 specification rows, and 4 network records. |
| QR code features | Account setup uses an authenticator QR; device enrollment uses a separate, expiring, one-use QR token. | Integration tests cover QR creation, token expiry/revocation/replay protection, and enrollment. Physical phone scanning was not tested. |
| Device specification detection | The Windows agent collects CPU, physical core count, RAM and usage, storage and available capacity, GPU, motherboard, OS, network adapter, and IP information from the computer running the EXE. | Independent native collectors use `psutil`, Windows registry, and standard-library APIs. Component failures are logged and do not stop other collection; missing values are shown as “Unavailable” and represented in the existing API-compatible payload. Mocked partial-failure tests and a run on the current Windows host passed. The affected user's endpoint was not available for testing. |
| Device agent integration | Confirmed QR enrollment downloads a personalized one-file Windows EXE that submits allowlisted inventory after approval; diagnosis uses a separate, short-lived, single-use run token. | Existing EXE tests cover enrollment. Diagnostic report submission is tested through the Flask endpoint and isolated test database; no diagnostic EXE was built or run end-to-end in this task, and no live-MySQL write was made. |
| EXE-based deployment | A verified QR scan and explicit trust confirmation lead to a per-enrollment EXE download; the dashboard links to Device Verification. The executable needs no Python or manual URL/token setup on the Windows client. | PyInstaller runs on the 64-bit Windows application host; tests cover build behavior, invalid tokens, unsupported hosts, errors, download headers, remote HTTPS enforcement, and no Python-script fallback. Code signing, antivirus reputation, and deployed TLS remain unverified. |
| Dashboard features | Dashboard data is database-backed; standard users must have a verified device, while administrators bypass that gate. | Integration tests cover dashboard statistics and access gates. The restored schema is valid; live application routes were smoke-tested after restoration. |
| Device archiving and restoration | Archive/restore changes lifecycle state; administrator deletion is a retained soft delete. | Integration tests cover lifecycle transitions and history retention. No archived devices were present in the restored data. |
| Audit logs | Diagnostic start/completion events are recorded in the existing device and activity log tables. | Integration tests verify persisted start/completion device events and activity records. The restored database's earlier snapshot contained 20 device logs and 88 activity logs. |
| Database integration | Flask-SQLAlchemy connects to MariaDB; the app loads its private `.env`, supports `DATABASE_URL` overrides, and has a read-only `check-db` command. | The effective target is `localhost:3307/devmonitor`; `DATABASE_URL` is unset. `check-db`, row-count comparison, and all 18 MariaDB table checks passed after restore. |
| Error handling | Database connection, missing-database/schema, SMTP, and validation failures return actionable errors and are logged without passwords or verification codes. | Integration tests cover database/setup errors, malformed input, and SMTP failure paths. Before recovery, `check-db` correctly reported that the configured server did not contain `devmonitor`; it now passes. |
| Data recovery and backup | A full physical backup was isolated, inspected, and recovered through a disposable copy and logical export. | All expected DevMonitor table files were present; all recovered tables passed integrity checks. A final SQL backup was created and retained outside Git. See recovery details below. |
| Security features | CSRF checks, server-side RBAC/ownership, password hashing, bounded email verification, one-use tokens, encrypted TOTP secrets, and secure-cookie configuration are implemented. | Integration tests cover these controls. Production HTTPS, least-privilege database credentials, independent security review, browser security, and operational monitoring remain deployment work. |
| Testing coverage | The repository provides SQLite-backed integration tests for routes, auth, database behavior, device workflows, QR enrollment, executable packaging, and agent collection/submission. | All 50 tests pass. They validate application behavior but do not replace live credential, inbox, browser, or affected-device testing. |
| Feature validation against roadmap | The implemented and future-work boundary is recorded in `FEATURES_AND_FUTURE_WORK.md`. | Account and device workflows listed as implemented are covered by tests. Continuous telemetry, real diagnostics, alerts, reports, account recovery, managed agent updates, and production deployment are not implemented and are not claimed as passing. |

## EXE agent migration and validation

The migration keeps the existing one-time QR enrollment API, `devmonitor` schema, device ownership, audit events, and duplicate-registration protection. After account verification and an explicit trust confirmation, the Windows server builds a one-file EXE containing the short-lived enrollment token and configured submission URL. The database retains only the SHA-256 token hash; the existing API accepts it once. Inventory collection is local to the computer running the EXE. The user reviews the detected information and approves submission through the existing API and database models.

This removes Python installation and manual agent configuration from the endpoint workflow. The project requirements install PyInstaller on the application host; the builder uses an isolated temporary directory and deletes its source/build files after producing the response. The build fails visibly on non-Windows hosts or packaging errors and never falls back to serving a Python script. The downloaded executable contains a temporary bearer token, so remote deployments must use HTTPS and users must treat it like a credential.

The generated file was verified as an AMD64 PE binary and launched on the current Windows host. It collected local device information and submitted the structured payload to a local test endpoint. A second end-to-end run used the actual executable with a local Flask endpoint and isolated SQLite database; the response and expected device, specification, device-log, audit, and token-consumption records were verified. This confirms packaged-agent execution and the enrollment persistence path without changing the recovered `devmonitor` data. It does not confirm behavior on the affected user's endpoint or a write to the live MariaDB database. Code signing, antivirus reputation, and production deployment remain unverified.

## Device specification detection issue

The reported endpoint failure, “Could not collect device information,” was traced to an all-or-nothing inventory routine: all hardware queries ran in one PowerShell process with `$ErrorActionPreference = 'Stop'`. A PowerShell launch or command failure discarded the entire collection. The exact command that failed on the user's computer cannot be confirmed because its original agent log/output was not available.

The PowerShell dependency was replaced with independent collectors using `psutil`, Windows registry values, and standard-library APIs. CPU, cores, memory, storage, GPU, motherboard, operating-system, and network information are collected independently. Inaccessible drives are skipped while other mounts are retained; exceptions are logged and missing fields use the supported unavailable representation rather than stopping the agent. Diagnostic logs rotate at `%LOCALAPPDATA%\DevMonitor\logs\device-agent.log`, with temp-directory and console fallbacks. Logs contain exception details and unavailable-field names, not credentials or inventory values.

The EXE collects from the Windows computer where it runs; the QR-scanning phone only opens the enrollment page. Automated tests cover collector fallbacks, partial storage/network results, unavailable fields, logs, and the unchanged payload contract. The packaged EXE and local API/database workflow passed as described above. Dashboard behavior and duplicate-token protection remain covered by the application integration suite. The affected user's computer, live MariaDB submission, and live dashboard after an agent registration were not tested.

## Device health and diagnostics enhancement

The prior placeholder scan did not inspect the endpoint. A browser/server-side scan cannot assess the user's separate PC, so My Devices now downloads a run-specific EXE for the target computer. That EXE gathers local, one-time signals, displays circular health gauges and findings, asks for consent, then submits a structured report. The backend validates report shape and size, accepts a time-limited single-use bearer token, and saves scores/checks to the existing `diagnostic_runs` and `diagnostic_checks` tables. Device and activity logs record start and completion. No schema change or continuous monitoring is claimed.

Health color thresholds and report persistence/replay handling pass automated tests. The previous all-or-nothing PowerShell scanner is no longer used for this workflow. CPU temperature, SMART/storage health, startup duration, Windows event-log analysis, complete security posture, and Device Manager problem codes may be inaccessible; they are marked unavailable or skipped. Driver age is only a recommendation signal. The diagnostic-mode EXE was not built or run against an endpoint during this pass; tested report submissions used the isolated Flask test database. The requested success modal and five-second Dashboard redirect are implemented but have not been exercised in a browser.

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

The figures above describe the recovery-time backup snapshot. A later read-only `check-db` run reported 10 users and 20 registration tokens, rather than the snapshot's 9 users and 16 tokens. The source and timing of those additional rows were not established in this task; no live-database writes were made by the agent validation.

## Testing and regression results

Run the integration suite from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s device_monitoring_prototype\tests -v
```

**Result:** All 51 tests pass. Coverage includes registration/login, password hashing, email/TOTP verification, RBAC, database configuration/error handling, CRUD, dashboard, specifications/history, archive/restore, QR enrollment, audit logs, EXE build/download behavior, inventory fallbacks, diagnostic report validation/persistence, bearer-token replay rejection, audit entries, and health-color thresholds. The existing packaged registration EXE was verified in earlier work; this task did not build/run diagnostic mode or write to recovered MariaDB. Browser/accessibility testing, live MySQL diagnostic submission, target-endpoint behavior, user acceptance, and per-request build performance remain unverified.

## Backup, restore, and follow-up recommendations

- Keep the original `data_old` physical copy and the final logical SQL backup on separate protected storage. Test backups periodically and record checksums.
- Prefer regular logical backups of `devmonitor` (for example, `mysqldump --single-transaction`) and verify that each dump contains the expected schema and data. Restrict access because backups contain password hashes and encrypted TOTP secrets.
- For physical recovery, stop MariaDB first and preserve a complete copy of the matching-version data directory. Never mix individual `.ibd` files with a different `ibdata1`/InnoDB dictionary. Test crash recovery on a disposable copy before restoring.
- Preserve `SECRET_KEY` and `TOTP_ENCRYPTION_KEY` in a separate secure backup; changing or losing the TOTP key can make stored authenticator secrets unreadable.
- Keep the app's `MYSQL_PORT` aligned with XAMPP's configured port. `DATABASE_URL`, when set, overrides the separate `MYSQL_*` settings. Keep the database name `devmonitor`.
- Keep the agent-building host on 64-bit Windows and install the pinned project requirements. Use HTTPS for remote QR enrollment because the personalized EXE contains a short-lived bearer token. Code-sign the EXE and check server capacity/build latency before production use.
- Use a dedicated least-privilege database account rather than a global administrator account when the active MariaDB privilege tables are healthy. Do not copy the damaged `mysql` system schema from the recovery backup into the active server.
- Diagnose the unrelated `barangay_portal` tablespace and backup system-table issues separately if those databases are needed. Do not remove or repair files in the original backup in place.
- Before production use, build and run the diagnostic EXE against a disposable test account/database, complete browser/accessibility and user-acceptance testing, and measure per-run build latency. Implement future roadmap work (continuous telemetry, broader supported diagnostics, alerts, reporting, account recovery, and managed/signed agent delivery) before claiming production monitoring.
