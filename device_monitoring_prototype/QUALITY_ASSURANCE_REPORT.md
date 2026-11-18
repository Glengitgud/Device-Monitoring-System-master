# Quality Assurance Report

**System:** DevMonitor Device Monitoring System
**Review date:** 2026-11-18
**Result:** Scope validation covers authentication, registration, device enrollment, the Device Agent EXE, specification detection, health monitoring, diagnostics, dashboard/device monitoring, audit logs, database/API integration, real-time synchronization, error handling, and UX. The integrated Device Scan goal is that the EXE only collects and submits; health scores, findings, and troubleshooting must appear inside the website after the backend saves the report. Follow-up commits remove local-only diagnostic windows and complete website refresh/history/completion UX. Recovery and schema checks for the restored `devmonitor` database remain valid; live MariaDB was not used for diagnostic writes in this review.

## Scope and feature validation

Validation reflects the current implementation described in `FEATURES_AND_FUTURE_WORK.md`. Prototype behavior is not described as production-ready monitoring.

| Area | Implemented behavior | Validation and limits |
|---|---|---|
| User authentication | Sign-in accepts username or email; TOTP is required for accounts that have it enabled. | Integration tests cover password sign-in, email sign-in, MFA, failed attempts, and authorization. One encrypted TOTP secret in the restored data decrypted successfully with the current key. A live sign-in using an account password was not attempted because no test credentials were supplied. |
| User registration | Registration stages an account and creates the user only after email-code and authenticator verification. | Integration tests cover both verification steps, expiration, resend limits, duplicate addresses, and SMTP failure. No live registration was performed during recovery to avoid sending mail or adding a test account to restored data. |
| Email verification | Gmail-delivered six-digit codes are HMAC-hashed, short-lived, and single-use; TOTP verification is also required. | Automated tests cover delivery/error paths, expiration, replay, and throttling. Real inbox delivery was not re-tested during this review. |
| Password security | New passwords use bcrypt; existing Werkzeug hashes remain supported. Password policy and confirmation are validated server-side. | Restored data has 1 bcrypt hash and 8 legacy hashes; integration tests verify both hash formats and registration policy. Plaintext passwords are not stored or reported. |
| Admin access and management | RBAC protects user management, all-device administration, and administrative logs. Administrators cannot use public device registration. | Integration tests cover administrator and standard-user boundaries, user changes, and rejected registration paths. Restored roles and associations are present and pass schema/integrity checks. |
| Device registration | Authorized standard users can register devices manually or through the confirmed agent enrollment flow. Agent submission writes device/specification/network/audit records and consumes the one-use token in one transaction. | Integration tests cover registration, owner scoping, validation, persistence, token status, and access. Four restored devices and four specification records remain accessible in the database. |
| Device Agent EXE | Personalized Windows EXE collects inventory or a one-time diagnostic report locally and submits to the enrollment/diagnostics API. | Enrollment returns the device identity; diagnostic mode uses a run-scoped bearer token. Local-only diagnostic result windows are being removed so results appear only in the website. |
| Device specification detection | Agent collects CPU, cores, RAM, storage, GPU, motherboard, OS, adapters, and IP addresses from the computer running the EXE. | Independent collectors; partial failures leave unavailable fields without aborting submission. |
| Device health monitoring | Overall/hardware/software/driver and component scores use green 80–100, yellow 60–79, orange 40–59, and red 0–39 bands. | Threshold tests pass. Scores are advisory guidance, not hardware warranties. |
| Device diagnostics | My Devices downloads a run-specific diagnostic EXE; the agent submits the structured report for website display. | Persistence uses existing `diagnostic_runs` / `diagnostic_checks`; findings include severity, cause, recommendation, and steps. |
| Dashboard integration | Fleet counts and device rows are database-backed; latest completed scan supplies health score labels. | Access gates and no-cache responses are covered by integration tests. |
| Device monitoring | Dashboard and My Devices refresh while visible; endpoint health scans remain point-in-time. | Continuous telemetry remains future work. |
| Audit logs | Diagnostic start/completion and registration events are recorded in device and activity logs. | Integration tests verify persisted start/completion events. |
| Database integration | Flask-SQLAlchemy connects to MariaDB; `check-db` is read-only. | Effective target `localhost:3307/devmonitor`; 18 tables pass integrity checks after restore. |
| API communication | Diagnostic EXE posts the report with its run token; authenticated status/history/dashboard/details retrieve saved results. | Report validation, replay rejection, and retrieval are covered by integration tests. |
| Real-time synchronization | After submission, status polling and page refreshers should surface scores, issues, and troubleshooting without a manual reload. | Follow-up work completes automatic device/dashboard refresh and scan-completion redirects after the agent submits. |
| Error handling | Database, SMTP, validation, and expired-token failures return actionable errors without logging secrets. | Integration tests cover malformed input and setup/error paths. |
| User experience improvements | Enrollment and scan completion use in-app success dialogs with Dashboard/device actions and a five-second redirect option. | Browser animation and accessibility still need live browser confirmation. |
| Hardware detection | Endpoint-local checks include utilization, capacity/free space, GPU presence, connectivity, and CPU temperature when available. | Unsupported sensors are marked unavailable; capacity is not SMART health. |
| Software detection | Checks inspect OS identity and selected critical services. | Startup, event-log, and full security posture checks are not claimed. |
| Driver analysis | Display/network driver metadata and Windows PnP problem codes when available. | Old metadata is a review signal only. |
| Device information management | Owners/admins can view and update device details and detected specifications. | Incomplete legacy JSON and missing health scores render safely. |
| QR code features | Authenticator QR for account setup; separate expiring one-use QR for device enrollment. | Physical phone scanning was not tested. |
| EXE-based deployment | Verified QR scan and trust confirmation produce a one-file Windows EXE with no Python install on the client. | Code signing and production TLS remain unverified. |
| Device archiving and restoration | Archive/restore changes lifecycle state; administrator deletion is a retained soft delete. | History is retained. |
| Data recovery and backup | Physical backup recovered and logically restored into the active MariaDB instance. | Final SQL backup retained outside Git. |
| Security features | CSRF, RBAC/ownership, hashing, bounded email verification, one-use tokens, encrypted TOTP, secure cookies. | Production HTTPS and operational review remain deployment work. |
| Testing coverage | SQLite-backed integration suite for auth, devices, QR, EXE packaging, diagnostics, and dashboard sync. | Does not replace live credential, inbox, browser, or affected-device testing. |
| Feature validation against roadmap | Boundary recorded in `FEATURES_AND_FUTURE_WORK.md`. | Continuous telemetry, alerts, reports, recovery, and managed agent delivery remain future work. |

## Integrated Device Scan workflow (target)

Intended path for Device Scan inside the Device Monitoring System:

1. Open My Devices and start Device Scan.
2. Download the Device Agent EXE if needed and run it on the target computer.
3. Agent performs hardware and software checks.
4. Agent submits the report to the backend API (no local-only result window).
5. Backend validates and stores scores, issues, recommendations, troubleshooting steps, timestamps, and status.
6. Website polling refreshes device cards, health indicators, dashboard stats, and the Device Scan Results view automatically.
7. Users review health scores, findings, recommended fixes, step-by-step troubleshooting, and scan history in the website.

Open gaps at the start of this pass: local diagnostic overview windows, delayed or missing in-app result refresh after EXE submission, and incomplete scan-completion navigation (View Results / View Device / Dashboard with countdown).

## EXE agent migration and validation

The migration keeps the existing one-time QR enrollment API, `devmonitor` schema, device ownership, audit events, and duplicate-registration protection. After account verification and an explicit trust confirmation, the Windows server builds a one-file EXE containing the short-lived enrollment token and configured submission URL. The database retains only the SHA-256 token hash; the existing API accepts it once. Inventory collection is local to the computer running the EXE. The user reviews the detected information and approves submission through the existing API and database models.

This removes Python installation and manual agent configuration from the endpoint workflow. The project requirements install PyInstaller on the application host; the builder uses an isolated temporary directory and deletes its source/build files after producing the response. The build fails visibly on non-Windows hosts or packaging errors and never falls back to serving a Python script. The downloaded executable contains a temporary bearer token, so remote deployments must use HTTPS and users must treat it like a credential.

The generated file was verified as an AMD64 PE binary and launched on the current Windows host. It collected local device information and submitted the structured payload to a local test endpoint. A second end-to-end run used the actual executable with a local Flask endpoint and isolated SQLite database; the response and expected device, specification, device-log, audit, and token-consumption records were verified. This confirms packaged-agent execution and the enrollment persistence path without changing the recovered `devmonitor` data. It does not confirm behavior on the affected user's endpoint or a write to the live MariaDB database. Code signing, antivirus reputation, and production deployment remain unverified.

## Device specification detection issue

The reported endpoint failure, “Could not collect device information,” was traced to an all-or-nothing inventory routine: all hardware queries ran in one PowerShell process with `$ErrorActionPreference = 'Stop'`. A PowerShell launch or command failure discarded the entire collection. The exact command that failed on the user's computer cannot be confirmed because its original agent log/output was not available.

The PowerShell dependency was replaced with independent collectors using `psutil`, Windows registry values, and standard-library APIs. CPU, cores, memory, storage, GPU, motherboard, operating-system, and network information are collected independently. Inaccessible drives are skipped while other mounts are retained; exceptions are logged and missing fields use the supported unavailable representation rather than stopping the agent. Diagnostic logs rotate at `%LOCALAPPDATA%\DevMonitor\logs\device-agent.log`, with temp-directory and console fallbacks. Logs contain exception details and unavailable-field names, not credentials or inventory values.

The EXE collects from the Windows computer where it runs; the QR-scanning phone only opens the enrollment page. Automated tests cover collector fallbacks, partial storage/network results, unavailable fields, logs, and the unchanged payload contract. The packaged EXE and local API/database workflow passed as described above. Dashboard behavior and duplicate-token protection remain covered by the application integration suite. The affected user's computer, live MariaDB submission, and live dashboard after an agent registration were not tested.

## Device registration synchronization and specification viewing

The registration endpoint commits the device, detected specification, available network record, audit event, and token consumption before it returns success. The existing status API previously reported only a verified-device count, so clients could not resolve the newly registered device for a details link. The browser also had duplicate declarations of a JavaScript timer variable; this caused a syntax error that prevented the entire page script from running, including status polling, list refresh, and the completion dialog.

The status endpoints now return the registered device ID and specifications URL without caching. Device Verification polls for completion, My Devices refreshes device records every five seconds, and dashboard data refreshes every ten seconds while the page is visible. A success dialog provides Dashboard and device-details actions, a visible five-second countdown, and a close action that cancels the redirect. These changes use the existing enrollment records and database schema.

The specifications page had unsafe assumptions about historical JSON fields (for example, requiring every storage entry to have numeric capacity fields and every adapter value to be a string). Such incomplete/null records can cause a server error during rendering. Values are now type-checked and omitted or displayed as unavailable; old diagnostic records without health scores render as “Not assessed.” The view still enforces the existing device ownership check. No real corrupted live record was modified, so the exact contents that caused the reported user's error are not independently confirmed.

## Device health and diagnostics enhancement

The prior placeholder scan did not inspect the endpoint. A browser/server-side scan cannot assess the user's separate PC, so My Devices now downloads a run-specific EXE for the target computer. That EXE gathers local, one-time signals, displays circular health gauges and findings, asks for consent, then submits a structured report. The backend validates report shape and size, accepts a time-limited single-use bearer token, and saves scores/checks to the existing `diagnostic_runs` and `diagnostic_checks` tables. Device and activity logs record start and completion. No schema change or continuous monitoring is claimed.

Health color thresholds and report persistence/replay handling pass automated tests. A follow-up fixed the EXE's `KeyError: 'drivers'`: driver health is a top-level score, not a component-score key. Health gauges now read that score correctly. The report also identifies low-free-space volumes by drive letter, differentiates configured-host connection failures at DNS, TCP, TLS, and API-path stages, and checks Windows-reported Plug-and-Play problem codes for enumerated devices. Findings include actionable, numbered steps; a PnP code can indicate a driver, configuration, resource, or connection issue but does not establish its cause. Checks for CPU temperature, SMART/storage health, startup duration, Windows event logs, and complete security posture remain unavailable or limited. Targeted tests cover the screenshot regression and sample storage/network/device findings. The updated diagnostic-mode EXE built successfully but was not run interactively or on another endpoint; report submissions used the isolated Flask test database.

## Device diagnosis data synchronization follow-up

The report path stores calculated scores in the existing diagnostic-check JSON record and stores individual measurements and findings in the existing diagnostic-check rows. A reproducible display risk was found in choosing the latest completed run by start time alone: overlapping scans can finish in a different order, and a later-started scoreless historical run could therefore hide the more recently completed health report. Page, device-list, and dashboard selection now use completion time (with run ID as a tie-breaker), and the post-commit response reloads the committed run state instead of returning a stale in-memory status.

The specification page now shows collected check summaries, measured values, units, and limitations alongside health scores and troubleshooting steps. Unmeasured signals are labeled “Not assessed” rather than presented as a fabricated value. The dashboard, diagnostic-status, and history responses disable caching; the browser continues its existing automatic dashboard refresh. A regression test creates a health report using the agent’s health calculator, submits it to the API, verifies the saved score/check data and completion response, and checks that both the dashboard and specification page display the result despite an overlapping run. This uses the isolated SQLite test database; no live MariaDB, affected endpoint, or browser session was available, so the exact historical production record remains unverified.

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

**Result:** All 54 integration tests pass. Coverage includes registration/login, password hashing, email/TOTP verification, RBAC, database configuration/error handling, CRUD, dashboard, specifications/history, archive/restore, QR enrollment, audit logs, EXE build/download behavior, inventory fallbacks, diagnostic scoring, API submission and persistence, score/measurement retrieval across overlapping runs, registration status, specification rendering with incomplete JSON and legacy reports, cache prevention, bearer-token replay rejection, audit entries, health-color thresholds, and low-storage/network/PnP findings. The browser poller retries temporary diagnostic-status connection errors, and registration/device/dashboard views automatically refresh. A smoke run on the current Windows host collected 18 checks and rendered seven gauge entries without database writes. The updated diagnostic-mode EXE built successfully as a Windows PE binary; it was not run interactively or against a separate endpoint, and recovered MariaDB was not written. Browser/accessibility testing, target-endpoint behavior, user acceptance, and per-request build performance remain unverified.

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
