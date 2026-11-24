# Quality Assurance Report

**System:** DevMonitor Device Monitoring System
**Review date:** 2026-11-25 (supersedes 2026-11-22)
**Branch reviewed:** `feature/device-limits-admin-verification` (from `master` @ `33e8cef`)
**Reference:** [FEATURES_AND_FUTURE_WORK.md](FEATURES_AND_FUTURE_WORK.md)

This report records what has been tested in DevMonitor, how it was tested, and what still needs work. It is written for a capstone demonstration: each row says what a feature does and how we know it works.

## Summary

| Item | Result |
|---|---|
| Automated regression | **208 tests passed, 0 failed** (177 before this review, 31 new) |
| Added in this review | MAC-based duplicate prevention, 4-device limit, admin sign-in code, 5-minute code countdown |
| Database | 19 ORM tables match `schema.sql`; migrations `013` and `014` added (additive, apply once) |
| Open issues | 11, none critical (see [Open issues and risks](#open-issues-and-risks)) |
| Not implemented | Password reset / account recovery (roadmap item) |

**Evidence:** **A** = automated test, **L** = live check on real hardware or in a browser (this review: local preview with a throwaway SQLite database), **R** = code review only, **N** = not verified yet (needs hardware, a Mac, or a deployment).
**Status:** ✅ Pass · ⚠️ Pass with an open risk · ❌ Fail · ⏸ Not verifiable here · ➖ Not implemented

## 1. Database

| What is checked | Status | Evidence | Notes |
|---|---|---|---|
| Users, roles, permissions (`users`, `roles`, `permissions`, `user_roles`, `role_permissions`) | ✅ | A | `init-db` seeds roles and the reserved `admin` account once and never resets credentials. |
| Authentication data (bcrypt hash, encrypted TOTP secret, `email_verified`, `status`) | ✅ | A | Legacy Werkzeug hashes still verify. |
| Staged registration (`registration_challenges`, `email_verifications`) | ✅ | A | Codes stored only as HMAC hashes. |
| Email code generation and 5-minute expiry | ✅ | A | `EMAIL_CODE_LIFETIME` = 5 min; boundary tested at 4:50 (accepted) and 5:01 (refused). |
| Admin sign-in codes (`login_verifications`, migration `014`) | ✅ | A | HMAC hash, 5-min expiry, 5 attempts, single use. |
| Device registration and ownership (`devices.owner_user_id`, `registered_by_user_id`, `is_verified`) | ✅ | A | Owner FK is `RESTRICT`; archive/soft-delete keep history. |
| Enrollment tokens (`device_registration_tokens`) | ✅ | A | SHA-256 hashed, 30-min, single-use, claimed atomically; new `rejected_at`/`rejection_reason` (migration `013`). |
| MAC address storage and uniqueness | ✅ | A, R | Stored as `00:11:22:AA:BB:CC`; `ix_devices_mac_address` index. Uniqueness is enforced in `services.py` (see [design note](#mac-duplicate-rule)). |
| Live monitoring (`devices.monitoring_*`, `device_metrics`) | ✅ | A | Only the credential hash is stored; 7-day retention. |
| Sessions | ✅ | A | Flask-Login signed cookie; no server-side session table. Pending sign-in state is cleared on success, failure limit, or "Back". |
| Audit logs (`logs`, `activity_logs`) | ✅ | A | New events: `device.registration_rejected`, `auth.admin_login_code_sent`, `auth.admin_login_code_failed`, `auth.admin_password_reset`. Codes and passwords are never logged. |
| `schema.sql` vs models (`check-db`) | ✅ | A | 19/19 tables, indexes, unique keys, FKs, and check constraints. |
| Migration chain | ⚠️ | R | Upgrade-only from the XAMPP prototype (QA-04). `013`/`014` are additive. |
| Cascades in tests | ⚠️ | R | SQLite tests run without `PRAGMA foreign_keys` (QA-06). |

## 2. Device registration and security

| What is checked | Status | Evidence | Notes |
|---|---|---|---|
| Duplicate device on the same account | ✅ | A | HTTP 409 "This device is already registered to your account." |
| Same device on a different account | ✅ | A | HTTP 409 "This device is already registered to another account." |
| MAC normalisation (`-` or `:`, any case) | ✅ | A | `3c-22-fb-aa-bb-cc` and `3C:22:FB:AA:BB:CC` are the same device. |
| Archived / deleted devices | ✅ | A | Archived blocks other accounts; the owner may re-register. Admin soft-delete releases the MAC. Restoring a duplicate is refused. |
| Phones and tablets without a real MAC | ✅ | A | Android 10+ sends none; iOS's `02:00:00:00:00:00` is ignored, so mobile enrollment is unaffected. |
| 4-device limit (standard users) | ✅ | A | Enforced on enrollment, manual add, restore, and when issuing QR/download/app-link tokens. Archived devices do not count; admins exempt. |
| Refusal reaches the user | ✅ | A, R | Agents show the server's `error` (Windows, Linux/macOS, Android, iOS); the **Link a Device** page shows a red "Device not registered" notice. |
| Token validation (expired, used, revoked, wrong owner, replay) | ✅ | A, L | A refused (duplicate/limit) enrollment does not consume the token. |
| Device linking (QR scan-to-register, direct download, `devmonitor://` app link) | ✅ | A, L | Admins cannot create enrollments. |
| Device verification gate | ✅ | A | Dashboard stays locked until one verified, non-deleted device exists. |

### MAC duplicate rule

One physical device belongs to one account. A device counts as already registered when another device row has the same MAC and is **active** (any account) or **archived on a different account**. The archived device's own owner may register it again (it is their device), and a device removed by an administrator (soft delete) frees its MAC. The rule lives in `services.ensure_mac_address_available()`. It is not a database `UNIQUE` key because archived and deleted rows keep their MAC for history, phones report no MAC, and existing installs may already hold duplicates.

## 3. Authentication

| What is checked | Status | Evidence | Notes |
|---|---|---|---|
| Sign-in (username or email + password) | ✅ | A, L | Wrong password: 401 and audit row. |
| Second factor for standard users (TOTP) | ✅ | A | Replay and drift window tested. |
| Registration (email code → TOTP → account) | ✅ | A | Resume after refresh, cancel, resend cooldown and hourly limit. |
| 5-minute email code with visible countdown | ✅ | A, L | The dialog shows `m:ss`, amber in the last minute, red when expired; expired codes are refused with a **Resend code** hint, and the timer restarts on resend. |
| Real Gmail delivery | ⏸ | N | `check-mail` validates SMTP; real delivery needs the production mailbox. |
| Password reset / recovery | ➖ | – | Not implemented (roadmap). Admin password can be reset by CLI only (`create-admin --reset-password`). |
| Session handling | ✅ | A | Session cleared at sign-in, logout, and for inactive accounts; optional secure cookies. |
| Unauthorised access | ✅ | A | Anonymous → login; standard users → 403 on admin routes; other owners' devices → 404/403; CSRF required on writes. |

## 4. Administrator module

| What is checked | Status | Evidence | Notes |
|---|---|---|---|
| Admin account uses `devmonitor.system@gmail.com` | ✅ | A | Configurable as `ADMIN_EMAIL`. `init-db` and migration `014` move the old `admin@localhost`; `create-admin` refuses any other address. |
| Admin sign-in = password + emailed 6-digit code | ✅ | A, L | Password alone signs nothing in; the code page shows a 5-minute countdown and **Resend code** (60 s cooldown). |
| Wrong, expired, reused, or too many codes | ✅ | A | All refused; mail failure keeps the admin signed out (503). |
| Admin panel re-verification (`/admin`, `/api/admin/*`) | ✅ | A | Password on every visit; the first visit after each sign-in also needs a 5-minute emailed code (with countdown and resend). |
| User management (create, role, status, final-admin guard) | ✅ | A | |
| Device management (archive, restore, soft delete, scan) | ✅ | A | |
| Audit log viewer and Excel export | ✅ | A | Export needs fresh credentials and is audited; emails are masked. |

## 5. Monitoring, scanning, and the dashboard

| What is checked | Status | Evidence | Notes |
|---|---|---|---|
| Live monitoring (opt-in consent, 30 s heartbeats, Offline after 90 s, Stop) | ✅ | A | Consent defaults to "Not now"; stop from website, device, archive, or inactive owner. |
| Task Manager entry ("DevMonitor Live Monitoring", startup entry) | ✅ | A, R | Window-less launch and naming tested; viewing it in Task Manager on a clean PC: N. |
| Device scanner (registration window) | ✅ | A, L | Sends nothing until **Register This Device**. |
| Health diagnostics (one-time scan) | ✅ | A, L | Windows only (QA-09). |
| Dashboard (counts, status, polling) | ✅ | A, L | |
| My Devices (list, search, filter, details, archive/restore) | ✅ | A, L | |
| Downloads and installation | ⚠️ | A, L | Packages validated before they are offered; unsigned Windows EXE triggers SmartScreen (QA-07). |
| Scan-to-register (QR) | ✅ | A, L | |

## 6. Cross-platform

| Platform | Status | Evidence | Notes |
|---|---|---|---|
| Windows (agent, scanner, live monitoring) | ✅ | A, L | Only platform with health scanning and live monitoring. |
| Linux (`.deb` / portable) | ⚠️ | A | Built and protocol-tested end to end; not run on hardware. |
| macOS (DMG) | ⏸ | A, N | Collector and CI build tested; needs notarization and a Mac (QA-08). |
| Android | ⏸ | R, N | Sends no MAC, so it is never blocked as a duplicate; not installed on a phone. |
| iOS | ⏸ | A (CI), N | Constant placeholder MAC is ignored; TestFlight/App Store distribution only. |
| Browser (desktop and 375 px) | ✅ | L | Admin code page (desktop) and registration countdown (375 px), including the red expired state, checked live in this review. The rejection notice was not viewed live. |

## Open issues and risks

| ID | Issue | Impact | Risk | Recommendation |
|---|---|---|---|---|
| QA-04 | SQL migrations cannot build a database from empty | Old installs that apply only the SQL files miss tables created by `init-db`. | Medium | Document "migrations → `init-db` → `check-db`", or add a `CREATE TABLE IF NOT EXISTS` migration. |
| QA-05 | No purge of expired single-use records | `device_registration_tokens`, `email_verifications`, `registration_challenges`, `login_verifications` grow without limit. | Low | Add a `purge-expired` CLI job. |
| QA-06 | Cascades not exercised in tests | FK `CASCADE`/`RESTRICT` trusted, not tested. | Low | Enable `PRAGMA foreign_keys=ON` in the test config. |
| QA-07 | Unsigned Windows EXE | SmartScreen warning on first run. | Medium | Authenticode signing. |
| QA-08 | macOS window freezes while collecting | Brief "Not responding". | Low | Collect on a worker thread. |
| QA-09 | Health scanner is Windows-only | Other platforms register but cannot scan. | Low | Port the checks to `device_agent_unix.py`. |
| QA-10 | Local venv is Python 3.14; AGENTS.md says 3.12 | Environment drift (suite passes on 3.14). | Low | Recreate the venv with `py -3.12`. |
| QA-11 | MAC uniqueness is application-level | Two enrollments of the same new device in the same instant could both succeed. | Low | Acceptable for a prototype; a MySQL generated column + unique key on active rows would close it. |
| QA-12 | A scan can update a device's MAC without the duplicate check | A device whose primary adapter changes could take another device's MAC. | Low | Call `ensure_mac_address_available` in `scanner.py` before saving a new MAC. |
| QA-13 | Agent test depends on whether stdin is a terminal | `test_monitoring_is_only_enabled_on_an_explicit_yes` failed in 2 of 5 full runs during this review (once before any new test existed) and always passes alone; the final 3 full runs passed. | Low | Patch `sys.stdin.isatty` in the test's `offer()` helper. |
| QA-14 | `FEATURES_AND_FUTURE_WORK.md` is out of date | It still says monitoring is not continuous and only Windows is supported, and it lists neither the device limit nor admin codes. | Low (documentation) | Refresh it from this report. |

## Coverage gaps and recommended extra tests

1. **Password reset** does not exist yet; when it is added, test token expiry, single use, and audit.
2. **Concurrency:** two simultaneous enrollments with one MAC (needs MySQL, not SQLite).
3. **Migrations on MySQL/TiDB:** apply `013` and `014` to a copy of production and run `check-db`.
4. **Browser check** of the red "Device not registered" notice on the Link a Device page (the countdowns were checked live).
5. **Real Gmail delivery** of the admin sign-in code to `devmonitor.system@gmail.com`.
6. **Mobile apps** showing the 409 "already registered" and "up to 4 devices" messages on real phones.
7. **Scanner MAC change** (QA-12) once fixed.

## Regression testing summary

| Suite / check | Result |
|---|---|
| Baseline on `master` before changes | 177 passed |
| After this review (full suite) | 208 passed |
| New: `test_device_registration_rules.py` | 11 tests: duplicates (same/other account, archived, deleted, mobile), limit, website notice |
| New: `test_admin_login_verification.py` | 15 tests: admin panel code, code required, wrong/expired/locked code, resend cooldown, mail failure, `init-db`/`create-admin` |
| New: `test_email_code_expiry.py` | 5 tests: 5-minute lifetime, countdown value, boundary, resend, page markup |
| Updated existing tests | Admin sign-ins finish the email-code step (`complete_admin_login`); `check-db` expects 19 tables; verification status includes `registration_rejection` |
| Security controls weakened | None. CSRF, owner scoping, token hashing, and admin re-verification are unchanged. |

## User acceptance (demo checklist)

1. Register a new account: watch the code countdown, let one code expire, select **Resend code**, finish with the new code.
2. Link a Windows PC. Run the same agent again on the same PC: the agent and the **Link a Device** page both say "already registered".
3. Sign in on a second account and try the same PC: "already registered to another account".
4. Link four devices, then try a fifth: "You can register up to 4 devices".
5. Sign in as `admin`: after the password, enter the code sent to `devmonitor.system@gmail.com` before the timer runs out.

## Run the regression suite

```powershell
python -m unittest discover -s device_monitoring_prototype\tests
```
