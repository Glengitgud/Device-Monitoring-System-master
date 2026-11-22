# Quality Assurance Report

**System:** DevMonitor Device Monitoring System
**Review date:** 2026-11-22 (supersedes 2026-11-21)
**Branch reviewed:** `qa/scanner-window-and-readability` (from `master` @ `76faae8`)
**Reference:** [FEATURES_AND_FUTURE_WORK.md](FEATURES_AND_FUTURE_WORK.md)

## Summary

| Item | Result |
|---|---|
| Automated regression | **143 tests passed, 0 failed** (137 baseline + 6 new scanner-window tests) |
| Issues fixed this review | 3 (agent console workflow, specification readability, broken test file) |
| Open issues | 7 (none critical; see [Open issues and risks](#open-issues-and-risks)) |
| Database audit | `schema.sql` matches all 18 ORM tables; no orphaned rows; migration chain is upgrade-only (see [Database audit](#database-audit)) |
| Apple readiness | macOS: buildable via CI, registration only, needs notarization. iOS: TestFlight/App Store only, reduced inventory (see [Apple platform readiness](#apple-platform-readiness)) |

**Evidence levels used below:** **A** = automated test, **L** = live check performed in this review (real Windows host, packaged EXE, or browser), **R** = code review only, **N** = not verified (needs hardware or a deployment).

## Coverage by area

Status: ✅ Pass · ⚠️ Pass with open risk · ❌ Fail · ⏸ Not verifiable here

| Area | Status | Evidence | Mapped to FEATURES_AND_FUTURE_WORK.md | Notes / remaining work |
|---|---|---|---|---|
| Authentication & Authorization | ✅ | A, L | Account Registration and Authentication; Role-Based Access | Password login, TOTP challenge, admin re-verification, and 403 on `/api/admin/*` for standard users are all covered by tests. Password login verified live. |
| User Registration & Account Management | ✅ | A | Account Registration and Authentication | Staged email → TOTP → create flow, resend cooldowns, refresh resume. Real Gmail SMTP delivery: **N**. |
| Admin Panel | ✅ | A | Role-Based Access and Administration; Excel Export | Fresh-credential gate, audit of verify/deny/export, email masking. |
| Device Registration | ✅ | A, L | Device Registration; MAC Address Support | One-use hashed tokens, owner binding, replay rejected (packaged EXE live: second use exits 1). |
| Device Scanner (registration agent) | ✅ fixed | A, L | Windows Device Agent and Scanner | **QA-01 fixed.** Windowed EXE opens the scanner window; see the [QA-01 root cause analysis](#qa-01-downloaded-agent-opens-a-command-prompt-workflow). |
| Device Scanner (health scan) | ✅ | A, L | Windows Device Agent and Scanner; Device Monitoring | Already `--noconsole`. Real health report from this host submitted through `/api/devices/<id>/scan`, then `/api/device-agent/scans/<id>`, and rendered. Windows-only. |
| Device Verification | ✅ | A | Device Registration | Dashboard stays locked until one verified device exists; archived devices still count, deleted devices do not. |
| Device Inventory / My Devices | ✅ | A, L | Dashboard, Device Management, and UI | List, search, filter, archive/restore. Rendered live at desktop and 375 px. |
| Device Specifications | ✅ fixed | L | Dashboard, Device Management, and UI | **QA-02 fixed.** Contrast measured in the browser (see [QA-02](#qa-02-device-specifications-and-scan-results-hard-to-read)). |
| Downloads & Client Distribution | ⚠️ | A, L | Windows Device Agent; Deployment planning | Per-download and generic EXE both windowed. Unsigned EXE still triggers SmartScreen (**QA-07**). |
| Notifications & Logging | ⚠️ | A | Audit Logs and Data Privacy; Planned: alert delivery | `logs` + `activity_logs` written for enrollment, scan, admin, and export. There is **no notification centre or alert delivery** (roadmap item, not a defect). Agent writes `%LOCALAPPDATA%\DevMonitor\logs\device-agent.log`. |
| API Endpoints | ✅ | A | Implemented feature sections | CSRF on writes, bearer tokens on agent routes, size-limited and validated payloads, JSON errors. |
| Database Schema | ✅ | A, L, R | Database and Deployment Support | 18/18 tables match `schema.sql`. |
| Database Migrations | ⚠️ | R | Database and Deployment Support | `001`–`011` are upgrade deltas, not a from-empty chain (**QA-04**). No migration needed for this review's changes. |
| Security Controls | ✅ | A, R | Security hardening (partial) | No control was weakened. The new loopback hand-off is keyed (see [QA-01](#qa-01-downloaded-agent-opens-a-command-prompt-workflow)). No general rate limiter or security-header audit yet (roadmap). |
| Session Handling | ✅ | A | Account Registration and Authentication | Flask-Login sessions, admin verification bound to the session and cleared on revisit, optional secure cookies. |
| Error Handling | ✅ | A, L | Implemented feature sections | Agent errors now appear in the scanner window, in the same text as before. An expired link triggers an automatic background re-link. |
| Platform Compatibility | ⚠️ | A, L, N | Cross-platform support (partial) | Windows: **L**. Linux: built and protocol-tested, not run on hardware. Android: built, not installed. macOS/iOS: **N** (need a Mac). |

## Issues fixed in this review

### QA-01 Downloaded agent opens a command prompt workflow

**Issue**
- **Description:** Launching the downloaded Windows agent opened a black console window. It showed the inventory as text and asked the user to paste a `devmonitor://` link, type a device name and type, type `yes`, and then "Press Enter". On the generic (GitHub Release) build, the browser hand-off also launched a *second* console window.
- **Root cause:** Both Windows builds were packaged as console programs (`agent_builder.py` passed `--console` for registration mode; `publish-agents.yml` built with `--console`). `device_agent.main()` implemented registration only as `input()` prompts. A GUI existed only for the final success screen.
- **Impact:** Users did not recognise the scanner and abandoned registration, so the dashboard stayed locked (it requires a verified device).
- **Risk level:** High (blocks onboarding for every Windows user).

**Fix strategy**
- The registration EXE is now built `--noconsole` (Windows GUI subsystem). On launch it opens the **DevMonitor Device Scanner** window, which:
  1. starts collecting immediately on a worker thread;
  2. links in the background: a per-download build already carries its token, and a generic build opens the signed-in website's `/device-link/open`, which hands back a one-use link;
  3. shows the scan, with the name and type pre-filled (hostname; Laptop/Desktop from battery presence);
  4. sends nothing until the user selects **Register This Device**, which preserves the user-confirmed requirement in AGENTS.md;
  5. then shows the existing success window and opens the dashboard.
- **Single window:** when the browser re-launches the agent with the link, the new process passes it to the open window over `127.0.0.1` and exits. The port and a random per-run key are kept in `%LOCALAPPDATA%\DevMonitor\agent-handoff.json` (user profile only); a wrong key is ignored. If no window is open, the new process opens its own.
- An expired or used link (HTTP 401) automatically fetches a new link instead of telling the user to start over.
- **Files modified:** `device_agent.py` (submission extracted into `submit_payload()`/`SubmissionError`, plus `LinkHandoff`, `ScannerWindow`, `_wants_window()`, and `--cli`/`--output`), `agent_builder.py`, `.github/workflows/publish-agents.yml`, `templates/device_verification.html`, `templates/device_link_open.html`, `static/js/script.js` (copy no longer says "type yes"), `tests/test_agent_builder.py`, `tests/test_dashboard_access.py`.
- **Database impact:** None. The same enrollment endpoint, payload, and token consumption are used.
- **Backward compatibility:** The text flow is unchanged for `--yes`, `--print-specs`, `--cli`, and non-packaged runs, so CI and scripts keep working. `--print-specs --output FILE` was added because a windowed EXE should not rely on stdout. The scanner (health) mode is untouched. Linux and macOS agents are untouched.
- **Residual:** The generic build still needs one browser visit to prove which account the device belongs to (the browser holds the user's session). The per-download build needs no browser at all.

**Validation**

| Test case | Result |
|---|---|
| Packaged generic EXE PE header | ✅ Subsystem 2 (GUI): Windows never allocates a console |
| Real `ScannerWindow` on this host: scans, link arrives via hand-off, Register enabled, submits with correct bearer token, success screen opens dashboard | ✅ L |
| Packaged EXE `--print-specs --output` → `ci_backend.py validate-specs` | ✅ L |
| Packaged EXE `--print-specs > file` (stdout redirect still works when windowed) | ✅ L |
| Packaged EXE `--yes <link>` end-to-end against `ci_backend.py serve` + `check` | ✅ L (`CHECK PASSED`) |
| Replay of a used link | ✅ L (rejected, exit 1, clear message) |
| Window chosen only for a packaged, console-less launch; `--yes`/`--print-specs`/`--cli` keep the text flow | ✅ A |
| `main()` opens the window instead of prompting | ✅ A |
| Hand-off round trip; wrong key ignored; file cleaned up | ✅ A |
| Second launch with a link exits without a window | ✅ A |
| Existing console tests (cancel, `y`, expired download message) | ✅ A (unchanged) |
| Double-click on a clean Windows PC with a real browser hand-off | ⏸ N (needs a deployed site; acceptance step 7) |

**Regression status:** No regressions. 143/143 tests pass.

### QA-02 Device specifications and scan results hard to read

**Issue**
- **Description:** On *My Devices → View Device Specifications*, the device summary line ("Device ID · type · status · owner") and all muted text in *Device Scan Results* were nearly invisible. Health gauges, issue cards, and check lists were unstyled on desktop.
- **Root cause:** In `style.css`, an `@media (max-width: 575.98px)` block that should only have padded `.device-card` enclosed about 200 lines of desktop styles, including `.content-card .text-muted`. On screens wider than a phone, Bootstrap's light-theme muted colour `rgba(33,37,41,.75)` was applied on the dark card.
- **Impact:** Measured contrast **1.23:1** (WCAG minimum 4.5:1). Scan results were effectively unreadable on desktop.
- **Risk level:** Medium (accessibility and usability; no data impact).

**Fix strategy**
- The media query now holds only its mobile rules, and the desktop rules are back at top level. `.device-card-details` keeps its own mobile block.
- Added tokens `--dm-spec-value: #ffffff` and `--dm-spec-label: #dbe4ee` for the specification grid and the device details card.
- **Files modified:** `static/css/style.css`. **Database impact:** None. **Backward compatibility:** Phone layout is unchanged; desktop now gets the styles that were always intended.

**Validation** (computed in the browser against the real page, seeded with an enrolled device and a real scan)

| Element | Before | After |
|---|---|---|
| Device summary line | 1.23:1 | 10.60:1 |
| Specification value | 17.35:1 | **19.00:1** (white) |
| Specification label | 10.60:1 | 14.79:1 |
| Scan-result muted text | 1.23:1 | 10.60:1 |
| Diagnostic issue / check text | unstyled | 15.42:1 |
| Health gauge grid on desktop | not a grid | grid |
| 375 px viewport | – | No horizontal scroll; all fields visible |

**Regression status:** My Devices list and dashboard unchanged visually. No test depends on CSS.

### QA-03 Uncommitted edit broke the integration test module

- **Description / root cause:** A stray `3` was inserted before an assertion in `tests/test_database_integration.py` (line 992) in the working tree, which is a syntax error.
- **Impact:** The whole module fails to import, so its integration tests would silently drop out of a discovery run. **Risk:** Medium (hidden coverage loss).
- **Fix:** Removed the character, so the file matches `master` again. No commit is needed.
- **Validation:** Suite runs all 137 baseline tests.

## Open issues and risks

| ID | Issue | Root cause | Impact | Risk | Recommended remediation |
|---|---|---|---|---|---|
| QA-04 | SQL migrations cannot build a database from empty | `001`–`011` are deltas on the original XAMPP prototype. `roles`, `permissions`, `user_roles`, `role_permissions`, `activity_logs`, `device_metrics`, `network_interfaces`, `network_observations`, and `diagnostic_checks` are created by no migration. | A DBA who applies only the SQL files to an old install gets missing tables. They are created only if `init-db` (`create_all`) also runs. | Medium | Document "apply migrations, then `init-db`, then `check-db`" as the upgrade procedure, or add `012_create_missing_tables.sql` with `CREATE TABLE IF NOT EXISTS`. |
| QA-05 | No retention or purge of expired single-use records | No cleanup job for `device_registration_tokens`, `email_verifications`, or `registration_challenges`. | Tables grow without bound, and old hashed tokens are kept longer than needed. | Low | Add a `purge-expired` CLI command (cron) that deletes rows past expiry plus a grace period. |
| QA-06 | Cascade behaviour not exercised by tests | SQLite test DB runs without `PRAGMA foreign_keys=ON`. | `ON DELETE CASCADE / SET NULL / RESTRICT` are trusted, not tested. Production InnoDB does enforce them. | Low | Enable the pragma in the test app config. |
| QA-07 | Unsigned Windows EXE | No code-signing certificate. | SmartScreen shows "Windows protected your PC" before the scanner opens, which is a second source of first-run confusion. | Medium | Authenticode signing (roadmap: "signed Windows executable delivery"). Until then, the download card should say "More info → Run anyway". |
| QA-08 | macOS window freezes while collecting | `device_agent_unix.run_gui()` calls `collector.collect()` on the Tk thread (`system_profiler`, up to 20 s). | Window shows "Not responding" briefly. | Low | Move collection to a worker thread, as in the Windows `ScannerWindow`. |
| QA-09 | Health scanner is Windows-only | `agent_builder` requires `win32`; scanner mode exists only in `device_agent.py`. | macOS/Linux devices register but cannot produce scan results. | Low (documented limitation) | Port `collect_health_report` checks to `device_agent_unix.py`. |
| QA-10 | Local venv is Python 3.14; AGENTS.md specifies 3.12 | Environment drift. | Suite passes on 3.14; PyInstaller 6.17 builds fine. CI uses 3.12. | Low | Recreate the venv with `py -3.12` to match CI. |

## Database audit

| Check | Result | Method |
|---|---|---|
| `schema.sql` vs ORM models | ✅ 18/18 tables, all columns match | Parsed `CREATE TABLE` columns vs `db.metadata` |
| Migrations vs models | ⚠️ Upgrade-only chain (QA-04) | Cumulative `CREATE`/`ADD COLUMN` across `001`–`011` |
| Redundant columns | ✅ None found. `device_specifications.cpu_model`/`gpu_model`/`memory_bytes`/`storage_bytes` are the ORM names for agent `cpu_name`/`gpu_information`/`ram_capacity_bytes`/`storage_total_bytes`, so they are not duplicates. | Review |
| Relationships / constraints | ✅ FKs with explicit `CASCADE` (child data), `SET NULL` (audit and actor references), `RESTRICT` (device owner). Check constraints on status, lifecycle, and spec bounds. Token hash unique. | `models.py` review |
| Orphaned records | ✅ 0 devices without owner, specs without device, tokens without user, used tokens without device, runs without device, checks without run | SQL against the live QA database after real enroll + scan |
| New-feature persistence | ✅ Enrollment wrote the device, spec (incl. MAC), consumed token, `logs`, and `activity_logs`. Scan wrote `diagnostic_runs` + `diagnostic_checks`. | L |
| Changes in this review | None. No schema or migration change was required. | – |

## Apple platform readiness

### macOS (agent exists: `device_agent_unix.py` + `agents/macos/`)

| Requirement | Finding |
|---|---|
| Packaging | PyInstaller `.app` in a universal2 `.dmg` (`build_macos.sh`), built on GitHub `macos-latest` by `publish-agents.yml` / `build-apple-agents.yml`. Cannot be built on Windows. |
| Installer / download | DMG → drag to Applications. Ad-hoc signed unless the Developer ID secrets are set. Without notarization, macOS 15 requires *System Settings → Privacy & Security → Open Anyway* once. **Recommendation:** Apple Developer Program + Developer ID + notarization before public release. |
| Permissions | None required. `sysctl`, `vm_stat`, `system_profiler`, and `ifconfig` run as the user. Only the `devmonitor://` URL scheme is registered (Info.plist `CFBundleURLTypes`). Entitlement: `disable-library-validation` (PyInstaller). No Full Disk Access, admin rights, or kernel extension. |
| Collection limits | CPU/chip, cores, RAM total/used, data volume, GPUs, model identifier, macOS version, adapters, IPs, MAC (en0) are available. Not collected: SMART/disk health, temperatures, serial (deliberately). |
| Scanner compatibility | **Registration only.** The health scanner is Windows-only (QA-09). The GUI already avoids a terminal and receives links via Apple events (`::tk::mac::LaunchURL`), so it has the same single-window behaviour as the Windows fix. Collection blocks the UI (QA-08). |
| Status | ⏸ Not run on a Mac in this review. Ready for CI build; needs notarization and a hardware acceptance pass. |

### iOS / iPadOS (agent exists: SwiftUI app in `agents/ios/`)

| Requirement | Finding |
|---|---|
| Deployment | Only App Store, TestFlight (public link via `IOS_DISTRIBUTION_URL`), Ad Hoc (≤100 registered UDIDs per year), or Apple Business Manager custom apps. An `.ipa` cannot be a normal website download. The site offers an OTA `itms-services://` link only for valid Ad Hoc/Enterprise IPAs over HTTPS. Requires the Apple Developer Program. |
| Platform restrictions | Sandboxed. No arbitrary process execution, no system-wide telemetry, no background scanning without a qualifying background mode. App Transport Security requires HTTPS (a `localhost` exception only). |
| Permissions | None requested; the app uses only public `UIDevice`/`ProcessInfo` APIs. The `devmonitor://` scheme receives the link. Local Network permission is needed only for a LAN (non-HTTPS-domain) server, which ATS blocks anyway. |
| Unsupported by iOS security | MAC address (returns a constant), serial number, IMEI, system-wide RAM usage, other apps' or processes' data, GPU details, device name (iOS 16+ without an entitlement), and free/total disk off-device (required-reason API policy). Health scanning equivalent to Windows is not possible. |
| Recommended compliant approach | Keep the iOS app as an **inventory-only registration client** distributed via TestFlight → App Store. Keep the existing privacy manifest (`agents/ios/Resources/PrivacyInfo.xcprivacy`) in step with every required-reason API the collector uses. Fleet-managed iPhones should be handled through **MDM** (Apple Business Manager + an MDM server) rather than a custom agent: MDM is the only Apple-sanctioned route to serials, compliance state, and inventory. |
| Status | ⏸ Not built or run in this review (needs Xcode on macOS). |

## Regression testing summary

| Suite / check | Result |
|---|---|
| `python -m unittest discover -s device_monitoring_prototype/tests` (baseline, before changes) | 137 passed |
| Same, after QA-01 | 143 passed |
| Same, after QA-01 + QA-02 (final) | 143 passed |
| Authentication, registration, admin, CSRF, masking, export | Pass (A) |
| Device registration, verification, dashboard lock/unlock | Pass (A + L) |
| Device scanner submission and history | Pass (A + L) |
| My Devices, specifications, scan results (desktop + 375 px) | Pass (L) |
| Downloads: builder flags, workflow text, package validators, release manifest | Pass (A); packaged EXE built and run (L) |
| Database operations: enroll, scan, orphan queries | Pass (L) |
| Security controls bypassed | None. Tokens, CSRF, ownership, and admin checks unchanged. |

## User acceptance (remaining live checks)

1. On a clean Windows 11 PC, sign in on the deployed site, download from **Downloads**, and double-click. Expect SmartScreen (QA-07), then **only** the DevMonitor Device Scanner window. There must be no console at any point.
2. Generic build: the browser opens `/device-link/open`; choose **Open**. Expect no second window, and the open scanner shows "Scan complete".
3. Select **Register This Device**. Expect the success window, then the dashboard unlocks.
4. Open **My Devices → View Device Specifications** on a desktop monitor and a phone. All text must be clearly legible.
5. Real Gmail SMTP sign-up, production MySQL `check-db` after migrations, and a macOS DMG install on hardware.

## Recommended git commits

| Commit | Scope |
|---|---|
| `f2ce57a` Open the scanner window when the Windows agent is launched | QA-01 |
| `1945459` Make device specifications readable on desktop | QA-02 |
| Update the QA report for the scanner window and readability fixes | This report + `FEATURES_AND_FUTURE_WORK.md` |

## Run the regression suite

```powershell
python -m unittest discover -s device_monitoring_prototype\tests
```
