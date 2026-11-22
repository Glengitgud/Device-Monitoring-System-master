# DevMonitor — Features and Future Work

**System:** Device Monitoring System  
**Document status:** Capstone implementation baseline  
**Review date:** 2026-11-21

This document describes the functionality present in the current
`device_monitoring_prototype` codebase. Status is based on implementation,
database models, Flask routes, UI templates, and automated tests. Items marked
as partially implemented are operational only within documented limitations.

## Implemented Features

### Account Registration and Authentication

- Public staged registration requires a username, display name, email, and an
  8–16 character password containing at least one capital letter and one
  special character.
- Registration sends a six-digit Gmail email verification code that expires
  after five minutes. Codes are HMAC-hashed, single-use, attempt-limited,
  resend-cooled, and hourly-limited.
- Registration then requires a Google Authenticator-compatible TOTP code.
  TOTP secrets are encrypted at rest and TOTP replay is rejected.
- The account is created only after email and TOTP verification succeed.
- New passwords use bcrypt. Existing Werkzeug password hashes remain
  verifiable for migration compatibility.
- Login accepts a username or registered email. TOTP-enabled accounts receive
  a second-factor challenge after password verification.
- Sessions use Flask-Login with CSRF protection on API writes.
- Administrator login is separate from administrator panel verification.
  `/admin` and `/api/admin/*` require a fresh password check and active
  Administrator role.
- Account status, password, role, and email verification data are persisted and
  checked server-side.

### Role-Based Access and Administration

- Role and permission models support Administrator and User roles.
- Server-side checks restrict administrator pages, user management, audit logs,
  exports, and administrator-only device deletion.
- Device pages and APIs are owner-scoped, while administrators can manage all
  active, archived, and deleted devices.
- Administrators can create accounts, assign Administrator or User roles,
  update account status and profile data, and deactivate accounts.
- Reserved bootstrap account `admin` is excluded from public and
  administrator user-management operations.
- Administrator verification, panel access, account actions, device actions,
  scan actions, and export actions are recorded in the audit system.

### Device Registration

- Standard users receive a QR-based, 30-minute, single-use enrollment flow.
- Enrollment tokens are random, SHA-256 hashed at rest, owner-bound,
  revocable, and consumed atomically after registration.
- The QR page synchronizes its countdown and status with the server.
- Regenerating a token revokes the previous unused token.
- The enrollment page requires explicit account verification and confirmation
  of trust before an executable is downloaded.
- QR registration is unavailable to Administrator accounts.
- Successful registration links and verifies the device, stores the owner and
  registrant, captures inventory, and unlocks the standard-user dashboard.
- Registration success shows a confirmation state with a five-second automatic
  dashboard redirect and immediate navigation controls.

### MAC Address Support

- The Windows enrollment and scanner agents collect an available hardware MAC
  address.
- MAC addresses are validated in colon-separated hexadecimal format and stored
  in uppercase.
- The address is persisted on the device and its enrollment token.
- Device details and specifications views expose the stored MAC address.
- Network interface records can retain interface names and MAC addresses.
- Migration `011_device_mac_address.sql` provides additive support for existing
  databases.

### Windows Device Agent and Scanner

- The application host can build one-file Windows executables with PyInstaller.
- Registration mode is a windowed executable: launching it opens the
  DevMonitor Device Scanner, which scans immediately, shows the detected
  inventory, and submits it only after the user selects Register This Device.
  Linking to the account happens in the background; no console is shown.
  Text prompts remain available for automation (`--yes`, `--print-specs`,
  `--cli`).
- Scanner mode is a silent, no-console executable with a short-lived bearer
  token and an explicit submission endpoint.
- Collector components are best-effort: a failed hardware or network check does
  not prevent the remaining inventory from being submitted.
- Collection includes CPU name and core count, RAM capacity and usage, storage
  devices and available space, GPU information, motherboard brand, OS details,
  network adapter names, IP addresses, and MAC address.
- Scanner reports include overall, hardware, software, and driver scores;
  component scores; individual checks; detected issues; severity; root-cause
  text; recommendations; and numbered troubleshooting steps.
- Network checks distinguish DNS, TCP, TLS, and endpoint-path failures.
- Storage findings identify affected volumes. Unsupported values remain
  unavailable rather than being inferred.
- Diagnostic and inventory submissions are size-limited and strictly validated.

### Device Monitoring

- Active, archived, and deleted lifecycle states are stored separately from
  online, offline, maintenance, retired, and unknown connectivity status.
- A device is marked online after a successful IP-bearing registration or
  scanner submission and is recorded with `last_seen_at`.
- Devices without a successful scan or check-in for five minutes transition to
  offline and produce a device event and audit record.
- Dashboard and device views refresh through browser-side polling.
- The dashboard shows total, online, and offline fleet counts plus device,
  owner, operating system, CPU, RAM, health, and status information.
- Health data reflects the latest approved one-time scanner result. It does not
  represent continuous telemetry.
- Scanner history is retained in `diagnostic_runs` and `diagnostic_checks`.
- A 15-minute scanner authorization expires if a report is not submitted.
- Resource samples are represented in the schema, but live CPU, memory, storage,
  and network collection is not performed continuously.

### Dashboard, Device Management, and UI

- The dashboard is database-backed and restricted for standard users until at
  least one verified device is registered.
- My Devices provides owner/registrant-scoped inventory, status filtering,
  search, sorting, pagination, details, specifications, archive/restore, and
  administrator soft-delete operations.
- Device details show collected specifications, IP information, MAC address,
  lifecycle state, timestamps, event history, scanner runs, network records,
  and metrics when present.
- Archived Devices provides device search and lifecycle restoration.
- The custom responsive dark UI includes desktop navigation and a mobile
  sidebar, status badges, cards, tables, alerts, and modal flows.
- Browser-side values are escaped and presentation data is returned from
  server-authorized endpoints.

### Audit Logs and Data Privacy

- Two audit streams are implemented: device event `logs` and broader
  `activity_logs`.
- Audit records include actor, event type, entity, timestamp, IP address where
  applicable, and success or reason details.
- Administrator credential values, email verification codes, and submitted
  passwords are not persisted in audit details.
- Server-side masking protects email addresses in administrative listings,
  audit details, and exports. Operational usernames and device fields remain
  visible.
- Device and account history is preserved by archive and soft-delete behavior.
  There is no physical-delete route for devices.
- Export and sensitive-view operations are re-authenticated or
  permission-gated and audited.

### Excel Export

- Administrators can export selected Users, Devices, Device Information, Audit
  Logs, and Monitoring Data worksheets to an in-memory `.xlsx` workbook.
- Export requires fresh administrator username and password verification.
- Denied, started, failed, and successful export attempts are audited.
- The export is downloaded directly and is not written to public static
  directories.

### Database and Deployment Support

- Flask-SQLAlchemy models define users, RBAC, staged registration, email
  verification, devices, specifications, MAC addresses, network observations,
  diagnostic runs/checks, metrics, device events, and activity logs.
- `schema.sql` provides a full MySQL/MariaDB schema for new installations.
- Additive migrations `001` through `011` support documented upgrade paths.
- `init-db` creates missing model-backed tables, default roles, and the
  development Administrator account without resetting existing credentials.
- `check-db` performs read-only model/schema parity checks.
- `check-mail` validates Gmail SMTP connectivity and authentication without
  sending mail.
- The application supports XAMPP on Windows, environment-based database
  configuration, `.env` credentials, pooled connection pre-ping, and optional
  secure session cookies.
- `create-admin` and `seed-sample-data` provide controlled CLI setup.
- Automated Flask, database, authentication, and agent-builder tests cover
  core workflows in an isolated SQLite test database.

## Partially Implemented Features

| Area | Current implementation | Remaining limitation |
|---|---|---|
| **Device monitoring** | Online/offline state, last-seen timestamps, five-minute stale-status transition, and latest scanner health | No persistent agent or continuous CPU/RAM/storage/network telemetry |
| **Device Scanner** | One-time, authorized Windows inventory and health report | Windows-only, per-run executable, user-initiated, and no persistent scheduling |
| **Device health diagnostics** | CPU, RAM, storage, GPU, network, operating-system, driver, and PnP checks with color bands and guidance | Smart/disk-health, CPU temperature, startup timing, event-log, and complete security posture may be unavailable |
| **Dashboard updates** | Browser polling and scanner-completion refresh | No WebSocket or server-sent event push and no real-time trend display |
| **Manual device registration** | A server API can create an owned device and collect the Flask-host inventory | Not the primary QR workflow and not exposed as the modern My Devices registration path |
| **Cross-platform support** | Windows 64-bit executable build and collection | macOS, Linux, ARM, and mobile endpoint collectors are not implemented |
| **Deployment planning** | Local XAMPP/Flask setup, environment configuration, migrations, database and mail checks | HTTPS, code signing, production server configuration, backups, and operations are deployment prerequisites rather than completed production services |
| **Data privacy controls** | Masking, soft lifecycle operations, environment-secret handling, and audit records | No configurable retention policy, consent ledger, data subject workflow, or formal privacy review |
| **Security hardening** | CSRF, server-side authorization, password hashing, TOTP, email throttles, validated reports, and secure-cookie configuration | No completed penetration test, general web request-rate limiter, security headers audit, or production key-management integration |

## Planned Features

These items are supported as roadmap work only when they are not already
present in the codebase.

- Independent account recovery and password-reset flow.
- Password-reset audit controls and account unlock/recovery operations.
- Administrator-managed organization email domains and verified-domain login
  policies.
- Persistent, explicitly consented endpoint agent lifecycle.
- Agent installation, update, signature verification, pause/stop controls, and
  device credential revocation.
- Scheduled and automatically initiated endpoint scans.
- Continuous CPU, RAM, storage, and connectivity telemetry.
- Historical resource and utilization trend charts.
- Offline/threshold alert delivery by email or in-app notification center.
- SMS, webhook, Slack, or PagerDuty integrations.
- PDF and CSV reports for inventory, health, and user activity.
- General API request and login rate limiting.
- Production security review, automated vulnerability scanning, and hardening
  of security headers and error responses.
- HTTPS deployment and signed Windows executable delivery.
- Containerization and production reverse-proxy/application-server deployment.
- Load balancing and horizontal scaling for large organizations.
- Expanded audit coverage for future schedules, recovery, notifications,
  retention, and operations.

## Future Enhancements

- macOS inventory and diagnostics collector.
- Linux inventory and diagnostics collector.
- Mobile operating-system support, subject to platform security and permissions.
- Architecture-aware and signed multi-platform agent builds.
- Centralized schedule, policy, and endpoint configuration management.
- Configurable health thresholds and organization-specific alert policies.
- Metrics retention tiers, archival, purge, and privacy-compliant export.
- Capacity and fleet-health analytics, forecasting, and executive reporting.
- Optional machine-learning-assisted anomaly detection based on verified
  historical telemetry.
- Progressive web application or native administrative clients.
- Organization-wide directory/identity integration after domain ownership and
  identity-provider verification are established.
- High-availability database deployment and documented disaster recovery.

## Implementation Scope

DevMonitor is a database-backed Flask prototype with verified QR device
enrollment, consented Windows inventory and one-time health scanning,
owner-scoped device management, administrator controls, audit records, and
Gmail/TOTP account protection. It does not continuously monitor endpoints,
silently install agents, or provide a production operations platform.
