# Device Monitoring Prototype — Feature Summary

## Implemented Features vs. Future Development

This document separates working, database-backed prototype features from
the enhancements that still require production development.

---

## UI/UX Design

The prototype uses a **dark minimal theme** built on a custom colour
palette derived from three core hex values:

| Token | Hex | Usage |
|---|---|---|
| `--dm-darkest` | `#0d0221` | Page backgrounds, deepest surface |
| `--dm-dark` | `#0f084b` | Sidebar, top navbar, card headers |
| `--dm-accent` | `#26408b` | Primary buttons, active states, focus rings |

Design principles followed:

- **Dark-first, minimal UI** — reduces visual clutter and eye strain.
- **Consistent spacing & border radii** — 12 px card radius, 8 px input radius.
- **Accessible contrast** — light text on dark surfaces meets WCAG AA.
- **Responsive layout** — sidebar collapses to a mobile drawer at ≤ 992 px.
- **Clean login screen** — no extraneous information; a focused sign-in form.

---

## Implemented Database Features

The application uses MySQL through Flask-SQLAlchemy. New public accounts are staged in a temporary registration challenge and are not created until both Gmail email and Google Authenticator checks pass. Email uses configurable Gmail SMTP with STARTTLS; six-digit codes are HMAC-hashed, expire after five minutes, are single-use, and have bounded attempts and resend cooldown/hour limits. New passwords use bcrypt; existing Werkzeug hashes remain verifiable for backward compatibility. Authenticator secrets are Fernet-encrypted at rest. Existing accounts are retained as verified during migration; TOTP is required at sign-in whenever enabled. Login accepts a username or registered email. Auth forms provide real-time email-format feedback, while registration checks case-insensitive email uniqueness on the server. On first setup, `init-db` creates the reserved `admin` account with the Administrator role and bootstrap password `admin123`; rerunning it preserves existing credentials and account status. Administrator-only user management/log access and owner-scoped device operations are enforced by Flask views, not by JavaScript alone. Device enrollment continues to use separate, expiring, single-use QR tokens; administrators cannot access device registration.

| Feature | Current implementation |
|---|---|
| **User Registration and Login** | Account creation enforces password policy and matching confirmation. A required six-digit email code and authenticator TOTP are verified before the account row is created. Existing users may sign in with a username or email; users with TOTP enabled must complete the second-factor challenge. |
| **Email Verification** | A registration popup requests a six-digit code sent through Gmail SMTP (`smtp.gmail.com:587`, STARTTLS) from the authenticated Gmail account. The multipart plain-text/HTML message includes DevMonitor branding and the five-minute expiry. Codes are HMAC-hashed at rest, cannot be reused, and have bounded attempts plus 60-second resend cooldown/hourly limits. SMTP sender/account mismatches and malformed messages are rejected; failed initial delivery expires the unsent code and permits an immediate retry, while failed resends consume the cooldown to prevent abuse. `check-mail` validates SMTP connectivity/authentication without sending; delivery failures and code rejection are logged without logging credentials or codes. |
| **Google Authenticator** | A unique TOTP secret is generated per pending registration, encrypted in the database, and delivered to the UI only as a provisioning QR. RFC 6238 6-digit codes are checked with a small clock-skew window and replay protection. Successful verification stores the encrypted secret and verification timestamp. |
| **Authentication Database Changes** | `users.email_verified` defaults to false for newly created rows; legacy accounts retain their verified state. `registration_challenges` stages account data and rate-limit counters. `email_verifications` stores HMAC-digested codes, expiry, verified/used state, and timestamps; plaintext codes are never persisted. Migration `010_gmail_email_verification.sql` adds the table and default without deleting existing data. |
| **Role-Based Access** | Roles and permissions are stored in RBAC tables; `/admin`, user-management, and administrator log endpoints require an administrator. |
| **Device Registration and Verification** | Account registration issues a 30-minute QR link containing a random token stored as a SHA-256 hash. Scanning opens a verification page; explicit account verification and a trust confirmation are required before the token-bound Windows EXE is built and downloaded. The QR is rendered on a white canvas with a dark pattern, displays a server-clock-synchronized countdown/token status, and can be regenerated; regenerating revokes the prior unused token. A dashboard link enters the same protected flow. Successful registration links the device, marks it verified, and unlocks protected dashboard/device/monitoring routes. Administrators always retain dashboard access and can manage existing devices but cannot register devices or use QR enrollment. |
| **Windows EXE Device Agent** | On a 64-bit Windows application host, PyInstaller builds a one-file executable with the confirmed enrollment token and server URL. It collects only CPU name/core count, RAM capacity/usage, storage devices/capacity/available space, GPU, motherboard brand, OS name/version, network adapter names, and IP addresses from the computer running the EXE. Native Windows, registry, and `psutil` collectors handle each component independently; a failure is logged and unavailable fields do not prevent the remaining inventory from being reviewed or submitted. Diagnostics rotate at `%LOCALAPPDATA%\DevMonitor\logs\device-agent.log`, with temp-directory/console fallbacks. Users need no Python installation or manual agent configuration; the EXE displays the inventory and asks before submission. It does not run persistently or collect telemetry. |
| **Device Specifications** | The confirmed inventory is validated, stored with the device and owner, and available on the Detected Device Specifications page and from the existing View action. Registration/update dates, status, and device event history are shown. |
| **Device Editing and Removal** | Active devices can be updated; archive/restore uses a lifecycle state, while administrator deletion is a retained soft delete. No application route physically removes devices. |
| **Device Health and Diagnostics** | My Devices can build a run-specific Windows diagnostic EXE for the target device. The user runs it on that computer to collect hardware/software signals and confirms submission; results are not shown in a separate local report window. Score/check reports are validated and saved in the existing `diagnostic_runs` and `diagnostic_checks` tables for display inside the website; device and activity logs record scan start/completion. Health scoring is a one-time advisory assessment, not continuous monitoring. |
| **Health Indicators and Guidance** | CPU, RAM, storage capacity, GPU presence, network, driver metadata, Windows-reported Plug-and-Play problem codes, and selected OS/service signals use circular indicators and color bands (green 80–100, yellow 60–79, orange 40–59, red 0–39). Findings include severity, root cause, impact, recommended fix, and numbered troubleshooting steps (for example High RAM Usage, Low Storage Space, and Network Connectivity Problems). Network checks distinguish DNS, TCP, TLS, and endpoint-path failures; low storage names the affected volume. A PnP code identifies a reported device problem but cannot by itself prove a loose connection. Unsupported signals are not inferred. |
| **Diagnostic History** | Device details/history retain each diagnostic run, its saved checks, scores, recommendations, and status. Dashboard health links open the corresponding device report. |
| **Registration Completion** | Successful QR registration displays a success state, Dashboard shortcut, and five-second automatic redirect with an immediate navigation option. |
| **User Management** | Administrators can create accounts, update roles/status, and deactivate users without deleting their history. |
| **Device Details and Logs** | Owners/registrants see their device specifications; administrators can view and manage all active/archived devices and see complete device and audit history. Device search and status filtering, archive/restore, and retained soft deletion are available. Administrators can also search/filter activity and device event logs. These are application records, not operating-system or web-server logs. |
| **Dashboard** | Fleet counts and rows are queried from MySQL. Standard users need at least one non-deleted verified device and see their verification status; unverified users cannot access device or monitoring pages/APIs. Administrators are not subject to this gate. |
| **Search, Sort and Pagination** | Browser-side presentation of records returned from the database-backed endpoints. |
| **Input and Session Security** | Server-side validation, CSRF token checks, bcrypt password hashes for new accounts, legacy hash verification, HMAC-digested single-use email codes, resend/attempt throttles, Fernet-encrypted TOTP secrets, HttpOnly/SameSite cookies, and configurable Secure cookies. Gmail app credentials are loaded only from `.env`; SMTP and verification logs never include credentials or submitted codes. |
| **Database Health Check** | `check-db` compares model tables, columns, indexes, foreign keys, and check constraints with the configured database and reports key record counts without modifying data. |

---

## Remaining Work for Production Monitoring

To turn this prototype into a production-ready system, the following
areas would need to be designed and built with proper backend
technologies.

### 1. Account Hardening
- Add password reset and operational account recovery. Registration and login MFA are implemented; production still needs independent security review and operational alerting for abuse.
- The reserved `admin` / `admin123` bootstrap credential is for local setup only and is created only when the account is missing; rerunning `init-db` preserves existing credentials and account status. Replace the bootstrap credential before deployment.
- For multi-domain login, keep local username login separate from organization email login. Validate email syntax, normalize and check the domain against an administrator-managed allowed-domains table, verify credentials and account status (active, suspended, or disabled), record success/failure without logging credentials, then redirect by assigned role. Verify domain ownership before enabling it; an email suffix alone does not establish identity.

### 2. Endpoint Agent and Real Device Collection
- The current Windows agent performs a one-time, user-confirmed inventory submission with best-effort per-component detection and local diagnostic logging. A signed installer, managed deployment, agent updates, and continuous collection are future work.
- Endpoint diagnostics are now one-time, consent-gated checks. Continuous CPU, RAM, storage, and connectivity telemetry remains future work and requires a documented consent and retention policy.
- CPU temperature, SMART/storage health, startup duration, Windows event-log analysis, complete security posture, and Device Manager problem codes depend on hardware/Windows access and may be reported unavailable. Driver age metadata is only a review signal.

### 3. Real-Time Updates
- Use WebSockets or Server-Sent Events to push live status changes to the dashboard without refreshing the page.

### 4. Security Hardening and Deployment
- Protect against common web vulnerabilities (XSS, CSRF, SQL injection).
- Use HTTPS for all communications.
- Implement rate limiting and input sanitization.
- Secure API endpoints with authentication middleware.

### 5. Reporting & Analytics
- Generate exportable reports (PDF, CSV) on device health, inventory, and user activity.
- Add historical charts showing resource usage trends over time.

### 6. Notification & Alerting System
- Send email or SMS alerts when a device goes offline or a resource threshold is exceeded.
- Provide an in-app notification center for administrators.

### 7. Deployment & Scalability
- Containerize the application (e.g., Docker).
- Deploy behind a production web server (e.g., Nginx + Gunicorn).
- Add load balancing and horizontal scaling for larger organizations.

### 8. Audit Logging
- Continue expanding audit coverage to include any future administrative actions and operational events.

---

## Summary

This prototype successfully demonstrates the **user interface** and
**workflow** of a centralized device monitoring system. It is designed
to be presented as a college project to show how the system would look
and behave.

The UI follows a **dark minimal design language** using a cohesive
palette of deep purples and blues (`#0d0221`, `#0f084b`, `#26408b`),
providing an industry-standard look with clean typography, consistent
spacing, and responsive layouts.

Accounts, five-minute email verification records, encrypted TOTP state, device inventory and verification flags, QR enrollment records, confirmed Windows endpoint specifications, network snapshots, and consented one-time health/diagnostic reports are persisted in MySQL. Reports reuse existing diagnostic tables; no diagnostics schema migration is required. New account passwords use bcrypt and pre-existing Werkzeug hashes remain supported. Gmail credentials are private `.env` configuration and must be rotated if exposed. The application does not continuously monitor endpoints. Production use still requires HTTPS, code signing and managed agent delivery, broader supported diagnostics, recovery controls, and operational review.
