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

The application uses MySQL through Flask-SQLAlchemy. Public registration stores standard-user accounts with Werkzeug password hashes; account creation requires the password and confirmation to match and enforces 8-16 characters, at least one capital letter, and at least one special character. Flask-Login manages sessions. `init-db` ensures the reserved `admin` account is active, has the Administrator role, and uses the hashed bootstrap password `admin123`. The account is excluded from user management and protected from public registration. Administrator-only user management/log access and owner-scoped device operations are enforced by Flask views, not by JavaScript alone. Signed-in users can issue short-lived, single-use QR enrollment tokens for their own accounts.

| Feature | Current implementation |
|---|---|
| **User Registration and Login** | Account creation enforces the password length/complexity policy and confirmation match; user records and hashed passwords are persisted in MySQL, invalid credentials are rejected, and login attempts are recorded in activity logs. |
| **Role-Based Access** | Roles and permissions are stored in RBAC tables; `/admin`, user-management, and administrator log endpoints require an administrator. |
| **Device Registration** | Manual registration remains available. Users can also generate a 30-minute QR link that automatically downloads a token-bound Windows Python agent. Its one-use token is stored as a SHA-256 hash and associates the confirmed device submission with the issuing account. |
| **Windows Device Agent** | With the user's confirmation, the agent collects only CPU name/core count, RAM capacity/usage, storage devices/capacity/available space, GPU, motherboard brand, OS name/version, network adapter names, and IP addresses. It displays the inventory and asks before submission; it does not run persistently or collect telemetry. |
| **Device Specifications** | The confirmed inventory is validated, stored with the device and owner, and available on the Detected Device Specifications page and from the existing View action. Registration/update dates, status, and device event history are shown. |
| **Device Editing and Removal** | Active devices can be updated; archive/restore uses a lifecycle state, while administrator deletion is a retained soft delete. No application route physically removes devices. |
| **Diagnostic History** | Each scan action creates a new, explicitly placeholder diagnostic record; no actual diagnostic test runs. |
| **User Management** | Administrators can create accounts, update roles/status, and deactivate users without deleting their history. |
| **Device Details and Logs** | Owners/registrants see their device specifications; administrators can view and manage all active/archived devices and see complete device and audit history. Device search and status filtering, archive/restore, and retained soft deletion are available. Administrators can also search/filter activity and device event logs. These are application records, not operating-system or web-server logs. |
| **Dashboard** | Fleet counts and rows are queried from MySQL. |
| **Search, Sort and Pagination** | Browser-side presentation of records returned from the database-backed endpoints. |
| **Input and Session Security** | Server-side validation, CSRF token checks, HttpOnly/SameSite cookies, and configurable Secure cookies. |

---

## Remaining Work for Production Monitoring

To turn this prototype into a production-ready system, the following
areas would need to be designed and built with proper backend
technologies.

### 1. Account Hardening
- Add MFA, password reset, rate limiting, and operational account recovery.
- The reserved `admin` / `admin123` bootstrap credential is for local setup only; `init-db` restores this account and credential. Replace it before deployment.
- For multi-domain login, keep local username login separate from organization email login. Validate email syntax, normalize and check the domain against an administrator-managed allowed-domains table, verify credentials and account status (active, suspended, or disabled), record success/failure without logging credentials, then redirect by assigned role. Verify domain ownership before enabling it; an email suffix alone does not establish identity.

### 2. Endpoint Agent and Real Device Collection
- The current Windows agent performs a one-time, user-confirmed inventory submission. A signed installer, managed deployment, agent updates, and continuous collection are future work.
- Add real diagnostics and ongoing CPU, RAM, storage, and connectivity telemetry only with a documented consent and retention policy.

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

Accounts, device inventory, QR enrollment records, confirmed Windows endpoint specifications, network snapshots, and diagnostic placeholder history are persisted in MySQL. The application does not continuously monitor endpoints or execute real diagnostic tests. Production use still requires HTTPS, deployment hardening, managed/signed agent delivery, telemetry and diagnostic work, recovery controls, and operational review.
