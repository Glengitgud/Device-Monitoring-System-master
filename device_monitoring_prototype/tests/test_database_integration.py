import os
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import json
import smtplib
import struct
import time
import xml.etree.ElementTree as ET
from types import SimpleNamespace

from sqlalchemy import inspect
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

from device_monitoring_prototype.app import (
    _database_error_message,
    _database_uri,
    create_app,
)
from device_monitoring_prototype.app import app as default_app
from device_monitoring_prototype import device_agent
from device_monitoring_prototype.models import (
    ActivityLog,
    Device,
    DeviceRegistrationToken,
    DeviceMetric,
    DiagnosticRun,
    EmailVerification,
    Log,
    NetworkInterface,
    NetworkObservation,
    NetworkRecord,
    Permission,
    Role,
    RegistrationChallenge,
    User,
    db,
)
from device_monitoring_prototype.authentication import (
    EmailDeliveryError,
    _send_email,
    check_smtp_connection,
    decrypt_totp_secret,
    totp_counter,
    utcnow,
)
from device_monitoring_prototype.services import hash_password, verify_password


def _totp_code(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


class DatabaseIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "integration-test-secret",
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
                "MAIL_SERVER": None,
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            db.session.add_all(
                [
                    Role(name="Administrator"),
                    Role(name="User"),
                ]
            )
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def register_and_login(
        self,
        email="test@example.com",
        username="testuser",
        full_name="Test User",
        password="Passw0rd!",
        client=None,
    ):
        client = client or self.client
        client.get("/register")
        with client.session_transaction() as session:
            token = session["_csrf_token"]
        registration = {
            "csrf_token": token,
            "full_name": full_name,
            "email": email,
            "username": username,
            "password": password,
            "confirm_password": password,
        }
        with patch("device_monitoring_prototype.authentication._send_email") as send_email:
            response = client.post("/api/registration/start", data=registration)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        email_code = send_email.call_args.args[1]
        email_verified = client.post(
            "/api/registration/verify-email",
            data={"csrf_token": token, "code": email_code},
        )
        self.assertEqual(email_verified.status_code, 200)
        self.assertTrue(
            email_verified.json["qr_code"].startswith("data:image/svg+xml;base64,")
        )
        with self.app.app_context():
            with client.session_transaction() as session:
                pending_id = session["registration_challenge_id"]
            pending = db.session.get(RegistrationChallenge, pending_id)
            secret = decrypt_totp_secret(pending.totp_secret_encrypted)
            current_counter = int(time.time() // 30)
            registration_totp = _totp_code(secret, current_counter)
        completed = client.post(
            "/api/registration/verify-authenticator",
            data={"csrf_token": token, "code": registration_totp},
        )
        self.assertEqual(completed.status_code, 200, completed.get_data(as_text=True))
        with self.app.app_context():
            user = User.query.filter_by(username=username).one()
            self.assertTrue(verify_password(password, user.password_hash))
            self.assertTrue(user.password_hash.startswith("$2b$"))
            self.assertNotEqual(user.password_hash, password)
            self.assertTrue(user.email_verified)
            self.assertTrue(user.totp_enabled)
            secret = decrypt_totp_secret(user.totp_secret_encrypted)

        response = client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": username,
                "password": "incorrect-password",
            },
        )
        self.assertEqual(response.status_code, 401)
        response = client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": username,
                "password": password,
            },
        )
        self.assertEqual(response.status_code, 200)
        with client.session_transaction() as session:
            token = session["_csrf_token"]
        with self.app.app_context():
            user = User.query.filter_by(username=username).one()
            login_counter = user.totp_last_counter + 1
        with patch(
            "device_monitoring_prototype.authentication.totp_counter",
            side_effect=lambda secret, code: totp_counter(
                secret, code, now=login_counter * 30 + 1
            ),
        ):
            response = client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "totp_code": _totp_code(secret, login_counter),
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/device-verification")
        return token

    def complete_qr_enrollment(self, csrf, name="Verified test device"):
        qr = self.client.post(
            "/api/device-registration-tokens",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(qr.status_code, 200, qr.get_data(as_text=True))
        token = qr.json["enrollment_url"].rstrip("/").rsplit("/", 1)[-1]
        verified = self.client.post(
            f"/enroll/{token}/verify",
            data={"csrf_token": csrf},
        )
        self.assertEqual(verified.status_code, 302)
        download = self.client.post(
            f"/enroll/{token}/agent.py",
            data={"csrf_token": csrf, "trust_device_agent": "yes"},
        )
        self.assertEqual(download.status_code, 200)
        specifications = {
            "cpu_name": "Test CPU",
            "cpu_cores": 4,
            "ram_capacity_bytes": 8 * 1024**3,
            "ram_usage_bytes": 3 * 1024**3,
            "storage_devices": [
                {"name": "C:", "total_bytes": 256, "available_bytes": 128}
            ],
            "storage_total_bytes": 256,
            "storage_available_bytes": 128,
            "gpu_information": ["Test GPU"],
            "motherboard_brand": "Test Board",
            "operating_system_name": "Windows 11",
            "operating_system_version": "10.0.26100",
            "network_adapters": ["Ethernet"],
            "ip_addresses": ["192.0.2.20"],
        }
        agent = self.app.test_client().post(
            "/api/device-agent/enroll",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": name,
                "device_type": "Desktop",
                "specifications": specifications,
            },
        )
        self.assertEqual(agent.status_code, 201, agent.get_data(as_text=True))
        return agent.json["device_id"]

    def test_login_and_registration_pages_render(self):
        login_page = self.client.get("/")
        self.assertEqual(login_page.status_code, 200)
        self.assertIn(b'id="loginEmailValidation"', login_page.data)
        self.assertIn(b'id="loginPasswordStrength"', login_page.data)
        self.assertIn(b"js/password-strength.js", login_page.data)
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="registerForm"', response.data)
        self.assertIn(b'id="confirm_password"', response.data)
        self.assertIn(b'id="registerEmailValidation"', response.data)
        self.assertIn(b'id="registerPasswordStrength"', response.data)
        self.assertIn(b'id="registrationVerificationDialog"', response.data)
        self.assertIn(b'id="authenticatorQrCode"', response.data)
        self.assertIn(b"js/password-strength.js", response.data)
        self.assertIn(b"js/register.js", response.data)
        self.assertIn(b"js/register.js", login_page.data)

    def test_login_accepts_registered_email_and_rejects_unknown_email(self):
        csrf = self.register_and_login(
            full_name="Email Login User",
            email="EmailLogin@example.com",
            username="emaillogin",
            password="EmailPass1!",
        )
        self.client.post("/logout", data={"csrf_token": csrf})
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        email_login = self.client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "username": "EMAILLOGIN@example.com",
                "password": "EmailPass1!",
            },
        )
        self.assertEqual(email_login.status_code, 200)
        self.assertIn(b"Google Authenticator code", email_login.data)
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        with self.app.app_context():
            user = User.query.filter_by(username="emaillogin").one()
            secret = decrypt_totp_secret(user.totp_secret_encrypted)
            login_counter = user.totp_last_counter + 1
            invalid_codes = {
                _totp_code(secret, candidate)
                for candidate in (login_counter - 1, login_counter, login_counter + 1)
            }
        invalid_code = "000000" if "000000" not in invalid_codes else "000001"
        failed_mfa = self.client.post(
            "/login",
            data={"csrf_token": csrf, "totp_code": invalid_code},
        )
        self.assertEqual(failed_mfa.status_code, 401)
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        with patch(
            "device_monitoring_prototype.authentication.totp_counter",
            side_effect=lambda secret, code: totp_counter(
                secret, code, now=login_counter * 30 + 1
            ),
        ):
            email_login = self.client.post(
                "/login",
                data={
                    "csrf_token": csrf,
                    "totp_code": _totp_code(secret, login_counter),
                },
            )
        self.assertEqual(email_login.status_code, 302)
        self.assertEqual(email_login.location, "/device-verification")
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

        self.client.get("/device-verification")
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        self.client.post("/logout", data={"csrf_token": csrf})
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        unknown_email_login = self.client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "username": "unknown@example.com",
                "password": "EmailPass1!",
            },
        )
        self.assertEqual(unknown_email_login.status_code, 401)

    def test_registration_rejects_malformed_and_duplicate_emails_case_insensitively(self):
        csrf = self.register_and_login(
            full_name="Email Validation User",
            email="valid.address+tag@example.com",
            username="emailvalidation",
            password="EmailPass1!",
        )
        self.client.post("/logout", data={"csrf_token": csrf})
        self.client.get("/register")
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        valid_payload = {
            "csrf_token": csrf,
            "full_name": "Email Validation User",
            "email": "valid.address+tag@example.com",
            "username": "emailvalidation",
            "password": "EmailPass1!",
            "confirm_password": "EmailPass1!",
        }
        duplicate = self.client.post(
            "/api/registration/start",
            data={
                **valid_payload,
                "email": "VALID.ADDRESS+TAG@EXAMPLE.COM",
                "username": "differentuser",
            },
        )
        self.assertEqual(duplicate.status_code, 400)
        self.assertIn(b"already registered", duplicate.data)

        malformed_addresses = (
            "missing-at.example.com",
            "no-domain@example",
            "bad..dots@example.com",
            "bad domain@example.com",
        )
        for index, email in enumerate(malformed_addresses):
            with self.subTest(email=email):
                response = self.client.post(
                    "/api/registration/start",
                    data={
                        **valid_payload,
                        "email": email,
                        "username": f"invalidemail{index}",
                    },
                )
                self.assertEqual(response.status_code, 400)
                self.assertIn(b"valid email address", response.data.lower())

    def test_environment_file_is_loaded_from_application_directory(self):
        with patch("device_monitoring_prototype.app.load_dotenv") as load_dotenv:
            create_app(
                {
                    "TESTING": True,
                    "SQLALCHEMY_DATABASE_URI": "sqlite://",
                }
            )
        load_dotenv.assert_called_once_with(
            dotenv_path=Path(default_app.root_path, ".env")
        )

    def test_database_uri_defaults_to_xampp_mysql(self):
        with patch.dict(os.environ, {}, clear=True):
            url = make_url(_database_uri())
        self.assertEqual(url.drivername, "mysql+pymysql")
        self.assertEqual(url.host, "localhost")
        self.assertEqual(url.port, 3306)
        self.assertEqual(url.database, "devmonitor")
        self.assertEqual(url.username, "root")
        self.assertEqual(url.password, "")

    def test_database_uri_escapes_credentials_and_uses_configured_target(self):
        settings = {
            "DATABASE_URL": "",
            "MYSQL_USER": "monitor user",
            "MYSQL_PASSWORD": "p@ss:/word",
            "MYSQL_HOST": "127.0.0.1",
            "MYSQL_PORT": "3307",
            "MYSQL_DATABASE": "devmonitor",
        }
        with patch.dict(os.environ, settings, clear=True):
            url = make_url(_database_uri())
        self.assertEqual(url.username, "monitor user")
        self.assertEqual(url.password, "p@ss:/word")
        self.assertEqual(url.host, "127.0.0.1")
        self.assertEqual(url.port, 3307)
        self.assertEqual(url.database, "devmonitor")

    def test_database_errors_distinguish_schema_and_connection_problems(self):
        missing_table = OperationalError(
            "SELECT * FROM device_registration_tokens",
            {},
            Exception(1146, "Table does not exist"),
        )
        connection_down = OperationalError(
            "SELECT 1",
            {},
            Exception(2003, "Can't connect to MySQL server"),
        )
        bad_credentials = OperationalError(
            "SELECT 1",
            {},
            Exception(1045, "Access denied"),
        )

        self.assertIn("schema is incomplete", _database_error_message(missing_table))
        self.assertIn("running", _database_error_message(connection_down))
        self.assertIn("MYSQL_USER", _database_error_message(bad_credentials))

    def test_init_db_command_includes_device_logs(self):
        result = self.app.test_cli_runner().invoke(args=["init-db"])
        self.assertEqual(result.exit_code, 0, result.output)
        with self.app.app_context():
            self.assertIn("logs", inspect(db.engine).get_table_names())
            self.assertEqual(Role.query.count(), 2)

    def test_init_db_reports_existing_schema_drift_without_overwriting_tables(self):
        incomplete_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "integration-test-secret",
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
            }
        )
        with incomplete_app.app_context():
            with db.engine.begin() as connection:
                connection.exec_driver_sql(
                    "CREATE TABLE devices (id INTEGER PRIMARY KEY)"
                )

        result = incomplete_app.test_cli_runner().invoke(args=["init-db"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("devices.device_name", result.output)
        self.assertIn("apply the required migrations", result.output)
        with incomplete_app.app_context():
            self.assertEqual(
                {column["name"] for column in inspect(db.engine).get_columns("devices")},
                {"id"},
            )

    def test_check_db_command_validates_declared_schema_and_row_counts(self):
        result = self.app.test_cli_runner().invoke(args=["check-db"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("18 tables", result.output)
        self.assertIn(
            "primary/unique keys, foreign keys, and check constraints",
            result.output,
        )
        self.assertIn("users=0", result.output)
        self.assertIn("devices=0", result.output)
        self.assertIn("archived devices=0", result.output)
        self.assertIn("device specifications=0", result.output)
        self.assertIn("device registration tokens=0", result.output)

    def test_init_db_creates_default_admin_once_and_admin_can_log_in(self):
        runner = self.app.test_cli_runner()
        first_result = runner.invoke(args=["init-db"])
        self.assertEqual(first_result.exit_code, 0, first_result.output)
        second_result = runner.invoke(args=["init-db"])
        self.assertEqual(second_result.exit_code, 0, second_result.output)
        self.assertIn("credentials were preserved", second_result.output)

        with self.app.app_context():
            administrator = User.query.filter_by(username="admin").one()
            self.assertTrue(administrator.is_admin)
            self.assertTrue(administrator.is_active)
            self.assertTrue(verify_password("admin123", administrator.password_hash))
            self.assertEqual(User.query.filter_by(username="admin").count(), 1)

        response = self.client.post(
            "/api/registration/start",
            data={
                "full_name": "Duplicate Administrator",
                "email": "duplicate-admin@example.com",
                "username": "Admin",
                "password": "Passw0rd!",
                "confirm_password": "Passw0rd!",
            },
        )
        self.assertEqual(response.status_code, 400)
        with self.app.app_context():
            user_role = Role.query.filter_by(name="User").one()
            custom_permission = Permission(
                code="custom.preserved",
                description="Existing application permission",
            )
            user_role.permissions.append(custom_permission)
            db.session.add(custom_permission)
            administrator = User.query.filter_by(username="admin").one()
            administrator.status = "inactive"
            administrator.password_hash = generate_password_hash("old-admin-password")
            administrator.roles.clear()
            db.session.commit()
        repair_result = runner.invoke(args=["init-db"])
        self.assertEqual(repair_result.exit_code, 0, repair_result.output)
        with self.app.app_context():
            administrator = User.query.filter_by(username="admin").one()
            self.assertTrue(administrator.is_admin)
            self.assertEqual(administrator.status, "inactive")
            self.assertTrue(
                check_password_hash(administrator.password_hash, "old-admin-password")
            )
            self.assertIn(
                "Administrator",
                {role.name for role in administrator.roles},
            )
            user_role = Role.query.filter_by(name="User").one()
            self.assertIn(
                "custom.preserved",
                {permission.code for permission in user_role.permissions},
            )

        self.client.get("/login")
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]
        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "admin",
                "password": "old-admin-password",
            },
        )
        self.assertEqual(response.status_code, 302)
        admin_page = self.client.get("/admin")
        self.assertEqual(admin_page.status_code, 200)
        self.assertIn(b'id="usersPanel" class="accordion-collapse collapse"', admin_page.data)
        self.assertIn(b'id="activityLogsPanel" class="accordion-collapse collapse"', admin_page.data)
        self.assertIn(b'id="deviceLogsPanel" class="accordion-collapse collapse"', admin_page.data)
        self.assertIn(b'id="usersShowMoreBtn"', admin_page.data)
        self.assertIn(b'id="activityLogsShowMoreBtn"', admin_page.data)
        self.assertIn(b'id="deviceLogsShowMoreBtn"', admin_page.data)
        self.assertNotIn(
            "admin",
            {user["username"] for user in self.client.get("/api/users").json},
        )
        with self.app.app_context():
            admin_id = User.query.filter_by(username="admin").one().id
        self.client.get("/dashboard")
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]
        protected_admin = self.client.patch(
            f"/api/users/{admin_id}",
            headers={"X-CSRF-Token": token},
            json={"status": "inactive", "role": "User"},
        )
        self.assertEqual(protected_admin.status_code, 400)

    def test_all_standard_user_pages_and_apis_render(self):
        csrf = self.register_and_login()
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        self.assertEqual(self.client.get("/api/dashboard").status_code, 403)
        for path in ("/devices", "/archived-devices"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 302)
        self.assertEqual(self.client.get("/api/devices").status_code, 403)
        self.assertEqual(
            self.client.get("/api/device-verification-status").status_code, 200
        )
        verification_page = self.client.get("/device-verification")
        self.assertIn(b"deviceVerificationPending", verification_page.data)
        self.assertIn(b"createDeviceQrBtn", verification_page.data)
        self.complete_qr_enrollment(csrf)
        devices_page = self.client.get("/devices")
        self.assertEqual(devices_page.status_code, 200)
        self.assertIn(b'id="generateDeviceQrBtn"', devices_page.data)
        self.assertIn(b'id="deviceStatusFilter"', devices_page.data)
        self.assertEqual(self.client.get("/archived-devices").status_code, 200)
        static_response = self.client.get("/static/css/style.css")
        self.assertEqual(static_response.status_code, 200)
        static_response.close()

    def test_qr_device_registration_verifies_user_and_unlocks_dashboard(self):
        csrf = self.register_and_login()
        denied_page = self.client.get("/dashboard")
        self.assertEqual(denied_page.status_code, 302)
        self.assertEqual(denied_page.location, "/device-verification")
        denied_api = self.client.get("/api/dashboard")
        self.assertEqual(denied_api.status_code, 403)
        self.assertIn("verify and register a device", denied_api.json["error"].lower())

        qr_response = self.client.post(
            "/api/device-registration-tokens",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(qr_response.status_code, 200)
        token = qr_response.json["enrollment_url"].rstrip("/").rsplit("/", 1)[-1]
        verification_page = self.client.get(f"/enroll/{token}")
        self.assertEqual(verification_page.status_code, 200)
        self.assertIn(b"Verify Account", verification_page.data)
        unverified_download = self.client.post(
            f"/enroll/{token}/agent.py",
            data={"csrf_token": csrf, "trust_device_agent": "yes"},
        )
        self.assertEqual(unverified_download.status_code, 403)
        verified_page = self.client.post(
            f"/enroll/{token}/verify",
            data={"csrf_token": csrf},
        )
        self.assertEqual(verified_page.status_code, 302)
        confirmed_download = self.client.post(
            f"/enroll/{token}/agent.py",
            data={"csrf_token": csrf, "trust_device_agent": "yes"},
        )
        self.assertEqual(confirmed_download.status_code, 200)
        self.assertIn(token.encode(), confirmed_download.data)
        specifications = {
            "cpu_name": "Verification CPU",
            "cpu_cores": 4,
            "ram_capacity_bytes": 8 * 1024**3,
            "ram_usage_bytes": 3 * 1024**3,
            "storage_devices": [
                {
                    "name": "C:",
                    "total_bytes": 256 * 1024**3,
                    "available_bytes": 128 * 1024**3,
                }
            ],
            "storage_total_bytes": 256 * 1024**3,
            "storage_available_bytes": 128 * 1024**3,
            "gpu_information": ["Verification GPU"],
            "motherboard_brand": "Verification Board",
            "operating_system_name": "Windows 11",
            "operating_system_version": "10.0.26100",
            "network_adapters": ["Ethernet"],
            "ip_addresses": ["192.0.2.45"],
        }
        enrolled = self.client.post(
            "/api/device-agent/enroll",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "Verified workstation",
                "device_type": "Desktop",
                "specifications": specifications,
            },
        )
        self.assertEqual(enrolled.status_code, 201)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/api/dashboard").status_code, 200)
        self.assertEqual(
            self.client.get("/api/device-verification-status").json,
            {"verified": True, "verified_devices": 1},
        )
        with self.app.app_context():
            device = db.session.get(Device, enrolled.json["device_id"])
            self.assertTrue(device.is_verified)
            self.assertEqual(device.owner_user_id, enrolled.json["owner_user_id"])
            self.assertEqual(device.hardware_spec.cpu_model, "Verification CPU")

        self.assertEqual(
            self.app.test_cli_runner().invoke(args=["init-db"]).exit_code,
            0,
        )
        admin_client = self.app.test_client()
        admin_client.get("/login")
        with admin_client.session_transaction() as session:
            admin_csrf = session["_csrf_token"]
        admin_login = admin_client.post(
            "/login",
            data={
                "csrf_token": admin_csrf,
                "username": "admin",
                "password": "admin123",
            },
        )
        self.assertEqual(admin_login.location, "/dashboard")
        self.assertEqual(admin_client.get("/dashboard").status_code, 200)
        self.assertEqual(admin_client.get("/api/dashboard").status_code, 200)
        self.assertEqual(admin_client.get("/device-verification").status_code, 404)
        admin_devices = admin_client.get("/devices")
        self.assertNotIn(b"Generate QR Code", admin_devices.data)
        self.assertNotIn(b"navDeviceVerification", admin_devices.data)

    def test_auth_forms_report_database_setup_errors_without_500(self):
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "database-error-test-secret",
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
            }
        )
        client = app.test_client()
        try:
            client.get("/login")
            with client.session_transaction() as session:
                token = session["_csrf_token"]
            login_response = client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "username": "missing",
                    "password": "unused",
                },
            )
            self.assertEqual(login_response.status_code, 503)
            self.assertIn(b"schema is incomplete", login_response.data.lower())
            self.assertIn(b"does not update existing tables", login_response.data)
            self.assertIn(b"Copy-Item", login_response.data)
            self.assertIn(b"device_monitoring_prototype.app init-db", login_response.data)

            with app.app_context():
                db.create_all()
            register_response = client.post(
                "/register",
                data={
                    "csrf_token": token,
                    "full_name": "Test User",
                    "email": "setup@example.com",
                    "username": "setupuser",
                    "password": "Passw0rd!",
                    "confirm_password": "Passw0rd!",
                },
            )
            self.assertEqual(register_response.status_code, 503)
            self.assertIn(b"init-db", register_response.data)
        finally:
            with app.app_context():
                db.session.remove()
                db.drop_all()

    def test_registration_login_and_password_hash(self):
        self.register_and_login()
        dashboard_response = self.client.get("/dashboard")
        self.assertEqual(dashboard_response.status_code, 302)
        self.assertEqual(dashboard_response.location, "/device-verification")

    def test_registration_enforces_password_policy_and_confirmation(self):
        self.client.get("/register")
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]

        invalid_passwords = (
            ("short", "Abcdef!", "Abcdef!"),
            ("long", "Abcdefghijklmnop!", "Abcdefghijklmnop!"),
            ("no-capital", "abcdefg!", "abcdefg!"),
            ("non-ascii-capital", "Äbcdefg!", "Äbcdefg!"),
            ("no-special", "Abcdefg1", "Abcdefg1"),
            ("mismatch", "Abcdefg!", "Abcdefg?"),
        )
        for username, password, confirmation in invalid_passwords:
            with self.subTest(username=username):
                response = self.client.post(
                    "/api/registration/start",
                    data={
                        "csrf_token": token,
                        "full_name": "Password Test",
                        "email": f"{username}@example.com",
                        "username": username,
                        "password": password,
                        "confirm_password": confirmation,
                    },
                )
                self.assertEqual(response.status_code, 400)
                with self.app.app_context():
                    self.assertIsNone(
                        User.query.filter_by(username=username).one_or_none()
                    )

        for username, password in (
            ("eightchar", "Abcdefg!"),
            ("sixteenchar", "Abcdefghijklmno!"),
        ):
            with self.subTest(username=username):
                with patch("device_monitoring_prototype.authentication._send_email"):
                    response = self.client.post(
                        "/api/registration/start",
                        data={
                            "csrf_token": token,
                            "full_name": "Password Test",
                            "email": f"{username}@example.com",
                            "username": username,
                            "password": password,
                            "confirm_password": password,
                        },
                    )
                self.assertEqual(response.status_code, 200)
                with self.app.app_context():
                    self.assertIsNone(
                        User.query.filter_by(username=username).one_or_none()
                    )

    def test_registration_creates_account_and_displays_verification_qr(self):
        self.client.get("/register")
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]

        registration = {
            "csrf_token": token,
            "full_name": "Registered User",
            "email": "registered@example.com",
            "username": "registered",
            "password": "Passw0rd!",
            "confirm_password": "Passw0rd!",
        }
        with patch("device_monitoring_prototype.authentication._send_email") as send_email:
            response = self.client.post("/api/registration/start", data=registration)
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            self.assertIsNone(User.query.filter_by(username="registered").one_or_none())
        email_verified = self.client.post(
            "/api/registration/verify-email",
            data={"csrf_token": token, "code": send_email.call_args.args[1]},
        )
        self.assertEqual(email_verified.status_code, 200)
        self.assertTrue(
            email_verified.json["qr_code"].startswith("data:image/svg+xml;base64,")
        )
        qr_svg = base64.b64decode(email_verified.json["qr_code"].split(",", 1)[1])
        qr_root = ET.fromstring(qr_svg)
        svg_namespace = "{http://www.w3.org/2000/svg}"
        self.assertEqual(
            next(qr_root.iter(f"{svg_namespace}rect")).get("fill"), "#ffffff"
        )
        self.assertEqual(
            next(qr_root.iter(f"{svg_namespace}path")).get("fill"), "#111827"
        )
        with self.app.app_context():
            self.assertIsNone(User.query.filter_by(username="registered").one_or_none())
            with self.client.session_transaction() as session:
                challenge = db.session.get(
                    RegistrationChallenge, session["registration_challenge_id"]
                )
                secret = decrypt_totp_secret(challenge.totp_secret_encrypted)
                counter = int(time.time() // 30)
        self.assertNotIn(secret.encode("ascii"), email_verified.data)
        valid_codes = {
                _totp_code(secret, candidate)
                for candidate in (counter - 1, counter, counter + 1)
        }
        invalid_code = "000000" if "000000" not in valid_codes else "000001"
        invalid_totp = self.client.post(
                "/api/registration/verify-authenticator",
                data={"csrf_token": token, "code": invalid_code},
        )
        self.assertEqual(invalid_totp.status_code, 400)
        valid_code = _totp_code(secret, counter)
        response = self.client.post(
            "/api/registration/verify-authenticator",
            data={"csrf_token": token, "code": valid_code},
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.json["redirect_url"].endswith("/device-verification"))
        with self.app.app_context():
            user = User.query.filter_by(username="registered").one()
            self.assertTrue(user.email_verified)
            self.assertIsNotNone(user.email_verified_at)
            self.assertTrue(user.totp_enabled)
            self.assertIsNotNone(user.totp_verified_at)
            self.assertNotEqual(user.totp_secret_encrypted, secret)
            self.assertNotEqual(user.password_hash, "Passw0rd!")

    def test_missing_email_transport_blocks_registration_without_creating_user(self):
            self.client.get("/register")
            with self.client.session_transaction() as session:
                csrf = session["_csrf_token"]
            response = self.client.post(
                "/api/registration/start",
                data={
                    "csrf_token": csrf,
                    "full_name": "No Mail User",
                    "email": "nomail@example.com",
                    "username": "nomailuser",
                    "password": "NoMailPass1!",
                    "confirm_password": "NoMailPass1!",
                },
            )
            self.assertEqual(response.status_code, 503)
            self.assertIn("email verification is not configured", response.json["error"].lower())
            with self.app.app_context():
                self.assertIsNone(User.query.filter_by(username="nomailuser").one_or_none())
                with self.client.session_transaction() as session:
                    challenge = db.session.get(
                        RegistrationChallenge, session["registration_challenge_id"]
                    )
                    self.assertIsNotNone(challenge.password_hash)
                    self.assertNotEqual(challenge.password_hash, "NoMailPass1!")

    def test_initial_email_failure_expires_unsent_code_and_allows_immediate_resend(self):
        self.client.get("/register")
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        with patch(
            "device_monitoring_prototype.authentication._send_email",
            side_effect=EmailDeliveryError("Email service unavailable."),
        ):
            failed = self.client.post(
                "/api/registration/start",
                data={
                    "csrf_token": csrf,
                    "full_name": "Retry Mail User",
                    "email": "retry-mail@example.com",
                    "username": "retry_mail_user",
                    "password": "RetryMail1!",
                    "confirm_password": "RetryMail1!",
                },
            )
        self.assertEqual(failed.status_code, 503)
        with self.client.session_transaction() as session:
            challenge_id = session["registration_challenge_id"]
        with self.app.app_context():
            challenge = db.session.get(RegistrationChallenge, challenge_id)
            verification = EmailVerification.query.filter_by(
                registration_challenge_id=challenge_id
            ).one()
            self.assertLessEqual(verification.expires_at, utcnow())
            self.assertEqual(challenge.email_send_count, 0)
            self.assertIsNone(User.query.filter_by(username="retry_mail_user").one_or_none())

        with patch("device_monitoring_prototype.authentication._send_email") as send_email:
            resent = self.client.post(
                "/api/registration/resend-code", data={"csrf_token": csrf}
            )
        self.assertEqual(resent.status_code, 200, resent.get_data(as_text=True))
        self.assertEqual(send_email.call_args.args[0], "retry-mail@example.com")
        delivered_code = send_email.call_args.args[1]
        with self.app.app_context():
            challenge = db.session.get(RegistrationChallenge, challenge_id)
            challenge.last_email_sent_at = utcnow() - timedelta(seconds=61)
            db.session.commit()
            verifications = EmailVerification.query.filter_by(
                registration_challenge_id=challenge_id
            ).order_by(EmailVerification.id).all()
            self.assertEqual(challenge.email_send_count, 1)
            self.assertGreater(verifications[-1].expires_at, utcnow())
        with patch(
            "device_monitoring_prototype.authentication._send_email",
            side_effect=EmailDeliveryError("Email service unavailable."),
        ):
            failed_resend = self.client.post(
                "/api/registration/resend-code", data={"csrf_token": csrf}
            )
        self.assertEqual(failed_resend.status_code, 503)
        with self.app.app_context():
            challenge = db.session.get(RegistrationChallenge, challenge_id)
            self.assertEqual(challenge.email_send_count, 2)
        verified = self.client.post(
            "/api/registration/verify-email",
            data={"csrf_token": csrf, "code": delivered_code},
        )
        self.assertEqual(verified.status_code, 200, verified.get_data(as_text=True))

    def test_email_verification_is_bound_to_registration_email(self):
        self.client.get("/register")
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        with patch("device_monitoring_prototype.authentication._send_email") as send_email:
            started = self.client.post(
                "/api/registration/start",
                data={
                    "csrf_token": csrf,
                    "full_name": "Email Binding Test",
                    "email": "email-binding@example.com",
                    "username": "email_binding",
                    "password": "EmailBinding1!",
                    "confirm_password": "EmailBinding1!",
                },
            )
        self.assertEqual(started.status_code, 200)
        code = send_email.call_args.args[1]
        with self.app.app_context():
            with self.client.session_transaction() as session:
                challenge_id = session["registration_challenge_id"]
                challenge = db.session.get(
                    RegistrationChallenge, session["registration_challenge_id"]
                )
            verification = EmailVerification.query.filter_by(
                registration_challenge_id=challenge_id
            ).one()
            verification.email = "different@example.com"
            db.session.commit()
        response = self.client.post(
            "/api/registration/verify-email",
            data={"csrf_token": csrf, "code": code},
        )
        self.assertEqual(response.status_code, 400)
        with self.app.app_context():
            challenge = db.session.get(RegistrationChallenge, challenge_id)
            self.assertIsNone(challenge.email_verified_at)
            self.assertIsNone(User.query.filter_by(username="email_binding").one_or_none())

    def test_registration_code_expiry_invalid_code_and_resend_limits(self):
        self.client.get("/register")
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        with patch("device_monitoring_prototype.authentication._send_email") as send_email:
            started = self.client.post(
                "/api/registration/start",
                data={
                    "csrf_token": csrf,
                    "full_name": "Expiry Test",
                    "email": "expiry@example.com",
                    "username": "expiryuser",
                    "password": "ExpiryPass1!",
                    "confirm_password": "ExpiryPass1!",
                },
            )
        self.assertEqual(started.status_code, 200)
        first_code = send_email.call_args.args[1]
        empty = self.client.post(
            "/api/registration/verify-email",
            data={"csrf_token": csrf, "code": ""},
        )
        self.assertEqual(empty.status_code, 400)
        wrong_code = "000000" if first_code != "000000" else "000001"
        invalid = self.client.post(
            "/api/registration/verify-email",
            data={"csrf_token": csrf, "code": wrong_code},
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertIn("incorrect", invalid.json["error"].lower())
        too_soon = self.client.post(
            "/api/registration/resend-code", data={"csrf_token": csrf}
        )
        self.assertEqual(too_soon.status_code, 400)
        self.assertIn("wait", too_soon.json["error"].lower())

        with self.app.app_context():
            with self.client.session_transaction() as session:
                challenge = db.session.get(
                    RegistrationChallenge, session["registration_challenge_id"]
                )
                verification = EmailVerification.query.filter_by(
                    registration_challenge_id=challenge.id
                ).one()
                verification.expires_at = utcnow() - timedelta(seconds=1)
                challenge.last_email_sent_at = utcnow() - timedelta(seconds=61)
                db.session.commit()
        expired = self.client.post(
            "/api/registration/verify-email",
            data={"csrf_token": csrf, "code": first_code},
        )
        self.assertEqual(expired.status_code, 400)
        self.assertIn("expired", expired.json["error"].lower())

        with patch("device_monitoring_prototype.authentication._send_email") as send_email:
            resent = self.client.post(
                "/api/registration/resend-code", data={"csrf_token": csrf}
            )
        self.assertEqual(resent.status_code, 200)
        self.assertIn("sent", resent.json["message"].lower())
        second_code = send_email.call_args.args[1]
        self.assertNotEqual(first_code, second_code)
        with self.app.app_context():
            with self.client.session_transaction() as session:
                challenge = db.session.get(
                    RegistrationChallenge, session["registration_challenge_id"]
                )
                verifications = (
                    EmailVerification.query.filter_by(
                        registration_challenge_id=challenge.id
                    )
                    .order_by(EmailVerification.id)
                    .all()
                )
                self.assertEqual(len(verifications), 2)
                self.assertEqual(len(verifications[0].verification_code), 64)
                self.assertNotEqual(verifications[0].verification_code, first_code)
                self.assertLessEqual(
                    verifications[1].expires_at - verifications[1].created_at,
                    timedelta(minutes=5),
                )
        verified = self.client.post(
            "/api/registration/verify-email",
            data={"csrf_token": csrf, "code": second_code},
        )
        self.assertEqual(verified.status_code, 200)
        reused = self.client.post(
            "/api/registration/verify-email",
            data={"csrf_token": csrf, "code": second_code},
        )
        self.assertEqual(reused.status_code, 400)
        with self.app.app_context():
            verification = EmailVerification.query.filter_by(verified=True).one()
            self.assertIsNotNone(verification.used_at)

        with self.app.app_context():
            with self.client.session_transaction() as session:
                challenge = db.session.get(
                    RegistrationChallenge, session["registration_challenge_id"]
                )
                challenge.expires_at = utcnow() - timedelta(seconds=1)
                db.session.commit()
        expired_registration = self.client.post(
            "/api/registration/verify-authenticator",
            data={"csrf_token": csrf, "code": "123456"},
        )
        self.assertEqual(expired_registration.status_code, 400)
        self.assertIn("registration has expired", expired_registration.json["error"].lower())
        with self.app.app_context():
            self.assertIsNone(User.query.filter_by(username="expiryuser").one_or_none())

    def test_totp_uses_rfc6238_sha1_six_digit_code(self):
        secret = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")
        self.assertEqual(totp_counter(secret, "287082", now=59), 1)

    def test_email_sender_uses_tls_and_delivers_the_verification_code(self):
        with self.app.app_context():
            self.app.config.update(
                MAIL_SERVER="smtp.example.test",
                MAIL_PORT=587,
                MAIL_USERNAME="mailer@example.test",
                MAIL_PASSWORD="mail-secret",
                MAIL_DEFAULT_SENDER="mailer@example.test",
                MAIL_USE_TLS=True,
            )
            with patch("device_monitoring_prototype.authentication.smtplib.SMTP") as smtp_factory:
                smtp = smtp_factory.return_value
                _send_email("recipient@example.test", "123456")
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("mailer@example.test", "mail-secret")
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(message["To"], "recipient@example.test")
        self.assertEqual(message["From"], "DevMonitor <mailer@example.test>")
        plain_body = message.get_body(preferencelist=("plain",)).get_content()
        self.assertIn("123456", plain_body)
        self.assertIn("5 minutes", plain_body)
        self.assertIn("DevMonitor", message.get_body(preferencelist=("html",)).get_content())
        self.assertIn("123456", message.get_body(preferencelist=("html",)).get_content())
        smtp.close.assert_called_once()

    def test_gmail_sender_must_match_authenticated_account(self):
        with self.app.app_context():
            self.app.config.update(
                MAIL_SERVER="smtp.gmail.com",
                MAIL_PORT=587,
                MAIL_USERNAME="mailer@example.test",
                MAIL_PASSWORD="mail-secret",
                MAIL_DEFAULT_SENDER="different@example.test",
                MAIL_USE_TLS=True,
            )
            with self.assertRaises(EmailDeliveryError):
                _send_email("recipient@example.test", "123456")

    def test_smtp_connectivity_check_authenticates_without_sending_email(self):
        with self.app.app_context():
            self.app.config.update(
                MAIL_SERVER="smtp.gmail.com",
                MAIL_PORT=587,
                MAIL_USERNAME="mailer@example.test",
                MAIL_PASSWORD="mail-secret",
                MAIL_USE_TLS=True,
            )
            with patch("device_monitoring_prototype.authentication.smtplib.SMTP") as smtp_factory:
                smtp = smtp_factory.return_value
                smtp.noop.return_value = (250, b"OK")
                check_smtp_connection()
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("mailer@example.test", "mail-secret")
        smtp.send_message.assert_not_called()
        smtp.noop.assert_called_once()
        smtp.close.assert_called_once()

    def test_smtp_authentication_and_recipient_failures_are_reported_safely(self):
        with self.app.app_context():
            self.app.config.update(
                MAIL_SERVER="smtp.gmail.com",
                MAIL_PORT=587,
                MAIL_USERNAME="mailer@example.test",
                MAIL_PASSWORD="mail-secret",
                MAIL_DEFAULT_SENDER="mailer@example.test",
                MAIL_USE_TLS=True,
            )
            with patch("device_monitoring_prototype.authentication.smtplib.SMTP") as smtp_factory:
                smtp = smtp_factory.return_value
                smtp.login.side_effect = smtplib.SMTPAuthenticationError(
                    535, b"authentication rejected"
                )
                with self.assertLogs(self.app.logger, level="ERROR") as log_output:
                    with self.assertRaises(EmailDeliveryError):
                        _send_email("recipient@example.test", "123456")
                self.assertIn("SMTP authentication failed", log_output.output[0])
                self.assertNotIn("mail-secret", log_output.output[0])

            with patch("device_monitoring_prototype.authentication.smtplib.SMTP") as smtp_factory:
                smtp = smtp_factory.return_value
                smtp.send_message.return_value = {
                    "recipient@example.test": (550, b"recipient rejected")
                }
                with self.assertRaises(EmailDeliveryError):
                    _send_email("recipient@example.test", "123456")
                smtp.close.assert_called_once()

    def test_bcrypt_password_hashes_and_legacy_hashes_are_verified(self):
        bcrypt_hash = hash_password("Passw0rd!")
        legacy_hash = generate_password_hash("OldPassw0rd!")
        self.assertTrue(bcrypt_hash.startswith("$2b$"))
        self.assertTrue(verify_password("Passw0rd!", bcrypt_hash))
        self.assertFalse(verify_password("wrong", bcrypt_hash))
        self.assertTrue(verify_password("OldPassw0rd!", legacy_hash))

    def test_new_user_email_verified_database_default_is_false(self):
        with self.app.app_context():
            user = User(
                username="unverified",
                email="unverified@example.com",
                password_hash=hash_password("Passw0rd!"),
            )
            db.session.add(user)
            db.session.commit()
            self.assertFalse(user.email_verified)
            self.assertFalse(user.is_active)

    def test_failed_login_is_recorded_without_storing_password(self):
        token = self.register_and_login()
        logout = self.client.post(
            "/logout",
            data={"csrf_token": token},
        )
        self.assertEqual(logout.status_code, 302)
        self.client.get("/login")
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]
        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "testuser",
                "password": "incorrect-password",
            },
        )
        self.assertEqual(response.status_code, 401)
        with self.app.app_context():
            entry = ActivityLog.query.filter_by(
                event_type="auth.login_failed"
            ).order_by(ActivityLog.id.desc()).first()
            self.assertIsNotNone(entry)
            self.assertEqual(entry.details, {"username": "testuser"})
            self.assertNotIn("incorrect-password", str(entry.details))

    def test_device_registration_and_history_are_persisted(self):
        token = self.register_and_login()
        self.complete_qr_enrollment(token)
        hardware = {
            "cpu_model": "Test CPU",
            "cpu_cores": 4,
            "cpu_threads": 8,
            "memory_bytes": 16 * 1024**3,
            "storage_bytes": 512 * 1024**3,
            "gpu_model": None,
            "motherboard_model": None,
            "operating_system_version": "Test OS",
        }
        network = {
            "ip_address": "192.0.2.10",
            "subnet_mask": "255.255.255.0",
            "default_gateway": "192.0.2.1",
            "dns_server": "192.0.2.53",
            "connectivity_status": "connected",
        }
        with patch(
            "device_monitoring_prototype.services.collect_hardware",
            return_value=hardware,
        ), patch(
            "device_monitoring_prototype.services.collect_network",
            return_value=network,
        ):
            response = self.client.post(
                "/api/devices",
                headers={"X-CSRF-Token": token},
                json={
                    "name": "Test Laptop",
                    "hostname": "test-laptop",
                    "type": "Laptop",
                    "os": "Test OS",
                    "status": "online",
                },
            )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        device_id = response.json["id"]
        with self.app.app_context():
            device = db.session.get(Device, device_id)
            self.assertEqual(device.owner.username, "testuser")
            self.assertEqual(device.hardware_spec.cpu_model, "Test CPU")
            self.assertEqual(len(device.network_records), 1)
            self.assertEqual(len(device.logs), 1)
            self.assertEqual(device.logs[0].event, "Device registered")
            interface = NetworkInterface(
                device=device,
                interface_name="Ethernet",
                mac_address="00:11:22:33:44:55",
                interface_type="wired",
                is_primary=True,
            )
            interface.observations.append(
                NetworkObservation(
                    ip_address="192.0.2.11",
                    subnet_prefix=24,
                    gateway="192.0.2.1",
                    dns_servers=["192.0.2.53"],
                    connection_type="wired",
                )
            )
            db.session.add_all(
                [
                    interface,
                    DeviceMetric(
                        device=device,
                        cpu_percent=22.5,
                        memory_percent=40,
                        storage_percent=55,
                        memory_used_bytes=8 * 1024**3,
                        storage_used_bytes=200 * 1024**3,
                        network_rx_bytes=1024,
                        network_tx_bytes=2048,
                    ),
                ]
            )
            db.session.commit()

        response = self.client.post(
            f"/api/devices/{device_id}/diagnostics",
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(response.status_code, 201)
        history = self.client.get(f"/api/devices/{device_id}/history")
        self.assertEqual(len(history.json["diagnostics"]), 1)
        self.assertEqual(len(history.json["network"]), 1)
        self.assertEqual(len(history.json["logs"]), 2)
        details = self.client.get(f"/api/devices/{device_id}")
        self.assertEqual(details.status_code, 200, details.get_data(as_text=True))
        self.assertEqual(details.json["view_mode"], "user")
        self.assertEqual(details.json["device_name"], "Test Laptop")
        self.assertEqual(details.json["ip_address"], "192.0.2.10")
        self.assertEqual(
            set(details.json),
            {
                "view_mode",
                "device_name",
                "device_type",
                "operating_system",
                "status",
                "ip_address",
                "specification",
                "registered_at",
            },
        )
        self.assertEqual(details.json["specification"]["cpu_model"], "Test CPU")
        self.assertEqual(details.json["specification"]["cpu_cores"], 4)
        with self.app.app_context():
            device = db.session.get(Device, device_id)
            self.assertEqual(DiagnosticRun.query.count(), 1)
            self.assertEqual(NetworkRecord.query.count(), 2)
            self.assertEqual(Log.query.count(), 3)
            self.assertEqual(len(device.network_interfaces), 1)
            self.assertEqual(len(device.metric_samples), 1)
            self.assertEqual(len(device.diagnostic_runs), 1)

    def test_sample_data_command_creates_linked_records(self):
        result = self.app.test_cli_runner().invoke(
            args=["seed-sample-data"],
            input="Sample1!\nSample1!\n",
        )
        self.assertEqual(result.exit_code, 0, result.output)
        with self.app.app_context():
            user = User.query.filter_by(username="sample_user").one()
            device = Device.query.filter_by(device_name="Sample Laptop").one()
            self.assertEqual(device.owner.id, user.id)
            self.assertEqual(len(device.network_records), 1)
            self.assertEqual(len(device.logs), 1)
            self.assertNotEqual(
                user.password_hash,
                "Sample1!",
            )

    def test_device_archive_search_restore_and_soft_delete_retains_row(self):
        token = self.register_and_login()
        self.complete_qr_enrollment(token)
        with patch(
            "device_monitoring_prototype.services.collect_hardware",
            return_value={"cpu_model": "Archive Test CPU"},
        ), patch(
            "device_monitoring_prototype.services.collect_network",
            return_value={"ip_address": "192.0.2.31"},
        ):
            created = self.client.post(
                "/api/devices",
                headers={"X-CSRF-Token": token},
                json={
                    "name": "Archive Search Device",
                    "type": "Laptop",
                    "os": "Test OS",
                    "status": "online",
                },
            )
        self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
        device_id = created.json["id"]
        archived_page = self.client.get("/archived-devices")
        self.assertEqual(archived_page.status_code, 200)
        archived = self.client.post(
            f"/api/devices/{device_id}/archive",
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(archived.status_code, 204)
        self.assertNotIn(
            device_id,
            {item["id"] for item in self.client.get("/api/devices").json},
        )
        self.assertIn(
            device_id,
            {item["id"] for item in self.client.get("/api/archived-devices").json},
        )
        with self.app.app_context():
            archived_row = db.session.get(Device, device_id)
            self.assertEqual(archived_row.lifecycle_status, "archived")
            self.assertIsNotNone(archived_row.archived_at)
            self.assertIsNotNone(archived_row.archived_by_user_id)
        archived_details = self.client.get(f"/api/devices/{device_id}")
        self.assertEqual(archived_details.status_code, 200)
        self.assertEqual(archived_details.json["view_mode"], "user")
        denied_delete = self.client.delete(
            f"/api/devices/{device_id}",
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(denied_delete.status_code, 403)
        restored = self.client.post(
            f"/api/devices/{device_id}/restore",
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(restored.status_code, 204)
        with self.app.app_context():
            device = db.session.get(Device, device_id)
            self.assertEqual(device.lifecycle_status, "active")
            self.assertIsNone(device.archived_at)

    def test_standard_user_cannot_open_admin_panel(self):
        token = self.register_and_login()
        self.complete_qr_enrollment(token)
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Administrator access is required", response.data)
        self.assertEqual(self.client.get("/api/users").status_code, 403)
        denied_logs = self.client.get("/api/admin/logs")
        self.assertEqual(denied_logs.status_code, 403)
        self.assertEqual(
            denied_logs.json["error"],
            "Administrator access is required for this action.",
        )
        with self.app.app_context():
            role = Role.query.filter_by(name="User").one()
            registering_user = User.query.filter_by(username="testuser").one()
            other_owner = User(
                username="otherowner",
                email="otherowner@example.com",
                full_name="Other Owner",
                password_hash=generate_password_hash("other-owner-password"),
                status="active",
            )
            other_owner.roles.append(role)
            other_device = Device(
                asset_tag="DM-PRIVATE-DEVICE",
                device_name="Private Device",
                hostname="private-device",
                device_type="Laptop",
                status="online",
                owner=other_owner,
                registered_by=other_owner,
            )
            registered_for_other = Device(
                asset_tag="DM-REGISTERED-DEVICE",
                device_name="Registered for Other",
                hostname="registered-for-other",
                device_type="Laptop",
                status="online",
                owner=other_owner,
                registered_by=registering_user,
            )
            db.session.add_all([other_owner, other_device, registered_for_other])
            db.session.commit()
            other_device_id = other_device.id
            registered_device_id = registered_for_other.id
        self.assertEqual(
            self.client.get(f"/api/devices/{other_device_id}").status_code,
            404,
        )
        self.assertEqual(
            self.client.get(f"/api/devices/{registered_device_id}").status_code,
            200,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/devices/{other_device_id}",
                headers={"X-CSRF-Token": token},
                json={"name": "Unauthorized edit"},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.delete(
                f"/api/devices/{other_device_id}",
                headers={"X-CSRF-Token": token},
            ).status_code,
            403,
        )
        denied_create = self.client.post(
            "/api/users",
            headers={"X-CSRF-Token": token},
            json={
                "full_name": "Denied User",
                "email": "denied@example.com",
                "username": "denied",
                "password": "denied-password-long-enough",
                "role": "User",
            },
        )
        self.assertEqual(denied_create.status_code, 403)

    def test_admin_can_manage_devices_but_cannot_register_new_devices(self):
        with self.app.app_context():
            administrator = User(
                username="deviceadmin",
                email="deviceadmin@example.com",
                full_name="Device Admin",
                password_hash=generate_password_hash("device-admin-password"),
                status="active",
                email_verified=True,
            )
            owner = User(
                username="deviceowner",
                email="deviceowner@example.com",
                full_name="Device Owner",
                password_hash=generate_password_hash("device-owner-password"),
                status="active",
            )
            admin_role = Role.query.filter_by(name="Administrator").one()
            user_role = Role.query.filter_by(name="User").one()
            administrator.roles.append(admin_role)
            owner.roles.append(user_role)
            device = Device(
                asset_tag="DM-OWNED-DEVICE",
                device_name="Owner Workstation",
                hostname="owner-workstation",
                device_type="Workstation",
                status="online",
                owner=owner,
                registered_by=owner,
            )
            db.session.add_all([administrator, owner, device])
            db.session.commit()
            device_id = device.id

        self.client.get("/login")
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]
        login = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "deviceadmin",
                "password": "device-admin-password",
            },
        )
        self.assertEqual(login.status_code, 302)
        self.client.get("/dashboard")
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]

        with patch(
            "device_monitoring_prototype.services.collect_hardware",
            return_value={"cpu_model": "Admin Test CPU"},
        ), patch(
            "device_monitoring_prototype.services.collect_network",
            return_value={"ip_address": "192.0.2.20"},
        ):
            created = self.client.post(
                "/api/devices",
                headers={"X-CSRF-Token": token},
                json={
                    "name": "Admin Registered Device",
                    "type": "Desktop",
                    "os": "Test OS",
                    "status": "online",
                },
            )
        self.assertEqual(created.status_code, 403, created.get_data(as_text=True))
        devices_page = self.client.get("/devices")
        self.assertNotIn(b"Generate QR Code", devices_page.data)
        self.assertNotIn(b' id="addDeviceBtn"', devices_page.data)
        self.assertNotIn(b"Register a Device with QR Code", devices_page.data)
        self.assertNotIn(b"deviceRegistrationQrModal", devices_page.data)
        qr_request = self.client.post(
            "/api/device-registration-tokens",
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(qr_request.status_code, 403)
        admin_token = "A" * 43
        self.assertEqual(
            self.client.get(
                f"/api/device-registration-tokens/{admin_token}/status"
            ).status_code,
            403,
        )
        self.assertEqual(self.client.get(f"/enroll/{admin_token}").status_code, 403)
        self.assertEqual(
            self.client.get(f"/enroll/{admin_token}/agent.py").status_code, 403
        )
        self.assertEqual(
            self.client.post(
                "/api/device-agent/enroll",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={},
            ).status_code,
            403,
        )
        self.assertEqual(self.client.get("/api/devices").status_code, 200)

        details = self.client.get(f"/api/devices/{device_id}")
        self.assertEqual(details.status_code, 200, details.get_data(as_text=True))
        self.assertEqual(details.json["view_mode"], "administrator")
        self.assertEqual(details.json["device_name"], "Owner Workstation")
        self.assertEqual(details.json["hostname"], "owner-workstation")
        self.assertEqual(details.json["owner"]["username"], "deviceowner")
        self.assertIn("activity_logs", details.json)
        self.assertIn("network_interfaces", details.json)
        updated = self.client.patch(
            f"/api/devices/{device_id}",
            headers={"X-CSRF-Token": token},
            json={"name": "Updated Owner Workstation"},
        )
        self.assertEqual(updated.status_code, 200, updated.get_data(as_text=True))
        archived = self.client.post(
            f"/api/devices/{device_id}/archive",
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(archived.status_code, 204)
        self.assertIn(
            device_id,
            {item["id"] for item in self.client.get("/api/archived-devices").json},
        )
        restored = self.client.post(
            f"/api/devices/{device_id}/restore",
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(restored.status_code, 204)
        removed = self.client.delete(
            f"/api/devices/{device_id}",
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(removed.status_code, 204)
        with self.app.app_context():
            retained = db.session.get(Device, device_id)
            self.assertIsNotNone(retained)
            self.assertEqual(retained.lifecycle_status, "deleted")
            self.assertIsNotNone(retained.deleted_at)
        self.assertNotIn(
            device_id,
            {item["id"] for item in self.client.get("/api/devices").json},
        )
        deleted_details = self.client.get(f"/api/devices/{device_id}")
        self.assertEqual(deleted_details.status_code, 200)
        self.assertEqual(deleted_details.json["view_mode"], "administrator")
        self.assertEqual(deleted_details.json["lifecycle_status"], "deleted")

        device_logs = self.client.get("/api/admin/logs?kind=device&q=updated")
        self.assertEqual(device_logs.status_code, 200, device_logs.get_data(as_text=True))
        self.assertTrue(any("updated" in entry["event"].lower() for entry in device_logs.json))

    def test_admin_can_create_users_and_role_changes_are_server_checked(self):
        with self.app.app_context():
            administrator = User(
                username="rootadmin",
                email="admin@example.com",
                full_name="Root Admin",
                password_hash=generate_password_hash("admin-password-long-enough"),
                status="active",
                email_verified=True,
            )
            administrator.roles.append(Role.query.filter_by(name="Administrator").one())
            db.session.add(administrator)
            db.session.commit()
            admin_id = administrator.id

        self.client.get("/login")
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]
        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "rootadmin",
                "password": "admin-password-long-enough",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.client.get("/dashboard")
        with self.client.session_transaction() as session:
            token = session["_csrf_token"]

        invalid_response = self.client.post(
            "/api/users",
            headers={"X-CSRF-Token": token},
            json={
                "full_name": "Weak User",
                "email": "weak@example.com",
                "username": "weakuser",
                "password": "weakpass",
                "confirm_password": "weakpass",
                "role": "User",
            },
        )
        self.assertEqual(invalid_response.status_code, 400)

        response = self.client.post(
            "/api/users",
            headers={"X-CSRF-Token": token},
            json={
                "full_name": "Managed User",
                "email": "managed@example.com",
                "username": "managed",
                "password": "Managed1!",
                "confirm_password": "Managed1!",
                "role": "User",
            },
        )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        managed_user_id = response.json["id"]
        response = self.client.patch(
            f"/api/users/{managed_user_id}",
            headers={"X-CSRF-Token": token},
            json={"full_name": "Updated Managed User"},
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.json["fullName"], "Updated Managed User")
        denied = self.client.patch(
            f"/api/users/{admin_id}",
            headers={"X-CSRF-Token": token},
            json={"role": "User"},
        )
        self.assertEqual(denied.status_code, 400)
        self.assertEqual(self.client.get("/api/users").status_code, 200)

        logs = self.client.get("/api/admin/logs?kind=activity&q=auth.login_succeeded")
        self.assertEqual(logs.status_code, 200, logs.get_data(as_text=True))
        self.assertTrue(any(entry["event"] == "auth.login_succeeded" for entry in logs.json))
        with self.app.app_context():
            db.session.add_all(
                ActivityLog(
                    actor_user_id=admin_id,
                    event_type="pagination-test",
                    details={"index": index},
                )
                for index in range(25)
            )
            db.session.commit()
        first_log_page = self.client.get(
            "/api/admin/logs?kind=activity&q=pagination-test&limit=10&offset=0"
        )
        second_log_page = self.client.get(
            "/api/admin/logs?kind=activity&q=pagination-test&limit=10&offset=10"
        )
        self.assertEqual(first_log_page.status_code, 200)
        self.assertEqual(second_log_page.status_code, 200)
        self.assertEqual(len(first_log_page.json), 10)
        self.assertEqual(len(second_log_page.json), 10)
        self.assertFalse(
            {entry["id"] for entry in first_log_page.json}
            & {entry["id"] for entry in second_log_page.json}
        )
        invalid_page = self.client.get("/api/admin/logs?kind=activity&limit=0")
        self.assertEqual(invalid_page.status_code, 400)
        invalid_filter = self.client.get("/api/admin/logs?kind=unknown")
        self.assertEqual(invalid_filter.status_code, 400)
        response = self.client.delete(
            f"/api/users/{managed_user_id}",
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(response.status_code, 204)
        with self.app.app_context():
            self.assertEqual(db.session.get(User, managed_user_id).status, "inactive")
    def test_qr_agent_enrollment_persists_specs_and_rejects_token_reuse(self):
        csrf = self.register_and_login()
        qr_response = self.client.post(
            "/api/device-registration-tokens",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(qr_response.status_code, 200, qr_response.get_data(as_text=True))
        qr_data = qr_response.json
        self.assertTrue(qr_data["qr_code"].startswith("data:image/svg+xml;base64,"))
        qr_svg = base64.b64decode(qr_data["qr_code"].split(",", 1)[1])
        self.assertIn(b"<svg", qr_svg)
        token = qr_data["enrollment_url"].rstrip("/").rsplit("/", 1)[-1]
        with self.app.app_context():
            registration = DeviceRegistrationToken.query.filter_by(
                token_hash=hashlib.sha256(token.encode()).hexdigest()
            ).one()
            self.assertEqual(registration.user.username, "testuser")
            self.assertNotEqual(registration.token_hash, token)
            self.assertEqual(len(registration.token_hash), 64)

        enrollment_page = self.client.get(f"/enroll/{token}")
        self.assertEqual(enrollment_page.status_code, 200)
        self.assertIn(b"Verify Account", enrollment_page.data)
        self.assertEqual(
            self.client.post(
                f"/enroll/{token}/agent.py",
                data={"csrf_token": csrf, "trust_device_agent": "yes"},
            ).status_code,
            403,
        )
        self.client.post(
            f"/enroll/{token}/verify",
            data={"csrf_token": csrf},
        )
        download = self.client.post(
            f"/enroll/{token}/agent.py",
            data={"csrf_token": csrf, "trust_device_agent": "yes"},
        )
        self.assertEqual(download.status_code, 200)
        self.assertIn(token.encode(), download.data)
        self.assertNotIn(b"__REGISTRATION_TOKEN__", download.data)
        self.assertIn("no-store", download.headers["Cache-Control"])

        specifications = {
            "cpu_name": "Example CPU",
            "ram_capacity_bytes": 16 * 1024**3,
            "ram_usage_bytes": 8 * 1024**3,
            "cpu_cores": 8,
            "storage_devices": [
                {
                    "name": "C:",
                    "total_bytes": 512 * 1024**3,
                    "available_bytes": 256 * 1024**3,
                }
            ],
            "storage_total_bytes": 512 * 1024**3,
            "storage_available_bytes": 256 * 1024**3,
            "gpu_information": ["Example GPU"],
            "motherboard_brand": "Example Board",
            "operating_system_name": "Windows 11 Pro",
            "operating_system_version": "10.0.26100",
            "network_adapters": ["Ethernet"],
            "ip_addresses": ["192.0.2.15", "2001:db8::1"],
        }
        payload = {
            "name": "Test Desktop",
            "device_type": "Desktop",
            "specifications": specifications,
        }
        agent_client = self.app.test_client()
        invalid_payload = {
            **payload,
            "specifications": {**specifications, "ram_usage_bytes": 17 * 1024**3},
        }
        invalid = agent_client.post(
            "/api/device-agent/enroll",
            headers={"Authorization": f"Bearer {token}"},
            json=invalid_payload,
        )
        self.assertEqual(invalid.status_code, 400, invalid.get_data(as_text=True))
        invalid_specifications = [
            {**specifications, "ip_addresses": ["not-an-ip"]},
            {**specifications, "storage_total_bytes": 1},
            {**specifications, "cpu_cores": 513},
            {**specifications, "unexpected": "field"},
        ]
        for invalid_spec in invalid_specifications:
            response = agent_client.post(
                "/api/device-agent/enroll",
                headers={"Authorization": f"Bearer {token}"},
                json={**payload, "specifications": invalid_spec},
            )
            self.assertEqual(response.status_code, 400)

        response = agent_client.post(
            "/api/device-agent/enroll",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        device_id = response.json["device_id"]
        consumed_status = self.client.get(
            f"/api/device-registration-tokens/{token}/status"
        )
        self.assertEqual(consumed_status.status_code, 200)
        self.assertEqual(consumed_status.json["status"], "used")
        details = self.client.get(f"/api/devices/{device_id}")
        self.assertEqual(details.status_code, 200)
        self.assertEqual(details.json["specification"]["cpu_model"], "Example CPU")
        self.assertEqual(
            details.json["specification"]["ram_usage_bytes"], 8 * 1024**3
        )
        self.assertEqual(
            details.json["specification"]["storage_devices"],
            specifications["storage_devices"],
        )
        self.assertEqual(
            details.json["specification"]["network_adapters"], ["Ethernet"]
        )
        self.assertEqual(
            details.json["specification"]["ip_addresses"],
            ["192.0.2.15", "2001:db8::1"],
        )
        specifications_page = self.client.get(
            f"/devices/{device_id}/specifications"
        )
        self.assertEqual(specifications_page.status_code, 200)
        self.assertIn(b"Detected Device Specifications", specifications_page.data)
        self.assertIn(b"Example Board", specifications_page.data)
        self.assertIn(b"Device registered with QR-based agent", specifications_page.data)
        with self.app.app_context():
            device = db.session.get(Device, device_id)
            self.assertEqual(device.owner.username, "testuser")
            self.assertEqual(device.registered_by.id, device.owner_user_id)
            self.assertEqual(device.status, "online")
            self.assertIsNotNone(device.registered_at)
            self.assertIsNotNone(device.updated_at)
            self.assertEqual(device.network_records[0].ip_address, "192.0.2.15")
            token_record = DeviceRegistrationToken.query.filter_by(
                token_hash=hashlib.sha256(token.encode()).hexdigest()
            ).one()
            self.assertIsNotNone(token_record.used_at)
            self.assertEqual(token_record.device_id, device.id)
            self.assertEqual(token_record.user_id, device.owner_user_id)

        replay = agent_client.post(
            "/api/device-agent/enroll",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
        self.assertEqual(replay.status_code, 401)

        other_client = self.app.test_client()
        self.register_and_login(
            full_name="Other User",
            email="other@example.com",
            username="otheruser",
            password="OtherUser1!",
            client=other_client,
        )
        self.assertEqual(
            other_client.get(f"/devices/{device_id}/specifications").status_code,
            302,
        )
        self.assertEqual(
            self.app.test_cli_runner().invoke(args=["init-db"]).exit_code,
            0,
        )
        admin_client = self.app.test_client()
        admin_client.get("/login")
        with admin_client.session_transaction() as session:
            admin_csrf = session["_csrf_token"]
        admin_login = admin_client.post(
            "/login",
            data={
                "csrf_token": admin_csrf,
                "username": "admin",
                "password": "admin123",
            },
        )
        self.assertEqual(admin_login.status_code, 302)
        self.assertEqual(
            admin_client.get(f"/devices/{device_id}/specifications").status_code,
            200,
        )

    def test_device_registration_qr_expires_and_requires_authenticated_creation(self):
        self.assertEqual(
            self.client.post("/api/device-registration-tokens").status_code, 400
        )
        csrf = self.register_and_login()
        first = self.client.post(
            "/api/device-registration-tokens",
            headers={"X-CSRF-Token": csrf},
        )
        second = self.client.post(
            "/api/device-registration-tokens",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertIn("server_time", first.json)
        svg_bytes = base64.b64decode(first.json["qr_code"].split(",", 1)[1])
        svg_root = ET.fromstring(svg_bytes)
        svg_namespace = "{http://www.w3.org/2000/svg}"
        background = next(svg_root.iter(f"{svg_namespace}rect"))
        qr_pattern = next(svg_root.iter(f"{svg_namespace}path"))
        self.assertEqual(background.get("fill"), "#ffffff")
        self.assertEqual(qr_pattern.get("fill"), "#111827")
        devices_page = self.client.get("/device-verification")
        self.assertIn(b"qr-code-card", devices_page.data)
        self.assertIn(b"deviceQrExpiryCard", devices_page.data)
        self.assertIn(b' id="createDeviceQrBtn"', devices_page.data)
        first_token = first.json["enrollment_url"].rstrip("/").rsplit("/", 1)[-1]
        second_token = second.json["enrollment_url"].rstrip("/").rsplit("/", 1)[-1]
        self.assertNotEqual(first_token, second_token)
        first_status = self.client.get(
            f"/api/device-registration-tokens/{first_token}/status"
        )
        self.assertEqual(first_status.json["status"], "revoked")
        active_status = self.client.get(
            f"/api/device-registration-tokens/{second_token}/status"
        )
        self.assertEqual(active_status.status_code, 200)
        self.assertEqual(active_status.json["status"], "active")
        self.assertIn("server_time", active_status.json)
        other_client = self.app.test_client()
        self.register_and_login(
            full_name="Another User",
            email="another@example.com",
            username="anotheruser",
            password="AnotherUser1!",
            client=other_client,
        )
        unauthorized_status = other_client.get(
            f"/api/device-registration-tokens/{second_token}/status"
        )
        self.assertEqual(unauthorized_status.status_code, 404)
        with self.app.app_context():
            registration = DeviceRegistrationToken.query.filter_by(
                token_hash=hashlib.sha256(second_token.encode()).hexdigest()
            ).one()
            registration.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            db.session.commit()
        expired_page = self.client.get(f"/enroll/{second_token}")
        self.assertEqual(expired_page.status_code, 410)
        expired_status = self.client.get(
            f"/api/device-registration-tokens/{second_token}/status"
        )
        self.assertEqual(expired_status.status_code, 200)
        self.assertEqual(expired_status.json["status"], "expired")

    def test_windows_agent_parses_only_the_requested_inventory_fields(self):
        expected = {
            "cpu_name": "Example CPU",
            "cpu_cores": 4,
            "ram_capacity_bytes": 8 * 1024**3,
            "ram_usage_bytes": 3 * 1024**3,
            "storage_devices": [
                {"name": "C:", "total_bytes": 256, "available_bytes": 128}
            ],
            "storage_total_bytes": 256,
            "storage_available_bytes": 128,
            "gpu_information": ["Example GPU"],
            "motherboard_brand": "Example Board",
            "operating_system_name": "Windows 11",
            "operating_system_version": "10.0.26100",
            "network_adapters": ["Ethernet"],
            "ip_addresses": ["192.0.2.20"],
        }
        with patch.dict(
            device_agent.collect_specifications.__globals__,
            {"os": SimpleNamespace(name="nt")},
        ):
            with patch.object(
                device_agent.subprocess,
                "run",
                return_value=SimpleNamespace(stdout=json.dumps(expected)),
            ) as powershell:
                detected = device_agent.collect_specifications()
        self.assertEqual(detected, expected)
        self.assertIn("Win32_Processor", powershell.call_args.args[0][-1])
        self.assertNotIn("-ExecutionPolicy", powershell.call_args.args[0])
        self.assertEqual(
            {key for _, key in device_agent.FIELD_LABELS},
            set(expected),
        )


if __name__ == "__main__":
    unittest.main()
