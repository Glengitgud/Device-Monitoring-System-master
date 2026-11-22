"""Dashboard access and "Link a Device" flow (isolated in-memory databases)."""

import hashlib
import io
import json
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from device_monitoring_prototype.app import create_app
from device_monitoring_prototype.authentication import decrypt_totp_secret, totp_counter
from device_monitoring_prototype.models import (
    Device,
    DeviceRegistrationToken,
    Role,
    User,
    db,
)
from device_monitoring_prototype.services import create_device, soft_delete_device
from device_monitoring_prototype.tests import test_database_integration as base_tests

GIB = 1024 ** 3


def agent_payload(name="Office PC", device_type="Desktop"):
    return {
        "name": name,
        "device_type": device_type,
        "specifications": {
            "cpu_name": "Intel Core i5", "cpu_cores": 4,
            "ram_capacity_bytes": 8 * GIB, "ram_usage_bytes": 3 * GIB,
            "storage_devices": [{"name": "C:", "total_bytes": 256 * GIB, "available_bytes": 100 * GIB}],
            "storage_total_bytes": 256 * GIB, "storage_available_bytes": 100 * GIB,
            "gpu_information": ["Intel UHD"], "motherboard_brand": "ASUS",
            "operating_system_name": "Windows 11", "operating_system_version": "10.0.26100",
            "network_adapters": ["Ethernet"], "ip_addresses": ["192.0.2.10"],
        },
    }


class DashboardAccessTest(unittest.TestCase):
    register_and_login = base_tests.DatabaseIntegrationTest.register_and_login

    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "dashboard-access-test",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "MAIL_SERVER": None,
        })
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            db.session.add_all([Role(name="Administrator"), Role(name="User")])
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    # -- helpers ---------------------------------------------------------

    def issue_link_token(self, csrf, client=None):
        client = client or self.client
        response = client.post("/api/device-link", headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return parse_qs(urlsplit(response.json["link"]).query)["token"][0]

    def enroll(self, token, payload=None):
        """Submit exactly as an agent does: separate client, bearer token, no cookies."""
        return self.app.test_client().post(
            "/api/device-agent/enroll",
            headers={"Authorization": f"Bearer {token}"},
            json=payload or agent_payload(),
        )

    def sign_in(self, username="testuser", password="Passw0rd!", next_url=None, client=None):
        """Full password + authenticator login; returns the final redirect response."""
        client = client or self.client
        client.post("/logout", data={"csrf_token": self.csrf_for(client)})
        client.get("/login")
        form = {"csrf_token": self.csrf_for(client), "username": username, "password": password}
        if next_url:
            form["next"] = next_url
        self.assertEqual(client.post("/login", data=form).status_code, 200)
        with self.app.app_context():
            user = User.query.filter_by(username=username).one()
            secret = decrypt_totp_secret(user.totp_secret_encrypted)
            counter = (user.totp_last_counter or int(time.time() // 30)) + 1
        with patch(
            "device_monitoring_prototype.authentication.totp_counter",
            side_effect=lambda s, c: totp_counter(s, c, now=counter * 30 + 1),
        ):
            return client.post("/login", data={
                "csrf_token": self.csrf_for(client),
                "totp_code": base_tests._totp_code(secret, counter),
            })

    @staticmethod
    def csrf_for(client):
        with client.session_transaction() as session:
            return session.get("_csrf_token", "")

    def device_count(self, username="testuser"):
        with self.app.app_context():
            user = User.query.filter_by(username=username).one()
            return Device.query.filter_by(owner_user_id=user.id).count()

    def status(self):
        return self.client.get("/api/device-verification-status").json

    # -- scenarios -------------------------------------------------------

    def test_new_account_with_zero_devices_is_sent_to_link_a_device(self):
        self.register_and_login()  # asserts the post-login landing is /device-verification
        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 302)
        self.assertEqual(dashboard.location, "/device-verification")
        self.assertEqual(self.client.get("/login").location, "/device-verification")
        self.assertEqual(self.client.get("/register").location, "/device-verification")
        self.assertEqual(self.client.get("/api/dashboard").status_code, 403)
        self.assertEqual(self.client.get("/api/devices").status_code, 403)
        self.assertEqual(self.client.get("/devices").status_code, 302)
        self.assertEqual(self.status()["verified"], False)
        page = self.client.get("/device-verification")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="deviceRegistrationSuccessModal"', page.data)

    def test_enrollment_unlocks_the_dashboard_immediately_without_relogin(self):
        csrf = self.register_and_login()
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        token = self.issue_link_token(csrf)
        enrolled = self.enroll(token)
        self.assertEqual(enrolled.status_code, 201, enrolled.get_data(as_text=True))
        # Same browser session, no logout/login: access is granted at once.
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/api/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/login").location, "/dashboard")
        status = self.status()
        self.assertTrue(status["verified"])
        self.assertEqual(status["verified_devices"], 1)
        self.assertEqual(status["latest_device"]["id"], enrolled.json["device_id"])
        with self.app.app_context():
            device = db.session.get(Device, enrolled.json["device_id"])
            user = User.query.filter_by(username="testuser").one()
            self.assertTrue(device.is_verified)
            self.assertEqual(device.owner_user_id, user.id)
            self.assertEqual(device.registered_by_user_id, user.id)
            self.assertEqual(device.lifecycle_status, "active")

    def test_refreshing_after_enrollment_keeps_access_and_does_not_loop(self):
        csrf = self.register_and_login()
        self.assertEqual(self.enroll(self.issue_link_token(csrf)).status_code, 201)
        for _ in range(3):
            self.assertEqual(self.client.get("/dashboard").status_code, 200)
            page = self.client.get("/device-verification")
            self.assertEqual(page.status_code, 200)
            # The verified banner is rendered visible on reload.
            self.assertIn(b'class="alert alert-success "', page.data)
            self.assertIn(b"1 verified device linked", page.data)

    def test_enrollment_rejection_shows_a_reason_and_does_not_unlock(self):
        csrf = self.register_and_login()
        token = self.issue_link_token(csrf)
        bad_type = self.enroll(token, agent_payload(device_type="Toaster"))
        self.assertEqual(bad_type.status_code, 400)
        self.assertIn("Device type must be", bad_type.json["error"])
        incomplete = agent_payload()
        del incomplete["specifications"]["cpu_name"]
        rejected = self.enroll(token, incomplete)
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("incomplete", rejected.json["error"])
        self.assertEqual(self.enroll(token, {"name": "x"}).status_code, 400)
        self.assertEqual(self.device_count(), 0)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        # A rejected payload does not burn the one-use token; a corrected retry works.
        self.assertEqual(self.enroll(token).status_code, 201)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_missing_or_forged_tokens_are_refused(self):
        self.register_and_login()
        no_auth = self.app.test_client().post("/api/device-agent/enroll", json=agent_payload())
        self.assertEqual(no_auth.status_code, 401)
        self.assertEqual(self.enroll("F" * 43).status_code, 401)
        self.assertEqual(self.device_count(), 0)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_expired_enrollment_token_is_refused(self):
        csrf = self.register_and_login()
        token = self.issue_link_token(csrf)
        with self.app.app_context():
            registration = DeviceRegistrationToken.query.filter_by(
                token_hash=hashlib.sha256(token.encode("ascii")).hexdigest()
            ).one()
            registration.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.session.commit()
        expired = self.enroll(token)
        self.assertEqual(expired.status_code, 401)
        self.assertIn("token", expired.json["error"].lower())
        self.assertEqual(self.device_count(), 0)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_duplicate_enrollment_with_the_same_token_is_refused(self):
        csrf = self.register_and_login()
        token = self.issue_link_token(csrf)
        self.assertEqual(self.enroll(token).status_code, 201)
        duplicate = self.enroll(token, agent_payload(name="Second try"))
        self.assertEqual(duplicate.status_code, 401)
        self.assertEqual(self.device_count(), 1)

    def test_a_later_download_or_link_does_not_invalidate_an_earlier_agent(self):
        """Regression: each new download used to revoke every earlier unused token,
        so running an agent downloaded a minute before failed with HTTP 401."""
        csrf = self.register_and_login()
        with patch(
            "device_monitoring_prototype.app.build_agent_executable",
            return_value=b"MZagent",
        ) as build:
            first = self.client.post("/device-agent/windows.exe", data={"csrf_token": csrf})
            self.client.post("/device-agent/windows.exe", data={"csrf_token": csrf})
        self.assertEqual(first.status_code, 200)
        earlier_agent_token = build.call_args_list[0].args[0]
        self.issue_link_token(csrf)  # e.g. "Link this device" tapped on the Link page
        self.client.post("/device-agent/linux/deb", data={"csrf_token": csrf})
        enrolled = self.enroll(earlier_agent_token)
        self.assertEqual(enrolled.status_code, 201, enrolled.get_data(as_text=True))
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_live_direct_tokens_are_capped_per_user(self):
        csrf = self.register_and_login()
        tokens = [self.issue_link_token(csrf) for _ in range(7)]
        # Only the newest MAX_PENDING_DIRECT_TOKENS (5) stay usable.
        self.assertEqual(self.enroll(tokens[0]).status_code, 401)
        self.assertEqual(self.enroll(tokens[1]).status_code, 401)
        self.assertEqual(self.enroll(tokens[2]).status_code, 201)
        self.assertEqual(self.enroll(tokens[6], agent_payload(name="Laptop")).status_code, 201)
        self.assertEqual(self.device_count(), 2)

    def test_link_page_reports_a_downloaded_agent_that_has_not_submitted(self):
        csrf = self.register_and_login()
        self.assertIsNone(self.status()["pending_enrollment"])
        page = self.client.get("/device-verification").get_data(as_text=True)
        self.assertIn('id="pendingEnrollmentNotice"', page)
        self.assertRegex(page, r'id="pendingEnrollmentNotice"[^>]*\bhidden\b')
        token = self.issue_link_token(csrf)
        pending = self.status()["pending_enrollment"]
        self.assertIsNotNone(pending)
        self.assertIn("expires_at", pending)
        page = self.client.get("/device-verification").get_data(as_text=True)
        self.assertNotRegex(page, r'id="pendingEnrollmentNotice"[^>]*\bhidden\b')
        # First device: download-and-open steps instead of the "Link this device" button.
        self.assertIn('id="firstDeviceCard"', page)
        self.assertNotIn('id="linkThisDeviceBtn"', page)
        self.assertEqual(self.enroll(token).status_code, 201)
        status = self.status()
        self.assertTrue(status["verified"])
        self.assertIsNone(status["pending_enrollment"])

    def test_existing_account_with_linked_devices_lands_on_the_dashboard_after_login(self):
        csrf = self.register_and_login()
        self.assertEqual(self.enroll(self.issue_link_token(csrf)).status_code, 201)
        landing = self.sign_in()
        self.assertEqual(landing.status_code, 302)
        self.assertEqual(landing.location, "/dashboard")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        # A safe "next" page is honoured; an off-site one is ignored.
        self.assertEqual(self.sign_in(next_url="/devices").location, "/devices")
        self.assertEqual(self.sign_in(next_url="https://evil.example/x").location, "/dashboard")

    def test_unverified_user_login_ignores_next_and_links_a_device_first(self):
        self.register_and_login()
        landing = self.sign_in(next_url="/dashboard")
        self.assertEqual(landing.location, "/device-verification")

    def test_navigation_between_downloads_link_and_dashboard_never_loops(self):
        csrf = self.register_and_login()
        for path in ("/download", "/device-verification", "/dashboard", "/download", "/dashboard"):
            with self.subTest(state="unverified", path=path):
                response = self.client.get(path, follow_redirects=True)
                self.assertEqual(response.status_code, 200)
                self.assertLessEqual(len(response.history), 1)
                expected = "/device-verification" if path == "/dashboard" else path
                self.assertEqual(response.request.path, expected)
        self.assertEqual(self.enroll(self.issue_link_token(csrf)).status_code, 201)
        for path in ("/download", "/device-verification", "/dashboard", "/devices", "/login"):
            with self.subTest(state="verified", path=path):
                response = self.client.get(path, follow_redirects=True)
                self.assertEqual(response.status_code, 200)
                self.assertLessEqual(len(response.history), 1)
                self.assertEqual(response.request.path, "/dashboard" if path == "/login" else path)

    def test_administrators_keep_their_access(self):
        self.register_and_login()
        with self.app.app_context():
            user = User.query.filter_by(username="testuser").one()
            user.roles = [Role.query.filter_by(name="Administrator").one()]
            db.session.commit()
        csrf = self.csrf_for(self.client)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/login").location, "/dashboard")
        self.assertEqual(self.client.get("/device-verification").status_code, 404)
        self.assertEqual(self.client.get("/download").status_code, 200)
        self.assertEqual(self.client.post("/api/device-link", headers={"X-CSRF-Token": csrf}).status_code, 403)
        self.assertEqual(self.sign_in().location, "/dashboard")

    def test_only_the_users_own_verified_active_devices_unlock_access(self):
        csrf = self.register_and_login()
        other = self.app.test_client()
        other_csrf = self.register_and_login(
            email="other@example.com", username="otheruser", full_name="Other User", client=other
        )
        # Another user's verified device does not unlock this account.
        self.assertEqual(self.enroll(self.issue_link_token(other_csrf, client=other)).status_code, 201)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        self.assertEqual(other.get("/dashboard").status_code, 200)
        with self.app.test_request_context():
            user = User.query.filter_by(username="testuser").one()
            # An unverified device (e.g. pre-dating migration 007) does not count.
            create_device(user, {"name": "Legacy PC", "hostname": "legacy", "type": "Desktop",
                                 "os": "Windows 10", "status": "online"})
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        enrolled = self.enroll(self.issue_link_token(csrf))
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        # Archived devices still count; a deleted (removed) device does not.
        self.client.post(f"/api/devices/{enrolled.json['device_id']}/archive",
                         headers={"X-CSRF-Token": self.csrf_for(self.client)})
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        with self.app.test_request_context():
            soft_delete_device(db.session.get(Device, enrolled.json["device_id"]))
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        self.assertEqual(self.client.get("/dashboard", follow_redirects=True).request.path,
                         "/device-verification")


class WindowsAgentConsoleTest(unittest.TestCase):
    """The packaged Windows agent must explain what happened before its window closes."""

    def setUp(self):
        from device_monitoring_prototype import device_agent
        self.agent = device_agent
        self.specs = agent_payload()["specifications"]

    def run_main(self, answers, urlopen=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(self.agent, "collect_specifications", return_value=dict(self.specs)), \
                patch.object(self.agent, "collect_health_report", return_value={"checks": [], "issues": []}), \
                patch.object(self.agent, "configure_logging", return_value="agent.log"), \
                patch.object(self.agent, "input", side_effect=answers, create=True), \
                patch.object(self.agent, "REGISTRATION_TOKEN", "T" * 43), \
                patch.object(self.agent, "SUBMISSION_URL", "https://monitor.example.edu/api/device-agent/enroll"), \
                patch.object(self.agent.urllib.request, "urlopen", urlopen or (lambda *a, **k: None)) as opener, \
                patch("sys.stdout", stdout), patch("sys.stderr", stderr), \
                self.assertLogs(self.agent.LOGGER, level="INFO") as logs:
            code = self.agent.main()
        return code, stdout.getvalue() + stderr.getvalue(), "\n".join(logs.output), opener

    def test_cancelling_is_logged_and_nothing_is_sent(self):
        code, output, log, _ = self.run_main(["", "Laptop", "no"])
        self.assertEqual(code, 0)
        self.assertIn("Submission cancelled", output)
        self.assertIn("type yes", output)
        self.assertIn("cancelled at the confirmation prompt", log)
        self.assertNotIn("Submitting payload", log)

    def test_y_is_accepted_as_confirmation(self):
        class Response(io.BytesIO):
            status = 201
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False

        sent = []

        def urlopen(request, timeout):
            sent.append(request)
            return Response(b'{"device_id": 7}')

        with patch.object(self.agent, "show_registration_success"):
            code, output, log, _ = self.run_main(["", "Laptop", "y"], urlopen=urlopen)
        self.assertEqual(code, 0)
        self.assertEqual(len(sent), 1)
        self.assertIn("Device Registered Successfully", output)

    def test_expired_download_gets_a_clear_instruction(self):
        import urllib.error

        def expired(request, timeout):
            raise urllib.error.HTTPError(
                request.full_url, 401, "Unauthorized", {},
                io.BytesIO(b'{"error": "This device registration token is invalid or expired."}'),
            )

        with patch.object(self.agent, "_show_log_location"):
            code, output, _log, _ = self.run_main(["", "Laptop", "yes"], urlopen=expired)
        self.assertEqual(code, 1)
        self.assertIn("this download has expired or was already used", output)
        self.assertIn("Download the agent again", output)
        self.assertNotIn('{"error"', output)

    def test_review_window_sections_show_every_specification(self):
        specs = dict(self.specs)
        specs.update(
            ram_capacity_bytes=16 * 1024 ** 3,
            ram_usage_bytes=8 * 1024 ** 3,
            storage_devices=[{"name": "C:\\", "total_bytes": 100 * 1024 ** 3,
                              "available_bytes": 25 * 1024 ** 3}],
            storage_total_bytes=100 * 1024 ** 3,
            storage_available_bytes=25 * 1024 ** 3,
        )
        sections = self.agent.specification_sections(specs)
        rows = {row["label"]: row for _title, section in sections for row in section}
        for label, _key in self.agent.FIELD_LABELS:
            self.assertIn(label, rows)
        self.assertEqual(rows["RAM usage"]["value"], "8.0 GB in use (50%)")
        self.assertAlmostEqual(rows["RAM usage"]["fraction"], 0.5)
        self.assertEqual(rows["C:\\"]["value"], "25.0 GB free of 100.0 GB")
        self.assertAlmostEqual(rows["C:\\"]["fraction"], 0.75)
        self.assertTrue(rows["C:\\"]["detail"])
        # Missing values are shown as Unavailable instead of crashing the window.
        empty = {row["label"]: row["value"]
                 for _t, section in self.agent.specification_sections({}) for row in section}
        self.assertEqual(empty["Total storage capacity"], "Unavailable")
        self.assertEqual(empty["CPU name"], "Unavailable")

    def test_packaged_exe_reviews_in_a_window_and_script_uses_console(self):
        parse = self.agent._parse_arguments
        self.assertFalse(self.agent._use_review_window(parse([])))
        self.assertTrue(self.agent._use_review_window(parse(["--gui"])))
        with patch.object(self.agent.sys, "frozen", True, create=True):
            self.assertTrue(self.agent._use_review_window(parse([])))
            self.assertFalse(self.agent._use_review_window(parse(["--console"])))
            self.assertFalse(self.agent._use_review_window(parse(["--yes"])))

    def test_review_window_approval_submits_without_console_prompts(self):
        class Response(io.BytesIO):
            status = 201
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False

        sent = []

        def urlopen(request, timeout):
            sent.append(json.loads(request.data))
            return Response(b'{"device_id": 9}')

        approved = {"name": "Lab PC", "device_type": "Laptop"}
        with patch.object(self.agent, "_use_review_window", return_value=True), \
                patch.object(self.agent, "review_specifications_window", return_value=approved) as window, \
                patch.object(self.agent, "show_registration_success") as success:
            code, output, _log, _ = self.run_main([], urlopen=urlopen)
        self.assertEqual(code, 0)
        window.assert_called_once()
        success.assert_called_once()
        self.assertEqual((sent[0]["name"], sent[0]["device_type"]), ("Lab PC", "Laptop"))
        self.assertNotIn("Detected device specifications", output)

    def test_review_window_cancel_sends_nothing_and_failure_falls_back(self):
        with patch.object(self.agent, "_use_review_window", return_value=True), \
                patch.object(self.agent, "review_specifications_window", return_value=None):
            code, output, log, _ = self.run_main([])
        self.assertEqual(code, 0)
        self.assertIn("Submission cancelled", output)
        self.assertNotIn("Submitting payload", log)

        with patch.object(self.agent, "_use_review_window", return_value=True), \
                patch.object(self.agent, "review_specifications_window", side_effect=RuntimeError("no display")):
            code, output, log, _ = self.run_main(["", "Laptop", "no"])
        self.assertEqual(code, 0)
        self.assertIn("continuing in this console", output)
        self.assertIn("Detected device specifications", output)
        self.assertNotIn("Submitting payload", log)

    def test_packaged_console_waits_for_enter_before_closing(self):
        with patch.object(self.agent.sys, "frozen", True, create=True), \
                patch.object(self.agent.sys, "stdin") as stdin, \
                patch.object(self.agent, "input", create=True) as prompt:
            stdin.isatty.return_value = True
            self.agent._pause_before_closing()
        prompt.assert_called_once()
        # Not frozen (tests, python script) or no console: never blocks.
        with patch.object(self.agent, "input", create=True) as prompt:
            self.agent._pause_before_closing()
        prompt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
