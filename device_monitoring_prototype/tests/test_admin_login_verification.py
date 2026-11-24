"""Administrator sign-in: password plus a 6-digit code emailed to the admin mailbox."""

import unittest
from datetime import timedelta
from unittest.mock import patch

from device_monitoring_prototype.app import create_app
from device_monitoring_prototype.authentication import (
    DEFAULT_ADMIN_EMAIL,
    EmailDeliveryError,
    utcnow,
)
from device_monitoring_prototype.models import (
    ActivityLog,
    LoginVerification,
    Role,
    User,
    db,
)
from device_monitoring_prototype.services import hash_password, verify_password

SEND_EMAIL = "device_monitoring_prototype.authentication._send_email"


class AdminLoginVerificationTest(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "admin-login-test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "MAIL_SERVER": None,
        })
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            db.session.add_all([Role(name="Administrator"), Role(name="User")])
            db.session.commit()
        self.runner = self.app.test_cli_runner()
        self.assertEqual(self.runner.invoke(args=["init-db"]).exit_code, 0)

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def csrf(self):
        with self.client.session_transaction() as session:
            return session.get("_csrf_token", "")

    def submit_password(self, password="admin123"):
        self.client.get("/login")
        with patch(SEND_EMAIL) as send_email:
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "admin", "password": password,
            })
        return response, send_email

    def submit_code(self, code):
        return self.client.post("/login", data={"csrf_token": self.csrf(), "email_code": code})

    def signed_in_user_id(self):
        with self.client.session_transaction() as session:
            return session.get("_user_id")

    def test_default_administrator_uses_the_system_mailbox(self):
        self.assertEqual(DEFAULT_ADMIN_EMAIL, "devmonitor.system@gmail.com")
        with self.app.app_context():
            self.assertEqual(
                User.query.filter_by(username="admin").one().email,
                "devmonitor.system@gmail.com",
            )

    def test_password_alone_does_not_sign_the_administrator_in(self):
        response, send_email = self.submit_password()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Email sign-in code", response.data)
        self.assertRegex(response.get_data(as_text=True), r'data-code-expires-in="(299|300)"')
        self.assertIsNone(self.signed_in_user_id())
        self.assertEqual(send_email.call_args.args[0], "devmonitor.system@gmail.com")
        self.assertEqual(send_email.call_args.kwargs["purpose"], "admin_login")
        # The dashboard stays closed until the code is entered.
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_wrong_password_sends_no_code(self):
        response, send_email = self.submit_password("not-the-password")
        self.assertEqual(response.status_code, 401)
        send_email.assert_not_called()

    def test_correct_code_completes_sign_in_and_is_audited(self):
        _response, send_email = self.submit_password()
        code = send_email.call_args.args[1]
        wrong = "000000" if code != "000000" else "111111"
        rejected = self.submit_code(wrong)
        self.assertEqual(rejected.status_code, 401)
        self.assertIn(b"incorrect", rejected.data)
        self.assertIsNone(self.signed_in_user_id())

        accepted = self.submit_code(code)
        self.assertEqual(accepted.status_code, 302)
        self.assertEqual(accepted.location, "/dashboard")
        self.assertIsNotNone(self.signed_in_user_id())
        with self.app.app_context():
            success = ActivityLog.query.filter_by(event_type="auth.login_succeeded").one()
            self.assertEqual(success.details["method"], "email")
            # A used code cannot be replayed.
            self.assertIsNotNone(LoginVerification.query.one().used_at)

    def test_expired_code_is_rejected_and_resend_issues_a_new_one(self):
        _response, send_email = self.submit_password()
        old_code = send_email.call_args.args[1]
        with self.app.app_context():
            verification = LoginVerification.query.one()
            verification.expires_at = utcnow() - timedelta(seconds=1)
            verification.created_at = utcnow() - timedelta(minutes=6)
            db.session.commit()
        expired = self.submit_code(old_code)
        self.assertEqual(expired.status_code, 401)
        self.assertIn(b"expired", expired.data)
        self.assertIn(b"Resend code", expired.data)

        with patch(SEND_EMAIL) as resend:
            resent = self.client.post("/login", data={"csrf_token": self.csrf(), "resend_code": "1"})
        self.assertEqual(resent.status_code, 200)
        self.assertIn(b"A new sign-in code has been sent", resent.data)
        self.assertEqual(self.submit_code(resend.call_args.args[1]).status_code, 302)

    def test_resend_waits_for_the_cooldown(self):
        self.submit_password()
        with patch(SEND_EMAIL) as resend:
            response = self.client.post("/login", data={"csrf_token": self.csrf(), "resend_code": "1"})
        self.assertEqual(response.status_code, 429)
        self.assertIn(b"Please wait", response.data)
        resend.assert_not_called()

    def test_too_many_wrong_codes_lock_the_code(self):
        _response, send_email = self.submit_password()
        code = send_email.call_args.args[1]
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(5):
            self.submit_code(wrong)
        locked = self.submit_code(code)
        self.assertEqual(locked.status_code, 401)
        self.assertIn(b"Too many incorrect codes", locked.data)

    def test_email_failure_keeps_the_administrator_signed_out(self):
        self.client.get("/login")
        with patch(SEND_EMAIL, side_effect=EmailDeliveryError("Mail is down.")):
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "admin", "password": "admin123",
            })
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"Mail is down.", response.data)
        self.assertIsNone(self.signed_in_user_id())
        with self.client.session_transaction() as session:
            self.assertNotIn("pending_login_user_id", session)

    def test_init_db_moves_the_bootstrap_address_to_the_admin_mailbox(self):
        with self.app.app_context():
            User.query.filter_by(username="admin").one().email = "admin@localhost"
            db.session.commit()
        result = self.runner.invoke(args=["init-db"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Administrator email set to devmonitor.system@gmail.com", result.output)

    def test_create_admin_requires_the_admin_mailbox_and_can_reset_the_password(self):
        refused = self.runner.invoke(
            args=["create-admin", "--username", "second", "--email", "other@example.com",
                  "--full-name", "Second Admin"],
        )
        self.assertNotEqual(refused.exit_code, 0)
        self.assertIn("must use devmonitor.system@gmail.com", refused.output)

        reset = self.runner.invoke(
            args=["create-admin", "--username", "admin", "--full-name", "Administrator",
                  "--reset-password"],
            input="N3w-Admin-Pass\nN3w-Admin-Pass\n",
        )
        self.assertEqual(reset.exit_code, 0, reset.output)
        with self.app.app_context():
            administrator = User.query.filter_by(username="admin").one()
            self.assertTrue(verify_password("N3w-Admin-Pass", administrator.password_hash))

    def test_create_admin_creates_an_account_on_an_empty_mailbox(self):
        with self.app.app_context():
            administrator = User.query.filter_by(username="admin").one()
            administrator.email = "retired-admin@example.com"
            db.session.commit()
        created = self.runner.invoke(
            args=["create-admin", "--username", "opsadmin", "--full-name", "Ops Admin"],
            input="Adm1n-Passw0rd!\nAdm1n-Passw0rd!\n",
        )
        self.assertEqual(created.exit_code, 0, created.output)
        with self.app.app_context():
            user = User.query.filter_by(username="opsadmin").one()
            self.assertEqual(user.email, "devmonitor.system@gmail.com")
            self.assertTrue(user.is_admin)

    def test_standard_users_still_use_their_authenticator(self):
        with self.app.app_context():
            user = User(
                username="plainuser",
                email="plain@example.test",
                password_hash=hash_password("Passw0rd!"),
                status="active",
                email_verified=True,
                totp_enabled=True,
                totp_secret_encrypted="unused",
            )
            user.roles.append(Role.query.filter_by(name="User").one())
            db.session.add(user)
            db.session.commit()
        self.client.get("/login")
        with patch(SEND_EMAIL) as send_email:
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "plainuser", "password": "Passw0rd!",
            })
        self.assertIn(b"Google Authenticator code", response.data)
        send_email.assert_not_called()


if __name__ == "__main__":
    unittest.main()
