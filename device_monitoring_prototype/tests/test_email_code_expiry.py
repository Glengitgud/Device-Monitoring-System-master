"""Registration email codes: 5-minute server-side expiry and the visible countdown."""

import unittest
from datetime import timedelta
from unittest.mock import patch

from device_monitoring_prototype.app import create_app
from device_monitoring_prototype.authentication import EMAIL_CODE_LIFETIME, utcnow
from device_monitoring_prototype.models import (
    EmailVerification,
    RegistrationChallenge,
    Role,
    db,
)

SEND_EMAIL = "device_monitoring_prototype.authentication._send_email"


class EmailCodeExpiryTest(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "email-code-expiry-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "MAIL_SERVER": None,
        })
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            db.session.add_all([Role(name="Administrator"), Role(name="User")])
            db.session.commit()
        self.client.get("/register")
        with self.client.session_transaction() as session:
            self.csrf = session["_csrf_token"]
        with patch(SEND_EMAIL) as send_email:
            started = self.client.post("/api/registration/start", data={
                "csrf_token": self.csrf,
                "full_name": "Timer Test",
                "email": "timer@example.com",
                "username": "timeruser",
                "password": "TimerPass1!",
                "confirm_password": "TimerPass1!",
            })
        self.assertEqual(started.status_code, 200, started.get_data(as_text=True))
        self.code = send_email.call_args.args[1]

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def age_code(self, seconds):
        """Move the current code (and the resend clock) ``seconds`` into the past."""
        with self.app.app_context():
            verification = EmailVerification.query.order_by(EmailVerification.id.desc()).first()
            verification.created_at -= timedelta(seconds=seconds)
            verification.expires_at -= timedelta(seconds=seconds)
            challenge = db.session.get(RegistrationChallenge, verification.registration_challenge_id)
            challenge.last_email_sent_at -= timedelta(seconds=seconds)
            db.session.commit()

    def verify(self, code):
        return self.client.post(
            "/api/registration/verify-email", data={"csrf_token": self.csrf, "code": code}
        )

    def test_code_lifetime_is_five_minutes(self):
        self.assertEqual(EMAIL_CODE_LIFETIME, timedelta(minutes=5))
        with self.app.app_context():
            verification = EmailVerification.query.one()
            self.assertEqual(verification.expires_at - verification.created_at, EMAIL_CODE_LIFETIME)

    def test_status_reports_the_time_left_for_the_countdown(self):
        remaining = self.client.get("/api/registration/status").json["code_expires_in_seconds"]
        self.assertTrue(295 <= remaining <= 300, remaining)
        self.age_code(240)
        remaining = self.client.get("/api/registration/status").json["code_expires_in_seconds"]
        self.assertTrue(55 <= remaining <= 60, remaining)

    def test_code_still_works_just_before_five_minutes(self):
        self.age_code(290)
        self.assertEqual(self.verify(self.code).status_code, 200)

    def test_expired_code_is_rejected_with_a_resend_hint(self):
        self.age_code(301)
        self.assertEqual(
            self.client.get("/api/registration/status").json["code_expires_in_seconds"], 0
        )
        expired = self.verify(self.code)
        self.assertEqual(expired.status_code, 400)
        self.assertIn("expired", expired.json["error"])
        self.assertIn("Resend code", expired.json["error"])

        with patch(SEND_EMAIL) as send_email:
            resent = self.client.post(
                "/api/registration/resend-code", data={"csrf_token": self.csrf}
            )
        self.assertEqual(resent.status_code, 200)
        self.assertTrue(295 <= resent.json["code_expires_in_seconds"] <= 300)
        self.assertEqual(self.verify(send_email.call_args.args[1]).status_code, 200)

    def test_registration_page_shows_the_countdown(self):
        page = self.client.get("/register").get_data(as_text=True)
        self.assertIn('id="emailCodeExpiry"', page)
        self.assertIn('role="timer"', page)
        self.assertIn("js/code-expiry.js", page)


if __name__ == "__main__":
    unittest.main()
