"""Public homepage (/) and its "Contact us" form."""

import re
import unittest
from unittest.mock import MagicMock, patch

from device_monitoring_prototype.app import create_app
from device_monitoring_prototype.authentication import EmailDeliveryError, send_contact_message
from device_monitoring_prototype.models import Role, db
from device_monitoring_prototype.tests import test_database_integration as base_tests

MESSAGE = {
    "name": "Ana Reyes",
    "email": "ana@example.com",
    "subject": "Question about the agent",
    "message": "Does the Android app work on tablets too?",
}


class HomepageTest(unittest.TestCase):
    register_and_login = base_tests.DatabaseIntegrationTest.register_and_login

    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "homepage-test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "MAIL_SERVER": "smtp.example.com",
            "MAIL_USERNAME": "team@example.com",
            "MAIL_PASSWORD": "not-a-real-password",
            "MAIL_DEFAULT_SENDER": "team@example.com",
            "CONTACT_RECIPIENT": "",
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

    def csrf(self):
        page = self.client.get("/").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

    def post_contact(self, **overrides):
        return self.client.post("/contact", data={**MESSAGE, "csrf_token": self.csrf(), **overrides})

    def test_visitors_see_the_homepage_first(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        for section in ('id="home"', 'id="about"', 'id="system"', 'id="contact"'):
            self.assertIn(section, html)
        for label in (">Home<", ">About<", ">The System<", ">Contact us<"):
            self.assertIn(label, html)
        self.assertIn('href="/login"', html)
        self.assertIn('href="/register"', html)
        self.assertIn("mailto:team@example.com", html)
        self.assertIn("css/home.css", html)
        # Sign-in still lives at /login, and both auth pages link back home.
        for path in ("/login", "/register"):
            with self.subTest(path=path):
                page = self.client.get(path)
                self.assertEqual(page.status_code, 200)
                self.assertIn(b"Back to home", page.data)

    def test_signed_in_users_also_see_it_with_their_shortcuts(self):
        self.register_and_login()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)  # not redirected, even without a device
        html = response.get_data(as_text=True)
        self.assertIn("Open my dashboard", html)
        self.assertIn('href="/device-verification"', html)
        self.assertNotIn('href="/register"', html)
        self.assertIn('value="test@example.com"', html)  # contact form prefilled

    def test_contact_message_is_emailed_to_the_team(self):
        with patch("device_monitoring_prototype.app.send_contact_message") as send:
            response = self.post_contact()
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertIn("sent", response.json["message"])
        send.assert_called_once_with(MESSAGE)

    def test_contact_requires_csrf_and_valid_fields(self):
        with patch("device_monitoring_prototype.app.send_contact_message") as send:
            no_csrf = self.client.post("/contact", data=MESSAGE)
            self.assertIn(no_csrf.status_code, {400, 403})
            for field, value in (
                ("name", ""),
                ("email", "not-an-email"),
                ("subject", ""),
                ("message", "short"),
                ("subject", "Hello\r\nBcc: victim@example.com"),
                ("message", "x" * 4001),
            ):
                with self.subTest(field=field, value=value[:20]):
                    self.assertEqual(self.post_contact(**{field: value}).status_code, 400)
        send.assert_not_called()

    def test_bots_filling_the_hidden_field_are_ignored(self):
        with patch("device_monitoring_prototype.app.send_contact_message") as send:
            response = self.post_contact(website="https://spam.example")
        self.assertEqual(response.status_code, 200)
        send.assert_not_called()

    def test_messages_are_rate_limited_per_session(self):
        with patch("device_monitoring_prototype.app.send_contact_message") as send:
            codes = [self.post_contact().status_code for _ in range(4)]
        self.assertEqual(codes, [200, 200, 200, 429])
        self.assertEqual(send.call_count, 3)

    def test_mail_failures_are_reported_without_details(self):
        failure = EmailDeliveryError("Your message could not be sent right now. Please try again later.")
        with patch("device_monitoring_prototype.app.send_contact_message", side_effect=failure):
            response = self.post_contact()
        self.assertEqual(response.status_code, 503)
        self.assertIn("could not be sent", response.json["error"])

    def test_the_email_goes_to_the_inbox_with_the_visitor_as_reply_to(self):
        smtp = MagicMock()
        smtp.send_message.return_value = {}
        with self.app.app_context(), patch(
            "device_monitoring_prototype.authentication._open_smtp", return_value=smtp
        ):
            send_contact_message(MESSAGE)
            self.app.config["MAIL_SERVER"] = ""
            with self.assertRaises(EmailDeliveryError):
                send_contact_message(MESSAGE)
        sent = smtp.send_message.call_args.args[0]
        self.assertEqual(sent["To"], "team@example.com")
        self.assertEqual(sent["Reply-To"], "Ana Reyes <ana@example.com>")
        self.assertEqual(sent["Subject"], "[DevMonitor contact] Question about the agent")
        self.assertIn("Does the Android app work on tablets too?", sent.get_content())
        smtp.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
