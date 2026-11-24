"""Device registration rules: MAC duplicate prevention and the per-user device limit."""

import unittest

from device_monitoring_prototype.app import create_app
from device_monitoring_prototype.models import (
    ActivityLog,
    Device,
    DeviceRegistrationToken,
    Role,
    User,
    db,
)
from device_monitoring_prototype.services import (
    MAX_DEVICES_PER_USER,
    DeviceLimitError,
    ValidationError,
    archive_device,
    hash_password,
    issue_direct_agent_download_token,
    normalize_mac_address,
    restore_device,
    soft_delete_device,
)
from device_monitoring_prototype.tests import test_database_integration as base_tests

GB = 1024**3
SPECIFICATIONS = {
    "cpu_name": "Test CPU",
    "cpu_cores": 4,
    "ram_capacity_bytes": 8 * GB,
    "ram_usage_bytes": 3 * GB,
    "storage_devices": [{"name": "C:", "total_bytes": 256, "available_bytes": 128}],
    "storage_total_bytes": 256,
    "storage_available_bytes": 128,
    "gpu_information": ["Test GPU"],
    "motherboard_brand": "Test Board",
    "operating_system_name": "Windows 11",
    "operating_system_version": "10.0.26100",
    "network_adapters": ["Ethernet"],
    "ip_addresses": ["192.0.2.30"],
}


class DeviceRegistrationRulesTest(unittest.TestCase):
    register_and_login = base_tests.DatabaseIntegrationTest.register_and_login

    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "device-rules-test-secret",
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

    # -- helpers -------------------------------------------------------------
    def make_user(self, username, *, admin=False):
        with self.app.app_context():
            user = User(
                username=username,
                email=f"{username}@example.test",
                display_name=username.title(),
                password_hash=hash_password("Passw0rd!"),
                status="active",
                email_verified=True,
            )
            user.roles.append(
                Role.query.filter_by(name="Administrator" if admin else "User").one()
            )
            db.session.add(user)
            db.session.commit()
            return user.id

    def issue_token(self, user_id):
        with self.app.test_request_context():
            return issue_direct_agent_download_token(db.session.get(User, user_id))[0]

    def enroll(self, token, mac_address="3C:22:FB:AA:BB:CC", name="Rules PC"):
        specifications = dict(SPECIFICATIONS)
        if mac_address is not None:
            specifications["mac_address"] = mac_address
        return self.app.test_client().post(
            "/api/device-agent/enroll",
            headers={"Authorization": f"Bearer {token}"},
            json={"name": name, "device_type": "Desktop", "specifications": specifications},
        )

    def enroll_for(self, user_id, mac_address="3C:22:FB:AA:BB:CC", name="Rules PC"):
        return self.enroll(self.issue_token(user_id), mac_address, name)

    def add_devices(self, user_id, count, *, lifecycle_status="active"):
        with self.app.app_context():
            for index in range(count):
                db.session.add(Device(
                    asset_tag=f"DM-RULES-{user_id}-{lifecycle_status}-{index}",
                    device_name=f"Existing {index}",
                    hostname=f"existing-{index}",
                    device_type="Desktop",
                    owner_user_id=user_id,
                    is_verified=True,
                    lifecycle_status=lifecycle_status,
                ))
            db.session.commit()

    # -- MAC duplicate prevention ---------------------------------------------
    def test_mac_addresses_are_normalized(self):
        self.assertEqual(normalize_mac_address("3c-22-fb-aa-bb-cc"), "3C:22:FB:AA:BB:CC")
        self.assertEqual(normalize_mac_address(" 3c:22:fb:aa:bb:cc "), "3C:22:FB:AA:BB:CC")
        self.assertIsNone(normalize_mac_address(""))
        self.assertIsNone(normalize_mac_address(None))
        with self.assertRaises(ValidationError):
            normalize_mac_address("3C:22:FB:AA:BB")

    def test_same_user_cannot_register_the_same_device_twice(self):
        owner = self.make_user("rulesowner")
        self.assertEqual(self.enroll_for(owner).status_code, 201)

        token = self.issue_token(owner)
        duplicate = self.enroll(token, mac_address="3c-22-fb-aa-bb-cc")
        self.assertEqual(duplicate.status_code, 409)
        self.assertIn("already registered to your account", duplicate.json["error"])
        with self.app.app_context():
            self.assertEqual(Device.query.count(), 1)
            registration = DeviceRegistrationToken.query.order_by(
                DeviceRegistrationToken.id.desc()
            ).first()
            # The token is not consumed, and the reason is recorded for the website.
            self.assertIsNone(registration.used_at)
            self.assertIn("already registered", registration.rejection_reason)
            self.assertEqual(
                ActivityLog.query.filter_by(event_type="device.registration_rejected").count(), 1
            )

    def test_another_account_cannot_register_a_registered_device(self):
        first = self.make_user("firstowner")
        second = self.make_user("secondowner")
        self.assertEqual(self.enroll_for(first).status_code, 201)

        duplicate = self.enroll_for(second)
        self.assertEqual(duplicate.status_code, 409)
        self.assertIn("already registered to another account", duplicate.json["error"])
        with self.app.app_context():
            self.assertEqual(Device.query.filter_by(owner_user_id=second).count(), 0)

    def test_archived_device_blocks_other_accounts_but_not_its_owner(self):
        owner = self.make_user("archiveowner")
        other = self.make_user("archiveother")
        device_id = self.enroll_for(owner).json["device_id"]
        with self.app.test_request_context():
            archive_device(db.session.get(Device, device_id))

        self.assertEqual(self.enroll_for(other).status_code, 409)
        self.assertEqual(self.enroll_for(owner, name="Re-registered PC").status_code, 201)
        # Restoring the archived copy would now duplicate the active one.
        with self.app.test_request_context():
            with self.assertRaises(ValidationError):
                restore_device(db.session.get(Device, device_id))

    def test_deleted_device_releases_its_mac_address(self):
        first = self.make_user("deletedowner")
        second = self.make_user("newowner")
        device_id = self.enroll_for(first).json["device_id"]
        with self.app.test_request_context():
            soft_delete_device(db.session.get(Device, device_id))
        self.assertEqual(self.enroll_for(second).status_code, 201)

    def test_devices_without_a_real_mac_are_not_deduplicated(self):
        first = self.make_user("phoneowner")
        second = self.make_user("tabletowner")
        # Android 10+ sends no MAC; iOS reports the same placeholder for every device.
        self.assertEqual(self.enroll_for(first, mac_address=None).status_code, 201)
        self.assertEqual(self.enroll_for(second, mac_address=None).status_code, 201)
        self.assertEqual(self.enroll_for(first, mac_address="02:00:00:00:00:00").status_code, 201)
        self.assertEqual(self.enroll_for(second, mac_address="02:00:00:00:00:00").status_code, 201)

    def test_website_shows_why_the_device_was_not_registered(self):
        csrf = self.register_and_login()
        other = self.make_user("websiteother")
        self.assertEqual(self.enroll_for(other).status_code, 201)
        with self.app.app_context():
            user_id = User.query.filter_by(username="testuser").one().id

        self.assertEqual(self.enroll_for(user_id).status_code, 409)
        status = self.client.get("/api/device-verification-status").json
        self.assertIn("already registered", status["registration_rejection"]["message"])

        # A later successful registration clears the notice.
        self.assertEqual(self.enroll_for(user_id, mac_address="3C:22:FB:00:00:01").status_code, 201)
        self.assertIsNone(
            self.client.get("/api/device-verification-status").json["registration_rejection"]
        )
        self.assertTrue(csrf)

    # -- device limit -----------------------------------------------------------
    def test_standard_user_can_register_at_most_four_devices(self):
        owner = self.make_user("limitowner")
        tokens = [self.issue_token(owner) for _ in range(MAX_DEVICES_PER_USER + 1)]
        for index, token in enumerate(tokens[:MAX_DEVICES_PER_USER]):
            response = self.enroll(token, f"3C:22:FB:00:00:0{index}", name=f"Device {index}")
            self.assertEqual(response.status_code, 201, response.get_data(as_text=True))

        refused = self.enroll(tokens[-1], "3C:22:FB:00:00:09", name="Fifth device")
        self.assertEqual(refused.status_code, 409)
        self.assertIn(f"up to {MAX_DEVICES_PER_USER} devices", refused.json["error"])
        with self.app.app_context():
            self.assertEqual(Device.query.filter_by(owner_user_id=owner).count(), 4)
        # No new download or app link is issued while the account is full.
        with self.app.test_request_context():
            with self.assertRaises(DeviceLimitError):
                issue_direct_agent_download_token(db.session.get(User, owner))

    def test_archived_devices_do_not_count_toward_the_limit(self):
        owner = self.make_user("archivelimit")
        self.add_devices(owner, MAX_DEVICES_PER_USER - 1)
        self.add_devices(owner, 3, lifecycle_status="archived")
        self.assertEqual(self.enroll_for(owner).status_code, 201)

        # The account is full again, so an archived device cannot be restored.
        with self.app.test_request_context():
            archived = Device.query.filter_by(
                owner_user_id=owner, lifecycle_status="archived"
            ).first()
            with self.assertRaises(DeviceLimitError):
                restore_device(archived)

    def test_manual_device_creation_respects_the_limit(self):
        csrf = self.register_and_login()
        with self.app.app_context():
            user_id = User.query.filter_by(username="testuser").one().id
        self.add_devices(user_id, MAX_DEVICES_PER_USER)
        self.client.get("/dashboard")
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        response = self.client.post(
            "/api/devices",
            headers={"X-CSRF-Token": csrf},
            json={"name": "Manual PC", "type": "Desktop", "os": "Windows 11"},
        )
        self.assertEqual(response.status_code, 409)
        self.assertIn("up to 4 devices", response.json["error"])

    def test_administrators_are_exempt_from_the_limit(self):
        from device_monitoring_prototype.services import ensure_device_capacity

        admin = self.make_user("limitadmin", admin=True)
        self.add_devices(admin, MAX_DEVICES_PER_USER + 1)
        with self.app.app_context():
            ensure_device_capacity(db.session.get(User, admin))


if __name__ == "__main__":
    unittest.main()
