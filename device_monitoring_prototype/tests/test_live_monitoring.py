"""Opt-in live monitoring: consent, heartbeats, Online/Offline, stopping, retention."""

import json
import os
import tempfile
import unittest
import urllib.error
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from werkzeug.security import generate_password_hash

from device_monitoring_prototype import device_agent
from device_monitoring_prototype.app import create_app
from device_monitoring_prototype.models import (
    ActivityLog,
    Device,
    DeviceMetric,
    Log,
    Role,
    User,
    db,
)
from device_monitoring_prototype.services import prune_device_metrics
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
    "ip_addresses": ["192.0.2.20"],
}
HEARTBEAT = {
    "cpu_percent": 37.5,
    "memory_percent": 61.25,
    "memory_used_bytes": 5 * GB,
    "storage_percent": 48.0,
    "storage_used_bytes": 120 * GB,
    "network_rx_bytes": 9_000_000,
    "network_tx_bytes": 4_000_000,
    "network_rx_bytes_per_sec": 2048,
    "network_tx_bytes_per_sec": 512,
}


class LiveMonitoringApiTest(unittest.TestCase):
    register_and_login = base_tests.DatabaseIntegrationTest.register_and_login

    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "live-monitoring-test-secret",
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
    def enroll(self, csrf, *, client=None, monitoring=True, name="Monitored PC"):
        """Link a device through the QR flow; returns the agent's enroll response."""
        client = client or self.client
        qr = client.post("/api/device-registration-tokens", headers={"X-CSRF-Token": csrf})
        self.assertEqual(qr.status_code, 200, qr.get_data(as_text=True))
        token = qr.json["enrollment_url"].rstrip("/").rsplit("/", 1)[-1]
        self.assertEqual(
            client.post(f"/enroll/{token}/verify", data={"csrf_token": csrf}).status_code, 302
        )
        with patch(
            "device_monitoring_prototype.app.build_agent_executable",
            return_value=b"MZtest-" + token.encode(),
        ):
            download = client.post(
                f"/enroll/{token}/agent.exe",
                data={"csrf_token": csrf, "trust_device_agent": "yes"},
            )
        self.assertEqual(download.status_code, 200)
        headers = {"Authorization": f"Bearer {token}"}
        if monitoring:
            headers["X-DevMonitor-Monitoring"] = "supported"
        agent = self.app.test_client().post(
            "/api/device-agent/enroll",
            headers=headers,
            json={"name": name, "device_type": "Desktop", "specifications": SPECIFICATIONS},
        )
        self.assertEqual(agent.status_code, 201, agent.get_data(as_text=True))
        return agent.json

    def agent_post(self, path, token, body=None):
        return self.app.test_client().post(
            path, headers={"Authorization": f"Bearer {token}"}, json=body or {}
        )

    def heartbeat(self, token, **overrides):
        return self.agent_post("/api/device-agent/heartbeat", token, {**HEARTBEAT, **overrides})

    def monitored_device(self):
        """Signed-in owner with one device whose user turned monitoring on."""
        csrf = self.register_and_login()
        enrolled = self.enroll(csrf)
        token = enrolled["monitoring"]["token"]
        enabled = self.agent_post("/api/device-agent/monitoring/enable", token)
        self.assertEqual(enabled.status_code, 200, enabled.get_data(as_text=True))
        self.client.get("/dashboard")
        with self.client.session_transaction() as session:
            csrf = session["_csrf_token"]
        return csrf, enrolled["device_id"], token

    def age(self, device_id, seconds):
        """Pretend the last heartbeat happened ``seconds`` ago."""
        past = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        with self.app.app_context():
            device = db.session.get(Device, device_id)
            device.last_seen_at = past
            for metric in DeviceMetric.query.filter_by(device_id=device_id):
                metric.collected_at = past
            db.session.commit()

    def device(self, device_id):
        with self.app.app_context():
            device = db.session.get(Device, device_id)
            db.session.expunge(device)
            return device

    # -- consent and credential ----------------------------------------------------
    def test_agents_without_monitoring_support_get_no_credential(self):
        csrf = self.register_and_login()
        enrolled = self.enroll(csrf, monitoring=False)
        self.assertNotIn("monitoring", enrolled)
        device = self.device(enrolled["device_id"])
        self.assertIsNone(device.monitoring_token_hash)
        self.assertIsNone(device.monitoring_enabled_at)

    def test_credential_is_inactive_until_the_device_user_consents(self):
        csrf = self.register_and_login()
        enrolled = self.enroll(csrf)
        token = enrolled["monitoring"]["token"]
        self.assertEqual(enrolled["monitoring"]["heartbeat_interval_seconds"], 30)
        device = self.device(enrolled["device_id"])
        self.assertIsNotNone(device.monitoring_token_hash)
        self.assertNotEqual(device.monitoring_token_hash, token)  # only the hash is stored
        self.assertIsNone(device.monitoring_enabled_at)

        refused = self.heartbeat(token)
        self.assertEqual(refused.status_code, 401)
        self.assertEqual(refused.json["monitoring"], "revoked")

        enabled = self.agent_post("/api/device-agent/monitoring/enable", token)
        self.assertEqual(enabled.status_code, 200)
        self.assertEqual(enabled.json["heartbeat_interval_seconds"], 30)
        with self.app.app_context():
            self.assertEqual(
                ActivityLog.query.filter_by(
                    event_type="device.monitoring_enabled", entity_id=enrolled["device_id"]
                ).count(),
                1,
            )
        self.assertEqual(self.heartbeat(token).status_code, 201)

    def test_consent_must_arrive_within_the_activation_window(self):
        csrf = self.register_and_login()
        enrolled = self.enroll(csrf)
        with self.app.app_context():
            device = db.session.get(Device, enrolled["device_id"])
            device.registered_at = datetime.now(timezone.utc) - timedelta(minutes=20)
            db.session.commit()
        late = self.agent_post("/api/device-agent/monitoring/enable", enrolled["monitoring"]["token"])
        self.assertEqual(late.status_code, 401)
        self.assertIsNone(self.device(enrolled["device_id"]).monitoring_token_hash)

    # -- heartbeats ------------------------------------------------------------------
    def test_heartbeats_store_samples_and_feed_the_dashboard(self):
        csrf, device_id, token = self.monitored_device()
        response = self.heartbeat(token)
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        self.assertEqual(response.json["next_heartbeat_seconds"], 30)

        with self.app.app_context():
            sample = DeviceMetric.query.filter_by(device_id=device_id).one()
            self.assertEqual(float(sample.cpu_percent), 37.5)
            self.assertEqual(float(sample.memory_percent), 61.25)
            self.assertEqual(sample.network_rx_bytes_per_sec, 2048)
            self.assertEqual(sample.network_tx_bytes_per_sec, 512)
            device = db.session.get(Device, device_id)
            self.assertEqual(device.status, "online")
            self.assertIsNotNone(device.last_seen_at)

        # A second heartbeat right away is refused; 30 s later it is accepted.
        too_soon = self.heartbeat(token, cpu_percent=80)
        self.assertEqual(too_soon.status_code, 429)
        self.assertEqual(too_soon.headers["Retry-After"], "30")
        self.age(device_id, 30)
        self.assertEqual(self.heartbeat(token, cpu_percent=80).status_code, 201)

        dashboard = self.client.get("/api/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertEqual(dashboard.json["monitored"], 1)
        self.assertEqual(dashboard.json["refresh_seconds"], 30)
        listed = dashboard.json["devices"][0]
        self.assertTrue(listed["monitoring"]["enabled"])
        self.assertEqual(listed["monitoring"]["offlineAfterSeconds"], 90)
        self.assertEqual(listed["live"]["cpuPercent"], 80.0)
        self.assertEqual(listed["live"]["networkRxBytesPerSec"], 2048)

        metrics = self.client.get(f"/api/devices/{device_id}/metrics?minutes=60")
        self.assertEqual(metrics.status_code, 200)
        self.assertEqual([s["cpuPercent"] for s in metrics.json["samples"]], [37.5, 80.0])
        newest = metrics.json["samples"][-1]["collectedAt"]
        incremental = self.client.get(
            f"/api/devices/{device_id}/metrics", query_string={"since": newest}
        )
        self.assertEqual(incremental.json["samples"], [])
        self.assertEqual(
            self.client.get(f"/api/devices/{device_id}/metrics?since=yesterday").status_code, 400
        )

    def test_heartbeats_are_authenticated_and_validated(self):
        _csrf, _device_id, token = self.monitored_device()
        no_header = self.app.test_client().post("/api/device-agent/heartbeat", json=HEARTBEAT)
        self.assertEqual(no_header.status_code, 401)
        self.assertEqual(self.heartbeat("x" * 43).status_code, 401)
        for bad in (
            {"cpu_percent": 150},
            {"cpu_percent": True},
            {"memory_percent": "61"},
            {"network_rx_bytes_per_sec": -1},
            {"network_rx_bytes_per_sec": 1.5},
            {"keystrokes": "nope"},
        ):
            with self.subTest(bad=bad):
                self.assertEqual(self.heartbeat(token, **bad).status_code, 400)
        missing_usage = self.agent_post(
            "/api/device-agent/heartbeat", token, {"storage_percent": 10}
        )
        self.assertEqual(missing_usage.status_code, 400)

    # -- Online / Offline --------------------------------------------------------------
    def test_monitored_devices_go_offline_after_90_seconds_and_recover(self):
        _csrf, device_id, token = self.monitored_device()
        self.assertEqual(self.heartbeat(token).status_code, 201)
        self.age(device_id, 60)
        self.assertEqual(self.client.get("/api/dashboard").json["devices"][0]["status"], "Online")

        self.age(device_id, 91)
        self.assertEqual(self.client.get("/api/dashboard").json["devices"][0]["status"], "Offline")
        with self.app.app_context():
            offline = ActivityLog.query.filter_by(
                event_type="device.status_offline", entity_id=device_id
            ).one()
            self.assertIn("90 seconds", offline.details["reason"])

        self.assertEqual(self.heartbeat(token).status_code, 201)
        self.assertEqual(self.client.get("/api/dashboard").json["devices"][0]["status"], "Online")
        with self.app.app_context():
            self.assertEqual(
                Log.query.filter_by(
                    device_id=device_id, event="Device status changed to online"
                ).count(),
                1,
            )

    def test_unmonitored_devices_keep_the_five_minute_rule(self):
        csrf = self.register_and_login()
        device_id = self.enroll(csrf, monitoring=False)["device_id"]
        self.age(device_id, 120)
        self.assertEqual(self.client.get("/api/dashboard").json["devices"][0]["status"], "Online")
        self.age(device_id, 301)
        self.assertEqual(self.client.get("/api/dashboard").json["devices"][0]["status"], "Offline")

    # -- stopping --------------------------------------------------------------------
    def test_owner_can_stop_monitoring_and_the_agent_is_told(self):
        csrf, device_id, token = self.monitored_device()
        self.assertEqual(self.heartbeat(token).status_code, 201)
        without_csrf = self.client.post(f"/api/devices/{device_id}/monitoring/stop")
        self.assertEqual(without_csrf.status_code, 400)

        stopped = self.client.post(
            f"/api/devices/{device_id}/monitoring/stop", headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(stopped.status_code, 200, stopped.get_data(as_text=True))
        self.assertFalse(stopped.json["monitoring"]["enabled"])
        self.assertEqual(stopped.json["status"], "Offline")
        refused = self.heartbeat(token)
        self.assertEqual(refused.status_code, 401)
        self.assertEqual(refused.json["monitoring"], "revoked")
        with self.app.app_context():
            entry = ActivityLog.query.filter_by(
                event_type="device.monitoring_stopped", entity_id=device_id
            ).one()
            self.assertEqual(entry.details["reason"], "stopped_by_owner")
        page = self.client.get(f"/devices/{device_id}/specifications")
        self.assertIn(b"Live monitoring is off for this device.", page.data)

    def test_device_can_stop_monitoring_itself(self):
        _csrf, device_id, token = self.monitored_device()
        stopped = self.agent_post("/api/device-agent/monitoring/stop", token)
        self.assertEqual(stopped.status_code, 200)
        self.assertEqual(self.heartbeat(token).status_code, 401)
        with self.app.app_context():
            entry = ActivityLog.query.filter_by(
                event_type="device.monitoring_stopped", entity_id=device_id
            ).one()
            self.assertEqual(entry.details["reason"], "stopped_on_device")
        # Unknown credentials get the same answer, revealing nothing.
        self.assertEqual(self.agent_post("/api/device-agent/monitoring/stop", "y" * 43).status_code, 200)

    def test_archiving_the_device_or_deactivating_the_owner_revokes_monitoring(self):
        csrf, device_id, token = self.monitored_device()
        archived = self.client.post(
            f"/api/devices/{device_id}/archive", headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(archived.status_code, 204, archived.get_data(as_text=True))
        self.assertEqual(self.heartbeat(token).status_code, 401)
        self.assertIsNone(self.device(device_id).monitoring_token_hash)

    def test_inactive_owner_heartbeats_are_refused(self):
        _csrf, device_id, token = self.monitored_device()
        with self.app.app_context():
            User.query.filter_by(username="testuser").one().status = "inactive"
            db.session.commit()
        self.assertEqual(self.heartbeat(token).status_code, 401)
        self.assertIsNone(self.device(device_id).monitoring_token_hash)

    # -- access control -----------------------------------------------------------------
    def test_other_users_cannot_read_or_stop_monitoring_but_admins_can(self):
        _csrf, device_id, token = self.monitored_device()
        self.assertEqual(self.heartbeat(token).status_code, 201)

        other = self.app.test_client()
        other_csrf = self.register_and_login(
            email="other@example.com", username="otheruser", full_name="Other User", client=other
        )
        self.enroll(other_csrf, client=other, name="Other PC")
        self.assertEqual(other.get(f"/api/devices/{device_id}/metrics").status_code, 404)
        self.assertEqual(
            other.post(
                f"/api/devices/{device_id}/monitoring/stop", headers={"X-CSRF-Token": other_csrf}
            ).status_code,
            404,
        )
        self.assertNotIn(
            device_id, [device["id"] for device in other.get("/api/dashboard").json["devices"]]
        )
        self.assertTrue(self.device(device_id).monitoring_active)

        with self.app.app_context():
            admin = User(
                username="monitoradmin",
                email="monitoradmin@example.com",
                full_name="Monitor Admin",
                password_hash=generate_password_hash("monitor-admin-password"),
                status="active",
                email_verified=True,
            )
            admin.roles.append(Role.query.filter_by(name="Administrator").one())
            db.session.add(admin)
            db.session.commit()
        admin_client = self.app.test_client()
        admin_client.get("/login")
        with admin_client.session_transaction() as session:
            admin_csrf = session["_csrf_token"]
        login = base_tests.complete_admin_login(
            admin_client,
            {
                "csrf_token": admin_csrf,
                "username": "monitoradmin",
                "password": "monitor-admin-password",
            },
        )
        self.assertEqual(login.status_code, 302)
        admin_client.get("/dashboard")  # login clears the session; this issues a new CSRF token
        with admin_client.session_transaction() as session:
            admin_csrf = session["_csrf_token"]
        self.assertEqual(admin_client.get(f"/api/devices/{device_id}/metrics").status_code, 200)
        stopped = admin_client.post(
            f"/api/devices/{device_id}/monitoring/stop", headers={"X-CSRF-Token": admin_csrf}
        )
        self.assertEqual(stopped.status_code, 200)
        with self.app.app_context():
            entry = ActivityLog.query.filter_by(
                event_type="device.monitoring_stopped", entity_id=device_id
            ).one()
            self.assertEqual(entry.details["reason"], "stopped_by_administrator")

    # -- retention and pages ------------------------------------------------------------
    def test_samples_older_than_seven_days_are_pruned(self):
        _csrf, device_id, _token = self.monitored_device()
        now = datetime.now(timezone.utc)
        with self.app.app_context():
            for age in (timedelta(days=8), timedelta(days=6, hours=23)):
                db.session.add(DeviceMetric(device_id=device_id, cpu_percent=5, collected_at=now - age))
            db.session.commit()
            self.assertEqual(prune_device_metrics(device_id, now=now), 1)
            db.session.commit()
            self.assertEqual(DeviceMetric.query.filter_by(device_id=device_id).count(), 1)

    def test_device_page_shows_the_live_monitoring_card(self):
        _csrf, device_id, _token = self.monitored_device()
        page = self.client.get(f"/devices/{device_id}/specifications")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="liveMonitoringPanel"', page.data)
        self.assertIn(b"Stop live monitoring", page.data)
        dashboard = self.client.get("/dashboard")
        self.assertIn(b"Live Usage", dashboard.data)


Counters = namedtuple("Counters", "bytes_recv bytes_sent")


class LiveMonitoringAgentTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        patcher = patch.object(device_agent, "monitoring_directory", return_value=self.directory)
        patcher.start()
        self.addCleanup(patcher.stop)

    def sampler_with(self, first, second):
        clock = iter([100.0, 130.0]).__next__
        patches = [
            patch.object(device_agent.psutil, "net_io_counters", side_effect=[first, second]),
            patch.object(device_agent.psutil, "cpu_percent", return_value=12.5),
            patch.object(
                device_agent.psutil, "virtual_memory",
                return_value=SimpleNamespace(percent=50.0, used=4 * GB),
            ),
            patch.object(
                device_agent.psutil, "disk_partitions",
                return_value=[
                    SimpleNamespace(mountpoint="C:\\", opts="rw,fixed", fstype="NTFS"),
                    SimpleNamespace(mountpoint="D:\\", opts="cdrom", fstype=""),
                ],
            ),
            patch.object(
                device_agent.psutil, "disk_usage",
                return_value=SimpleNamespace(used=60 * GB, total=100 * GB),
            ),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        return device_agent.LiveMetricSampler(clock=clock).sample()

    def test_network_speed_is_the_counter_difference_per_second(self):
        sample = self.sampler_with(
            {"Ethernet": Counters(1000, 500), "Loopback Pseudo-Interface 1": Counters(10**9, 10**9)},
            {
                "Ethernet": Counters(1000 + 30 * 2048, 500 + 30 * 512),
                "Loopback Pseudo-Interface 1": Counters(2 * 10**9, 2 * 10**9),
            },
        )
        self.assertEqual(sample["network_rx_bytes_per_sec"], 2048)
        self.assertEqual(sample["network_tx_bytes_per_sec"], 512)
        self.assertEqual(sample["network_rx_bytes"], 1000 + 30 * 2048)  # loopback excluded
        self.assertEqual(sample["cpu_percent"], 12.5)
        self.assertEqual(sample["memory_percent"], 50.0)
        self.assertEqual(sample["storage_percent"], 60.0)  # the CD drive is skipped

    def test_counter_reset_reports_no_speed_for_that_interval(self):
        sample = self.sampler_with(
            {"Ethernet": Counters(50_000, 50_000)}, {"Ethernet": Counters(100, 100)}
        )
        self.assertIsNone(sample["network_rx_bytes_per_sec"])
        self.assertIsNone(sample["network_tx_bytes_per_sec"])

    def test_heartbeat_results(self):
        config = {"server": "https://devmonitor.example", "token": "t" * 43}
        with patch.object(device_agent, "_post_agent_json", return_value=(201, {})):
            self.assertEqual(device_agent.send_heartbeat(config, {}), "ok")
        with patch.object(
            device_agent, "_post_agent_json", return_value=(401, {"monitoring": "revoked"})
        ):
            self.assertEqual(device_agent.send_heartbeat(config, {}), "revoked")
        with patch.object(device_agent, "_post_agent_json", return_value=(429, {})):
            self.assertEqual(device_agent.send_heartbeat(config, {}), "retry")
        with patch.object(
            device_agent, "_post_agent_json", side_effect=urllib.error.URLError("offline")
        ):
            self.assertEqual(device_agent.send_heartbeat(config, {}), "retry")

    def test_monitor_sends_every_30_seconds_and_removes_itself_when_revoked(self):
        sleep = MagicMock()
        config = {"server": "https://devmonitor.example", "device_id": 7, "token": "t" * 43}
        sampler = MagicMock()
        sampler.return_value.sample.return_value = {"cpu_percent": 1}
        with (
            patch.object(device_agent, "load_monitoring_config", return_value=config),
            patch.object(device_agent, "_acquire_single_instance", return_value=True),
            patch.object(device_agent, "_hide_monitor_console"),
            patch.object(device_agent, "LiveMetricSampler", sampler),
            patch.object(device_agent, "send_heartbeat", side_effect=["ok", "retry", "revoked"]) as send,
            patch.object(device_agent, "remove_local_monitoring") as remove,
            patch("builtins.print"),
        ):
            self.assertEqual(device_agent.run_monitor(sleep=sleep), 0)
        self.assertEqual(send.call_count, 3)
        sleep.assert_called_with(30)
        remove.assert_called_once()
        self.assertFalse((self.directory / device_agent.MONITOR_PID_NAME).exists())

    def test_monitor_does_nothing_without_consent(self):
        with (
            patch.object(device_agent, "load_monitoring_config", return_value=None),
            patch.object(device_agent, "send_heartbeat") as send,
            patch("builtins.print"),
        ):
            self.assertEqual(device_agent.run_monitor(sleep=MagicMock(), max_beats=1), 2)
        send.assert_not_called()

    def offer(self, args, answer=""):
        monitoring = {"token": "m" * 43}
        with (
            patch.object(device_agent, "monitoring_supported", return_value=True),
            patch.object(
                device_agent, "SUBMISSION_URL", "https://devmonitor.example/api/device-agent/enroll"
            ),
            patch.object(device_agent, "input", return_value=answer, create=True),
            patch.object(device_agent, "enable_live_monitoring", return_value=True) as enable,
            patch("builtins.print"),
        ):
            device_agent.offer_live_monitoring(args, monitoring, 7, use_window=False)
        return enable

    def test_monitoring_is_only_enabled_on_an_explicit_yes(self):
        interactive = SimpleNamespace(yes=False, enable_monitoring=False)
        self.offer(interactive, answer="").assert_not_called()
        self.offer(interactive, answer="no").assert_not_called()
        self.offer(interactive, answer="yes").assert_called_once_with(
            "https://devmonitor.example", 7, "m" * 43
        )
        self.offer(SimpleNamespace(yes=True, enable_monitoring=False)).assert_not_called()
        self.offer(SimpleNamespace(yes=True, enable_monitoring=True)).assert_called_once()

    def test_enable_sets_up_startup_only_after_the_server_confirms(self):
        server, token = "https://devmonitor.example", "m" * 43
        command = (["agent.exe", "--monitor"], '"agent.exe" --monitor')
        with (
            patch.object(device_agent, "_post_agent_json", return_value=(401, {"error": "expired"})),
            patch.object(device_agent, "_register_autostart") as autostart,
            patch("builtins.print"),
        ):
            self.assertFalse(device_agent.enable_live_monitoring(server, 7, token))
        autostart.assert_not_called()

        with (
            patch.object(device_agent, "_post_agent_json", return_value=(200, {"monitoring": "enabled"})),
            patch.object(device_agent, "_monitor_command", return_value=command),
            patch.object(device_agent, "save_monitoring_config") as save,
            patch.object(device_agent, "_register_autostart") as autostart,
            patch.object(device_agent, "_launch_monitor") as launch,
            patch("builtins.print"),
        ):
            self.assertTrue(device_agent.enable_live_monitoring(server, 7, token))
        save.assert_called_once_with(server, 7, token)
        autostart.assert_called_once_with(command[1])
        launch.assert_called_once_with(command[0])

    def test_monitor_starts_without_a_window_and_is_named_for_task_manager(self):
        with patch("subprocess.Popen") as popen:
            device_agent._launch_monitor(["agent.exe", "--monitor"])
        flags = popen.call_args.kwargs["creationflags"]
        if os.name == "nt":
            import subprocess

            self.assertTrue(flags & subprocess.CREATE_NO_WINDOW)
            self.assertFalse(flags & subprocess.CREATE_NEW_CONSOLE)
        self.assertNotIn("startupinfo", popen.call_args.kwargs)
        # Task Manager shows the process and the startup entry under the same name.
        self.assertEqual(
            device_agent.MONITOR_EXECUTABLE_NAME, device_agent.MONITOR_STARTUP_NAME + ".exe"
        )
        consent = device_agent.CONSENT_TEXT.format(server="devmonitor.example")
        self.assertIn("without a window", consent)
        self.assertIn("Task Manager", consent)
        self.assertIn(device_agent.MONITOR_STARTUP_NAME, consent)

    def test_failed_local_setup_turns_monitoring_back_off(self):
        calls = []

        def post(url, token, payload, timeout=15):
            calls.append(url)
            return 200, {"monitoring": "enabled"}

        with (
            patch.object(device_agent, "_post_agent_json", side_effect=post),
            patch.object(device_agent, "_monitor_command", side_effect=OSError("disk full")),
            patch.object(device_agent, "remove_local_monitoring") as remove,
            patch("builtins.print"),
        ):
            self.assertFalse(
                device_agent.enable_live_monitoring("https://devmonitor.example", 7, "m" * 43)
            )
        self.assertEqual(calls[-1], "https://devmonitor.example" + device_agent.MONITORING_STOP_PATH)
        remove.assert_called_once()

    def test_credential_is_stored_protected_and_read_back(self):
        with (
            patch.object(device_agent, "_protect_secret", side_effect=lambda value: "enc:" + value[::-1]),
            patch.object(device_agent, "_unprotect_secret", side_effect=lambda value: value[4:][::-1]),
        ):
            device_agent.save_monitoring_config("https://devmonitor.example", 7, "secret-token")
            stored = json.loads((self.directory / device_agent.MONITOR_CONFIG_NAME).read_text())
            self.assertNotIn("secret-token", json.dumps(stored))
            loaded = device_agent.load_monitoring_config()
        self.assertEqual(loaded["token"], "secret-token")
        self.assertEqual(loaded["server"], "https://devmonitor.example")

    def test_stop_monitoring_tells_the_server_and_cleans_up(self):
        config = {"server": "https://devmonitor.example", "device_id": 7, "token": "t" * 43}
        with (
            patch.object(device_agent, "load_monitoring_config", return_value=config),
            patch.object(device_agent, "_post_agent_json", return_value=(200, {})) as post,
            patch.object(device_agent, "_stop_running_monitor") as stop_process,
            patch.object(device_agent, "remove_local_monitoring") as remove,
            patch("builtins.print"),
        ):
            self.assertEqual(device_agent.stop_live_monitoring(), 0)
        self.assertEqual(
            post.call_args.args[0], "https://devmonitor.example" + device_agent.MONITORING_STOP_PATH
        )
        stop_process.assert_called_once()
        remove.assert_called_once()

    def test_registration_offers_monitoring_and_declining_sends_nothing_more(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 201
        response.read.return_value = json.dumps(
            {"device_id": 25, "monitoring": {"token": "m" * 43}}
        ).encode()
        requests = []

        def capture(request, timeout):
            requests.append(request)
            return response

        with (
            patch.object(device_agent, "configure_logging", return_value="agent.log"),
            patch.object(device_agent, "collect_specifications", return_value=SPECIFICATIONS),
            patch.object(device_agent, "collect_health_report", return_value={}),
            patch.object(device_agent, "show_registration_success"),
            patch.object(device_agent, "monitoring_supported", return_value=True),
            patch.object(device_agent.platform, "node", return_value="endpoint-host"),
            patch.object(device_agent, "input", side_effect=["", "Laptop", "yes", ""], create=True),
            patch.object(device_agent, "REGISTRATION_TOKEN", "a" * 43),
            patch.object(
                device_agent, "SUBMISSION_URL", "https://devmonitor.example/api/device-agent/enroll"
            ),
            patch.object(device_agent.urllib.request, "urlopen", side_effect=capture),
            patch.object(device_agent, "enable_live_monitoring") as enable,
            patch.object(device_agent.sys, "stdout"),
        ):
            self.assertEqual(device_agent.main(["--console"]), 0)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].get_header("X-devmonitor-monitoring"), "supported")
        enable.assert_not_called()


if __name__ == "__main__":
    unittest.main()
