"""Tests for the Linux/macOS agent, Linux packages, app links and the downloads hub."""

import io
import json
import os
import plistlib
import re
import tarfile
import tempfile
import types
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
import urllib.error
import urllib.parse
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from device_monitoring_prototype import device_agent_unix as agent
from device_monitoring_prototype.app import create_app
from device_monitoring_prototype.linux_package import (
    LinuxPackageError,
    build_deb,
    build_portable_archive,
)
from device_monitoring_prototype.models import Device, Role, db
from device_monitoring_prototype.services import validate_detected_specifications
from device_monitoring_prototype.tests import test_database_integration as base_tests

TOKEN = "T" * 43
GIB = 1024 ** 3


def parse_ar(data):
    """Return [(name, bytes)] for a Unix ar archive (the .deb container)."""
    assert data[:8] == b"!<arch>\n", "not an ar archive"
    members, offset = [], 8
    while offset < len(data):
        header = data[offset:offset + 60]
        assert header[58:60] == b"`\n", "bad ar member header"
        name = header[:16].decode("ascii").strip()
        size = int(header[48:58].decode("ascii").strip())
        body = data[offset + 60:offset + 60 + size]
        members.append((name, body))
        offset += 60 + size + (size % 2)
    return members


def load_agent_source(source_bytes):
    module = types.ModuleType("packaged_devmonitor_agent")
    exec(compile(source_bytes, "devmonitor-agent", "exec"), module.__dict__)
    return module


def fake_statvfs(sizes):
    def statvfs(mountpoint):
        if mountpoint not in sizes:
            raise OSError("not mounted")
        total, free = sizes[mountpoint]
        return SimpleNamespace(f_blocks=total // 4096, f_bavail=free // 4096, f_frsize=4096)
    return statvfs


def make_linux_root(directory):
    root = Path(directory)
    files = {
        "proc/cpuinfo": (
            "processor\t: 0\nmodel name\t: Intel(R) Core(TM) i5-1135G7 @ 2.40GHz\n\n"
            "processor\t: 1\nmodel name\t: Intel(R) Core(TM) i5-1135G7 @ 2.40GHz\n"
        ),
        "proc/meminfo": "MemTotal:       16384000 kB\nMemFree:  1000 kB\nMemAvailable:   8192000 kB\n",
        "proc/mounts": (
            "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n"
            "/dev/nvme0n1p1 /boot/efi vfat rw 0 0\n"
            "tmpfs /run tmpfs rw 0 0\n"
            "/dev/loop3 /snap/core/1 squashfs ro 0 0\n"
            "/dev/nvme0n1p2 /var/snap ext4 rw 0 0\n"
        ),
        "proc/sys/kernel/osrelease": "6.8.0-45-generic\n",
        "etc/os-release": 'NAME="Ubuntu"\nVERSION="24.04.1 LTS (Noble Numbat)"\nVERSION_ID="24.04"\n',
        "sys/class/dmi/id/board_vendor": "LENOVO\n",
        "sys/class/dmi/id/board_name": "20XWCTO1WW\n",
        "sys/class/dmi/id/chassis_type": "10\n",
        "sys/class/net/lo/address": "00:00:00:00:00:00\n",
        "sys/class/net/wlp0s20f3/address": "a4:c3:f0:12:34:56\n",
        "sys/class/net/docker0/address": "02:42:ac:11:00:01\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (root / "sys/class/net/wlp0s20f3/device").mkdir()
    return root


def fake_linux_run(command, timeout=8):
    if command[0] == "lspci":
        return (
            "00:02.0 VGA compatible controller: Intel Corporation TigerLake-LP GT2 [Iris Xe Graphics] (rev 01)\n"
            "00:14.3 Network controller: Intel Corporation Wi-Fi 6 AX201\n"
        )
    if command[:2] == ["ip", "-j"]:
        return json.dumps([
            {"ifname": "lo", "addr_info": [{"local": "127.0.0.1"}]},
            {"ifname": "wlp0s20f3", "addr_info": [
                {"local": "192.168.1.42"}, {"local": "fe80::1"}, {"local": "2001:db8::42"}
            ]},
        ])
    return ""


MAC_OUTPUTS = {
    ("sysctl", "-n", "machdep.cpu.brand_string"): "Apple M2\n",
    ("sysctl", "-n", "hw.ncpu"): "8\n",
    ("sysctl", "-n", "hw.memsize"): str(16 * GIB) + "\n",
    ("vm_stat",): (
        "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
        "Pages free:                               12345.\n"
        "Pages active:                            300000.\n"
        "Pages wired down:                        100000.\n"
        "Pages occupied by compressor:             50000.\n"
    ),
    ("system_profiler", "-json", "SPHardwareDataType"): json.dumps(
        {"SPHardwareDataType": [{"machine_name": "MacBook Air", "machine_model": "Mac14,2", "chip_type": "Apple M2"}]}
    ),
    ("system_profiler", "-json", "SPDisplaysDataType"): json.dumps(
        {"SPDisplaysDataType": [{"sppci_model": "Apple M2"}]}
    ),
    ("sw_vers", "-productName"): "macOS\n",
    ("sw_vers", "-productVersion"): "14.5\n",
    ("sw_vers", "-buildVersion"): "23F79\n",
    ("ifconfig",): (
        "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
        "\tinet 127.0.0.1 netmask 0xff000000\n"
        "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
        "\tether 3c:22:fb:aa:bb:cc\n"
        "\tinet6 fe80::1c%en0 prefixlen 64 secured scopeid 0xb\n"
        "\tinet 10.0.0.25 netmask 0xffffff00 broadcast 10.0.0.255\n"
        "utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n"
        "\tinet6 fe80::2%utun0 prefixlen 64 scopeid 0xc\n"
    ),
}


def fake_mac_run(command, timeout=8):
    return MAC_OUTPUTS.get(tuple(command), "")


def make_apk():
    """Structurally valid APK fixture: manifest, dex and a v2 signing block marker."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary-manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
        archive.writestr("resources.arsc", b"\x02\x00\x0c\x00")
    data = buffer.getvalue()
    # A real v2 signature block sits just before the ZIP central directory.
    return data + b"\x00" * 16 + b"APK Sig Block 42"


def make_dmg():
    """UDIF disk image fixture: any payload followed by a 512-byte 'koly' trailer."""
    return b"\x00" * 2048 + b"koly" + b"\x00\x00\x00\x04" + b"\x00" * 504


def make_ipa(signed=True, profile="ad-hoc"):
    now = datetime.now(timezone.utc)
    info = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.devmonitor.agent",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "1",
            "CFBundleDisplayName": "DevMonitor Agent",
        },
        fmt=plistlib.FMT_BINARY,
    )
    provisioning = {
        "Name": "DevMonitor fixture",
        "ExpirationDate": now + timedelta(days=200),
        "Entitlements": {"get-task-allow": False},
    }
    if profile == "ad-hoc":
        provisioning["ProvisionedDevices"] = ["00008110-000A1B2C3D4E5F60"]
    elif profile == "development":
        provisioning["ProvisionedDevices"] = ["00008110-000A1B2C3D4E5F60"]
        provisioning["Entitlements"]["get-task-allow"] = True
    elif profile == "expired":
        provisioning["ProvisionedDevices"] = ["00008110-000A1B2C3D4E5F60"]
        provisioning["ExpirationDate"] = now - timedelta(days=1)
    # A .mobileprovision wraps an XML plist in a CMS signature envelope.
    envelope = b"0\x82\x1d\x9a\x06\t*\x86H" + plistlib.dumps(provisioning) + b"\xa0\x82\x0c\x00signature"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        app_dir = "Payload/DevMonitorAgent.app/"
        archive.writestr(app_dir + "Info.plist", info)
        archive.writestr(app_dir + "DevMonitorAgent", b"\xcf\xfa\xed\xfe arm64 binary")
        if signed:
            archive.writestr(app_dir + "embedded.mobileprovision", envelope)
            archive.writestr(app_dir + "_CodeSignature/CodeResources", plistlib.dumps({"files": {}}))
    return buffer.getvalue()


class UnixAgentUnitTest(unittest.TestCase):
    def test_linux_collector_reports_valid_specifications(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = agent.LinuxCollector(
                root=make_linux_root(directory),
                run=fake_linux_run,
                statvfs=fake_statvfs({"/": (500 * GIB, 200 * GIB), "/boot/efi": (GIB, GIB // 2)}),
            )
            specs = collector.collect()
            self.assertEqual(collector.device_type(), "Laptop")
        self.assertEqual(specs["cpu_name"], "Intel(R) Core(TM) i5-1135G7 @ 2.40GHz")
        self.assertEqual(specs["cpu_cores"], 2)
        self.assertEqual(specs["ram_capacity_bytes"], 16384000 * 1024)
        self.assertEqual(specs["ram_usage_bytes"], (16384000 - 8192000) * 1024)
        # tmpfs, squashfs/loop and the duplicate bind of the same disk are skipped.
        self.assertEqual([item["name"] for item in specs["storage_devices"]],
                         ["/ (nvme0n1p2)", "/boot/efi (nvme0n1p1)"])
        self.assertEqual(specs["gpu_information"],
                         ["Intel Corporation TigerLake-LP GT2 [Iris Xe Graphics] (rev 01)"])
        self.assertEqual(specs["motherboard_brand"], "LENOVO 20XWCTO1WW")
        self.assertEqual(specs["operating_system_name"], "Ubuntu")
        self.assertEqual(specs["operating_system_version"],
                         "24.04.1 LTS (Noble Numbat) (kernel 6.8.0-45-generic)")
        self.assertEqual(specs["network_adapters"], ["docker0", "wlp0s20f3"])
        self.assertEqual(specs["ip_addresses"], ["192.168.1.42", "2001:db8::42"])
        self.assertEqual(specs["mac_address"], "A4:C3:F0:12:34:56")
        validate_detected_specifications(agent.build_payload("x", "Laptop", specs)["specifications"])

    def test_linux_collector_degrades_gracefully_on_a_bare_system(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = agent.LinuxCollector(root=directory, run=lambda *a, **k: "", statvfs=fake_statvfs({}))
            specs = collector.collect()
            self.assertEqual(collector.device_type(), "Desktop")
        self.assertEqual(specs["storage_devices"], [])
        self.assertEqual(specs["gpu_information"], [agent.UNAVAILABLE])
        validate_detected_specifications(agent.build_payload("x", "Desktop", specs)["specifications"])

    def test_mac_collector_reports_valid_specifications(self):
        collector = agent.MacCollector(
            run=fake_mac_run,
            statvfs=fake_statvfs({"/System/Volumes/Data": (460 * GIB, 120 * GIB)}),
            exists=lambda path: path == "/System/Volumes/Data",
        )
        specs = collector.collect()
        self.assertEqual(collector.device_type(), "Laptop")
        self.assertEqual(specs["cpu_name"], "Apple M2")
        self.assertEqual(specs["cpu_cores"], 8)
        self.assertEqual(specs["ram_capacity_bytes"], 16 * GIB)
        self.assertEqual(specs["ram_usage_bytes"], 450000 * 16384)
        self.assertEqual(specs["storage_devices"][0]["name"], "Macintosh HD")
        self.assertEqual(specs["gpu_information"], ["Apple M2"])
        self.assertEqual(specs["motherboard_brand"], "Apple Mac14,2")
        self.assertEqual((specs["operating_system_name"], specs["operating_system_version"]),
                         ("macOS", "14.5 (23F79)"))
        self.assertEqual(specs["network_adapters"], ["en0"])
        self.assertEqual(specs["ip_addresses"], ["10.0.0.25"])
        self.assertEqual(specs["mac_address"], "3C:22:FB:AA:BB:CC")
        validate_detected_specifications(agent.build_payload("x", "Laptop", specs)["specifications"])

    def test_enrollment_links_are_validated(self):
        url, token = agent.parse_enrollment_link(
            f"devmonitor://enroll?server=https%3A%2F%2Fmonitor.example.edu&token={TOKEN}"
        )
        self.assertEqual(url, "https://monitor.example.edu/api/device-agent/enroll")
        self.assertEqual(token, TOKEN)
        agent.parse_enrollment_link(f"devmonitor://enroll?server=http://127.0.0.1:5000&token={TOKEN}")
        for bad in (
            f"https://enroll?server=https://a.example&token={TOKEN}",
            f"devmonitor://other?server=https://a.example&token={TOKEN}",
            f"devmonitor://enroll?server=http://evil.example&token={TOKEN}",
            f"devmonitor://enroll?server=https://user:pw@a.example&token={TOKEN}",
            "devmonitor://enroll?server=https://a.example&token=short",
            "",
        ):
            with self.subTest(link=bad), self.assertRaises(agent.AgentError):
                agent.parse_enrollment_link(bad)
        self.assertIsNone(agent.embedded_enrollment())

    def test_submission_errors_become_actionable_messages(self):
        def unreachable(request, timeout):
            raise urllib.error.URLError("connection refused")

        def expired(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {},
                                         io.BytesIO(b'{"error":"bad token"}'))

        def rejected(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 400, "Bad Request", {},
                                         io.BytesIO(b'{"error":"Device type must be Desktop."}'))

        url = "https://monitor.example.edu/api/device-agent/enroll"
        for opener, expected in (
            (unreachable, "Could not reach the DevMonitor server at monitor.example.edu"),
            (expired, "expired or was already used"),
            (rejected, "Device type must be Desktop."),
        ):
            with self.subTest(expected=expected), self.assertRaisesRegex(agent.AgentError, expected):
                agent.submit_registration(url, TOKEN, {"name": "x"}, opener=opener)


class LinuxPackageTest(unittest.TestCase):
    def test_deb_is_a_valid_debian_package_with_the_token_embedded(self):
        deb = build_deb(TOKEN, "https://monitor.example.edu/api/device-agent/enroll", mtime=1_700_000_000)
        members = parse_ar(deb)
        self.assertEqual([name for name, _ in members], ["debian-binary", "control.tar.gz", "data.tar.gz"])
        self.assertEqual(members[0][1], b"2.0\n")
        with tarfile.open(fileobj=io.BytesIO(members[1][1])) as control_tar:
            control = control_tar.extractfile("./control").read().decode()
        self.assertIn("Package: devmonitor-agent\n", control)
        self.assertIn("Architecture: all\n", control)
        self.assertIn("Depends: python3 (>= 3.8)\n", control)
        with tarfile.open(fileobj=io.BytesIO(members[2][1])) as data_tar:
            script_info = data_tar.getmember("./usr/bin/devmonitor-agent")
            self.assertEqual(script_info.mode, 0o755)
            self.assertEqual((script_info.uid, script_info.uname), (0, "root"))
            script = data_tar.extractfile(script_info).read()
            desktop = data_tar.extractfile("./usr/share/applications/devmonitor-agent.desktop").read()
        self.assertTrue(script.startswith(b"#!/usr/bin/env python3"))
        self.assertIn(b"Exec=devmonitor-agent", desktop)
        module = load_agent_source(script)
        self.assertEqual(
            module.embedded_enrollment(),
            ("https://monitor.example.edu/api/device-agent/enroll", TOKEN),
        )

    def test_portable_archive_and_invalid_tokens(self):
        archive = build_portable_archive(TOKEN, "https://monitor.example.edu/api/device-agent/enroll")
        with tarfile.open(fileobj=io.BytesIO(archive)) as portable:
            self.assertEqual(portable.getmember("devmonitor-agent/devmonitor-agent").mode, 0o755)
            self.assertIn(b"embedded", portable.extractfile("devmonitor-agent/devmonitor-agent").read())
        with self.assertRaises(LinuxPackageError):
            build_deb("not-a-token", "https://x.example/api/device-agent/enroll")


class DownloadHubIntegrationTest(unittest.TestCase):
    register_and_login = base_tests.DatabaseIntegrationTest.register_and_login
    _download_cards = base_tests.DatabaseIntegrationTest._download_cards

    def setUp(self):
        self.packages = tempfile.TemporaryDirectory()
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "integration-test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "MAIL_SERVER": None,
            "AGENT_PACKAGES_DIR": self.packages.name,
            "IOS_DISTRIBUTION_URL": "",
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
        self.packages.cleanup()

    def _flask_opener(self):
        """urlopen replacement that sends the agent's request to the Flask app."""
        client = self.app.test_client()

        def opener(request, timeout):
            parts = urllib.parse.urlsplit(request.full_url)
            response = client.open(
                parts.path + (f"?{parts.query}" if parts.query else ""),
                method=request.get_method(),
                data=request.data,
                headers=dict(request.header_items()),
            )
            if response.status_code >= 400:
                raise urllib.error.HTTPError(request.full_url, response.status_code, "error",
                                             {}, io.BytesIO(response.data))
            return io.BytesIO(response.data)
        return opener

    def test_linux_deb_download_registers_the_device_end_to_end(self):
        csrf = self.register_and_login()
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        download = self.client.post("/device-agent/linux/deb", data={"csrf_token": csrf})
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.mimetype, "application/vnd.debian.binary-package")
        self.assertIn("devmonitor-agent_1.0.0_all.deb", download.headers["Content-Disposition"])
        self.assertEqual(download.headers["Cache-Control"], "no-store")
        members = dict(parse_ar(download.data))
        with tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"])) as data_tar:
            script = data_tar.extractfile("./usr/bin/devmonitor-agent").read()
        packaged = load_agent_source(script)
        enrollment = packaged.embedded_enrollment()
        self.assertEqual(enrollment[0], "http://localhost/api/device-agent/enroll")

        with tempfile.TemporaryDirectory() as directory:
            collector = packaged.LinuxCollector(
                root=make_linux_root(directory), run=fake_linux_run,
                statvfs=fake_statvfs({"/": (500 * GIB, 200 * GIB)}),
            )
            payload = packaged.build_payload("ubuntu-laptop", collector.device_type(), collector.collect())
        result = packaged.submit_registration(*enrollment, payload, opener=self._flask_opener())
        self.assertEqual(result["name"], "ubuntu-laptop")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        with self.app.app_context():
            device = db.session.get(Device, result["device_id"])
            self.assertEqual(device.device_type, "Laptop")
            self.assertEqual(device.operating_system, "Ubuntu")
        with self.assertRaisesRegex(packaged.AgentError, "expired or was already used"):
            packaged.submit_registration(*enrollment, payload, opener=self._flask_opener())

    def test_device_link_hands_a_one_use_token_to_an_installed_app(self):
        csrf = self.register_and_login()
        refused = self.client.post("/api/device-link")
        self.assertEqual(refused.status_code, 400)
        link = self.client.post("/api/device-link", headers={"X-CSRF-Token": csrf})
        self.assertEqual(link.status_code, 200, link.get_data(as_text=True))
        self.assertEqual(link.headers["Cache-Control"], "no-store")
        self.assertTrue(link.json["link"].startswith("devmonitor://enroll?server=http%3A%2F%2Flocalhost&token="))
        enrollment = agent.parse_enrollment_link(link.json["link"])
        phone_specs = {
            "cpu_name": "Qualcomm SM8550", "cpu_cores": 8,
            "ram_capacity_bytes": 8 * GIB, "ram_usage_bytes": 5 * GIB,
            "storage_devices": [{"name": "Internal storage", "total_bytes": 128 * GIB, "available_bytes": 40 * GIB}],
            "storage_total_bytes": 128 * GIB, "storage_available_bytes": 40 * GIB,
            "gpu_information": ["Adreno (TM) 740"], "motherboard_brand": "samsung SM-S911B",
            "operating_system_name": "Android", "operating_system_version": "14 (API 34)",
            "network_adapters": ["wlan0"], "ip_addresses": ["192.168.1.77"],
        }
        result = agent.submit_registration(
            *enrollment, {"name": "Galaxy S23", "device_type": "Phone", "specifications": phone_specs},
            opener=self._flask_opener(),
        )
        with self.app.app_context():
            self.assertEqual(db.session.get(Device, result["device_id"]).device_type, "Phone")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_published_packages_and_store_links_enable_their_cards(self):
        self.register_and_login()
        _html, cards = self._download_cards()
        self.assertEqual(cards["android"][0], "is-pending")
        apk_path = Path(self.packages.name, "devmonitor-agent.apk")
        apk_path.write_bytes(make_apk())
        self.app.config["IOS_DISTRIBUTION_URL"] = "https://testflight.apple.com/join/AbCdEf12"
        _html, cards = self._download_cards()
        self.assertEqual(cards["android"][0], "is-available")
        self.assertIn('href="/downloads/android"', cards["android"][1])
        self.assertIn("Download .apk", cards["android"][1])
        self.assertIn("SHA-256", cards["android"][1])
        self.assertEqual(cards["macos"][0], "is-pending")
        self.assertIn(".dmg build pending", cards["macos"][1])
        # The Apple cards show real build progress derived from this checkout.
        self.assertIn("Build ready", cards["macos"][1])
        self.assertIn("macOS build progress", cards["macos"][1])
        self.assertRegex(cards["macos"][1], r'is-done">\s*<i class="bi bi-check-circle-fill"[^>]*></i>\s*<span>macOS agent')
        self.assertRegex(cards["macos"][1], r'is-open">\s*<i class="bi bi-circle"[^>]*></i>\s*<span>Published \.dmg')
        self.assertEqual(cards["ios"][0], "is-available")
        self.assertIn('href="https://testflight.apple.com/join/AbCdEf12"', cards["ios"][1])
        self.assertIn("Get on TestFlight", cards["ios"][1])
        self.assertNotIn("itms-services", cards["ios"][1])
        served = self.client.get("/downloads/android")
        self.assertEqual(served.status_code, 200)
        self.assertEqual(served.data, apk_path.read_bytes())
        self.assertEqual(served.mimetype, "application/vnd.android.package-archive")
        served.close()
        # Only Apple distribution URLs are accepted for the iOS button.
        self.app.config["IOS_DISTRIBUTION_URL"] = "https://evil.example/app.ipa"
        self.assertEqual(self._download_cards()[1]["ios"][0], "is-pending")
        # Only known package names can ever be served (no path traversal).
        for probe in ("/downloads/ios", "/downloads/linux", "/downloads/app.py"):
            with self.subTest(probe=probe):
                self.assertEqual(self.client.get(probe).status_code, 404)
        # Windows has no published package here, so it falls back to the page.
        self.assertEqual(self.client.get("/downloads/windows").status_code, 302)
        traversal = self.client.get("/downloads/..%2Fapp.py")
        self.assertNotEqual(traversal.status_code, 200)
        self.assertNotIn(b"def create_app", traversal.data)

    def test_fake_or_unsigned_packages_are_never_offered(self):
        self.register_and_login()
        Path(self.packages.name, "devmonitor-agent.apk").write_bytes(b"PK\x03\x04 not really an apk")
        Path(self.packages.name, "DevMonitor-Agent.dmg").write_bytes(b"\0" * 4096)
        Path(self.packages.name, "DevMonitor-Agent.ipa").write_bytes(make_ipa(signed=False))
        _html, cards = self._download_cards()
        for platform in ("android", "macos", "ios"):
            with self.subTest(platform=platform):
                self.assertEqual(cards[platform][0], "is-pending")
                self.assertIn("failed verification", cards[platform][1])
                self.assertNotIn("Download .", cards[platform][1].split("dl-problem")[0])
        self.assertIn("not signed for distribution", cards["ios"][1])
        self.assertEqual(self.client.get("/downloads/android").status_code, 302)
        self.assertEqual(self.client.get("/downloads/macos").status_code, 302)

    def test_signed_dmg_is_offered_as_a_dedicated_dmg_download(self):
        self.register_and_login()
        dmg = make_dmg()
        Path(self.packages.name, "DevMonitor-Agent.dmg").write_bytes(dmg)
        _html, cards = self._download_cards()
        self.assertEqual(cards["macos"][0], "is-available")
        self.assertIn('<span class="dl-format">.dmg</span>', cards["macos"][1])
        self.assertIn("Download .dmg", cards["macos"][1])
        self.assertIn('href="/downloads/macos"', cards["macos"][1])
        served = self.client.get("/downloads/macos")
        self.assertEqual(served.status_code, 200)
        self.assertEqual(served.mimetype, "application/x-apple-diskimage")
        self.assertIn("DevMonitor-Agent.dmg", served.headers["Content-Disposition"])
        self.assertEqual(served.data, dmg)
        served.close()

    def test_ad_hoc_ipa_is_installable_over_the_air_only_via_https(self):
        csrf = self.register_and_login()
        ipa = make_ipa(profile="ad-hoc")
        Path(self.packages.name, "DevMonitor-Agent.ipa").write_bytes(ipa)

        # Over plain HTTP iOS refuses itms-services installs, so nothing is offered.
        _html, cards = self._download_cards()
        self.assertEqual(cards["ios"][0], "is-pending")
        self.assertIn("require the site to use HTTPS", cards["ios"][1])

        self.app.config["PUBLIC_BASE_URL"] = "https://monitor.example.edu"
        _html, cards = self._download_cards()
        self.assertEqual(cards["ios"][0], "is-available")
        body = cards["ios"][1]
        self.assertIn("Install .ipa", body)
        self.assertIn("Ad Hoc build · registered devices only", body)
        link = re.search(r'href="(itms-services://[^"]+)"', body).group(1).replace("&amp;", "&")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
        self.assertEqual(query["action"], ["download-manifest"])
        manifest_url = query["url"][0]
        self.assertTrue(manifest_url.startswith("https://monitor.example.edu/downloads/ios/"))

        # iOS fetches the manifest and IPA without the browser's session cookie.
        anonymous = self.app.test_client()
        manifest = anonymous.get(urllib.parse.urlsplit(manifest_url).path)
        self.assertEqual(manifest.status_code, 200)
        self.assertEqual(manifest.headers["Cache-Control"], "no-store")
        item = plistlib.loads(manifest.data)["items"][0]
        self.assertEqual(item["metadata"]["bundle-identifier"], "com.devmonitor.agent")
        self.assertEqual(item["metadata"]["bundle-version"], "1.0.0")
        package_url = item["assets"][0]["url"]
        self.assertTrue(package_url.startswith("https://monitor.example.edu/downloads/ios/"))
        package = anonymous.get(urllib.parse.urlsplit(package_url).path)
        self.assertEqual(package.status_code, 200)
        self.assertEqual(package.data, ipa)
        package.close()

        # A forged or tampered grant gets nothing.
        grant = urllib.parse.urlsplit(manifest_url).path.split("/")[3]
        for bad in ("forged", grant[:-2] + ("AA" if grant[-2:] != "AA" else "BB")):
            self.assertEqual(anonymous.get(f"/downloads/ios/{bad}/manifest.plist").status_code, 404)
            self.assertEqual(anonymous.get(f"/downloads/ios/{bad}/DevMonitor-Agent.ipa").status_code, 404)
        self.assertIsNotNone(csrf)

    def test_ipas_that_cannot_be_installed_from_a_website_are_explained(self):
        self.register_and_login()
        self.app.config["PUBLIC_BASE_URL"] = "https://monitor.example.edu"
        for profile, message in (
            ("app-store", "app-store build"),
            ("development", "development build"),
            ("expired", "has expired"),
        ):
            with self.subTest(profile=profile):
                Path(self.packages.name, "DevMonitor-Agent.ipa").write_bytes(make_ipa(profile=profile))
                _html, cards = self._download_cards()
                self.assertEqual(cards["ios"][0], "is-pending")
                self.assertIn(message, cards["ios"][1])
                self.assertNotIn("itms-services", cards["ios"][1])

    def test_admins_see_downloads_but_cannot_create_enrollments(self):
        from device_monitoring_prototype.models import User
        csrf = self.register_and_login()
        with self.app.app_context():
            user = User.query.filter_by(username="testuser").one()
            user.roles = [Role.query.filter_by(name="Administrator").one()]
            db.session.commit()
        html, cards = self._download_cards()
        self.assertIn("Standard accounts only", cards["windows"][1])
        self.assertNotIn("<form", cards["linux"][1])
        self.assertEqual(
            self.client.post("/api/device-link", headers={"X-CSRF-Token": csrf}).status_code, 403
        )
        self.assertEqual(
            self.client.post("/device-agent/linux/deb", data={"csrf_token": csrf},
                             headers={"Accept": "application/json"}).status_code, 403
        )


RELEASE_URL = "https://github.com/example/devmonitor/releases/download/agents-latest"


def release_manifest(**packages):
    defaults = {
        "windows": "DevMonitor-Agent-Windows.exe",
        "android": "devmonitor-agent.apk",
        "macos": "DevMonitor-Agent.dmg",
    }
    return {
        "packages": {
            key: {"filename": defaults[key], "sha256": "ab" * 32, "size": 5 * 1024 * 1024,
                  "version": "1.0.0", **(overrides or {})}
            for key, overrides in packages.items()
        }
    }


class ReleaseHostedPackagesTest(unittest.TestCase):
    """Packages published to a GitHub Release (hosts without a disk, e.g. Vercel)."""

    register_and_login = base_tests.DatabaseIntegrationTest.register_and_login
    _download_cards = base_tests.DatabaseIntegrationTest._download_cards

    def setUp(self):
        self.packages = tempfile.TemporaryDirectory()
        self._make_app()
        self.manifest = release_manifest(windows=None, android=None, macos=None)
        self.fetches = []
        opener = patch("device_monitoring_prototype.app.urllib.request.urlopen", self._urlopen)
        opener.start()
        self.addCleanup(opener.stop)
        # Behave like a Linux host (Vercel), where the per-user .exe cannot be built.
        linux = patch("device_monitoring_prototype.app.sys.platform", "linux")
        linux.start()
        self.addCleanup(linux.stop)

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
        self.packages.cleanup()

    def _make_app(self):
        """A fresh app (and so an empty manifest cache) with a new in-memory database."""
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "integration-test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "MAIL_SERVER": None,
            "AGENT_PACKAGES_DIR": self.packages.name,
            "IOS_DISTRIBUTION_URL": "",
            "AGENT_RELEASE_URL": RELEASE_URL,
        })
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            db.session.add_all([Role(name="Administrator"), Role(name="User")])
            db.session.commit()

    def _urlopen(self, request, timeout):
        self.fetches.append(request.full_url)
        if isinstance(self.manifest, Exception):
            raise self.manifest
        body = self.manifest if isinstance(self.manifest, bytes) else json.dumps(self.manifest).encode()
        return io.BytesIO(body)

    def test_release_packages_enable_cards_and_redirect_downloads(self):
        self.register_and_login()
        _html, cards = self._download_cards()
        for platform, label in (("windows", ".exe"), ("android", ".apk"), ("macos", ".dmg")):
            with self.subTest(platform=platform):
                state, body = cards[platform]
                self.assertEqual(state, "is-available")
                self.assertIn(f'href="/downloads/{platform}"', body)
                self.assertIn(f"Download {label}", body)
                self.assertIn("5.0 MB", body)
        self.assertIn("Link this device", cards["windows"][1])
        self.assertEqual(self.fetches, [f"{RELEASE_URL}/agents-manifest.json"])
        for platform, filename in (
            ("windows", "DevMonitor-Agent-Windows.exe"),
            ("android", "devmonitor-agent.apk"),
            ("macos", "DevMonitor-Agent.dmg"),
        ):
            with self.subTest(download=platform):
                response = self.client.get(f"/downloads/{platform}")
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["Location"], f"{RELEASE_URL}/{filename}")
        # The manifest is cached instead of being fetched on every page view.
        self.assertEqual(len(self.fetches), 1)

    def test_a_local_package_takes_priority_over_the_release(self):
        self.register_and_login()
        Path(self.packages.name, "devmonitor-agent.apk").write_bytes(make_apk())
        served = self.client.get("/downloads/android")
        self.assertEqual(served.status_code, 200)
        self.assertEqual(served.mimetype, "application/vnd.android.package-archive")
        served.close()

    def test_missing_or_untrustworthy_release_entries_are_not_offered(self):
        self.register_and_login()
        self.manifest = release_manifest(
            windows={"filename": "../evil.exe"},
            android={"sha256": "not-a-hash"},
        )
        _html, cards = self._download_cards()
        for platform in ("windows", "android", "macos"):
            with self.subTest(platform=platform):
                self.assertEqual(cards[platform][0], "is-pending")
                self.assertEqual(self.client.get(f"/downloads/{platform}").status_code, 302)
                self.assertNotIn(
                    "github.com",
                    self.client.get(f"/downloads/{platform}").headers["Location"],
                )

    def test_an_unreachable_or_broken_release_leaves_cards_pending(self):
        for failure in (
            urllib.error.URLError("offline"),
            TimeoutError("slow"),
            b"not json",
            b'{"packages": []}',
            b"{" + b" " * (64 * 1024) + b"}",
        ):
            with self.subTest(failure=repr(failure)[:40]):
                self.tearDown()
                self.packages = tempfile.TemporaryDirectory()
                self._make_app()
                self.manifest = failure
                self.fetches.clear()
                self.register_and_login()
                _html, cards = self._download_cards()
                for platform in ("windows", "android", "macos"):
                    self.assertEqual(cards[platform][0], "is-pending")
                # A failure is cached briefly, so pages do not wait on every view.
                self._download_cards()
                self.assertEqual(len(self.fetches), 1)

    def test_only_https_release_urls_are_used(self):
        self.register_and_login()
        self.app.config["AGENT_RELEASE_URL"] = "http://insecure.example/releases"
        _html, cards = self._download_cards()
        self.assertEqual(cards["android"][0], "is-pending")
        self.assertEqual(self.fetches, [])


class WindowsAgentLinkTest(unittest.TestCase):
    """The generic Windows build enrolls with a "Link this device" link."""

    def setUp(self):
        from device_monitoring_prototype import device_agent

        self.agent = device_agent

    def test_valid_links_give_the_enroll_and_dashboard_urls(self):
        link = "devmonitor://enroll?" + urllib.parse.urlencode(
            {"server": "https://monitor.example.com", "token": TOKEN}
        )
        self.assertEqual(
            self.agent.parse_enrollment_link(f'"{link}"'),
            (
                "https://monitor.example.com/api/device-agent/enroll",
                TOKEN,
                "https://monitor.example.com/dashboard",
            ),
        )
        local = "devmonitor://enroll?server=http%3A%2F%2Flocalhost%3A5000&token=" + TOKEN
        self.assertEqual(
            self.agent.parse_enrollment_link(local)[0],
            "http://localhost:5000/api/device-agent/enroll",
        )

    def test_unsafe_or_incomplete_links_are_rejected(self):
        for link in (
            "",
            "https://monitor.example.com",
            "devmonitor://other?server=https%3A%2F%2Fm.example&token=" + TOKEN,
            "devmonitor://enroll?server=http%3A%2F%2Fevil.example&token=" + TOKEN,
            "devmonitor://enroll?server=https%3A%2F%2Fu%3Ap%40m.example&token=" + TOKEN,
            "devmonitor://enroll?server=https%3A%2F%2Fm.example%2Fpath&token=" + TOKEN,
            "devmonitor://enroll?server=https%3A%2F%2Fm.example&token=short",
        ):
            with self.subTest(link=link), self.assertRaises(ValueError):
                self.agent.parse_enrollment_link(link)

    def test_placeholders_are_not_treated_as_embedded_values(self):
        self.assertEqual(self.agent._embedded("__REGISTRATION" + "_TOKEN__"), "")
        self.assertEqual(self.agent._embedded(TOKEN), TOKEN)

    def test_generic_build_without_a_link_stops_before_collecting(self):
        with patch.object(self.agent, "collect_specifications") as collect, \
                patch.object(self.agent, "configure_logging", return_value=None), \
                patch.object(self.agent, "_show_log_location"), \
                patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(self.agent.main(["--yes"]), 2)
        collect.assert_not_called()
        self.assertIn("Link this device", stderr.getvalue())

    def test_per_download_builds_still_embed_their_token(self):
        source = Path(self.agent.__file__).read_text(encoding="utf-8")
        self.assertEqual(source.count('"__REGISTRATION_TOKEN__"'), 1)
        self.assertEqual(source.count('"__SUBMISSION_URL__"'), 1)


if __name__ == "__main__":
    unittest.main()
