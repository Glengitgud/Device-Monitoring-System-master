"""Checks for the macOS/iOS build workflow, scripts and Apple configuration.

These run on any OS. The Apple builds themselves can only run on macOS; the
GitHub Actions workflow (.github/workflows/build-apple-agents.yml) does that.
"""

import io
import json
import plistlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from device_monitoring_prototype import device_agent_unix as agent

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "build-apple-agents.yml"


def posix_bash():
    """A real bash (Git Bash on Windows), not the WSL launcher in System32."""
    candidates = [shutil.which("bash"), r"C:\Program Files\Gitinash.exe"]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and "system32" not in candidate.lower():
            return candidate
    return None


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def job(self, name):
        match = re.search(rf"^  {name}:\n(.*?)(?=^  [a-z][\w-]*:\n|\Z)", self.text, re.S | re.M)
        self.assertIsNotNone(match, f"job {name} missing")
        return match.group(1)

    def test_jobs_run_on_github_hosted_macos(self):
        for name in ("macos-dmg", "ios-app", "ios-signed"):
            with self.subTest(job=name):
                self.assertRegex(self.job(name), r"runs-on: macos-1\d")
        self.assertIn("permissions:\n  contents: read", self.text)

    def test_referenced_scripts_exist(self):
        for script in sorted(set(re.findall(r"(?:bash|python) (agents/[\w/.-]+)", self.text))):
            with self.subTest(script=script):
                self.assertTrue((ROOT / script).is_file(), script)
        self.assertIn("device_monitoring_prototype/device_agent_unix.py --print-specs", self.text)

    def test_macos_job_builds_checks_and_enrolls_end_to_end(self):
        job = self.job("macos-dmg")
        for step in (
            "bash agents/macos/build_macos.sh",
            "hdiutil attach agents/macos/dist/DevMonitor-Agent.dmg",
            "CFBundleURLTypes.0.CFBundleURLSchemes.0",
            "lipo -archs",
            "codesign --verify --deep --strict",
            'ci_backend.py serve',
            '--yes --name "CI Mac" "$LINK"',
            "--expect-os macOS",
            "A used registration link was accepted twice",
            "actions/upload-artifact@v4",
        ):
            with self.subTest(step=step):
                self.assertIn(step, job)

    def test_ios_job_runs_simulator_tests_with_a_real_backend(self):
        job = self.job("ios-app")
        for step in (
            "xcodegen generate",
            "xcodebuild test",
            "TEST_RUNNER_DEVMONITOR_LINK",
            "--expect-type Phone Tablet --expect-os iOS",
            '-destination "generic/platform=iOS"',
            "CODE_SIGNING_ALLOWED=NO",
        ):
            with self.subTest(step=step):
                self.assertIn(step, job)
        self.assertNotIn(".ipa", job.replace("not installable", ""))

    def test_signed_ios_build_is_manual_and_requires_secrets(self):
        job = self.job("ios-signed")
        self.assertIn("if: github.event_name == 'workflow_dispatch' && inputs.ios_distribution != 'none'", job)
        self.assertIn("Require Apple signing secrets", job)
        self.assertIn("bash agents/ios/build_ios.sh", job)
        self.assertIn('rm -f "$ASC_KEY_PATH"', job)

    def test_secrets_are_never_echoed(self):
        for line in self.text.splitlines():
            if "secrets." in line:
                with self.subTest(line=line.strip()):
                    self.assertNotRegex(line, r"\b(echo|run:|cat)\b.*secrets\.")


class AppleConfigurationTest(unittest.TestCase):
    def test_property_lists_are_valid(self):
        for relative in (
            "agents/macos/entitlements.plist",
            "agents/ios/ExportOptions-TestFlight.plist",
            "agents/ios/ExportOptions-AdHoc.plist",
            "agents/ios/Resources/PrivacyInfo.xcprivacy",
        ):
            with self.subTest(plist=relative):
                with open(ROOT / relative, "rb") as handle:
                    self.assertIsInstance(plistlib.load(handle), dict)
        with open(ROOT / "agents/ios/ExportOptions-TestFlight.plist", "rb") as handle:
            self.assertEqual(plistlib.load(handle)["method"], "app-store-connect")
        with open(ROOT / "agents/ios/ExportOptions-AdHoc.plist", "rb") as handle:
            self.assertEqual(plistlib.load(handle)["method"], "release-testing")
        with open(ROOT / "agents/ios/Resources/PrivacyInfo.xcprivacy", "rb") as handle:
            privacy = plistlib.load(handle)
        self.assertFalse(privacy["NSPrivacyTracking"])
        self.assertEqual(privacy["NSPrivacyAccessedAPITypes"], [])

    def test_ios_project_declares_app_tests_and_link_scheme(self):
        project = (ROOT / "agents/ios/project.yml").read_text(encoding="utf-8")
        for needle in (
            'iOS: "16.0"',
            "CFBundleURLSchemes: [devmonitor]",
            "NSAllowsLocalNetworking: true",
            "DevMonitorAgentTests:",
            "type: bundle.unit-test",
            "testTargets:",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, project)
        for source in ("DevMonitorAgentApp", "ContentView", "EnrollmentClient",
                       "EnrollmentLink", "DeviceSpecs", "SpecCollector"):
            with self.subTest(source=source):
                self.assertTrue((ROOT / f"agents/ios/Sources/{source}.swift").is_file())
        tests = (ROOT / "agents/ios/Tests/DevMonitorAgentTests.swift").read_text(encoding="utf-8")
        self.assertIn("@testable import DevMonitorAgent", tests)
        self.assertIn('environment["DEVMONITOR_LINK"]', tests)

    def test_ios_app_never_reads_or_sends_disk_space(self):
        sources = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "agents/ios/Sources").glob("*.swift"))
        for api in ("volumeAvailableCapacity", "volumeTotalCapacity", "systemFreeSize", "systemSize"):
            with self.subTest(api=api):
                self.assertNotIn(api, sources)

    def test_macos_build_script_registers_url_scheme_signs_and_notarizes(self):
        script = (ROOT / "agents/macos/build_macos.sh").read_text(encoding="utf-8")
        for needle in ("set -euo pipefail", "--argv-emulation", "CFBundleURLSchemes",
                       "codesign --force --deep --options runtime", "hdiutil create",
                       "xcrun notarytool submit", "xcrun stapler staple"):
            with self.subTest(needle=needle):
                self.assertIn(needle, script)

    @unittest.skipUnless(posix_bash(), "no POSIX bash available")
    def test_shell_scripts_have_valid_syntax(self):
        for script in ("agents/macos/build_macos.sh", "agents/ios/build_ios.sh"):
            with self.subTest(script=script):
                result = subprocess.run([posix_bash(), "-n", str(ROOT / script)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


class PrintSpecsTest(unittest.TestCase):
    def test_print_specs_outputs_json_and_sends_nothing(self):
        class Collector:
            def collect(self):
                return {"cpu_name": "Apple M2"}

            def device_type(self):
                return "Laptop"

        output = io.StringIO()
        with patch.object(agent, "collector_for_this_system", return_value=Collector()), \
                patch.object(agent, "submit_registration") as submit, \
                patch("sys.stdout", output):
            self.assertEqual(agent.main(["--print-specs"]), 0)
        submit.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()),
                         {"device_type": "Laptop", "specifications": {"cpu_name": "Apple M2"}})


class CiBackendTest(unittest.TestCase):
    """The throwaway backend used by the workflow works end to end."""

    def test_serve_enroll_check_and_replay(self):
        from device_monitoring_prototype.tests.test_multiplatform_agents import (
            GIB, fake_linux_run, fake_statvfs, make_linux_root,
        )

        port = free_port()
        with tempfile.TemporaryDirectory() as scratch:
            db_path = Path(scratch, "ci.db")
            links = Path(scratch, "links.txt")
            server = subprocess.Popen(
                [sys.executable, str(ROOT / "agents/ci/ci_backend.py"), "serve", "--db", str(db_path),
                 "--port", str(port), "--link-file", str(links), "--link-host", "127.0.0.1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                for _ in range(120):
                    if links.exists() and links.read_text().strip():
                        break
                    time.sleep(0.25)
                link = links.read_text().split()[0]
                self.assertTrue(link.startswith(f"devmonitor://enroll?server=http%3A%2F%2F127.0.0.1%3A{port}"))
                enrollment = agent.parse_enrollment_link(link)
                with tempfile.TemporaryDirectory() as root:
                    collector = agent.LinuxCollector(root=make_linux_root(root), run=fake_linux_run,
                                                     statvfs=fake_statvfs({"/": (500 * GIB, 200 * GIB)}))
                    payload = agent.build_payload("ci-test", collector.device_type(), collector.collect())
                for _ in range(40):
                    try:
                        result = agent.submit_registration(*enrollment, payload)
                        break
                    except agent.AgentError as error:
                        if "Could not reach" not in str(error):
                            raise
                        time.sleep(0.25)
                self.assertEqual(result["name"], "ci-test")
                with self.assertRaisesRegex(agent.AgentError, "expired or was already used"):
                    agent.submit_registration(*enrollment, payload)
            finally:
                server.terminate()
                server.wait(timeout=20)
            check = subprocess.run(
                [sys.executable, str(ROOT / "agents/ci/ci_backend.py"), "check", "--db", str(db_path),
                 "--expect-type", "Laptop", "--expect-os", "Ubuntu"],
                capture_output=True, text=True,
            )
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            self.assertIn("CHECK PASSED", check.stdout)
            wrong = subprocess.run(
                [sys.executable, str(ROOT / "agents/ci/ci_backend.py"), "check", "--db", str(db_path),
                 "--expect-os", "macOS"],
                capture_output=True, text=True,
            )
            self.assertEqual(wrong.returncode, 1)


if __name__ == "__main__":
    unittest.main()
