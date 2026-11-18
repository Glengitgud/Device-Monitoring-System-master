import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from device_monitoring_prototype.agent_builder import (
    DeviceAgentBuildError,
    build_agent_executable,
)


class DeviceAgentBuilderTest(unittest.TestCase):
    def test_builds_a_windows_executable_with_enrollment_settings(self):
        registration_token = "a" * 43
        submission_url = "https://devmonitor.example/api/device-agent/enroll"
        captured = {}

        def fake_build(command, **kwargs):
            source_path = Path(command[-1])
            captured["source"] = source_path.read_text(encoding="utf-8")
            captured["command"] = command
            captured["kwargs"] = kwargs
            dist_dir = Path(command[command.index("--distpath") + 1])
            dist_dir.mkdir(parents=True)
            (dist_dir / "devmonitor-device-agent.exe").write_bytes(b"MZtest")
            return SimpleNamespace(returncode=0)

        with patch(
            "device_monitoring_prototype.agent_builder.subprocess.run",
            side_effect=fake_build,
        ) as run:
            executable = build_agent_executable(registration_token, submission_url)

        self.assertTrue(executable.startswith(b"MZ"))
        self.assertIn(f'REGISTRATION_TOKEN = "{registration_token}"', captured["source"])
        self.assertIn(f'SUBMISSION_URL = "{submission_url}"', captured["source"])
        self.assertNotIn("__REGISTRATION_TOKEN__", captured["source"])
        self.assertNotIn("__SUBMISSION_URL__", captured["source"])
        self.assertIn("--onefile", captured["command"])
        self.assertIn("--console", captured["command"])
        self.assertEqual(captured["kwargs"]["timeout"], 240)
        run.assert_called_once()

    def test_rejects_invalid_tokens_before_starting_packager(self):
        with patch(
            "device_monitoring_prototype.agent_builder.subprocess.run"
        ) as run:
            with self.assertRaises(DeviceAgentBuildError):
                build_agent_executable("invalid", "https://devmonitor.example/enroll")
        run.assert_not_called()

    def test_requires_a_windows_build_host(self):
        with patch("device_monitoring_prototype.agent_builder.sys.platform", "linux"):
            with patch(
                "device_monitoring_prototype.agent_builder.subprocess.run"
            ) as run:
                with self.assertRaisesRegex(
                    DeviceAgentBuildError, "must be built on a Windows"
                ):
                    build_agent_executable(
                        "a" * 43, "https://devmonitor.example/api/device-agent/enroll"
                    )
        run.assert_not_called()

    def test_reports_packaging_failure_without_falling_back_to_python(self):
        with patch(
            "device_monitoring_prototype.agent_builder.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, ["PyInstaller"]),
        ):
            with self.assertRaisesRegex(
                DeviceAgentBuildError, "executable could not be built"
            ):
                build_agent_executable(
                    "a" * 43, "https://devmonitor.example/api/device-agent/enroll"
                )


if __name__ == "__main__":
    unittest.main()
