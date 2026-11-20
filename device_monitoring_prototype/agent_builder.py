"""Build a token-bound Windows executable for a confirmed enrollment."""

import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


class DeviceAgentBuildError(RuntimeError):
    """Raised when a personalized Windows agent cannot be produced."""


def build_agent_executable(
    registration_token,
    submission_url,
    *,
    mode="registration",
    scan_run_id="",
    scan_token="",
    dashboard_url="",
):
    if mode not in {"registration", "scanner"}:
        raise DeviceAgentBuildError("The Device Agent mode is invalid.")
    if mode == "registration" and not re.fullmatch(
        r"[A-Za-z0-9_-]{40,64}", registration_token or ""
    ):
        raise DeviceAgentBuildError("The device registration token is invalid.")
    if mode == "scanner" and (
        not str(scan_run_id).isdigit()
        or not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", scan_token or "")
    ):
        raise DeviceAgentBuildError("The scan authorization is invalid.")
    if sys.platform != "win32":
        raise DeviceAgentBuildError(
            "The Windows agent must be built on a Windows application host."
        )

    source_path = Path(__file__).with_name("device_agent.py")
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as error:
        raise DeviceAgentBuildError(
            "The Windows agent source could not be read."
        ) from error
    replacements = {
        "__REGISTRATION_TOKEN__": registration_token or "",
        "__SUBMISSION_URL__": submission_url,
        "__SCAN_RUN_ID__": str(scan_run_id or ""),
        "__SCAN_TOKEN__": scan_token or "",
        "__DASHBOARD_URL__": dashboard_url or "",
    }
    for placeholder, value in replacements.items():
        source = source.replace(f'"{placeholder}"', json.dumps(value))
    if any(placeholder in source for placeholder in replacements):
        raise DeviceAgentBuildError("The agent source has unresolved settings.")

    try:
        with tempfile.TemporaryDirectory(prefix="devmonitor-agent-") as directory:
            build_dir = Path(directory)
            source_file = build_dir / "device_agent.py"
            source_file.write_text(source, encoding="utf-8")
            dist_dir = build_dir / "dist"
            command = [
                sys.executable,
                "-m",
                "PyInstaller",
                "--onefile",
                "--console" if mode == "registration" else "--noconsole",
                "--clean",
                "--noconfirm",
                "--name",
                "devmonitor-device-agent" if mode == "registration" else "devmonitor-device-scanner",
                "--distpath",
                str(dist_dir),
                "--workpath",
                str(build_dir / "work"),
                "--specpath",
                str(build_dir),
                str(source_file),
            ]
            try:
                subprocess.run(
                    command,
                    cwd=build_dir,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=240,
                )
            except subprocess.SubprocessError as error:
                raise DeviceAgentBuildError(
                    "The Windows agent executable could not be built."
                ) from error

            executable_name = (
                "devmonitor-device-agent.exe"
                if mode == "registration"
                else "devmonitor-device-scanner.exe"
            )
            executable = dist_dir / executable_name
            if not executable.is_file():
                raise DeviceAgentBuildError(
                    "The Windows agent build did not produce an executable."
                )
            executable_bytes = executable.read_bytes()
            if not executable_bytes.startswith(b"MZ"):
                raise DeviceAgentBuildError(
                    "The Windows agent build produced an invalid executable."
                )
            return executable_bytes
    except OSError as error:
        raise DeviceAgentBuildError(
            "The Windows agent executable could not be prepared."
        ) from error
