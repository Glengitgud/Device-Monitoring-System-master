"""Build a token-bound Windows executable for a confirmed enrollment."""

import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


class DeviceAgentBuildError(RuntimeError):
    """Raised when a personalized Windows agent cannot be produced."""


def build_agent_executable(registration_token, submission_url):
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", registration_token):
        raise DeviceAgentBuildError("The device registration token is invalid.")
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
    source = source.replace(
        '"__REGISTRATION_TOKEN__"', json.dumps(registration_token)
    ).replace('"__SUBMISSION_URL__"', json.dumps(submission_url))
    if "__REGISTRATION_TOKEN__" in source or "__SUBMISSION_URL__" in source:
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
                "--console",
                "--clean",
                "--noconfirm",
                "--name",
                "devmonitor-device-agent",
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

            executable = dist_dir / "devmonitor-device-agent.exe"
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
