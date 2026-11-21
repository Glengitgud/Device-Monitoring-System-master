"""Build per-download Linux packages of the DevMonitor agent in pure Python.

The Linux agent (device_agent_unix.py) only needs the system ``python3``, so
no compilation is required and the packages can be produced on any server OS:

* ``deb``: Debian/Ubuntu/Mint/Pop!_OS/Kali package (``dpkg -i`` / double-click).
* ``tar.gz``: portable archive for other distributions (Fedora, Arch, ...).

Each package embeds a one-use registration token, exactly like the Windows EXE.
"""

import gzip
import io
import json
import re
import tarfile
import time
from pathlib import Path

PACKAGE_NAME = "devmonitor-agent"
PACKAGE_VERSION = "1.0.0"
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{40,64}")
DESKTOP_ENTRY = """[Desktop Entry]
Type=Application
Name=DevMonitor Device Agent
Comment=Register this computer with your DevMonitor account
Exec=devmonitor-agent
Icon=computer
Terminal=true
Categories=System;Monitor;
"""
PORTABLE_README = """DevMonitor Device Agent for Linux
=================================

Requirements: Python 3.8 or newer (preinstalled on most distributions).

Run:
    ./devmonitor-agent

The agent shows the detected specifications and submits nothing until you
type "yes". This download is linked to your account, works once, and its
registration expires 30 minutes after it was downloaded.
"""


class LinuxPackageError(RuntimeError):
    """Raised when a Linux package cannot be produced."""


def agent_source(registration_token, submission_url):
    if not TOKEN_PATTERN.fullmatch(registration_token or ""):
        raise LinuxPackageError("The device registration token is invalid.")
    source_path = Path(__file__).with_name("device_agent_unix.py")
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as error:
        raise LinuxPackageError("The Linux agent source could not be read.") from error
    for placeholder, value in (
        ("__REGISTRATION_TOKEN__", registration_token),
        ("__SUBMISSION_URL__", submission_url),
    ):
        quoted = f'"{placeholder}"'
        if source.count(quoted) != 1:
            raise LinuxPackageError("The Linux agent source has unexpected settings.")
        source = source.replace(quoted, json.dumps(value))
    return source.encode("utf-8")


def _tar_gz(entries, mtime):
    """entries: list of (path, bytes|None for directory, mode)."""
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=mtime) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for path, data, mode in entries:
                info = tarfile.TarInfo(path)
                info.mtime = mtime
                info.mode = mode
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                if data is None:
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                else:
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _ar_member(name, data, mtime):
    header = (
        f"{name:<16}{mtime:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n"
    ).encode("ascii")
    if len(header) != 60:
        raise LinuxPackageError("Invalid archive member header.")
    return header + data + (b"\n" if len(data) % 2 else b"")


def build_deb(registration_token, submission_url, mtime=None):
    mtime = int(mtime if mtime is not None else time.time())
    script = agent_source(registration_token, submission_url)
    desktop = DESKTOP_ENTRY.encode("utf-8")
    data_entries = [
        ("./", None, 0o755),
        ("./usr/", None, 0o755),
        ("./usr/bin/", None, 0o755),
        (f"./usr/bin/{PACKAGE_NAME}", script, 0o755),
        ("./usr/share/", None, 0o755),
        ("./usr/share/applications/", None, 0o755),
        (f"./usr/share/applications/{PACKAGE_NAME}.desktop", desktop, 0o644),
    ]
    installed_kib = (len(script) + len(desktop)) // 1024 + 1
    control = (
        f"Package: {PACKAGE_NAME}\n"
        f"Version: {PACKAGE_VERSION}\n"
        "Section: admin\n"
        "Priority: optional\n"
        "Architecture: all\n"
        "Depends: python3 (>= 3.8)\n"
        f"Installed-Size: {installed_kib}\n"
        "Maintainer: DevMonitor Project <support@devmonitor.invalid>\n"
        "Description: DevMonitor Device Agent\n"
        " Collects this computer's hardware and network specifications and,\n"
        " after you confirm, links the device to your DevMonitor account.\n"
    ).encode("utf-8")
    control_tar = _tar_gz([("./", None, 0o755), ("./control", control, 0o644)], mtime)
    data_tar = _tar_gz(data_entries, mtime)
    return (
        b"!<arch>\n"
        + _ar_member("debian-binary", b"2.0\n", mtime)
        + _ar_member("control.tar.gz", control_tar, mtime)
        + _ar_member("data.tar.gz", data_tar, mtime)
    )


def build_portable_archive(registration_token, submission_url, mtime=None):
    mtime = int(mtime if mtime is not None else time.time())
    script = agent_source(registration_token, submission_url)
    return _tar_gz(
        [
            (f"{PACKAGE_NAME}/", None, 0o755),
            (f"{PACKAGE_NAME}/{PACKAGE_NAME}", script, 0o755),
            (f"{PACKAGE_NAME}/README.txt", PORTABLE_README.encode("utf-8"), 0o644),
        ],
        mtime,
    )
