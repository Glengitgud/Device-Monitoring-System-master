"""Structural checks for published agent packages.

The Downloads page only offers a package that passes these checks, so a
placeholder, truncated upload or unsigned build is never linked.

They verify the container format and the presence of signing material; they do
not replace Apple/Google signature verification on the device itself.
"""

import plistlib
import re
import zipfile
from datetime import datetime, timezone
from pathlib import PurePosixPath

APK_SIGNING_BLOCK_MAGIC = b"APK Sig Block 42"
DMG_TRAILER_MAGIC = b"koly"
IPA_APP_PATTERN = re.compile(r"^Payload/([^/]+\.app)/")


class PackageValidationError(ValueError):
    """The file is not a usable, signed package of the expected type."""


def validate_apk(path):
    """Android package: a ZIP with a manifest, compiled code and a signature."""
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
    except (OSError, zipfile.BadZipFile) as error:
        raise PackageValidationError("The APK is not a valid Android package archive.") from error
    if "AndroidManifest.xml" not in names or not any(
        re.fullmatch(r"classes\d*\.dex", name) for name in names
    ):
        raise PackageValidationError("The APK is missing its manifest or compiled code.")
    with open(path, "rb") as package:
        signed_v2 = APK_SIGNING_BLOCK_MAGIC in package.read()
    signed_v1 = any(
        re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC)", name, re.IGNORECASE) for name in names
    )
    if not (signed_v2 or signed_v1):
        raise PackageValidationError("The APK is not signed.")
    return {"signed": True}


def validate_dmg(path):
    """Apple disk image: every UDIF image ends with a 512-byte "koly" trailer."""
    try:
        with open(path, "rb") as image:
            image.seek(0, 2)
            if image.tell() < 512:
                raise PackageValidationError("The DMG is too small to be a disk image.")
            image.seek(-512, 2)
            trailer = image.read(512)
    except OSError as error:
        raise PackageValidationError("The DMG could not be read.") from error
    if not trailer.startswith(DMG_TRAILER_MAGIC):
        raise PackageValidationError("The file is not an Apple disk image (.dmg).")
    return {}


def _embedded_plist(data):
    """A .mobileprovision is a CMS envelope around a readable XML plist."""
    start = data.find(b"<?xml")
    end = data.find(b"</plist>")
    if start < 0 or end < 0:
        raise PackageValidationError("The provisioning profile could not be read.")
    return plistlib.loads(data[start:end + len(b"</plist>")])


def inspect_ipa(path, now=None):
    """Return signing/distribution details of an iOS app archive.

    ``distribution`` is one of: ``ad-hoc`` and ``enterprise`` (installable
    over the air on permitted devices), ``development`` (only devices of the
    developer, via Xcode), ``app-store`` (installable only via TestFlight /
    App Store, never from a website).
    """
    now = now or datetime.now(timezone.utc)
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            apps = {match.group(1) for name in names if (match := IPA_APP_PATTERN.match(name))}
            if len(apps) != 1:
                raise PackageValidationError("The IPA must contain exactly one Payload/*.app bundle.")
            app = f"Payload/{apps.pop()}"
            required = (f"{app}/Info.plist", f"{app}/embedded.mobileprovision",
                        f"{app}/_CodeSignature/CodeResources")
            missing = [PurePosixPath(name).name for name in required if name not in names]
            if missing:
                raise PackageValidationError(
                    "The IPA is not signed for distribution (missing " + ", ".join(missing) + ")."
                )
            info = plistlib.loads(archive.read(f"{app}/Info.plist"))
            profile = _embedded_plist(archive.read(f"{app}/embedded.mobileprovision"))
    except (OSError, zipfile.BadZipFile, plistlib.InvalidFileException) as error:
        raise PackageValidationError("The IPA is not a valid iOS app archive.") from error

    expires = profile.get("ExpirationDate")
    if isinstance(expires, datetime):
        expires = expires if expires.tzinfo else expires.replace(tzinfo=timezone.utc)
        if expires <= now:
            raise PackageValidationError("The IPA's provisioning profile has expired.")
    entitlements = profile.get("Entitlements") or {}
    if profile.get("ProvisionsAllDevices"):
        distribution = "enterprise"
    elif entitlements.get("get-task-allow"):
        distribution = "development"
    elif profile.get("ProvisionedDevices"):
        distribution = "ad-hoc"
    else:
        distribution = "app-store"
    bundle_id = info.get("CFBundleIdentifier")
    version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
    if not bundle_id or not version:
        raise PackageValidationError("The IPA's Info.plist has no bundle identifier or version.")
    return {
        "distribution": distribution,
        "over_the_air": distribution in {"ad-hoc", "enterprise"},
        "bundle_id": bundle_id,
        "version": str(version),
        "title": info.get("CFBundleDisplayName") or info.get("CFBundleName") or "DevMonitor Agent",
        "device_limit": len(profile.get("ProvisionedDevices") or []) or None,
        "expires": expires.date().isoformat() if isinstance(expires, datetime) else None,
    }
