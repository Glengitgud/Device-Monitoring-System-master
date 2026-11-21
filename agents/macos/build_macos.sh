#!/usr/bin/env bash
# Build "DevMonitor Agent.app" and DevMonitor-Agent.dmg on macOS 12+.
#
# The app is the same standard-library agent used for Linux
# (device_monitoring_prototype/device_agent_unix.py), frozen with PyInstaller
# and given a Tk window. It registers the devmonitor:// URL scheme so the
# website's "Link this device" button opens it with a one-use token.
#
# Requirements (on a Mac — PyInstaller cannot cross-compile from Windows/Linux):
#   * Python 3.11+ from python.org (its "universal2" build includes Tk and
#     produces an app that runs on both Apple Silicon and Intel Macs)
#   * Xcode Command Line Tools: xcode-select --install
# Optional, for a Gatekeeper-approved download (Apple Developer Program):
#   DEVELOPER_ID_APPLICATION="Developer ID Application: Your Name (TEAMID)"
#   NOTARY_PROFILE=devmonitor-notary   # created once with:
#     xcrun notarytool store-credentials devmonitor-notary --apple-id you@example.com --team-id TEAMID
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
APP_NAME="DevMonitor Agent"
DIST="$HERE/dist"
APP="$DIST/$APP_NAME.app"
DMG="$DIST/DevMonitor-Agent.dmg"
VERSION="1.0.0"
PYTHON="${PYTHON:-python3}"
ARCH="${TARGET_ARCH:-universal2}"

[[ "$(uname)" == "Darwin" ]] || { echo "This script must run on macOS." >&2; exit 1; }

"$PYTHON" -m venv "$HERE/.venv"
# shellcheck disable=SC1091
source "$HERE/.venv/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet "pyinstaller==6.17.0" "pillow>=10"
python -c "import tkinter" || { echo "This Python has no Tk. Use the python.org installer." >&2; exit 1; }

rm -rf "$HERE/build" "$DIST"
pyinstaller \
  --noconfirm --clean --windowed \
  --name "$APP_NAME" \
  --osx-bundle-identifier com.devmonitor.agent \
  --argv-emulation \
  --target-arch "$ARCH" \
  --icon "$ROOT/agents/shared/icon-1024.png" \
  --distpath "$DIST" --workpath "$HERE/build" --specpath "$HERE/build" \
  ${DEVELOPER_ID_APPLICATION:+--codesign-identity "$DEVELOPER_ID_APPLICATION"} \
  ${DEVELOPER_ID_APPLICATION:+--osx-entitlements-file "$HERE/entitlements.plist"} \
  "$ROOT/device_monitoring_prototype/device_agent_unix.py"

PLIST="$APP/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$VERSION" "$PLIST"
plutil -replace CFBundleVersion -string "$VERSION" "$PLIST"
plutil -replace LSMinimumSystemVersion -string "12.0" "$PLIST"
plutil -replace NSHumanReadableCopyright -string "DevMonitor Project" "$PLIST"
plutil -insert CFBundleURLTypes -json \
  '[{"CFBundleURLName":"com.devmonitor.agent.enroll","CFBundleURLSchemes":["devmonitor"]}]' "$PLIST"

# Editing Info.plist invalidates the signature, so (re)sign the bundle last.
if [[ -n "${DEVELOPER_ID_APPLICATION:-}" ]]; then
  codesign --force --deep --options runtime --timestamp \
    --entitlements "$HERE/entitlements.plist" \
    --sign "$DEVELOPER_ID_APPLICATION" "$APP"
else
  codesign --force --deep --sign - "$APP"
  echo "WARNING: ad-hoc signature only. Downloaded copies will be blocked by Gatekeeper" \
       "until the user chooses Open Anyway in System Settings > Privacy & Security." >&2
fi
codesign --verify --deep --strict --verbose=2 "$APP"

STAGING="$HERE/build/dmg"
rm -rf "$STAGING" && mkdir -p "$STAGING"
cp -R "$APP" "$STAGING/"
ln -s /Applications "$STAGING/Applications"
hdiutil create -volname "$APP_NAME" -srcfolder "$STAGING" -ov -format UDZO "$DMG"

if [[ -n "${DEVELOPER_ID_APPLICATION:-}" ]]; then
  codesign --force --timestamp --sign "$DEVELOPER_ID_APPLICATION" "$DMG"
fi
if [[ -n "${NOTARY_PROFILE:-}" ]]; then
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG"
  spctl --assess --type open --context context:primary-signature --verbose "$DMG"
fi

shasum -a 256 "$DMG"
echo "Built $DMG"
echo "Publish it by copying to device_monitoring_prototype/agent_packages/DevMonitor-Agent.dmg"
