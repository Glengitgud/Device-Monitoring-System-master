#!/usr/bin/env bash
# Archive the DevMonitor Agent iOS app and export a SIGNED .ipa.
#
#   METHOD=testflight ./build_ios.sh   # upload to App Store Connect -> TestFlight (recommended)
#   METHOD=ad-hoc     ./build_ios.sh   # .ipa for devices registered in your Ad Hoc profile
#
# Requirements (Apple does not allow any of this on Windows/Linux):
#   * A Mac with Xcode 15.3+ (export methods "app-store-connect" / "release-testing")
#     and XcodeGen (brew install xcodegen)
#   * Apple Developer Program membership (US$99/year)
#   * TEAM_ID=<your 10-character Team ID>
#   * Xcode signed in to that Apple ID (Xcode > Settings > Accounts) so
#     automatic signing can create the certificates and provisioning profiles.
#   * Ad Hoc only: the testers' iPhone/iPad UDIDs registered in the developer
#     portal (max 100 per device type per membership year).
#
# Publishing the result:
#   * testflight: after Beta App Review, enable a public link in App Store
#     Connect and set IOS_DISTRIBUTION_URL=https://testflight.apple.com/join/XXXX
#   * ad-hoc: copy build/export/DevMonitorAgent.ipa to
#     device_monitoring_prototype/agent_packages/DevMonitor-Agent.ipa. The site
#     offers it (via itms-services) only when it is served over HTTPS and the
#     IPA contains a valid, unexpired Ad Hoc or Enterprise profile.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
METHOD="${METHOD:-testflight}"
: "${TEAM_ID:?Set TEAM_ID to your Apple Developer Team ID}"
[[ "$(uname)" == "Darwin" ]] || { echo "This script must run on macOS with Xcode." >&2; exit 1; }

case "$METHOD" in
  testflight) EXPORT_OPTIONS="$HERE/ExportOptions-TestFlight.plist" ;;
  ad-hoc)     EXPORT_OPTIONS="$HERE/ExportOptions-AdHoc.plist" ;;
  *) echo "METHOD must be testflight or ad-hoc" >&2; exit 1 ;;
esac

# Non-interactive signing (CI): an App Store Connect API key lets xcodebuild
# create certificates/profiles without an Xcode account sign-in.
#   ASC_KEY_PATH=/path/AuthKey_XXXX.p8 ASC_KEY_ID=XXXX ASC_ISSUER_ID=uuid
AUTH_ARGS=()
if [[ -n "${ASC_KEY_PATH:-}" ]]; then
  : "${ASC_KEY_ID:?Set ASC_KEY_ID with ASC_KEY_PATH}" "${ASC_ISSUER_ID:?Set ASC_ISSUER_ID with ASC_KEY_PATH}"
  AUTH_ARGS=(-authenticationKeyPath "$ASC_KEY_PATH"
             -authenticationKeyID "$ASC_KEY_ID"
             -authenticationKeyIssuerID "$ASC_ISSUER_ID")
fi

cd "$HERE"
xcodegen generate
rm -rf build
xcodebuild \
  -project DevMonitorAgent.xcodeproj \
  -scheme DevMonitorAgent \
  -configuration Release \
  -destination "generic/platform=iOS" \
  -archivePath build/DevMonitorAgent.xcarchive \
  -allowProvisioningUpdates \
  ${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"} \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  archive

# Substitute the team into a temporary copy of the export options.
EXPORT_PLIST="build/ExportOptions.plist"
sed "s/__TEAM_ID__/$TEAM_ID/" "$EXPORT_OPTIONS" > "$EXPORT_PLIST"
xcodebuild \
  -exportArchive \
  -archivePath build/DevMonitorAgent.xcarchive \
  -exportOptionsPlist "$EXPORT_PLIST" \
  -exportPath build/export \
  -allowProvisioningUpdates \
  ${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}

if [[ "$METHOD" == "ad-hoc" ]]; then
  IPA="build/export/DevMonitorAgent.ipa"
  # An .ipa is a zip: verify the signature of the app bundle inside it.
  rm -rf build/ipa-check && mkdir -p build/ipa-check
  unzip -q "$IPA" -d build/ipa-check
  codesign --verify --deep --strict --verbose=2 build/ipa-check/Payload/*.app
  # Show which devices the embedded profile allows.
  unzip -p "$IPA" 'Payload/*.app/embedded.mobileprovision' \
    | security cms -D | plutil -extract ProvisionedDevices json -o - - || true
  shasum -a 256 "$IPA"
  echo "Signed Ad Hoc IPA: $HERE/$IPA"
else
  echo "Uploaded to App Store Connect. Finish in App Store Connect > TestFlight."
fi
