#!/usr/bin/env bash
# Check that the packaged Mac app can make a verified HTTPS connection.
#
# The end-to-end enrollment test uses a local http:// backend, so it cannot
# catch a frozen app that has no trusted certificates. Here the app submits a
# dummy registration to a public HTTPS API that is not a DevMonitor server:
# the expected answer is an HTTP rejection (which proves TLS succeeded), never
# "could not be verified" / "Could not reach". No DevMonitor data is sent anywhere.
#
# Usage: check_macos_https.sh "/path/DevMonitor Agent.app"
set -uo pipefail

APP="$1"
TOKEN="cicheckcicheckcicheckcicheckcicheckcicheck"
LINK="devmonitor://enroll?server=https%3A%2F%2Fapi.github.com&token=$TOKEN"

output="$("$APP/Contents/MacOS/DevMonitor Agent" --yes --name "CI HTTPS check" "$LINK" 2>&1)"
echo "$output"

if grep -qE "could not be verified|Could not reach" <<<"$output"; then
  echo "::error::The packaged app could not make a verified HTTPS connection (missing CA certificates?)." >&2
  exit 1
fi
if ! grep -q "server rejected the registration" <<<"$output"; then
  echo "::error::Unexpected result from the HTTPS check; see the output above." >&2
  exit 1
fi
echo "HTTPS certificate verification works in the packaged app."
