# DevMonitor Device Agents

Every agent follows the same protocol: it collects the device's specifications,
shows them to the user, and only after approval sends
`POST /api/device-agent/enroll` with `Authorization: Bearer <one-use token>`.
The server (`services.register_agent_device`) validates the payload, consumes
the token, and links the device to the token owner's account.

| Platform | Package | How the token arrives | Source | Built & verified here? |
|---|---|---|---|---|
| Windows 10/11 x64 | `.exe` (PyInstaller) | Embedded per download on a Windows host; otherwise the published generic `.exe` uses "Link this device" | `device_monitoring_prototype/device_agent.py` | Yes |
| Linux | `.deb` + portable `.tar.gz` | Embedded per download | `device_monitoring_prototype/device_agent_unix.py`, `linux_package.py` | Built + protocol-tested; not yet run on a real Linux machine |
| Android 8+ | signed `.apk` | "Link this device" (`devmonitor://enroll?...`) | `agents/android` | Built, signed, lint-clean, protocol-tested on JVM; not yet installed on a phone |
| macOS 12+ | `.dmg` with `.app` | "Link this device" | `device_agent_unix.py` + `agents/macos` | **No** – needs a Mac |
| iOS/iPadOS 16+ | TestFlight / App Store | "Link this device" | `agents/ios` | **No** – needs a Mac + Apple Developer Program |

Published packages are served from `device_monitoring_prototype/agent_packages/`
(git-ignored). A card on the Downloads page becomes available only when its
file exists there (or, for iOS, when `IOS_DISTRIBUTION_URL` is a TestFlight or
App Store link), so the website never offers a placeholder.

### Hosts without a disk or Windows (Vercel): publish to a GitHub Release

`.github/workflows/publish-agents.yml` ("Publish agents") builds the Windows
`.exe`, the signed Android `.apk` and the macOS `.dmg` on GitHub-hosted
machines, checks each with the validators in `package_validation.py`, and
uploads them with `agents-manifest.json` to the `agents-latest` release. It runs
when agent code changes on `master`, or from the **Actions** tab (*Run workflow*).

Point the website at it (for example in Vercel's environment variables):

```
AGENT_RELEASE_URL=https://github.com/OWNER/REPO/releases/download/agents-latest
```

A package in `agent_packages/` still takes priority. The release copy is used
only when no local file exists, and the card appears only when the manifest
lists it. On a non-Windows host the Windows card offers the generic `.exe`:
it contains no token, registers the `devmonitor://` link handler for the
current user on first run, and enrolls with the one-use link from
*Link this device* (or a pasted link), like the Android and macOS apps.

The Android job needs the release signing key as repository secrets
(*Settings → Secrets and variables → Actions*): `ANDROID_KEYSTORE_BASE64`
(the `.jks` file, base64), `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`,
`ANDROID_KEY_PASSWORD`. Without them the job is skipped and nothing is
published for Android. iOS is not published by this workflow (see below).

Phones and other computers cannot reach `127.0.0.1`. Set `PUBLIC_BASE_URL` to an
HTTPS address that the device can reach (a deployment, or a tunnel such as
Cloudflare Tunnel or ngrok during testing). iOS (App Transport Security) and
Android (network security config) refuse plain HTTP except to `localhost`.

---

## Linux

Nothing to build: the server generates the packages for each download.

Test on Ubuntu/Debian (VM, spare PC, live USB, or WSL):

```bash
sudo apt install ./devmonitor-agent_1.0.0_all.deb   # or: sudo dpkg -i ...
devmonitor-agent                                    # review, then type yes
dpkg -L devmonitor-agent                            # installed files
sudo apt remove devmonitor-agent
```

Other distributions: extract `devmonitor-agent-linux.tar.gz` and run
`./devmonitor-agent/devmonitor-agent` (needs Python 3.8+, present on most systems).

Collected: CPU model/cores, RAM total/used, mounted disks, GPUs (`lspci` or
DRM), board vendor/model (DMI), distribution and kernel, adapters, IPs, MAC.
No root access is required; fields a system does not expose are reported as
"Unavailable".

## Android

Requirements: Android Studio (or the Android SDK + JDK 17), this machine has both.

```powershell
cd agents\android
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
.\gradlew.bat assembleRelease
Copy-Item app\build\outputs\apk\release\app-release.apk ..\..\device_monitoring_prototype\agent_packages\devmonitor-agent.apk
```

Signing: the release key lives **outside the repository** in
`%USERPROFILE%\.devmonitor\` (`devmonitor-android-release.jks` and
`android-keystore.properties`). Back it up privately. If it is lost, installed
apps cannot be updated (users must uninstall first). Never commit it.

Test on a phone: enable Developer options → USB debugging, then

```powershell
$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
& $adb install -r app\build\outputs\apk\release\app-release.apk
& $adb reverse tcp:5000 tcp:5000   # phone's localhost:5000 -> this PC's Flask
```

then on the phone open `http://localhost:5000`, sign in, *Link a Device* →
*Link this device*. (An emulator needs CPU virtualization enabled in the BIOS.)

Installing from the website: users must allow their browser to "Install unknown
apps", and Play Protect may show a warning for apps outside Google Play.
Collected: SoC/CPU, cores, RAM total/used, internal storage, GPU (OpenGL
renderer), manufacturer/model, Android version, adapters, IPs. Not available to
apps: hardware MAC address (Android 10+), serial number.

## macOS

Requirements: a Mac (macOS 12+), Python 3.11+ from python.org, Xcode Command
Line Tools. PyInstaller cannot cross-compile, so this cannot be built on Windows.

```bash
bash agents/macos/build_macos.sh          # ad-hoc signed DMG (testing)
```

For a download that opens normally on other Macs you need the **Apple Developer
Program** (US$99/year): a *Developer ID Application* certificate plus
notarization. Then:

```bash
export DEVELOPER_ID_APPLICATION="Developer ID Application: Name (TEAMID)"
xcrun notarytool store-credentials devmonitor-notary --apple-id you@example.com --team-id TEAMID
export NOTARY_PROFILE=devmonitor-notary
bash agents/macos/build_macos.sh
```

Without notarization, macOS 15 users must try to open the app once, then choose
*System Settings → Privacy & Security → Open Anyway*.
Publish by copying `agents/macos/dist/DevMonitor-Agent.dmg` to
`device_monitoring_prototype/agent_packages/DevMonitor-Agent.dmg`; the card then
shows **Download .dmg**. The server checks the file really is an Apple disk
image (UDIF `koly` trailer) before offering it.
Collected: chip/CPU, cores, RAM total/used (`vm_stat`), data volume, GPUs,
model identifier, macOS version/build, adapters, IPs, MAC (en0).

## iOS / iPadOS

Requirements: a Mac with Xcode 15+, [XcodeGen](https://github.com/yonaskolb/XcodeGen),
and the **Apple Developer Program** (US$99/year) for anything beyond your own
test device.

```bash
cd agents/ios && xcodegen generate && open DevMonitorAgent.xcodeproj
```

Set your Team and a unique bundle identifier and run it on your own iPhone.
Then build a **signed** distribution with `agents/ios/build_ios.sh` (Xcode 15.3+):

```bash
TEAM_ID=ABCDE12345 METHOD=testflight bash agents/ios/build_ios.sh   # uploads to App Store Connect
TEAM_ID=ABCDE12345 METHOD=ad-hoc     bash agents/ios/build_ios.sh   # build/export/DevMonitorAgent.ipa
```

The website's iOS card supports both supported routes:

* **TestFlight / App Store (recommended, any user):** after Beta App Review,
  enable a public TestFlight link and set
  `IOS_DISTRIBUTION_URL=https://testflight.apple.com/join/XXXXXXXX`. The card
  shows **Get on TestFlight**.
* **`.ipa` over the air (Ad Hoc / Enterprise only):** copy the signed IPA to
  `device_monitoring_prototype/agent_packages/DevMonitor-Agent.ipa`. The card
  shows **Install .ipa** (an `itms-services://` link with a 15-minute signed
  manifest URL) only when the IPA contains an unexpired Ad Hoc or Enterprise
  profile **and** the site is served over HTTPS. App Store/TestFlight-signed,
  development-signed, expired or unsigned IPAs are detected and never offered,
  because iOS would refuse to install them. Ad Hoc installs work only on the
  devices whose UDIDs are in the profile.

Supported ways to put the app on other people's iPhones are App Store,
TestFlight (beta, up to 10,000 testers, builds expire after 90 days), Ad Hoc
(up to 100 registered devices per year) or Apple Business Manager custom apps.
An `.ipa` cannot be offered as a normal website download.

Platform limits: apps cannot read the MAC address, serial number, system-wide
memory usage or (iOS 16+) the user's device name. Apple's required-reason API
rules do not allow sending free/total disk space off the device, so the iOS
agent does not report storage.

## Building macOS and iOS without a Mac (GitHub Actions)

`.github/workflows/build-apple-agents.yml` runs on GitHub-hosted macOS runners.
Start it from the repository's **Actions** tab (*Run workflow*) after the
workflow file is pushed; it also runs on pull requests that touch the agents.

Without any secrets it:

* **macOS:** runs the agent on real macOS and validates what it detects with the
  server's own validator; builds a universal `DevMonitor Agent.app` and
  `DevMonitor-Agent.dmg`; mounts the DMG and checks the app, URL scheme,
  architectures and signature; then the packaged app **enrolls the runner Mac**
  against a throwaway backend (`agents/ci/ci_backend.py`, temporary SQLite) and
  a replayed link is refused. The DMG is uploaded as an artifact. It is
  ad-hoc signed, so Gatekeeper warns until it is Developer ID signed and
  notarized.
* **iOS:** generates the Xcode project, runs the XCTest suite in the iOS
  Simulator (link parsing, payload contract, on-device collection, and a **real
  enrollment** against the throwaway backend), and compiles for real devices
  without signing. No installable `.ipa` can be produced without Apple signing.

Add these repository secrets for distributable builds (Apple Developer Program):

| Secret | Used for |
|---|---|
| `MACOS_CERT_P12_BASE64`, `MACOS_CERT_PASSWORD`, `DEVELOPER_ID_APPLICATION` | Developer ID signing of the `.app`/`.dmg` |
| `NOTARY_APPLE_ID`, `NOTARY_TEAM_ID`, `NOTARY_APP_PASSWORD` | Apple notarization + stapling |
| `APPLE_TEAM_ID`, `ASC_KEY_ID`, `ASC_ISSUER_ID`, `ASC_KEY_P8_BASE64` | iOS archive signing; run the workflow with *ios_distribution* = `testflight` or `ad-hoc` |

Cost note: macOS runner minutes are free for public repositories; private
repositories use their plan's minutes at a higher macOS rate.
