#!/usr/bin/env python3
"""DevMonitor Device Agent for Linux and macOS.

Standard library only, so it runs on any system with Python 3.8+:
* Linux packages (.deb / portable .tar.gz) are generated per download by the
  server, which injects a one-use registration token below.
* The macOS app is a generic signed build; it receives the token from a
  ``devmonitor://enroll?server=...&token=...`` "Link this device" link.

The agent shows what it detected and submits nothing until the user approves.
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REGISTRATION_TOKEN = "__REGISTRATION_TOKEN__"
SUBMISSION_URL = "__SUBMISSION_URL__"
# Website of the published macOS app (set by the release workflow). Without a link the
# app opens SERVER_URL/device-link/open, which hands it a link automatically.
SERVER_URL = "__SERVER_URL__"
LINK_OPEN_PATH = "/device-link/open"
AGENT_VERSION = "1.0.0"
UNAVAILABLE = "Unavailable"
LINK_SCHEME = "devmonitor"
ENROLL_PATH = "/api/device-agent/enroll"
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{40,64}")
MAC_PATTERN = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
LINUX_FILESYSTEMS = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "zfs",
    "vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "bcachefs",
}
# SMBIOS chassis types that describe portable machines.
PORTABLE_CHASSIS = {8, 9, 10, 11, 14, 30, 31, 32}
SPEC_LABELS = (
    ("Processor", "cpu_name"),
    ("CPU cores", "cpu_cores"),
    ("Memory", "ram_capacity_bytes"),
    ("Memory in use", "ram_usage_bytes"),
    ("Storage", "storage_devices"),
    ("Graphics", "gpu_information"),
    ("Motherboard", "motherboard_brand"),
    ("Operating system", "operating_system_name"),
    ("OS version", "operating_system_version"),
    ("Network adapters", "network_adapters"),
    ("IP addresses", "ip_addresses"),
    ("MAC address", "mac_address"),
)


class AgentError(Exception):
    """A problem the user can act on; the message is shown as-is."""


# --------------------------------------------------------------------------
# Enrollment details
# --------------------------------------------------------------------------

def _embedded(value):
    return "" if value.startswith("__") and value.endswith("__") else value


def validate_server_url(server):
    parsed = urllib.parse.urlsplit(server or "")
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise AgentError("The registration link does not contain a valid server address.")
    if parsed.scheme != "https" and parsed.hostname not in LOCAL_HOSTS:
        raise AgentError("For your security the DevMonitor server must use HTTPS.")
    return f"{parsed.scheme}://{parsed.netloc}"


def parse_enrollment_link(link):
    """Return (submission_url, token) from a devmonitor://enroll link."""
    parsed = urllib.parse.urlsplit((link or "").strip())
    if parsed.scheme != LINK_SCHEME or (parsed.netloc or parsed.path.strip("/")) != "enroll":
        raise AgentError("That is not a DevMonitor registration link.")
    query = urllib.parse.parse_qs(parsed.query)
    server = validate_server_url((query.get("server") or [""])[0])
    token = (query.get("token") or [""])[0]
    if not TOKEN_PATTERN.fullmatch(token):
        raise AgentError("The registration link is incomplete. Create a new link on the website.")
    return server + ENROLL_PATH, token


def link_open_url():
    """SERVER_URL/device-link/open for a build that knows its website, else ""."""
    server = _embedded(SERVER_URL)
    if not server:
        return ""
    try:
        return validate_server_url(server) + LINK_OPEN_PATH
    except AgentError:
        return ""


def embedded_enrollment():
    token = _embedded(REGISTRATION_TOKEN)
    url = _embedded(SUBMISSION_URL)
    if not token or not url:
        return None
    parsed = urllib.parse.urlsplit(url)
    server = validate_server_url(f"{parsed.scheme}://{parsed.netloc}")
    return server + ENROLL_PATH, token


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _run(command, timeout=8):
    if not shutil.which(command[0]):
        return ""
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _clean(value, limit=120):
    value = " ".join(str(value or "").split())
    return value[:limit] if value else None


def _safe(collector, fallback):
    try:
        value = collector()
    except Exception:  # noqa: BLE001 - one failing probe must not stop the rest
        return fallback
    return fallback if value in (None, "", []) else value


def _public_addresses(candidates):
    addresses = []
    for candidate in candidates:
        try:
            address = ipaddress.ip_address(str(candidate).split("%")[0])
        except ValueError:
            continue
        if address.is_loopback or address.is_link_local or address.is_unspecified:
            continue
        if str(address) not in addresses:
            addresses.append(str(address))
    return addresses


def _primary_address():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))  # TEST-NET: no packet is sent for UDP connect
        return probe.getsockname()[0]


def _normalise_mac(value):
    value = (value or "").strip()
    if MAC_PATTERN.fullmatch(value) and value not in {"00:00:00:00:00:00"}:
        return value.upper()
    return None


def _statvfs(path):
    # os.statvfs only exists on POSIX systems; resolved at call time.
    return os.statvfs(path)


def _storage_totals(storage_devices):
    return (
        sum(item["total_bytes"] for item in storage_devices),
        sum(item["available_bytes"] for item in storage_devices),
    )


# --------------------------------------------------------------------------
# Linux collectors
# --------------------------------------------------------------------------

class LinuxCollector:
    def __init__(self, root="/", run=_run, statvfs=_statvfs):
        self.root = Path(root)
        self.run = run
        self.statvfs = statvfs

    def path(self, relative):
        return self.root / relative

    def cpu(self):
        cpuinfo = _read(self.path("proc/cpuinfo"))
        name = None
        for key in ("model name", "Hardware", "Model", "cpu model"):
            match = re.search(rf"^{key}\s*:\s*(.+)$", cpuinfo, re.M)
            if match:
                name = _clean(match.group(1), 255)
                break
        cores = len(re.findall(r"^processor\s*:", cpuinfo, re.M)) or os.cpu_count()
        return name, cores

    def memory(self):
        meminfo = _read(self.path("proc/meminfo"))
        values = {
            key: int(amount) * 1024
            for key, amount in re.findall(r"^(\w+):\s+(\d+)\s*kB", meminfo, re.M)
        }
        total = values.get("MemTotal")
        available = values.get("MemAvailable", values.get("MemFree"))
        if not total:
            return None, None
        used = total - available if available is not None else None
        return total, max(0, min(used, total)) if used is not None else None

    def storage(self):
        devices, seen = [], set()
        for line in _read(self.path("proc/mounts")).splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mountpoint, fstype = parts[0], parts[1], parts[2]
            mountpoint = mountpoint.replace("\\040", " ")
            if (
                fstype not in LINUX_FILESYSTEMS
                or not device.startswith("/dev/")
                or device.startswith("/dev/loop")
                or device in seen
            ):
                continue
            try:
                stats = self.statvfs(mountpoint)
            except OSError:
                continue
            total = stats.f_blocks * stats.f_frsize
            available = min(stats.f_bavail * stats.f_frsize, total)
            if total <= 0:
                continue
            seen.add(device)
            name = f"{mountpoint} ({device.rsplit('/', 1)[-1]})"
            devices.append({"name": name[:128], "total_bytes": total, "available_bytes": available})
        return devices[:64]

    def gpus(self):
        names = []
        for line in self.run(["lspci"]).splitlines():
            if re.search(r"VGA compatible controller|3D controller|Display controller", line):
                names.append(_clean(line.split(": ", 1)[-1], 255))
        if not names:
            vendors = {"0x10de": "NVIDIA", "0x1002": "AMD", "0x8086": "Intel", "0x1af4": "Virtio"}
            for card in sorted(self.path("sys/class/drm").glob("card[0-9]")):
                vendor = _read(card / "device" / "vendor").lower()
                if vendor:
                    names.append(f"{vendors.get(vendor, vendor)} graphics")
        return [name for name in dict.fromkeys(names) if name][:32]

    def motherboard(self):
        dmi = self.path("sys/class/dmi/id")
        vendor = _read(dmi / "board_vendor") or _read(dmi / "sys_vendor")
        model = _read(dmi / "board_name") or _read(dmi / "product_name")
        return _clean(" ".join(part for part in (vendor, model) if part))

    def operating_system(self):
        release = {}
        for line in _read(self.path("etc/os-release")).splitlines():
            key, _, value = line.partition("=")
            release[key.strip()] = value.strip().strip('"')
        name = release.get("NAME") or "Linux"
        version = release.get("VERSION") or release.get("VERSION_ID") or ""
        kernel = _read(self.path("proc/sys/kernel/osrelease"))
        detail = f"{version} (kernel {kernel})" if kernel else version
        return _clean(name), _clean(detail.strip(), 255)

    def network(self):
        adapters, mac = [], None
        net = self.path("sys/class/net")
        for interface in sorted(net.glob("*")) if net.exists() else []:
            if interface.name == "lo":
                continue
            adapters.append(interface.name[:128])
            # Physical adapters have a "device" link; virtual bridges do not.
            if mac is None and (interface / "device").exists():
                mac = _normalise_mac(_read(interface / "address"))
        addresses = []
        output = self.run(["ip", "-j", "addr"])
        if output:
            try:
                for interface in json.loads(output):
                    addresses.extend(item.get("local") for item in interface.get("addr_info", []))
            except (ValueError, AttributeError, TypeError):
                addresses = []
        if not addresses:
            addresses = [_safe(_primary_address, "")]
        return adapters[:64], _public_addresses(addresses)[:64], mac

    def device_type(self):
        chassis = _read(self.path("sys/class/dmi/id/chassis_type"))
        return "Laptop" if chassis.isdigit() and int(chassis) in PORTABLE_CHASSIS else "Desktop"

    def collect(self):
        cpu_name, cores = _safe(self.cpu, (None, os.cpu_count()))
        ram_total, ram_used = _safe(self.memory, (None, None))
        storage = _safe(self.storage, [])
        adapters, addresses, mac = _safe(self.network, ([], [], None))
        os_name, os_version = _safe(self.operating_system, ("Linux", None))
        storage_total, storage_available = _storage_totals(storage)
        return {
            "cpu_name": cpu_name or _clean(platform.processor(), 255) or UNAVAILABLE,
            "cpu_cores": cores,
            "ram_capacity_bytes": ram_total,
            "ram_usage_bytes": ram_used,
            "storage_devices": storage,
            "storage_total_bytes": storage_total,
            "storage_available_bytes": storage_available,
            "gpu_information": _safe(self.gpus, [UNAVAILABLE]),
            "motherboard_brand": _safe(self.motherboard, UNAVAILABLE),
            "operating_system_name": os_name,
            "operating_system_version": os_version,
            "network_adapters": adapters or [UNAVAILABLE],
            "ip_addresses": addresses,
            "mac_address": mac,
        }


# --------------------------------------------------------------------------
# macOS collectors
# --------------------------------------------------------------------------

class MacCollector:
    def __init__(self, run=_run, statvfs=_statvfs, exists=os.path.exists):
        self.run = run
        self.statvfs = statvfs
        self.exists = exists
        self._hardware = None

    def sysctl(self, key):
        return self.run(["sysctl", "-n", key]).strip()

    def hardware(self):
        if self._hardware is None:
            try:
                items = json.loads(self.run(["system_profiler", "-json", "SPHardwareDataType"], 20))
                self._hardware = items["SPHardwareDataType"][0]
            except (ValueError, KeyError, IndexError, TypeError):
                self._hardware = {}
        return self._hardware

    def cpu(self):
        name = self.sysctl("machdep.cpu.brand_string") or self.hardware().get("chip_type")
        cores = self.sysctl("hw.ncpu")
        return _clean(name, 255), int(cores) if cores.isdigit() else os.cpu_count()

    def memory(self):
        total = self.sysctl("hw.memsize")
        if not total.isdigit():
            return None, None
        total = int(total)
        vm_stat = self.run(["vm_stat"])
        page = re.search(r"page size of (\d+) bytes", vm_stat)
        counts = {
            key.strip(): int(value)
            for key, value in re.findall(r"^([^:\n]+):\s+(\d+)\.", vm_stat, re.M)
        }
        if not page:
            return total, None
        used_pages = sum(
            counts.get(key, 0)
            for key in ("Pages active", "Pages wired down", "Pages occupied by compressor")
        )
        return total, min(used_pages * int(page.group(1)), total)

    def storage(self):
        # On APFS the user's data lives on the Data volume of the boot disk.
        mount = "/System/Volumes/Data" if self.exists("/System/Volumes/Data") else "/"
        stats = self.statvfs(mount)
        total = stats.f_blocks * stats.f_frsize
        available = min(stats.f_bavail * stats.f_frsize, total)
        return [{"name": "Macintosh HD", "total_bytes": total, "available_bytes": available}]

    def gpus(self):
        try:
            items = json.loads(self.run(["system_profiler", "-json", "SPDisplaysDataType"], 20))
            names = [item.get("sppci_model") for item in items["SPDisplaysDataType"]]
        except (ValueError, KeyError, TypeError):
            return []
        return [_clean(name, 255) for name in names if name][:32]

    def motherboard(self):
        model = self.hardware().get("machine_model") or self.sysctl("hw.model")
        return _clean(f"Apple {model}" if model else "Apple")

    def operating_system(self):
        version = self.run(["sw_vers", "-productVersion"]).strip()
        build = self.run(["sw_vers", "-buildVersion"]).strip()
        name = self.run(["sw_vers", "-productName"]).strip() or "macOS"
        return _clean(name), _clean(f"{version} ({build})" if build else version, 255)

    def network(self):
        adapters, candidates, mac, current = [], [], None, None
        for line in self.run(["ifconfig"]).splitlines():
            header = re.match(r"^([A-Za-z0-9]+):\s+flags=", line)
            if header:
                current = header.group(1)
                if not current.startswith(("lo", "gif", "stf", "utun", "awdl", "llw", "anpi", "ap")):
                    adapters.append(current)
                continue
            line = line.strip()
            if current and line.startswith(("inet ", "inet6 ")):
                candidates.append(line.split()[1])
            elif current == "en0" and line.startswith("ether "):
                mac = _normalise_mac(line.split()[1])
        return list(dict.fromkeys(adapters))[:64], _public_addresses(candidates)[:64], mac

    def device_type(self):
        name = self.hardware().get("machine_name", "")
        return "Laptop" if "MacBook" in name else "Desktop"

    def collect(self):
        cpu_name, cores = _safe(self.cpu, (None, os.cpu_count()))
        ram_total, ram_used = _safe(self.memory, (None, None))
        storage = _safe(self.storage, [])
        adapters, addresses, mac = _safe(self.network, ([], [], None))
        os_name, os_version = _safe(self.operating_system, ("macOS", None))
        storage_total, storage_available = _storage_totals(storage)
        return {
            "cpu_name": cpu_name or UNAVAILABLE,
            "cpu_cores": cores,
            "ram_capacity_bytes": ram_total,
            "ram_usage_bytes": ram_used,
            "storage_devices": storage,
            "storage_total_bytes": storage_total,
            "storage_available_bytes": storage_available,
            "gpu_information": _safe(self.gpus, [UNAVAILABLE]),
            "motherboard_brand": _safe(self.motherboard, "Apple"),
            "operating_system_name": os_name,
            "operating_system_version": os_version,
            "network_adapters": adapters or [UNAVAILABLE],
            "ip_addresses": addresses,
            "mac_address": mac,
        }


def collector_for_this_system():
    if sys.platform == "darwin":
        return MacCollector()
    if sys.platform.startswith("linux"):
        return LinuxCollector()
    raise AgentError("This agent supports Linux and macOS. Use the Windows agent on Windows.")


# --------------------------------------------------------------------------
# Submission
# --------------------------------------------------------------------------

def submit_registration(submission_url, token, payload, opener=urllib.request.urlopen):
    request = urllib.request.Request(
        submission_url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"DevMonitorAgent/{AGENT_VERSION} ({platform.system()})",
        },
    )
    host = urllib.parse.urlsplit(submission_url).netloc
    try:
        with opener(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as error:
        try:
            message = json.loads(error.read().decode("utf-8")).get("error")
        except (ValueError, AttributeError):
            message = None
        if error.code == 401:
            raise AgentError(
                "This registration link has expired or was already used. "
                "Create a new one on the DevMonitor website and try again."
            ) from error
        raise AgentError(message or f"The server rejected the registration (HTTP {error.code}).") from error
    except ssl.SSLError as error:
        raise AgentError(f"The secure connection to {host} could not be verified.") from error
    except (urllib.error.URLError, TimeoutError, ConnectionError, socket.timeout) as error:
        raise AgentError(
            f"Could not reach the DevMonitor server at {host}. "
            "Check your internet connection and try again."
        ) from error


def build_payload(name, device_type, specifications):
    specifications = dict(specifications)
    mac = _normalise_mac(specifications.get("mac_address") or "")
    if mac:
        specifications["mac_address"] = mac
    else:
        specifications.pop("mac_address", None)
    return {"name": name[:120], "device_type": device_type, "specifications": specifications}


def describe(key, value):
    if value in (None, [], ""):
        return UNAVAILABLE
    if key.endswith("_bytes"):
        return f"{value / 1024 ** 3:.1f} GB"
    if key == "storage_devices":
        return "; ".join(
            f"{item['name']}: {item['available_bytes'] / 1024 ** 3:.1f} GB free of "
            f"{item['total_bytes'] / 1024 ** 3:.1f} GB"
            for item in value
        )
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def summary_lines(specifications):
    return [f"{label}: {describe(key, specifications.get(key))}" for label, key in SPEC_LABELS]


# --------------------------------------------------------------------------
# User interfaces
# --------------------------------------------------------------------------

def run_console(enrollment, collector, assume_yes=False, name=None):
    submission_url, token = enrollment
    print(f"DevMonitor Device Agent {AGENT_VERSION}")
    print(f"Server: {urllib.parse.urlsplit(submission_url).netloc}\n")
    print("Detected specifications:")
    specifications = collector.collect()
    for line in summary_lines(specifications):
        print(f"  {line}")
    default_name = socket.gethostname() or "My device"
    device_type = collector.device_type()
    if not assume_yes:
        name = input(f"\nDevice name [{default_name}]: ").strip() or default_name
        choice = input(f"Device type (Desktop/Laptop) [{device_type}]: ").strip().title()
        device_type = choice if choice in {"Desktop", "Laptop"} else device_type
        if input("Submit this device to your DevMonitor account? Type yes to confirm: ").strip().casefold() != "yes":
            print("Nothing was submitted.")
            return 1
    result = submit_registration(
        submission_url, token, build_payload(name or default_name, device_type, specifications)
    )
    print(f"\nRegistered \"{result.get('name', name)}\" (asset {result.get('asset_tag', '-')}).")
    print("Return to the DevMonitor website: your dashboard is now available.")
    return 0


def run_gui(enrollment, collector):  # pragma: no cover - needs a display
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title("DevMonitor Device Agent")
    root.minsize(520, 460)
    frame = ttk.Frame(root, padding=18)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="DevMonitor Device Agent", font=("", 16, "bold")).pack(anchor="w")
    status = tk.StringVar()
    state = {"enrollment": enrollment, "specifications": None}

    link_frame = ttk.Frame(frame)
    link_var = tk.StringVar()
    website = link_open_url()

    def open_website():
        import webbrowser

        try:
            webbrowser.open(website, new=2)
        except webbrowser.Error:
            status.set("Could not open the browser. Paste the link from the website instead.")

    ttk.Label(
        link_frame,
        wraplength=480,
        text=(
            "Linking this Mac to your DevMonitor account: your browser opens the "
            "DevMonitor website (sign in if asked). When it asks to open DevMonitor "
            "Agent, choose Open. Nothing happened? Paste the link shown on the website:"
            if website else
            "Open the DevMonitor website on this computer, go to Device Verification "
            "and click “Link this device”. You can also paste the link here:"
        ),
    ).pack(anchor="w", pady=(8, 4))
    if website:
        ttk.Button(link_frame, text="Open the DevMonitor website", command=open_website).pack(
            anchor="w", pady=(0, 6)
        )
    ttk.Entry(link_frame, textvariable=link_var).pack(fill="x")

    details = tk.Text(frame, height=13, width=64, wrap="word", relief="flat")
    name_var = tk.StringVar(value=socket.gethostname() or "My Mac")
    form = ttk.Frame(frame)
    ttk.Label(form, text="Device name").grid(row=0, column=0, sticky="w")
    ttk.Entry(form, textvariable=name_var, width=36).grid(row=0, column=1, sticky="we", padx=8)
    button = ttk.Button(frame, text="Register This Device")

    def show_details():
        server = urllib.parse.urlsplit(state["enrollment"][0]).netloc
        state["specifications"] = collector.collect()
        details.configure(state="normal")
        details.delete("1.0", "end")
        details.insert("end", f"Server: {server}\n\n" + "\n".join(summary_lines(state["specifications"])))
        details.configure(state="disabled")
        link_frame.pack_forget()
        details.pack(fill="both", expand=True, pady=10)
        form.pack(fill="x")
        status.set("Review the details, then select Register This Device.")

    def register():
        if state["enrollment"] is None:
            try:
                state["enrollment"] = parse_enrollment_link(link_var.get())
            except AgentError as error:
                status.set(str(error))
                return
            show_details()
            return
        button.state(["disabled"])
        status.set("Registering...")
        root.update_idletasks()
        try:
            result = submit_registration(
                state["enrollment"][0],
                state["enrollment"][1],
                build_payload(name_var.get().strip() or "My Mac", collector.device_type(), state["specifications"]),
            )
        except AgentError as error:
            status.set(str(error))
            button.state(["!disabled"])
            return
        status.set(f"Registered “{result.get('name', '')}”. Return to the website to open your dashboard.")
        button.configure(text="Close", command=root.destroy)
        button.state(["!disabled"])

    def receive_link(*urls):
        """macOS delivers devmonitor:// links to the running app as an Apple event."""
        if state["enrollment"] is not None or state["specifications"] is not None:
            return
        for url in urls:
            try:
                state["enrollment"] = parse_enrollment_link(url)
            except AgentError as error:
                status.set(str(error))
                continue
            button.configure(text="Register This Device")
            show_details()
            root.deiconify()
            root.lift()
            return

    if sys.platform == "darwin":
        root.createcommand("::tk::mac::LaunchURL", receive_link)

    button.configure(command=register)
    if enrollment is None:
        link_frame.pack(fill="x")
        button.configure(text="Continue")
        if website:
            root.after(400, open_website)
    else:
        show_details()
    button.pack(anchor="e", pady=(12, 0))
    ttk.Label(frame, textvariable=status, wraplength=480, foreground="#334").pack(anchor="w", pady=(10, 0))
    root.mainloop()
    return 0


def resolve_enrollment(link):
    if link:
        return parse_enrollment_link(link)
    return embedded_enrollment()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Register this computer with DevMonitor.")
    parser.add_argument("link", nargs="?", help="devmonitor://enroll link from the website")
    parser.add_argument("--yes", action="store_true", help="submit without prompting")
    parser.add_argument("--name", help="device name to use with --yes")
    parser.add_argument("--version", action="version", version=AGENT_VERSION)
    parser.add_argument(
        "--print-specs",
        action="store_true",
        help="print the detected specifications as JSON and exit (nothing is sent)",
    )
    # macOS may pass a process serial number argument when launching apps.
    args, _unknown = parser.parse_known_args(argv)
    try:
        collector = collector_for_this_system()
        if args.print_specs:
            print(json.dumps(
                {"device_type": collector.device_type(), "specifications": collector.collect()},
                indent=2,
            ))
            return 0
        enrollment = resolve_enrollment(args.link)
        interactive_console = sys.stdin is not None and sys.stdin.isatty()
        if enrollment is not None and (interactive_console or args.yes):
            return run_console(enrollment, collector, assume_yes=args.yes, name=args.name)
        try:
            return run_gui(enrollment, collector)
        except ImportError:
            if enrollment is None:
                raise AgentError(
                    "No registration link was provided. Run: devmonitor-agent "
                    "'devmonitor://enroll?...' (copy the link from the website)."
                )
            raise AgentError("Run this agent from a terminal to register the device.")
    except AgentError as error:
        print(f"\nError: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled. Nothing was submitted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
