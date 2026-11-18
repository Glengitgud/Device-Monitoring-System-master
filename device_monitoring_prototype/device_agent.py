"""Windows inventory agent template; server injects one-time enrollment credentials."""

import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import platform
import socket
import sys
import tempfile
import urllib.error
import urllib.request

import psutil


REGISTRATION_TOKEN = "__REGISTRATION_TOKEN__"
SUBMISSION_URL = "__SUBMISSION_URL__"
UNAVAILABLE = "Unavailable"
LOGGER = logging.getLogger("devmonitor.device_agent")
LOG_PATH = None

FIELD_LABELS = (
    ("CPU name", "cpu_name"),
    ("RAM capacity", "ram_capacity_bytes"),
    ("RAM usage", "ram_usage_bytes"),
    ("Number of CPU cores", "cpu_cores"),
    ("Storage devices", "storage_devices"),
    ("Total storage capacity", "storage_total_bytes"),
    ("Available storage capacity", "storage_available_bytes"),
    ("GPU information", "gpu_information"),
    ("Motherboard brand", "motherboard_brand"),
    ("Operating system name", "operating_system_name"),
    ("Operating system version", "operating_system_version"),
    ("Installed network adapters", "network_adapters"),
    ("IP address", "ip_addresses"),
)


def configure_logging():
    global LOG_PATH
    if LOGGER.handlers:
        return LOG_PATH

    log_directory = Path(
        os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
    ) / "DevMonitor" / "logs"
    try:
        log_directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        log_directory = Path(tempfile.gettempdir()) / "DevMonitor" / "logs"
        try:
            log_directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            LOGGER.addHandler(logging.StreamHandler(sys.stderr))
            LOGGER.setLevel(logging.INFO)
            LOGGER.propagate = False
            LOGGER.exception("Could not create the Device Agent log directory.")
            return None

    LOG_PATH = log_directory / "device-agent.log"
    try:
        handler = RotatingFileHandler(
            LOG_PATH,
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
    except OSError:
        LOG_PATH = None
        LOGGER.addHandler(logging.StreamHandler(sys.stderr))
        LOGGER.setLevel(logging.INFO)
        LOGGER.propagate = False
        LOGGER.exception("Could not open the Device Agent log file.")
        return None

    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    return LOG_PATH


def _read_registry_value(key_path, value_name):
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
        value, _ = winreg.QueryValueEx(key, value_name)
    return str(value).strip()


def _collect_cpu_name():
    try:
        value = _read_registry_value(
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "ProcessorNameString",
        )
        if value:
            return value
    except OSError:
        LOGGER.exception("CPU model registry lookup failed.")
    return platform.processor().strip() or UNAVAILABLE


def _collect_cpu_cores():
    return psutil.cpu_count(logical=False) or os.cpu_count()


def _collect_memory():
    memory = psutil.virtual_memory()
    return {
        "ram_capacity_bytes": int(memory.total),
        "ram_usage_bytes": int(memory.used),
    }


def _collect_storage():
    devices = []
    seen_mounts = set()
    for partition in psutil.disk_partitions(all=False):
        mount = partition.mountpoint
        if mount in seen_mounts:
            continue
        seen_mounts.add(mount)
        try:
            usage = psutil.disk_usage(mount)
        except (OSError, PermissionError):
            LOGGER.exception("Storage usage lookup failed for mount %s.", mount)
            continue
        devices.append(
            {
                "name": mount,
                "total_bytes": int(usage.total),
                "available_bytes": int(usage.free),
            }
        )
    return devices


def _collect_gpu_information():
    import winreg

    key_path = (
        r"SYSTEM\CurrentControlSet\Control\Class"
        r"\{4d36e968-e325-11ce-bfc1-08002be10318}"
    )
    names = []
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as graphics_key:
        index = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(graphics_key, index)
            except OSError:
                break
            index += 1
            try:
                with winreg.OpenKey(graphics_key, subkey_name) as device_key:
                    name, _ = winreg.QueryValueEx(device_key, "DriverDesc")
                name = str(name).strip()
                if name and name not in names:
                    names.append(name)
            except OSError:
                LOGGER.exception("GPU registry lookup failed for entry %s.", subkey_name)
    return names or [UNAVAILABLE]


def _collect_motherboard_brand():
    try:
        value = _read_registry_value(
            r"HARDWARE\DESCRIPTION\System\BIOS",
            "BaseBoardManufacturer",
        )
    except OSError:
        LOGGER.exception("Motherboard registry lookup failed.")
        return UNAVAILABLE
    return value or UNAVAILABLE


def _collect_operating_system():
    name = platform.system()
    version = platform.version()
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        ) as key:
            try:
                name, _ = winreg.QueryValueEx(key, "ProductName")
            except OSError:
                LOGGER.exception("Windows product-name registry value is unavailable.")
            try:
                version, _ = winreg.QueryValueEx(key, "DisplayVersion")
            except OSError:
                try:
                    version, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
                except OSError:
                    LOGGER.exception("Windows version registry value is unavailable.")
            try:
                build_number, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
                if str(name).startswith("Windows 10") and int(build_number) >= 22000:
                    name = "Windows 11"
            except (OSError, ValueError, TypeError):
                LOGGER.exception("Windows build number is unavailable.")
    except OSError:
        LOGGER.exception("Windows version registry lookup failed.")
    return {
        "operating_system_name": str(name).strip() or UNAVAILABLE,
        "operating_system_version": str(version).strip() or UNAVAILABLE,
    }


def _collect_network():
    addresses = psutil.net_if_addrs()
    adapters = sorted(name for name in addresses if name.strip())
    ip_addresses = set()
    for interface_addresses in addresses.values():
        for address in interface_addresses:
            if address.family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            candidate = address.address.split("%", 1)[0]
            try:
                parsed = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
                continue
            ip_addresses.add(str(parsed))
    return {
        "network_adapters": adapters or [UNAVAILABLE],
        "ip_addresses": sorted(ip_addresses),
    }


def _collect_component(name, collector, fallback):
    try:
        return collector()
    except Exception:
        LOGGER.exception("Specification collection failed for %s.", name)
        return fallback


def _show_log_location(log_path):
    if log_path:
        print(f"Diagnostic log: {log_path}")
    else:
        print("Diagnostic details were written to the console.", file=sys.stderr)


def collect_specifications():
    configure_logging()
    if os.name != "nt":
        raise RuntimeError("This agent supports Windows desktop and laptop devices only.")

    storage_devices = _collect_component(
        "storage devices", _collect_storage, []
    )
    specifications = {
        "cpu_name": _collect_component(
            "CPU name", _collect_cpu_name, UNAVAILABLE
        ),
        "cpu_cores": _collect_component(
            "CPU core count", _collect_cpu_cores, None
        ),
        "ram_capacity_bytes": None,
        "ram_usage_bytes": None,
        "storage_devices": storage_devices,
        "storage_total_bytes": sum(item["total_bytes"] for item in storage_devices),
        "storage_available_bytes": sum(
            item["available_bytes"] for item in storage_devices
        ),
        "gpu_information": _collect_component(
            "GPU information", _collect_gpu_information, [UNAVAILABLE]
        ),
        "motherboard_brand": _collect_component(
            "motherboard brand", _collect_motherboard_brand, UNAVAILABLE
        ),
        "operating_system_name": platform.system() or UNAVAILABLE,
        "operating_system_version": platform.version() or UNAVAILABLE,
        "network_adapters": [UNAVAILABLE],
        "ip_addresses": [],
    }

    memory = _collect_component("memory", _collect_memory, {})
    specifications.update(memory)
    os_information = _collect_component(
        "operating system", _collect_operating_system, {}
    )
    specifications.update(os_information)
    network = _collect_component("network", _collect_network, {})
    specifications.update(network)

    LOGGER.info(
        "Inventory collection completed; unavailable fields: %s",
        ", ".join(
            key
            for key, value in specifications.items()
            if value is None
            or value == UNAVAILABLE
            or value == [UNAVAILABLE]
        )
        or "none",
    )
    return specifications


def display_value(key, value):
    if value is None or value == "" or value == [UNAVAILABLE]:
        return UNAVAILABLE
    if key.endswith("_bytes") and isinstance(value, int):
        return f"{value:,} bytes ({value / (1024 ** 3):.2f} GiB)"
    if isinstance(value, list):
        return ", ".join(display_value(key, item) for item in value) or UNAVAILABLE
    if isinstance(value, dict):
        name = value.get("name", "Storage")
        total = display_value("total_bytes", value.get("total_bytes"))
        available = display_value("available_bytes", value.get("available_bytes"))
        return f"{name}: {total} total, {available} available"
    return str(value)


def main():
    log_path = configure_logging()
    try:
        specifications = collect_specifications()
    except RuntimeError as error:
        LOGGER.exception("Device inventory could not be collected.")
        print(f"Could not collect device information: {error}", file=sys.stderr)
        _show_log_location(log_path)
        return 1

    print("\nDetected device specifications (review before submission):")
    for label, key in FIELD_LABELS:
        value = specifications.get(key)
        if (
            key in {"storage_total_bytes", "storage_available_bytes"}
            and not specifications["storage_devices"]
        ):
            value = UNAVAILABLE
        print(f"  {label}: {display_value(key, value)}")
    _show_log_location(log_path)

    name = input(f"\nDevice name for DevMonitor [{platform.node()}]: ").strip()
    name = name or platform.node()
    if not name or len(name) > 120:
        print("Enter a device name between 1 and 120 characters.", file=sys.stderr)
        return 1
    while True:
        device_type = input("Device type (Desktop/Laptop): ").strip().title()
        if device_type in {"Desktop", "Laptop"}:
            break
        print("Choose Desktop or Laptop.")

    print("\nOnly the specifications listed above and your device name/type will be sent.")
    if input("Submit this device to your DevMonitor account? Type yes to confirm: ").strip().casefold() != "yes":
        print("Submission cancelled; no device was registered.")
        return 0

    try:
        request = urllib.request.Request(
            SUBMISSION_URL,
            data=json.dumps(
                {
                    "name": name,
                    "device_type": device_type,
                    "specifications": specifications,
                }
            ).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {REGISTRATION_TOKEN}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
        if not isinstance(result, dict) or "device_id" not in result:
            raise ValueError("The server returned an invalid registration response.")
    except urllib.error.HTTPError as error:
        LOGGER.exception("Device registration request failed with HTTP %s.", error.code)
        message = error.read().decode("utf-8", errors="replace")
        print(f"Registration failed ({error.code}): {message}", file=sys.stderr)
        _show_log_location(log_path)
        return 1
    except (
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        LOGGER.exception("Device registration could not be completed.")
        print(f"Could not register this device: {error}", file=sys.stderr)
        _show_log_location(log_path)
        return 1

    LOGGER.info("Device registration succeeded (device_id=%s).", result["device_id"])
    print(f"Device registered successfully (Device ID: {result['device_id']}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
