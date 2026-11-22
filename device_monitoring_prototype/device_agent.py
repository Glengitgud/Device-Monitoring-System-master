"""Windows inventory agent.

Two builds come from this file:

* Per-download: a Windows server injects a one-use registration token below.
* Generic (published by CI): no token inside. It registers the ``devmonitor://``
  link handler for the current user and enrolls with the one-use
  ``devmonitor://enroll?server=...&token=...`` link from "Link this device",
  passed on the command line or pasted when asked.
"""

import argparse
import hmac
import ipaddress
import ctypes
import ctypes.wintypes
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import platform
import queue
import re
import secrets
import socket
import ssl
import sys
import tempfile
import threading
from datetime import datetime
import urllib.error
from urllib.parse import parse_qs, urlsplit
import urllib.request
import webbrowser

import psutil


REGISTRATION_TOKEN = "__REGISTRATION_TOKEN__"
SUBMISSION_URL = "__SUBMISSION_URL__"
SCAN_RUN_ID = "__SCAN_RUN_ID__"
SCAN_TOKEN = "__SCAN_TOKEN__"
DASHBOARD_URL = "__DASHBOARD_URL__"
# Website of the published generic build (set by the release workflow). When the
# agent has no link it opens SERVER_URL/device-link/open, which links it automatically.
SERVER_URL = "__SERVER_URL__"
LINK_OPEN_PATH = "/device-link/open"
AGENT_VERSION = "1.0.0"
LINK_SCHEME = "devmonitor"
ENROLL_PATH = "/api/device-agent/enroll"
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{40,64}")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
UNAVAILABLE = "Unavailable"
LOGGER = logging.getLogger("devmonitor.device_agent")
LOG_PATH = None
HEALTH_COLORS = (
    (80, "#16a34a", "Excellent"),
    (60, "#eab308", "Warning"),
    (40, "#f97316", "Attention Needed"),
    (0, "#dc2626", "Critical"),
)

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
    ("MAC address", "mac_address"),
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
    mac_addresses = []
    link_family = getattr(psutil, "AF_LINK", None)
    for interface_addresses in addresses.values():
        for address in interface_addresses:
            if link_family is not None and address.family == link_family:
                candidate = address.address.strip().replace("-", ":")
                if (
                    re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", candidate)
                    and candidate != "00:00:00:00:00:00"
                ):
                    mac_addresses.append(candidate.upper())
                continue
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
        "mac_address": sorted(set(mac_addresses))[0] if mac_addresses else None,
    }


def _collect_component(name, collector, fallback):
    try:
        return collector()
    except Exception:
        LOGGER.exception("Specification collection failed for %s.", name)
        return fallback


def _show_log_location(log_path):
    if log_path:
        print(f"Device Agent log: {log_path}")
    else:
        print("Device Agent details were written to the console.", file=sys.stderr)


def _unavailable_specification_fields(specifications):
    unavailable = []
    for key, value in specifications.items():
        if (
            value is None
            or value == UNAVAILABLE
            or value == [UNAVAILABLE]
            or (key in {"storage_devices", "ip_addresses"} and not value)
        ):
            unavailable.append(key)
    return unavailable


def _health_band(score):
    if score is None:
        return "#64748b", "Not assessed"
    for minimum, color, label in HEALTH_COLORS:
        if score >= minimum:
            return color, label
    return HEALTH_COLORS[-1][1], HEALTH_COLORS[-1][2]


def _score_from_usage(usage):
    if usage <= 40:
        return 100
    if usage <= 60:
        return 90
    if usage <= 75:
        return 80
    if usage <= 85:
        return 65
    if usage <= 95:
        return 50
    return 30


def _score_from_free_space(percent_free):
    if percent_free >= 30:
        return 100
    if percent_free >= 20:
        return 90
    if percent_free >= 10:
        return 70
    if percent_free >= 5:
        return 50
    return 30


def _collect_cpu_temperature():
    sensor_reader = getattr(psutil, "sensors_temperatures", None)
    if sensor_reader is None:
        return None
    sensors = sensor_reader(fahrenheit=False)
    readings = [
        float(entry.current)
        for entries in sensors.values()
        for entry in entries
        if entry.current is not None
    ]
    return max(readings) if readings else None


def _collect_driver_information():
    import winreg

    classes = {
        "display": r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}",
        "network": r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}",
    }
    drivers = []
    for category, key_path in classes.items():
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as root:
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(root, index)
                    except OSError:
                        break
                    index += 1
                    if not subkey_name.isdigit():
                        continue
                    try:
                        with winreg.OpenKey(root, subkey_name) as driver_key:
                            name = winreg.QueryValueEx(driver_key, "DriverDesc")[0]
                            try:
                                driver_date = winreg.QueryValueEx(
                                    driver_key, "DriverDate"
                                )[0]
                            except OSError:
                                driver_date = None
                            try:
                                version = winreg.QueryValueEx(
                                    driver_key, "DriverVersion"
                                )[0]
                            except OSError:
                                version = None
                        if name:
                            drivers.append(
                                {
                                    "category": category,
                                    "name": str(name).strip()[:255],
                                    "date": str(driver_date).strip()[:32]
                                    if driver_date
                                    else None,
                                    "version": str(version).strip()[:64]
                                    if version
                                    else None,
                                }
                            )
                    except OSError:
                        LOGGER.exception(
                            "Driver metadata lookup failed for %s entry %s.",
                            category,
                            subkey_name,
                        )
        except OSError:
            LOGGER.exception("Could not inspect %s driver metadata.", category)
    return drivers


def _collect_windows_services():
    services = {}
    for name in ("RpcSs", "EventLog", "Winmgmt", "Dnscache", "WinDefend", "MpsSvc"):
        try:
            services[name] = psutil.win_service_get(name).status()
        except (psutil.Error, OSError):
            LOGGER.exception("Could not inspect Windows service %s.", name)
            services[name] = None
    return services


def _check_submission_connectivity():
    """Find whether a connection failure is DNS, TCP, TLS, or a bad endpoint path."""
    try:
        parsed = urlsplit(SUBMISSION_URL)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            return {"ok": False, "stage": "configuration", "message": "The agent URL is invalid."}
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        return {"ok": False, "stage": "configuration", "message": str(error)}

    try:
        addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except OSError as error:
        LOGGER.warning("DevMonitor host name resolution failed: %s", error)
        return {
            "ok": False,
            "stage": "dns",
            "message": f"Could not resolve {parsed.hostname}: {error}",
        }
    if not addresses:
        return {
            "ok": False,
            "stage": "dns",
            "message": f"No network address was returned for {parsed.hostname}.",
        }

    try:
        connection = socket.create_connection((parsed.hostname, port), timeout=4)
    except OSError as error:
        LOGGER.warning("DevMonitor TCP connection failed (%s:%s): %s", parsed.hostname, port, error)
        return {
            "ok": False,
            "stage": "tcp",
            "message": f"Could not connect to {parsed.hostname}:{port}: {error}",
        }

    try:
        if parsed.scheme == "https":
            try:
                connection = ssl.create_default_context().wrap_socket(
                    connection, server_hostname=parsed.hostname
                )
            except (ssl.SSLError, OSError) as error:
                LOGGER.warning("DevMonitor TLS validation failed: %s", error)
                return {
                    "ok": False,
                    "stage": "tls",
                    "message": (
                        f"HTTPS negotiation failed for {parsed.hostname}:{port}: {error}. "
                        "The port, protocol, or server certificate may not match."
                    ),
                }
    finally:
        connection.close()

    try:
        request = urllib.request.Request(
            SUBMISSION_URL, method="GET", headers={"User-Agent": "DevMonitor-Diagnostics"}
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        LOGGER.warning("DevMonitor endpoint request failed: %s", error)
        return {
            "ok": False,
            "stage": "endpoint",
            "message": f"The server could not be reached at the configured path: {error}",
        }
    if status == 404 or status >= 500:
        return {
            "ok": False,
            "stage": "endpoint",
            "message": (
                f"The server returned HTTP {status} for the configured endpoint. "
                "The path may be incorrect or the application service may have failed."
            ),
        }
    return {"ok": True, "stage": "complete", "message": f"Server responded (HTTP {status})."}


def _collect_windows_device_problems():
    """Return Plug-and-Play problem codes reported by Windows for present devices."""
    if os.name != "nt":
        return None

    class DeviceInfoData(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.wintypes.DWORD),
            ("ClassGuid", ctypes.c_byte * 16),
            ("DevInst", ctypes.wintypes.DWORD),
            ("Reserved", ctypes.c_size_t),
        ]

    setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
    cfgmgr = ctypes.WinDLL("CfgMgr32", use_last_error=True)
    setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
    setupapi.SetupDiGetClassDevsW.argtypes = [
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.wintypes.DWORD
    ]
    setupapi.SetupDiEnumDeviceInfo.argtypes = [
        ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(DeviceInfoData)
    ]
    setupapi.SetupDiEnumDeviceInfo.restype = ctypes.wintypes.BOOL
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
    cfgmgr.CM_Get_DevNode_Status.argtypes = [
        ctypes.POINTER(ctypes.wintypes.DWORD),
        ctypes.POINTER(ctypes.wintypes.DWORD),
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
    ]
    cfgmgr.CM_Get_DevNode_Status.restype = ctypes.wintypes.ULONG
    setupapi.SetupDiGetDeviceRegistryPropertyW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(DeviceInfoData), ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p,
        ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD),
    ]
    setupapi.SetupDiGetDeviceRegistryPropertyW.restype = ctypes.wintypes.BOOL

    info_set = setupapi.SetupDiGetClassDevsW(None, None, None, 0x2 | 0x4)
    if info_set == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "Could not enumerate Windows devices.")
    problems = []
    try:
        index = 0
        while index < 4096:
            data = DeviceInfoData()
            data.cbSize = ctypes.sizeof(DeviceInfoData)
            if not setupapi.SetupDiEnumDeviceInfo(info_set, index, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error == 259:
                    break
                raise OSError(error, "Could not read Windows device status.")
            index += 1
            status = ctypes.wintypes.DWORD()
            problem = ctypes.wintypes.DWORD()
            result = cfgmgr.CM_Get_DevNode_Status(
                ctypes.byref(status), ctypes.byref(problem), data.DevInst, 0
            )
            if result != 0 or problem.value == 0:
                continue
            required_size = ctypes.wintypes.DWORD()
            device_name = "Unknown device"
            for property_id in (0xC, 0):
                setupapi.SetupDiGetDeviceRegistryPropertyW(
                    info_set, ctypes.byref(data), property_id, None, None, 0,
                    ctypes.byref(required_size),
                )
                if required_size.value == 0:
                    continue
                buffer = ctypes.create_unicode_buffer(
                    max(1, (required_size.value + ctypes.sizeof(ctypes.c_wchar) - 1)
                        // ctypes.sizeof(ctypes.c_wchar))
                )
                if setupapi.SetupDiGetDeviceRegistryPropertyW(
                    info_set, ctypes.byref(data), property_id, None,
                    ctypes.cast(buffer, ctypes.c_void_p), ctypes.sizeof(buffer),
                    ctypes.byref(required_size),
                ):
                    device_name = buffer.value.strip() or device_name
                    break
            problems.append({"name": device_name[:160], "code": int(problem.value)})
            if len(problems) >= 100:
                break
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(info_set)
    return problems


def _device_problem_description(code):
    descriptions = {
        1: "device is not configured correctly",
        10: "device could not start",
        12: "device has a resource conflict",
        22: "device is disabled",
        28: "device driver is missing",
        31: "Windows could not load the required driver",
        43: "Windows stopped the device after reporting a problem",
        45: "device is not currently connected",
        48: "driver is blocked",
        52: "Windows could not verify the driver signature",
    }
    return descriptions.get(code, f"Windows reported device problem code {code}")


def _health_gauges(scores):
    components = scores.get("components", {})
    return (
        ("CPU", components.get("cpu")),
        ("RAM", components.get("ram")),
        ("Storage", components.get("storage")),
        ("GPU", components.get("gpu")),
        ("Network", components.get("network")),
        ("Drivers", scores.get("drivers")),
        ("Operating system", components.get("operating_system")),
    )


def _assessment_check(
    name,
    category,
    score,
    summary,
    *,
    value=None,
    unit=None,
    source=None,
    limitations=None,
    issue=None,
):
    color, label = _health_band(score)
    status = "passed" if score is not None and score >= 80 else "warning"
    if score is None:
        status = "skipped"
    details = {
        "score": score,
        "health": label,
        "color": color,
        "value": value,
        "unit": unit,
        "source": source,
        "limitations": limitations,
    }
    if issue:
        details["issue"] = issue
    return {
        "name": name,
        "category": category,
        "status": status,
        "summary": summary,
        "details": details,
    }


def collect_health_report(specifications):
    """Assess observable Windows signals; do not infer unavailable hardware states."""
    LOGGER.info("Starting one-time endpoint health assessment.")
    cpu_usage = None
    try:
        cpu_usage = float(psutil.cpu_percent(interval=0.25))
    except (psutil.Error, OSError):
        LOGGER.exception("Could not measure CPU utilization.")

    try:
        memory = psutil.virtual_memory()
        ram_usage = float(memory.percent)
    except (psutil.Error, OSError):
        LOGGER.exception("Could not measure RAM utilization.")
        ram_usage = None

    storage_devices = specifications.get("storage_devices") or []
    storage_free_percent = [
        (item["available_bytes"] / item["total_bytes"]) * 100
        for item in storage_devices
        if item.get("total_bytes", 0) > 0
    ]
    storage_score = (
        min(_score_from_free_space(value) for value in storage_free_percent)
        if storage_free_percent
        else None
    )
    storage_summary = "No accessible storage volumes were measured."
    if storage_devices and storage_free_percent:
        storage_summary = "Accessible volume space: " + "; ".join(
            f"{item.get('name', 'Volume')}: "
            f"{item['available_bytes'] / item['total_bytes'] * 100:.1f}% free"
            for item in storage_devices
            if item.get("total_bytes", 0) > 0
        )

    gpu_values = specifications.get("gpu_information") or []
    gpu_available = bool(gpu_values and gpu_values != [UNAVAILABLE])
    network_result = _check_submission_connectivity()

    try:
        temperature = _collect_cpu_temperature()
    except (psutil.Error, OSError, NotImplementedError):
        LOGGER.exception("CPU temperature sensors are unavailable.")
        temperature = None

    try:
        drivers = _collect_driver_information()
    except (OSError, ImportError):
        LOGGER.exception("Driver metadata is unavailable.")
        drivers = []

    try:
        device_problems = _collect_windows_device_problems()
    except (OSError, ImportError, AttributeError, ctypes.ArgumentError):
        LOGGER.exception("Windows Plug-and-Play problem status is unavailable.")
        device_problems = None

    try:
        services = _collect_windows_services()
    except (psutil.Error, OSError):
        LOGGER.exception("Windows service status is unavailable.")
        services = {}

    cpu_score = _score_from_usage(cpu_usage) if cpu_usage is not None else None
    ram_score = _score_from_usage(ram_usage) if ram_usage is not None else None
    gpu_score = 100 if gpu_available else None
    network_connected = network_result["ok"]
    network_score = 100 if network_connected else (40 if specifications.get("ip_addresses") else 20)
    driver_dates = []
    for driver in drivers:
        driver_date = driver.get("date")
        if driver_date:
            for date_format in ("%Y%m%d", "%Y-%m-%d"):
                try:
                    driver_dates.append(
                        datetime.strptime(driver_date[:10], date_format).date()
                    )
                    break
                except ValueError:
                    continue
    old_driver_count = sum(
        (datetime.now().date() - driver_date).days > 365 * 5
        for driver_date in driver_dates
    )
    driver_score = None
    if drivers or device_problems is not None:
        metadata_score = (
            100 - round(old_driver_count / max(1, len(driver_dates)) * 60)
            if drivers and driver_dates
            else 100 if drivers else None
        )
        problem_score = max(0, 100 - 30 * len(device_problems or [])) if device_problems is not None else None
        available_scores = [
            score for score in (metadata_score, problem_score) if score is not None
        ]
        driver_score = min(available_scores) if available_scores else None
    os_detected = all(
        specifications.get(key) not in (None, "", UNAVAILABLE)
        for key in ("operating_system_name", "operating_system_version")
    )
    required_services = ("RpcSs", "EventLog")
    required_service_states = [services.get(name) for name in required_services]
    services_detected = all(state is not None for state in required_service_states)
    services_healthy = services_detected and all(
        state.casefold() == "running" for state in required_service_states
    )
    os_score = 100 if os_detected and services_healthy else (
        60 if os_detected and services_detected else (40 if not os_detected else None)
    )
    service_scores = [
        100 if state and state.casefold() == "running" else 40
        for state in services.values()
        if state is not None
    ]
    software_score = round(
        sum([os_score] + service_scores) / (1 + len(service_scores))
    ) if os_score is not None else None
    hardware_scores = [
        score
        for score in (cpu_score, ram_score, storage_score, gpu_score, network_score)
        if score is not None
    ]
    hardware_score = round(sum(hardware_scores) / len(hardware_scores)) if hardware_scores else None
    overall_scores = [
        score
        for score in (hardware_score, software_score, driver_score)
        if score is not None
    ]
    overall_score = round(sum(overall_scores) / len(overall_scores)) if overall_scores else None

    checks = []
    metrics = (
        ("CPU", "hardware", cpu_score, "CPU utilization", cpu_usage, "%"),
        ("RAM", "hardware", ram_score, "RAM utilization", ram_usage, "%"),
        ("Storage capacity", "hardware", storage_score, storage_summary, min(storage_free_percent) if storage_free_percent else None, "% free"),
        ("GPU availability", "hardware", gpu_score, "GPU detected" if gpu_available else "GPU availability could not be confirmed", len(gpu_values) if gpu_available else None, "device(s)"),
        ("Network connectivity", "hardware", network_score, network_result["message"], network_result, None),
        ("Operating system", "software", os_score, "OS identity and critical service status assessed" if os_detected else "Operating system information is incomplete", specifications.get("operating_system_name"), None),
        ("Driver metadata", "driver", driver_score, f"{len(drivers)} display/network driver record(s) inspected" if drivers else "Driver metadata unavailable", len(drivers), "record(s)"),
    )
    for name, category, score, summary, value, unit in metrics:
        issue = None
        if score is not None and score < 80:
            if name == "CPU":
                issue = _health_issue(
                    "High CPU utilization", score,
                    f"CPU utilization was {value:.0f}% during this short sample.",
                    "Heavy active workloads can temporarily raise CPU use.",
                    "Review active applications and repeat the check after unnecessary work is closed.",
                    ["Open Task Manager.", "Sort the Processes list by CPU.", "Close applications you recognize and do not need.", "Run the assessment again after a few minutes."],
                )
            elif name == "RAM":
                issue = _health_issue(
                    "High RAM utilization", score,
                    f"RAM utilization was {value:.0f}% during this sample.",
                    "Open applications and background tasks are using most available memory.",
                    "Review memory use and close unnecessary applications.",
                    ["Open Task Manager.", "Sort the Processes list by Memory.", "Save work and close applications you do not need.", "Restart the device if high use continues."],
                )
            elif name == "Storage capacity":
                issue = _health_issue(
                    "Low available storage", score,
                    f"{summary}. The lowest free-space volume has {value:.1f}% free.",
                    "A nearly full volume can prevent updates and normal application work.",
                    "Free space safely or ask an administrator about storage expansion.",
                    ["Open Settings and select System, then Storage.", "Review temporary files and large items.", "Back up important files before removing them.", "Avoid deleting Windows or application folders manually."],
                )
            elif name == "Network connectivity":
                stage = value["stage"]
                network_guidance = {
                    "configuration": (
                        "The executable was built with an invalid DevMonitor address.",
                        ["Re-download the agent from the signed-in DevMonitor page.", "If the issue continues, ask the administrator to verify PUBLIC_BASE_URL."],
                    ),
                    "dns": (
                        "The device could not translate the configured server name to a network address.",
                        ["Confirm the device has internet or organization-network access.", "Reconnect Wi-Fi or Ethernet.", "Check VPN and DNS settings with your network administrator.", "Retry after DNS service is restored."],
                    ),
                    "tcp": (
                        "The server name resolved, but its configured port did not accept a connection.",
                        ["Confirm the DevMonitor server is running.", "Verify the server address and port with the administrator.", "Check whether a firewall or VPN blocks that port.", "Retry when the service is reachable."],
                    ),
                    "tls": (
                        "The server was reached, but HTTPS negotiation failed; the configured port, protocol, or certificate may be wrong.",
                        ["Confirm the address uses the scheme and port supplied by the administrator (HTTPS commonly uses port 443).", "Check that the computer's date and time are correct.", "Open the DevMonitor HTTPS address in a browser and inspect any certificate warning.", "Ask the administrator to verify the listening port and renew or configure the server certificate.", "Do not bypass certificate validation."],
                    ),
                    "endpoint": (
                        "The network connection succeeded, but the configured DevMonitor API path did not respond correctly.",
                        ["Open the DevMonitor site in a browser.", "Confirm the application is running at the configured address.", "Ask the administrator to verify the deployed application path and agent download settings.", "Download a fresh agent after the server address is corrected."],
                    ),
                }
                cause, steps = network_guidance.get(
                    stage,
                    ("The configured DevMonitor server could not be reached.", ["Confirm the network connection and server address.", "Ask the administrator to check the application service and firewall.", "Retry after the connection is restored."]),
                )
                issue = _health_issue(
                    "DevMonitor connection problem", score,
                    value["message"],
                    cause,
                    "Follow the steps for the reported connection stage, then download a fresh agent if the server settings changed.",
                    steps,
                )
            elif name == "Driver metadata":
                issue = _health_issue(
                    "Review display/network driver information", score,
                    f"{old_driver_count} inspected driver record(s) have metadata older than five years.",
                    "Older metadata is a review signal only; it does not prove a driver is faulty or unsafe.",
                    "Check the device manufacturer's support page for compatible updates.",
                    ["Open Device Manager.", "Expand Display adapters and Network adapters.", "Open device Properties and review the Driver tab.", "Install only a compatible update from Windows Update or the manufacturer."],
                )
        checks.append(
            _assessment_check(
                name,
                category,
                score,
                summary,
                value=value,
                unit=unit,
                source="Local Windows endpoint; single-time sample",
                limitations=(
                    "Capacity is not physical disk/SMART health."
                    if name == "Storage capacity"
                    else "Only driver metadata was inspected; Device Manager problem codes and missing-driver states are not reliably exposed by this collector."
                    if name == "Driver metadata"
                    else "GPU presence does not test GPU performance or temperature."
                    if name == "GPU availability"
                    else None
                ),
                issue=issue,
            )
        )

    checks.append(
        _assessment_check(
            "CPU temperature",
            "hardware",
            None,
            f"Temperature: {temperature:.1f} °C" if temperature is not None else "No supported CPU temperature sensor was reported.",
            value=temperature,
            unit="°C",
            source="psutil temperature sensors",
            limitations="Many Windows systems do not expose CPU temperature without vendor-specific sensor software.",
        )
    )
    for service_name, state in services.items():
        is_critical = service_name in required_services
        service_score = (
            100 if state and state.casefold() == "running"
            else 40 if state is not None and is_critical
            else 70 if state is not None
            else None
        )
        issue = None
        if is_critical and state is not None and state.casefold() != "running":
            issue = _health_issue(
                f"Critical service {service_name} is not running",
                service_score,
                f"The Windows {service_name} service reported status {state}.",
                "A required Windows service may be stopped or unavailable.",
                "Review the service state with an administrator before changing it.",
                ["Press Windows+R and enter services.msc.", f"Find {service_name}.", "Review its status and startup type.", "Contact an administrator before changing a protected service."],
            )
        checks.append(
            _assessment_check(
                f"Windows service: {service_name}",
                "software",
                service_score,
                f"Status: {state or 'Unavailable'}",
                value=state,
                source="Windows service control manager via psutil",
                limitations="A stopped optional service is not necessarily a fault.",
                issue=issue,
            )
        )

    if device_problems:
        first_problem = device_problems[0]
        summary = "; ".join(
            f"{item['name']} (Code {item['code']}: {_device_problem_description(item['code'])})"
            for item in device_problems[:8]
        )[:800]
        device_problem_issue = _health_issue(
            "Windows reports a device or connection problem",
            driver_score if driver_score is not None else 40,
            f"Windows reported problems for {len(device_problems)} present device(s): {summary}.",
            "A Plug-and-Play problem code can indicate a disabled device, missing or incompatible driver, resource conflict, or a hardware/connection problem. The code does not prove which cause applies.",
            "Inspect the named device and its Windows problem code before replacing hardware or changing drivers.",
            [
                "Open Device Manager (press Windows+X, then choose Device Manager).",
                f"Locate {first_problem['name']} and open Properties.",
                f"Compare the Device status message with problem code {first_problem['code']}.",
                "For an external device, safely disconnect and reconnect its cable, power, or USB port, then select Action > Scan for hardware changes.",
                "If the issue remains, install a compatible driver from Windows Update or the device manufacturer's support page; contact an administrator for managed devices.",
            ],
        )
        checks.append(
            _assessment_check(
                "Connected device status",
                "driver",
                driver_score,
                f"{len(device_problems)} present device(s) report Plug-and-Play problems: {summary}",
                value=device_problems[:20],
                source="Windows SetupAPI and Configuration Manager",
                issue=device_problem_issue,
            )
        )
    else:
        checks.append(
            _assessment_check(
                "Connected device status",
                "driver",
                100 if device_problems == [] else None,
                "No Plug-and-Play problems were reported for present devices."
                if device_problems == []
                else "Windows device problem codes could not be inspected.",
                value=[] if device_problems == [] else None,
                source="Windows SetupAPI and Configuration Manager",
                limitations=(
                    None if device_problems == []
                    else "Only problem codes exposed for currently enumerated devices can be assessed; this cannot prove every physical connection is secure."
                ),
            )
        )

    for name, category, summary, limitation in (
        ("Startup performance", "software", "Startup duration was not measured.", "Reliable boot-duration history requires Windows event-log access and is not included in this one-time scan."),
        ("Common system errors", "software", "Windows event logs were not inspected.", "The agent does not read or upload Windows event-log contents."),
        ("Security configuration", "software", "Security configuration was not fully assessed.", "Service status alone cannot confirm antivirus, firewall, or update policy is correctly configured."),
    ):
        checks.append(
            _assessment_check(
                name,
                category,
                None,
                summary,
                source="Not collected",
                limitations=limitation,
            )
        )

    issues = [
        check["details"]["issue"]
        for check in checks
        if check["details"].get("issue")
    ]
    scores = {
        "overall": overall_score,
        "hardware": hardware_score,
        "software": software_score,
        "drivers": driver_score,
        "components": {
            "cpu": cpu_score,
            "ram": ram_score,
            "storage": storage_score,
            "gpu": gpu_score,
            "network": network_score,
            "operating_system": os_score,
        },
    }
    LOGGER.info(
        "Health assessment completed with %d findings and %d checks; scores=%s.",
        len(issues),
        len(checks),
        scores,
    )
    return {
        "scores": scores,
        "checks": checks,
        "issues": issues,
        "summary": (
            f"Endpoint assessment completed with overall score "
            f"{overall_score if overall_score is not None else 'unavailable'} "
            f"and {len(issues)} recommendation(s)."
        ),
    }


def _health_issue(title, score, description, root_cause, recommendation, steps):
    severity = (
        "critical" if score < 40 else "attention" if score < 60
        else "warning" if score < 80 else "info"
    )
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "root_cause": root_cause,
        "recommendation": recommendation,
        "steps": steps,
    }


# Colours shared by the agent's windows; they follow the website's dark purple theme.
AGENT_THEME = {
    "background": "#0d0221",
    "surface": "#120636",
    "surface_alt": "#1a0b4a",
    "border": "#2c1d6b",
    "accent": "#3458a8",
    "accent_active": "#26408b",
    "accent_light": "#93c5fd",
    "text": "#f8fafc",
    "muted": "#cbd5e1",
    "dim": "#94a3b8",
    "track": "#2a1d5c",
    "success": "#16a34a",
    "error": "#fca5a5",
}
FONT_FAMILY = "Segoe UI"


def _enable_dpi_awareness():
    """Draw Tk windows sharply on scaled (125%/150%) Windows displays."""
    if os.name != "nt":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass


def _pixel_scale(root):
    """Pixels per 96-dpi pixel, so paddings grow with the display's text scaling."""
    try:
        return max(float(root.winfo_fpixels("1i")) / 96.0, 1.0)
    except Exception:  # pragma: no cover - Tk without a real display
        return 1.0


def _work_area(root):
    """(left, top, right, bottom) of the screen area not covered by the taskbar."""
    if os.name == "nt":
        try:
            rect = ctypes.wintypes.RECT()
            if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0):
                return rect.left, rect.top, rect.right, rect.bottom
        except (AttributeError, OSError):
            pass
    return 0, 0, root.winfo_screenwidth(), root.winfo_screenheight()


def _place_window(root, width, height):
    """Centre the window in the work area so it never runs under the taskbar.

    ``width``/``height`` are the client size; the title bar and borders are
    added by Windows, so room is kept for them.
    """
    left, top, right, bottom = _work_area(root)
    chrome = int(round(48 * _pixel_scale(root)))
    width = min(width, right - left - chrome // 2)
    height = min(height, bottom - top - chrome)
    x = left + max((right - left - width) // 2, 0)
    y = top + max((bottom - top - chrome - height) // 3, 0)
    root.geometry(f"{width}x{height}+{x}+{y}")


def _bring_to_front(root):
    # Map the window first: setting -topmost on an unmapped window makes
    # Windows ignore the position chosen by _place_window.
    root.update()
    root.lift()
    try:
        root.attributes("-topmost", True)
        root.after(400, lambda: root.attributes("-topmost", False))
    except Exception:  # pragma: no cover - window manager without -topmost
        pass
    root.focus_force()


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _format_gb(value):
    if not _is_number(value) or value < 0:
        return UNAVAILABLE
    return f"{value / (1024 ** 3):,.1f} GB"


def _usage_fraction(used, total):
    if not (_is_number(used) and _is_number(total)) or total <= 0:
        return None
    return min(max(used / total, 0.0), 1.0)


def _usage_color(fraction):
    if fraction >= 0.9:
        return "#dc2626"
    if fraction >= 0.75:
        return "#eab308"
    return "#16a34a"


def _plain_value(value):
    if value is None or value == "" or value == [] or value == [UNAVAILABLE]:
        return UNAVAILABLE
    if isinstance(value, list):
        return "\n".join(str(item) for item in value if str(item).strip()) or UNAVAILABLE
    return str(value)


def specification_sections(specifications):
    """Group the detected specifications into titled sections for the review window.

    Each section is ``(title, rows)``; each row is a dict with ``label``,
    ``value`` (display text), ``fraction`` (0-1 for a usage bar, or None) and
    ``detail`` (True for per-drive rows). Every FIELD_LABELS label appears once.
    """
    specs = specifications or {}

    def row(label, value, fraction=None, detail=False):
        return {"label": label, "value": value, "fraction": fraction, "detail": detail}

    capacity = specs.get("ram_capacity_bytes")
    used = specs.get("ram_usage_bytes")
    ram_fraction = _usage_fraction(used, capacity)
    ram_usage = _format_gb(used)
    if ram_fraction is not None:
        ram_usage = f"{ram_usage} in use ({ram_fraction:.0%})"

    drives = [item for item in specs.get("storage_devices") or [] if isinstance(item, dict)]
    total = specs.get("storage_total_bytes") if drives else None
    available = specs.get("storage_available_bytes") if drives else None
    storage_fraction = (
        _usage_fraction(total - available, total)
        if _is_number(total) and _is_number(available) else None
    )
    drive_rows = []
    for drive in drives:
        drive_total = drive.get("total_bytes")
        drive_free = drive.get("available_bytes")
        drive_rows.append(row(
            str(drive.get("name") or "Drive"),
            f"{_format_gb(drive_free)} free of {_format_gb(drive_total)}",
            _usage_fraction(drive_total - drive_free, drive_total)
            if _is_number(drive_total) and _is_number(drive_free) else None,
            detail=True,
        ))
    drive_count = len(drives)
    storage_summary = (
        f"{drive_count} drive{'' if drive_count == 1 else 's'}" if drives else UNAVAILABLE
    )

    return [
        ("Processor", [
            row("CPU name", _plain_value(specs.get("cpu_name"))),
            row("Number of CPU cores", _plain_value(specs.get("cpu_cores"))),
        ]),
        ("Memory", [
            row("RAM capacity", _format_gb(capacity)),
            row("RAM usage", ram_usage, ram_fraction),
        ]),
        ("Storage", [
            row("Total storage capacity", _format_gb(total)),
            row(
                "Available storage capacity",
                f"{_format_gb(available)} free" if _is_number(available) else UNAVAILABLE,
                storage_fraction,
            ),
            row("Storage devices", storage_summary),
            *drive_rows,
        ]),
        ("Graphics", [
            row("GPU information", _plain_value(specs.get("gpu_information"))),
        ]),
        ("System", [
            row("Motherboard brand", _plain_value(specs.get("motherboard_brand"))),
            row("Operating system name", _plain_value(specs.get("operating_system_name"))),
            row("Operating system version", _plain_value(specs.get("operating_system_version"))),
        ]),
        ("Network", [
            row("Installed network adapters", _plain_value(specs.get("network_adapters"))),
            row("IP address", _plain_value(specs.get("ip_addresses"))),
            row("MAC address", _plain_value(specs.get("mac_address"))),
        ]),
    ]


def review_specifications_window(
    specifications, *, default_name, default_type, server=""
):  # pragma: no cover - needs a display
    """Show the detected specifications and ask the user to approve them.

    Returns ``{"name": ..., "device_type": ...}`` when the user clicks
    Register, or None when they cancel or close the window. Nothing is sent
    from here; the caller submits only after an approval.
    """
    import tkinter as tk
    from tkinter import ttk

    theme = AGENT_THEME
    _enable_dpi_awareness()
    root = tk.Tk()
    root.title("DevMonitor Agent - Review this device")
    root.configure(background=theme["background"])
    scale = _pixel_scale(root)

    def px(value):
        return int(round(value * scale))

    result = {}
    root.columnconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)

    # Header -----------------------------------------------------------------
    header = tk.Frame(root, background=theme["background"], padx=px(24), pady=px(18))
    header.grid(row=0, column=0, sticky="ew")
    tk.Label(
        header, text="Review this device", font=(FONT_FAMILY, 17, "bold"),
        foreground=theme["text"], background=theme["background"],
    ).pack(anchor="w")
    tk.Label(
        header,
        text=(
            "DevMonitor detected the details below. Nothing is sent until you "
            "click Register this device."
        ),
        font=(FONT_FAMILY, 10), foreground=theme["muted"],
        background=theme["background"], justify="left", wraplength=px(640),
    ).pack(anchor="w", pady=(px(4), 0))
    if server:
        tk.Label(
            header, text=f"Server: {server}", font=(FONT_FAMILY, 9),
            foreground=theme["dim"], background=theme["background"],
        ).pack(anchor="w", pady=(px(2), 0))

    # Scrollable grid of specification cards ---------------------------------
    body = tk.Frame(root, background=theme["background"])
    body.grid(row=1, column=0, sticky="nsew", padx=(px(18), px(6)))
    body.rowconfigure(0, weight=1)
    body.columnconfigure(0, weight=1)
    canvas = tk.Canvas(body, background=theme["background"], highlightthickness=0, borderwidth=0)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")  # the native Windows scrollbar ignores colours
    except tk.TclError:
        pass
    style.configure(
        "Agent.Vertical.TScrollbar", background=theme["border"],
        troughcolor=theme["background"], bordercolor=theme["background"],
        lightcolor=theme["border"], darkcolor=theme["border"],
        arrowcolor=theme["muted"], gripcount=0,
    )
    style.map("Agent.Vertical.TScrollbar", background=[("active", theme["accent"])])
    scrollbar = ttk.Scrollbar(
        body, orient="vertical", command=canvas.yview, style="Agent.Vertical.TScrollbar"
    )
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.grid(row=0, column=0, sticky="nsew")
    scrollbar.grid(row=0, column=1, sticky="ns")
    cards = tk.Frame(canvas, background=theme["background"])
    cards_window = canvas.create_window((0, 0), window=cards, anchor="nw")
    cards.columnconfigure((0, 1), weight=1, uniform="cards")
    cards.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda event: canvas.itemconfigure(cards_window, width=event.width))

    def on_mousewheel(event):
        canvas.yview_scroll(int(-event.delta / 120) or (-1 if event.delta > 0 else 1), "units")

    root.bind_all("<MouseWheel>", on_mousewheel)
    value_wrap = px(290)

    for index, (title, rows) in enumerate(specification_sections(specifications)):
        card = tk.Frame(
            cards, background=theme["surface"], padx=px(16), pady=px(14),
            highlightbackground=theme["border"], highlightthickness=1,
        )
        card.grid(row=index // 2, column=index % 2, sticky="nsew", padx=px(6), pady=px(6))
        tk.Label(
            card, text=title.upper(), font=(FONT_FAMILY, 9, "bold"),
            foreground=theme["accent_light"], background=theme["surface"],
        ).pack(anchor="w", pady=(0, px(6)))
        for spec_row in rows:
            indent = px(12) if spec_row["detail"] else 0
            tk.Label(
                card, text=spec_row["label"],
                font=(FONT_FAMILY, 9 if spec_row["detail"] else 8),
                foreground=theme["muted"] if spec_row["detail"] else theme["dim"],
                background=theme["surface"],
            ).pack(anchor="w", padx=(indent, 0), pady=(px(6), 0))
            unavailable = spec_row["value"] == UNAVAILABLE
            tk.Label(
                card, text=spec_row["value"],
                font=(FONT_FAMILY, 10, "italic" if unavailable else "normal"),
                foreground=theme["dim"] if unavailable else theme["text"],
                background=theme["surface"], justify="left", anchor="w",
                wraplength=value_wrap - indent,
            ).pack(anchor="w", fill="x", padx=(indent, 0))
            if spec_row["fraction"] is not None:
                track = tk.Frame(card, background=theme["track"], height=px(6))
                track.pack(fill="x", padx=(indent, 0), pady=(px(4), px(2)))
                tk.Frame(track, background=_usage_color(spec_row["fraction"])).place(
                    relx=0, rely=0, relheight=1, relwidth=max(spec_row["fraction"], 0.01)
                )

    # Footer: name, type, approve ---------------------------------------------
    footer = tk.Frame(
        root, background=theme["surface"], padx=px(24), pady=px(16),
        highlightbackground=theme["border"], highlightthickness=1,
    )
    footer.grid(row=2, column=0, sticky="ew", pady=(px(10), 0))
    footer.columnconfigure(1, weight=1)

    tk.Label(
        footer, text="Device name", font=(FONT_FAMILY, 10, "bold"),
        foreground=theme["text"], background=theme["surface"],
    ).grid(row=0, column=0, sticky="w", padx=(0, px(12)))
    name_var = tk.StringVar(value=default_name)
    name_entry = tk.Entry(
        footer, textvariable=name_var, font=(FONT_FAMILY, 10),
        background=theme["surface_alt"], foreground=theme["text"],
        insertbackground=theme["text"], relief="flat",
        highlightthickness=1, highlightbackground=theme["border"],
        highlightcolor=theme["accent_light"],
    )
    name_entry.grid(row=0, column=1, columnspan=2, sticky="ew", ipady=px(5))

    tk.Label(
        footer, text="Device type", font=(FONT_FAMILY, 10, "bold"),
        foreground=theme["text"], background=theme["surface"],
    ).grid(row=1, column=0, sticky="w", padx=(0, px(12)), pady=(px(10), 0))
    type_var = tk.StringVar(
        value=default_type if default_type in {"Desktop", "Laptop"} else "Desktop"
    )
    types = tk.Frame(footer, background=theme["surface"])
    types.grid(row=1, column=1, sticky="w", pady=(px(10), 0))
    for choice in ("Desktop", "Laptop"):
        tk.Radiobutton(
            types, text=choice, value=choice, variable=type_var, indicatoron=False,
            font=(FONT_FAMILY, 10), width=9, padx=px(10), pady=px(5),
            background=theme["surface_alt"], foreground=theme["muted"],
            selectcolor=theme["accent"], activebackground=theme["accent_active"],
            activeforeground=theme["text"], relief="flat", borderwidth=0,
            highlightthickness=0, cursor="hand2",
        ).pack(side="left", padx=(0, px(6)))

    error = tk.Label(
        footer, text="", font=(FONT_FAMILY, 9), foreground=theme["error"],
        background=theme["surface"], anchor="w",
    )
    error.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(px(6), 0))
    tk.Label(
        footer,
        text="Only the details above and this name and type are sent to your account.",
        font=(FONT_FAMILY, 9), foreground=theme["dim"], background=theme["surface"],
        anchor="w", justify="left", wraplength=px(380),
    ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(px(4), 0))

    def register(_event=None):
        name = name_var.get().strip()
        if not name or len(name) > 120:
            error.configure(text="Enter a device name between 1 and 120 characters.")
            name_entry.focus_set()
            return
        result.update(name=name, device_type=type_var.get())
        root.destroy()

    def cancel(_event=None):
        result.clear()
        root.destroy()

    buttons = tk.Frame(footer, background=theme["surface"])
    buttons.grid(row=3, column=2, sticky="e", pady=(px(4), 0))
    button_style = dict(
        font=(FONT_FAMILY, 10, "bold"), relief="flat", borderwidth=0,
        padx=px(20), pady=px(8), cursor="hand2",
    )
    tk.Button(
        buttons, text="Cancel", command=cancel,
        background=theme["surface_alt"], foreground=theme["muted"],
        activebackground=theme["border"], activeforeground=theme["text"],
        **button_style,
    ).pack(side="left", padx=(0, px(8)))
    tk.Button(
        buttons, text="Register this device", command=register,
        background=theme["accent"], foreground="#ffffff",
        activebackground=theme["accent_active"], activeforeground="#ffffff",
        **button_style,
    ).pack(side="left")

    root.bind("<Return>", register)
    root.bind("<Escape>", cancel)
    root.protocol("WM_DELETE_WINDOW", cancel)

    root.update_idletasks()
    width = max(
        cards.winfo_reqwidth() + scrollbar.winfo_reqwidth() + px(30),
        footer.winfo_reqwidth(),
        px(720),
    )
    height = (
        header.winfo_reqheight() + cards.winfo_reqheight()
        + footer.winfo_reqheight() + px(20)
    )
    root.minsize(px(640), px(420))
    _place_window(root, width, height)
    _bring_to_front(root)
    name_entry.focus_set()
    name_entry.icursor("end")
    root.mainloop()
    return dict(result) if result else None


def show_registration_success(seconds=5, dashboard_url=None):  # pragma: no cover - needs a display
    import tkinter as tk

    dashboard_url = dashboard_url or DASHBOARD_URL

    theme = AGENT_THEME
    _enable_dpi_awareness()
    root = tk.Tk()
    root.title("Device Registered Successfully")
    root.resizable(False, False)
    root.configure(background=theme["background"])
    scale = _pixel_scale(root)

    def px(value):
        return int(round(value * scale))

    # The window is sized from its content (below), so nothing is clipped at
    # any display scaling.
    body = tk.Frame(root, background=theme["background"], padx=px(40), pady=px(28))
    body.pack(fill="both", expand=True)
    tk.Label(
        body, text="✓", font=(FONT_FAMILY, 40, "bold"),
        foreground=theme["success"], background=theme["background"],
    ).pack()
    tk.Label(
        body, text="Device Registered Successfully",
        font=(FONT_FAMILY, 16, "bold"), foreground=theme["text"],
        background=theme["background"],
    ).pack(pady=(px(2), px(6)))
    tk.Label(
        body, text="You may now proceed to the Dashboard.",
        font=(FONT_FAMILY, 10), foreground=theme["muted"],
        background=theme["background"], wraplength=px(360), justify="center",
    ).pack()
    countdown = tk.Label(
        body, text="", font=(FONT_FAMILY, 10, "bold"),
        foreground=theme["muted"], background=theme["background"],
    )
    countdown.pack(pady=(px(14), 0))

    state = {"done": False, "timer": None}

    def redirect(_event=None):
        if state["done"]:
            return
        state["done"] = True
        if state["timer"] is not None:
            root.after_cancel(state["timer"])
        if dashboard_url:
            webbrowser.open(dashboard_url, new=2)
        root.destroy()

    def tick(remaining=seconds):
        if state["done"]:
            return
        countdown.configure(text=f"Redirecting to Dashboard in {remaining} seconds...")
        if remaining <= 0:
            redirect()
        else:
            state["timer"] = root.after(1000, tick, remaining - 1)

    button = tk.Button(
        body,
        text="Go to Dashboard Now",
        command=redirect,
        font=(FONT_FAMILY, 11, "bold"),
        background=theme["accent"],
        foreground="#ffffff",
        activebackground=theme["accent_active"],
        activeforeground="#ffffff",
        relief="flat",
        borderwidth=0,
        highlightthickness=0,
        cursor="hand2",
        padx=px(28),
        pady=px(11),
        anchor="center",
        justify="center",
    )
    button.pack(fill="x", pady=(px(18), 0))
    root.bind("<Return>", redirect)
    root.protocol("WM_DELETE_WINDOW", root.destroy)

    root.update_idletasks()
    _place_window(root, max(body.winfo_reqwidth(), px(440)), body.winfo_reqheight())
    _bring_to_front(root)
    button.focus_set()
    tick()
    root.mainloop()


def collect_specifications():
    configure_logging()
    if os.name != "nt":
        raise RuntimeError("This agent supports Windows desktop and laptop devices only.")
    LOGGER.info("Starting local Windows device specification collection.")

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
        "mac_address": None,
    }

    memory = _collect_component("memory", _collect_memory, {})
    specifications.update(memory)
    os_information = _collect_component(
        "operating system", _collect_operating_system, {}
    )
    specifications.update(os_information)
    network = _collect_component("network", _collect_network, {})
    specifications.update(network)

    unavailable = _unavailable_specification_fields(specifications)
    if unavailable:
        LOGGER.warning(
            "Inventory collection completed with unavailable fields: %s",
            ", ".join(unavailable),
        )
    else:
        LOGGER.info("Inventory collection completed with all fields available.")
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


def _embedded(value):
    """A value injected by the server, or "" while it is still a placeholder."""
    return "" if value.startswith("__") and value.endswith("__") else value


def server_origin(url):
    """The https:// (or local http://) origin of a DevMonitor server, else ValueError."""
    server = urlsplit(url or "")
    if (
        server.scheme not in {"http", "https"}
        or not server.hostname
        or server.username
        or server.password
        or server.query
        or server.fragment
        or server.path not in {"", "/"}
    ):
        raise ValueError("The registration link does not contain a valid server address.")
    if server.scheme != "https" and server.hostname not in LOCAL_HOSTS:
        raise ValueError("For your security the DevMonitor server must use HTTPS.")
    return f"{server.scheme}://{server.netloc}"


def parse_enrollment_link(link):
    """Return (submission_url, token, dashboard_url) from a devmonitor://enroll link."""
    parsed = urlsplit((link or "").strip().strip('"'))
    if parsed.scheme != LINK_SCHEME or (parsed.netloc or parsed.path.strip("/")) != "enroll":
        raise ValueError("That is not a DevMonitor registration link.")
    query = parse_qs(parsed.query)
    origin = server_origin((query.get("server") or [""])[0])
    token = (query.get("token") or [""])[0]
    if not TOKEN_PATTERN.fullmatch(token):
        raise ValueError(
            "The registration link is incomplete. Create a new link on the website."
        )
    return origin + ENROLL_PATH, token, origin + "/dashboard"


def link_open_url():
    """SERVER_URL/device-link/open for a build that knows its website, else ""."""
    try:
        return server_origin(_embedded(SERVER_URL)) + LINK_OPEN_PATH if _embedded(SERVER_URL) else ""
    except ValueError:
        LOGGER.warning("The built-in DevMonitor website address is invalid.")
        return ""


def open_website_to_link():
    """Ask the signed-in website for a link; it reopens this program with it."""
    url = link_open_url()
    if not url:
        return False
    try:
        opened = webbrowser.open(url, new=2)
    except (OSError, webbrowser.Error):
        LOGGER.warning("Could not open the browser at %s.", url, exc_info=True)
        return False
    LOGGER.info("Opened %s to link this computer (opened=%s).", url, opened)
    return bool(opened)


def register_link_handler():
    """Open devmonitor:// links with this program (current user only, no admin rights)."""
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return False
    try:
        import winreg

        command = f'"{sys.executable}" "%1"'
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{LINK_SCHEME}") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "URL:DevMonitor Agent")
            winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
        with winreg.CreateKey(
            winreg.HKEY_CURRENT_USER, rf"Software\Classes\{LINK_SCHEME}\shell\open\command"
        ) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)
    except OSError:
        LOGGER.warning("Could not register the devmonitor:// link handler.", exc_info=True)
        return False
    LOGGER.info("Registered the devmonitor:// link handler for %s.", sys.executable)
    return True


def resolve_link_enrollment(link, *, interactive):
    """Use the link argument, or ask for one; returns the parsed link or None."""
    if not link and interactive:
        if open_website_to_link():
            print(
                "\nLinking this computer to your DevMonitor account...\n"
                "  Your browser is opening the DevMonitor website. Sign in if asked.\n"
                "  When the browser asks to open \"DevMonitor Agent\", choose Open:\n"
                "  a new window then shows your device details. You can close this one.\n"
                "\n  Nothing happened? Paste the link shown on the website below.\n"
            )
        else:
            print(
                "\nTo link this computer to your DevMonitor account:\n"
                "  1. Sign in on the DevMonitor website on this computer.\n"
                "  2. Open \"Link a Device\" and click \"Link this device\".\n"
                "     This agent opens by itself. If it does not, copy the link shown\n"
                "     on the page and paste it below.\n"
            )
        try:
            link = input("Registration link (devmonitor://enroll?...): ").strip()
        except EOFError:
            link = ""
    if not link:
        print(
            "No registration link was provided. Click \"Link this device\" on the "
            "DevMonitor website to link this computer.",
            file=sys.stderr,
        )
        return None
    try:
        return parse_enrollment_link(link)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Opt-in live monitoring
# ---------------------------------------------------------------------------
# Runs only after the device user agrees (consent prompt after registration).
# It has no window. It is visible and stoppable through Task Manager only: the
# "DevMonitor Live Monitoring" process (Processes, End task pauses it until the
# next sign-in) and startup entry (Startup apps, Disable turns it off), plus the
# "Stop live monitoring" button on the website and "--stop-monitoring".
# Only usage figures are sent: CPU, memory, storage and network throughput.
#
# Platform-specific pieces are the five functions marked "platform hook";
# Linux/macOS support can be added by implementing them for those systems.

HEARTBEAT_PATH = "/api/device-agent/heartbeat"
MONITORING_ENABLE_PATH = "/api/device-agent/monitoring/enable"
MONITORING_STOP_PATH = "/api/device-agent/monitoring/stop"
HEARTBEAT_INTERVAL_SECONDS = 30
MONITOR_STARTUP_NAME = "DevMonitor Live Monitoring"
MONITOR_CONFIG_NAME = "monitoring.json"
MONITOR_PID_NAME = "monitoring.pid"
# The process name Task Manager shows; matches the startup entry's name.
MONITOR_EXECUTABLE_NAME = f"{MONITOR_STARTUP_NAME}.exe"
MONITOR_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
MONITOR_MUTEX_NAME = "Local\\DevMonitorLiveMonitoring"
_MONITOR_MUTEX = None
CONSENT_TEXT = (
    "DevMonitor can keep this device's dashboard up to date. When turned on it "
    "runs in the background whenever you sign in to Windows and sends this "
    "device's CPU, memory, storage and network usage to {server} every "
    f"{HEARTBEAT_INTERVAL_SECONDS} seconds.\n\n"
    "It does not collect files, keystrokes, screenshots, browsing history or "
    "the contents of your network traffic.\n\n"
    "It runs without a window. You can find it in Task Manager as "
    f"\"{MONITOR_STARTUP_NAME}\": under Processes (End task pauses it until you "
    "next sign in) and under Startup apps (Disable turns it off). You can also "
    "click \"Stop live monitoring\" on this device's page in DevMonitor."
)


def monitoring_supported():
    return sys.platform == "win32"


def monitoring_directory():
    return Path(
        os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
    ) / "DevMonitor"


def _server_base(url):
    """scheme://host[:port] of a DevMonitor URL; HTTPS unless it is local."""
    parts = urlsplit(url or "")
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("The DevMonitor server address is invalid.")
    if parts.scheme != "https" and parts.hostname not in LOCAL_HOSTS:
        raise ValueError("For your security the DevMonitor server must use HTTPS.")
    return f"{parts.scheme}://{parts.netloc}"


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _dpapi(data, protect):
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    buffer = ctypes.create_string_buffer(data, len(data))
    blob_in = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DataBlob()
    ui_forbidden = 0x01
    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(blob_in), "DevMonitor monitoring credential",
            None, None, None, ui_forbidden, ctypes.byref(blob_out),
        )
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, ui_forbidden,
            ctypes.byref(blob_out),
        )
    if not ok:
        raise OSError(ctypes.get_last_error(), "Windows could not protect the credential.")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


def _protect_secret(secret):  # platform hook
    """Encrypt for the signed-in Windows user only (DPAPI)."""
    import base64

    return base64.b64encode(_dpapi(secret.encode("utf-8"), protect=True)).decode("ascii")


def _unprotect_secret(protected):  # platform hook
    import base64

    return _dpapi(base64.b64decode(protected), protect=False).decode("utf-8")


def _register_autostart(command):  # platform hook
    """Start monitoring at sign-in for this user only (no administrator rights)."""
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, MONITOR_RUN_KEY) as key:
        winreg.SetValueEx(key, MONITOR_STARTUP_NAME, 0, winreg.REG_SZ, command)


def _remove_autostart():  # platform hook
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, MONITOR_RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, MONITOR_STARTUP_NAME)
    except FileNotFoundError:
        pass


def _acquire_single_instance():  # platform hook
    """True when this is the only monitor running for the signed-in user."""
    global _MONITOR_MUTEX
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.wintypes.HANDLE
    handle = kernel32.CreateMutexW(None, False, MONITOR_MUTEX_NAME)
    already_exists = ctypes.get_last_error() == 183
    if not handle or already_exists:
        return False
    _MONITOR_MUTEX = handle
    return True


def _hide_monitor_console():
    """The monitor shows no window; Task Manager is where it is seen and stopped.

    The packaged agent has no console at all. A console-based copy (an older
    build, or the script run by python.exe) hides the console only when it
    belongs to the monitor alone, so a terminal it was started from stays open.
    """
    if os.name != "nt":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        window = kernel32.GetConsoleWindow()
        if not window:
            return
        processes = (ctypes.wintypes.DWORD * 4)()
        if kernel32.GetConsoleProcessList(processes, 4) == 1:
            ctypes.windll.user32.ShowWindow(window, 0)  # SW_HIDE
    except (AttributeError, OSError):
        LOGGER.warning("Could not hide the monitoring console window.", exc_info=True)


def _monitor_command():
    """Command line that starts the background monitor from a stable location."""
    import shutil
    import subprocess

    if getattr(sys, "frozen", False):
        target = monitoring_directory() / MONITOR_EXECUTABLE_NAME
        source = Path(sys.executable).resolve()
        if source != target.resolve():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        arguments = [str(target), "--monitor"]
    else:
        arguments = [sys.executable, str(Path(__file__).resolve()), "--monitor"]
    return arguments, subprocess.list2cmdline(arguments)


def _launch_monitor(arguments):
    import subprocess

    # No window: the monitor is seen and stopped in Task Manager.
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    subprocess.Popen(arguments, creationflags=flags, close_fds=True)


def save_monitoring_config(server, device_id, token):
    directory = monitoring_directory()
    directory.mkdir(parents=True, exist_ok=True)
    config = {
        "server": server,
        "device_id": device_id,
        "credential": _protect_secret(token),
        "enabled_at": datetime.now().isoformat(timespec="seconds"),
    }
    (directory / MONITOR_CONFIG_NAME).write_text(json.dumps(config, indent=2), encoding="utf-8")


def load_monitoring_config():
    path = monitoring_directory() / MONITOR_CONFIG_NAME
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        return {
            "server": _server_base(config["server"]),
            "device_id": config.get("device_id"),
            "token": _unprotect_secret(config["credential"]),
        }
    except FileNotFoundError:
        return None
    except (OSError, ValueError, KeyError, TypeError):
        LOGGER.exception("The live monitoring settings could not be read.")
        return None


def remove_local_monitoring():
    """Remove the startup entry and the stored credential from this device."""
    try:
        _remove_autostart()
    except OSError:
        LOGGER.exception("Could not remove the live monitoring startup entry.")
    for name in (MONITOR_CONFIG_NAME, MONITOR_PID_NAME):
        try:
            (monitoring_directory() / name).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            LOGGER.exception("Could not delete %s.", name)


def _post_agent_json(url, token, payload, timeout=15):
    """POST JSON with a bearer credential. Returns (status, decoded body)."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": f"DevMonitor-Agent/{AGENT_VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", None) or response.getcode()
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read().decode("utf-8", errors="replace")
    try:
        return status, json.loads(body) if body else {}
    except ValueError:
        return status, {}


def _storage_usage():
    used = total = 0
    for partition in psutil.disk_partitions(all=False):
        options = (partition.opts or "").lower()
        if "cdrom" in options or not partition.fstype:
            continue
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except (OSError, PermissionError):
            continue
        used += int(usage.used)
        total += int(usage.total)
    if not total:
        return None, None
    return round(used / total * 100, 2), used


def _network_counters():
    """Bytes received/sent across real adapters (loopback excluded)."""
    received = sent = 0
    for name, counters in psutil.net_io_counters(pernic=True).items():
        lowered = name.lower()
        if lowered == "lo" or lowered.startswith("loopback"):
            continue
        received += int(counters.bytes_recv)
        sent += int(counters.bytes_sent)
    return received, sent


class LiveMetricSampler:
    """Collects one heartbeat sample; throughput is the counter delta per second."""

    def __init__(self, clock=None):
        import time

        self._clock = clock or time.monotonic
        psutil.cpu_percent(interval=None)  # primes the CPU counter
        self._previous = self._read_counters()

    def _read_counters(self):
        try:
            return (*_network_counters(), self._clock())
        except (psutil.Error, OSError):
            LOGGER.exception("Network counters are unavailable.")
            return None

    def sample(self):
        sample = {}
        try:
            sample["cpu_percent"] = round(float(psutil.cpu_percent(interval=None)), 2)
        except (psutil.Error, OSError):
            sample["cpu_percent"] = None
        try:
            memory = psutil.virtual_memory()
            sample["memory_percent"] = round(float(memory.percent), 2)
            sample["memory_used_bytes"] = int(memory.used)
        except (psutil.Error, OSError):
            sample["memory_percent"] = sample["memory_used_bytes"] = None
        sample["storage_percent"], sample["storage_used_bytes"] = _storage_usage()

        current = self._read_counters()
        sample["network_rx_bytes_per_sec"] = sample["network_tx_bytes_per_sec"] = None
        sample["network_rx_bytes"] = current[0] if current else None
        sample["network_tx_bytes"] = current[1] if current else None
        previous, self._previous = self._previous, current
        if previous and current:
            elapsed = current[2] - previous[2]
            received, sent = current[0] - previous[0], current[1] - previous[1]
            # A negative delta means the counters were reset (adapter restart,
            # sleep/resume); that interval has no valid speed.
            if elapsed > 0 and received >= 0 and sent >= 0:
                sample["network_rx_bytes_per_sec"] = int(received / elapsed)
                sample["network_tx_bytes_per_sec"] = int(sent / elapsed)
        return sample


def send_heartbeat(config, sample):
    """Returns "ok", "revoked", or "retry"."""
    try:
        status, body = _post_agent_json(config["server"] + HEARTBEAT_PATH, config["token"], sample)
    except (urllib.error.URLError, TimeoutError, OSError):
        LOGGER.warning("Heartbeat could not reach the server; retrying next interval.", exc_info=True)
        return "retry"
    if status == 201:
        return "ok"
    if status == 401 and body.get("monitoring") == "revoked":
        return "revoked"
    LOGGER.warning("Heartbeat was not accepted (HTTP %s): %s", status, body.get("error"))
    return "retry"


def run_monitor(sleep=None, max_beats=None):
    """Background loop started at sign-in. Returns a process exit code."""
    import time

    sleep = sleep or time.sleep
    config = load_monitoring_config()
    if config is None:
        print("Live monitoring is not turned on for this device.")
        return 2
    if not _acquire_single_instance():
        print("DevMonitor live monitoring is already running.")
        return 0
    _hide_monitor_console()
    pid_path = monitoring_directory() / MONITOR_PID_NAME
    try:
        pid_path.write_text(str(os.getpid()), encoding="ascii")
    except OSError:
        LOGGER.warning("Could not record the monitoring process ID.", exc_info=True)
    LOGGER.info("Live monitoring started (device_id=%s).", config.get("device_id"))

    sampler = LiveMetricSampler()
    beats = 0
    try:
        while max_beats is None or beats < max_beats:
            sleep(HEARTBEAT_INTERVAL_SECONDS)
            result = send_heartbeat(config, sampler.sample())
            beats += 1
            if result == "revoked":
                LOGGER.info("Live monitoring was stopped from DevMonitor; removing it from this device.")
                print("Live monitoring was stopped from DevMonitor. It has been removed from this device.")
                remove_local_monitoring()
                return 0
    except KeyboardInterrupt:
        LOGGER.info("Live monitoring paused by the user until next sign-in.")
    finally:
        try:
            pid_path.unlink()
        except OSError:
            pass
    return 0


def _stop_running_monitor():
    """End a running monitor process recorded in the PID file."""
    try:
        pid = int((monitoring_directory() / MONITOR_PID_NAME).read_text(encoding="ascii"))
    except (OSError, ValueError):
        return
    if pid == os.getpid():
        return
    try:
        process = psutil.Process(pid)
        if "--monitor" in process.cmdline():
            process.terminate()
    except (psutil.Error, OSError):
        LOGGER.warning("Could not end the running monitor process.", exc_info=True)


def stop_live_monitoring():
    """--stop-monitoring: tell the server, then remove everything locally."""
    config = load_monitoring_config()
    if config is not None:
        try:
            _post_agent_json(config["server"] + MONITORING_STOP_PATH, config["token"], {})
        except (urllib.error.URLError, TimeoutError, OSError):
            LOGGER.warning("Could not tell the server that monitoring stopped.", exc_info=True)
            print("The server could not be reached; it will show this device as Offline.")
    _stop_running_monitor()
    remove_local_monitoring()
    LOGGER.info("Live monitoring stopped on this device.")
    print("Live monitoring is off. Nothing more will be sent from this device.")
    return 0


def enable_live_monitoring(server, device_id, token):
    """Confirm consent with the server, then set up the background monitor."""
    try:
        status, body = _post_agent_json(server + MONITORING_ENABLE_PATH, token, {})
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        LOGGER.exception("Live monitoring could not be enabled.")
        print(f"Live monitoring could not be turned on: {error}", file=sys.stderr)
        return False
    if status != 200 or body.get("monitoring") != "enabled":
        print(
            f"Live monitoring could not be turned on: {body.get('error') or f'HTTP {status}'}",
            file=sys.stderr,
        )
        return False
    try:
        arguments, command = _monitor_command()
        save_monitoring_config(server, device_id, token)
        _register_autostart(command)
        _launch_monitor(arguments)
    except (OSError, ValueError):
        LOGGER.exception("Live monitoring could not be set up on this device.")
        print("Live monitoring could not be set up on this device; it has been turned off.",
              file=sys.stderr)
        try:
            _post_agent_json(server + MONITORING_STOP_PATH, token, {})
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        remove_local_monitoring()
        return False
    LOGGER.info("Live monitoring enabled (device_id=%s).", device_id)
    print(
        f"Live monitoring is ON. It runs without a window and starts when you sign in; "
        f"find \"{MONITOR_STARTUP_NAME}\" in Task Manager (Processes and Startup apps)."
    )
    return True


def ask_monitoring_consent_window(server):  # pragma: no cover - needs a display
    """Opt-in dialog. "Not now" is the default; closing the window also declines."""
    import tkinter as tk

    theme = AGENT_THEME
    _enable_dpi_awareness()
    root = tk.Tk()
    root.title("Turn on live monitoring?")
    root.resizable(False, False)
    root.configure(background=theme["background"])
    scale = _pixel_scale(root)

    def px(value):
        return int(round(value * scale))

    choice = {"enable": False}
    body = tk.Frame(root, background=theme["background"], padx=px(32), pady=px(26))
    body.pack(fill="both", expand=True)
    tk.Label(
        body, text="Turn on live monitoring?", font=(FONT_FAMILY, 15, "bold"),
        foreground=theme["text"], background=theme["background"],
    ).pack(anchor="w")
    tk.Label(
        body, text=CONSENT_TEXT.format(server=server), font=(FONT_FAMILY, 10),
        foreground=theme["muted"], background=theme["background"],
        wraplength=px(440), justify="left",
    ).pack(anchor="w", pady=(px(10), px(18)))
    buttons = tk.Frame(body, background=theme["background"])
    buttons.pack(fill="x")

    def finish(enable):
        choice["enable"] = enable
        root.destroy()

    def button(text, command, primary):
        return tk.Button(
            buttons, text=text, command=command, font=(FONT_FAMILY, 10, "bold"),
            background=theme["accent"] if primary else theme["surface_alt"],
            foreground="#ffffff",
            activebackground=theme["accent_active"] if primary else theme["border"],
            activeforeground="#ffffff", relief="flat", borderwidth=0,
            highlightthickness=0, cursor="hand2", padx=px(18), pady=px(9),
        )

    not_now = button("Not now", lambda: finish(False), primary=False)
    not_now.pack(side="right")
    button("Turn on live monitoring", lambda: finish(True), primary=True).pack(
        side="right", padx=(0, px(10))
    )
    root.bind("<Escape>", lambda _event: finish(False))
    root.protocol("WM_DELETE_WINDOW", lambda: finish(False))
    root.update_idletasks()
    _place_window(root, body.winfo_reqwidth(), body.winfo_reqheight())
    _bring_to_front(root)
    not_now.focus_set()
    root.mainloop()
    return choice["enable"]


def offer_live_monitoring(args, monitoring, device_id, use_window):
    """Ask the device user; enable only on an explicit yes."""
    token = monitoring.get("token") if isinstance(monitoring, dict) else None
    if not token or not monitoring_supported():
        return False
    try:
        server = _server_base(SUBMISSION_URL)
    except ValueError:
        LOGGER.exception("Live monitoring was not offered: invalid server address.")
        return False
    if args.yes:
        agreed = bool(args.enable_monitoring)
    else:
        agreed = None
        if use_window:
            try:
                agreed = ask_monitoring_consent_window(urlsplit(server).netloc)
            except Exception:
                LOGGER.exception("The monitoring consent window could not be shown.")
        if agreed is None and not (sys.stdin is not None and sys.stdin.isatty()):
            agreed = False
        if agreed is None:
            print("\nTurn on live monitoring?\n")
            print(CONSENT_TEXT.format(server=urlsplit(server).netloc))
            answer = input("\nType yes to turn on live monitoring (press Enter to skip): ")
            agreed = answer.strip().casefold() in {"yes", "y"}
    if not agreed:
        LOGGER.info("Live monitoring was not enabled (the user declined).")
        print("Live monitoring is off. You can link the device again later to turn it on.")
        return False
    return enable_live_monitoring(server, device_id, token)


class SubmissionError(RuntimeError):
    """The server refused a submission or could not be reached; str() is user-facing."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def submit_payload(submission_url, authorization_token, payload, *, scanner_mode, linked_with_link):
    """POST a registration or scan payload and return the server's JSON result."""
    response_key = "run_id" if scanner_mode else "device_id"
    try:
        report = payload.get("report") if isinstance(payload, dict) else None
        LOGGER.info(
            "Submitting payload (mode=%s, url=%s, payload_keys=%s, report_keys=%s).",
            "scanner" if scanner_mode else "registration",
            submission_url,
            sorted(payload.keys()) if isinstance(payload, dict) else [],
            sorted(report.keys()) if isinstance(report, dict) else [],
        )
        request = urllib.request.Request(
            submission_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {authorization_token}",
                "Content-Type": "application/json",
                # Lets the server offer opt-in live monitoring to this agent.
                **(
                    {"X-DevMonitor-Monitoring": "supported"}
                    if not scanner_mode and monitoring_supported()
                    else {}
                ),
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            response_status = getattr(response, "status", None) or response.getcode()
            result = json.loads(response.read().decode("utf-8"))
        LOGGER.info(
            "Submission response received (status=%s, keys=%s).",
            response_status,
            sorted(result.keys()) if isinstance(result, dict) else [],
        )
        if not isinstance(result, dict) or response_key not in result:
            raise ValueError("The server returned an invalid submission response.")
        return result
    except urllib.error.HTTPError as error:
        LOGGER.exception("Device agent submission failed with HTTP %s.", error.code)
        message = error.read().decode("utf-8", errors="replace")
        try:
            message = json.loads(message).get("error") or message
        except (ValueError, AttributeError):
            pass
        if error.code == 401 and linked_with_link:
            message = (
                "Submission failed: this registration link has expired or was already used.\n"
                "Click \"Link this device\" on the DevMonitor website to get a new one."
            )
        elif error.code == 401 and not scanner_mode:
            message = (
                "Submission failed: this download has expired or was already used.\n"
                "Download the agent again from the DevMonitor website (Downloads page) "
                "and run the new copy."
            )
        else:
            message = f"Submission failed ({error.code}): {message}"
        raise SubmissionError(message, error.code) from error
    except (
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        LOGGER.exception("Device agent submission could not be completed.")
        raise SubmissionError(f"Could not submit the information: {error}") from error


# --------------------------------------------------------------------------
# Link hand-off between agent processes
# --------------------------------------------------------------------------
#
# A generic build gets its one-use link from the website, which hands it back by
# starting this program again with a devmonitor:// argument. Instead of a second
# window, that process forwards the link to the window that is already open (over
# loopback, with a per-run key kept in the user's own profile) and exits.

HANDOFF_MAX_BYTES = 4096


def _handoff_path():
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / "DevMonitor" / "agent-handoff.json"


def _read_message(connection, limit=HANDOFF_MAX_BYTES):
    chunks, size = [], 0
    while size < limit:
        chunk = connection.recv(limit - size)
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


class LinkHandoff:
    """Receives devmonitor:// links from re-launched copies of this agent."""

    def __init__(self, on_link):
        self._on_link = on_link
        self._key = secrets.token_urlsafe(32)
        self._socket = None
        self._path = _handoff_path()

    def start(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.bind(("127.0.0.1", 0))
            self._socket.listen(2)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps({"port": self._socket.getsockname()[1], "key": self._key}),
                encoding="utf-8",
            )
        except OSError:
            LOGGER.warning("The link hand-off listener could not start.", exc_info=True)
            self.stop()
            return False
        threading.Thread(target=self._serve, name="devmonitor-link-handoff", daemon=True).start()
        return True

    def _serve(self):
        while self._socket is not None:
            try:
                connection, _address = self._socket.accept()
            except (OSError, AttributeError):
                return
            with connection:
                try:
                    connection.settimeout(5)
                    message = json.loads(_read_message(connection).decode("utf-8"))
                    if not hmac.compare_digest(str(message.get("key", "")), self._key):
                        LOGGER.warning("Ignored a link hand-off with the wrong key.")
                        continue
                    self._on_link(str(message.get("link", "")))
                    connection.sendall(b"ok")
                except (OSError, ValueError, AttributeError):
                    LOGGER.warning("Ignored an invalid link hand-off.", exc_info=True)

    def stop(self):
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        try:
            if json.loads(self._path.read_text(encoding="utf-8")).get("key") == self._key:
                self._path.unlink()
        except (OSError, ValueError, AttributeError):
            pass


def hand_off_link(link):
    """Give `link` to an agent window that is already open; False when there is none."""
    try:
        details = json.loads(_handoff_path().read_text(encoding="utf-8"))
        with socket.create_connection(("127.0.0.1", int(details["port"])), timeout=3) as connection:
            connection.sendall(json.dumps({"key": details["key"], "link": link}).encode("utf-8"))
            connection.shutdown(socket.SHUT_WR)
            accepted = _read_message(connection, 16) == b"ok"
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return False
    LOGGER.info("Handed the registration link to the open scanner window (accepted=%s).", accepted)
    return accepted


# --------------------------------------------------------------------------
# Scanner window
# --------------------------------------------------------------------------

WINDOW_COLORS = {
    "background": AGENT_THEME["background"],
    "panel": AGENT_THEME["surface_alt"],
    "text": AGENT_THEME["text"],
    "muted": AGENT_THEME["muted"],
    "error": AGENT_THEME["error"],
    "link": AGENT_THEME["accent_light"],
    "accent": AGENT_THEME["accent"],
    "accent_active": AGENT_THEME["accent_active"],
}


class ScannerWindow:  # pragma: no cover - needs a display
    """What a downloaded agent opens: the device is scanned, reviewed and registered.

    Scanning starts with the window. Enrollment runs in the background: a per-download
    build already carries its token, and a generic build asks the website (where the
    user is signed in) for a one-use link that comes back through LinkHandoff.
    Nothing is sent until the user selects Register This Device.
    """

    def __init__(self, enrollment, *, linked_with_link):
        import tkinter as tk
        from tkinter import ttk

        self.enrollment = enrollment
        self.linked_with_link = linked_with_link
        self.specifications = None
        # (server result, enrollment) once the device is registered.
        self.registered = None
        self.waiting_message = ""
        self.events = queue.Queue()
        self.handoff = None
        colors = WINDOW_COLORS
        plain = {"background": colors["background"], "foreground": colors["text"]}
        field = {
            "background": colors["panel"],
            "foreground": colors["text"],
            "insertbackground": colors["text"],
            "relief": "flat",
        }
        secondary = {
            "background": colors["panel"],
            "foreground": colors["text"],
            "activebackground": colors["accent_active"],
            "activeforeground": "#ffffff",
            "relief": "flat",
            "padx": 14,
            "pady": 8,
        }

        _enable_dpi_awareness()
        root = self.root = tk.Tk()
        root.title("DevMonitor Device Scanner")
        scale = _pixel_scale(root)
        _place_window(root, int(640 * scale), int(680 * scale))
        root.minsize(int(520 * scale), int(540 * scale))
        root.configure(background=colors["background"])
        style = ttk.Style(root)
        try:
            style.theme_use("clam")  # the native theme ignores the dark colours below
        except tk.TclError:
            pass
        style.configure(
            "Scanner.TCombobox",
            fieldbackground=colors["panel"],
            background=colors["panel"],
            foreground=colors["text"],
            arrowcolor=colors["text"],
        )
        style.map(
            "Scanner.TCombobox",
            fieldbackground=[("readonly", colors["panel"])],
            foreground=[("readonly", colors["text"])],
            selectbackground=[("readonly", colors["panel"])],
            selectforeground=[("readonly", colors["text"])],
        )
        style.configure(
            "Scanner.Horizontal.TProgressbar",
            background=colors["accent"],
            troughcolor=colors["panel"],
        )

        tk.Label(
            root, text="DevMonitor Device Scanner", font=("Segoe UI", 16, "bold"), **plain
        ).pack(anchor="w", padx=20, pady=(18, 2))
        self.status = tk.StringVar(value="Scanning this device...")
        self.status_label = tk.Label(
            root, textvariable=self.status, font=("Segoe UI", 10), wraplength=590,
            justify="left", background=colors["background"], foreground=colors["muted"],
        )
        self.status_label.pack(anchor="w", padx=20)
        self.progress = ttk.Progressbar(
            root, mode="indeterminate", style="Scanner.Horizontal.TProgressbar"
        )
        self.progress.pack(fill="x", padx=20, pady=(8, 4))
        self.progress.start(12)

        details_frame = tk.Frame(root, background=colors["panel"])
        details_frame.pack(fill="both", expand=True, padx=20, pady=8)
        scrollbar = tk.Scrollbar(details_frame)
        scrollbar.pack(side="right", fill="y")
        self.details = tk.Text(
            details_frame, wrap="word", height=14, font=("Segoe UI", 10),
            padx=12, pady=10, yscrollcommand=scrollbar.set, **field,
        )
        self.details.pack(fill="both", expand=True)
        scrollbar.configure(command=self.details.yview)
        self.details.tag_configure("label", foreground=colors["muted"])
        self.details.tag_configure(
            "section", foreground=colors["link"], font=(FONT_FAMILY, 11, "bold")
        )
        self.details.configure(state="disabled")

        form = tk.Frame(root, background=colors["background"])
        form.pack(fill="x", padx=20, pady=(4, 0))
        form.columnconfigure(1, weight=1)
        tk.Label(form, text="Device name", **plain).grid(row=0, column=0, sticky="w", pady=3)
        self.name = tk.StringVar(value=platform.node())
        tk.Entry(form, textvariable=self.name, **field).grid(
            row=0, column=1, sticky="we", padx=(10, 0), pady=3, ipady=4
        )
        tk.Label(form, text="Device type", **plain).grid(row=1, column=0, sticky="w", pady=3)
        self.device_type = tk.StringVar(value=_guess_device_type())
        ttk.Combobox(
            form, textvariable=self.device_type, values=("Desktop", "Laptop"),
            state="readonly", style="Scanner.TCombobox", width=12,
        ).grid(row=1, column=1, sticky="w", padx=(10, 0), pady=3)
        tk.Label(
            root,
            text=(
                "Only the details above and your device name and type are sent "
                "to your DevMonitor account."
            ),
            wraplength=590, justify="left", font=("Segoe UI", 9),
            background=colors["background"], foreground=colors["muted"],
        ).pack(anchor="w", padx=20, pady=(8, 0))

        self.buttons = tk.Frame(root, background=colors["background"])
        self.buttons.pack(fill="x", padx=20, pady=(12, 18))
        self.link_frame = tk.Frame(root, background=colors["background"])
        self.pasted_link = tk.StringVar()
        tk.Label(
            self.link_frame, text="Paste the link shown on the DevMonitor website:", **plain
        ).pack(anchor="w")
        row = tk.Frame(self.link_frame, background=colors["background"])
        row.pack(fill="x", pady=(4, 0))
        tk.Entry(row, textvariable=self.pasted_link, **field).pack(
            side="left", fill="x", expand=True, ipady=4
        )
        tk.Button(row, text="Use link", command=self._use_pasted_link, **secondary).pack(
            side="left", padx=(8, 0)
        )
        self.trouble = tk.Label(
            self.buttons, text="Having trouble linking?", cursor="hand2",
            font=("Segoe UI", 9, "underline"),
            background=colors["background"], foreground=colors["link"],
        )
        self.trouble.bind("<Button-1>", lambda _event: self._show_link_entry())
        self.register_button = tk.Button(
            self.buttons, text="Register This Device", command=self._register,
            state="disabled", background=colors["accent"], foreground="#ffffff",
            activebackground=colors["accent_active"], activeforeground="#ffffff",
            disabledforeground=colors["muted"], relief="flat", padx=18, pady=8,
        )
        self.register_button.pack(side="right")
        tk.Button(self.buttons, text="Close", command=root.destroy, **secondary).pack(
            side="right", padx=(0, 8)
        )

    def run(self):
        threading.Thread(target=self._scan, name="devmonitor-scan", daemon=True).start()
        if self.enrollment is None:
            self._request_link()
        self.root.after(100, self._poll)
        try:
            self.root.mainloop()
        finally:
            if self.handoff is not None:
                self.handoff.stop()
        return self.registered

    # -- background work (worker threads only post to self.events) ----------

    def _scan(self):
        try:
            self.events.put(("scanned", collect_specifications()))
        except (OSError, RuntimeError) as error:
            LOGGER.exception("Device inventory could not be collected.")
            self.events.put(("scan_failed", f"Could not collect device information: {error}"))

    def _request_link(self):
        """Generic build: the signed-in website hands this window a one-use link."""
        if self.handoff is None:
            self.handoff = LinkHandoff(lambda link: self.events.put(("link", link)))
            self.handoff.start()
        if open_website_to_link():
            self.waiting_message = (
                "Connecting to your DevMonitor account. Sign in on the website if your "
                "browser asks, and allow it to open DevMonitor Agent."
            )
        else:
            self.waiting_message = (
                "Sign in on the DevMonitor website on this computer and select "
                "Link this device on the Link a Device page."
            )
            self._show_link_entry()
        self._refresh()

    def _poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                getattr(self, f"_on_{kind}")(value)
        except queue.Empty:
            pass
        self.root.after(150, self._poll)

    # -- events (run on the Tk thread) ---------------------------------------

    def _on_scanned(self, specifications):
        self.specifications = specifications
        self.progress.stop()
        self.progress.pack_forget()
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        for title, rows in specification_sections(specifications):
            self.details.insert("end", f"{title}\n", "section")
            for row in rows:
                indent = "    " if row["detail"] else ""
                self.details.insert("end", f"{indent}{row['label']}\n", "label")
                self.details.insert("end", f"{indent}{row['value']}\n")
            self.details.insert("end", "\n")
        self.details.configure(state="disabled")
        self._refresh()

    def _on_scan_failed(self, message):
        self.progress.stop()
        self.progress.pack_forget()
        self._set_status(message, error=True)

    def _on_link(self, link):
        if self.enrollment is not None:
            return
        try:
            self.enrollment = parse_enrollment_link(link)
        except ValueError as error:
            self._set_status(str(error), error=True)
            return
        LOGGER.info("Using a registration link for %s.", self.enrollment[0])
        self.link_frame.pack_forget()
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self._refresh()

    def _on_submitted(self, result):
        self.registered = (result, self.enrollment)
        self.root.destroy()

    def _on_submit_failed(self, error):
        if error.status == 401 and self.linked_with_link:
            # The link expired or was used already: fetch a fresh one in the background.
            self.enrollment = None
            self._request_link()
            self._set_status(
                "That link has expired or was already used. Getting a new one from "
                "the DevMonitor website...",
                error=True,
            )
            return
        self.register_button.configure(state="normal")
        self._set_status(str(error), error=True)

    # -- user actions --------------------------------------------------------

    def _use_pasted_link(self):
        self._on_link(self.pasted_link.get())

    def _show_link_entry(self):
        if self.enrollment is None:
            self.link_frame.pack(fill="x", padx=20, pady=(8, 0), before=self.buttons)

    def _register(self):
        name = (self.name.get().strip() or platform.node() or "").strip()
        if not name or len(name) > 120:
            self._set_status("Enter a device name between 1 and 120 characters.", error=True)
            return
        device_type = self.device_type.get()
        if device_type not in {"Desktop", "Laptop"}:
            self._set_status("Choose Desktop or Laptop.", error=True)
            return
        if self.enrollment is None or self.specifications is None:
            return
        submission_url, token, _dashboard_url = self.enrollment
        payload = {"name": name, "device_type": device_type, "specifications": self.specifications}
        self.register_button.configure(state="disabled")
        self._set_status("Registering this device...")

        def submit():
            try:
                result = submit_payload(
                    submission_url, token, payload,
                    scanner_mode=False, linked_with_link=self.linked_with_link,
                )
            except SubmissionError as error:
                self.events.put(("submit_failed", error))
                return
            LOGGER.info("Device registration succeeded (device_id=%s).", result["device_id"])
            self.events.put(("submitted", result))

        threading.Thread(target=submit, name="devmonitor-submit", daemon=True).start()

    # -- presentation --------------------------------------------------------

    def _refresh(self):
        ready = self.specifications is not None and self.enrollment is not None
        self.register_button.configure(state="normal" if ready else "disabled")
        if self.enrollment is None:
            self.trouble.pack(side="left")
        else:
            self.trouble.pack_forget()
        if ready:
            server = urlsplit(self.enrollment[0]).netloc
            self._set_status(
                "Scan complete. Review the details, then select Register This Device "
                f"to add it to your account on {server}."
            )
        elif self.specifications is None:
            self._set_status(" ".join(filter(None, ("Scanning this device...", self.waiting_message))))
        else:
            self._set_status(self.waiting_message)

    def _set_status(self, text, *, error=False):
        self.status.set(text)
        self.status_label.configure(
            foreground=WINDOW_COLORS["error"] if error else WINDOW_COLORS["muted"]
        )


def _wants_window(args):
    """A packaged agent opened by double-click (no console) shows the scanner window.

    Scripts, tests and CI keep the text flow (`--yes`, `--print-specs`,
    `--console`/`--cli`); `--gui` forces the window.
    """
    if args.yes or args.print_specs or args.console:
        return False
    if args.gui:
        return True
    if not getattr(sys, "frozen", False):
        return False
    return sys.stdin is None or sys.stdout is None or not sys.stdin.isatty()


def run_scanner_window(args, *, linked_with_link):
    """Open the scanner window; returns the process exit code.

    After registration the opt-in live monitoring question and the success
    window follow, exactly as in the text flow.
    """
    global SUBMISSION_URL, REGISTRATION_TOKEN, DASHBOARD_URL

    link = args.link
    if linked_with_link:
        register_link_handler()
        if link and hand_off_link(link):
            return 0  # the window that is already open continues with this link
        enrollment = None
    else:
        enrollment = (SUBMISSION_URL, REGISTRATION_TOKEN, DASHBOARD_URL)
    try:
        import tkinter
    except ImportError:
        LOGGER.exception("The scanner window is unavailable (tkinter is missing).")
        return 1
    try:
        window = ScannerWindow(enrollment, linked_with_link=linked_with_link)
    except (tkinter.TclError, OSError, RuntimeError):
        LOGGER.exception("The scanner window could not be opened.")
        return 1
    if link:
        window.events.put(("link", link))
    registered = window.run()
    if registered is None:
        return 0
    result, (SUBMISSION_URL, REGISTRATION_TOKEN, DASHBOARD_URL) = registered
    offer_live_monitoring(args, result.get("monitoring"), result["device_id"], use_window=True)
    try:
        show_registration_success()
    except (ImportError, OSError, RuntimeError):
        LOGGER.exception("The registration success window could not be displayed.")
    return 0


def _guess_device_type():
    try:
        return "Laptop" if psutil.sensors_battery() is not None else "Desktop"
    except (AttributeError, NotImplementedError, OSError, RuntimeError):
        return "Desktop"


def _parse_arguments(argv):
    parser = argparse.ArgumentParser(description="Register this computer with DevMonitor.")
    parser.add_argument("link", nargs="?", help="devmonitor://enroll link from the website")
    parser.add_argument("--yes", action="store_true", help="submit without prompting")
    parser.add_argument("--name", help="device name to use with --yes")
    parser.add_argument("--device-type", choices=["Desktop", "Laptop"], help="used with --yes")
    parser.add_argument("--version", action="version", version=AGENT_VERSION)
    monitoring = parser.add_mutually_exclusive_group()
    monitoring.add_argument(
        "--monitor",
        action="store_true",
        help="run live monitoring (started at sign-in once you have turned it on)",
    )
    monitoring.add_argument(
        "--stop-monitoring",
        action="store_true",
        help="turn live monitoring off on this device and tell DevMonitor",
    )
    parser.add_argument(
        "--enable-monitoring",
        action="store_true",
        help="with --yes: also turn on live monitoring (you consent to it)",
    )
    parser.add_argument(
        "--print-specs",
        action="store_true",
        help="print the detected specifications as JSON and exit (nothing is sent)",
    )
    parser.add_argument("--output", help="with --print-specs: write the JSON to this file")
    review = parser.add_mutually_exclusive_group()
    review.add_argument(
        "--console",
        "--cli",
        dest="console",
        action="store_true",
        help="review the specifications in this console instead of a window",
    )
    review.add_argument(
        "--gui",
        action="store_true",
        help="review the specifications in a window (the default for the packaged EXE)",
    )
    args, _unknown = parser.parse_known_args(argv)
    return args


def _use_review_window(args):
    """The packaged EXE reviews in a window; running the script keeps the console."""
    if args.yes or args.console:
        return False
    return bool(args.gui or getattr(sys, "frozen", False))


def main(argv=None):
    global REGISTRATION_TOKEN, SUBMISSION_URL, DASHBOARD_URL

    args = _parse_arguments(sys.argv[1:] if argv is None else argv)
    log_path = configure_logging()
    if args.monitor:
        return run_monitor()
    if args.stop_monitoring:
        return stop_live_monitoring()
    if args.print_specs:
        try:
            text = json.dumps(
                {"device_type": _guess_device_type(), "specifications": collect_specifications()},
                indent=2,
                default=str,
            )
        except RuntimeError as error:
            print(f"Could not collect device information: {error}", file=sys.stderr)
            return 1
        if args.output:
            try:
                Path(args.output).write_text(text + "\n", encoding="utf-8")
            except OSError as error:
                print(f"Could not write {args.output}: {error}", file=sys.stderr)
                return 1
        else:
            print(text)
        return 0
    scanner_mode = (
        SCAN_RUN_ID not in {"__SCAN_RUN_ID__", ""}
        or "/api/device-agent/scans/" in SUBMISSION_URL
    )
    linked_with_link = not scanner_mode and not _embedded(REGISTRATION_TOKEN)
    if not scanner_mode and _wants_window(args):
        return run_scanner_window(args, linked_with_link=linked_with_link)
    if linked_with_link:
        # Generic build: the one-use token comes from a "Link this device" link.
        register_link_handler()
        interactive = sys.stdin is not None and sys.stdin.isatty() and not args.yes
        enrollment = resolve_link_enrollment(args.link, interactive=interactive)
        if enrollment is None:
            _show_log_location(log_path)
            return 2
        SUBMISSION_URL, REGISTRATION_TOKEN, DASHBOARD_URL = enrollment
        LOGGER.info("Using a registration link for %s.", SUBMISSION_URL)
    try:
        specifications = collect_specifications()
    except RuntimeError as error:
        LOGGER.exception("Device inventory could not be collected.")
        print(f"Could not collect device information: {error}", file=sys.stderr)
        _show_log_location(log_path)
        return 1

    report = collect_health_report(specifications)
    reviewed = None
    if not scanner_mode and _use_review_window(args):
        # The packaged EXE shows the specifications in a window; if Tk cannot
        # open one, the console review below is used instead.
        print("\nReview the detected device details in the DevMonitor window.")
        try:
            reviewed = review_specifications_window(
                specifications,
                default_name=(platform.node() or "").strip(),
                default_type=_guess_device_type(),
                server=urlsplit(SUBMISSION_URL).netloc,
            )
        except Exception:
            LOGGER.exception("The review window could not be displayed; using the console.")
            print("The review window could not be opened; continuing in this console.")
        else:
            if reviewed is None:
                LOGGER.info("Submission cancelled in the review window; nothing was sent.")
                print("Submission cancelled; no device was registered.")
                print(
                    "Run this agent again and click Register this device "
                    "to link the device to your account."
                )
                return 0

    if scanner_mode:
        payload = {"report": report, "specifications": specifications}
        authorization_token = SCAN_TOKEN
    elif reviewed is not None:
        payload = {
            "name": reviewed["name"],
            "device_type": reviewed["device_type"],
            "specifications": specifications,
        }
        authorization_token = REGISTRATION_TOKEN
    else:
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
        if args.yes:
            name = (args.name or platform.node() or "").strip()
            device_type = args.device_type or _guess_device_type()
        else:
            name = input(f"\nDevice name for DevMonitor [{platform.node()}]: ").strip()
            name = name or platform.node()
        if not name or len(name) > 120:
            print("Enter a device name between 1 and 120 characters.", file=sys.stderr)
            return 1
        while not args.yes:
            device_type = input("Device type (Desktop/Laptop): ").strip().title()
            if device_type in {"Desktop", "Laptop"}:
                break
            print("Choose Desktop or Laptop.")

        print("\nOnly the specifications listed above and your device name/type will be sent.")
        answer = "yes" if args.yes else input(
            "Submit this device to your DevMonitor account? Type yes to confirm: "
        )
        if answer.strip().casefold() not in {"yes", "y"}:
            LOGGER.info("Submission cancelled at the confirmation prompt; nothing was sent.")
            print("Submission cancelled; no device was registered.")
            print("Run this agent again and type yes to link the device to your account.")
            return 0
        payload = {
            "name": name,
            "device_type": device_type,
            "specifications": specifications,
        }
        authorization_token = REGISTRATION_TOKEN

    try:
        result = submit_payload(
            SUBMISSION_URL,
            authorization_token,
            payload,
            scanner_mode=scanner_mode,
            linked_with_link=linked_with_link,
        )
    except SubmissionError as error:
        print(str(error), file=sys.stderr)
        _show_log_location(log_path)
        return 1

    if scanner_mode:
        LOGGER.info("Device scan submitted (run_id=%s).", result["run_id"])
        if not DASHBOARD_URL:
            LOGGER.warning("The dashboard URL is not configured; scan results were saved.")
        else:
            try:
                if not webbrowser.open(DASHBOARD_URL, new=2):
                    LOGGER.warning(
                        "Could not open the dashboard after scan submission: %s",
                        DASHBOARD_URL,
                    )
            except (OSError, webbrowser.Error):
                LOGGER.warning(
                    "Could not open the dashboard after scan submission: %s",
                    DASHBOARD_URL,
                    exc_info=True,
                )
    else:
        LOGGER.info("Device registration succeeded (device_id=%s).", result["device_id"])
        print(f"Device Registered Successfully (Device ID: {result['device_id']}).")
        offer_live_monitoring(
            args,
            result.get("monitoring"),
            result["device_id"],
            use_window=reviewed is not None,
        )
        if args.yes:
            return 0
        try:
            show_registration_success()
        except (ImportError, OSError, RuntimeError) as error:
            LOGGER.exception("The registration success window could not be displayed.")
            print(
                f"Device registered successfully. Open the dashboard at {DASHBOARD_URL}.",
                file=sys.stderr,
            )
    return 0


def _pause_before_closing():
    """Keep the console window of the packaged EXE open so results stay readable."""
    if getattr(sys, "frozen", False) and sys.stdin is not None and sys.stdin.isatty():
        try:
            input("\nPress Enter to close this window...")
        except (EOFError, KeyboardInterrupt):
            pass


if __name__ == "__main__":
    exit_code = main()
    if not {"--yes", "--print-specs", "--monitor"} & set(sys.argv[1:]) and not _wants_window(
        _parse_arguments(sys.argv[1:])
    ):
        _pause_before_closing()
    raise SystemExit(exit_code)
