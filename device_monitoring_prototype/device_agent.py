"""Windows inventory agent.

Two builds come from this file:

* Per-download: a Windows server injects a one-use registration token below.
* Generic (published by CI): no token inside. It registers the ``devmonitor://``
  link handler for the current user and enrolls with the one-use
  ``devmonitor://enroll?server=...&token=...`` link from "Link this device",
  passed on the command line or pasted when asked.
"""

import argparse
import ipaddress
import ctypes
import ctypes.wintypes
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import platform
import re
import socket
import ssl
import sys
import tempfile
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


def show_registration_success():
    import tkinter as tk

    root = tk.Tk()
    root.title("Device Registered Successfully")
    root.geometry("430x300")
    root.resizable(False, False)
    root.configure(background="#0d0221")
    tk.Label(
        root, text="✓", font=("Segoe UI", 42, "bold"),
        foreground="#16a34a", background="#0d0221",
    ).pack(pady=(18, 0))
    tk.Label(
        root, text="Device Registered Successfully",
        font=("Segoe UI", 16, "bold"), foreground="#f8fafc",
        background="#0d0221",
    ).pack(pady=(2, 4))
    tk.Label(
        root, text="You may now proceed to the Dashboard.",
        foreground="#cbd5e1", background="#0d0221",
    ).pack()
    card = tk.Label(
        root, text="Open DevMonitor Dashboard",
        font=("Segoe UI", 11, "bold"), foreground="#93c5fd",
        background="#120636", cursor="hand2", padx=18, pady=14,
    )
    card.pack(fill="x", padx=28, pady=18)

    def redirect():
        webbrowser.open(DASHBOARD_URL)
        root.destroy()

    card.bind("<Button-1>", lambda _event: redirect())
    countdown = tk.Label(
        root, text="", foreground="#cbd5e1", background="#0d0221"
    )
    countdown.pack()

    def tick(seconds=5):
        countdown.configure(text=f"Redirecting to Dashboard in {seconds} seconds...")
        if seconds <= 0:
            redirect()
        else:
            root.after(1000, tick, seconds - 1)

    tk.Button(
        root,
        text="Go to Dashboard Now",
        command=redirect,
        background="#3458a8",
        foreground="#ffffff",
        activebackground="#26408b",
        activeforeground="#ffffff",
        relief="flat",
        padx=18,
        pady=8,
    ).pack(pady=(8, 14))
    root.after(0, tick)
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


def parse_enrollment_link(link):
    """Return (submission_url, token, dashboard_url) from a devmonitor://enroll link."""
    parsed = urlsplit((link or "").strip().strip('"'))
    if parsed.scheme != LINK_SCHEME or (parsed.netloc or parsed.path.strip("/")) != "enroll":
        raise ValueError("That is not a DevMonitor registration link.")
    query = parse_qs(parsed.query)
    server = urlsplit((query.get("server") or [""])[0])
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
    token = (query.get("token") or [""])[0]
    if not TOKEN_PATTERN.fullmatch(token):
        raise ValueError(
            "The registration link is incomplete. Create a new link on the website."
        )
    origin = f"{server.scheme}://{server.netloc}"
    return origin + ENROLL_PATH, token, origin + "/dashboard"


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
    parser.add_argument(
        "--print-specs",
        action="store_true",
        help="print the detected specifications as JSON and exit (nothing is sent)",
    )
    args, _unknown = parser.parse_known_args(argv)
    return args


def main(argv=None):
    global REGISTRATION_TOKEN, SUBMISSION_URL, DASHBOARD_URL

    args = _parse_arguments(sys.argv[1:] if argv is None else argv)
    log_path = configure_logging()
    if args.print_specs:
        try:
            print(json.dumps(
                {"device_type": _guess_device_type(), "specifications": collect_specifications()},
                indent=2,
                default=str,
            ))
        except RuntimeError as error:
            print(f"Could not collect device information: {error}", file=sys.stderr)
            return 1
        return 0
    scanner_mode = (
        SCAN_RUN_ID not in {"__SCAN_RUN_ID__", ""}
        or "/api/device-agent/scans/" in SUBMISSION_URL
    )
    linked_with_link = not scanner_mode and not _embedded(REGISTRATION_TOKEN)
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
    if scanner_mode:
        payload = {"report": report, "specifications": specifications}
        authorization_token = SCAN_TOKEN
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
        payload_keys = sorted(payload.keys()) if isinstance(payload, dict) else []
        report_keys = sorted(report.keys()) if scanner_mode and isinstance(report, dict) else []
        LOGGER.info(
            "Submitting payload (mode=%s, url=%s, payload_keys=%s, report_keys=%s).",
            "scanner" if scanner_mode else "registration",
            SUBMISSION_URL,
            payload_keys,
            report_keys,
        )
        request = urllib.request.Request(
            SUBMISSION_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {authorization_token}",
                "Content-Type": "application/json",
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
        response_key = "run_id" if scanner_mode else "device_id"
        if not isinstance(result, dict) or response_key not in result:
            raise ValueError("The server returned an invalid submission response.")
    except urllib.error.HTTPError as error:
        LOGGER.exception("Device agent submission failed with HTTP %s.", error.code)
        message = error.read().decode("utf-8", errors="replace")
        try:
            message = json.loads(message).get("error") or message
        except (ValueError, AttributeError):
            pass
        if error.code == 401 and linked_with_link:
            print(
                "Submission failed: this registration link has expired or was already used.\n"
                "Click \"Link this device\" on the DevMonitor website to get a new one.",
                file=sys.stderr,
            )
        elif error.code == 401 and not scanner_mode:
            print(
                "Submission failed: this download has expired or was already used.\n"
                "Download the agent again from the DevMonitor website (Downloads page) "
                "and run the new copy.",
                file=sys.stderr,
            )
        else:
            print(f"Submission failed ({error.code}): {message}", file=sys.stderr)
        _show_log_location(log_path)
        return 1
    except (
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        LOGGER.exception("Device agent submission could not be completed.")
        print(f"Could not submit the information: {error}", file=sys.stderr)
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
    if "--yes" not in sys.argv[1:] and "--print-specs" not in sys.argv[1:]:
        _pause_before_closing()
    raise SystemExit(exit_code)
