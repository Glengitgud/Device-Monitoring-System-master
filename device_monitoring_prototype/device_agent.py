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
from datetime import datetime
import urllib.error
from urllib.parse import urlsplit
import urllib.request
import webbrowser

import psutil


REGISTRATION_TOKEN = "__REGISTRATION_TOKEN__"
SUBMISSION_URL = "__SUBMISSION_URL__"
DIAGNOSTIC_RUN_ID = "__DIAGNOSTIC_RUN_ID__"
DIAGNOSTIC_TOKEN = "__DIAGNOSTIC_TOKEN__"
DASHBOARD_URL = "__DASHBOARD_URL__"
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
    parsed = urlsplit(SUBMISSION_URL)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        return False
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((parsed.hostname, port), timeout=3):
            return True
    except OSError:
        return False


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
    LOGGER.info("Starting one-time endpoint health and diagnostics assessment.")
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

    gpu_values = specifications.get("gpu_information") or []
    gpu_available = bool(gpu_values and gpu_values != [UNAVAILABLE])
    network_connected = _check_submission_connectivity()

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
        services = _collect_windows_services()
    except (psutil.Error, OSError):
        LOGGER.exception("Windows service status is unavailable.")
        services = {}

    cpu_score = _score_from_usage(cpu_usage) if cpu_usage is not None else None
    ram_score = _score_from_usage(ram_usage) if ram_usage is not None else None
    gpu_score = 100 if gpu_available else None
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
    driver_score = (
        max(30, 100 - round(old_driver_count / max(1, len(driver_dates)) * 60))
        if drivers
        else None
    )
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
        ("Storage capacity", "hardware", storage_score, "Lowest available volume space", min(storage_free_percent) if storage_free_percent else None, "% free"),
        ("GPU availability", "hardware", gpu_score, "GPU detected" if gpu_available else "GPU availability could not be confirmed", len(gpu_values) if gpu_available else None, "device(s)"),
        ("Network connectivity", "hardware", network_score, "Application host reachable" if network_connected else "Application host not reachable", network_connected, None),
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
                    f"The fullest accessible volume has {value:.1f}% free.",
                    "A nearly full volume can prevent updates and normal application work.",
                    "Free space safely or ask an administrator about storage expansion.",
                    ["Open Settings and select System, then Storage.", "Review temporary files and large items.", "Back up important files before removing them.", "Avoid deleting Windows or application folders manually."],
                )
            elif name == "Network connectivity":
                issue = _health_issue(
                    "DevMonitor connection unavailable", score,
                    "The agent could not establish a connection to the configured DevMonitor host.",
                    "The device may be offline, blocked by a firewall, or unable to resolve the host.",
                    "Check the network and retry; ask support if the service remains unavailable.",
                    ["Confirm Wi-Fi or Ethernet is connected.", "Open the DevMonitor site in a browser.", "Check whether a VPN or firewall is blocking access.", "Retry after connectivity returns."],
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

    for name, category, summary, limitation in (
        ("Startup performance", "software", "Startup duration was not measured.", "Reliable boot-duration history requires Windows event-log access and is not included in this one-time scan."),
        ("Device Manager warnings", "driver", "Plug-and-Play problem codes were not inspected.", "Driver metadata is not a substitute for Windows Device Manager problem codes."),
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
        "Health assessment completed with %d findings and %d checks.",
        len(issues),
        len(checks),
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


def show_health_window(report, title="Device health assessment"):
    """Display accessible circular scores and actionable local findings."""
    import tkinter as tk
    from tkinter.scrolledtext import ScrolledText

    try:
        root = tk.Tk()
    except tk.TclError as error:
        raise RuntimeError("A graphical desktop is unavailable.") from error
    root.title(title)
    root.geometry("860x690")
    root.minsize(680, 560)
    root.configure(background="#0d0221")
    root.option_add("*Font", "{Segoe UI} 10")
    tk.Label(
        root,
        text="Device health overview",
        font=("Segoe UI", 19, "bold"),
        foreground="#f8fafc",
        background="#0d0221",
    ).pack(anchor="w", padx=24, pady=(22, 2))
    tk.Label(
        root,
        text=(
            f"Overall {report['scores']['overall'] if report['scores']['overall'] is not None else 'N/A'}%  ·  "
            f"Hardware {report['scores']['hardware'] if report['scores']['hardware'] is not None else 'N/A'}%  ·  "
            f"Software {report['scores']['software'] if report['scores']['software'] is not None else 'N/A'}%  ·  "
            f"Drivers {report['scores']['drivers'] if report['scores']['drivers'] is not None else 'N/A'}%  "
            "— one-time checks on this computer; guidance, not continuous monitoring."
        ),
        foreground="#cbd5e1",
        background="#0d0221",
        wraplength=800,
        justify="left",
    ).pack(anchor="w", padx=24, pady=(0, 14))

    score_values = report["scores"]["components"]
    gauges = (
        ("CPU", score_values["cpu"]),
        ("RAM", score_values["ram"]),
        ("Storage", score_values["storage"]),
        ("GPU", score_values["gpu"]),
        ("Network", score_values["network"]),
        ("Drivers", score_values["drivers"]),
        ("Operating system", score_values["operating_system"]),
    )
    gauge_frame = tk.Frame(root, background="#0d0221")
    gauge_frame.pack(fill="x", padx=16)
    for index, (label, score) in enumerate(gauges):
        card = tk.Frame(
            gauge_frame,
            background="#120636",
            highlightbackground="#334155",
            highlightthickness=1,
        )
        card.grid(row=index // 4, column=index % 4, padx=6, pady=6, sticky="nsew")
        gauge_frame.grid_columnconfigure(index % 4, weight=1)
        canvas = tk.Canvas(card, width=112, height=112, background="#120636", highlightthickness=0)
        canvas.pack(padx=8, pady=(10, 0))
        canvas.create_oval(12, 12, 100, 100, outline="#334155", width=9)
        color, state = _health_band(score)
        if score is not None:
            canvas.create_arc(
                12, 12, 100, 100, start=90, extent=-score * 3.6,
                style="arc", outline=color, width=9,
            )
            score_text = f"{score}%"
        else:
            score_text = "N/A"
        canvas.create_text(56, 49, text=score_text, fill="#f8fafc", font=("Segoe UI", 17, "bold"))
        tk.Label(
            card,
            text=label,
            foreground="#f8fafc",
            background="#120636",
            wraplength=135,
        ).pack(padx=5, pady=(3, 0))
        tk.Label(
            card,
            text=state,
            foreground=color,
            background="#120636",
            font=("Segoe UI", 9, "bold"),
        ).pack(padx=5, pady=(0, 10))

    actions = ScrolledText(
        root, height=13, wrap="word", background="#120636",
        foreground="#e2e8f0", insertbackground="#ffffff",
        relief="flat", padx=12, pady=10,
    )
    actions.pack(fill="both", expand=True, padx=24, pady=12)
    if report["issues"]:
        for issue in report["issues"]:
            actions.insert(
                "end",
                f"{issue['severity'].upper()} — {issue['title']}\n"
                f"{issue['description']}\nCause: {issue['root_cause']}\n"
                f"Suggested action: {issue['recommendation']}\n"
                + "\n".join(f"  {step}. {instruction}" for step, instruction in enumerate(issue["steps"], 1))
                + "\n\n",
            )
    else:
        actions.insert("end", "No issues requiring attention were identified by the supported checks.\n\n")
    skipped = [
        check["name"] for check in report["checks"] if check["status"] == "skipped"
    ]
    if skipped:
        actions.insert("end", "Not assessed: " + ", ".join(skipped) + "\n")
    actions.configure(state="disabled")
    tk.Button(
        root,
        text="Continue",
        command=root.destroy,
        background="#3458a8",
        foreground="#ffffff",
        activebackground="#26408b",
        activeforeground="#ffffff",
        relief="flat",
        padx=24,
        pady=9,
    ).pack(anchor="e", padx=24, pady=(0, 18))
    root.mainloop()


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


def main():
    log_path = configure_logging()
    try:
        specifications = collect_specifications()
    except RuntimeError as error:
        LOGGER.exception("Device inventory could not be collected.")
        print(f"Could not collect device information: {error}", file=sys.stderr)
        _show_log_location(log_path)
        return 1

    report = collect_health_report(specifications)
    try:
        show_health_window(report)
    except (ImportError, OSError, RuntimeError) as error:
        LOGGER.exception("The graphical health overview could not be displayed.")
        print(f"Health overview window unavailable: {error}", file=sys.stderr)

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

    diagnostic_mode = DIAGNOSTIC_RUN_ID not in {"__DIAGNOSTIC_RUN_ID__", ""}
    if diagnostic_mode:
        print("\nThe diagnostic report will contain local health measurements and check results.")
        if input("Submit this diagnostic report? Type yes to confirm: ").strip().casefold() != "yes":
            print("Submission cancelled; no diagnostic report was saved.")
            return 0
        payload = {"report": report}
        authorization_token = DIAGNOSTIC_TOKEN
    else:
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
        payload = {
            "name": name,
            "device_type": device_type,
            "specifications": specifications,
        }
        authorization_token = REGISTRATION_TOKEN

    try:
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
            result = json.loads(response.read().decode("utf-8"))
        response_key = "run_id" if diagnostic_mode else "device_id"
        if not isinstance(result, dict) or response_key not in result:
            raise ValueError("The server returned an invalid submission response.")
    except urllib.error.HTTPError as error:
        LOGGER.exception("Device agent submission failed with HTTP %s.", error.code)
        message = error.read().decode("utf-8", errors="replace")
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

    if diagnostic_mode:
        LOGGER.info("Diagnostic report submitted (run_id=%s).", result["run_id"])
        print(f"Diagnostic report submitted (Run ID: {result['run_id']}).")
    else:
        LOGGER.info("Device registration succeeded (device_id=%s).", result["device_id"])
        print(f"Device Registered Successfully (Device ID: {result['device_id']}).")
        try:
            show_registration_success()
        except (ImportError, OSError, RuntimeError) as error:
            LOGGER.exception("The registration success window could not be displayed.")
            print(
                f"Device registered successfully. Open the dashboard at {DASHBOARD_URL}.",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
