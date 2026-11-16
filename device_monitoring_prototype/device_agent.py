"""Windows inventory agent template; server injects one-time enrollment credentials."""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request


REGISTRATION_TOKEN = "__REGISTRATION_TOKEN__"
SUBMISSION_URL = "__SUBMISSION_URL__"

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$processors = @(Get-CimInstance Win32_Processor)
$memory = @(Get-CimInstance Win32_PhysicalMemory)
$osInfo = Get-CimInstance Win32_OperatingSystem
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')
$adapters = @(Get-CimInstance Win32_NetworkAdapter |
    Where-Object { $_.Name } |
    Select-Object -ExpandProperty Name -Unique)
$addresses = @(Get-NetIPAddress -AddressState Preferred -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.|::1$|fe80:)' } |
    Select-Object -ExpandProperty IPAddress -Unique)
$freeMemory = [long]$osInfo.FreePhysicalMemory * 1024
$ramCapacity = [long](($memory | Measure-Object -Property Capacity -Sum).Sum)
$coreCount = [int](($processors | Measure-Object -Property NumberOfCores -Sum).Sum)
$inventory = @{
    cpu_name = [string]($processors | Select-Object -First 1 -ExpandProperty Name)
    cpu_cores = $coreCount
    ram_capacity_bytes = $ramCapacity
    ram_usage_bytes = [long][Math]::Max(0, $ramCapacity - $freeMemory)
    storage_devices = @($disks | ForEach-Object {
        @{
            name = [string]$_.DeviceID
            total_bytes = [long]$_.Size
            available_bytes = [long]$_.FreeSpace
        }
    })
    storage_total_bytes = [long](($disks | Measure-Object -Property Size -Sum).Sum)
    storage_available_bytes = [long](($disks | Measure-Object -Property FreeSpace -Sum).Sum)
    gpu_information = @(
        Get-CimInstance Win32_VideoController |
            Select-Object -ExpandProperty Name -Unique
    )
    motherboard_brand = [string](
        Get-CimInstance Win32_BaseBoard | Select-Object -First 1 -ExpandProperty Manufacturer
    )
    operating_system_name = [string]$osInfo.Caption
    operating_system_version = [string]$osInfo.Version
    network_adapters = $adapters
    ip_addresses = $addresses
}
ConvertTo-Json -InputObject $inventory -Compress -Depth 4
"""

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


def display_value(key, value):
    if value is None or value == "":
        return "Not available"
    if key.endswith("_bytes") and isinstance(value, int):
        return f"{value:,} bytes ({value / (1024 ** 3):.2f} GiB)"
    if isinstance(value, list):
        return ", ".join(display_value(key, item) for item in value) or "None detected"
    if isinstance(value, dict):
        name = value.get("name", "Storage")
        total = display_value("total_bytes", value.get("total_bytes"))
        available = display_value("available_bytes", value.get("available_bytes"))
        return f"{name}: {total} total, {available} available"
    return str(value)


def collect_specifications():
    if os.name != "nt":
        raise RuntimeError("This agent supports Windows desktop and laptop devices only.")
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            POWERSHELL_SCRIPT,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        inventory = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Windows returned an unreadable hardware inventory.") from error
    if not isinstance(inventory, dict):
        raise RuntimeError("Windows returned an invalid hardware inventory.")
    return inventory


def main():
    try:
        specifications = collect_specifications()
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        print(f"Could not collect device information: {error}", file=sys.stderr)
        return 1

    print("\nDetected device specifications (review before submission):")
    for label, key in FIELD_LABELS:
        print(f"  {label}: {display_value(key, specifications.get(key))}")

    name = input("\nDevice name for DevMonitor: ").strip()
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
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        message = error.read().decode("utf-8", errors="replace")
        print(f"Registration failed ({error.code}): {message}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        print(f"Could not reach DevMonitor: {error}", file=sys.stderr)
        return 1

    print(f"Device registered successfully (Device ID: {result['device_id']}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
