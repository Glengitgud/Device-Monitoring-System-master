import Foundation

/// Specifications in the shape the DevMonitor server validates.
struct DeviceSpecs {
    var cpuName: String?
    var cpuCores: Int?
    var ramCapacityBytes: Int64?
    var ramUsageBytes: Int64?
    var gpus: [String] = []
    var model: String?
    var osName: String?
    var osVersion: String?
    var networkAdapters: [String] = []
    var ipAddresses: [String] = []

    static let unavailable = "Unavailable"

    /// Storage is intentionally empty: Apple's required-reason API rules do not
    /// allow apps to send disk-space information off the device.
    func payload(name: String, deviceType: String) -> [String: Any] {
        func value(_ item: Any?) -> Any { item ?? NSNull() }
        let specifications: [String: Any] = [
            "cpu_name": value(cpuName),
            "cpu_cores": value(cpuCores),
            "ram_capacity_bytes": value(ramCapacityBytes),
            "ram_usage_bytes": value(ramUsageBytes),
            "storage_devices": [Any](),
            "storage_total_bytes": 0,
            "storage_available_bytes": 0,
            "gpu_information": gpus.isEmpty ? [Self.unavailable] : gpus,
            "motherboard_brand": value(model),
            "operating_system_name": value(osName),
            "operating_system_version": value(osVersion),
            "network_adapters": networkAdapters.isEmpty ? [Self.unavailable] : networkAdapters,
            "ip_addresses": ipAddresses,
        ]
        return ["name": String(name.prefix(120)), "device_type": deviceType, "specifications": specifications]
    }

    var summary: [SpecRow] {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .memory
        let cores: String = cpuCores.map { String($0) } ?? Self.unavailable
        let memory: String = ramCapacityBytes.map { formatter.string(fromByteCount: $0) } ?? Self.unavailable
        let system: String = (osName ?? "iOS") + " " + (osVersion ?? "")
        return [
            SpecRow(label: "Chip", value: cpuName ?? Self.unavailable),
            SpecRow(label: "CPU cores", value: cores),
            SpecRow(label: "Memory", value: memory),
            SpecRow(label: "Graphics", value: gpus.isEmpty ? Self.unavailable : gpus.joined(separator: ", ")),
            SpecRow(label: "Model", value: model ?? Self.unavailable),
            SpecRow(label: "Operating system", value: system),
            SpecRow(label: "Network", value: networkAdapters.isEmpty ? Self.unavailable : networkAdapters.joined(separator: ", ")),
            SpecRow(label: "IP addresses", value: ipAddresses.isEmpty ? Self.unavailable : ipAddresses.joined(separator: ", ")),
            SpecRow(label: "Storage", value: "Not shared on iOS"),
        ]
    }
}

struct SpecRow: Identifiable, Equatable {
    let label: String
    let value: String
    var id: String { label }
}
