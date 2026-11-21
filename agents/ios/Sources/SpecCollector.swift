import Darwin
import Metal
import UIKit

/// Collects what iOS exposes to App Store apps. Not available to apps: MAC
/// address, serial number, system-wide memory usage, and (since iOS 16) the
/// user-assigned device name; storage is withheld by policy (see DeviceSpecs).
@MainActor
enum SpecCollector {
    static func collect() -> DeviceSpecs {
        var specs = DeviceSpecs()
        let identifier = modelIdentifier()
        let gpu = MTLCreateSystemDefaultDevice()?.name
        specs.cpuName = gpu.map { $0.replacingOccurrences(of: " GPU", with: "") } ?? "Apple silicon"
        specs.cpuCores = ProcessInfo.processInfo.processorCount
        specs.ramCapacityBytes = Int64(clamping: ProcessInfo.processInfo.physicalMemory)
        specs.ramUsageBytes = nil
        if let gpu { specs.gpus = [gpu] }
        specs.model = "Apple \(identifier)"
        specs.osName = UIDevice.current.systemName
        specs.osVersion = UIDevice.current.systemVersion
        let network = networkInterfaces()
        specs.networkAdapters = network.adapters
        specs.ipAddresses = network.addresses
        return specs
    }

    static var deviceType: String {
        UIDevice.current.userInterfaceIdiom == .pad ? "Tablet" : "Phone"
    }

    static var defaultName: String { UIDevice.current.name }

    /// Hardware identifier such as "iPhone15,4".
    static func modelIdentifier() -> String {
        var info = utsname()
        uname(&info)
        return withUnsafeBytes(of: &info.machine) { buffer in
            String(decoding: buffer.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
    }

    static func networkInterfaces() -> (adapters: [String], addresses: [String]) {
        var adapters: [String] = []
        var addresses: [String] = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return ([], []) }
        defer { freeifaddrs(head) }
        var cursor = head
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let flags = Int32(entry.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0,
                  let address = entry.pointee.ifa_addr else { continue }
            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let length = socklen_t(family == AF_INET
                ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
            guard getnameinfo(address, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
            else { continue }
            var text = String(cString: host)
            if let scope = text.firstIndex(of: "%") { text = String(text[..<scope]) }
            if text.lowercased().hasPrefix("fe80") { continue }
            let name = String(cString: entry.pointee.ifa_name)
            if !adapters.contains(name) { adapters.append(name) }
            if !addresses.contains(text) { addresses.append(text) }
        }
        return (adapters, addresses)
    }
}
