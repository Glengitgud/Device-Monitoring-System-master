import XCTest
@testable import DevMonitorAgent

final class EnrollmentLinkTests: XCTestCase {
    private let token = String(repeating: "T", count: 43)

    func testParsesWebsiteLink() throws {
        let link = try EnrollmentLink.parse(
            "devmonitor://enroll?server=https%3A%2F%2Fmonitor.example.edu&token=\(token)")
        XCTAssertEqual(link.submissionURL.absoluteString,
                       "https://monitor.example.edu/api/device-agent/enroll")
        XCTAssertEqual(link.token, token)
        XCTAssertEqual(link.host, "monitor.example.edu")
    }

    func testAllowsLocalDevelopmentServer() throws {
        let link = try EnrollmentLink.parse(
            "devmonitor://enroll?server=http%3A%2F%2F127.0.0.1%3A5077&token=\(token)")
        XCTAssertEqual(link.host, "127.0.0.1:5077")
    }

    func testRejectsUnsafeOrForeignLinks() {
        let bad = [
            "https://enroll?server=https%3A%2F%2Fa.example&token=\(token)",
            "devmonitor://other?server=https%3A%2F%2Fa.example&token=\(token)",
            "devmonitor://enroll?server=http%3A%2F%2Fevil.example&token=\(token)",
            "devmonitor://enroll?server=https%3A%2F%2Fuser%3Apw%40a.example&token=\(token)",
            "devmonitor://enroll?server=https%3A%2F%2Fa.example&token=short",
            "",
        ]
        for text in bad {
            XCTAssertThrowsError(try EnrollmentLink.parse(text), text)
        }
    }
}

final class PayloadTests: XCTestCase {
    func testPayloadMatchesServerContract() throws {
        var specs = DeviceSpecs()
        specs.cpuName = "Apple A17 Pro"
        specs.cpuCores = 6
        specs.ramCapacityBytes = 8 * 1024 * 1024 * 1024
        specs.model = "Apple iPhone16,1"
        specs.osName = "iOS"
        specs.osVersion = "17.5"
        specs.networkAdapters = ["en0"]
        specs.ipAddresses = ["192.0.2.30"]
        let payload = specs.payload(name: "Test iPhone", deviceType: "Phone")
        XCTAssertEqual(payload["device_type"] as? String, "Phone")
        let body = try XCTUnwrap(payload["specifications"] as? [String: Any])
        XCTAssertEqual(Set(body.keys), [
            "cpu_name", "cpu_cores", "ram_capacity_bytes", "ram_usage_bytes",
            "storage_devices", "storage_total_bytes", "storage_available_bytes",
            "gpu_information", "motherboard_brand", "operating_system_name",
            "operating_system_version", "network_adapters", "ip_addresses",
        ])
        // Storage is never sent off the device (Apple required-reason API rules).
        XCTAssertEqual((body["storage_devices"] as? [Any])?.count, 0)
        XCTAssertEqual(body["storage_total_bytes"] as? Int, 0)
        XCTAssertTrue(body["ram_usage_bytes"] is NSNull)
        XCTAssertEqual(body["gpu_information"] as? [String], ["Unavailable"])
        XCTAssertTrue(JSONSerialization.isValidJSONObject(payload))
    }

    func testSuccessMessage() {
        XCTAssertEqual(ContentView.successMessage(for: EnrollmentResult(name: "Pad", assetTag: "DM-1")),
                       "Registered \u{201C}Pad\u{201D} (asset DM-1)")
    }
}

@MainActor
final class DeviceCollectionTests: XCTestCase {
    func testCollectorProducesSubmittableSpecifications() throws {
        let specs = SpecCollector.collect()
        XCTAssertNotNil(specs.cpuName)
        XCTAssertGreaterThan(specs.cpuCores ?? 0, 0)
        XCTAssertGreaterThan(specs.ramCapacityBytes ?? 0, 0)
        XCTAssertNotNil(specs.osVersion)
        XCTAssertTrue(["Phone", "Tablet"].contains(SpecCollector.deviceType))
        XCTAssertFalse(SpecCollector.modelIdentifier().isEmpty)
        XCTAssertTrue(JSONSerialization.isValidJSONObject(
            specs.payload(name: "Simulator", deviceType: SpecCollector.deviceType)))
    }
}

/// Real enrollment against a DevMonitor backend. CI starts a throwaway server
/// (agents/ci/ci_backend.py) and passes the one-use link via
/// TEST_RUNNER_DEVMONITOR_LINK; without it the test is skipped, not faked.
@MainActor
final class BackendEnrollmentTests: XCTestCase {
    func testEnrollsWithBackendAndTokenIsSingleUse() async throws {
        guard let raw = ProcessInfo.processInfo.environment["DEVMONITOR_LINK"], !raw.isEmpty else {
            throw XCTSkip("DEVMONITOR_LINK not provided; backend end-to-end test runs in CI.")
        }
        let link = try EnrollmentLink.parse(raw)
        let payload = SpecCollector.collect().payload(name: "CI iOS Simulator",
                                                      deviceType: SpecCollector.deviceType)
        let result = try await EnrollmentClient.submit(link: link, payload: payload)
        XCTAssertEqual(result.name, "CI iOS Simulator")
        XCTAssertNotNil(result.assetTag)
        do {
            _ = try await EnrollmentClient.submit(link: link, payload: payload)
            XCTFail("A used registration link must be refused.")
        } catch EnrollmentError.expired {
            // expected
        }
    }
}
