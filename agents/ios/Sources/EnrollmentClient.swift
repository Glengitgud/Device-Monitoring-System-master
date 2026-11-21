import Foundation

struct EnrollmentResult: Equatable {
    let name: String?
    let assetTag: String?
}

enum EnrollmentError: LocalizedError {
    case expired
    case rejected(String)
    case unreachable(String)
    case insecure(String)

    var errorDescription: String? {
        switch self {
        case .expired:
            return "This registration link has expired or was already used. "
                + "Create a new one on the DevMonitor website and try again."
        case .rejected(let message):
            return message
        case .unreachable(let host):
            return "Could not reach the DevMonitor server at \(host). "
                + "Check your internet connection and try again."
        case .insecure(let host):
            return "The secure connection to \(host) could not be verified."
        }
    }
}

enum EnrollmentClient {
    private static let certificateErrors: Set<URLError.Code> = [
        .serverCertificateUntrusted, .serverCertificateHasBadDate,
        .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid,
        .secureConnectionFailed, .appTransportSecurityRequiresSecureConnection,
    ]

    static func submit(link: EnrollmentLink, payload: [String: Any]) async throws -> EnrollmentResult {
        var request = URLRequest(url: link.submissionURL, timeoutInterval: 20)
        request.httpMethod = "POST"
        request.setValue("Bearer \(link.token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("DevMonitorAgent/1.0.0 (iOS)", forHTTPHeaderField: "User-Agent")
        request.httpBody = try JSONSerialization.data(withJSONObject: payload)

        let exchange: (Data, URLResponse)
        do {
            exchange = try await URLSession.shared.data(for: request)
        } catch let error as URLError where certificateErrors.contains(error.code) {
            throw EnrollmentError.insecure(link.host)
        } catch {
            throw EnrollmentError.unreachable(link.host)
        }
        let (data, response) = exchange
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        switch status {
        case 200, 201:
            return EnrollmentResult(name: body?["name"] as? String, assetTag: body?["asset_tag"] as? String)
        case 401:
            throw EnrollmentError.expired
        default:
            throw EnrollmentError.rejected(
                body?["error"] as? String ?? "The server rejected the registration (HTTP \(status)).")
        }
    }
}
