import Foundation

/// One-use hand-off created by "Link this device":
/// `devmonitor://enroll?server=https%3A%2F%2Fhost&token=...`
struct EnrollmentLink: Equatable {
    let serverURL: URL
    let token: String

    var submissionURL: URL { serverURL.appendingPathComponent("api/device-agent/enroll") }

    var host: String {
        guard let host = serverURL.host else { return serverURL.absoluteString }
        if let port = serverURL.port { return "\(host):\(port)" }
        return host
    }

    enum ParseError: LocalizedError {
        case notDevMonitor, invalidServer, insecureServer, incomplete

        var errorDescription: String? {
            switch self {
            case .notDevMonitor: return "That is not a DevMonitor registration link."
            case .invalidServer: return "The registration link does not contain a valid server address."
            case .insecureServer: return "For your security the DevMonitor server must use HTTPS."
            case .incomplete: return "The registration link is incomplete. Create a new link on the website."
            }
        }
    }

    static func parse(_ text: String) throws -> EnrollmentLink {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed),
              components.scheme == "devmonitor", components.host == "enroll" else {
            throw ParseError.notDevMonitor
        }
        let items = components.queryItems ?? []
        let server = items.first(where: { $0.name == "server" })?.value ?? ""
        let token = items.first(where: { $0.name == "token" })?.value ?? ""
        let origin = try validateServer(server)
        guard token.range(of: "^[A-Za-z0-9_-]{40,64}$", options: .regularExpression) != nil else {
            throw ParseError.incomplete
        }
        return EnrollmentLink(serverURL: origin, token: token)
    }

    static func validateServer(_ server: String) throws -> URL {
        guard let parts = URLComponents(string: server),
              let scheme = parts.scheme, scheme == "https" || scheme == "http",
              let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/" else {
            throw ParseError.invalidServer
        }
        if scheme == "http" && !["localhost", "127.0.0.1", "::1"].contains(host) {
            throw ParseError.insecureServer
        }
        var origin = URLComponents()
        origin.scheme = scheme
        origin.host = host
        origin.port = parts.port
        guard let url = origin.url else { throw ParseError.invalidServer }
        return url
    }
}
