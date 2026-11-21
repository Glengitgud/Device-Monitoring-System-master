import SwiftUI

@MainActor
final class AgentModel: ObservableObject {
    enum Phase: Equatable {
        case waitingForLink
        case review
        case submitting
        case registered(EnrollmentResult)
    }

    @Published var phase: Phase = .waitingForLink
    @Published var link: EnrollmentLink?
    @Published var specs: DeviceSpecs?
    @Published var deviceName = SpecCollector.defaultName
    @Published var pastedLink = ""
    @Published var message: String?

    func use(_ text: String) {
        do {
            link = try EnrollmentLink.parse(text)
            specs = SpecCollector.collect()
            message = nil
            phase = .review
        } catch {
            link = nil
            message = error.localizedDescription
            phase = .waitingForLink
        }
    }

    func register() {
        guard let link, let specs else { return }
        let name = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        let payload = specs.payload(name: name.isEmpty ? SpecCollector.defaultName : name,
                                    deviceType: SpecCollector.deviceType)
        phase = .submitting
        message = nil
        Task {
            do {
                phase = .registered(try await EnrollmentClient.submit(link: link, payload: payload))
            } catch {
                message = error.localizedDescription
                phase = .review
            }
        }
    }
}

struct ContentView: View {
    @ObservedObject var model: AgentModel
    @Environment(\.openURL) private var openURL

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("DEVMONITOR")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)
                Text("Device Agent").font(.largeTitle.bold())
                switch model.phase {
                case .waitingForLink:
                    waiting
                case .review, .submitting:
                    review
                case .registered(let result):
                    registered(result)
                }
                if let message = model.message {
                    Label(message, systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.red)
                }
            }
            .padding(24)
            .frame(maxWidth: 640, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
    }

    private var waiting: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("On this device, open the DevMonitor website, sign in, go to \u{201C}Link a Device\u{201D} and tap \u{201C}Link this device\u{201D}. You can also paste the link here.")
                .foregroundStyle(.secondary)
            TextField("devmonitor://enroll?\u{2026}", text: $model.pastedLink)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
            Button("Continue") { model.use(model.pastedLink) }
                .buttonStyle(.borderedProminent)
                .disabled(model.pastedLink.isEmpty)
        }
    }

    private var review: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Register this device with \(model.link?.host ?? "DevMonitor")? Nothing is sent until you tap Register.")
                .foregroundStyle(.secondary)
            if let specs = model.specs {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(specs.summary) { row in
                        HStack(alignment: .top) {
                            Text(row.label).foregroundStyle(.secondary).frame(width: 130, alignment: .leading)
                            Text(row.value)
                        }
                        .font(.callout)
                    }
                }
                .padding()
                .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 14))
            }
            TextField("Device name", text: $model.deviceName)
                .textFieldStyle(.roundedBorder)
            Button {
                model.register()
            } label: {
                if model.phase == .submitting {
                    ProgressView().frame(maxWidth: .infinity)
                } else {
                    Text("Register this device").frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(model.phase == .submitting)
        }
    }

    static func successMessage(for result: EnrollmentResult) -> String {
        let name: String = result.name ?? "this device"
        var message = "Registered \u{201C}" + name + "\u{201D}"
        if let assetTag = result.assetTag {
            message += " (asset " + assetTag + ")"
        }
        return message
    }

    private func registered(_ result: EnrollmentResult) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(Self.successMessage(for: result), systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
            Text("Your DevMonitor dashboard is now available.")
            if let server = model.link?.serverURL {
                Button("Open dashboard") { openURL(server.appendingPathComponent("dashboard")) }
                    .buttonStyle(.borderedProminent)
            }
        }
    }
}
