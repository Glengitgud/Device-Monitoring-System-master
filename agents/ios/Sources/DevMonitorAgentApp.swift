import SwiftUI

@main
struct DevMonitorAgentApp: App {
    @StateObject private var model = AgentModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .onOpenURL { url in model.use(url.absoluteString) }
        }
    }
}
