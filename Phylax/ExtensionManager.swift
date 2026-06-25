import Foundation
import SystemExtensions
import OSLog

private let log = Logger(subsystem: "com.jasperloverude.Phylax", category: "ExtensionManager")

@MainActor
final class ExtensionManager: NSObject, ObservableObject {
    static let extensionBundleID = "com.jasperloverude.Phylax.PhylaxExtension"

    enum Status: Equatable {
        case unknown, activating, active, deactivating, inactive
        case failed(String)

        static func == (lhs: Status, rhs: Status) -> Bool {
            switch (lhs, rhs) {
            case (.unknown, .unknown), (.activating, .activating),
                 (.active, .active), (.deactivating, .deactivating),
                 (.inactive, .inactive): return true
            case (.failed(let a), .failed(let b)): return a == b
            default: return false
            }
        }

        var isActive: Bool { self == .active }
        var isTransitioning: Bool { self == .activating || self == .deactivating }
    }

    @Published private(set) var status: Status = .unknown
    @Published private(set) var statusMessage = "Tap Activate to install the process guard."

    private var pendingActivation = true

    func activate() {
        pendingActivation = true
        status = .activating
        statusMessage = "Installing extension…"
        submit(OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID,
            queue: .main
        ))
    }

    func deactivate() {
        pendingActivation = false
        status = .deactivating
        statusMessage = "Removing extension…"
        submit(OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID,
            queue: .main
        ))
    }

    private func submit(_ request: OSSystemExtensionRequest) {
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }
}

extension ExtensionManager: OSSystemExtensionRequestDelegate {
    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            statusMessage = "Open System Settings → Privacy & Security to allow the extension."
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            switch result {
            case .completed:
                if pendingActivation {
                    status = .active
                    statusMessage = "Guard active — SIGKILL to protected processes is denied."
                } else {
                    status = .inactive
                    statusMessage = "Guard deactivated."
                }
            case .willCompleteAfterReboot:
                statusMessage = "Will complete after reboot."
            @unknown default:
                break
            }
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        let msg = error.localizedDescription
        log.error("Extension request failed: \(msg)")
        Task { @MainActor in
            status = .failed(msg)
            statusMessage = "Error: \(msg)"
        }
    }
}
