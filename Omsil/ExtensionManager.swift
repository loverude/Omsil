import Foundation
import SystemExtensions
import OSLog

private let log = Logger(subsystem: "com.jasperloverude.Omsil", category: "ExtensionManager")

@MainActor
final class ExtensionManager: NSObject, ObservableObject {
    static let extensionBundleID = "com.jasperloverude.Omsil.OmsilExtension"

    // Omsil is activate-only: there is deliberately no deactivation path in the
    // UI or this manager. Removing the guard is a privileged operation done via
    // System Settings / `systemextensionsctl` under a lockdown checklist, not a
    // one-tap button (context.md step C).
    enum Status: Equatable {
        case unknown, activating, active
        case failed(String)

        static func == (lhs: Status, rhs: Status) -> Bool {
            switch (lhs, rhs) {
            case (.unknown, .unknown), (.activating, .activating),
                 (.active, .active): return true
            case (.failed(let a), .failed(let b)): return a == b
            default: return false
            }
        }

        var isActive: Bool { self == .active }
        var isTransitioning: Bool { self == .activating }
    }

    @Published private(set) var status: Status = .unknown
    @Published private(set) var statusMessage = "Tap Activate to install the process guard."

    /// Activates unless already active or mid-activation. Safe to call on every
    /// launch — this is what the Omsil watchdog relies on when it relaunches the
    /// app to recover from an out-of-band deactivation (context.md step B).
    func activateIfNeeded() {
        guard !status.isActive && !status.isTransitioning else { return }
        activate()
    }

    func activate() {
        status = .activating
        statusMessage = "Installing extension…"
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID,
            queue: .main
        )
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
                status = .active
                statusMessage = "Guard active — SIGKILL to protected processes is denied."
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
