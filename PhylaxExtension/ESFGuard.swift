import Foundation
import EndpointSecurity
import OSLog

private let log = Logger(subsystem: "com.jasperloverude.Phylax.PhylaxExtension", category: "ESF")

final class ESFGuard {
    private var client: OpaquePointer?

    init() throws {
        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { client, message in
            ESFGuard.handle(client: client, message: message)
        }
        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            self.client = newClient
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            throw Failure.notEntitled
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            throw Failure.notPermitted
        default:
            throw Failure.clientError(result)
        }

        let events: [es_event_type_t] = [ES_EVENT_TYPE_AUTH_SIGNAL]
        guard es_subscribe(self.client!, events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            throw Failure.subscriptionFailed
        }

        log.notice("ESF guard active — AUTH_SIGNAL events subscribed")
    }

    deinit {
        if let c = client { es_delete_client(c) }
    }

    // Static handler so we never need to capture self — avoids any ARC dance
    // with the opaque C block stored inside the ESF framework.
    private static func handle(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        guard message.pointee.event_type == ES_EVENT_TYPE_AUTH_SIGNAL else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let sig = message.pointee.event.signal.sig
        // path.data is null-terminated per ESF contract
        let path = String(cString: message.pointee.event.signal.target.pointee.executable.pointee.path.data)

        if ProtectedProcesses.shouldBlock(signal: sig, executablePath: path) {
            log.notice("Denied signal \(sig) → \(path, privacy: .public)")
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
        } else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }

    enum Failure: Error, LocalizedError {
        case notEntitled
        case notPermitted
        case subscriptionFailed
        case clientError(es_new_client_result_t)

        var errorDescription: String? {
            switch self {
            case .notEntitled:    return "Missing com.apple.developer.endpoint-security.client entitlement"
            case .notPermitted:   return "Not permitted — grant Full Disk Access in System Settings"
            case .subscriptionFailed: return "es_subscribe failed"
            case .clientError(let r): return "es_new_client failed: \(r.rawValue)"
            }
        }
    }
}
