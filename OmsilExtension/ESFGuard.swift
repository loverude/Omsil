import Foundation
import EndpointSecurity
import OSLog

private let log = Logger(subsystem: "com.jasperloverude.Omsil.OmsilExtension", category: "ESF")

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

        // AUTH_SIGNAL guards protected processes against kill/stop.
        // AUTH_EXEC guards the guard itself, denying `systemextensionsctl
        // deactivate`/`reset` (context.md bypasses #2, #5). Note: AUTH_EXEC fires
        // for every process launch system-wide, so the handler's allow path must
        // stay cheap — argv is only parsed for `systemextensionsctl`.
        let events: [es_event_type_t] = [ES_EVENT_TYPE_AUTH_SIGNAL, ES_EVENT_TYPE_AUTH_EXEC]
        guard es_subscribe(self.client!, events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            throw Failure.subscriptionFailed
        }

        log.notice("ESF guard active — AUTH_SIGNAL + AUTH_EXEC events subscribed")
    }

    deinit {
        if let c = client { es_delete_client(c) }
    }

    // Static handler so we never need to capture self — avoids any ARC dance
    // with the opaque C block stored inside the ESF framework.
    private static func handle(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_AUTH_SIGNAL:
            handleSignal(client: client, message: message)
        case ES_EVENT_TYPE_AUTH_EXEC:
            handleExec(client: client, message: message)
        default:
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }

    private static func handleSignal(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
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

    private static func handleExec(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        let path = String(cString: message.pointee.event.exec.target.pointee.executable.pointee.path.data)

        // Fast path: anything other than systemextensionsctl is allowed without
        // touching argv (this handler runs on every exec on the machine).
        guard ProtectedProcesses.isSystemExtensionTool(path: path) else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let args = execArguments(message)
        if ProtectedProcesses.shouldBlockExec(arguments: args) {
            log.notice("Denied exec \(path, privacy: .public) argv=\(args, privacy: .public)")
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
        } else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }

    /// Extracts argv from an AUTH_EXEC message. The es_exec_* accessors need a
    /// pointer to the exec event; a local copy is taken so we can pass an inout
    /// pointer (the message itself is delivered as an immutable pointer). The
    /// copied struct's internal offsets still reference the live message buffer,
    /// which is valid for the duration of this callback.
    private static func execArguments(_ message: UnsafePointer<es_message_t>) -> [String] {
        var exec = message.pointee.event.exec
        return withUnsafePointer(to: &exec) { execPtr -> [String] in
            let count = es_exec_arg_count(execPtr)
            var args: [String] = []
            args.reserveCapacity(Int(count))
            for i in 0..<count {
                if let s = string(from: es_exec_arg(execPtr, i)) { args.append(s) }
            }
            return args
        }
    }

    /// Argv tokens are length-delimited and not guaranteed null-terminated.
    private static func string(from token: es_string_token_t) -> String? {
        guard let data = token.data, token.length > 0 else { return nil }
        return data.withMemoryRebound(to: UInt8.self, capacity: token.length) {
            String(decoding: UnsafeBufferPointer(start: $0, count: token.length), as: UTF8.self)
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
