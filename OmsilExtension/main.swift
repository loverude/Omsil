import Foundation
import OSLog

private let log = Logger(subsystem: "com.jasperloverude.Omsil.OmsilExtension", category: "main")

// Strong reference lives for the entire process lifetime.
private var esfGuard: ESFGuard?

do {
    esfGuard = try ESFGuard()
} catch {
    log.fault("Failed to start ESF guard: \(error.localizedDescription)")
    exit(1)
}

RunLoop.main.run()
