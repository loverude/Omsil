import Foundation

enum ProtectedProcesses {
    // Exact executable names (last path component) to protect
    private static let names: Set<String> = [
        "Cold Turkey Blocker",
        "ColdTurkeyBlocker",
        "Little Snitch Agent",
        "Little Snitch Network Monitor",
        "LittleSnitchAgent",
        "LittleSnitchNetworkMonitor",
        "LittleSnitchDaemon",
        "LittleSnitchExtension",
        "OmsilExtension",
        "Omsil",
    ]

    // Path substrings — catches helpers, daemons, and versioned bundles.
    //
    // NOTE: `coldturkey-watchdog` is intentionally NOT listed here. AUTH_SIGNAL
    // reports the executable path of the *target process*, which for the watchdog
    // is the shell interpreter (`/bin/bash`), not the script path — the script
    // name is only an argv entry. A fragment match would never fire (dead code,
    // see context.md bypass #6). Watchdog recovery instead relies on launchd
    // `KeepAlive`, which restarts it in ~100ms.
    private static let pathFragments: [String] = [
        "/Cold Turkey Blocker.app/",
        "/Little Snitch",
        "LittleSnitch",
        "/Omsil.app/",
    ]

    /// Returns true if the given signal to the given executable path should be denied.
    static func shouldBlock(signal sig: Int32, executablePath path: String) -> Bool {
        guard sig == SIGKILL || sig == SIGTERM || sig == SIGSTOP else { return false }
        let name = (path as NSString).lastPathComponent
        if names.contains(name) { return true }
        return pathFragments.contains { path.contains($0) }
    }

    // MARK: - Exec protection

    /// Subcommands of `systemextensionsctl` that would tear down the guard.
    /// `deactivate` removes a named extension; `reset` unloads *all* extensions
    /// without taking a bundle-ID argument (context.md bypass #5), so it must be
    /// matched independently rather than relying on a bundle-ID argv check.
    private static let blockedSubcommands: Set<String> = ["deactivate", "reset"]

    /// True if the exec target is the `systemextensionsctl` CLI, whose argv we
    /// must inspect. All other executables are allowed without parsing argv so
    /// the AUTH_EXEC hot path stays cheap.
    static func isSystemExtensionTool(path: String) -> Bool {
        (path as NSString).lastPathComponent == "systemextensionsctl"
    }

    /// True if a `systemextensionsctl` invocation should be denied — i.e. it
    /// carries a destructive subcommand. Read-only use (`list`, etc.) is allowed
    /// so the Omsil watchdog can poll activation state.
    static func shouldBlockExec(arguments: [String]) -> Bool {
        arguments.contains { blockedSubcommands.contains($0) }
    }
}
