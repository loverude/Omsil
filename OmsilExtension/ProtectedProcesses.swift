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

    // MARK: - Code-signing identities (primary match)

    // Protected processes are matched by (Team ID, signing-ID prefix) rather than
    // executable path. The kernel computes these from the binary's signature, so
    // they are spoof-resistant — an attacker can't claim another team's ID without
    // that team's signing key — and stable across app updates, unlike a pinned
    // cdhash. A renamed/moved protected binary still matches (context.md bypass
    // #6). Values captured from the installed apps via `codesign -dv`:
    //   Little Snitch:  MLZF7K7B5R  at.obdev.littlesnitch[.daemon/.agent/...]
    //   Cold Turkey:    VH26F58M5A  com.getcoldturkey.blocker[, -safari-ext]
    //   Omsil (ours):   KLZNQUF7A7  com.jasperloverude.Omsil[.OmsilExtension]
    private static let identities: [(teamID: String, signingPrefixes: [String])] = [
        ("KLZNQUF7A7", ["com.jasperloverude.Omsil"]),
        ("MLZF7K7B5R", ["at.obdev.littlesnitch"]),
        ("VH26F58M5A", ["com.getcoldturkey."]),
    ]

    /// True if the signing identity belongs to a protected vendor/product. Both
    /// fields come straight from the kernel's view of the code signature and are
    /// empty for unsigned/adhoc binaries, which therefore never match here.
    private static func matchesIdentity(teamID: String, signingID: String) -> Bool {
        guard !teamID.isEmpty else { return false }
        return identities.contains { rule in
            rule.teamID == teamID && rule.signingPrefixes.contains { signingID.hasPrefix($0) }
        }
    }

    /// Legacy name/path-fragment match, retained only as a fallback for binaries
    /// with no usable signing info. It can false-negative on a moved/renamed
    /// binary — exactly what the identity match above fixes — but it can't reduce
    /// protection (false positives are harmless in this threat model).
    private static func matchesPath(executablePath path: String) -> Bool {
        let name = (path as NSString).lastPathComponent
        if names.contains(name) { return true }
        return pathFragments.contains { path.contains($0) }
    }

    /// True if the target process is protected: identity match first, path fallback.
    private static func isProtected(teamID: String, signingID: String, executablePath path: String) -> Bool {
        matchesIdentity(teamID: teamID, signingID: signingID) || matchesPath(executablePath: path)
    }

    /// Returns true if the given signal to the given target should be denied.
    static func shouldBlock(signal sig: Int32, teamID: String, signingID: String, executablePath path: String) -> Bool {
        guard sig == SIGKILL || sig == SIGTERM || sig == SIGSTOP else { return false }
        return isProtected(teamID: teamID, signingID: signingID, executablePath: path)
    }

    // MARK: - Task-port protection

    /// True if acquiring a Mach task port for the given target should be denied.
    /// A control task port (`task_for_pid` → `AUTH_GET_TASK`) grants full
    /// read/write/suspend over the target — enough to neutralise the guard
    /// without ever sending it a signal it could see (context.md bypass #3). The
    /// read-only port (`AUTH_GET_TASK_READ`, used by debuggers/profilers/crash
    /// reporters) is denied for the same tamper reason; if that interferes with
    /// legitimate diagnostics on the protected apps, drop the GET_TASK_READ
    /// subscription in ESFGuard and keep only GET_TASK.
    static func shouldBlockTaskAccess(teamID: String, signingID: String, executablePath path: String) -> Bool {
        isProtected(teamID: teamID, signingID: signingID, executablePath: path)
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
