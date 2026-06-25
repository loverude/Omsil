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
        "PhylaxExtension",
        "Phylax",
    ]

    // Path substrings — catches helpers, daemons, and versioned bundles
    private static let pathFragments: [String] = [
        "/Cold Turkey Blocker.app/",
        "/Little Snitch",
        "coldturkey-watchdog",
        "LittleSnitch",
        "/Phylax.app/",
    ]

    /// Returns true if the given signal to the given executable path should be denied.
    static func shouldBlock(signal sig: Int32, executablePath path: String) -> Bool {
        guard sig == SIGKILL || sig == SIGTERM || sig == SIGSTOP else { return false }
        let name = (path as NSString).lastPathComponent
        if names.contains(name) { return true }
        return pathFragments.contains { path.contains($0) }
    }
}
