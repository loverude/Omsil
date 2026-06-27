# CLAUDE.md

## Project

Omsil is a macOS Endpoint Security Framework (ESF) system extension that hardens a
configurable set of protected processes (e.g. Cold Turkey, Little Snitch) against
termination and tampering — denying SIGKILL, exec replacement, and Mach task-port
acquisition.

- `Omsil/` — host app (SwiftUI) that installs/activates the system extension.
- `OmsilExtension/` — the ESF extension: `ESFGuard.swift` (auth event handling),
  `ProtectedProcesses.swift` (the protected set), `main.swift` (entry point).
- `OmsilTests/`, `OmsilUITests/` — test targets.

## Commit style

Use a lowercase **category/verb prefix + colon + summary**:

```
<prefix>: <imperative, lowercase summary>
```

Examples from history:

```
init: scaffold phylax esf system extension
rename: Harden guard (exec-block, activate-only) and rename Phylax → Omsil
harden: deny Mach task-port acquisition for protected processes
```

The prefix names the kind of change (`init`, `rename`, `harden`, `fix`, `refactor`,
`docs`, etc.). Keep the summary short and present-tense.

Do **not** add `Co-Authored-By: Claude` or any Claude attribution to commits or PRs.
