import SwiftUI

struct ContentView: View {
    @StateObject private var ext = ExtensionManager()

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: iconName)
                .font(.system(size: 52))
                .foregroundStyle(iconColor)
                .symbolEffect(.pulse, isActive: ext.status.isTransitioning)

            VStack(spacing: 4) {
                Text("Omsil")
                    .font(.title.bold())
                Text("Process Guard")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Text(ext.statusMessage)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 280)

            // Activate-only: the guard cannot be torn down from this UI.
            Button(buttonLabel) {
                ext.activate()
            }
            .buttonStyle(.borderedProminent)
            .disabled(ext.status.isActive || ext.status.isTransitioning)
        }
        .padding(32)
        .frame(minWidth: 360, minHeight: 300)
        // Re-arm the guard on every launch. This is what lets the watchdog
        // recover protection simply by relaunching the app (context.md step B).
        .task {
            ext.activateIfNeeded()
        }
    }

    private var iconName: String {
        switch ext.status {
        case .active:       return "lock.shield.fill"
        case .activating:   return "shield"
        case .failed:       return "exclamationmark.shield"
        default:            return "shield.slash"
        }
    }

    private var iconColor: Color {
        switch ext.status {
        case .active:      return .green
        case .failed:      return .red
        case .activating:  return .orange
        default:           return .secondary
        }
    }

    private var buttonLabel: String {
        switch ext.status {
        case .activating:   return "Activating…"
        case .active:       return "Guard Active"
        default:            return "Activate Guard"
        }
    }
}

#Preview {
    ContentView()
}
