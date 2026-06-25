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
                Text("Phylax")
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

            Button(buttonLabel) {
                if ext.status.isActive {
                    ext.deactivate()
                } else {
                    ext.activate()
                }
            }
            .buttonStyle(.borderedProminent)
            .tint(ext.status.isActive ? .red : .accentColor)
            .disabled(ext.status.isTransitioning)
        }
        .padding(32)
        .frame(minWidth: 360, minHeight: 300)
    }

    private var iconName: String {
        switch ext.status {
        case .active:                       return "lock.shield.fill"
        case .activating, .deactivating:    return "shield"
        case .failed:                       return "exclamationmark.shield"
        default:                            return "shield.slash"
        }
    }

    private var iconColor: Color {
        switch ext.status {
        case .active:      return .green
        case .failed:      return .red
        case .activating,
             .deactivating: return .orange
        default:           return .secondary
        }
    }

    private var buttonLabel: String {
        switch ext.status {
        case .activating:   return "Activating…"
        case .deactivating: return "Deactivating…"
        case .active:       return "Deactivate Guard"
        default:            return "Activate Guard"
        }
    }
}

#Preview {
    ContentView()
}
