/*
 Copyright (c) 2024-2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI
import AppKit

// SECURITY: Prevents screen recording/capture of windows containing password fields.
// Sets NSWindow.sharingType = .none on the hosting window, which blocks
// screenshots, screen recording, and AirPlay mirroring of the window contents.
struct ScreenCaptureProtection: ViewModifier {
    func body(content: Content) -> some View {
        content.background(ScreenCaptureProtectionHelper())
    }
}

private struct ScreenCaptureProtectionHelper: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            if let window = view.window {
                window.sharingType = .none
            }
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        // Re-apply in case the window changed
        if let window = nsView.window {
            window.sharingType = .none
        }
    }
}

extension View {
    func screenCaptureProtection() -> some View {
        modifier(ScreenCaptureProtection())
    }
}

struct MountSheet: View {
    @EnvironmentObject var vm: VolumeManager
    @EnvironmentObject var prefs: PreferencesManager
    @Environment(\.dismiss) private var dismiss

    @State private var volumePath = ""
    @State private var password = ""
    @State private var keyfiles: [String] = []
    @State private var mountPoint = ""
    @State private var readOnly = false
    @State private var useBackupHeaders = false
    @State private var showOptions = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Mount Volume")
                .font(.title2)
                .fontWeight(.semibold)

            // Volume path
            HStack {
                TextField("Volume path", text: $volumePath)
                    .textFieldStyle(.roundedBorder)

                Button("Browse...") {
                    let panel = NSOpenPanel()
                    panel.canChooseFiles = true
                    panel.canChooseDirectories = false
                    panel.allowsMultipleSelection = false
                    panel.title = "Select Encrypted Volume"
                    if panel.runModal() == .OK, let url = panel.url {
                        volumePath = url.path
                    }
                }
            }

            // Password
            PasswordView("Password", text: $password, focused: $passwordFocused)

            // Keyfiles
            HStack {
                Text("Keyfiles:")
                    .foregroundColor(.secondary)

                if keyfiles.isEmpty {
                    Text("None")
                        .foregroundColor(.secondary)
                } else {
                    Text("\(keyfiles.count) selected")
                }

                Spacer()

                Button("Add...") {
                    let panel = NSOpenPanel()
                    panel.canChooseFiles = true
                    panel.canChooseDirectories = true
                    panel.allowsMultipleSelection = true
                    panel.title = "Select Keyfiles"
                    if panel.runModal() == .OK {
                        keyfiles.append(contentsOf: panel.urls.map(\.path))
                    }
                }

                if !keyfiles.isEmpty {
                    Button("Clear") {
                        keyfiles.removeAll()
                    }
                }
            }

            // Options toggle
            DisclosureGroup("Options", isExpanded: $showOptions) {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        TextField("Mount point (optional)", text: $mountPoint)
                            .textFieldStyle(.roundedBorder)
                        Button("Browse...") {
                            let panel = NSOpenPanel()
                            panel.canChooseFiles = false
                            panel.canChooseDirectories = true
                            panel.canCreateDirectories = true
                            panel.title = "Select Mount Point"
                            if panel.runModal() == .OK, let url = panel.url {
                                mountPoint = url.path
                            }
                        }
                    }

                    Toggle("Read-only", isOn: $readOnly)
                    Toggle("Use backup headers", isOn: $useBackupHeaders)
                }
                .padding(.leading, 4)
            }

            // Error display
            if let error = vm.errorMessage {
                Text(error)
                    .foregroundColor(.red)
                    .font(.callout)
            }

            Divider()

            // Buttons
            HStack {
                if vm.isLoading {
                    ProgressView()
                        .controlSize(.small)
                    Text(vm.loadingStatus)
                        .foregroundColor(.secondary)
                }

                Spacer()

                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                .disabled(vm.isLoading)

                Button("Mount") {
                    vm.mountVolume(
                        path: volumePath,
                        password: password,
                        keyfiles: keyfiles,
                        mountPoint: mountPoint.isEmpty ? nil : mountPoint,
                        readOnly: readOnly,
                        useBackupHeaders: useBackupHeaders
                    )
                }
                .keyboardShortcut(.defaultAction)
                .disabled(volumePath.isEmpty || password.isEmpty || vm.isLoading)
            }
        }
        .padding(20)
        .frame(minWidth: 480)
        .screenCaptureProtection()
        .onAppear {
            readOnly = prefs.defaultReadOnly
            passwordFocused = true
        }
        .onChange(of: vm.showMountSheet) { newValue in
            if !newValue { dismiss() }
        }
    }
}
