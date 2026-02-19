/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI

struct ChangePasswordSheet: View {
    @EnvironmentObject var vm: VolumeManager
    @Environment(\.dismiss) private var dismiss

    @State private var volumePath = ""
    @State private var currentPassword = ""
    @State private var currentKeyfiles: [String] = []
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var newKeyfiles: [String] = []
    @State private var selectedHash = ""
    @FocusState private var passwordFocused: Bool

    /// Optional pre-filled volume path (set from context menu)
    var initialVolumePath: String?

    var passwordMismatch: Bool {
        !newPassword.isEmpty && !confirmPassword.isEmpty && newPassword != confirmPassword
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Change Volume Password")
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
                    panel.title = "Select Encrypted Volume"
                    if panel.runModal() == .OK, let url = panel.url {
                        volumePath = url.path
                    }
                }
            }

            Divider()

            // Current credentials
            Text("Current Credentials")
                .font(.caption)
                .foregroundColor(.secondary)

            PasswordView("Current password", text: $currentPassword, focused: $passwordFocused)
            KeyfilePicker(label: "Current keyfiles:", keyfiles: $currentKeyfiles)

            Divider()

            // New credentials
            Text("New Credentials")
                .font(.caption)
                .foregroundColor(.secondary)

            PasswordView("New password", text: $newPassword)
            PasswordView("Confirm new password", text: $confirmPassword)

            if passwordMismatch {
                Text("Passwords do not match")
                    .foregroundColor(.red)
                    .font(.caption)
            }

            KeyfilePicker(label: "New keyfiles:", keyfiles: $newKeyfiles)

            // Hash algorithm
            Picker("PKCS-5 PRF:", selection: $selectedHash) {
                Text("(unchanged)").tag("")
                ForEach(vm.availableHashAlgorithms, id: \.self) { hash in
                    Text(hash).tag(hash)
                }
            }
            .pickerStyle(.menu)
            .help("The hash algorithm used for key derivation. Select '(unchanged)' to keep the current setting.")

            // Error display
            if let error = vm.errorMessage {
                Text(error)
                    .foregroundColor(.red)
                    .font(.callout)
            }

            Divider()

            HStack {
                if vm.isLoading {
                    ProgressView()
                        .controlSize(.small)
                    Text("Changing password...")
                        .foregroundColor(.secondary)
                }

                Spacer()

                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(vm.isLoading)

                Button("Change") {
                    vm.changePassword(
                        volumePath: volumePath,
                        currentPassword: currentPassword,
                        keyfiles: currentKeyfiles.isEmpty ? nil : currentKeyfiles,
                        newPassword: newPassword,
                        newKeyfiles: newKeyfiles.isEmpty ? nil : newKeyfiles,
                        newHash: selectedHash.isEmpty ? nil : selectedHash
                    )
                }
                .keyboardShortcut(.defaultAction)
                .disabled(volumePath.isEmpty || currentPassword.isEmpty
                          || newPassword.isEmpty || passwordMismatch || vm.isLoading)
            }
        }
        .padding(20)
        .frame(minWidth: 460)
        .screenCaptureProtection()
        .onAppear {
            if let path = initialVolumePath {
                volumePath = path
            }
            passwordFocused = true
        }
        .onChange(of: vm.showChangePasswordSheet) { newValue in
            if !newValue { dismiss() }
        }
        .onDisappear {
            vm.errorMessage = nil
        }
    }
}
