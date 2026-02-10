/*
 Copyright (c) 2024 TrueCrypt macOS Port. All rights reserved.

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
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var selectedHash = ""

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
                    panel.title = "Select TrueCrypt Volume"
                    if panel.runModal() == .OK, let url = panel.url {
                        volumePath = url.path
                    }
                }
            }

            Divider()

            // Current password
            PasswordView("Current password", text: $currentPassword)

            Divider()

            // New password
            PasswordView("New password", text: $newPassword)
            PasswordView("Confirm new password", text: $confirmPassword)

            if passwordMismatch {
                Text("Passwords do not match")
                    .foregroundColor(.red)
                    .font(.caption)
            }

            // Hash algorithm
            Picker("PKCS-5 PRF:", selection: $selectedHash) {
                Text("(unchanged)").tag("")
                ForEach(vm.availableHashAlgorithms, id: \.self) { hash in
                    Text(hash).tag(hash)
                }
            }
            .pickerStyle(.menu)

            // Error display
            if let error = vm.errorMessage {
                Text(error)
                    .foregroundColor(.red)
                    .font(.callout)
            }

            Divider()

            HStack {
                Spacer()

                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)

                Button("Change") {
                    vm.changePassword(
                        volumePath: volumePath,
                        currentPassword: currentPassword,
                        keyfiles: nil,
                        newPassword: newPassword,
                        newKeyfiles: nil,
                        newHash: selectedHash.isEmpty ? nil : selectedHash
                    )
                }
                .keyboardShortcut(.defaultAction)
                .disabled(volumePath.isEmpty || currentPassword.isEmpty
                          || newPassword.isEmpty || passwordMismatch)
            }
        }
        .padding(20)
        .frame(minWidth: 420)
        .screenCaptureProtection()
        .onChange(of: vm.showChangePasswordSheet) { newValue in
            if !newValue { dismiss() }
        }
    }
}
