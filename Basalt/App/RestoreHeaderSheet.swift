/*
 Copyright (c) 2024-2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI
import AppKit

struct RestoreHeaderSheet: View {
    @EnvironmentObject var vm: VolumeManager
    @Environment(\.dismiss) private var dismiss

    @State private var volumePath = ""
    @State private var password = ""
    @State private var keyfiles: [String] = []
    @State private var restoreSource = 0 // 0 = Internal backup, 1 = External file
    @State private var backupFilePath = ""
    @State private var showConfirmation = false
    @FocusState private var passwordFocused: Bool

    /// Optional pre-filled volume path (set from context menu)
    var initialVolumePath: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Restore Volume Headers")
                .font(.title2)
                .fontWeight(.semibold)

            Label("Restores a damaged volume header from a backup. This can help if the volume cannot be mounted due to header corruption.", systemImage: "exclamationmark.triangle")
                .font(.callout)
                .foregroundColor(.orange)

            // Volume path
            VStack(alignment: .leading, spacing: 6) {
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
            }

            Divider()

            // Restore source selection
            Picker("Restore from:", selection: $restoreSource) {
                Text("Internal backup (embedded in volume)").tag(0)
                Text("External backup file").tag(1)
            }
            .pickerStyle(.radioGroup)

            if restoreSource == 0 {
                Label("The volume header will be restored from the backup copy stored at the end of the volume file.", systemImage: "info.circle")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                // External backup file
                VStack(alignment: .leading, spacing: 6) {
                    Text("Backup file:")
                        .foregroundColor(.secondary)
                    HStack {
                        TextField("Backup file path", text: $backupFilePath)
                            .textFieldStyle(.roundedBorder)

                        Button("Browse...") {
                            let panel = NSOpenPanel()
                            panel.canChooseFiles = true
                            panel.canChooseDirectories = false
                            panel.allowsMultipleSelection = false
                            panel.title = "Select Header Backup File"
                            if panel.runModal() == .OK, let url = panel.url {
                                backupFilePath = url.path
                            }
                        }
                    }
                }
            }

            Divider()

            // Password (for the backup — same password used when backup was created)
            PasswordView("Password", text: $password, focused: $passwordFocused)

            // Keyfiles
            KeyfilePicker(label: "Keyfiles:", keyfiles: $keyfiles)

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
                    Text("Restoring headers...")
                        .foregroundColor(.secondary)
                }

                Spacer()

                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                .disabled(vm.isLoading)

                Button("Restore") {
                    showConfirmation = true
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canRestore || vm.isLoading)
            }
        }
        .padding(20)
        .frame(minWidth: 480)
        .screenCaptureProtection()
        .onAppear {
            if let path = initialVolumePath {
                volumePath = path
            }
            passwordFocused = true
        }
        .onChange(of: vm.showRestoreSheet) { newValue in
            if !newValue { dismiss() }
        }
        .onDisappear {
            vm.errorMessage = nil
        }
        .alert("Confirm Header Restore", isPresented: $showConfirmation) {
            Button("Cancel", role: .cancel) { }
            Button("Restore", role: .destructive) {
                performRestore()
            }
        } message: {
            Text("This will overwrite the current volume header. Make sure you have a backup of the current header before proceeding.\n\nAre you sure you want to restore the volume header?")
        }
    }

    private var canRestore: Bool {
        !volumePath.isEmpty && !password.isEmpty
            && (restoreSource == 0 || !backupFilePath.isEmpty)
    }

    private func performRestore() {
        let kf = keyfiles.isEmpty ? nil : keyfiles
        if restoreSource == 0 {
            vm.restoreVolumeHeadersFromInternal(
                volumePath: volumePath,
                password: password,
                keyfiles: kf
            )
        } else {
            vm.restoreVolumeHeadersFromFile(
                volumePath: volumePath,
                backupFilePath: backupFilePath,
                password: password,
                keyfiles: kf
            )
        }
    }
}
