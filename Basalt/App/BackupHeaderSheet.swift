/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI
import AppKit

struct BackupHeaderSheet: View {
    @EnvironmentObject var vm: VolumeManager
    @Environment(\.dismiss) private var dismiss

    @State private var volumePath = ""
    @State private var password = ""
    @State private var keyfiles: [String] = []
    @State private var hasHiddenVolume = false
    @State private var hiddenPassword = ""
    @State private var hiddenKeyfiles: [String] = []
    @State private var backupFilePath = ""
    @FocusState private var passwordFocused: Bool

    /// Optional pre-filled volume path (set from context menu)
    var initialVolumePath: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Backup Volume Headers")
                .font(.title2)
                .fontWeight(.semibold)

            Label("Creates an external backup of the volume header. This allows recovery if the header becomes corrupted.", systemImage: "info.circle")
                .font(.callout)
                .foregroundColor(.secondary)

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

            // Password
            PasswordView("Volume password", text: $password, focused: $passwordFocused)

            // Keyfiles
            KeyfilePicker(label: "Keyfiles:", keyfiles: $keyfiles)

            Divider()

            // Hidden volume section
            Toggle("Volume contains a hidden volume", isOn: $hasHiddenVolume)

            if hasHiddenVolume {
                VStack(alignment: .leading, spacing: 8) {
                    PasswordView("Hidden volume password", text: $hiddenPassword)
                    KeyfilePicker(label: "Hidden keyfiles:", keyfiles: $hiddenKeyfiles)
                }
                .padding(.leading, 20)
            }

            Divider()

            // Backup file destination
            VStack(alignment: .leading, spacing: 6) {
                Text("Backup file:")
                    .foregroundColor(.secondary)
                HStack {
                    TextField("Backup file path", text: $backupFilePath)
                        .textFieldStyle(.roundedBorder)

                    Button("Browse...") {
                        let panel = NSSavePanel()
                        panel.title = "Save Header Backup"
                        panel.nameFieldStringValue = "volume-header-backup.dat"
                        if panel.runModal() == .OK, let url = panel.url {
                            backupFilePath = url.path
                        }
                    }
                }
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
                    Text("Backing up headers...")
                        .foregroundColor(.secondary)
                }

                Spacer()

                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                .disabled(vm.isLoading)

                Button("Backup") {
                    vm.backupVolumeHeaders(
                        volumePath: volumePath,
                        password: password,
                        keyfiles: keyfiles.isEmpty ? nil : keyfiles,
                        hiddenPassword: hasHiddenVolume ? hiddenPassword : nil,
                        hiddenKeyfiles: hasHiddenVolume && !hiddenKeyfiles.isEmpty ? hiddenKeyfiles : nil,
                        backupFilePath: backupFilePath
                    )
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canBackup || vm.isLoading)
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
        .onChange(of: vm.showBackupSheet) { newValue in
            if !newValue { dismiss() }
        }
        .onDisappear {
            vm.errorMessage = nil
        }
    }

    private var canBackup: Bool {
        !volumePath.isEmpty && !password.isEmpty && !backupFilePath.isEmpty
            && (!hasHiddenVolume || !hiddenPassword.isEmpty)
    }
}

// MARK: - Reusable Keyfile Picker

/// Small inline keyfile picker used by backup/restore sheets.
struct KeyfilePicker: View {
    let label: String
    @Binding var keyfiles: [String]

    var body: some View {
        HStack {
            Text(label)
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
    }
}
