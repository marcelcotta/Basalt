/*
 Copyright (c) 2024 TrueCrypt macOS Port. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI
import AppKit

struct CreateVolumeSheet: View {
    @EnvironmentObject var vm: VolumeManager
    @EnvironmentObject var prefs: PreferencesManager
    @Environment(\.dismiss) private var dismiss

    // Step tracking
    @State private var currentStep = 0
    private let totalSteps = 4

    // Step 1: File & Size
    @State private var volumePath = ""
    @State private var sizeValue = ""
    @State private var sizeUnit = "MB"

    // Step 2: Encryption
    @State private var selectedEncryption = "AES"
    @State private var selectedHash = ""
    @State private var legacyIterations = false

    // Step 3: Password
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var keyfiles: [String] = []
    @FocusState private var passwordFocused: Bool

    // Step 4: Filesystem & Format
    @State private var filesystem: Int = 1 // 0=None, 1=FAT, 2=HFS+
    @State private var quickFormat = false

    // Progress
    @State private var isCreating = false
    @State private var creationProgress: Double = 0.0
    @State private var creationDone = false
    @State private var progressTimer: Timer?

    private let sizeUnits = ["KB", "MB", "GB"]

    var passwordMismatch: Bool {
        !password.isEmpty && !confirmPassword.isEmpty && password != confirmPassword
    }

    var passwordTooShort: Bool {
        !password.isEmpty && password.count < 20
    }

    var sizeInBytes: UInt64 {
        guard let val = Double(sizeValue), val > 0 else { return 0 }
        switch sizeUnit {
        case "KB": return UInt64(val * 1024)
        case "MB": return UInt64(val * 1024 * 1024)
        case "GB": return UInt64(val * 1024 * 1024 * 1024)
        default: return 0
        }
    }

    var canProceedStep1: Bool {
        !volumePath.isEmpty && sizeInBytes >= 292864 // ~286 KB min for FAT
    }

    var canProceedStep2: Bool {
        !selectedEncryption.isEmpty && !selectedHash.isEmpty
    }

    var canProceedStep3: Bool {
        !password.isEmpty && !passwordMismatch
    }

    var canCreate: Bool {
        canProceedStep1 && canProceedStep2 && canProceedStep3 && !isCreating
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Title
            Text("Create TrueCrypt Volume")
                .font(.title2)
                .fontWeight(.semibold)

            // Step indicator
            HStack(spacing: 4) {
                ForEach(0..<totalSteps, id: \.self) { step in
                    Capsule()
                        .fill(step <= currentStep ? Color.accentColor : Color.secondary.opacity(0.3))
                        .frame(height: 4)
                }
            }

            stepLabels

            Divider()

            // Step content
            Group {
                switch currentStep {
                case 0: step1FileAndSize
                case 1: step2Encryption
                case 2: step3Password
                case 3: step4FilesystemAndFormat
                default: EmptyView()
                }
            }
            .frame(minHeight: 160)

            // Error display
            if let error = vm.errorMessage {
                Text(error)
                    .foregroundColor(.red)
                    .font(.callout)
            }

            Divider()

            // Navigation buttons
            navigationButtons
        }
        .padding(20)
        .frame(minWidth: 520)
        .screenCaptureProtection()
        .onAppear {
            // Set defaults from available algorithms
            if selectedHash.isEmpty, let first = vm.availableHashAlgorithms.first(where: { $0.contains("SHA-512") }) {
                selectedHash = first
            } else if selectedHash.isEmpty, let first = vm.availableHashAlgorithms.first {
                selectedHash = first
            }
        }
        .onDisappear {
            progressTimer?.invalidate()
            progressTimer = nil
        }
        .onChange(of: vm.showCreateSheet) { newValue in
            if !newValue { dismiss() }
        }
        .onChange(of: selectedHash) { newValue in
            // Argon2id variants have no legacy — reset toggle
            if newValue.hasPrefix("Argon2id") { legacyIterations = false }
        }
    }

    // MARK: - Step Labels

    private var stepLabels: some View {
        HStack {
            ForEach(Array(["Location", "Encryption", "Password", "Format"].enumerated()), id: \.offset) { index, label in
                if index > 0 { Spacer() }
                Text(label)
                    .font(.caption)
                    .fontWeight(index == currentStep ? .semibold : .regular)
                    .foregroundColor(index == currentStep ? .primary : .secondary)
                if index < totalSteps - 1 { Spacer() }
            }
        }
    }

    // MARK: - Step 1: File & Size

    private var step1FileAndSize: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Choose a location and size for the new volume.")
                .font(.callout)
                .foregroundColor(.secondary)

            HStack {
                TextField("Volume file path", text: $volumePath)
                    .textFieldStyle(.roundedBorder)

                Button("Browse...") {
                    let panel = NSSavePanel()
                    panel.title = "Create TrueCrypt Volume"
                    panel.nameFieldStringValue = "volume.tc"
                    panel.canCreateDirectories = true
                    if panel.runModal() == .OK, let url = panel.url {
                        volumePath = url.path
                    }
                }
            }

            HStack {
                Text("Volume size:")
                TextField("Size", text: $sizeValue)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 100)
                Picker("", selection: $sizeUnit) {
                    ForEach(sizeUnits, id: \.self) { Text($0) }
                }
                .pickerStyle(.segmented)
                .frame(width: 160)
            }

            if sizeInBytes > 0 {
                Text(formatBytes(sizeInBytes))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }

    // MARK: - Step 2: Encryption

    private var step2Encryption: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Choose the encryption and hash algorithms.")
                .font(.callout)
                .foregroundColor(.secondary)

            Picker("Encryption Algorithm:", selection: $selectedEncryption) {
                ForEach(vm.availableEncryptionAlgorithms, id: \.self) { algo in
                    Text(algo).tag(algo)
                }
            }
            .pickerStyle(.menu)

            Picker("Hash Algorithm:", selection: $selectedHash) {
                ForEach(vm.availableHashAlgorithms, id: \.self) { hash in
                    Text(hash).tag(hash)
                }
            }
            .pickerStyle(.menu)

            Divider()

            if selectedHash == "Argon2id" {
                Label("Argon2id (512 MB, 4 threads) — strong protection against brute-force attacks.", systemImage: "shield.checkered")
                    .font(.caption)
                    .foregroundColor(.green)
            } else if selectedHash == "Argon2id-Max" {
                Label("Argon2id Maximum Security (1 GB, 8 threads) — strongest protection for high-value data.", systemImage: "shield.checkered")
                    .font(.caption)
                    .foregroundColor(.green)
            } else {
                Toggle("TrueCrypt 7.1a compatible (legacy iterations)", isOn: $legacyIterations)

                if legacyIterations {
                    Label("Uses original TrueCrypt iteration counts (1000–2000). The volume can be opened with TrueCrypt 7.1a but has weaker key derivation.", systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundColor(.orange)
                } else {
                    Text("AES with SHA-512 is recommended for most users. Cascade ciphers provide additional security layers.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    // MARK: - Step 3: Password

    private var step3Password: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Choose a strong password for the volume.")
                .font(.callout)
                .foregroundColor(.secondary)

            PasswordView("Password", text: $password, focused: $passwordFocused)
            PasswordView("Confirm password", text: $confirmPassword)

            if passwordMismatch {
                Text("Passwords do not match")
                    .foregroundColor(.red)
                    .font(.caption)
            }

            if passwordTooShort {
                Label("Short passwords are significantly easier to crack. Consider using 20+ characters.", systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundColor(.orange)
            }

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
                    Button("Clear") { keyfiles.removeAll() }
                }
            }
        }
    }

    // MARK: - Step 4: Filesystem & Format

    private var step4FilesystemAndFormat: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !isCreating && !creationDone {
                Text("Choose a filesystem and start formatting.")
                    .font(.callout)
                    .foregroundColor(.secondary)

                Picker("Filesystem:", selection: $filesystem) {
                    Text("None").tag(0)
                    Text("FAT").tag(1)
                    Text("Mac OS Extended (HFS+)").tag(2)
                }
                .pickerStyle(.menu)

                if filesystem == 1 && sizeInBytes > 4_294_967_295 { // FAT 4 GB limit
                    Label("FAT does not support files larger than 4 GB. Consider Mac OS Extended for larger files.", systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundColor(.orange)
                }

                Toggle("Quick format", isOn: $quickFormat)

                if !quickFormat {
                    Text("Full format writes encrypted random data to the entire volume. This is more secure but takes longer.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } else if isCreating {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Creating volume...")
                        .font(.callout)
                        .fontWeight(.medium)

                    ProgressView(value: creationProgress) {
                        Text("\(Int(creationProgress * 100))%")
                            .font(.caption)
                            .monospacedDigit()
                    }

                    Text(formatBytes(UInt64(creationProgress * Double(sizeInBytes))) + " / " + formatBytes(sizeInBytes))
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .monospacedDigit()
                }
            } else if creationDone {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Volume created successfully!", systemImage: "checkmark.circle.fill")
                        .font(.callout)
                        .foregroundColor(.green)

                    Text(volumePath)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    // MARK: - Navigation Buttons

    private var navigationButtons: some View {
        HStack {
            if isCreating {
                Button("Abort") {
                    vm.abortVolumeCreation()
                    progressTimer?.invalidate()
                    progressTimer = nil
                    isCreating = false
                }
            }

            Spacer()

            if creationDone {
                Button("Done") {
                    vm.showCreateSheet = false
                }
                .keyboardShortcut(.defaultAction)
            } else {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isCreating)

                if currentStep > 0 && !isCreating {
                    Button("Back") { currentStep -= 1 }
                }

                if currentStep < totalSteps - 1 {
                    Button("Next") { currentStep += 1 }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canProceedForCurrentStep)
                } else if !isCreating {
                    Button("Create") { startCreation() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canCreate)
                }
            }
        }
    }

    private var canProceedForCurrentStep: Bool {
        switch currentStep {
        case 0: return canProceedStep1
        case 1: return canProceedStep2
        case 2: return canProceedStep3
        default: return true
        }
    }

    // MARK: - Creation

    private func startCreation() {
        vm.errorMessage = nil
        isCreating = true
        creationProgress = 0.0

        let options = TCVolumeCreationOptions()
        options.path = volumePath
        options.volumeType = .normal
        options.size = sizeInBytes
        options.password = password
        if !keyfiles.isEmpty { options.keyfilePaths = keyfiles }
        options.encryptionAlgorithm = selectedEncryption
        options.hashAlgorithm = selectedHash
        options.filesystem = TCFilesystemType(rawValue: filesystem) ?? .none
        options.quickFormat = quickFormat
        options.legacyIterations = legacyIterations

        vm.createVolume(options: options) { success in
            isCreating = false
            progressTimer?.invalidate()
            progressTimer = nil
            if success {
                creationDone = true
            }
        }

        // Poll progress
        progressTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { _ in
            Task { @MainActor in
                let progress = vm.getCreationProgress()
                creationProgress = progress
            }
        }
    }

    // MARK: - Helpers

    private func formatBytes(_ bytes: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(bytes))
    }
}
