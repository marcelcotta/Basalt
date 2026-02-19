/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI
import UniformTypeIdentifiers

struct MainWindow: View {
    @EnvironmentObject var vm: VolumeManager
    @EnvironmentObject var prefs: PreferencesManager

    /// Volume path pre-filled for sheets opened from context menu
    @State private var contextVolumePath: String?

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar area
            HStack {
                Button { vm.showMountSheet = true } label: {
                    Label("Mount", systemImage: "externaldrive.badge.plus")
                }

                Button {
                    if let vol = vm.selectedVolume {
                        vm.dismountVolume(vol, force: prefs.forceDismount)
                    }
                } label: {
                    Label("Dismount", systemImage: "eject")
                }
                .disabled(vm.selectedSlot == nil)

                Spacer()

                if vm.isLoading {
                    ProgressView()
                        .controlSize(.small)
                }

                Button {
                    vm.dismountAll(force: prefs.forceDismount)
                } label: {
                    Label("Dismount All", systemImage: "eject.circle")
                }
                .disabled(vm.mountedVolumes.isEmpty)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Divider()

            // Volume list
            if vm.mountedVolumes.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "lock.shield")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No Volumes Mounted")
                        .font(.title2)
                        .foregroundColor(.secondary)
                    Text("Click Mount or drop a volume file here")
                        .font(.callout)
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                List(selection: $vm.selectedSlot) {
                    ForEach(vm.mountedVolumes, id: \.slotNumber) { vol in
                        VolumeRow(volume: vol)
                            .tag(vol.slotNumber)
                            .onTapGesture(count: 2) {
                                if !vol.mountPoint.isEmpty {
                                    NSWorkspace.shared.selectFile(nil,
                                        inFileViewerRootedAtPath: vol.mountPoint)
                                }
                            }
                            .onTapGesture(count: 1) {
                                vm.selectedSlot = vol.slotNumber
                            }
                            .contextMenu {
                                Button("Dismount") {
                                    vm.dismountVolume(vol, force: prefs.forceDismount)
                                }

                                Button("Show in Finder") {
                                    if !vol.mountPoint.isEmpty {
                                        NSWorkspace.shared.selectFile(nil,
                                            inFileViewerRootedAtPath: vol.mountPoint)
                                    }
                                }
                                .disabled(vol.mountPoint.isEmpty)

                                Divider()

                                Button("Change Password...") {
                                    contextVolumePath = vol.path
                                    vm.showChangePasswordSheet = true
                                }

                                Button("Backup Headers...") {
                                    contextVolumePath = vol.path
                                    vm.showBackupSheet = true
                                }

                                Button("Restore Headers...") {
                                    contextVolumePath = vol.path
                                    vm.showRestoreSheet = true
                                }
                            }
                    }
                }
            }
        }
        .onDrop(of: [.fileURL], isTargeted: nil) { providers in
            guard let provider = providers.first else { return false }
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in
                    vm.mountPath = url.path
                    vm.showMountSheet = true
                }
            }
            return true
        }
        .frame(minWidth: 600, minHeight: 300)
        .sheet(isPresented: $vm.showMountSheet) {
            MountSheet()
                .environmentObject(vm)
                .environmentObject(prefs)
        }
        .sheet(isPresented: $vm.showChangePasswordSheet, onDismiss: { contextVolumePath = nil }) {
            ChangePasswordSheet(initialVolumePath: contextVolumePath)
                .environmentObject(vm)
        }
        .sheet(isPresented: $vm.showCreateSheet) {
            CreateVolumeSheet()
                .environmentObject(vm)
                .environmentObject(prefs)
        }
        .sheet(isPresented: $vm.showBackupSheet, onDismiss: { contextVolumePath = nil }) {
            BackupHeaderSheet(initialVolumePath: contextVolumePath)
                .environmentObject(vm)
        }
        .sheet(isPresented: $vm.showRestoreSheet, onDismiss: { contextVolumePath = nil }) {
            RestoreHeaderSheet(initialVolumePath: contextVolumePath)
                .environmentObject(vm)
        }
        .alert("Error", isPresented: Binding(
            get: { vm.errorMessage != nil && !vm.showMountSheet },
            set: { if !$0 { vm.errorMessage = nil } }
        )) {
            Button("OK") { vm.errorMessage = nil }
        } message: {
            Text(vm.errorMessage ?? "")
        }
        .alert("Info", isPresented: .constant(vm.infoMessage != nil)) {
            Button("OK") { vm.infoMessage = nil }
        } message: {
            Text(vm.infoMessage ?? "")
        }
        .onAppear {
            vm.refreshVolumes()
        }
        .screenCaptureProtection()
    }
}

// MARK: - Volume Row

struct VolumeRow: View {
    let volume: TCVolumeInfo

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(volume.path)
                    .font(.body)
                    .lineLimit(1)
                    .truncationMode(.middle)

                HStack(spacing: 8) {
                    if !volume.mountPoint.isEmpty {
                        Label(volume.mountPoint, systemImage: "folder")
                    }
                    Text(formatSize(volume.size))
                    Text(volume.encryptionAlgorithmName)

                    if volume.pkcs5PrfName.hasPrefix("Argon2id") {
                        Label(volume.pkcs5PrfName, systemImage: "shield.checkered")
                            .font(.system(size: 10, weight: .medium))
                            .foregroundColor(.green)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background(Color.green.opacity(0.15))
                            .cornerRadius(4)
                    } else {
                        Text(volume.pkcs5PrfName)
                    }
                }
                .font(.caption)
                .foregroundColor(.secondary)
            }

            Spacer()

            HStack(spacing: 4) {
                if volume.hiddenVolumeProtectionTriggered {
                    Label("Protection Triggered", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption2)
                        .foregroundColor(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Color.red)
                        .cornerRadius(4)
                }
                if volume.isHiddenVolume {
                    Text("Hidden")
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Color.orange.opacity(0.2))
                        .cornerRadius(4)
                }
                if volume.isReadOnly {
                    Text("Read-Only")
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Color.blue.opacity(0.2))
                        .cornerRadius(4)
                }
            }
        }
        .padding(.vertical, 2)
    }

    private func formatSize(_ bytes: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(bytes))
    }
}

// MARK: - TCVolumeInfo Identifiable conformance

extension TCVolumeInfo: @retroactive Identifiable {
    public var id: Int { slotNumber }
}
