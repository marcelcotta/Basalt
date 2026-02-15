/*
 Copyright (c) 2024-2026 Basalt contributors. All rights reserved.

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
    @State private var protectHiddenVolume = false
    @State private var hiddenVolumePassword = ""
    @State private var hiddenVolumeKeyfiles: [String] = []
    @State private var showOptions = false
    @State private var showDevicePicker = false
    @State private var availableDevices: [TCHostDevice] = []
    @State private var loadingDevices = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Mount Volume")
                .font(.title2)
                .fontWeight(.semibold)

            // Volume path (file or device)
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    TextField("Volume path or device", text: $volumePath)
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

                    Button("Device...") {
                        loadingDevices = true
                        vm.getHostDevices { devices in
                            availableDevices = devices
                            loadingDevices = false
                            showDevicePicker = true
                        }
                    }
                    .disabled(loadingDevices)
                    .popover(isPresented: $showDevicePicker, arrowEdge: .bottom) {
                        DevicePickerPopover(devices: availableDevices) { path in
                            volumePath = path
                            showDevicePicker = false
                        }
                    }

                    if loadingDevices {
                        ProgressView()
                            .controlSize(.small)
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

                    Divider()

                    Toggle("Protect hidden volume when mounting outer", isOn: $protectHiddenVolume)

                    if protectHiddenVolume {
                        PasswordView("Hidden volume password", text: $hiddenVolumePassword)

                        HStack {
                            Text("Hidden keyfiles:")
                                .font(.caption)
                                .foregroundColor(.secondary)

                            if hiddenVolumeKeyfiles.isEmpty {
                                Text("None")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            } else {
                                Text("\(hiddenVolumeKeyfiles.count) selected")
                                    .font(.caption)
                            }

                            Spacer()

                            Button("Add...") {
                                let panel = NSOpenPanel()
                                panel.canChooseFiles = true
                                panel.canChooseDirectories = true
                                panel.allowsMultipleSelection = true
                                panel.title = "Select Hidden Volume Keyfiles"
                                if panel.runModal() == .OK {
                                    hiddenVolumeKeyfiles.append(contentsOf: panel.urls.map(\.path))
                                }
                            }
                            .controlSize(.small)

                            if !hiddenVolumeKeyfiles.isEmpty {
                                Button("Clear") { hiddenVolumeKeyfiles.removeAll() }
                                    .controlSize(.small)
                            }
                        }

                        Label("Prevents the outer volume from overwriting the hidden volume's data area.", systemImage: "info.circle")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
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
                        useBackupHeaders: useBackupHeaders,
                        protectHiddenVolume: protectHiddenVolume,
                        hiddenVolumePassword: protectHiddenVolume ? hiddenVolumePassword : nil,
                        hiddenVolumeKeyfiles: protectHiddenVolume ? hiddenVolumeKeyfiles : nil
                    )
                }
                .keyboardShortcut(.defaultAction)
                .disabled(volumePath.isEmpty || (password.isEmpty && keyfiles.isEmpty) || vm.isLoading
                          || (protectHiddenVolume && hiddenVolumePassword.isEmpty))
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
        .onDisappear {
            vm.errorMessage = nil
        }
    }
}

// MARK: - Device Picker Popover

/// Popover listing available devices and partitions for selection.
/// Shared between MountSheet and CreateVolumeSheet.
///
/// By default only removable/external devices are shown to protect against
/// accidental formatting of the system disk or APFS internal volumes.
struct DevicePickerPopover: View {
    let devices: [TCHostDevice]
    let onSelect: (String) -> Void

    @State private var showAllDevices = false

    private let byteFormatter: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .file
        return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Select Device")
                .font(.headline)
                .padding(.bottom, 4)

            let rows = filteredDeviceRows
            if rows.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("No removable devices found.")
                        .foregroundColor(.secondary)
                        .font(.callout)

                    if !showAllDevices && hasInternalDevices {
                        Text("Internal disks are hidden for safety.")
                            .foregroundColor(.secondary)
                            .font(.caption)
                    } else {
                        Text("Device enumeration may require admin privileges.")
                            .foregroundColor(.secondary)
                            .font(.caption)
                    }
                }
                .padding(.vertical, 8)
            } else {
                ScrollView(.vertical) {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(rows, id: \.path) { row in
                            deviceRow(row)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(minHeight: 200, maxHeight: 300)
            }

            Divider()

            Toggle("Show internal disks", isOn: $showAllDevices)
                .font(.caption)
                .foregroundColor(.secondary)

            if showAllDevices {
                Label("Selecting an internal disk can destroy your system!", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundColor(.red)
            }
        }
        .padding(12)
        .frame(minWidth: 400)
    }

    private struct DeviceRow {
        let path: String
        let size: UInt64
        let removable: Bool
        let mountPoint: String
        let isPartition: Bool
    }

    /// True if there are any non-removable devices in the list
    private var hasInternalDevices: Bool {
        devices.contains { !$0.removable }
    }

    private var filteredDeviceRows: [DeviceRow] {
        var rows: [DeviceRow] = []
        for dev in devices {
            // Skip non-removable devices unless "Show all" is on
            let showDev = dev.removable || showAllDevices
            guard showDev else { continue }

            rows.append(DeviceRow(
                path: dev.path,
                size: dev.size,
                removable: dev.removable,
                mountPoint: dev.mountPoint,
                isPartition: false
            ))
            for part in dev.partitions {
                rows.append(DeviceRow(
                    path: part.path,
                    size: part.size,
                    removable: part.removable,
                    mountPoint: part.mountPoint,
                    isPartition: true
                ))
            }
        }
        return rows
    }

    @ViewBuilder
    private func deviceRow(_ row: DeviceRow) -> some View {
        Button {
            onSelect(row.path)
        } label: {
            HStack {
                if row.isPartition {
                    Text("  ")
                        .frame(width: 16)
                }
                Image(systemName: row.removable ? "externaldrive.badge.checkmark" : "internaldrive")
                    .foregroundColor(row.removable ? .blue : .secondary)
                    .frame(width: 20)

                Text(row.path)
                    .lineLimit(1)

                if !row.removable {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundColor(.orange)
                        .font(.caption)
                }

                Spacer()

                Text(byteFormatter.string(fromByteCount: Int64(row.size)))
                    .foregroundColor(.secondary)
                    .frame(width: 80, alignment: .trailing)

                if !row.mountPoint.isEmpty {
                    Text(row.mountPoint)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .frame(width: 120, alignment: .trailing)
                }
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 8)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(
            RoundedRectangle(cornerRadius: 4)
                .fill(Color.primary.opacity(0.001))
        )
        .onHover { hovering in
            if hovering {
                NSCursor.pointingHand.push()
            } else {
                NSCursor.pop()
            }
        }
    }
}
