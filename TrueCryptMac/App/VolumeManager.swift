/*
 Copyright (c) 2024 TrueCrypt macOS Port. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import Foundation
import AppKit
import Combine

/// Observable model that wraps TCCoreBridge for SwiftUI binding.
/// ObjC methods with (NSError **) parameters are imported as throwing in Swift.
@MainActor
class VolumeManager: ObservableObject {

    // MARK: - Published state

    @Published var mountedVolumes: [TCVolumeInfo] = []
    @Published var errorMessage: String?
    @Published var infoMessage: String?
    @Published var isLoading = false
    @Published var loadingStatus = "Mounting..."

    // Sheet presentation
    @Published var showMountSheet = false
    @Published var showCreateSheet = false
    @Published var showChangePasswordSheet = false
    @Published var showBackupSheet = false
    @Published var showRestoreSheet = false

    @Published var selectedSlot: Int?

    var selectedVolume: TCVolumeInfo? {
        guard let slot = selectedSlot else { return nil }
        return mountedVolumes.first { $0.slotNumber == slot }
    }

    // MARK: - Preferences (set by TrueCryptApp on appear)

    var preferences: PreferencesManager?

    // MARK: - Private

    private let bridge = TCCoreBridge.shared()
    private var refreshTimer: Timer?
    private var statusObserver: NSObjectProtocol?

    // Inactivity tracking: slot -> (lastDataRead + lastDataWritten, lastActivityDate)
    private var lastIOActivity: [Int: (total: UInt64, date: Date)] = [:]

    // MARK: - Init

    init() {
        initializeCore()
        startRefreshTimer()

        statusObserver = NotificationCenter.default.addObserver(
            forName: NSNotification.Name("TCLoadingStatusChanged"),
            object: nil, queue: .main
        ) { [weak self] notification in
            guard let self, let status = notification.userInfo?["status"] as? String else { return }
            let vm = self
            Task { @MainActor in vm.loadingStatus = status }
        }
    }

    deinit {
        refreshTimer?.invalidate()
        if let obs = statusObserver { NotificationCenter.default.removeObserver(obs) }
    }

    // MARK: - Core Lifecycle

    private func initializeCore() {
        do {
            try bridge.initializeCore()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Refresh

    private func startRefreshTimer() {
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            Task { @MainActor [weak self] in
                self?.refreshVolumes()
            }
        }
    }

    func refreshVolumes() {
        mountedVolumes = bridge.mountedVolumes()
        checkInactivity()
    }

    // MARK: - Inactivity Tracking

    private func checkInactivity() {
        guard let prefs = preferences, prefs.dismountOnInactivity, !mountedVolumes.isEmpty else {
            lastIOActivity.removeAll()
            return
        }

        let now = Date()
        let timeout = TimeInterval(prefs.maxIdleMinutes * 60)
        var volumesToDismount: [TCVolumeInfo] = []

        // Track current slots
        var activeSlots = Set<Int>()

        for vol in mountedVolumes {
            let slot = vol.slotNumber
            activeSlots.insert(slot)
            let currentTotal = vol.totalDataRead &+ vol.totalDataWritten

            if let last = lastIOActivity[slot] {
                if currentTotal != last.total {
                    // I/O happened — update timestamp
                    lastIOActivity[slot] = (currentTotal, now)
                } else if now.timeIntervalSince(last.date) >= timeout {
                    // No I/O for longer than timeout
                    volumesToDismount.append(vol)
                }
            } else {
                // First time seeing this volume — record baseline
                lastIOActivity[slot] = (currentTotal, now)
            }
        }

        // Clean up entries for volumes no longer mounted
        for slot in lastIOActivity.keys where !activeSlots.contains(slot) {
            lastIOActivity.removeValue(forKey: slot)
        }

        // Dismount idle volumes
        for vol in volumesToDismount {
            lastIOActivity.removeValue(forKey: vol.slotNumber)
            dismountVolume(vol, force: prefs.forceDismount)
        }
    }

    // MARK: - Mount

    func mountVolume(path: String, password: String, keyfiles: [String] = [],
                     mountPoint: String? = nil, readOnly: Bool = false,
                     useBackupHeaders: Bool = false) {
        isLoading = true
        loadingStatus = "Mounting..."
        errorMessage = nil

        let options = TCMountOptions()
        options.volumePath = path
        options.password = password
        if !keyfiles.isEmpty { options.keyfilePaths = keyfiles }
        if let mp = mountPoint { options.mountPoint = mp }
        options.readOnly = readOnly
        options.useBackupHeaders = useBackupHeaders
        preferences?.applyToMountOptions(options)
        // Explicit user choices override defaults
        if readOnly { options.readOnly = true }

        let shouldOpenFinder = preferences?.openFinderAfterMount ?? false

        Task.detached { [bridge] in
            var vol: TCVolumeInfo?
            var errMsg: String?

            do {
                vol = try bridge.mountVolume(options)
            } catch {
                errMsg = error.localizedDescription
            }

            let resultVol = vol
            let resultErr = errMsg

            await MainActor.run { [weak self] in
                self?.isLoading = false
                if let vol = resultVol {
                    self?.refreshVolumes()
                    self?.showMountSheet = false
                    if shouldOpenFinder && !vol.mountPoint.isEmpty {
                        NSWorkspace.shared.selectFile(nil,
                            inFileViewerRootedAtPath: vol.mountPoint)
                    }
                } else {
                    self?.errorMessage = resultErr ?? "Mount failed"
                }
            }
        }
    }

    // MARK: - Dismount

    func dismountVolume(_ volume: TCVolumeInfo, force: Bool = false) {
        isLoading = true
        errorMessage = nil

        let mountPoint = volume.mountPoint
        let shouldCloseFinder = preferences?.closeFinderOnDismount ?? false

        Task.detached { [bridge] in
            var errMsg: String?

            do {
                try bridge.dismountVolume(volume, force: force)
            } catch {
                errMsg = error.localizedDescription
            }

            let resultErr = errMsg
            await MainActor.run { [weak self] in
                self?.isLoading = false
                if resultErr == nil {
                    if shouldCloseFinder && !mountPoint.isEmpty {
                        Self.closeFinderWindows(at: mountPoint)
                    }
                    self?.refreshVolumes()
                    self?.selectedSlot = nil
                } else {
                    self?.errorMessage = resultErr
                }
            }
        }
    }

    func dismountAll(force: Bool = false) {
        isLoading = true
        errorMessage = nil

        let mountPoints = mountedVolumes.map(\.mountPoint)
        let shouldCloseFinder = preferences?.closeFinderOnDismount ?? false

        Task.detached { [bridge] in
            var errMsg: String?

            do {
                try bridge.dismountAllVolumes(force)
            } catch {
                errMsg = error.localizedDescription
            }

            let resultErr = errMsg
            await MainActor.run { [weak self] in
                self?.isLoading = false
                if resultErr == nil {
                    if shouldCloseFinder {
                        for mp in mountPoints where !mp.isEmpty {
                            Self.closeFinderWindows(at: mp)
                        }
                    }
                    self?.refreshVolumes()
                    self?.selectedSlot = nil
                } else {
                    self?.errorMessage = resultErr
                }
            }
        }
    }

    // MARK: - Finder Window Management

    private static func closeFinderWindows(at path: String) {
        // Escape backslashes and quotes for safe AppleScript string embedding
        let escaped = path
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = """
            tell application "Finder"
                close (every window whose target exists and POSIX path of (target as alias) starts with "\(escaped)")
            end tell
            """
        if let appleScript = NSAppleScript(source: script) {
            appleScript.executeAndReturnError(nil)
        }
    }

    // MARK: - Change Password

    func changePassword(volumePath: String, currentPassword: String,
                        keyfiles: [String]?, newPassword: String,
                        newKeyfiles: [String]?, newHash: String?) {
        isLoading = true
        errorMessage = nil

        Task.detached { [bridge] in
            var errMsg: String?

            do {
                try bridge.changePassword(
                    forVolume: volumePath,
                    password: currentPassword,
                    keyfiles: keyfiles,
                    newPassword: newPassword,
                    newKeyfiles: newKeyfiles,
                    newHash: newHash
                )
            } catch {
                errMsg = error.localizedDescription
            }

            let resultErr = errMsg
            await MainActor.run { [weak self] in
                self?.isLoading = false
                if resultErr == nil {
                    self?.showChangePasswordSheet = false
                    self?.infoMessage = "Password changed successfully"
                } else {
                    self?.errorMessage = resultErr
                }
            }
        }
    }

    // MARK: - Keyfile

    func createKeyfile(path: String) {
        do {
            try bridge.createKeyfile(path)
            infoMessage = "Keyfile created: \(path)"
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Self-Test

    func runSelfTest() {
        isLoading = true
        errorMessage = nil

        Task.detached { [bridge] in
            var errMsg: String?

            do {
                try bridge.runSelfTest()
            } catch {
                errMsg = error.localizedDescription
            }

            let resultErr = errMsg
            await MainActor.run { [weak self] in
                self?.isLoading = false
                if resultErr == nil {
                    self?.infoMessage = "All self-tests passed"
                } else {
                    self?.errorMessage = resultErr
                }
            }
        }
    }

    // MARK: - Volume Creation

    func createVolume(options: TCVolumeCreationOptions, completion: @escaping (Bool) -> Void) {
        errorMessage = nil

        // Save values needed for post-creation formatting
        let volumePath = options.path
        let password = options.password ?? ""
        let keyfiles = options.keyfilePaths
        let filesystem = options.filesystem

        Task.detached { [bridge] in
            var errMsg: String?

            do {
                try bridge.startVolumeCreation(options)
            } catch {
                errMsg = error.localizedDescription
            }

            if let err = errMsg {
                await MainActor.run { [weak self] in
                    self?.errorMessage = err
                    completion(false)
                }
                return
            }

            // Poll until creation finishes
            while true {
                let progress = bridge.volumeCreationProgress()
                if !progress.inProgress {
                    break
                }
                try? await Task.sleep(nanoseconds: 200_000_000) // 200ms
            }

            // Post-creation formatting for HFS+ (mounts temporarily, runs newfs_hfs, dismounts)
            if filesystem == .macOsExt {
                do {
                    try bridge.formatVolumeFilesystem(
                        volumePath, password: password,
                        keyfiles: keyfiles, filesystem: filesystem)
                } catch {
                    await MainActor.run { [weak self] in
                        self?.errorMessage = "Volume created but filesystem formatting failed: \(error.localizedDescription)"
                        completion(false)
                    }
                    return
                }
            }

            await MainActor.run {
                completion(true)
            }
        }
    }

    func getCreationProgress() -> Double {
        let progress = bridge.volumeCreationProgress()
        return progress.fraction
    }

    func abortVolumeCreation() {
        bridge.abortVolumeCreation()
    }

    // MARK: - Algorithm Info

    var availableEncryptionAlgorithms: [String] {
        bridge.availableEncryptionAlgorithms()
    }

    var availableHashAlgorithms: [String] {
        bridge.availableHashAlgorithms()
    }

}
