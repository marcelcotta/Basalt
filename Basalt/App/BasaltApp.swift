/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI
import IOKit.pwr_mgt

/// Custom entry point: intercept --core-service before SwiftUI starts.
///
/// When CoreService needs admin privileges it re-launches the binary via
/// `sudo /path/to/Basalt --core-service`.  Without this check the full
/// SwiftUI app would start (opening a new window) instead of running the
/// elevated service loop.
@main
enum BasaltEntry {
    static func main() {
        if TCHandleCoreServiceArgument(CommandLine.argc, CommandLine.unsafeArgv) {
            return
        }
        BasaltApp.main()
    }
}

struct BasaltApp: App {
    @StateObject private var volumeManager = VolumeManager()
    @StateObject private var preferences = PreferencesManager()
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            MainWindow()
                .environmentObject(volumeManager)
                .environmentObject(preferences)
                .onAppear {
                    volumeManager.preferences = preferences
                    appDelegate.volumeManager = volumeManager
                    appDelegate.preferences = preferences
                    appDelegate.observeVolumes(volumeManager)
                }
        }
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Run Self-Test...") {
                    volumeManager.runSelfTest()
                }
            }

            CommandGroup(replacing: .newItem) {
                Button("Mount Volume...") {
                    volumeManager.showMountSheet = true
                }
                .keyboardShortcut("m", modifiers: .command)

                Button("Create Volume...") {
                    volumeManager.showCreateSheet = true
                }
                .keyboardShortcut("n", modifiers: [.command, .shift])

                Divider()

                Button("Change Password...") {
                    volumeManager.showChangePasswordSheet = true
                }

                Button("Backup Volume Headers...") {
                    volumeManager.showBackupSheet = true
                }

                Button("Restore Volume Headers...") {
                    volumeManager.showRestoreSheet = true
                }

                Divider()

                Button("Dismount All") {
                    volumeManager.dismountAll(force: preferences.forceDismount)
                }
                .keyboardShortcut("d", modifiers: [.command, .shift])
            }
        }

        Settings {
            PreferencesView()
                .environmentObject(preferences)
        }
    }
}

// MARK: - App Delegate for lifecycle events + screen saver observation

class AppDelegate: NSObject, NSApplicationDelegate {
    var volumeManager: VolumeManager?
    var preferences: PreferencesManager?

    private var statusItem: NSStatusItem?
    private var volumeObserver: NSObjectProtocol?

    // System power notifications (IORegisterForSystemPower)
    private var powerRootPort: io_connect_t = 0
    private var powerNotifyPort: IONotificationPortRef?
    private var powerNotifier: io_object_t = 0

    /// Set when logout/shutdown/restart was requested (willPowerOff); the
    /// following terminate request then waits for the dismount.
    private var powerOffRequestedAt: Date?

    /// Set once applicationShouldTerminate has tried to dismount.
    private var quitDismountAttempted = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        // SECURITY: Prevent screen capture of ALL windows (including alerts/dialogs).
        //
        // SwiftUI .alert() creates a separate NSAlert window that does not inherit
        // sharingType from the parent window. Notification-based approaches
        // (didBecomeKey, didUpdate) fire AFTER the window is already visible,
        // leaving a brief frame where content could be captured.
        //
        // Solution: Swizzle NSWindow.orderFront(_:) to set sharingType = .none
        // BEFORE the window becomes visible. This covers all windows in the
        // process: main window, sheets, alerts, settings, popovers, etc.
        NSWindow.installScreenCaptureProtection()

        // Observe screen saver start and screen lock for auto-dismount.
        // A lock via Ctrl-Cmd-Q, the lid or Touch ID does not start the screen saver.
        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(screenSaverDidStart),
            name: NSNotification.Name("com.apple.screensaver.didstart"),
            object: nil
        )
        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(screenSaverDidStart),
            name: NSNotification.Name("com.apple.screenIsLocked"),
            object: nil
        )

        // Observe system sleep for auto-dismount. IOKit lets us delay the
        // sleep until the volumes are dismounted (NSWorkspace.willSleep does not).
        registerForSystemPowerNotifications()

        // Observe logout/shutdown/restart for auto-dismount
        NSWorkspace.shared.notificationCenter.addObserver(
            self,
            selector: #selector(systemWillPowerOff),
            name: NSWorkspace.willPowerOffNotification,
            object: nil
        )

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appWillTerminate),
            name: NSApplication.willTerminateNotification,
            object: nil
        )
    }

    // MARK: - Menu Bar Status Item

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "Basalt")
        }
        rebuildStatusMenu(volumes: [])
    }

    func observeVolumes(_ vm: VolumeManager) {
        volumeObserver = NotificationCenter.default.addObserver(
            forName: .basaltVolumesChanged, object: nil, queue: .main
        ) { [weak self] notification in
            let volumes = notification.userInfo?["volumes"] as? [TCVolumeInfo] ?? []
            self?.rebuildStatusMenu(volumes: volumes)
            if let button = self?.statusItem?.button {
                let name = volumes.isEmpty ? "lock.shield" : "lock.shield.fill"
                button.image = NSImage(systemSymbolName: name, accessibilityDescription: "Basalt")
            }
        }
    }

    private func rebuildStatusMenu(volumes: [TCVolumeInfo]) {
        let menu = NSMenu()

        if volumes.isEmpty {
            let item = NSMenuItem(title: String(localized: "No Volumes Mounted"), action: nil, keyEquivalent: "")
            item.isEnabled = false
            menu.addItem(item)
        } else {
            for vol in volumes {
                let label = (vol.mountPoint.isEmpty ? vol.path : vol.mountPoint)
                let item = NSMenuItem(title: label, action: nil, keyEquivalent: "")
                item.isEnabled = false
                menu.addItem(item)

                let dismountItem = NSMenuItem(title: "  " + String(localized: "Dismount"), action: #selector(statusMenuDismount(_:)), keyEquivalent: "")
                dismountItem.target = self
                dismountItem.representedObject = vol
                menu.addItem(dismountItem)
            }

            menu.addItem(NSMenuItem.separator())

            let dismountAll = NSMenuItem(title: String(localized: "Dismount All"), action: #selector(statusMenuDismountAll), keyEquivalent: "")
            dismountAll.target = self
            menu.addItem(dismountAll)
        }

        menu.addItem(NSMenuItem.separator())

        let mount = NSMenuItem(title: String(localized: "Mount Volume..."), action: #selector(statusMenuMount), keyEquivalent: "")
        mount.target = self
        menu.addItem(mount)

        menu.addItem(NSMenuItem.separator())

        let quit = NSMenuItem(title: String(localized: "Quit Basalt"), action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit)

        statusItem?.menu = menu
    }

    @objc private func statusMenuMount() {
        NSApp.activate(ignoringOtherApps: true)
        Task { @MainActor in
            volumeManager?.showMountSheet = true
        }
    }

    @objc private func statusMenuDismount(_ sender: NSMenuItem) {
        guard let vol = sender.representedObject as? TCVolumeInfo else { return }
        Task { @MainActor in
            volumeManager?.dismountVolume(vol, force: preferences?.forceDismount ?? true)
        }
    }

    @objc private func statusMenuDismountAll() {
        Task { @MainActor in
            volumeManager?.dismountAll(force: preferences?.forceDismount ?? true)
        }
    }

    // MARK: - App Lifecycle

    /// Logout/shutdown asks running apps to quit right after willPowerOff.
    private var isPoweringOff: Bool {
        powerOffRequestedAt.map { Date().timeIntervalSince($0) < 120 } ?? false
    }

    private var shouldDismountOnQuit: Bool {
        guard let prefs = preferences else { return false }
        return prefs.dismountOnQuit || (isPoweringOff && prefs.dismountOnLogOff)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let prefs = preferences, let vm = volumeManager, shouldDismountOnQuit else {
            return .terminateNow
        }

        // Dismount before answering instead of deferring the answer with
        // .terminateLater, which left the volumes mounted after quitting.
        quitDismountAttempted = true
        guard let error = vm.dismountAllBeforeQuit(force: prefs.forceDismount) else {
            return .terminateNow
        }

        // Never hold up logout, restart or shutdown.
        if isPoweringOff { return .terminateNow }

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = String(localized: "Volumes could not be dismounted")
        alert.informativeText = error + "\n\n"
            + String(localized: "If you quit now, the volumes stay mounted and accessible.")
        alert.addButton(withTitle: String(localized: "Cancel"))
        alert.addButton(withTitle: String(localized: "Quit Anyway"))
        if alert.runModal() == .alertSecondButtonReturn {
            return .terminateNow
        }
        quitDismountAttempted = false
        return .terminateCancel
    }

    /// Fallback for terminations that bypass applicationShouldTerminate.
    @objc private func appWillTerminate(_ notification: Notification) {
        guard !quitDismountAttempted, let prefs = preferences, let vm = volumeManager,
              shouldDismountOnQuit else { return }
        _ = vm.dismountAllBeforeQuit(force: prefs.forceDismount, timeout: 30)
    }

    // MARK: - System Sleep

    // IOKit message constants (iokit_common_msg(...)); the C macros are not
    // imported into Swift.
    private static let kIOMessageCanSystemSleep: UInt32 = 0xE000_0270
    private static let kIOMessageSystemWillSleep: UInt32 = 0xE000_0280

    private func registerForSystemPowerNotifications() {
        let refcon = Unmanaged.passUnretained(self).toOpaque()
        powerRootPort = IORegisterForSystemPower(refcon, &powerNotifyPort, { refcon, _, messageType, messageArgument in
            // C callback on the main run loop; hop onto the main actor explicitly.
            guard let refcon else { return }
            let delegate = Unmanaged<AppDelegate>.fromOpaque(refcon).takeUnretainedValue()
            let notificationID = Int(bitPattern: messageArgument)
            Task { @MainActor in
                delegate.handlePowerMessage(messageType, notificationID: notificationID)
            }
        }, &powerNotifier)

        guard powerRootPort != 0, let port = powerNotifyPort else { return }
        CFRunLoopAddSource(CFRunLoopGetMain(),
                           IONotificationPortGetRunLoopSource(port).takeUnretainedValue(),
                           .commonModes)
    }

    /// The system waits (up to ~30 s) for IOAllowPowerChange before sleeping,
    /// which gives the dismount time to finish.
    @MainActor
    private func handlePowerMessage(_ messageType: UInt32, notificationID: Int) {
        switch messageType {
        case Self.kIOMessageCanSystemSleep:
            IOAllowPowerChange(powerRootPort, notificationID)

        case Self.kIOMessageSystemWillSleep:
            guard let prefs = preferences, prefs.dismountOnSleep,
                  let vm = volumeManager, !vm.mountedVolumes.isEmpty
            else {
                IOAllowPowerChange(powerRootPort, notificationID)
                return
            }
            let rootPort = powerRootPort
            vm.dismountAll(force: prefs.forceDismount) {
                IOAllowPowerChange(rootPort, notificationID)
            }

        default:
            break
        }
    }

    @objc private func screenSaverDidStart(_ notification: Notification) {
        Task { @MainActor in
            guard let prefs = preferences, prefs.dismountOnScreenSaver else { return }
            volumeManager?.dismountAll(force: prefs.forceDismount)
        }
    }

    @objc private func systemWillPowerOff(_ notification: Notification) {
        // The dismount itself happens in applicationShouldTerminate, which the
        // system calls next and which can delay quitting until it is done.
        powerOffRequestedAt = Date()
    }
}

extension Notification.Name {
    static let basaltVolumesChanged = Notification.Name("BasaltVolumesChanged")
}

// MARK: - Screen Capture Protection via Method Swizzling
//
// Swizzles NSWindow.orderFront(_:) so that sharingType is set to .none
// BEFORE the window becomes visible. This eliminates the timing gap that
// exists with notification-based approaches (didBecomeKey fires AFTER
// the window is already rendered).
//
// Covers: main window, sheets, .alert() dialogs, Settings, popovers,
// and any other NSWindow subclass created by SwiftUI or AppKit.

extension NSWindow {
    private static var swizzled = false

    static func installScreenCaptureProtection() {
        guard !swizzled else { return }
        swizzled = true

        // Swizzle orderFront(_:) — called by AppKit before any window becomes visible
        let originalSelector = #selector(NSWindow.orderFront(_:))
        let swizzledSelector = #selector(NSWindow.basalt_orderFront(_:))

        guard let originalMethod = class_getInstanceMethod(NSWindow.self, originalSelector),
              let swizzledMethod = class_getInstanceMethod(NSWindow.self, swizzledSelector)
        else { return }

        method_exchangeImplementations(originalMethod, swizzledMethod)

        // Also swizzle makeKeyAndOrderFront(_:) for windows that skip orderFront
        let originalMKOF = #selector(NSWindow.makeKeyAndOrderFront(_:))
        let swizzledMKOF = #selector(NSWindow.basalt_makeKeyAndOrderFront(_:))

        guard let origMKOF = class_getInstanceMethod(NSWindow.self, originalMKOF),
              let swizMKOF = class_getInstanceMethod(NSWindow.self, swizzledMKOF)
        else { return }

        method_exchangeImplementations(origMKOF, swizMKOF)
    }

    @objc private func basalt_orderFront(_ sender: Any?) {
        if self.sharingType != .none {
            self.sharingType = .none
        }
        // Call the original (swizzled) implementation
        self.basalt_orderFront(sender)
    }

    @objc private func basalt_makeKeyAndOrderFront(_ sender: Any?) {
        if self.sharingType != .none {
            self.sharingType = .none
        }
        // Call the original (swizzled) implementation
        self.basalt_makeKeyAndOrderFront(sender)
    }
}
