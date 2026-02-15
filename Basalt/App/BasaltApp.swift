/*
 Copyright (c) 2024-2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI

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

    func applicationDidFinishLaunching(_ notification: Notification) {
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

        // Observe screen saver start for auto-dismount
        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(screenSaverDidStart),
            name: NSNotification.Name("com.apple.screensaver.didstart"),
            object: nil
        )

        // Observe system sleep for auto-dismount
        NSWorkspace.shared.notificationCenter.addObserver(
            self,
            selector: #selector(systemWillSleep),
            name: NSWorkspace.willSleepNotification,
            object: nil
        )

        // Observe logout/shutdown/restart for auto-dismount
        NSWorkspace.shared.notificationCenter.addObserver(
            self,
            selector: #selector(systemWillPowerOff),
            name: NSWorkspace.willPowerOffNotification,
            object: nil
        )
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let prefs = preferences, let vm = volumeManager else { return .terminateNow }

        if prefs.dismountOnQuit && !vm.mountedVolumes.isEmpty {
            Task { @MainActor in
                vm.dismountAll(force: prefs.forceDismount)
                NSApp.reply(toApplicationShouldTerminate: true)
            }
            return .terminateLater
        }

        return .terminateNow
    }

    @objc private func screenSaverDidStart(_ notification: Notification) {
        Task { @MainActor in
            guard let prefs = preferences, prefs.dismountOnScreenSaver else { return }
            volumeManager?.dismountAll(force: prefs.forceDismount)
        }
    }

    @objc private func systemWillSleep(_ notification: Notification) {
        Task { @MainActor in
            guard let prefs = preferences, prefs.dismountOnSleep else { return }
            volumeManager?.dismountAll(force: prefs.forceDismount)
        }
    }

    @objc private func systemWillPowerOff(_ notification: Notification) {
        Task { @MainActor in
            guard let prefs = preferences, prefs.dismountOnLogOff else { return }
            volumeManager?.dismountAll(force: prefs.forceDismount)
        }
    }
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
