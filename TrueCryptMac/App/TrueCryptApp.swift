/*
 Copyright (c) 2024 TrueCrypt macOS Port. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI

@main
struct TrueCryptApp: App {
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
