/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI

struct PreferencesView: View {
    @EnvironmentObject var prefs: PreferencesManager

    var body: some View {
        TabView {
            securityTab
                .tabItem { Label("Security", systemImage: "lock.shield") }

            mountDefaultsTab
                .tabItem { Label("Mount Defaults", systemImage: "externaldrive") }
        }
        .frame(width: 450, height: 360)
    }

    // MARK: - Security Tab

    private var securityTab: some View {
        Form {
            Section("Auto-Dismount") {
                Toggle("Dismount all when screen saver starts", isOn: $prefs.dismountOnScreenSaver)
                Toggle("Dismount all when system sleeps", isOn: $prefs.dismountOnSleep)

                HStack {
                    Toggle("Dismount all after", isOn: $prefs.dismountOnInactivity)
                    Picker("", selection: $prefs.maxIdleMinutes) {
                        Text("5 min").tag(5)
                        Text("10 min").tag(10)
                        Text("30 min").tag(30)
                        Text("1 hour").tag(60)
                        Text("2 hours").tag(120)
                    }
                    .labelsHidden()
                    .fixedSize()
                    .disabled(!prefs.dismountOnInactivity)
                    Text("of inactivity")
                }

                Toggle("Dismount all on logout/shutdown", isOn: $prefs.dismountOnLogOff)

                Toggle("Force dismount (even if files are open)", isOn: $prefs.forceDismount)
                    .help("Unmounts volumes even if applications still have open files. Disable to be warned about open files first.")
            }

            Divider()

            Section("On Quit") {
                Toggle("Dismount all volumes when Basalt quits", isOn: $prefs.dismountOnQuit)
            }

            Divider()

            Section("Key Derivation") {
                Toggle("Don't prompt to upgrade legacy volumes", isOn: $prefs.suppressKdfUpgradePrompt)
                    .help("Silences the prompt to upgrade old TrueCrypt volumes to stronger key derivation.")
            }
        }
        .padding(20)
    }

    // MARK: - Mount Defaults Tab

    private var mountDefaultsTab: some View {
        Form {
            Section("Default Mount Options") {
                Toggle("Preserve file timestamps", isOn: $prefs.defaultPreserveTimestamps)
                    .help("Keeps original file dates unchanged when accessing files on the volume.")
                Toggle("Mount as read-only", isOn: $prefs.defaultReadOnly)
            }

            Divider()

            Section("After Mounting") {
                Toggle("Open Finder at mount point", isOn: $prefs.openFinderAfterMount)
            }

            Divider()

            Section("On Dismount") {
                Toggle("Close Finder windows of dismounted volumes", isOn: $prefs.closeFinderOnDismount)
            }
        }
        .padding(20)
    }
}
