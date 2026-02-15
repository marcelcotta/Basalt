/*
 Copyright (c) 2024-2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import Foundation
import AppKit

/// Manages persistent user preferences via UserDefaults.
@MainActor
class PreferencesManager: ObservableObject {

    // MARK: - Security

    @Published var suppressKdfUpgradePrompt: Bool {
        didSet { UserDefaults.standard.set(suppressKdfUpgradePrompt, forKey: "suppressKdfUpgradePrompt") }
    }

    @Published var dismountOnScreenSaver: Bool {
        didSet { UserDefaults.standard.set(dismountOnScreenSaver, forKey: "dismountOnScreenSaver") }
    }

    @Published var dismountOnSleep: Bool {
        didSet { UserDefaults.standard.set(dismountOnSleep, forKey: "dismountOnSleep") }
    }

    @Published var forceDismount: Bool {
        didSet { UserDefaults.standard.set(forceDismount, forKey: "forceDismount") }
    }

    @Published var dismountOnQuit: Bool {
        didSet { UserDefaults.standard.set(dismountOnQuit, forKey: "dismountOnQuit") }
    }

    @Published var dismountOnLogOff: Bool {
        didSet { UserDefaults.standard.set(dismountOnLogOff, forKey: "dismountOnLogOff") }
    }

    @Published var dismountOnInactivity: Bool {
        didSet { UserDefaults.standard.set(dismountOnInactivity, forKey: "dismountOnInactivity") }
    }

    @Published var maxIdleMinutes: Int {
        didSet { UserDefaults.standard.set(maxIdleMinutes, forKey: "maxIdleMinutes") }
    }

    // MARK: - Mount Defaults

    @Published var defaultPreserveTimestamps: Bool {
        didSet { UserDefaults.standard.set(defaultPreserveTimestamps, forKey: "defaultPreserveTimestamps") }
    }

    @Published var defaultReadOnly: Bool {
        didSet { UserDefaults.standard.set(defaultReadOnly, forKey: "defaultReadOnly") }
    }

    @Published var openFinderAfterMount: Bool {
        didSet { UserDefaults.standard.set(openFinderAfterMount, forKey: "openFinderAfterMount") }
    }

    @Published var closeFinderOnDismount: Bool {
        didSet { UserDefaults.standard.set(closeFinderOnDismount, forKey: "closeFinderOnDismount") }
    }

    // MARK: - Init

    init() {
        let d = UserDefaults.standard

        d.register(defaults: [
            "suppressKdfUpgradePrompt": false,
            "dismountOnScreenSaver": false,
            "dismountOnSleep": false,
            "forceDismount": true,
            "dismountOnQuit": false,
            "dismountOnLogOff": true,
            "dismountOnInactivity": false,
            "maxIdleMinutes": 60,
            "defaultPreserveTimestamps": true,
            "defaultReadOnly": false,
            "openFinderAfterMount": true,
            "closeFinderOnDismount": true,
        ])

        suppressKdfUpgradePrompt = d.bool(forKey: "suppressKdfUpgradePrompt")
        dismountOnScreenSaver = d.bool(forKey: "dismountOnScreenSaver")
        dismountOnSleep = d.bool(forKey: "dismountOnSleep")
        forceDismount = d.bool(forKey: "forceDismount")
        dismountOnQuit = d.bool(forKey: "dismountOnQuit")
        dismountOnLogOff = d.bool(forKey: "dismountOnLogOff")
        dismountOnInactivity = d.bool(forKey: "dismountOnInactivity")
        maxIdleMinutes = d.integer(forKey: "maxIdleMinutes")
        defaultPreserveTimestamps = d.bool(forKey: "defaultPreserveTimestamps")
        defaultReadOnly = d.bool(forKey: "defaultReadOnly")
        openFinderAfterMount = d.bool(forKey: "openFinderAfterMount")
        closeFinderOnDismount = d.bool(forKey: "closeFinderOnDismount")
    }

    // MARK: - Apply to Mount Options

    func applyToMountOptions(_ opts: TCMountOptions) {
        opts.preserveTimestamps = defaultPreserveTimestamps
        opts.readOnly = defaultReadOnly
    }
}
