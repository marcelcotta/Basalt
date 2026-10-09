/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI

private let dicewareWordSet: Set<String> = Set(Diceware.wordList ?? [])

// MARK: - Strength meter

/// Four-segment strength bar with an entropy estimate for new passwords.
struct PasswordStrengthMeter: View {
    let password: String

    private var estimate: PasswordStrengthEstimate {
        PasswordStrengthEstimate.estimate(password, wordList: dicewareWordSet)
    }

    var body: some View {
        if !password.isEmpty {
            let estimate = estimate
            let level = estimate.level
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 3) {
                    ForEach(0..<4) { segment in
                        Capsule()
                            .fill(segment <= level.rawValue ? color(for: level) : Color.secondary.opacity(0.2))
                            .frame(height: 4)
                    }
                }
                HStack(spacing: 4) {
                    Text(label(for: level))
                        .fontWeight(.medium)
                        .foregroundColor(color(for: level))
                    Text("about \(Int(estimate.bits.rounded())) bits")
                        .foregroundColor(.secondary)
                }
                .font(.caption)

                if level == .weak {
                    Text("Easy to guess. Use a longer password or generate a passphrase.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .help("Rough estimate of how many guesses an attacker needs (2^bits). Argon2id makes each guess expensive, but cannot make a weak password strong.")
        }
    }

    private func label(for level: PasswordStrengthLevel) -> LocalizedStringKey {
        switch level {
        case .weak: return "Weak"
        case .fair: return "Fair"
        case .good: return "Good"
        case .strong: return "Strong"
        }
    }

    private func color(for level: PasswordStrengthLevel) -> Color {
        switch level {
        case .weak: return .red
        case .fair: return .orange
        case .good: return .yellow
        case .strong: return .green
        }
    }
}

// MARK: - Passphrase generator

/// Button with a popover that generates a Diceware passphrase and hands it to
/// `onUse` (which fills the password fields).
struct PassphraseGeneratorButton: View {
    let onUse: (String) -> Void

    @State private var showPopover = false
    @State private var wordCount = 6
    @State private var passphrase = ""

    var body: some View {
        Button {
            regenerate()
            showPopover = true
        } label: {
            Label("Generate Passphrase…", systemImage: "dice")
        }
        .disabled(Diceware.wordList == nil)
        .help("Creates a random passphrase from the EFF Diceware list. Easy to remember, hard to guess.")
        .popover(isPresented: $showPopover, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 10) {
                Text("Random Passphrase")
                    .font(.headline)

                Stepper(value: $wordCount, in: 5...7) {
                    Text("\(wordCount) words (about \(Int((Double(wordCount) * Diceware.bitsPerWord).rounded())) bits)")
                }
                .onChange(of: wordCount) { _ in regenerate() }

                Text(passphrase)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.1)))

                Label("Write it down or memorize it before you continue. There is no way to recover a forgotten password.", systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundColor(.orange)

                HStack {
                    Button("Regenerate") { regenerate() }
                    Spacer()
                    Button("Use Passphrase") {
                        onUse(passphrase)
                        passphrase = ""
                        showPopover = false
                    }
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(14)
            .frame(width: 420)
            .screenCaptureProtection()
        }
    }

    private func regenerate() {
        guard let list = Diceware.wordList else { return }
        passphrase = Diceware.passphrase(words: wordCount, from: list)
    }
}
