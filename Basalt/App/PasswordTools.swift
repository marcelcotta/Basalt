/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import Foundation

// MARK: - Diceware passphrases

/// Passphrase generator based on the EFF large wordlist (7776 words,
/// ~12.9 bits per word). Words are chosen with Swift's
/// SystemRandomNumberGenerator, which uses arc4random_buf (the system CSPRNG)
/// on Apple platforms.
enum Diceware {
    static let bitsPerWord = log2(7776.0)

    /// Volume passwords are limited to 64 bytes (TrueCrypt format).
    static let maxPassphraseBytes = 64

    /// Parses the EFF list format ("11111<TAB>abacus" per line).
    static func parseWordList(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).compactMap { line in
            let fields = line.split(separator: "\t")
            guard fields.count == 2 else { return nil }
            return String(fields[1])
        }
    }

    /// The bundled list, or nil if the resource is missing or damaged.
    static let wordList: [String]? = {
        guard let url = Bundle.main.url(forResource: "eff_large_wordlist", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8)
        else { return nil }
        let words = parseWordList(text)
        return words.count == 7776 ? words : nil
    }()

    /// Random passphrase of `count` words, regenerated until it fits into a
    /// volume password.
    static func passphrase(words count: Int, separator: String = "-", from list: [String]) -> String {
        precondition(!list.isEmpty && count > 0)
        while true {
            var generator = SystemRandomNumberGenerator()
            let words = (0..<count).map { _ in list.randomElement(using: &generator)! }
            let phrase = words.joined(separator: separator)
            if phrase.utf8.count <= maxPassphraseBytes {
                return phrase
            }
        }
    }
}

// MARK: - Password strength

enum PasswordStrengthLevel: Int, Comparable {
    case weak, fair, good, strong

    static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// Deliberately conservative entropy estimate used for feedback in the UI.
/// It recognises words from the Diceware list, common passwords, repeated
/// characters and simple sequences; everything else is rated by the size of
/// the character classes it uses.
struct PasswordStrengthEstimate {
    let bits: Double

    var level: PasswordStrengthLevel {
        switch bits {
        case ..<45: return .weak
        case ..<60: return .fair
        case ..<80: return .good
        default: return .strong
        }
    }

    private static let commonPasswords: Set<String> = [
        "password", "passwort", "motdepasse", "contraseña", "contrasena", "senha",
        "qwerty", "qwertz", "azerty", "letmein", "welcome", "admin", "login",
        "iloveyou", "monkey", "dragon", "master", "sunshine", "princess",
        "football", "baseball", "superman", "trustno1", "secret", "geheim",
        "hallo", "hello", "abc", "abcdef", "basalt", "truecrypt", "veracrypt",
    ]

    private static let separators = CharacterSet(charactersIn: "-_. ,;:/+")

    static func estimate(_ password: String, wordList: Set<String>? = nil) -> PasswordStrengthEstimate {
        guard !password.isEmpty else { return PasswordStrengthEstimate(bits: 0) }

        let tokens = password
            .components(separatedBy: separators)
            .filter { !$0.isEmpty }

        // Passphrase: rate each Diceware word at its list entropy.
        if tokens.count >= 2, let wordList {
            var bits = 0.0
            for token in tokens {
                if wordList.contains(token.lowercased()) {
                    bits += Diceware.bitsPerWord + (token == token.lowercased() ? 0 : 1)
                } else {
                    bits += characterBits(token, wordList: wordList)
                }
            }
            return PasswordStrengthEstimate(bits: min(bits, 256))
        }

        return PasswordStrengthEstimate(bits: min(characterBits(password, wordList: wordList), 256))
    }

    /// Entropy of a single token from its character classes, with penalties
    /// for dictionary words, common passwords, repetitions and sequences.
    private static func characterBits(_ token: String, wordList: Set<String>?) -> Double {
        let lowered = token.lowercased()
        let core = unleet(lowered.trimmingCharacters(in: .decimalDigits.union(.punctuationCharacters).union(.symbols)))
        let decorations = Double(token.count - core.count)

        // Common password or a single dictionary word, possibly with leetspeak
        // and a few digits or symbols around it: a guesser tries those first.
        if commonPasswords.contains(core) || commonPasswords.contains(unleet(lowered)) {
            return 4 + 3.3 * decorations
        }
        if let wordList, wordList.contains(core) {
            return Diceware.bitsPerWord + (token == lowered ? 0 : 1) + 3.3 * decorations
        }

        var pool = 0
        var hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false, hasOther = false
        for scalar in token.unicodeScalars {
            switch scalar.value {
            case 0x61...0x7A: hasLower = true
            case 0x41...0x5A: hasUpper = true
            case 0x30...0x39: hasDigit = true
            case 0x20...0x7E: hasSymbol = true
            default: hasOther = true
            }
        }
        if hasLower { pool += 26 }
        if hasUpper { pool += 26 }
        if hasDigit { pool += 10 }
        if hasSymbol { pool += 33 }
        if hasOther { pool += 64 }
        let scalars = Array(token.unicodeScalars)
        let values = scalars.map { Int($0.value) }

        // Runs of letters are most likely words: plain runs of four or more
        // letters, and leetspeak runs such as "Tr0ub4dor" (six or more letters
        // once normalised, at most every third one substituted, word-like case).
        let normalized = Array(unleet(token).unicodeScalars)
        let canNormalize = normalized.count == scalars.count
        let isLetter: (Int) -> Bool = { CharacterSet.letters.contains(scalars[$0]) }
        let isLetterNormalized: (Int) -> Bool = {
            CharacterSet.letters.contains(canNormalize ? normalized[$0] : scalars[$0])
        }

        func plainRuns(in range: Range<Int>) -> [Range<Int>] {
            var runs: [Range<Int>] = []
            var start = range.lowerBound
            while start < range.upperBound {
                guard isLetter(start) else { start += 1; continue }
                var end = start
                while end < range.upperBound && isLetter(end) { end += 1 }
                if end - start >= 4 { runs.append(start..<end) }
                start = end
            }
            return runs
        }

        func looksLikeWord(_ run: Range<Int>) -> Bool {
            let substitutions = run.filter { !isLetter($0) }.count
            guard run.count >= 6, substitutions * 3 <= run.count else { return false }
            let letters = run.filter(isLetter).map { scalars[$0] }
            let lower = letters.filter { CharacterSet.lowercaseLetters.contains($0) }.count
            let upper = letters.count - lower
            let firstUpper = isLetter(run.lowerBound) && CharacterSet.uppercaseLetters.contains(scalars[run.lowerBound])
            return upper == 0 || lower == 0 || (upper == 1 && firstUpper)
        }

        var wordRuns: [Range<Int>] = []
        var start = 0
        while start < scalars.count {
            guard isLetterNormalized(start) else { start += 1; continue }
            var end = start
            while end < scalars.count && isLetterNormalized(end) { end += 1 }
            let run = start..<end
            if !run.contains(where: { !isLetter($0) }) {
                if run.count >= 4 { wordRuns.append(run) }
            } else if looksLikeWord(run) {
                wordRuns.append(run)
            } else {
                wordRuns.append(contentsOf: plainRuns(in: run))
            }
            start = end
        }
        let structured = !wordRuns.isEmpty
        let poolBits = log2(Double(max(pool, 2)))

        func classBits(_ value: Int) -> Double {
            guard structured else { return poolBits }
            switch value {
            case 0x30...0x39: return log2(10)
            case 0x61...0x7A, 0x41...0x5A: return log2(26)
            case 0x20...0x7E: return log2(33)
            default: return log2(64)
            }
        }

        var bits = 0.0
        var i = 0
        while i < scalars.count {
            if let run = wordRuns.first(where: { $0.lowerBound == i }) {
                // Natural language carries roughly 2.5 bits per letter.
                bits += Double(run.count) * 2.5
                i = run.upperBound
                continue
            }

            // Repeated characters and runs like "1234" add little information.
            let full = classBits(values[i])
            if i > 0 && values[i] == values[i - 1] {
                bits += 0.25 * full
            } else if i > 1 && values[i] - values[i - 1] == values[i - 1] - values[i - 2]
                        && abs(values[i] - values[i - 1]) == 1 {
                bits += 0.25 * full
            } else {
                bits += full
            }
            i += 1
        }

        // Few distinct characters (e.g. "abababab") cap the estimate.
        return min(bits, Double(Set(values).count) * 8)
    }

    private static func unleet(_ s: String) -> String {
        let map: [Character: Character] = ["0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"]
        return String(s.map { map[$0] ?? $0 })
    }
}
