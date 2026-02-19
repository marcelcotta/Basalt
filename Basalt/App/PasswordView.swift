/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

import SwiftUI

/// Secure password entry with show/hide toggle.
/// Uses native SecureField (NSSecureTextField) — solves the wxWidgets
/// SecurePasswordInput problem completely via the OS-managed secure text field.
struct PasswordView: View {
    let label: String
    @Binding var password: String
    @State private var showPassword = false
    var focused: FocusState<Bool>.Binding?

    init(_ label: String = "Password", text: Binding<String>, focused: FocusState<Bool>.Binding? = nil) {
        self.label = label
        self._password = text
        self.focused = focused
    }

    var body: some View {
        HStack {
            if showPassword {
                let field = TextField(label, text: $password)
                    .textFieldStyle(.roundedBorder)
                if let focused {
                    field.focused(focused)
                } else {
                    field
                }
            } else {
                let field = SecureField(label, text: $password)
                    .textFieldStyle(.roundedBorder)
                if let focused {
                    field.focused(focused)
                } else {
                    field
                }
            }

            Button {
                showPassword.toggle()
            } label: {
                Image(systemName: showPassword ? "eye.slash" : "eye")
                    .foregroundColor(.secondary)
            }
            .buttonStyle(.borderless)
            .focusable(false)
            .help(showPassword ? "Hide password" : "Show password")
        }
    }
}
