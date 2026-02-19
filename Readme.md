<p align="center">
  <img src="Resources/Icons/basalt-icon-256.png" width="128" alt="Basalt icon">
</p>
<h1 align="center">Basalt</h1>
<p align="center">
  <strong>A security-hardened fork of TrueCrypt 7.1a for macOS</strong><br>
  Native SwiftUI app &middot; Argon2id key derivation &middot; DarwinFUSE (no kext) &middot; Universal Binary (arm64 + x86_64)
</p>
<p align="center">
  <img src="https://img.shields.io/badge/macOS-12%2B-blue" alt="macOS 12+">
  <img src="https://img.shields.io/badge/license-TrueCrypt%203.0-lightgrey" alt="License">
</p>

---

TrueCrypt was abandoned in 2014. VeraCrypt continued it, but added questionable
ciphers, a complex PIM system, and a Windows bootloader signed by Microsoft.

Basalt takes a different path: fix what's broken, remove what shouldn't be there,
and build a native macOS app from scratch. No wxWidgets, no password cache, no
window dressing — just solid encryption with modern key derivation.

<p align="center">
  <img src="docs/screenshots/main-window.png" width="720" alt="Basalt main window with mounted volumes">
</p>

<p align="center">
  <img src="docs/screenshots/mount-dialog.png" width="720" alt="Mount volume dialog">
  <img src="docs/screenshots/create-encryption.png" width="720" alt="Volume creation — encryption settings with Argon2id-Max">
</p>


## Key Features

- **Argon2id key derivation** — 1 GB memory cost, 8 threads. GPU-resistant by design.
- **Opens TrueCrypt & VeraCrypt volumes** — plus automatic KDF upgrade prompt for legacy iterations.
- **Hidden volumes** — create and mount with plausible deniability, with write protection for the outer volume.
- **Native SwiftUI app** — no wxWidgets, no Qt on macOS. Clean, dark-mode interface.
- **CLI included** — `basalt-cli` for scripting and headless use.
- **DarwinFUSE built-in** — no macFUSE, no kernel extension, no SIP changes.
- **Zero-state design** — no password cache, no favorites, no history. Forensic analysis reveals nothing.
- **Auto-dismount** — on inactivity, screen lock, sleep, quit, and logout.
- **Screen capture protection** — the entire app is invisible to screenshots, screen recording, and AirPlay.
- **~60,000 lines of attack surface removed** — boot loader, kernel driver, PKCS#11, wxWidgets all deleted.

<details>
<summary><strong>More screenshots</strong></summary>
<br>
<p align="center">
  <img src="docs/screenshots/create-location.png" width="720" alt="Volume creation — location and size">
  <img src="docs/screenshots/create-password.png" width="720" alt="Volume creation — password and keyfiles">
  <img src="docs/screenshots/create-format.png" width="720" alt="Volume creation — filesystem format">
  <img src="docs/screenshots/protection-triggered.png" width="720" alt="Hidden volume protection triggered warning">
</p>
</details>


## Volume Compatibility

| Format | Mount | Create |
|--------|:-----:|:------:|
| Basalt | ✓ | ✓ |
| TrueCrypt 7.1a | ✓ | ✓ (legacy mode) |
| VeraCrypt | ✓ | — |

Existing volumes just work. Legacy TrueCrypt volumes get an automatic upgrade
prompt for modern key derivation.


## Building

Requirements: macOS 12+, Xcode Command Line Tools, pkg-config.
No external FUSE installation required.

**GUI (Basalt.app):**
```sh
cd Basalt && ./build.sh
```

**CLI:**
```sh
make cli
```

**Universal Binary (arm64 + x86_64):**
```sh
bash build-universal.sh release
```


## Architecture

```
Basalt.app (SwiftUI)          Native macOS UI (macOS 12+)
  TCCoreBridge.mm (ObjC++)    Bridge: Foundation ↔ C++
basalt-cli (C++)              Standalone terminal tool
  libBasaltCore.a (src/)      Crypto + Volume + FUSE + Platform
    DarwinFUSE (C)            NFSv4 userspace FUSE (no kernel extension)
```


## Documentation

| Document | Contents |
|----------|----------|
| **[SECURITY.md](SECURITY.md)** | All 34 security hardening measures, attack surface reduction, cipher selection rationale, comparison with VeraCrypt, steganographic keyfiles guide |
| **[License.txt](License.txt)** | TrueCrypt License 3.0 |


## License

Based on [TrueCrypt](http://www.truecrypt.org/), freely available at
http://www.truecrypt.org/.

Governed by the TrueCrypt License 3.0 — see [License.txt](License.txt) for
the full text. TrueCrypt is a trademark of the TrueCrypt Foundation. VeraCrypt
is a trademark of IDRIX. Basalt is an independent project, not affiliated with
or endorsed by either.
