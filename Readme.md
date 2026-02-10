# Basalt

A modern, security-hardened fork of TrueCrypt 7.1a for macOS and Linux.

Basalt replaces TrueCrypt's wxWidgets GUI with a native SwiftUI app and adds
state-of-the-art key derivation via Argon2id — while maintaining full backward
compatibility with existing TrueCrypt and VeraCrypt volumes.


## Key Improvements over TrueCrypt 7.1a

- **Argon2id KDF** (RFC 9106): Memory-hard key derivation with two tiers
  - Standard: 512 MB, t=4, p=4
  - Maximum Security: 1 GB, t=4, p=8
- **PBKDF2 hardened**: 500,000+ iterations (up from 1,000-2,000)
- **Native macOS UI**: SwiftUI app with volume creation wizard, preferences,
  auto-dismount on sleep/screensaver/inactivity
- **Security hardening**: `memset_s()`, constant-time comparison, XTS key
  validation, `getentropy()`, screen-capture protection, FUSE `nosuid,nodev`
- **Universal Binary**: arm64 + x86_64 (macOS 12+)
- **CVE fixes**: Mount-point validation (CVE-2025-23021), absolute paths for
  system binaries (CVE-2024-54187)


## Compatibility

| Volume Type | Mount | Create |
|-------------|-------|--------|
| TrueCrypt 7.1a (AES, Serpent, Twofish) | Yes | Yes (legacy mode) |
| VeraCrypt (AES, Serpent, Twofish) | Yes | No |
| Basalt (Argon2id) | Yes | Yes |

Basalt volumes use `BSLT` magic bytes and cannot be opened by TrueCrypt 7.1a
or VeraCrypt (which lack Argon2id support).


## Building

### macOS

Requirements: macOS 12+, Xcode Command Line Tools, macFUSE, pkg-config

```sh
# Core library
make BASE_DIR=/tmp/truecrypt-build NOASM=1 libTrueCryptCore

# CLI tool
make BASE_DIR=/tmp/truecrypt-build NOASM=1 cli

# SwiftUI app
cd Basalt && bash build.sh debug

# Universal binary (arm64 + x86_64)
bash build-universal.sh release
```

Note: If your source path contains spaces, the build system automatically
creates a symlink at `/tmp/truecrypt-build`.

### Linux

Requirements: g++ (5+), make, pkg-config, libfuse-dev, dm-crypt kernel module

```sh
# Install dependencies (Debian/Ubuntu)
sudo apt install build-essential pkg-config libfuse-dev

# Install dependencies (Fedora/RHEL)
sudo dnf install gcc-c++ make pkgconfig fuse-devel

# Build CLI tool
make NOASM=1 cli

# Run self-tests
./CLI/basalt-cli --test

# Mount a volume (requires sudo for device-mapper)
sudo ./CLI/basalt-cli --mount /path/to/volume
```

The Linux build produces `basalt-cli` (command-line only). The SwiftUI GUI
is macOS-exclusive.


## Architecture

```
Basalt.app (SwiftUI)          Native macOS UI (macOS 12+)
TCCoreBridge.mm (ObjC++)      Bridge: Foundation <-> C++
basalt-cli (C++)              Standalone terminal tool (macOS + Linux)
libTrueCryptCore.a            Platform + Volume + Driver + Core
```

The C++ namespace remains `TrueCrypt` for internal compatibility.
On Linux, mounting uses FUSE + device-mapper (`dm-crypt`); on macOS it uses
FUSE + `hdiutil`.


## Security

See [SECURITY.md](SECURITY.md) for a detailed description of all security
hardening measures.


## License

Governed by the TrueCrypt License 3.0. See `License.txt` for details.

As required by the license, this derived work is not called "TrueCrypt".
