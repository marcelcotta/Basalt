<p align="center">
  <img src="Resources/Icons/Basalt.png" width="128" alt="Basalt icon">
</p>
<h1 align="center">Basalt</h1>
<p align="center">
  <strong>A security-hardened fork of TrueCrypt 7.1a for macOS and Linux</strong><br>
  Native SwiftUI app &middot; Argon2id key derivation &middot; DarwinFUSE (no kext) &middot; Universal Binary (arm64 + x86_64)
</p>
<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-blue" alt="Version 1.0">
  <img src="https://img.shields.io/badge/macOS-12%2B-blue" alt="macOS 12+">
  <img src="https://img.shields.io/badge/Linux-CLI-green" alt="Linux CLI">
  <img src="https://img.shields.io/badge/license-TrueCrypt%203.0-lightgrey" alt="License">
</p>

---

TrueCrypt was abandoned in 2014. VeraCrypt continued it, but added questionable
ciphers, a complex PIM system, and a Windows bootloader signed by Microsoft.

Basalt takes a different path: fix what's broken, remove what shouldn't be there,
and build a native macOS app from scratch. No wxWidgets, no password cache, no
window dressing — just solid encryption with modern key derivation.


## What Basalt Does Differently

### Compared to TrueCrypt 7.1a

TrueCrypt's crypto was audited and found sound. Its implementation had issues:

| Area | TrueCrypt 7.1a | Basalt |
|------|---------------|--------|
| **Key derivation** | PBKDF2, 1,000–2,000 iterations | Argon2id-Max (1 GB, p=8) default + PBKDF2 at 500,000 iterations |
| **Memory erasure** | `volatile` pointer trick (can be optimized away) | `memset_s()` (C11, guaranteed) |
| **RNG pool mixing** | Addition (`+=`, accumulates bias) | XOR (`^=`, entropy-neutral) |
| **Password cache** | Plaintext passwords kept in heap | Removed entirely |
| **Entropy source** | `/dev/urandom` file I/O | `getentropy()` kernel syscall |
| **Key comparison** | `memcmp()` (timing side-channel) | Constant-time comparison |
| **XTS keys** | No validation | Rejects identical key pairs |
| **PBKDF2 block counter** | Single byte (RFC non-compliant) | 4-byte big-endian (RFC 2898) |
| **GUI toolkit** | wxWidgets (86 files, ~2 MB dependency) | Native SwiftUI / standalone CLI |
| **FUSE** | Requires macFUSE kernel extension | DarwinFUSE — built-in NFSv4 loopback, no kext needed |
| **Screen capture** | Unprotected | `NSWindow.sharingType = .none` |
| **FUSE mounts** | Default options | `nosuid,nodev` |
| **AES on ARM** | Software T-tables (cache-timing vulnerable) | ARMv8 hardware AES (constant-time) |
| **Mount points** | No validation | System directories blocked |
| **Volume creation** | GUI only | GUI + CLI (`basalt-cli --create`) |


### Compared to VeraCrypt

VeraCrypt fixed many of the same issues. Basalt diverges where VeraCrypt made
choices we disagree with:

| Area | VeraCrypt | Basalt |
|------|-----------|--------|
| **Ciphers** | AES, Serpent, Twofish + Camellia + **Kuznyechik** | AES, Serpent, Twofish only |
| **Kuznyechik** | Included despite S-box concerns (Perrin & Udovenko 2019) | Excluded — unexplained algebraic structure from FSB |
| **PIM** | User-tunable iterations (can weaken to ~2,000) | Fixed high iterations (500,000) — no user footgun |
| **Password cache** | Still caches plaintext passwords in memory | Removed entirely |
| **Force dismount** | Off by default | On by default |
| **Bootloader** | UEFI DcsBoot signed by Microsoft UEFI CA 2011 | No bootloader — no third-party trust chain |
| **Pre-compiled blobs** | DCS bootloader binaries, no reproducible builds | 100% built from source |
| **Key derivation** | PBKDF2 (same iterations as Basalt at PIM=0) | Argon2id (memory-hard) + PBKDF2 |
| **Argon2id parallelism** | p=1 ("consistent behavior") | p=4 / p=8 (actual GPU resistance) |
| **FUSE dependency** | Requires macFUSE / OSXFUSE | DarwinFUSE — zero external dependencies |

**Why no Kuznyechik?** The S-box was designed by the FSB and claimed to be random.
Researchers proved it contains a hidden algebraic structure — the same class of
"nothing up my sleeve" violation that made Dual_EC_DRBG a scandal.

**Why no PIM?** PIM provides ~10 bits of entropy (values 1–999) while allowing
users to set dangerously low iterations. Adding 2–3 characters to your password
gives the same brute-force resistance without the risk.


## Volume Compatibility

Basalt opens volumes from all three ecosystems. Magic bytes are encrypted inside
the header — a Basalt volume on disk is indistinguishable from random data.

| Magic | Format | Mount | Create |
|-------|--------|:-----:|:------:|
| `BSLT` | Basalt | ✓ | ✓ |
| `TRUE` | TrueCrypt 7.1a | ✓ | ✓ (legacy mode) |
| `VERA` | VeraCrypt | ✓ | — |

- **TrueCrypt 7.1a volumes**: Mount without delay (legacy KDFs tried first). Automatic upgrade prompt for iteration counts.
- **VeraCrypt volumes**: AES, Serpent, Twofish and their cascades. Camellia/Kuznyechik volumes are not supported.
- **Basalt volumes**: Argon2id or hardened PBKDF2. Cannot be opened by TrueCrypt or VeraCrypt.


## Zero-State Design

Basalt remembers nothing.

- **No password cache** — enter your password every time
- **No favorites, no history** — no record of which containers exist or when they were used
- **No default keyfiles** — keyfile selection is explicit, per-operation
- **No window state** — nothing persisted to disk
- **Screen capture blocked** — the entire app window is invisible to screenshots, screen recording, and AirPlay

Forensic analysis of the application reveals nothing about your volumes.


## Auto-Dismount

Volumes are automatically closed when you're not there:

- **Inactivity timeout** — per-volume I/O tracking (5/10/30/60/120 min)
- **Screen saver** — volumes close when the screen locks
- **System sleep** — volumes close before the machine sleeps
- **App quit** — async dismount before exit
- **Logout / shutdown** — volumes close on system power events

Force dismount is on by default — volumes close even when processes hold open handles.


## Security Hardening Summary

34 security measures across 9 waves. Full details in [SECURITY.md](SECURITY.md).

**Critical fixes**: `memset_s()` for memory erasure, XOR-based RNG mixing, PBKDF2
RFC compliance, constant-time key comparison, XTS key validation, stack password wipe.

**Structural**: `mlock()` for key memory, password cache removal, 500x PBKDF2 iteration
increase, Argon2id with 512 MB / 1 GB memory cost.

**Platform**: ARMv8 hardware AES (cache-timing immune), `getentropy()` syscall,
screen capture protection, FUSE `nosuid,nodev`, mount point validation.

**CVE fixes**: CVE-2025-23021 (mount point traversal), CVE-2024-54187 (PATH hijacking).


## Building

### macOS

Requirements: macOS 12+, Xcode Command Line Tools, pkg-config

No external FUSE installation required — DarwinFUSE is built-in.

```sh
# Universal binary (arm64 + x86_64) — recommended
bash build-universal.sh release

# Or build components individually:
make BASE_DIR=/tmp/truecrypt-build NOASM=1 libTrueCryptCore   # Core library
make BASE_DIR=/tmp/truecrypt-build NOASM=1 cli                 # CLI tool
cd Basalt && bash build.sh debug                               # SwiftUI app
```

### Linux

Requirements: g++ (5+), make, pkg-config, libfuse-dev, dm-crypt kernel module

```sh
# Debian/Ubuntu
sudo apt install build-essential pkg-config libfuse-dev

# Fedora/RHEL
sudo dnf install gcc-c++ make pkgconfig fuse-devel

# Build and test
make NOASM=1 cli
./CLI/basalt-cli --test

# Mount a volume
sudo ./CLI/basalt-cli --mount /path/to/volume
```

The Linux build produces `basalt-cli` (command-line only). The SwiftUI GUI is macOS-exclusive.


## Architecture

```
Basalt.app (SwiftUI)          Native macOS UI (macOS 12+)
  TCCoreBridge.mm (ObjC++)    Bridge: Foundation <-> C++
basalt-cli (C++)              Standalone terminal tool (macOS + Linux)
  libTrueCryptCore.a          Crypto + Volume + FUSE + Platform
```

The C++ namespace remains `TrueCrypt` for internal compatibility.
On Linux, mounting uses libfuse + device-mapper (`dm-crypt`); on macOS it uses
DarwinFUSE (built-in NFSv4 loopback) + `hdiutil`.


## DarwinFUSE

Basalt includes DarwinFUSE, an open-source userspace filesystem layer for macOS
using NFSv4 loopback. No kernel extension, no System Extension, no SIP changes,
no Recovery Mode.

DarwinFUSE implements the standard FUSE API (v26) and can serve as a drop-in
replacement for macFUSE in other projects.


## Design Decisions

Some things Basalt deliberately doesn't do:

- **No full disk encryption** — Container-based only. FDE requires a bootloader, and bootloaders require trusting Microsoft or building your own pre-boot environment. Use FileVault (macOS) or LUKS (Linux) for system encryption.
- **Not notarized** — No Apple in the trust chain. Approve manually in System Settings → Privacy & Security.
- **Legacy hash algorithms maintained** — SHA-1 and RIPEMD-160 exist for opening old volumes, not for creating new ones. Argon2id-Max is the default.


## Actual Limitations

Things we'd fix if we could:

- **No authenticated encryption** — XTS mode doesn't detect tampering. AES-GCM would, but requires a format change.
- **Serpent/Twofish are software-only** — No hardware acceleration exists for these ciphers on any platform. AES with ARMv8 extensions is faster and constant-time; cascades trade speed for defense-in-depth.


## License

Governed by the TrueCrypt License 3.0. See [License.txt](License.txt) for details.

As required by the license, this derived work is not called "TrueCrypt".
