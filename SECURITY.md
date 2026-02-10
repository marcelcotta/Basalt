# Security Hardening: Basalt (TrueCrypt 7.1a macOS Port)

This document describes all security-relevant changes made to the TrueCrypt 7.1a
codebase as part of the macOS 14 (Apple Silicon) port. The goal is to fix known
weaknesses identified by the original OCAP audits (2013-2015) and bring the
implementation to modern standards — without breaking compatibility with existing
TrueCrypt volumes.

No backdoors were found in the original TrueCrypt 7.1a source code during our
comprehensive audit (RNG, PBKDF2, encryption, volume headers, memory handling,
and suspicious pattern analysis).


## Wave 1 — Critical Fixes

### 1. Secure Memory Erasure (`burn()`)
**File:** `Common/Tcdefs.h`
**Problem:** The original `burn()` macro used a volatile pointer trick that compilers
could optimize away, leaving sensitive data (keys, passwords) in memory.
**Fix:** Replaced with `memset_s()` (C11 Annex K), which is guaranteed not to be
optimized away. Available on macOS 10.9+.

### 2. Stack Password Wipe
**File:** `Volume/VolumePassword.cpp`
**Problem:** The stack buffer holding the user's password was not zeroed after use.
**Fix:** Added `burn(passwordBuf, sizeof(passwordBuf))` after password processing.

### 3. RNG Pool Mixing: XOR instead of Addition
**File:** `Core/RandomNumberGenerator.cpp` (3 locations)
**Problem:** The entropy pool used `+=` (addition) for mixing, which can accumulate
bias over time and is not entropy-neutral.
**Fix:** Changed to `^=` (XOR), which is the standard cryptographic mixing operation
and preserves entropy.

### 4. RNG Pool Inversion Removed
**File:** `Core/RandomNumberGenerator.cpp`
**Problem:** After mixing, the pool was inverted (`~Pool[i]`), a non-standard operation
with no cryptographic justification that reduces effective entropy.
**Fix:** Removed the inversion step entirely.

### 5. Hash Initialization Before ProcessData
**File:** `Core/RandomNumberGenerator.cpp`
**Problem:** `PoolHash->ProcessData()` was called without prior `Init()`, potentially
processing data with stale internal state.
**Fix:** Added `PoolHash->Init()` before each `ProcessData()` call.

### 6. RNG Self-Test After Seeding
**File:** `Core/RandomNumberGenerator.cpp`
**Problem:** The RNG self-test ran before the pool was seeded with system entropy,
testing uninitialized state.
**Fix:** Reordered `Start()`: set hash algorithm, seed pool, then run self-test.

### 7. StringConverter Secure Erasure
**File:** `Platform/StringConverter.cpp`
**Problem:** `StringConverter::Erase()` overwrote strings with spaces instead of using
`burn()`, and the space-writing could be optimized away.
**Fix:** Now uses `burn()` (→ `memset_s`) for both `string` and `wstring` variants.

### 8. Constant-Time Password Comparison
**Files:** `Platform/Memory.h`, `Platform/Memory.cpp`, `Platform/Buffer.h`
**Problem:** `BufferPtr::IsDataEqual()` used `memcmp()`, which can leak information
about key material through timing side channels.
**Fix:** Added `Memory::ConstantTimeCompare()` using volatile pointers and OR-accumulation.
`IsDataEqual()` now uses this function.

### 9. PBKDF2 Block Counter Encoding
**File:** `Common/Pkcs5.c` (4 locations: SHA-512, SHA-1, RIPEMD-160, Whirlpool)
**Problem:** The PBKDF2 block counter was written as a single byte (`counter[3] = b`),
which is incorrect per RFC 2898 (must be 4-byte big-endian). For derived keys longer
than one hash output block, this would produce incorrect key material.
**Fix:** Proper 4-byte big-endian encoding of the block counter.


## Wave 2 — Structural Improvements

### 10. Memory Locking (`mlock`)
**File:** `Platform/Buffer.cpp`
**Problem:** `SecureBuffer` contents (encryption keys, passwords) could be swapped to
disk by the OS, where they persist unencrypted.
**Fix:** `SecureBuffer::Allocate()` now calls `mlock()` to pin pages in RAM.
`SecureBuffer::Free()` calls `munlock()` after `Erase()`.

### 11. XTS Key Equality Check
**Files:** `Volume/EncryptionModeXTS.cpp`, `Volume/EncryptionModeXTS.h`
**Problem:** XTS mode (IEEE 1619 / NIST SP 800-38E) requires that the primary
encryption key and the secondary (tweak) key are not identical. TrueCrypt did not
verify this.
**Fix:** `SetKey()` now calls `ValidateXtsKeys()` which compares each cipher's primary
key against its corresponding secondary key using constant-time comparison. Throws
`ParameterIncorrect` if keys are equal.

### 12. Password Cache Removed Entirely
**Files removed:** `Volume/VolumePasswordCache.h`, `Volume/VolumePasswordCache.cpp`
**Files changed:** `Core/CoreBase.h`, `Core/Unix/CoreUnix.h`, `Core/Unix/CoreUnix.cpp`,
`Core/Unix/CoreServiceProxy.h`, `Core/MountOptions.h`, `Core/MountOptions.cpp`,
`Volume/Volume.make`
**Problem:** The original TrueCrypt password cache stored plaintext passwords in the
heap after successful mounts, keeping sensitive key material in memory longer than
necessary. Even with the timeout mechanism added in an earlier hardening pass, cached
passwords represent unnecessary attack surface — a memory dump at any point during
the timeout window reveals all recently-used passwords.
**Fix:** The password cache has been completely removed from all layers:
- `VolumePasswordCache` class deleted (header + implementation)
- `CachePassword` field removed from `MountOptions` (serialization, clone, init)
- Cache lookup branch removed from `CoreServiceProxy::MountVolume()`
- `IsPasswordCacheEmpty()` and `WipePasswordCache()` removed from `CoreBase` interface
- All UI layers (SwiftUI bridge, CLI) cleaned of cache references
Users must enter their password for each mount operation. This is the most secure
approach and eliminates an entire class of password exposure risk.

### 13. PBKDF2 Iteration Increase (250–500x)
**Files:** `Volume/Pkcs5Kdf.h`, `Volume/Pkcs5Kdf.cpp`
**Problem:** Original iteration counts (1000–2000) were chosen in 2004 and offer
negligible brute-force resistance on modern hardware.
**Fix:** New volumes use hardened iteration counts matching VeraCrypt levels:

| Hash Algorithm | TrueCrypt 7.1a | This Port  | Factor |
|----------------|---------------|------------|--------|
| SHA-512        | 1,000         | 500,000    | 500x   |
| Whirlpool      | 1,000         | 500,000    | 500x   |
| RIPEMD-160     | 2,000         | 655,331    | 328x   |
| SHA-1          | 2,000         | 500,000    | 250x   |

**Backward compatibility:** Legacy KDF classes with original iteration counts are
preserved and tried first when opening volumes. This ensures existing TrueCrypt 7.1a
volumes open without delay. New volumes are always created with high iterations.
`GetAlgorithm()` (used for volume creation) returns only modern KDFs.


## Compatibility

- **Existing TrueCrypt 7.1a volumes:** Fully supported. Legacy KDFs are tried first
  during volume open, so there is no performance penalty.
- **New volumes created by this port:** Use high iteration counts. They cannot be
  opened by the original TrueCrypt 7.1a (which lacks the modern KDFs) but could be
  opened by any implementation that supports the same iteration counts.
- **VeraCrypt volumes:** Not directly compatible (different header format and magic
  bytes), but the iteration counts are equivalent.


## Wave 3 — Performance & Entropy Hardening

### 14. ARMv8 Hardware AES Acceleration
**File:** `Crypto/Aes_hw_cpu_arm.c`
**Problem:** The software AES implementation uses T-tables (lookup tables) that are
vulnerable to cache-timing side-channel attacks. Additionally, software AES is ~10x
slower than hardware AES on Apple Silicon.
**Fix:** New drop-in replacement using ARMv8 Cryptographic Extensions (NEON intrinsics:
`vaeseq_u8`, `vaesdq_u8`, `vaesmcq_u8`, `vaesimcq_u8`). Provides constant-time AES
operations immune to cache-timing attacks. Automatically detected via `__ARM_FEATURE_CRYPTO`
at compile time. Works with `NOASM=1` as these are C intrinsics, not assembly.
Provides `aes_hw_cpu_encrypt/decrypt` and `_32_blocks` variants matching the x86 AES-NI
interface for seamless integration.

### 15. macOS Native Entropy Source (`getentropy`)
**File:** `Core/RandomNumberGenerator.cpp`
**Problem:** Entropy was gathered exclusively from `/dev/urandom` via file descriptor
I/O — functional but suboptimal. The additional `/dev/random` non-blocking read on
macOS is pointless (both are identical on modern macOS, backed by Fortuna CSPRNG).
**Fix:** On macOS, the primary entropy source is now `getentropy()` (available since
macOS 10.12). This is a direct system call to the kernel CSPRNG, requires no file
descriptors, and cannot be intercepted by filesystem-level attacks.
Falls back to `/dev/urandom` if `getentropy()` fails (should never happen on macOS 10.12+).
The redundant `/dev/random` non-blocking read is removed on macOS.


## Wave 4 — Header Migration Tool

### 16. Automatic Legacy KDF Upgrade Prompt
**Files:** Originally `Main/GraphicUserInterface.cpp`, `Main/TextUserInterface.cpp` (now
removed with wxWidgets). The upgrade logic lives in `Core/CoreBase.cpp` (`ChangePassword`
with `wipePassCount` parameter). Each UI layer (CLI, SwiftUI) can implement its own
upgrade prompt using the `VolumeOperationCallback` interface.
**Problem:** Existing TrueCrypt volumes use low PBKDF2 iterations (1000-2000) that offer
minimal brute-force resistance. Users must manually re-encrypt headers to benefit from
the improved iteration counts.
**Fix:** After mounting a volume with legacy iterations (< 10,000), the UI layer offers to
upgrade the volume header to modern iterations. The dialog shows the exact current and
target iteration counts.

The upgrade preserves the user's password, keyfiles, and hash algorithm choice. Only the
iteration count changes. The file hash will change (header bytes are different), but the
on-disk encryption format and data content are unchanged.

### 17. Single-Pass Wipe for KDF Upgrades
**Files:** `Core/CoreBase.h`, `Core/CoreBase.cpp`
**Problem:** `ChangePassword()` performs `PRAND_DISK_WIPE_PASSES` (256 in release builds)
wipe passes per header, re-deriving the key each time. This is a security feature designed
to make the old key material forensically unrecoverable when changing passwords. However,
a KDF upgrade keeps the same master key — 256 wipe passes with expensive PBKDF2 iterations
(500,000+) would take 4+ minutes and freeze the GUI.
**Fix:** Added an optional `wipePassCount` parameter to `ChangePassword()`. The KDF upgrade
calls with `wipePassCount=1` since the master key is unchanged and there is no old key
material to securely erase. The normal "Change Password" dialog continues to use the full
256 wipe passes.


## Wave 5 — Password Memory Hardening (Historical)

### 18. Secure Password Input Buffer (`SecurePasswordInput`) [SUPERSEDED]
**Status:** This mitigation was part of the wxWidgets-based GUI and has been superseded
by the complete removal of wxWidgets in Wave 6. The SwiftUI-based UI uses
`NSSecureTextField` (via SwiftUI `SecureField`) which is managed by the system's Cocoa
layer, and the ObjC++ bridge handles password data through `mlock()`-pinned buffers in
the `TCCocoaCallback` class.

**Original problem (now eliminated):** wxWidgets `wxTextCtrl` stored passwords as
`wxString` in the regular heap with copy-on-write semantics, undo buffers, and
platform string conversions creating uncontrollable copies.


## Wave 6 — wxWidgets Removal & Native UI

### 19. Complete wxWidgets Removal
**Files removed:** Entire `Main/` directory (86 files), all wx build infrastructure
**Problem:** wxWidgets was a significant attack surface and source of security concerns:
- Password handling through `wxString` with uncontrollable heap copies (Wave 5 mitigation)
- Destruction-order bugs causing memory corruption (`DestroyChildren()` before C++ dtors)
- Signal handler deadlocks (`wxMessageBox` from signal context → `NSAlert runModal()` hang)
- Large, complex dependency (~2 MB of third-party code) with its own vulnerability history
- No access to modern macOS security APIs (Secure Enclave, Keychain integration, etc.)

**Fix:** wxWidgets completely removed. Replaced with:
1. **`libTrueCryptCore.a`** — UI-independent static library containing all crypto, volume,
   and platform logic. Zero wxWidgets symbols.
2. **`VolumeOperationCallback`** — Abstract C++ interface for user interaction, implemented
   separately by each UI layer.
3. **Standalone CLI (`truecrypt-cli`)** — getopt_long + POSIX terminal I/O (termios).
   Password input uses `tcsetattr()` to disable echo. No toolkit dependency.
4. **SwiftUI macOS app (`Basalt.app`)** — Native macOS UI via ObjC++ bridge
   (`TCCoreBridge.mm`). Passwords handled through `NSSecureTextField` (system-managed).

### 20. ObjC++ Bridge Security Design
**Files:** `Basalt/Bridge/TCCoreBridge.mm`, `Basalt/Bridge/TCCocoaCallback.mm`
**Design principles:**
- C++ exceptions are caught at the bridge boundary and converted to `NSError`. No C++
  exceptions propagate into Swift/ObjC runtime.
- Password strings from `NSSecureTextField` are immediately converted to `VolumePassword`
  (which uses `mlock()`-pinned `SecureBuffer`) and the `NSString` intermediate is
  short-lived and managed by ARC.
- All UI callbacks dispatch to the main thread via `dispatch_sync(dispatch_get_main_queue())`
  — no cross-thread UI manipulation.
- `arc4random_buf()` used for entropy in the CocoaCallback (system CSPRNG, no file I/O).

### 21. CLI Password Security
**Files:** `CLI/CLICallback.h`, `CLI/CLICallback.cpp`
**Design:** Password input uses POSIX `termios` to disable terminal echo (`ECHO` flag).
Echo is restored in all code paths (including exceptions) via RAII-style cleanup.
Passwords are read directly into `VolumePassword` objects backed by `mlock()`-pinned
`SecureBuffer`. No intermediate `wxString` or heap-allocated string copies.


## Wave 7 — Runtime Protection & Auto-Dismount

### 22. Inactivity-Based Auto-Dismount
**Files:** `Basalt/App/VolumeManager.swift`, `Basalt/App/PreferencesManager.swift`
**Problem:** Mounted volumes remain accessible indefinitely, even when the user has
stopped working. An unattended machine with mounted encrypted volumes defeats the
purpose of encryption.
**Fix:** Per-volume I/O activity tracking using the existing `TotalDataRead` and
`TotalDataWritten` counters from the FUSE driver. Every 2 seconds, the refresh timer
compares current I/O totals with previously recorded values. If a volume has had no
read or write activity for the configured timeout (5/10/30/60/120 minutes), it is
automatically dismounted. Each volume is tracked independently — only idle volumes
are affected.

### 23. Event-Based Auto-Dismount
**Files:** `Basalt/App/TrueCryptApp.swift` (AppDelegate)
**Problem:** Volumes remain mounted during security-sensitive system transitions
(screen lock, sleep, application exit, logout) where the user is not actively present.
**Fix:** Four automatic dismount triggers:
- **Screen saver:** `DistributedNotificationCenter` observes `com.apple.screensaver.didstart`
- **System sleep:** `NSWorkspace.willSleepNotification`
- **Logout/shutdown/restart:** `NSWorkspace.willPowerOffNotification` (default: on)
- **Application quit:** `applicationShouldTerminate` with `.terminateLater` for async
  dismount before exit
Each trigger is independently configurable. Force dismount is enabled by default and
applies to all dismount operations (manual and automatic), ensuring volumes can always
be closed even when processes hold open file handles.

### 25. Force Dismount as Default
**Files:** `Basalt/App/PreferencesManager.swift`, `Basalt/App/MainWindow.swift`
**Problem:** Non-forced dismount fails when any process holds an open file handle to
the mounted volume. This creates a security issue: the user intends to close the volume
but cannot because of a background process (Spotlight indexing, antivirus scan, shell
`cd` into the mount point, etc.). The volume remains accessible against the user's intent.
**Fix:** `forceDismount` defaults to `true`. All dismount operations — toolbar buttons,
context menu, keyboard shortcut (Cmd+Shift+D), and all auto-dismount triggers — respect
this preference. The setting can be disabled in Preferences for users who prefer to be
notified about open files. The previous separate "Dismount (Force)" context menu item
has been removed in favor of the unified preference.

### 24. CLI KDF Upgrade Prompt
**Files:** `CLI/main.cpp`
**Problem:** The KDF upgrade dialog (Wave 4, #16) was only available in the SwiftUI GUI.
CLI users mounting legacy volumes had no way to upgrade their volume headers to modern
iteration counts.
**Fix:** After a successful mount in interactive mode, `VolumeOperations::UpgradeKdf()`
is called, which checks if the mounted volume uses legacy iterations (< 10,000) and
prompts the user to upgrade. Skipped in `--non-interactive` mode to allow scripted usage.


---

## Wave 8: Hardening (CVE Mitigations + Anti-Screen-Capture)

### 26. FAST_ERASE64 Replaced with memset_s()
**Files:** `Common/Tcdefs.h`
**Problem:** The `FAST_ERASE64` macro used `volatile uint64*` pointer writes to wipe
XTS whitening values and LRW key material. The C/C++ standards do not guarantee that
`volatile` stores to stack-allocated memory survive optimization when the buffer is about
to go out of scope. This affected all XTS encrypt/decrypt paths (EncryptionModeXTS.cpp,
Xts.c, Crypto.c) — a total of 16 wipe sites handling key-derived whitening material.
**Fix:** `FAST_ERASE64` macro now delegates to `burn()`, which uses `memset_s()` (C11
Annex K). This is the only standards-compliant guarantee against compiler optimization
of wipe operations.

### 27. Mount Point Validation (CVE-2025-23021)
**Files:** `Core/Unix/CoreUnix.cpp`
**Problem:** VeraCrypt 1.26.18 fixed CVE-2025-23021: volumes could be mounted on system
directories (`/usr/bin`, `/etc`, `/System`, etc.), enabling arbitrary code execution by
replacing system binaries with volume contents.
**Fix:** `MountVolume()` now validates the mount point against a list of protected system
paths before proceeding. Mounting on `/`, `/usr`, `/bin`, `/sbin`, `/etc`, `/var`,
`/System`, `/Library`, `/Applications`, `/dev`, `/private`, and `/opt` is rejected.

### 28. Absolute Paths for System Binaries (CVE-2024-54187)
**Files:** `Core/Unix/CoreUnix.cpp`, `Core/Unix/MacOSX/CoreMacOSX.cpp`
**Problem:** VeraCrypt 1.26.15 fixed CVE-2024-54187: `Process::Execute()` was called with
bare binary names (`mount`, `umount`, `hdiutil`), allowing PATH hijacking. An attacker
placing a malicious binary earlier in PATH could execute arbitrary code with elevated
privileges.
**Fix:** All `Process::Execute()` calls on macOS now use absolute paths:
`/sbin/mount`, `/sbin/umount`, `/usr/bin/hdiutil`, `/usr/bin/open`. The FUSE exec functor
is unaffected as it calls `fuse_main()` directly, not via PATH lookup.

### 29. Screen Capture Protection
**Files:** `Basalt/App/MainWindow.swift`, `Basalt/App/MountSheet.swift`,
`Basalt/App/ChangePasswordSheet.swift`, `Basalt/Bridge/TCCocoaCallback.mm`,
`Basalt/Bridge/TCCoreBridge.mm`
**Problem:** Screen recording malware can capture password entry and volume metadata
(container paths, mount points). macOS provides `NSWindow.sharingType = .none` to prevent
screenshots, screen recording, and AirPlay mirroring of specific windows.
**Fix:** The **entire application window** (main window + all sheets) sets `sharingType = .none`
on its hosting NSWindow. This prevents screenshots from capturing any TrueCrypt content —
volume paths, mount points, encryption details, and password entry are all invisible to screen
capture, screen sharing, and AirPlay mirroring. NSAlert password dialogs also set this
property directly. Implemented via `NSViewRepresentable` helper with `screenCaptureProtection()`
SwiftUI modifier.


### 30. FUSE Mount Options Hardening (nosuid, nodev)
**Files:** `Driver/Fuse/FuseService.cpp`
**Problem:** Without explicit restrictions, a mounted TrueCrypt volume could contain
setuid/setgid binaries or device nodes. An attacker who can place files on a volume
(e.g., a shared volume, a volume from an untrusted source) could use setuid binaries
for privilege escalation or device nodes for unauthorized hardware access.
**Fix:** All FUSE mounts now include `nosuid,nodev` options. `nosuid` prevents execution
of setuid/setgid programs from the volume, `nodev` prevents creation or use of device
special files. These are standard mount hardening flags used by default in most Linux
distributions for removable media.


## Wave 9: Volume Creation & UX Hardening

### 31. Volume Creation: FilesystemClusterSize Initialization
**Files:** `Basalt/Bridge/TCCoreBridge.mm`
**Problem:** The `VolumeCreationOptions` C++ struct has no constructor. The bridge allocated
it with `make_shared<VolumeCreationOptions>()` without initializing `FilesystemClusterSize`,
leaving it as garbage memory. The FAT formatter used this garbage value as cluster size
instead of auto-detecting the optimal size, producing a corrupt FAT filesystem that
`hdiutil attach` could not read — making newly created FAT volumes unmountable.
**Fix:** Explicitly set `cppOpts->FilesystemClusterSize = 0` (0 = auto-detect).

### 32. Volume Creation: HFS+ Filesystem Formatting
**Files:** `Basalt/Bridge/TCCoreBridge.mm`, `Basalt/App/VolumeManager.swift`
**Problem:** The VolumeCreator C++ class only formats FAT filesystems internally. HFS+
(Mac OS Extended) requires an external formatter (`newfs_hfs`), which the deleted wxWidgets
UI layer previously handled. Without it, HFS+ volumes were created with encrypted
random data but no filesystem, causing mount failures.
**Fix:** New `formatVolumeFilesystem:` bridge method. After volume creation completes,
the volume is temporarily mounted with `NoFilesystem=true` (FUSE + `hdiutil attach -nomount`),
`/sbin/newfs_hfs -v TrueCrypt` is run on the virtual block device (`/dev/diskN`), and the
volume is dismounted. The VolumeManager orchestrates this automatically for HFS+ volumes.

### 33. Legacy KDF Iteration Option for 7.1a Compatibility
**Files:** `Basalt/Bridge/TCCoreBridge.h`, `Basalt/Bridge/TCCoreBridge.mm`,
`Basalt/App/CreateVolumeSheet.swift`
**Problem:** Volumes created with modern iteration counts (500,000+) cannot be opened by
TrueCrypt 7.1a. Users who need cross-version compatibility had no option to create
legacy-compatible volumes.
**Fix:** Added `legacyIterations` property to `TCVolumeCreationOptions` and a toggle in the
Create Volume wizard: "TrueCrypt 7.1a compatible (legacy iterations)". When enabled, the
bridge passes `allowLegacy=true` to `Pkcs5Kdf::GetAlgorithm()`, selecting the original
iteration counts (1000/2000). A warning is displayed explaining the weaker key derivation.

### 34. Tab Navigation: Password Field Focus Order
**Files:** `Basalt/App/PasswordView.swift`
**Problem:** The show/hide password toggle button (eye icon) was focusable, intercepting
Tab key navigation between password fields. In the Create Volume wizard, pressing Tab after
the first password field focused the eye icon instead of the confirmation field.
**Fix:** Added `.focusable(false)` to the toggle button, removing it from the Tab order.
This applies to all password fields across the application (Mount, Change Password, Create).


## What This Port Does Change: Zero-State Design

This application remembers nothing. No favorites, no cached passwords, no default
keyfiles, no mount history, no recently-used lists. Every operation starts clean.

- **No password cache:** The original TrueCrypt cached volume passwords in memory
  (`VolumePasswordCache`). This port removed the feature entirely (Wave 7).
- **No favorites or history:** Volume paths are never persisted to disk. There is no
  record of which containers exist, when they were last mounted, or how often they are
  used. Forensic analysis of the application reveals nothing about your volumes.
- **No default keyfile paths:** Keyfile selection is always explicit, per-operation.
- **No window state persistence:** Window positions, last-used directories, and dialog
  states are not saved.
- **Screen capture protection:** The entire application window is invisible to screenshots,
  screen recording, and screen sharing (`NSWindow.sharingType = .none`).

The existence of your containers is your business, not your application's.


## Volume Format Compatibility

Basalt uses its own header magic (`BSLT`) for newly created volumes but can open volumes
from all three ecosystems:

| Magic Bytes | Format     | Read (Mount) | Write (Create) |
|-------------|------------|:------------:|:--------------:|
| `BSLT`      | Basalt     | ✓            | ✓              |
| `TRUE`      | TrueCrypt  | ✓            | —              |
| `VERA`      | VeraCrypt  | ✓            | —              |

**The magic bytes are encrypted** — they reside inside the volume header, which is
itself encrypted with the user's password via PBKDF2. This means:

- **No forensic fingerprint:** A Basalt volume is indistinguishable from random data on
  disk. No tool can determine whether a file is a Basalt, TrueCrypt, or VeraCrypt volume
  without the correct password.
- **No shortcut for iteration detection:** The magic bytes are only visible after
  successful decryption. The application must still try all KDF/cipher combinations during
  mount — the magic bytes merely confirm that decryption succeeded.
- **Hidden volumes unaffected:** Outer and inner headers are encrypted independently.
  The magic bytes of one cannot reveal the existence of the other.

**VeraCrypt limitation:** Only VeraCrypt volumes using AES, Serpent, or Twofish (and
their cascades) can be mounted. Volumes using Camellia or Kuznyechik are not supported
(see "Cipher Selection" above for the rationale).

**Backward compatibility:** Basalt volumes (`BSLT`) cannot be opened by TrueCrypt 7.1a
or VeraCrypt, as they do not recognize the `BSLT` magic. Use the "TrueCrypt 7.1a
compatible" option during volume creation if cross-application compatibility is required
(this uses legacy iteration counts but still writes the `BSLT` header).


## What This Port Does NOT Change

- **Encryption algorithms:** AES, Serpent, Twofish and their cascades remain unchanged.
- **XTS mode implementation:** Only the key validation was added; the XTS math is
  unchanged.
- **Volume header layout:** Binary structure (offsets, sizes, backup header position) is
  identical to TrueCrypt 7.1a / VeraCrypt. Only the 4-byte magic identifier differs.
- **On-disk format:** Volumes are byte-compatible at the encryption layer. Data area
  layout, sector sizes, and XTS tweak computation are unchanged.
- **FUSE driver:** Volume mounting still uses macFUSE. The FUSE driver logic is unchanged
  (only mount options were hardened with nosuid/nodev).


## Known Remaining Weaknesses

These are known issues that may be addressed in future work:

1. **No authenticated encryption:** XTS does not detect tampering. AES-GCM or similar
   would require a format change.
2. **NSSecureTextField internal buffers:** The SwiftUI `SecureField` (backed by
   `NSSecureTextField`) is managed by Cocoa. While the system provides better password
   handling than wxWidgets, Apple's internal buffer management is opaque and may briefly
   retain password data. The bridge minimizes exposure by immediately converting to
   `mlock()`-pinned `SecureBuffer`.
3. **Legacy hash algorithms:** SHA-1 and RIPEMD-160 are maintained for compatibility
   but are not recommended for new volumes. SHA-512 is the recommended default.
4. **Serpent/Twofish remain software-only:** No hardware acceleration for these ciphers
   on ARM (no hardware support exists).
5. **Code signing:** The app bundle is not currently signed or notarized. macOS
   Gatekeeper will require the user to manually allow execution.


## Cipher Selection: Why Not Camellia or Kuznyechik?

VeraCrypt added Camellia and Kuznyechik (GOST R 34.12-2015) as additional cipher options.
This port deliberately does not include them:

**Kuznyechik (Russian GOST standard):**
- Designed by the FSB (Russian Federal Security Service, successor to the KGB).
- In 2019, researchers Léo Perrin and Aleksei Udovenko demonstrated that the S-box was
  **not randomly generated** as claimed in the specification. It contains a hidden algebraic
  structure (a decomposition into two simpler permutations composed with a linear map).
  This is the same type of "nothing up my sleeve" violation that made Dual_EC_DRBG
  (NSA-backed RNG) a scandal.
- The design rationale for the S-box has never been publicly explained.
- Adding a cipher with unexplained structural anomalies designed by a signals intelligence
  agency would undermine the trust model of the entire application.

**Camellia (NTT/Mitsubishi):**
- A well-regarded cipher with no known weaknesses and solid academic analysis.
- However, it provides no security advantage over AES: same block size (128-bit), same key
  lengths, comparable security margin.
- No hardware acceleration on Apple Silicon — performance would be 5-10x slower than AES
  with ARMv8 Cryptographic Extensions.
- More cipher options means more code, more testing surface, and more potential for
  implementation errors, without any corresponding security benefit.

**Our cipher suite (AES + Serpent + Twofish):**
- All three are AES competition finalists with 25+ years of public cryptanalysis.
- AES: Hardware-accelerated on both ARM and x86, constant-time via dedicated instructions.
- Serpent: Most conservative design in the AES competition (32 rounds; best known attack
  reaches 12 rounds). Highest security margin of any practical block cipher.
- Twofish: Unbroken, with a deliberately different internal structure from AES and Serpent,
  making cascade combinations (AES-Twofish-Serpent) robust against algorithm-specific breaks.
- Cascaded modes provide defense-in-depth without introducing questionable ciphers.


## Why Not PIM (Personal Iterations Multiplier)?

VeraCrypt allows users to specify a custom PIM value that controls the PBKDF2 iteration
count. This port deliberately does not implement PIM:

**PIM is security by obscurity:**
- PIM adds a second secret parameter to the mount process, but one with far less entropy
  than the password itself. Typical PIM values range from 1 to 999, providing at most ~10
  bits of entropy. An attacker simply iterates all PIM values, multiplying the brute-force
  cost by only ~1,000x — the same improvement gained by adding 2–3 characters to the
  password.
- Users may perceive PIM as a second factor, but it is merely a weak multiplier on
  existing key derivation. True second factors (keyfiles, hardware tokens) provide
  independent entropy sources.

**PIM can actively reduce security:**
- VeraCrypt allows low PIM values. With SHA-512, PIM=1 results in only ~2,048 PBKDF2
  iterations — **245x weaker** than this port's fixed 500,000 iterations. Users who set
  low PIM values for "faster mount times" dramatically undermine their volume's
  brute-force resistance.
- This creates a dangerous asymmetry: the feature is marketed as a security enhancement
  but its most common use case (performance optimization) reduces security.

**Our approach — fixed high iterations — is strictly better:**
- 655,331 iterations (RIPEMD-160) / 500,000 (SHA-512, Whirlpool, SHA-1) cannot be
  weakened by user misconfiguration.
- Users who want stronger protection should use longer passwords and/or keyfiles, which
  add real entropy rather than obscurity.
- The iteration counts match VeraCrypt's defaults (PIM=0), so there is no performance
  or security disadvantage compared to a correctly-configured VeraCrypt volume.


## Comparison with VeraCrypt

This port addresses the same vulnerability classes as VeraCrypt but takes a more
security-conservative approach in several areas:

**Areas where this port is stricter than VeraCrypt:**
- **Password cache completely removed.** VeraCrypt still maintains an in-memory password
  cache that stores plaintext passwords after mount. This port eliminates the feature entirely.
- **No questionable ciphers.** VeraCrypt includes Kuznyechik despite the 2019 S-box
  structure concerns. This port uses only AES competition finalists.
- **Force dismount by default.** Ensures volumes can always be closed, even when background
  processes hold file handles. VeraCrypt defaults to non-forced dismount.
- **Smaller codebase.** wxWidgets removal eliminates ~86 files and a large third-party
  dependency with its own vulnerability history.

**Areas where VeraCrypt has capabilities this port does not:**
- **PIM (Personal Iterations Multiplier):** User-tunable PBKDF2 iteration count.
  Deliberately not implemented — PIM is security by obscurity that can reduce security
  when misconfigured (see "Why Not PIM?" above). Fixed high iteration counts are safer.
- **Full disk encryption (Windows):** VeraCrypt's primary use case. Not applicable to
  this macOS-only port.
- **Cross-platform support:** Windows, Linux, macOS, FreeBSD. This port targets macOS only.

**VeraCrypt bootloader trust chain concern:**
VeraCrypt's UEFI bootloader (DcsBoot.efi, DcsInt.efi) is sourced from the separate
VeraCrypt-DCS project, which has received minimal updates since 2022. These bootloader
binaries are signed by Microsoft Corporation UEFI CA 2011 — a third-party certificate
that places Microsoft in the trust chain for full disk encryption. The DCS source code
uses an outdated EDK2 fork, and reproducible builds of the shipped binaries have not
been demonstrated. For full disk encryption, the bootloader IS the security boundary,
making this a significant trust concern.

This port does not provide boot encryption and therefore has no bootloader trust chain
dependency. All components are built from source with no pre-compiled binary blobs.


## Audit Methodology

The security audit was performed using LLM-assisted analysis of the complete TrueCrypt
7.1a source code, covering:
- Random number generation (pool mixing, entropy sources, self-tests)
- Key derivation (PBKDF2 implementation, iteration counts, RFC compliance)
- Encryption (AES/Serpent/Twofish implementations, mode of operation)
- Volume header format and key management
- Memory security (erasure, locking, lifetime)
- Suspicious patterns and potential backdoors

Additionally, all 2,687 commits of the VeraCrypt fork were analyzed to identify
security-relevant changes, fixes, and potential concerns. This informed the selection
and prioritization of hardening measures.
