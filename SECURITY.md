# Security Hardening: Basalt (TrueCrypt 7.1a macOS Port)

This document describes all security-relevant changes made to the TrueCrypt 7.1a
codebase as part of the macOS 12+ universal (arm64 + x86_64) port. The goal is to fix known
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

### 6. RNG Self-Test Order [CORRECTED in Wave 10]
**File:** `Core/RandomNumberGenerator.cpp`
**Original change:** `Start()` was reordered to seed the pool first and run the
self-test afterwards.
**Correction (Wave 10, #39):** `Test()` zeroes the pool and fills it with
deterministic data, so running it after seeding discarded the initial entropy. The
original TrueCrypt order (self-test, then seed) has been restored. Output quality
was not affected in practice because every `GetData()` call mixes in fresh kernel
entropy (`getentropy()`) before and after extraction.

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
3. **Standalone CLI (`basalt-cli`)** — getopt_long + POSIX terminal I/O (termios).
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
  short-lived and managed by ARC. Since Wave 11 (#46) the conversion goes through a
  wiped stack buffer only.
- All UI callbacks dispatch to the main thread via `dispatch_sync(dispatch_get_main_queue())`
  — no cross-thread UI manipulation.
- `arc4random_buf()` used for entropy in the CocoaCallback (system CSPRNG, no file I/O).

### 21. CLI Password Security
**Files:** `CLI/CLICallback.h`, `CLI/CLICallback.cpp`
**Design:** Password input uses POSIX `termios` to disable terminal echo (`ECHO` flag).
Echo is restored in all code paths (including exceptions) via RAII-style cleanup.
Passwords are read directly into `VolumePassword` objects backed by `mlock()`-pinned
`SecureBuffer`. No intermediate `wxString` or heap-allocated string copies.
For scripts, see `--password-stdin` (Wave 11, #45).


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
**Files:** `Basalt/App/BasaltApp.swift` (AppDelegate)
**Problem:** Volumes remain mounted during security-sensitive system transitions
(screen lock, sleep, application exit, logout) where the user is not actively present.
**Fix:** Four automatic dismount triggers:
- **Screen saver / screen lock:** `DistributedNotificationCenter` observes
  `com.apple.screensaver.didstart` and (since Wave 10) `com.apple.screenIsLocked`
- **System sleep:** IOKit system power notifications; sleep waits for the dismount
  (since Wave 11, #48 — previously `NSWorkspace.willSleepNotification`, which does not wait)
- **Logout/shutdown/restart:** `NSWorkspace.willPowerOffNotification` (default: on)
- **Application quit:** `applicationShouldTerminate` dismounts before it answers (since
  Wave 11, #48 — previously `.terminateLater`, which let the app quit before the
  dismount had finished). On by default since Wave 11.
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
**Completed in Wave 10 (#40):** DarwinFUSE still ran `mount_nfs` and the privilege
elevation still ran `sudo` through `$PATH`; both now use `/sbin/mount_nfs` and
`/usr/bin/sudo`.

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
**Files:** `src/Fuse/FuseService.cpp`
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


## Wave 10 — Independent Audit (October 2026)

A source review of Basalt 1.1.1 and its embedded DarwinFUSE, with the portable
core compiled and exercised on Linux (self-tests, cross-checks against reference
implementations, regression tests). Details: [docs/AUDIT-2026-10.md](docs/AUDIT-2026-10.md).

### 35. Argon2id Now Conforms to RFC 9106 (Existing Volumes Stay Openable)
**Files:** `Crypto/Argon2/core.c`, `Crypto/Argon2/ref.c`, `Crypto/Argon2/argon2.c`,
`Common/Argon2Kdf.c`, `Volume/Pkcs5Kdf.*`, `Volume/EncryptionTest.cpp`
**Problem:** The compression function deviated from RFC 9106 in two places: the
v1.3 XOR into the previous block contents (`with_xor`) was ignored, and the
diagonal step of the row round fed the wrong words into G. The output matched no
other Argon2 implementation, and the self-test vectors had been generated with the
same code, so the deviation went unnoticed. The result is an unanalysed variant
with reduced diffusion and without the v1.3 tradeoff-attack mitigation.
**Fix:** `fill_block()` follows RFC 9106 and reproduces the official test vector
(RFC 9106 §5.3) and libargon2 outputs for the production parameters. The previous
function is frozen as `fill_block_basalt_legacy()` and only reachable through two
open-only KDFs ("Argon2id (legacy)", "Argon2id-Max (legacy)") that are tried after
their standard counterparts when opening a volume and are never used to write a
header. After mounting such a volume the existing upgrade prompt offers to
re-encrypt the header with standard Argon2id; changing the password also upgrades
it. Volumes created from now on cannot be opened by Basalt ≤ 1.1.x.

### 36. Local NFS Transport Instead of a Loopback TCP Port (DarwinFUSE)
**Files:** `DarwinFUSE/src/nfs4_server.c`, `DarwinFUSE/src/darwinfuse.c`
**Problem:** The NFS server that serves the decrypted volume image listened on
`127.0.0.1:<ephemeral port>` without authentication. AUTH_SYS credentials are
asserted by the client, so any local process — other user accounts, sandboxed apps
with network access — could read and write the decrypted volume, bypassing file
permissions, TCC and the FUSE access check (`CheckAccessRights()`).
**Fix:** The server listens on a Unix domain socket inside a private `mkdtemp()`
directory (0700) and additionally rejects peers whose UID is neither root nor the
owner (`LOCAL_PEERCRED`). `mount_nfs` connects via `proto=ticotsord,port=<socket>`,
supported by the macOS NFS client since 10.15, with `nocallback` (the NFSv4 client's
SETCLIENTID rejects a callback channel over a local socket with EINVAL; without
callbacks the kernel also opens no NFSv4 callback listener). Verified on macOS (Apple
Silicon, including a 5 GB copy); a failed local mount is now an error. The previous TCP
transport is only available in builds with `-DDFUSE_TCP_FALLBACK=1`, for diagnosis.

### 37. Overflow-Safe Sector Bounds (Hidden Volume Header Overwrite)
**Files:** `Volume/Volume.cpp`, `Fuse/FuseService.cpp`, `DarwinFUSE/src/nfs4_ops.c`
**Problem:** `WriteSectors()` checked `byteOffset + length > VolumeDataSize`, which
wraps for offsets near 2^64 (a negative `off_t` from an NFS request). Such a write
landed in front of the data area — on the hidden volume header — bypassing hidden
volume protection. `ReadSectors()` had no bounds check, and `fuse_service_read()`
underflowed for offsets beyond the end.
**Fix:** Overflow-free checks in both functions, negative offsets rejected in the
FUSE service, and NFS READ/WRITE offsets that do not fit `off_t` refused with
`NFS4ERR_INVAL`.

### 38. No Log Files, No /tmp Symlink Targets
**Files:** `DarwinFUSE/src/darwinfuse_internal.h`, `Fuse/FuseService.cpp`,
`Core/Unix/CoreUnix.cpp`
**Problem:** DarwinFUSE appended every operation (including mount points) to
`/tmp/darwinfuse.log` in release builds — contradicting the zero-state design and,
when elevated, a symlink target in a world-writable directory. The `.auxinfo` file
next to the aux mount point was created with `O_CREAT|O_TRUNC` (followable symlink
or hard link as root) and read without ownership check.
**Fix:** Informational logging is compiled out by default and errors go to stderr
only. `.auxinfo` is unlinked and recreated with `O_EXCL|O_NOFOLLOW`; it is only
read if it is a regular file owned by the current user or root.

### 39. RNG Start Order
See the correction under #6.

### 40. Absolute Paths for `mount_nfs` and `sudo`
See the completion note under #28. `sudo` from `$PATH` would have allowed a fake
binary in a user-writable directory to capture the administrator password.

### 41. Refuse Passwords That Would Be Truncated
**Files:** `Volume/VolumePassword.*`, `Core/VolumeCreator.cpp`, `Core/CoreBase.cpp`
**Problem:** Passwords are stored one byte per character (TrueCrypt format). Characters
above U+00FF (e.g. €, Cyrillic, Greek, CJK, emoji, decomposed accents) were silently
reduced to their low byte, losing entropy and creating collisions (€ = ¬). TrueCrypt's
GUI warned about this; the check was lost with the wxWidgets UI.
**Fix:** Creating a volume or setting a new password with such characters is refused
with an explanatory error. Existing volumes still open with the previous encoding.

### 42. AES-NI on Intel Macs
**Files:** `Crypto/Aes_hw_cpu_x86.c`, `Volume/Volume.make`, `Volume/Cipher.h`
**Problem:** Universal builds use `NOASM=1`, which also dropped the AES-NI assembly on
x86_64, so Intel Macs ran table-based software AES (slower, cache-timing exposure).
**Fix:** AES-NI via compiler intrinsics with run-time CPU detection, analogous to the
ARMv8 implementation (#14). Cross-checked against the software implementation;
about 7× faster XTS throughput on the test machine.

### 43. Build Script Symlink in Private Directory
**Files:** `Basalt/build.sh`, `build-universal.sh`
**Problem:** The build used the fixed path `/tmp/truecrypt-build`; another local user
could pre-create it so that the script builds (and later signs) a foreign tree.
**Fix:** The symlink lives in the per-user `$TMPDIR`.


## Wave 11 — Follow-ups to the Audit (October 2026)

Improvements suggested in the audit report (open items O-1, O-2, O-3, O-6) and
usability changes with a security angle.

### 44. Choosing the Key Derivation When Mounting
**Files:** `Volume/Pkcs5Kdf.*`, `Volume/Volume.*`, `Core/MountOptions.*`, `Core/CoreBase.*`,
`Core/Unix/CoreUnix.cpp`, `CLI/main.cpp`, `Basalt/App/MountSheet.swift`, `Basalt/App/PreferencesView.swift`
**Problem:** The KDF is not stored in the header (it cannot be, without revealing
information), so opening a volume tries every supported KDF in turn. With two Argon2id
profiles, their legacy variants and the PBKDF2 PRFs, a wrong password took over a
minute to report, and a correct one could wait for several KDFs that do not apply.
**Fix:** An optional KDF hint (`Argon2id-Max`, `Argon2id`, `PBKDF2`) restricts the attempts
to that family; the legacy (pre-RFC 9106) Argon2id variants are included in the Argon2id
choices. The GUI offers it under Options in the mount sheet and as a default in
Settings; the CLI accepts `--kdf=auto|argon2id-max|argon2id|pbkdf2`. A wrong password
is reported after one KDF family instead of all of them (11.5 s instead of 79 s in a
test on Linux), and the error says that only the selected KDF was tried. The hint is never
written to the volume; the default is stored like the other mount defaults. Protected
hidden volume headers are always tried with all KDFs.

### 45. Passwords via Standard Input (CLI)
**Files:** `CLI/main.cpp`
**Problem:** `--password=` is visible in the process list to all local users and ends up
in shell history (audit O-1).
**Fix:** `--password-stdin` reads the password from the first line of standard input
(mutually exclusive with `--password`). Passwords given on the command line now print a
warning, and the help text recommends the prompt or stdin.

### 46. Fewer Password Copies in the Bridge
**Files:** `Basalt/Bridge/TCCocoaCallback.*`, `Basalt/Bridge/TCCoreBridge.mm`, `Basalt/App/VolumeManager.swift`
**Problem:** Every password passed through an `NSData` (UTF-32) and a `std::wstring`
before reaching `VolumePassword`; neither was wiped (audit O-2).
**Fix:** `PasswordFromNS()` copies the characters with `-getBytes:` into a fixed stack
buffer that is `burn()`ed after the `VolumePassword` has been filled. All ten call sites
use it. Mount options drop their password strings once converted. Swift `String`
storage itself remains out of reach (see Known Remaining Weaknesses).

### 47. Password Strength Meter and Diceware Generator
**Files:** `Basalt/App/PasswordTools.swift`, `Basalt/App/PasswordStrengthView.swift`,
`Basalt/Resources/eff_large_wordlist.txt`
**Problem:** Argon2id makes each guess expensive, but cannot rescue a weak password;
the app gave no feedback beyond a minimum length.
**Fix:** New-password fields show a conservative entropy estimate (common passwords,
dictionary words, leetspeak, repetitions and sequences are discounted). A generator
creates 5–7 word passphrases from the EFF large wordlist (12.9 bits per word) using the
system CSPRNG (`SystemRandomNumberGenerator`), limited to the 64-byte password maximum.
Characters beyond Latin-1 (#41) are flagged in the dialog before the volume is created.

### 48. Sleep and Quit Wait for Auto-Dismount
**Files:** `Basalt/App/BasaltApp.swift`, `Basalt/App/VolumeManager.swift`,
`Basalt/App/PreferencesManager.swift`
**Problem:** "Dismount when system sleeps" reacted to `NSWorkspace.willSleepNotification`
and started an asynchronous dismount; the Mac could go to sleep with volumes still
mounted and keys in RAM (audit O-3). "Dismount when Basalt quits" started an
asynchronous dismount and let the app quit right away, so the volumes stayed mounted
— with no Basalt window or menu bar icon left to dismount them. The option was off
by default.
**Fix:** The app registers for IOKit system power notifications and acknowledges
`kIOMessageSystemWillSleep` with `IOAllowPowerChange` only after the dismount has
finished (the system waits up to about 30 s). On quit, logout, restart and shutdown,
`applicationShouldTerminate` dismounts before it answers: the dismount runs on a
background queue while the main run loop keeps servicing the main queue (so an
administrator password prompt still works), with a 60 s limit. If a volume cannot
be dismounted on quit, Basalt asks before quitting; logout and shutdown are never
held up. A `willTerminate` observer covers terminations that bypass the delegate.
Dismounting on quit is now on by default.

### 49. Spotlight Marker Only Where Harmless
**Files:** `Basalt/App/VolumeManager.swift`
**Problem:** `.metadata_never_index` was written on every mount, modifying the outer
volume even when mounted read-only or with hidden volume protection (audit O-6).
**Fix:** The marker is created once, and never on read-only mounts or on outer volumes
mounted with hidden volume protection.

### 50. Header Backup Reminder
**Files:** `Basalt/App/CreateVolumeSheet.swift`, `Basalt/App/MainWindow.swift`
**Problem:** A damaged header makes a volume unrecoverable; the embedded backup header
does not help if the whole container file is lost or overwritten.
**Fix:** After a volume has been created, the wizard recommends an external header
backup and opens the backup sheet with the new volume preselected.

### 51. NFS Daemon Ends After Dismount (Keys No Longer Left in Memory)
**Files:** `DarwinFUSE/src/nfs4_server.c`, `DarwinFUSE/src/darwinfuse.c`
**Problem:** Found in testing: every mount left a `Basalt` process behind after the
dismount. DarwinFUSE accepts the kernel's NFS connection while mounting and then hands
the server over to a daemon process via `fork()`; `nfs4_server_restart()` reset the
"a client has connected" flag, and since the kernel keeps using the existing connection
the exit condition never became true. The orphaned daemon kept the volume open with its
master keys in memory and kept serving the decrypted volume image; in 1.1.1 that was a
loopback TCP port, so after "dismount" any local process could still read and write the
volume. Present in 1.1.1; the standalone DarwinFUSE had the same
defect.
**Fix:** The flag survives the hand-over. The daemon exits when no client is connected
and its mount is no longer in the mount table (read with `MNT_NOWAIT`, which never
queries the server; for the local socket the mount source must match as well), then
closes the volume and wipes the keys (`fuse_service_destroy`). A kernel reconnect while
the volume is still mounted does not end the daemon.


## Attack Surface Reduction

The original TrueCrypt 7.1a codebase included several subsystems designed for
Windows full-disk encryption and enterprise environments. These have been
completely removed from Basalt because they are irrelevant to container-based
encryption and represent unnecessary attack surface.

### Windows Kernel Driver (14 files removed)
**Deleted:** `Driver/Ntdriver.c/h`, `Ntvol.c/h`, `DriveFilter.c/h`,
`DumpFilter.c/h`, `EncryptedIoQueue.c/h`, build infrastructure.

Kernel drivers run at Ring 0 with full system access. A single vulnerability
(buffer overflow, IOCTL validation error, race condition) grants an attacker
complete control. Basalt uses DarwinFUSE — a userspace NFSv4 implementation
that requires no kernel extension and runs unprivileged.

### Pre-Boot Encryption / Boot Loader (27 files removed)
**Deleted:** Entire `Boot/Windows/` directory — `BootMain.cpp`, `BootSector.asm`,
`BootEncryptedIo.cpp`, `BootDiskIo.cpp`, `BootConsoleIo.cpp`, `BootMemory.cpp`,
and 21 additional files (16-bit assembly, BIOS I/O, decompressor, CRT startup).

Pre-boot code runs before any operating system, with no ASLR, no DEP, no
stack canaries. It is the hardest code to audit and the most dangerous to get
wrong. VeraCrypt's pre-boot DCS bootloader is signed by Microsoft UEFI CA 2011,
placing Microsoft in the trust chain. Basalt has no bootloader and no
third-party trust chain.

### PKCS#11 / Hardware Token Support (5 files removed)
**Deleted:** `Common/SecurityToken.cpp/h` (~800 lines), `pkcs11.h`, `pkcs11f.h`,
`pkcs11t.h`.

PKCS#11 is a complex C API for hardware security modules that loads third-party
shared libraries (`.dylib` / `.dll`) at runtime. Each loaded library runs in the
application's address space with full access to all memory, including encryption
keys. A compromised or backdoored PKCS#11 module would bypass all other security
measures. Basalt uses keyfiles (regular files) as the second factor instead.

### wxWidgets GUI (86 files removed, ~2 MB dependency)
**Deleted:** Entire `Main/`, `Mount/`, `Format/` directories.

See Wave 6, §19 for details. The wxWidgets removal eliminated password handling
through `wxString` with uncontrollable heap copies, signal handler deadlocks,
destruction-order memory corruption, and a large third-party dependency.

### Net Effect

The full `git diff --stat` from TrueCrypt 7.1a to Basalt shows 110,488 lines
deleted and 16,195 lines added across 496 files changed. The codebase shrank
from 194,634 lines (345 source files) to 47,439 lines (223 source files) — a
**75.6% reduction**. Every removed line is a line that cannot contain a
vulnerability.


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
- **FUSE driver:** Volume mounting uses DarwinFUSE (built-in NFSv4 userspace FUSE). The
  FUSE driver logic is unchanged (only mount options were hardened with nosuid/nodev).


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
6. **Password copies outside locked memory:** SwiftUI keeps passwords in Swift `String`
   state (and `NSString` when passed to the bridge), which cannot be wiped. The bridge
   itself no longer creates unwiped copies (#46), but a password cannot be fully confined
   to `mlock()`-ed memory from SwiftUI.
7. **CLI `--password`:** Passwords given on the command line are visible to other local
   users via the process list. The CLI warns about it; use `--password-stdin` or the
   interactive prompt (#45).


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


## Best Practice: Steganographic Keyfiles

Any static, publicly available file can serve as a keyfile — in addition to a
strong password, not as a replacement.

**Requirements for a good public keyfile:**
- **Bit-identical** across all sources (verify with SHA-256 after download)
- **Available from multiple independent mirrors** (no single point of failure)
- **Memorable enough to locate again** without written notes
- **Static** — the file must never change (avoid "latest version" links)

**Examples:** Old OS installation ISOs (Windows 98, Ubuntu 14.04), RFC documents
from IETF, Linux kernel release tarballs, Wikimedia Commons images with stable
file hashes, Project Gutenberg plain-text editions.

**The border crossing scenario:**
When crossing borders with aggressive device inspection, carrying an encrypted
volume is already suspicious. Carrying a USB stick with keyfiles makes it worse.
With a public-file keyfile strategy:

1. Cross the border with an empty laptop (or with the volume on cloud storage)
2. After arrival, download the keyfile from its public source
3. Mount the volume with password + keyfile
4. No suspicious USB stick, no keyfile on the device, no evidence of what the
   keyfile is

**Important:** The keyfile adds entropy from its content (first 1,048,576 bytes
are hashed into the key derivation pool). The security comes from the attacker
not knowing *which* of millions of publicly available files you chose — not from
the file being secret. This is defense-in-depth on top of a strong password, not
a standalone protection.


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

Wave 10 additionally verified implementations against independent references
(libargon2 / RFC 9106 test vectors for Argon2id, software AES vs. AES-NI) and
exercised the volume and NFS layers with regression tests; see
[docs/AUDIT-2026-10.md](docs/AUDIT-2026-10.md).
