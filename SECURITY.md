# Security

Basalt is a fork of TrueCrypt 7.1a for macOS. This document describes how it protects
your data, what it leaves out on purpose, and where its limits are. Existing TrueCrypt
volumes keep working.

Review of the TrueCrypt 7.1a source (random number generator, key derivation,
encryption, volume headers, memory handling) found no backdoor.


## Key derivation

- **Argon2id** (RFC 9106) for new volumes, in two profiles: *Standard* (512 MB, 4 lanes)
  and *Maximum* (1 GB, 8 lanes). The implementation reproduces the official test vector
  and the output of libargon2.
- **PBKDF2** for existing volumes: TrueCrypt's original counts (1,000–2,000 iterations)
  and VeraCrypt's 500,000 (655,331 for RIPEMD-160). New volumes use PBKDF2 only if
  "TrueCrypt 7.1a compatible" is chosen, which warns about the weaker derivation.
- **Upgrade on mount.** TrueCrypt and VeraCrypt volumes are offered Argon2id-Max. Only the
  header is rewritten; master key, password, keyfiles and data stay as they are.
  Afterwards TrueCrypt and VeraCrypt can no longer open the volume. Headers written by
  Basalt 1.1.x and earlier use a non-standard Argon2id variant; they still open and are
  offered the same upgrade. Volumes created since 1.2.0 do not open in 1.1.x.
- **The key derivation function is not stored in the header**, so mounting tries all
  supported ones, cheapest first. PBKDF2 runs on all cores.
- **No PIM.** A user-chosen iteration multiplier adds about 10 bits at best and lets users
  lower the cost: PIM 1 with SHA-512 means roughly 2,048 iterations. Iteration counts are
  fixed. A longer password or a keyfile adds real entropy.


## Memory and randomness

- Keys and passwords live in `mlock()`-pinned buffers and are wiped with `memset_s()`,
  which the compiler cannot optimise away. This also covers XTS whitening values and
  password strings. Secret data is compared in constant time.
- There is no password cache. Every mount asks for the password.
- The app copies passwords from the text field into a wiped stack buffer. The CLI reads
  them without echo, or from standard input with `--password-stdin`; `--password` shows
  up in the process list and prints a warning.
- Entropy comes from `getentropy()`. The pool is mixed with XOR, not addition, without the
  former inversion step, and the hash is initialised before use.
- XTS rejects volumes whose primary and secondary keys are identical. PBKDF2 block
  counters are encoded big-endian as RFC 2898 requires.
- AES uses the hardware instructions (ARMv8 crypto extensions, AES-NI on Intel). They run
  in constant time; the table-based software version is open to cache-timing attacks.


## Volumes

- New volumes carry the header magic `BSLT`. Basalt also opens `TRUE` (TrueCrypt) and
  `VERA` (VeraCrypt) volumes. The magic lies inside the encrypted header, so a volume is
  indistinguishable from random data, and hidden volumes are unaffected.
- Header layout, data area, ciphers (AES, Serpent, Twofish and their cascades) and XTS are
  the same as in TrueCrypt 7.1a and VeraCrypt.
- VeraCrypt volumes using Camellia, Kuznyechik, the SHA-256, BLAKE2s or Streebog PRF, or a
  custom PIM cannot be opened.
- Sector arithmetic is overflow-safe, so a crafted offset cannot reach the hidden volume
  header and bypass hidden volume protection.
- Passwords are stored one byte per character. New passwords with characters beyond Latin-1
  (€, Cyrillic, CJK, emoji) are refused instead of being truncated silently. Existing
  volumes open as before.


## Mounting

- No kernel extension and no SIP change. **DarwinFUSE**, a userspace NFSv4 server inside
  the app, serves the volume over a Unix domain socket in a private directory (mode 0700)
  and accepts only the owner and root. The kernel's NFS client connects to it through
  `mount_nfs`. No TCP port is opened.
- When a volume is dismounted, the server ends, closes the volume and wipes the keys. If
  the app is killed or crashes, the service that did the mounting dismounts its volumes.
- Mounts use `nosuid,nodev`. System directories (`/`, `/usr`, `/etc`, `/System`,
  `/Library`, `/Applications`, …) are refused as mount points.
- System tools (`mount_nfs`, `mount`, `umount`, `hdiutil`, `sudo`, `open`) run by absolute
  path, so a manipulated `PATH` cannot redirect them or capture the administrator password.
- No log files are written. Helper files are created with `O_EXCL|O_NOFOLLOW` and read
  only if they belong to the user or root. The build script keeps its symlink in the
  per-user temporary directory.


## App behaviour

- Volumes are dismounted after inactivity (5 to 120 minutes), at screen saver and screen
  lock, before sleep (the Mac waits for it), at logout and shutdown, and when the app
  quits. Force dismount is the default, so a background process cannot keep a volume open
  against your intent.
- The app remembers nothing: no favourites, history, recent lists, default keyfiles or
  window state. The Spotlight exclusion marker is written only where it changes nothing
  that matters, never on read-only mounts or on an outer volume with hidden volume
  protection.
- The app's windows are excluded from screenshots, screen recording and AirPlay.
- After creating a volume, the wizard recommends an external header backup.


## Smaller attack surface

Removed from TrueCrypt: the Windows kernel driver, the boot loader with pre-boot
authentication, PKCS#11 token support (it loads third-party libraries into the process)
and wxWidgets. The code base shrank from 194,634 to 47,439 lines, 75 % less. Without boot
encryption there is no boot-loader trust chain.


## Cipher selection

- **AES, Serpent and Twofish** and their cascades. All were finalists of the AES
  competition and have decades of public analysis. Their different internal structures
  make cascades robust against a break of a single algorithm.
- **Kuznyechik** is left out. In 2019 Perrin and Udovenko showed that its S-box has a
  hidden structure that the design never explained.
- **Camellia** is left out. It is sound, but offers no advantage over AES, has no hardware
  support on Apple silicon, and adds code to maintain.

Compared with VeraCrypt, Basalt has no password cache, no Kuznyechik, force dismount by
default and a smaller code base. It lacks PIM (on purpose), Windows full-disk encryption
and support for other platforms.


## Keyfiles

A keyfile adds entropy to the password; the first 1 MiB is hashed into the key. Any static
public file can serve: an old installer image, an RFC, a release tarball. It must be
bit-identical on all mirrors and never change. The strength comes from the attacker not
knowing which of millions of public files you chose, not from the file being secret. Use a
keyfile in addition to a strong password, not instead of one.


## Known limitations

1. **No authenticated encryption.** XTS does not detect tampering.
2. **Password copies.** Text typed into SwiftUI fields lives in Swift `String` storage that
   cannot be wiped or locked. The bridge copies it out immediately.
3. **Algorithms.** SHA-1 and RIPEMD-160 remain for compatibility; SHA-512 is the default.
   Serpent and Twofish are software only.
4. **Administrator password dialog.** Volumes on devices need root. Basalt asks for the
   macOS password in its own dialog and hands it to `sudo -S`, which teaches users to type
   that password into application windows. A privileged helper registered with
   `SMAppService` would use the system authorization prompt instead.
5. **Killing everything at once.** If all Basalt processes are killed together, the mount
   is left behind without a server and cannot be used.
6. **Self-built binaries** are signed ad-hoc only; see the Readme for Gatekeeper.


## Review

The TrueCrypt 7.1a source was analysed with LLM assistance (random number generator, key
derivation, encryption, volume headers, memory handling, suspicious patterns), together with
the commits of the VeraCrypt fork. Argon2id was checked against the RFC 9106 test vector
and libargon2, AES-NI against the software implementation.
