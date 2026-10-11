# Release checklist (macOS)

Manual tests that need a real Mac. Run them on Apple Silicon and Intel (or
Rosetta), on the oldest and newest supported macOS, with the build that
`release.sh` produces (signed with the hardened runtime, as users get it).

1. `bash build-universal.sh release`; "Run Self-Test…" in the app passes.
2. Mount a file container. `mount | grep basalt` shows the aux mount as
   `<…/darwinfuse.XXXXXX/nfs.sock>:/`; `lsof -nP -iTCP -sTCP:LISTEN` shows no
   Basalt/DarwinFUSE listener. Read and write a large file (> 1 GB), dismount.
3. Mount a volume created by an older version with Argon2id-Max: the badge shows
   "Argon2id-Max (legacy)", the upgrade prompt appears; after upgrading the
   volume remounts as "Argon2id-Max". Repeat with an Argon2id (standard) volume
   and a TrueCrypt 7.1a volume.
4. Create a volume with a password containing "€" → clear error; with "äöü" → works.
5. Mount and dismount a device-hosted volume (sudo path) — `/tmp` contains no
   `darwinfuse.log`; `.auxinfo` is root-owned 0600.
6. Lock the screen with Ctrl-Cmd-Q with "dismount on screen saver" enabled.
7. With "dismount when system sleeps" enabled and a volume mounted, choose
   Apple menu > Sleep: the volume is gone after wake (`pmset -g log` shows the
   sleep was delayed only briefly). Quit with Cmd-Q and from the menu bar icon:
   `mount` lists no Basalt volume afterwards. With "Force dismount" off and a file
   open on the volume, quitting asks before leaving the volume mounted.
8. Mount a TrueCrypt and a VeraCrypt volume: the prompt offers Argon2id-Max and
   warns that TrueCrypt/VeraCrypt can no longer open the volume; after upgrading
   it mounts noticeably faster. A wrong password is reported in about a third of
   the time the old sequential key derivation needed. `basalt-cli --password-stdin
   --kdf=argon2id-max …` with the password piped in.
9. Switch the system language (e.g. German, Japanese): menus, sheets, errors and
   the upgrade prompt are translated, no text is clipped (Settings window, wizard).
10. After dismounting all volumes and quitting, `ps -ax | grep -i [b]asalt` lists
    no process (SECURITY.md #51).
11. Mount a volume, `kill -9` the app's main process: within a few seconds the
    volume is dismounted and no Basalt process is left (SECURITY.md #52). With
    "dismount on quit" off, a regular quit keeps the volume mounted.
12. Upgrade the header of a device-hosted volume and change the password of one:
    both work as a non-administrator (the device is handed over temporarily and
    belongs to root again afterwards: `ls -l /dev/diskN`).
13. Verify the shipped files: `spctl --assess --type open --context
    context:primary-signature -v Basalt.dmg`, `xcrun stapler validate Basalt.dmg`,
    and `codesign -dvv Basalt.app` shows the Developer ID and the `runtime` flag.
