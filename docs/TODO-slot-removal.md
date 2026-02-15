# TODO: Slot-System entfernen

## Zusammenfassung

Der `VolumeSlotNumber`-Layer ist auf allen drei Plattformen redundant und sollte entfernt werden.

## Analyse

### Was der Slot auf jeder Plattform tut (bzw. nicht tut)

**macOS:**
- Slot hat KEINEN Einfluss auf den Mount-Point — `hdiutil attach` bestimmt `/Volumes/<label>` selbst
- `GetDefaultMountPointPrefix()` = `/Volumes/truecrypt` (CoreMacOSX.h:25), aber wenn der Mount-Point damit beginnt, wird gar kein `-mountpoint` an hdiutil übergeben → macOS entscheidet
- Der tatsächliche Mount-Point wird über `GetMountedFilesystems(VirtualDevice)` ermittelt
- Slot wird nur in der FUSE-Control-Datei (`/tmp/.basalt_aux_mntN/control`) mitgespeichert
- Volume-Discovery: FUSE-Aux-Mount-Scan, nicht Slot-basiert

**Linux:**
- Einzige Plattform, wo Slot den Default-Mount-Point beeinflusst: Slot 3 → `/media/basalt3`
- Aber: User kann beliebigen Mount-Point angeben, dann wird Slot nur als Metadatum gespeichert

**Windows:**
- Slot = Laufwerksbuchstabe - 'A' + 1 (D: = 4, E: = 5, ...)
- **ABER:** LamarckFUSE (lamarckfuse.c:611-617) leitet Slot UND iSCSI-Port direkt aus dem Laufwerksbuchstaben ab — der von oben übergebene Slot wird ignoriert:
  ```c
  char letter = toupper(out->mount_point[0]);
  out->slot = letter - 'A' + 1;
  out->port = iscsi_port_for_slot(out->slot);
  ```
- `WriteSlotInfo()`/`ReadSlotInfo()` für Cross-Process-Discovery könnte stattdessen direkt den Laufwerksbuchstaben als Key nutzen

## Betroffene Dateien (93 Stellen, 18 Dateien)

| Datei | Stellen | Aufwand |
|-------|---------|---------|
| Core/CoreBase.h | 9 | Interface-Methoden entfernen/vereinfachen |
| Core/CoreBase.cpp | 19 | `CoalesceSlotNumberAndMountPoint` eliminieren, `GetFirstFreeSlotNumber` → direkt freien Mount-Point finden |
| Core/MountOptions.h/cpp | 5 | `SlotNumber` aus MountOptions entfernen |
| Volume/VolumeInfo.h/cpp | 3 | `SlotNumber` aus VolumeInfo entfernen (⚠ Serialisierungsformat!) |
| Volume/VolumeSlot.h | 1 | Typedef entfernen |
| Core/Unix/CoreUnix.h/cpp | 8 | `MountPointToSlotNumber`/`SlotNumberToMountPoint` entfernen |
| Core/Unix/MacOSX/CoreMacOSX.h | 1 | `GetDefaultMountPointPrefix` Override entfernen |
| Core/Unix/Linux/CoreLinux.cpp | 1 | `truecrypt` Device-Name ohne Slot |
| Core/Windows/CoreWindows.h/cpp | 22 | Slot-Info Files → Drive-Letter-basiert, MountPoint direkt |
| Driver/Fuse/FuseService.h/cpp | 10 | `SlotNumber` Parameter aus `Mount()` entfernen |
| Driver/Fuse/FuseServiceWindows.cpp | 4 | Slot-Parameter entfernen |
| CLI/main.cpp | 5 | `--slot` Parameter → `--drive-letter` (Windows) oder entfernen |
| GUI/core_bridge.cpp | 3 | Slot aus Bridge entfernen |
| Basalt/Bridge/TCCoreBridge.mm | 3 | `slotNumber` aus TCVolumeInfo/TCMountOptions entfernen |

## Vorgehensweise

1. **VolumeInfo**: `SlotNumber` durch eine UUID oder einfach den Volume-Path als ID ersetzen
2. **MountOptions**: `SlotNumber` entfernen — Mount-Point direkt übergeben
3. **CoreBase**: `CoalesceSlotNumberAndMountPoint()` durch `EnsureMountPoint()` ersetzen (findet freien Mount-Point, ohne Slot-Umweg)
4. **Linux**: Freien Mount-Point durch Scan von `/media/basalt*` finden statt über Slot-Nummer
5. **Windows**: `WriteSlotInfo`/`ReadSlotInfo` → Key = Laufwerksbuchstabe statt Slot-Nummer
6. **macOS/Swift GUI**: `TCVolumeInfo.id` von `slotNumber` auf `path` oder `mountPoint` umstellen
7. **CLI**: `--slot N` entfernen, ggf. `--drive-letter X` nur auf Windows
8. **Serialisierung**: Ggf. `SlotNumber` beim Deserialisieren ignorieren (Backward-Compat)

## Risiken

- **Serialisierungsformat**: Alte FUSE-Control-Files enthalten `SlotNumber` — muss graceful ignoriert werden
- **CLI-Compat**: Scripte die `--slot` nutzen brechen
- **Gleichzeitig 3 Plattformen**: Alle drei Frontends + Core betroffen → sorgfältig testen

## Priorität

Niedrig — funktional ändert sich nichts. Machen wenn keine anderen Baustellen offen sind.
