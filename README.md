# NoNative

A minimal Android root / environment-integrity detector, implemented in pure
Kotlin with **zero dependencies and no native code**.

## Behavior

- Pure white screen, no UI components at all.
- Detection starts automatically on launch.
- Big verdict in the center: **Dirty** (red) = root / integrity anomaly detected,
  **Clean** (green) = clean. A small hint line lists the signal categories underneath.

## Build & install

```bash
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Requires JDK 17, Android SDK (minSdk 29 / compileSdk 36).

## Detection coverage

| Area | Checks |
|---|---|
| su / SU binaries | fixed-path scan via `stat` (errno separates *hidden* su from absent), `which` fallback |
| anti-hiding | mounts vs mountinfo cross-view, mountinfo overlay-root leak, devpts `ksu_file` PTY labels, `/data/local/tmp` owner, `/data/adb` verdict gated on SELinux enforcing |
| su — root schemes | `/data/adb`, `/sbin/.magisk`, KernelSU/APatch/Magisk dirs, `/data/local/tmp` payloads |
| nativeroot | daemon/prop/process scans, uid-0 self check, `/proc/net/unix` socket names, kallsyms & module list with root-tool token scan (best effort) |
| dangerous apps | package scan: Magisk/KernelSU/APatch/SuperSU/KingRoot/Xposed/LSPosed/LSPatch/HMA/TaiChi/MMRL, shell tools as hint |
| lsposed / zygisk | runtime class probes, boot-classpath probe, call-stack sampling across several call paths, `/proc/self/maps` library tokens |
| mount | Magisk paths in `/proc/self/mounts`, overlay on `/`, writable system partitions, loop devices |
| system properties | ro.debuggable/ro.secure/build type/test-keys, `init.svc.*` keyword scan, Build-vs-getprop dual-source and SystemProperties-vs-getprop cross-path consistency, empty vbmeta digest, `/proc/cmdline`+`/proc/bootconfig` `androidboot.*` cross-check |
| bootloader | ro.boot.verifiedbootstate / flash.locked / vbmeta.device_state, Samsung warranty bit, **KeyMint key attestation** (ASN.1-parsed RootOfTrust: deviceLocked + verifiedBootState) |
| kernel check | kernel identity consistency (uname vs /proc/version vs osrelease), community-kernel markers in `/proc/version`, kallsyms exposure, `/proc/modules`, TracerPid, zygote inet-GID check |
| selinux | `/sys/fs/selinux/enforce` + `getenforce` fallback, process domain check |
| virtualization | qemu/goldfish/ranchu/vbox props & fingerprints, emulator device nodes, binary-translation layer hint |
| custom ROM | LineageOS/CM property markers (hint only — modification is not root) |
| tee | keystore attestation security level (software-only reported as hint) |

## Known gaps (intentional)

Native-level probes need C/asm and are **out of scope for a
no-native-code project**: KernelSU prctl magic probing, KernelPatch supercall
side-channel, SUSFS `setresuid` side-channel, netlink permission-boundary
checks, statx mount-ID cross-views, SELinux policy oracle, and heap-memory
scanning. Root schemes that hide themselves (denylist/Shamiko-style unmounting,
repackaged managers) may therefore evade detection here as well — a "Clean"
verdict only means no listed evidence was found, not that the device is untouched.

## Contributors

Detection ideas credited to [@eltavine](https://github.com/eltavine)
([Duck-Detector-Refactoring](https://github.com/eltavine/Duck-Detector-Refactoring)),
also listed as a commit co-author.

## License

Copyright (C) 2026 JavSaia

This project is licensed under the GNU General Public License version 2 **only**
(SPDX: `GPL-2.0-only`) — see [LICENSE](LICENSE).
