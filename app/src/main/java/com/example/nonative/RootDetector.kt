// SPDX-License-Identifier: GPL-2.0-only
package com.example.nonative

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.Locale

/**
 * Root / environment integrity detector. Coverage:
 * SU binaries and root-scheme directories, root manager packages, Xposed/LSPosed
 * runtime injection, /proc/self/maps injected libraries, Magisk mount artifacts,
 * suspicious processes, system properties, bootloader / verified boot state,
 * KeyMint hardware attestation, SELinux, kernel identity, Frida, emulators.
 *
 * Every check runs with the app's own permissions (no root, no native code).
 * Solid evidence is reported as danger (drives the Yes verdict); weak evidence
 * is reported as warning (hint text only).
 */
object RootDetector {

    class Finding(val category: String, val detail: String, val danger: Boolean)

    class Report(val dangers: List<Finding>, val warnings: List<Finding>) {
        val detected: Boolean get() = dangers.isNotEmpty()
    }

    /** Root tooling keywords used for property-name/value and process-name scans */
    private val ROOT_TOKENS = listOf("magisk", "zygisk", "kernelsu", "ksu", "apatch", "kpatch", "susfs", "supersu", "daemonsu")

    /** Extended keywords for kernel-side artifacts (kallsyms, modules, version strings) */
    private val KERNEL_TOKENS = ROOT_TOKENS

    /** Additional keywords only meaningful for process / socket scans */
    private val PROCESS_TOKENS = ROOT_TOKENS + listOf("frida", "linjector")

    private val SU_PATHS = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sd/xbin/su",
        "/system/bin/failsafe/su", "/vendor/bin/su", "/vendor/xbin/su", "/product/bin/su",
        "/su/bin/su", "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/cache/su", "/data/su", "/data/adb/su",
        "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
        "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
        "/system/app/Superuser.apk",
        // temporary root payloads dropped in /data/local/tmp
        "/data/local/tmp/su", "/data/local/tmp/ksud", "/data/local/tmp/magisk",
        "/data/local/tmp/magisk64", "/data/local/tmp/apd",
    )

    private val ROOT_DIRS = listOf(
        "/data/adb", "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap",
        "/data/adb/modules", "/sbin/.magisk", "/cache/.disable_magisk",
    )

    private val FRIDA_PATHS = listOf(
        "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
    )

    private val BUSYBOX_PATHS = listOf("/system/xbin/busybox", "/system/bin/busybox")

    /** Device nodes that only exist inside emulators / VMs */
    private val EMULATOR_NODES = listOf(
        "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/socket/qemud",
        "/dev/vboxguest", "/dev/vboxuser",
    )

    /** package name -> label; a hit is treated as root-environment evidence */
    private val ROOT_PACKAGES = mapOf(
        "com.topjohnwu.magisk" to "Magisk",
        "com.topjohnwu.magisk.debug" to "Magisk (debug)",
        "io.github.huskydg.magisk" to "Magisk Delta",
        "me.weishu.kernelsu" to "KernelSU",
        "me.weishu.kernelsu.debug" to "KernelSU (debug)",
        "com.rifsxd.kernelsu" to "KernelSU",
        "com.rifsxd.ksunext" to "KernelSU Next",
        "me.bmax.apatch" to "APatch",
        "eu.chainfire.supersu" to "SuperSU",
        "eu.chainfire.supersu.pro" to "SuperSU Pro",
        "com.noshufou.android.su" to "Superuser",
        "com.noshufou.android.su.elite" to "Superuser Elite",
        "com.koushikdutta.superuser" to "Superuser",
        "com.thirdparty.superuser" to "Superuser",
        "com.yellowes.su" to "KingRoot",
        "com.kingroot.kinguser" to "KingRoot",
        "com.kingroot.master" to "KingRoot",
        "com.kingo.root" to "KingORoot",
        "com.kingouser.com" to "KingRoot",
        "de.robv.android.xposed.installer" to "Xposed Installer",
        "org.lsposed.manager" to "LSPosed Manager",
        "org.meowmeister.edxposed.manager" to "EdXposed Manager",
        "com.solohsu.android.edxp.manager" to "EdXposed Manager",
        "org.lsposed.lspatch" to "LSPatch",
        "com.saurik.substrate" to "Cydia Substrate",
        "com.tsng.hidemyapplist" to "Hide My Applist",
        "me.weishu.exp" to "TaiChi",
        "com.dergoogler.mmrl" to "MMRL",
    )

    /** hint-only, never flips the verdict to Yes */
    private val SHELL_PACKAGES = mapOf(
        "com.jackpal.androidterm" to "Terminal Emulator",
        "com.termux" to "Termux",
    )

    private val XPOSED_CLASSES = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "io.github.libxposed.api.XposedInterface",
    )

    /** keywords for /proc/self/maps (our own process only — no cross-app false positives) */
    private val MAPS_TOKENS = listOf(
        "zygisk", "riru", "xposed", "lspd", "lsposed", "edxposed", "lspatch",
        "magisk", "frida", "gum-js-loop", "linjector", "sandhook", "shadowhook", "dobby",
    )

    private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
    private const val ATTESTATION_ALIAS = "nonative_rootcheck"

    fun detect(context: Context): Report {
        val findings = ArrayList<Finding>()
        val props = readProps()
        findings += checkSuBinaries()
        findings += checkRootDirs()
        findings += checkPaths(FRIDA_PATHS, "Frida", "Frida server artifacts: ", danger = true)
        findings += checkPackages(context)
        findings += checkXposedRuntime()
        findings += checkMaps()
        findings += checkMounts()
        findings += checkMountinfo()
        findings += checkProcesses()
        findings += checkProperties(props)
        findings += checkBootParams(props)
        findings += checkPropSources(props)
        findings += checkSelinux()
        findings += checkKernelVersion()
        findings += checkKernelIdentity()
        findings += checkKernelVisibility()
        findings += checkDevpts()
        findings += checkLocalTmp()
        findings += checkProcStatus(context)
        findings += checkUnixSockets()
        findings += checkEmulatorNodes()
        findings += checkKeyAttestation()
        findings += checkBusybox()
        for (f in findings) {
            Log.d("NoNative", (if (f.danger) "D" else "W") + " | " + f.category + " | " + f.detail)
        }
        return Report(
            dangers = findings.filter { it.danger }.distinctBy { it.category + it.detail },
            warnings = findings.filterNot { it.danger }.distinctBy { it.category + it.detail },
        )
    }

    // ---------- SU binaries and root-scheme directories ----------

    private fun checkSuBinaries(): List<Finding> {
        val hits = ArrayList<String>()
        val hidden = ArrayList<String>()
        for (path in SU_PATHS) {
            try {
                Os.stat(path)
                hits += path
            } catch (e: ErrnoException) {
                // stock policy lets apps stat system/vendor/product paths, so a denial
                // there means the file exists but is hidden from apps — the hiding leaks
                val denied = e.errno == OsConstants.EACCES || e.errno == OsConstants.EPERM
                val gated = path.startsWith("/system") || path.startsWith("/vendor") || path.startsWith("/product")
                if (denied && gated) hidden += path
            } catch (t: Throwable) {
            }
        }
        for (name in listOf("su", "magisk", "ksud", "daemonsu")) {
            val p = exec("which", name)
            if (p.isNotEmpty() && !hits.contains(p)) hits += p
        }
        val out = ArrayList<Finding>()
        if (hits.isNotEmpty()) {
            out += Finding("SU binaries", "SU/root tool artifacts found: " + hits.joinToString(", "), danger = true)
        }
        if (hidden.isNotEmpty()) {
            out += Finding(
                "Hidden su paths",
                "stat denied where stock policy allows it (su exists but hidden): " + hidden.joinToString(", "),
                danger = true,
            )
        }
        return out
    }

    private fun checkRootDirs(): List<Finding> {
        val hits = ROOT_DIRS.filter { File(it).exists() }
        // modern AOSP init.rc also creates /data/adb, and userdebug/permissive systems
        // let apps stat it — the hit is only root evidence under an enforcing policy
        val enforcing = readText("/sys/fs/selinux/enforce")?.trim() == "1"
        if (hits.isEmpty()) return emptyList()
        return if (enforcing) {
            listOf(Finding("Root directories", "Root-scheme directories found (SELinux enforcing): " + hits.joinToString(", "), danger = true))
        } else {
            listOf(Finding("Root directories", "Root-scheme directories visible without an SELinux gate (userdebug expectation or hiding, hint only): " + hits.joinToString(", "), danger = false))
        }
    }

    private fun checkPaths(paths: List<String>, category: String, prefix: String, danger: Boolean): List<Finding> {
        val hits = paths.filter { File(it).exists() }
        return if (hits.isEmpty()) emptyList()
        else listOf(Finding(category, prefix + hits.joinToString(", "), danger = danger))
    }

    private fun checkBusybox(): List<Finding> {
        val hits = BUSYBOX_PATHS.filter { File(it).exists() }.toMutableList()
        val which = exec("which", "busybox")
        if (which.isNotEmpty() && !hits.contains(which)) hits += which
        return if (hits.isEmpty()) emptyList()
        else listOf(Finding("Busybox", "busybox found (hint only): " + hits.joinToString(", "), danger = false))
    }

    // ---------- package scan ----------

    private fun checkPackages(context: Context): List<Finding> {
        val pm = context.packageManager
        val installed: Set<String> = try {
            pm.getInstalledPackages(0).map { it.packageName }.toSet()
        } catch (t: Throwable) {
            // fall back to probing known package names one by one
            (ROOT_PACKAGES.keys + SHELL_PACKAGES.keys).filterTo(mutableSetOf()) { name ->
                try {
                    pm.getPackageInfo(name, 0); true
                } catch (t: Throwable) {
                    false
                }
            }
        }
        val out = ArrayList<Finding>()
        val root = installed.filter { ROOT_PACKAGES.containsKey(it) }
        if (root.isNotEmpty()) {
            out += Finding(
                "Root manager apps",
                "Related apps installed: " + root.mapNotNull { ROOT_PACKAGES[it] }.distinct().joinToString(", "),
                danger = true,
            )
        }
        val shell = installed.filter { SHELL_PACKAGES.containsKey(it) }
        if (shell.isNotEmpty()) {
            out += Finding(
                "Shell tools",
                "Terminal tools installed (hint only): " + shell.mapNotNull { SHELL_PACKAGES[it] }.distinct().joinToString(", "),
                danger = false,
            )
        }
        return out
    }

    // ---------- Xposed / LSPosed runtime injection ----------

    private fun checkXposedRuntime(): List<Finding> {
        val hits = ArrayList<String>()
        for (cls in XPOSED_CLASSES) {
            try {
                Class.forName(cls); hits += cls
            } catch (t: Throwable) {
            }
        }
        val bcp = System.getProperty("java.boot.class.path")
            ?: System.getProperty("sun.boot.class.path") ?: ""
        if (bcp.contains("XposedBridge", ignoreCase = true)) hits += "XposedBridge on boot classpath"
        // hooking frameworks inject their own frames into call stacks; sample several paths
        val stacks = ArrayList<Array<StackTraceElement>>()
        val sample = { stacks += Throwable().stackTrace }
        sample(); sample()
        val th = Thread(sample); th.start(); th.join(1000)
        for (st in stacks) {
            for (f in st) {
                val cn = f.className
                if (cn.contains("xposed", true) || cn.contains("lsposed", true) || cn.contains("lspatch", true)) {
                    hits += "stack: $cn"
                }
            }
        }
        return if (hits.isEmpty()) emptyList()
        else listOf(Finding("Hook framework", "Xposed/LSPosed runtime traces: " + hits.distinct().joinToString(", "), danger = true))
    }

    // ---------- own-process memory map ----------

    private fun checkMaps(): List<Finding> {
        val text = readText("/proc/self/maps") ?: return emptyList()
        val hits = MAPS_TOKENS.filter { text.contains(it, ignoreCase = true) }
        return if (hits.isEmpty()) emptyList()
        else listOf(Finding("Injected libraries", "Injection framework traces in process maps: " + hits.joinToString(", "), danger = true))
    }

    // ---------- mount tables ----------

    private fun checkMounts(): List<Finding> {
        val out = ArrayList<Finding>()
        val mounts = readText("/proc/self/mounts") ?: return out
        val topLevel = setOf("/", "/system", "/vendor", "/product")
        for (line in mounts.lineSequence()) {
            val parts = line.split(" ")
            if (parts.size < 4) continue
            val dev = parts[0]
            val mp = parts[1]
            val fstype = parts[2]
            val opts = parts[3]
            if (mp in topLevel && fstype == "overlay") {
                out += Finding("Overlay mount", "$mp mounted as overlay (systemless modification)", danger = true)
            }
            if (mp in setOf("/system", "/vendor", "/product")) {
                if (opts.split(",").contains("rw")) {
                    out += Finding("Writable system partition", "$mp mounted writable", danger = true)
                }
                if (dev.startsWith("/dev/loop")) {
                    out += Finding("Loop mount", "$mp mounted from loop device $dev (hint only)", danger = false)
                }
            }
            if (listOf(".magisk", "magisk", "/data/adb", "debug_ramdisk").any { mp.contains(it, true) || dev.contains(it, true) }) {
                out += Finding("Magisk mounts", "Magisk traces in mount table: $dev on $mp", danger = true)
            }
        }
        return out
    }

    // ---------- mountinfo: module overlay leaks + cross-view consistency ----------

    private fun unescapeMount(s: String): String = s
        .replace("\\134", "\\")
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")

    private fun checkMountinfo(): List<Finding> {
        val out = ArrayList<Finding>()
        val info = readText("/proc/self/mountinfo") ?: return out
        val infoPoints = HashSet<String>()
        for (line in info.lineSequence()) {
            val f = line.split(" ")
            if (f.size < 5) continue
            val root = unescapeMount(f[3])
            val mp = unescapeMount(f[4])
            infoPoints += mp
            // module overlays keep their backing store in the root field even when
            // the mountpoint looks innocent (e.g. /data/adb/modules/.../system)
            if (root.startsWith("/data/adb") || KERNEL_TOKENS.any { root.contains(it, true) }) {
                out += Finding("Module overlay", "mountinfo exposes overlay root $root on $mp", danger = true)
            }
        }
        // /proc/self/mounts and /proc/self/mountinfo describe the same namespace;
        // a hiding tool that filters only one of them leaves a mismatch behind
        val mounts = readText("/proc/self/mounts")
        if (mounts != null && infoPoints.isNotEmpty()) {
            val mountPoints = mounts.lineSequence()
                .map { it.split(" ") }
                .filter { it.size >= 2 }
                .map { unescapeMount(it[1]) }
                .toSet()
            if (mountPoints != infoPoints) {
                val onlyMounts = (mountPoints - infoPoints).take(3).joinToString(", ")
                val onlyInfo = (infoPoints - mountPoints).take(3).joinToString(", ")
                out += Finding(
                    "Mount cross-view mismatch",
                    "mounts vs mountinfo disagree (hiding traces): [$onlyMounts] vs [$onlyInfo]",
                    danger = true,
                )
            }
        }
        return out
    }

    // ---------- devpts PTY labels (KernelSU ksu_file leak) ----------

    private fun checkDevpts(): List<Finding> {
        val entries = File("/dev/pts").list() ?: return emptyList()
        val hits = ArrayList<String>()
        for (e in entries) {
            try {
                val label = String(Os.getxattr("/dev/pts/$e", "security.selinux")).trim('\u0000')
                if (label.contains("ksu_file", true) || KERNEL_TOKENS.any { label.contains(it, true) }) {
                    hits += "$e=$label"
                }
            } catch (t: Throwable) {
                // xattr read denied → probe unavailable, never guess
                return emptyList()
            }
        }
        return if (hits.isEmpty()) emptyList()
        else listOf(Finding("su PTY label", "devpts PTYs carry root-tool labels: " + hits.joinToString(", "), danger = true))
    }

    // ---------- /data/local/tmp DAC metadata (AOSP expects shell:shell 2000:2000) ----------

    private fun checkLocalTmp(): List<Finding> {
        return try {
            val st = Os.stat("/data/local/tmp")
            if (st.st_uid == 2000 && st.st_gid == 2000) emptyList()
            else listOf(
                Finding(
                    "Shell tmp",
                    "/data/local/tmp owner is ${st.st_uid}:${st.st_gid}, AOSP init creates 2000:2000 (rebuilt by root tooling?)",
                    danger = false,
                ),
            )
        } catch (t: Throwable) {
            emptyList()
        }
    }

    // ---------- process scan ----------

    private fun checkProcesses(): List<Finding> {
        val hits = LinkedHashSet<String>()
        val dirs = File("/proc").listFiles { f -> f.name.all { c -> c.isDigit() } } ?: return emptyList()
        for (d in dirs) {
            // entries we have no permission to read yield null and are skipped
            val cmd = (readText(d.absolutePath + "/cmdline") ?: continue)
                .replace('\u0000', ' ').trim()
            if (cmd.isEmpty()) continue
            val suspicious = cmd.split(' ').filter { it.isNotEmpty() }.any { t ->
                val base = t.substringAfterLast('/')
                PROCESS_TOKENS.any { base.contains(it, true) } || base == "su"
            }
            if (suspicious) hits += cmd
        }
        return if (hits.isEmpty()) emptyList()
        else listOf(Finding("Suspicious processes", "Root-related processes found: " + hits.joinToString(", "), danger = true))
    }

    // ---------- system properties ----------

    private fun checkProperties(props: Map<String, String>): List<Finding> {
        val out = ArrayList<Finding>()
        fun p(key: String): String = props[key] ?: ""

        // build shape
        if (p("ro.debuggable") == "1") out += Finding("Debuggable system", "ro.debuggable=1", danger = true)
        if (p("ro.secure") == "0") out += Finding("ro.secure=0", "adbd runs as root on this build", danger = true)
        val buildType = p("ro.build.type")
        if (buildType == "userdebug" || buildType == "eng") {
            out += Finding("Dev build", "ro.build.type=$buildType", danger = true)
        }
        if (p("ro.build.tags").contains("test-keys")) {
            out += Finding("Test-keys", "ro.build.tags=${p("ro.build.tags")}", danger = true)
        }

        // bootloader / verified boot
        when (p("ro.boot.verifiedbootstate")) {
            "orange" -> out += Finding("Unlocked bootloader", "verified boot state orange (unlocked)", danger = true)
            "red" -> out += Finding("Verified boot", "verified boot state red (verification failed)", danger = true)
            "yellow" -> out += Finding("Verified boot", "verified boot state yellow (custom signing, hint only)", danger = false)
        }
        if (p("ro.boot.flash.locked") == "0") {
            out += Finding("Unlocked bootloader", "ro.boot.flash.locked=0", danger = true)
        }
        if (p("ro.boot.vbmeta.device_state") == "unlocked") {
            out += Finding("Unlocked bootloader", "ro.boot.vbmeta.device_state=unlocked", danger = true)
        }
        if (p("ro.boot.warranty_bit") == "1" || p("ro.warranty_bit") == "1") {
            out += Finding("Warranty fuse", "Samsung warranty bit tripped (unofficial system)", danger = true)
        }
        val verity = p("ro.boot.veritymode")
        if (verity.isNotEmpty() && verity != "enforcing") {
            out += Finding("dm-verity", "ro.boot.veritymode=$verity (hint only)", danger = false)
        }
        if (p("sys.oem_unlock_allowed") == "1") {
            out += Finding("OEM unlock", "sys.oem_unlock_allowed=1 (hint only)", danger = false)
        }

        // empty vbmeta digest: libavb always includes the top-level vbmeta in the hash,
        // so the digest of an empty input can never come from verified boot
        val digest = p("ro.boot.vbmeta.digest").lowercase(Locale.US)
        if (digest.isNotEmpty()) {
            val empty256 = MessageDigest.getInstance("SHA-256").digest(ByteArray(0)).toHex()
            val empty512 = MessageDigest.getInstance("SHA-512").digest(ByteArray(0)).toHex()
            if (digest == empty256 || digest == empty512) {
                out += Finding("vbmeta digest", "ro.boot.vbmeta.digest equals the empty-input digest (resetprop trace)", danger = true)
            }
        }

        // root-scheme properties: names or init.svc values containing root tool keywords
        val propHits = props.entries
            .filter { e -> ROOT_TOKENS.any { e.key.contains(it, true) || e.value.contains(it, true) } }
            .map { it.key }
        if (propHits.isNotEmpty()) {
            out += Finding("Root properties", "Root tool properties found: " + propHits.distinct().joinToString(", "), danger = true)
        }

        // dual-source consistency: Build fields cached at process start vs the live
        // property service — a mismatch means properties were rewritten at runtime
        if (p("ro.build.fingerprint").isNotEmpty() && p("ro.build.fingerprint") != Build.FINGERPRINT) {
            out += Finding("Property tampering", "ro.build.fingerprint differs from Build.FINGERPRINT", danger = true)
        }
        if (p("ro.build.tags").isNotEmpty() && p("ro.build.tags") != Build.TAGS) {
            out += Finding("Property tampering", "ro.build.tags differs from Build.TAGS", danger = true)
        }

        // emulator / virtualization
        val fp = Build.FINGERPRINT.lowercase(Locale.US)
        val hw = Build.HARDWARE.lowercase(Locale.US)
        val model = Build.MODEL.lowercase(Locale.US)
        if (p("ro.kernel.qemu") == "1" || p("ro.boot.qemu") == "1" ||
            hw in setOf("goldfish", "ranchu", "vbox", "vbox86") ||
            fp.contains("generic") || fp.contains("emulator") || fp.contains("vbox") || fp.contains("vsoc") ||
            model.contains("emulator") || model.contains("google_sdk")
        ) {
            out += Finding("Emulator / VM", "emulator characteristics detected", danger = true)
        }
        val bridge = p("ro.dalvik.vm.native.bridge")
        if (bridge.contains("houdini", true) || bridge.contains("ndk", true)) {
            out += Finding("Binary translation", "native bridge: $bridge (hint only)", danger = false)
        }

        // custom ROM markers (modification != root, hint only)
        val romProps = props.keys.filter {
            it.startsWith("ro.lineage") || it.startsWith("ro.cm.") || it == "ro.modversion"
        }
        if (romProps.isNotEmpty()) {
            out += Finding("Custom ROM", "ROM properties present: " + romProps.joinToString(", ") + " (hint only)", danger = false)
        }
        return out
    }

    /** cross-check raw boot parameters against the imported ro.boot.* properties */
    private fun checkBootParams(props: Map<String, String>): List<Finding> {
        val raw = StringBuilder()
        raw.append(readText("/proc/cmdline") ?: "")
        raw.append('\n')
        raw.append(readText("/proc/bootconfig") ?: "")
        val text = raw.toString()
        if (text.isBlank()) return emptyList()
        val out = ArrayList<Finding>()
        val checks = mapOf(
            "verifiedbootstate" to "ro.boot.verifiedbootstate",
            "flash.locked" to "ro.boot.flash.locked",
            "vbmeta.device_state" to "ro.boot.vbmeta.device_state",
        )
        // spoofing modules tend to patch one source and forget the other
        for ((param, prop) in checks) {
            val m = Regex("androidboot\\.$param=([^\\s\"]+)").find(text) ?: continue
            val live = props[prop] ?: continue
            if (live.isNotEmpty() && live != m.groupValues[1]) {
                out += Finding(
                    "Boot cmdline mismatch",
                    "$prop=${live} but boot cmdline says ${m.groupValues[1]}",
                    danger = true,
                )
            }
        }
        return out
    }

    /** read a few properties through a second path and compare (in-process hook evidence) */
    private fun checkPropSources(props: Map<String, String>): List<Finding> {
        val out = ArrayList<Finding>()
        for (key in listOf("ro.build.fingerprint", "ro.build.tags", "ro.debuggable")) {
            val viaReflection = sysPropViaReflection(key) ?: continue
            val viaGetprop = props[key] ?: continue
            if (viaReflection.isNotEmpty() && viaGetprop.isNotEmpty() && viaReflection != viaGetprop) {
                out += Finding(
                    "Property source mismatch",
                    "$key reads differently via SystemProperties vs getprop (hook evidence)",
                    danger = true,
                )
            }
        }
        return out
    }

    // ---------- SELinux ----------

    private fun checkSelinux(): List<Finding> {
        val out = ArrayList<Finding>()
        var enforcing = false
        when (readText("/sys/fs/selinux/enforce")?.trim()) {
            "0" -> out += Finding("SELinux", "SELinux is permissive", danger = true)
            "1" -> enforcing = true
        }
        if (!enforcing) {
            when (exec("getenforce").trim().lowercase(Locale.US)) {
                "permissive", "disabled" -> out += Finding("SELinux", "getenforce reports non-enforcing", danger = true)
            }
        }
        val ctx = readText("/proc/self/attr/current")?.trim() ?: ""
        if (ctx.isNotEmpty()) {
            if (ctx.contains("magisk") || ctx.contains("su")) {
                out += Finding("SELinux domain", "process runs in a root tool domain: $ctx", danger = true)
            } else if (!ctx.contains("untrusted_app")) {
                out += Finding("SELinux domain", "unusual process domain: $ctx (hint only)", danger = false)
            }
        }
        return out
    }

    // ---------- kernel ----------

    private fun checkKernelVersion(): List<Finding> {
        val v = readText("/proc/version") ?: return emptyList()
        // community kernels often leave emoji / CJK characters / @ handles in the version string
        val marked = v.any { c ->
            (c.code in 0x2E80..0x9FFF) || (c.code in 0x1F000..0x1FAFF) || c == '@'
        }
        // root tooling baked into a custom kernel leaks its own name
        val tokens = KERNEL_TOKENS.filter { v.contains(it, true) }
        return when {
            tokens.isNotEmpty() -> listOf(
                Finding("Kernel traces", "/proc/version carries root-tool tokens (" + tokens.joinToString(", ") + ")", danger = true),
            )
            marked -> listOf(
                Finding("Kernel traces", "/proc/version contains non-standard characters (custom kernel, hint only)", danger = false),
            )
            else -> emptyList()
        }
    }

    /** uname vs /proc/version vs /proc/sys/kernel/osrelease consistency */
    private fun checkKernelIdentity(): List<Finding> {
        val out = ArrayList<Finding>()
        val uname = System.getProperty("os.version") ?: ""
        val osrelease = readText("/proc/sys/kernel/osrelease")?.trim() ?: ""
        val procVersion = readText("/proc/version") ?: ""
        if (uname.isNotEmpty() && osrelease.isNotEmpty() &&
            uname != osrelease && !uname.contains(osrelease) && !osrelease.contains(uname)
        ) {
            out += Finding("Kernel identity", "uname does not match /proc/sys/kernel/osrelease", danger = true)
        }
        if (osrelease.isNotEmpty() && procVersion.isNotEmpty() && !procVersion.contains(osrelease)) {
            out += Finding("Kernel identity", "/proc/version does not contain the kernel release string", danger = true)
        }
        return out
    }

    private fun checkKernelVisibility(): List<Finding> {
        val out = ArrayList<Finding>()
        val osrelease = readText("/proc/sys/kernel/osrelease") ?: ""
        if (osrelease.isNotEmpty()) {
            val tokens = KERNEL_TOKENS.filter { osrelease.contains(it, true) }
            if (tokens.isNotEmpty()) {
                out += Finding("Kernel symbols", "kernel release carries root-tool tokens (" + tokens.joinToString(", ") + ")", danger = true)
            }
        }
        val kallsyms = readText("/proc/kallsyms")
        if (kallsyms != null && kallsyms.length > 1000) {
            out += Finding("Kernel symbols", "/proc/kallsyms readable by the app (kernel pointers exposed, hint only)", danger = false)
            val tokens = KERNEL_TOKENS.filter { kallsyms.contains(it, true) }
            if (tokens.isNotEmpty()) {
                out += Finding("Kernel symbols", "root tool symbols found in kallsyms (" + tokens.joinToString(", ") + ")", danger = true)
            }
        }
        val modules = readText("/proc/modules")
        if (modules != null && modules.isNotEmpty()) {
            val tokens = KERNEL_TOKENS.filter { modules.contains(it, true) }
            if (tokens.isNotEmpty()) {
                out += Finding("Kernel modules", "root tool kernel modules loaded (" + tokens.joinToString(", ") + ")", danger = true)
            }
        }
        return out
    }

    // ---------- own-process status ----------

    private fun checkProcStatus(context: Context): List<Finding> {
        val out = ArrayList<Finding>()
        val status = readText("/proc/self/status") ?: return out
        val tracer = Regex("TracerPid:\\s*(\\d+)").find(status)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        if (tracer != 0) {
            out += Finding("Anti-analysis", "process is being traced by pid $tracer (hint only)", danger = false)
        }
        val uid = Regex("Uid:\\s*(\\d+)").find(status)?.groupValues?.get(1) ?: ""
        if (uid == "0") {
            out += Finding("Root uid", "process runs with uid 0", danger = true)
        }
        // supplementary GID check: zygote grants inet (3003) for INTERNET; frameworks
        // that re-specialize processes can lose it (LSPosed respawn anomaly)
        val groups = Regex("Groups:\\s*([^\\n]*)").find(status)?.groupValues?.get(1) ?: ""
        if (!Regex("\\b3003\\b").containsMatchIn(groups)) {
            val hasInternet = try {
                val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
                info.requestedPermissions?.contains("android.permission.INTERNET") == true
            } catch (t: Throwable) {
                false
            }
            if (hasInternet) {
                out += Finding("Zygote GID", "INTERNET granted but inet (3003) missing from groups (framework anomaly, hint only)", danger = false)
            }
        }
        return out
    }

    // ---------- unix sockets ----------

    private fun checkUnixSockets(): List<Finding> {
        // /proc/net/unix is usually restricted; when readable, root daemons may expose names
        val text = readText("/proc/net/unix") ?: return emptyList()
        val hits = ROOT_TOKENS.filter { text.contains(it, ignoreCase = true) }
        return if (hits.isEmpty()) emptyList()
        else listOf(Finding("Unix sockets", "root tool socket names visible: " + hits.joinToString(", "), danger = true))
    }

    // ---------- emulator device nodes ----------

    private fun checkEmulatorNodes(): List<Finding> {
        val hits = EMULATOR_NODES.filter { File(it).exists() }
        return if (hits.isEmpty()) emptyList()
        else listOf(Finding("Emulator / VM", "emulator device nodes present: " + hits.joinToString(", "), danger = true))
    }

    // ---------- KeyMint attestation (strongest bootloader evidence) ----------

    private fun checkKeyAttestation(): List<Finding> {
        val out = ArrayList<Finding>()
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            keyStore.deleteEntry(ATTESTATION_ALIAS)
            val kpg = java.security.KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
            val spec = android.security.keystore.KeyGenParameterSpec.Builder(
                ATTESTATION_ALIAS,
                android.security.keystore.KeyProperties.PURPOSE_SIGN or android.security.keystore.KeyProperties.PURPOSE_VERIFY,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge("nonative-rootcheck".toByteArray())
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()

            val chain = keyStore.getCertificateChain(ATTESTATION_ALIAS)
            keyStore.deleteEntry(ATTESTATION_ALIAS)
            val cert = chain?.firstOrNull() as? java.security.cert.X509Certificate ?: return emptyList()
            val ext = cert.getExtensionValue(ATTESTATION_OID) ?: return emptyList()

            // extension value is an OCTET STRING wrapping the KeyDescription SEQUENCE
            val outer = readTlv(ext, 0) ?: return emptyList()
            val keyDesc = readTlv(outer.content, 0) ?: return emptyList()
            val fields = readChildren(keyDesc.content)

            // fields: INTEGER attVersion, ENUMERATED attSecLevel, INTEGER kmVersion,
            //         ENUMERATED kmSecLevel, OCTETSTRING challenge, OCTETSTRING uniqueId,
            //         [0] softwareEnforced, [1] teeEnforced
            var attSecLevel = -1
            var sawEnumerated = false
            val authLists = ArrayList<Tlv>()
            for (f in fields) {
                when {
                    !sawEnumerated && f.first == 0x0A -> {
                        attSecLevel = if (f.content.isNotEmpty()) f.content[0].toInt() else -1
                        sawEnumerated = true
                    }
                    (f.first and 0xE0) == 0xA0 -> authLists += f
                }
            }

            // RootOfTrust ::= SEQUENCE { OCTETSTRING vbKey, BOOLEAN deviceLocked,
            //                            ENUMERATED bootState, OCTETSTRING vbHash }
            // tagged [704] inside the AuthorizationList (context-constructed, long form)
            var rootOfTrust: List<Tlv>? = null
            for (list in authLists.asReversed()) { // prefer the TEE list
                val tagged = readChildren(list.content).firstOrNull { (it.first and 0xE0) == 0xA0 && it.tagNum == 704L }
                if (tagged != null) {
                    val seq = readTlv(tagged.content, 0) ?: continue
                    rootOfTrust = readChildren(seq.content)
                    break
                }
            }
            val rot = rootOfTrust ?: return emptyList()
            val locked = rot.getOrNull(1)?.takeIf { it.first == 0x01 && it.content.isNotEmpty() }?.let { it.content[0].toInt() != 0 }
            val bootState = rot.getOrNull(2)?.takeIf { it.first == 0x0A && it.content.isNotEmpty() }?.let { it.content[0].toInt() }

            if (locked == false) {
                out += Finding("Key attestation", "attestation: device is UNLOCKED", danger = true)
            }
            when (bootState) {
                1 -> out += Finding("Key attestation", "verified boot state: SelfSigned (custom key)", danger = true)
                2 -> out += Finding("Key attestation", "verified boot state: Unverified", danger = true)
                3 -> out += Finding("Key attestation", "verified boot state: Failed", danger = true)
            }
            if (attSecLevel == 0) {
                out += Finding("Key attestation", "attestation is software-only (no TEE/hardware key, hint only)", danger = false)
            }
        } catch (t: Throwable) {
            // no keystore / no attestation support — unavailable, no conclusion
        }
        return out
    }

    // ---------- ASN.1 DER helpers ----------

    private class Tlv(val first: Int, val tagNum: Long, val content: ByteArray, val end: Int)

    private fun readTlv(buf: ByteArray, off: Int): Tlv? {
        if (off + 2 > buf.size) return null
        val first = buf[off].toInt() and 0xFF
        var tagNum = (first and 0x1F).toLong()
        var idx = off + 1
        if (tagNum == 0x1FL) {
            tagNum = 0
            var count = 0
            while (idx < buf.size && count < 5) {
                val b = buf[idx].toInt() and 0xFF
                idx++; count++
                tagNum = (tagNum shl 7) or (b and 0x7F).toLong()
                if (b and 0x80 == 0) break
            }
        }
        if (idx >= buf.size) return null
        var len = buf[idx].toInt() and 0xFF
        idx++
        if (len and 0x80 != 0) {
            val n = len and 0x7F
            if (n == 0 || n > 4 || idx + n > buf.size) return null
            len = 0
            repeat(n) {
                len = (len shl 8) or (buf[idx].toInt() and 0xFF)
                idx++
            }
        }
        if (idx + len > buf.size) return null
        return Tlv(first, tagNum, buf.copyOfRange(idx, idx + len), idx + len)
    }

    private fun readChildren(content: ByteArray): List<Tlv> {
        val out = ArrayList<Tlv>()
        var off = 0
        while (off < content.size) {
            val tlv = readTlv(content, off) ?: break
            out += tlv
            off = tlv.end
        }
        return out
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    // ---------- utilities ----------

    private fun sysPropViaReflection(key: String): String? = try {
        val clazz = Class.forName("android.os.SystemProperties")
        val get = clazz.getMethod("get", String::class.java)
        (get.invoke(null, key) as? String)?.ifEmpty { null }
    } catch (t: Throwable) {
        null
    }

    private fun exec(vararg cmd: String): String = try {
        val p = ProcessBuilder(*cmd).start()
        val out = p.inputStream.bufferedReader().readText().trim()
        p.waitFor()
        out
    } catch (t: Throwable) {
        ""
    }

    private fun readText(path: String): String? = try {
        File(path).inputStream().bufferedReader().use { it.readText() }
    } catch (t: Throwable) {
        null
    }

    private fun readProps(): Map<String, String> = try {
        val p = ProcessBuilder("getprop").start()
        val out = p.inputStream.bufferedReader().readText()
        p.waitFor()
        Regex("\\[(.*?)\\]:\\s*\\[(.*?)\\]").findAll(out)
            .associate { it.groupValues[1] to it.groupValues[2] }
    } catch (t: Throwable) {
        emptyMap()
    }
}
