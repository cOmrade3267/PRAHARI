package com.prahari.spike

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import net.dongliu.apk.parser.ApkFile
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.reference.MethodReference
import java.io.File
import java.security.MessageDigest

/**
 * The spike's whole point: prove that on THIS device we can, with no root and no network,
 *
 *   1. read an installed app's APK file (via ApplicationInfo.sourceDir),
 *   2. parse its real manifest permissions with apk-parser,
 *   3. walk its DEX bytecode with dexlib2 and see which dangerous APIs the code actually calls,
 *   4. hash the APK and read its signing certificate.
 *
 * It analyses this app's own APK first (always readable → proves the pipeline end-to-end),
 * then probes a handful of other installed apps to empirically answer the one open question
 * from the plan's risk register: "is sourceDir readable for other apps on this OEM/Android build?"
 */
class ReverseEngineer(private val context: Context) {

    data class ApkReport(
        val label: String,
        val path: String,
        val ok: Boolean,
        val error: String? = null,
        val pkg: String? = null,
        val versionName: String? = null,
        val targetSdk: String? = null,
        val permissions: List<String> = emptyList(),
        val apkSha256: String? = null,
        val signerSha256: String? = null,
        val installer: String? = null,
        val totalCalledMethodRefs: Int = 0,
        val sampleMethodRefs: List<String> = emptyList(),
        val dangerousHits: List<String> = emptyList(),
        val dexMillis: Long = 0,
    )

    /** Capability signatures we look for in the DEX call graph (smali "definingClass->name"). */
    private val dangerousApis: List<Pair<String, String>> = listOf(
        "Landroid/telephony/SmsManager;->sendTextMessage" to "Send SMS (premium fraud / OTP relay)",
        "Landroid/telephony/SmsManager;->sendMultipartTextMessage" to "Send multipart SMS",
        "Landroid/telephony/gsm/SmsManager;" to "Send SMS (legacy GSM)",
        "Landroid/accessibilityservice/AccessibilityService;" to "Accessibility service (screen read / auto-tap)",
        "->performGlobalAction" to "Accessibility global action (BACK/HOME injection)",
        "Landroid/media/projection/MediaProjectionManager;" to "Screen capture (MediaProjection)",
        "Ldalvik/system/DexClassLoader;" to "Dynamic code loading (DexClassLoader)",
        "Ldalvik/system/InMemoryDexClassLoader;" to "Dynamic code loading (in-memory dex)",
        "Ljava/lang/Runtime;->exec" to "Process execution (Runtime.exec)",
        "Ljava/lang/ProcessBuilder;" to "Process execution (ProcessBuilder)",
        "Ljava/lang/reflect/Method;->invoke" to "Reflection invoke (obfuscation)",
        "Ljava/lang/Class;->forName" to "Reflection class load",
        "->getInstalledPackages" to "Enumerate installed apps",
        "Ljavax/crypto/Cipher;" to "Crypto (possible payload decrypt)",
        "Landroid/util/Base64;" to "Base64 (possible payload decode)",
        "Ljava/net/HttpURLConnection;" to "Network sink (HTTP)",
        "Ljava/net/Socket;" to "Network sink (raw socket)",
        "Landroid/location/LocationManager;->requestLocationUpdates" to "Location tracking",
        "Landroid/content/ClipboardManager;" to "Clipboard access",
        "Landroid/content/pm/PackageInstaller" to "Installs further packages",
    )

    /** Builds the full human-readable spike report. Call from a background dispatcher. */
    fun runFullSpike(maxOtherApps: Int = 8): String {
        val sb = StringBuilder()
        sb.appendLine("PRAHARI — on-device RE spike")
        sb.appendLine("Device : ${Build.MANUFACTURER} ${Build.MODEL}")
        sb.appendLine("Android: API ${Build.VERSION.SDK_INT} (${Build.VERSION.RELEASE})")
        sb.appendLine("=".repeat(56))

        // 1) Analyse our own APK — guaranteed readable, proves the full pipeline.
        sb.appendLine("\n[1] SELF APK  (pipeline proof — must succeed)")
        val selfPath = context.applicationInfo.sourceDir
        val self = analyzeApk("self: ${context.packageName}", selfPath, context.packageName)
        sb.append(render(self))

        // 2) Probe other installed user apps — answers "is sourceDir readable here?"
        sb.appendLine("\n[2] OTHER INSTALLED APPS  (readability probe)")
        val pm = context.packageManager
        val others = userApps(pm).filter { it.packageName != context.packageName }.take(maxOtherApps)
        if (others.isEmpty()) {
            sb.appendLine("  (no third-party apps found — try a device with some installed)")
        }
        var readable = 0
        for (pi in others) {
            val ai = pi.applicationInfo ?: continue
            val path = ai.sourceDir ?: continue
            val label = labelOf(pm, ai, pi.packageName)
            val r = analyzeApk(label, path, pi.packageName)
            if (r.ok) readable++
            sb.append(render(r, compact = true))
        }

        sb.appendLine("\n" + "=".repeat(56))
        sb.appendLine("READABILITY VERDICT: $readable / ${others.size} other-app APKs parsed on this device.")
        sb.appendLine(
            if (readable == others.size && others.isNotEmpty())
                "=> Deep scan of other apps WORKS here. Tier A is green on this build."
            else if (readable > 0)
                "=> Partial: some APKs blocked. Ship the PackageManager-only fallback for the rest."
            else
                "=> Other-app APKs blocked on this build. Self-APK still works; rely on fallback + record this device."
        )
        return sb.toString()
    }

    /** Parse one APK file: manifest permissions (apk-parser) + DEX refs (dexlib2) + hashes. */
    fun analyzeApk(label: String, path: String, pkg: String?): ApkReport {
        val file = File(path)
        if (!file.exists() || !file.canRead()) {
            return ApkReport(label, path, ok = false, error = "APK not readable at sourceDir")
        }

        // --- manifest (apk-parser) ---
        var pkgName = pkg
        var versionName: String? = null
        var targetSdk: String? = null
        var permissions: List<String> = emptyList()
        try {
            ApkFile(file).use { apk ->
                val meta = apk.apkMeta
                pkgName = meta.packageName ?: pkg
                versionName = meta.versionName
                // getTargetSdkVersion() has returned String across apk-parser versions; normalise.
                targetSdk = meta.targetSdkVersion?.toString()
                permissions = meta.usesPermissions ?: emptyList()
            }
        } catch (e: Throwable) {
            return ApkReport(label, path, ok = false, error = "apk-parser failed: ${e.javaClass.simpleName}: ${e.message}")
        }

        // --- DEX bytecode (dexlib2) ---
        var totalRefs = 0
        val sample = LinkedHashSet<String>()
        val hits = LinkedHashSet<String>()
        var dexMillis = 0L
        try {
            val start = System.nanoTime()
            val container = DexFileFactory.loadDexContainer(file, Opcodes.getDefault())
            for (entryName in container.dexEntryNames) {
                val dexFile = container.getEntry(entryName)?.dexFile ?: continue
                for (classDef in dexFile.classes) {
                    for (method in classDef.methods) {
                        val impl = method.implementation ?: continue
                        for (insn in impl.instructions) {
                            if (insn !is ReferenceInstruction) continue
                            val ref = insn.reference
                            if (ref !is MethodReference) continue
                            val sig = ref.definingClass + "->" + ref.name
                            totalRefs++
                            if (sample.size < 40) sample.add(sig)
                            for ((needle, desc) in dangerousApis) {
                                if (sig.contains(needle)) hits.add(desc)
                            }
                        }
                    }
                }
            }
            dexMillis = (System.nanoTime() - start) / 1_000_000
        } catch (e: Throwable) {
            // Manifest parsed but DEX failed — still a useful partial result.
            return ApkReport(
                label, path, ok = true, error = "dexlib2 failed: ${e.javaClass.simpleName}",
                pkg = pkgName, versionName = versionName, targetSdk = targetSdk,
                permissions = permissions, apkSha256 = safeSha256(file),
                signerSha256 = pkg?.let { signerSha256(context.packageManager, it) },
                installer = pkg?.let { installerOf(context.packageManager, it) },
            )
        }

        return ApkReport(
            label = label, path = path, ok = true,
            pkg = pkgName, versionName = versionName, targetSdk = targetSdk,
            permissions = permissions,
            apkSha256 = safeSha256(file),
            signerSha256 = pkg?.let { signerSha256(context.packageManager, it) },
            installer = pkg?.let { installerOf(context.packageManager, it) },
            totalCalledMethodRefs = totalRefs,
            sampleMethodRefs = sample.toList(),
            dangerousHits = hits.toList(),
            dexMillis = dexMillis,
        )
    }

    // ---------- rendering ----------

    private fun render(r: ApkReport, compact: Boolean = false): String {
        val sb = StringBuilder()
        if (!r.ok) {
            sb.appendLine("  ✗ ${r.label}")
            sb.appendLine("      ${r.error}")
            return sb.toString()
        }
        sb.appendLine("  ✓ ${r.label}")
        sb.appendLine("      pkg=${r.pkg}  v=${r.versionName}  targetSdk=${r.targetSdk}  installer=${r.installer ?: "?"}")
        sb.appendLine("      apk sha256   : ${r.apkSha256?.take(32)}…")
        sb.appendLine("      signer sha256: ${r.signerSha256?.take(32) ?: "n/a"}…")
        sb.appendLine("      permissions  : ${r.permissions.size} declared")
        if (!compact) {
            r.permissions.take(12).forEach { sb.appendLine("         - ${it.substringAfterLast('.')}") }
            if (r.permissions.size > 12) sb.appendLine("         … +${r.permissions.size - 12} more")
        }
        sb.appendLine("      dex refs     : ${r.totalCalledMethodRefs} method calls scanned in ${r.dexMillis} ms")
        if (r.dangerousHits.isEmpty()) {
            sb.appendLine("      capability hits: none of the watched dangerous APIs")
        } else {
            sb.appendLine("      capability hits (${r.dangerousHits.size}):")
            r.dangerousHits.forEach { sb.appendLine("         ⚠ $it") }
        }
        if (!compact && r.sampleMethodRefs.isNotEmpty()) {
            sb.appendLine("      sample method refs:")
            r.sampleMethodRefs.take(10).forEach { sb.appendLine("         $it") }
        }
        return sb.toString()
    }

    // ---------- PackageManager helpers ----------

    @Suppress("DEPRECATION", "QueryPermissionsNeeded")
    private fun userApps(pm: PackageManager): List<PackageInfo> =
        pm.getInstalledPackages(0).filter { pi ->
            val ai = pi.applicationInfo ?: return@filter false
            (ai.flags and ApplicationInfo.FLAG_SYSTEM) == 0 &&
                (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0 &&
                ai.sourceDir != null
        }

    private fun labelOf(pm: PackageManager, ai: ApplicationInfo, pkg: String): String =
        try {
            "${pm.getApplicationLabel(ai)} ($pkg)"
        } catch (_: Exception) {
            pkg
        }

    @Suppress("DEPRECATION")
    private fun installerOf(pm: PackageManager, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            pm.getInstallerPackageName(pkg)
        }
    } catch (_: Exception) {
        null
    }

    @Suppress("DEPRECATION")
    private fun signerSha256(pm: PackageManager, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 28) {
            val pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
            pi.signingInfo?.apkContentsSigners?.firstOrNull()?.let { sha256Bytes(it.toByteArray()) }
        } else {
            val pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
            pi.signatures?.firstOrNull()?.let { sha256Bytes(it.toByteArray()) }
        }
    } catch (_: Exception) {
        null
    }

    // ---------- hashing ----------

    private fun safeSha256(file: File): String? = try {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { ins ->
            val buf = ByteArray(1 shl 16)
            while (true) {
                val n = ins.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        md.digest().toHex()
    } catch (_: Exception) {
        null
    }

    private fun sha256Bytes(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

    private fun ByteArray.toHex(): String {
        val out = StringBuilder(size * 2)
        for (b in this) {
            val v = b.toInt() and 0xFF
            out.append("0123456789abcdef"[v ushr 4])
            out.append("0123456789abcdef"[v and 0x0F])
        }
        return out.toString()
    }
}
