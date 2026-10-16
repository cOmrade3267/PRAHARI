package com.prahari.auditor.reversing

import android.content.Context
import com.prahari.auditor.core.AppRecord
import com.prahari.auditor.core.AttackStep
import com.prahari.auditor.core.CodeEvidence
import com.prahari.auditor.core.Tokens
import com.prahari.auditor.engine.ReverseEngineer
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.reference.FieldReference
import org.jf.dexlib2.iface.reference.MethodReference
import org.jf.dexlib2.iface.reference.StringReference
import org.jf.dexlib2.iface.reference.TypeReference
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * PLAN §2 on-device static reverse engineering (ported from ../../spike-re, proven to run on
 * Android). Opens the installed APK with no root, walks the DEX with dexlib2, and reports which
 * dangerous APIs the code actually references → capability tokens + human hits + the attack chain.
 * Also lists native libs and hashes the APK. Returns null if the APK can't be read (the orchestrator
 * then keeps the PackageManager-only result for that app).
 *
 * Everything is bounded (string/class caps + a reference-instruction budget) so a hostile or huge
 * APK cannot exhaust memory or hang the scan.
 */
class StaticReverseEngineer(private val context: Context) : ReverseEngineer {

    override suspend fun analyze(app: AppRecord): CodeEvidence? {
        val path = app.apkPath ?: return null
        val file = File(path)
        if (!file.exists() || !file.canRead()) return null // graceful fallback (PLAN §7)

        val caps = LinkedHashSet<String>()
        val hits = LinkedHashSet<String>()
        val classNames = LinkedHashSet<String>()
        val strings = ArrayList<String>(1024)

        val dexOk = try {
            val container = DexFileFactory.loadDexContainer(file, Opcodes.getDefault())
            var refBudget = MAX_REFERENCES
            scan@ for (entryName in container.dexEntryNames) {
                val dexFile = container.getEntry(entryName)?.dexFile ?: continue
                for (classDef in dexFile.classes) {
                    if (classNames.size < MAX_CLASSES) classNames.add(classDef.type)
                    for (method in classDef.methods) {
                        val impl = method.implementation ?: continue
                        for (insn in impl.instructions) {
                            if (insn !is ReferenceInstruction) continue
                            val ref = try { insn.reference } catch (_: Exception) { continue }
                            when (ref) {
                                is MethodReference -> {
                                    match(ref.definingClass + "->" + ref.name, caps, hits)
                                    match(ref.definingClass, caps, hits)
                                }
                                is FieldReference -> match(ref.definingClass, caps, hits)
                                is TypeReference -> match(ref.type, caps, hits)
                                is StringReference -> if (strings.size < MAX_STRINGS) {
                                    val s = ref.string
                                    strings.add(if (s.length > MAX_STRING_LEN) s.substring(0, MAX_STRING_LEN) else s)
                                }
                            }
                            if (--refBudget <= 0) break@scan
                        }
                    }
                }
            }
            true
        } catch (_: Throwable) {
            false // manifest/metadata still came from inventory; mark not deep-scanned
        }

        return CodeEvidence(
            capabilityTokens = caps,
            dangerousApiHits = hits.toList(),
            dexClassNames = classNames,
            dexStrings = strings,
            nativeLibNames = nativeLibs(file),
            attackChain = attackChain(caps),
            apkSha256 = sha256OfFile(file),
            deepScanned = dexOk,
        )
    }

    private fun match(signature: String, caps: MutableSet<String>, hits: MutableSet<String>) {
        for ((needle, cap, label) in DANGEROUS) {
            if (signature.contains(needle)) {
                if (cap != null) caps.add(cap)
                hits.add(label)
            }
        }
    }

    private fun attackChain(caps: Set<String>): List<AttackStep> {
        val steps = ArrayList<AttackStep>()
        if (Tokens.SMS_READ in caps) steps += AttackStep("Read your OTPs / texts", "SMS-read API referenced")
        if (Tokens.CONTACTS in caps || Tokens.CALL_LOG in caps) steps += AttackStep("Harvest your contacts / call log", "contacts/call-log API referenced")
        if (Tokens.LOCATION in caps) steps += AttackStep("Track your location", "location API referenced")
        if (Tokens.SCREEN_CAPTURE in caps) steps += AttackStep("Watch your screen", "MediaProjection referenced")
        if (Tokens.ACCESSIBILITY in caps) steps += AttackStep("Control the UI / auto-tap", "accessibility performGlobalAction referenced")
        if (Tokens.NETWORK in caps) steps += AttackStep("Send it off the device", "network sink referenced")
        if (Tokens.SMS_SEND in caps) steps += AttackStep("Send SMS silently", "SMS-send API referenced")
        if (Tokens.DYNAMIC_CODE in caps) steps += AttackStep("Load more code at runtime", "dynamic class loader referenced")
        if (Tokens.INSTALL_PACKAGES in caps) steps += AttackStep("Install further apps", "PackageInstaller referenced")
        return steps
    }

    private fun nativeLibs(apk: File): List<String> = try {
        ZipFile(apk).use { zf ->
            zf.entries().asSequence()
                .map { it.name }
                .filter { it.startsWith("lib/") && it.endsWith(".so") }
                .take(MAX_NATIVE_LIBS)
                .toList()
        }
    } catch (_: Exception) {
        emptyList()
    }

    private fun sha256OfFile(f: File): String? = try {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { ins ->
            val buf = ByteArray(1 shl 16)
            while (true) {
                val n = ins.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        val d = md.digest()
        val sb = StringBuilder(d.size * 2)
        for (b in d) {
            val v = b.toInt() and 0xFF
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0x0F])
        }
        sb.toString()
    } catch (_: Exception) {
        null
    }

    private companion object {
        const val MAX_REFERENCES = 400_000
        const val MAX_CLASSES = 50_000
        const val MAX_STRINGS = 20_000
        const val MAX_STRING_LEN = 512
        const val MAX_NATIVE_LIBS = 64

        /** (needle, capability-token-or-null, human label). Matched by substring on DEX signatures. */
        val DANGEROUS: List<Triple<String, String?, String>> = listOf(
            Triple("Landroid/telephony/SmsManager;->sendTextMessage", Tokens.SMS_SEND, "Sends SMS (premium fraud / OTP relay)"),
            Triple("Landroid/telephony/SmsManager;->sendMultipartTextMessage", Tokens.SMS_SEND, "Sends multipart SMS"),
            Triple("Landroid/telephony/SmsMessage;", Tokens.SMS_READ, "Reads SMS content"),
            Triple("Landroid/provider/Telephony\$Sms", Tokens.SMS_READ, "Reads the SMS inbox"),
            Triple("Landroid/accessibilityservice/AccessibilityService;", Tokens.ACCESSIBILITY, "Uses an accessibility service"),
            Triple("->performGlobalAction", Tokens.ACCESSIBILITY, "Injects global UI actions (BACK/HOME)"),
            Triple("Landroid/media/projection/MediaProjection", Tokens.SCREEN_CAPTURE, "Captures the screen"),
            Triple("Ldalvik/system/DexClassLoader;", Tokens.DYNAMIC_CODE, "Loads code dynamically (DexClassLoader)"),
            Triple("Ldalvik/system/InMemoryDexClassLoader;", Tokens.DYNAMIC_CODE, "Loads code dynamically (in-memory dex)"),
            Triple("Ljava/lang/Runtime;->exec", Tokens.PROCESS_EXEC, "Executes processes (Runtime.exec)"),
            Triple("Ljava/lang/ProcessBuilder;", Tokens.PROCESS_EXEC, "Executes processes (ProcessBuilder)"),
            Triple("Ljava/lang/reflect/Method;->invoke", Tokens.REFLECTION, "Uses reflection (obfuscation)"),
            Triple("Ljava/lang/Class;->forName", Tokens.REFLECTION, "Loads classes by name (reflection)"),
            Triple("->getInstalledPackages", Tokens.ENUMERATE_PACKAGES, "Enumerates installed apps"),
            Triple("Ljavax/crypto/Cipher;", null, "Uses crypto (possible payload decrypt)"),
            Triple("Landroid/util/Base64;", null, "Uses Base64 (possible payload decode)"),
            Triple("Ljava/net/HttpURLConnection;", Tokens.NETWORK, "Network sink (HTTP)"),
            Triple("Lokhttp3/", Tokens.NETWORK, "Network sink (OkHttp)"),
            Triple("Ljava/net/Socket;", Tokens.NETWORK, "Network sink (raw socket)"),
            Triple("Landroid/location/LocationManager;->requestLocationUpdates", Tokens.LOCATION, "Tracks location"),
            Triple("Lcom/google/android/gms/location/FusedLocation", Tokens.LOCATION, "Tracks location (fused provider)"),
            Triple("Landroid/media/MediaRecorder;", Tokens.MIC, "Records audio"),
            Triple("Landroid/media/AudioRecord;", Tokens.MIC, "Records audio (raw)"),
            Triple("Landroid/hardware/camera2/", Tokens.CAMERA, "Uses the camera"),
            Triple("Landroid/provider/ContactsContract", Tokens.CONTACTS, "Reads contacts"),
            Triple("Landroid/provider/CallLog", Tokens.CALL_LOG, "Reads the call log"),
            Triple("Landroid/content/ClipboardManager;", Tokens.CLIPBOARD, "Reads the clipboard"),
            Triple("Landroid/content/pm/PackageInstaller", Tokens.INSTALL_PACKAGES, "Installs further packages"),
        )
    }
}
