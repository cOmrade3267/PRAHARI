package com.prahari.intel

import android.content.Context
import org.json.JSONObject
import java.util.Locale

/**
 * Offline threat-intelligence engine for the Prahari auditor.
 *
 * Loads a bundled rules.json (+ IOC hash / bad-signer lists) from assets and matches an app's
 * static facts against it. No network, ever. Everything is bounded so a hostile APK cannot make
 * the scan blow up (string count + length caps, pre-compiled linear regexes).
 *
 * Wire-up: the RE engine (see ../PLAN.md §2) produces [AppFacts]; the scoring engine consumes the
 * returned [IntelHit] weights (IOC/signer hits force Critical per PLAN §5.5).
 */
class IntelEngine private constructor(
    private val packers: List<PackerRule>,
    private val nativePackers: List<NativePackerRule>,
    private val targetLists: List<TargetListRule>,
    private val c2Patterns: List<C2Rule>,
    private val combos: List<ComboRule>,
    private val iocHashes: Set<String>,
    private val badSigners: Set<String>,
    private val iocWeight: Int,
    private val badSignerWeight: Int,
) {

    /** Static facts about one app, assembled by the RE + inventory layers. */
    data class AppFacts(
        val packageName: String,
        /** cap.* / ctx.* / src.* / flag.* tokens the caller derived (see README vocabulary). */
        val tokens: Set<String> = emptySet(),
        /** Full permission names, e.g. "android.permission.READ_SMS". */
        val permissions: Set<String> = emptySet(),
        /** Smali class descriptors, e.g. "Lcom/foo/Bar;". */
        val dexClassNames: Set<String> = emptySet(),
        /** Bounded sample of DEX string constants. */
        val dexStrings: List<String> = emptyList(),
        /** Native lib entries, e.g. "lib/arm64-v8a/libshell.so" or "libshell.so". */
        val nativeLibNames: List<String> = emptyList(),
        val signerSha256: String? = null,
        val apkSha256: String? = null,
    )

    data class IntelHit(
        val ruleId: String,
        val label: String,
        val weight: Int,
        val family: String?,
        val evidence: String,
        val forcesCritical: Boolean = false,
    )

    data class PackerRule(val id: String, val label: String, val classPrefixes: List<String>, val weight: Int)
    data class NativePackerRule(val id: String, val label: String, val libNameContains: List<String>, val weight: Int)
    data class TargetListRule(val id: String, val label: String, val packageNames: List<String>, val threshold: Int, val weight: Int, val family: String?)
    data class C2Rule(val id: String, val label: String, val regex: Regex, val weight: Int, val heuristic: Boolean)
    data class ComboRule(val id: String, val label: String, val allOf: Set<String>, val anyOf: Set<String>, val noneOf: Set<String>, val weight: Int, val family: String?)

    fun evaluate(facts: AppFacts): List<IntelHit> {
        val hits = ArrayList<IntelHit>()

        // --- exact IOC matches (force Critical) ---
        facts.apkSha256?.lowercase(Locale.ROOT)?.let { h ->
            if (h in iocHashes) hits += IntelHit("ioc.apk_sha256", "APK hash is on the offline IOC list", iocWeight, "known-ioc", h, forcesCritical = true)
        }
        facts.signerSha256?.lowercase(Locale.ROOT)?.let { s ->
            if (s in badSigners) hits += IntelHit("ioc.bad_signer", "Signing certificate is on the bad-signer list", badSignerWeight, "known-ioc", s, forcesCritical = true)
        }

        // --- packers (DEX class-name prefixes) ---
        for (p in packers) {
            val match = p.classPrefixes.firstNotNullOfOrNull { pre ->
                facts.dexClassNames.firstOrNull { it.startsWith(pre) }
            }
            if (match != null) hits += IntelHit(p.id, p.label, p.weight, "packed", "class $match")
        }

        // --- native packers (.so names) ---
        for (np in nativePackers) {
            val match = np.libNameContains.firstNotNullOfOrNull { needle ->
                facts.nativeLibNames.firstOrNull { it.lowercase(Locale.ROOT).contains(needle.lowercase(Locale.ROOT)) }
            }
            if (match != null) hits += IntelHit(np.id, np.label, np.weight, "packed", "native lib $match")
        }

        // Bounded view of DEX strings for all string-based scans.
        val scan = facts.dexStrings.asSequence()
            .take(MAX_STRINGS)
            .map { if (it.length > MAX_STRING_LEN) it.substring(0, MAX_STRING_LEN) else it }
            .toList()

        // --- target lists (embedded victim package names) ---
        for (t in targetLists) {
            val found = LinkedHashSet<String>()
            for (name in t.packageNames) {
                if (scan.any { it.contains(name) }) {
                    found += name
                    if (found.size >= t.threshold + 3) break // enough evidence
                }
            }
            if (found.size >= t.threshold) {
                val sample = found.take(4).joinToString(", ")
                hits += IntelHit(t.id, t.label, t.weight, t.family, "${found.size} target package names incl. $sample")
            }
        }

        // --- C2 / dead-drop patterns ---
        for (c in c2Patterns) {
            val hit = scan.firstOrNull { c.regex.containsMatchIn(it) }
            if (hit != null) {
                val ev = if (hit.length > 80) hit.substring(0, 80) + "…" else hit
                hits += IntelHit(c.id, c.label + if (c.heuristic) " (heuristic)" else "", c.weight, "c2", "string \"$ev\"")
            }
        }

        // --- combination rules over the token universe ---
        val universe = HashSet(facts.tokens)
        for (perm in facts.permissions) universe += "perm." + perm.substringAfterLast('.')
        for (r in combos) {
            val allOk = r.allOf.all { it in universe }
            val anyOk = r.anyOf.isEmpty() || r.anyOf.any { it in universe }
            val noneOk = r.noneOf.none { it in universe }
            if (allOk && anyOk && noneOk) {
                val why = (r.allOf + r.anyOf.filter { it in universe }).joinToString("+")
                hits += IntelHit(r.id, r.label, r.weight, r.family, why)
            }
        }

        return hits
    }

    companion object {
        private const val MAX_STRINGS = 50_000
        private const val MAX_STRING_LEN = 4_096

        /** Convenience loader: reads assets/<dir>/rules.json and the referenced IOC/signer files. */
        fun fromAssets(context: Context, dir: String = "intel"): IntelEngine {
            val am = context.assets
            val rulesText = am.open("$dir/rules.json").bufferedReader().use { it.readText() }
            val root = JSONObject(rulesText)

            val packers = root.optJSONArray("packers").mapObjects {
                PackerRule(it.getString("id"), it.getString("label"), it.getJSONArray("classPrefixes").toStringList(), it.optInt("weight", 10))
            }
            val nativePackers = root.optJSONArray("nativePackers").mapObjects {
                NativePackerRule(it.getString("id"), it.getString("label"), it.getJSONArray("libNameContains").toStringList(), it.optInt("weight", 10))
            }
            val targetLists = root.optJSONArray("targetLists").mapObjects {
                TargetListRule(it.getString("id"), it.getString("label"), it.getJSONArray("packageNames").toStringList(), it.optInt("threshold", 5), it.optInt("weight", 20), it.optStringOrNull("family"))
            }
            val c2 = root.optJSONArray("c2Patterns").mapObjects {
                C2Rule(it.getString("id"), it.getString("label"), Regex(it.getString("regex"), RegexOption.IGNORE_CASE), it.optInt("weight", 10), it.optBoolean("heuristic", false))
            }
            val combos = root.optJSONArray("comboRules").mapObjects {
                ComboRule(
                    it.getString("id"), it.getString("label"),
                    it.optJSONArray("allOf").toStringList().toSet(),
                    it.optJSONArray("anyOf").toStringList().toSet(),
                    it.optJSONArray("noneOf").toStringList().toSet(),
                    it.optInt("weight", 10), it.optStringOrNull("family"),
                )
            }

            val iocHashes = readHashList(context, dir, root.optString("iocHashFile", "ioc_hashes.txt"))
            val badSigners = readHashList(context, dir, root.optString("badSignerFile", "bad_signers.txt"))

            return IntelEngine(
                packers, nativePackers, targetLists, c2, combos,
                iocHashes, badSigners,
                root.optInt("iocWeight", 100), root.optInt("badSignerWeight", 100),
            )
        }

        private fun readHashList(context: Context, dir: String, file: String): Set<String> = try {
            context.assets.open("$dir/$file").bufferedReader().useLines { lines ->
                lines.map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .map { it.substringBefore(' ').lowercase(Locale.ROOT) } // allow "<hash>  label" lines
                    .filter { it.matches(Regex("[0-9a-f]{64}")) }
                    .toSet()
            }
        } catch (_: Exception) {
            emptySet()
        }

        // --- tiny org.json helpers ---
        private fun org.json.JSONArray?.toStringList(): List<String> {
            if (this == null) return emptyList()
            val out = ArrayList<String>(length())
            for (i in 0 until length()) out.add(getString(i))
            return out
        }

        private fun <T> org.json.JSONArray?.mapObjects(f: (JSONObject) -> T): List<T> {
            if (this == null) return emptyList()
            val out = ArrayList<T>(length())
            for (i in 0 until length()) out.add(f(getJSONObject(i)))
            return out
        }

        private fun JSONObject.optStringOrNull(key: String): String? =
            if (isNull(key) || !has(key)) null else optString(key)
    }
}
