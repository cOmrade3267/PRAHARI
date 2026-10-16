package com.prahari.auditor.scoring

import com.prahari.auditor.core.AppRecord
import com.prahari.auditor.core.Category
import com.prahari.auditor.core.InstallerSource
import com.prahari.auditor.core.Reason
import com.prahari.auditor.core.RiskBand
import com.prahari.auditor.core.RiskResult
import com.prahari.auditor.core.SpecialAccess
import com.prahari.auditor.core.Tokens
import com.prahari.auditor.engine.ScoringEngine
import com.prahari.intel.IntelEngine
import kotlin.math.roundToInt

/**
 * The PLAN §5 rule model, and the single source of risk explanations.
 *
 * Scoring owns: §5.1 category base weights, §5.2 multipliers (used-in-code ×1.5, installer source,
 * old-targetSdk), special-access points, §5.5 intel overrides, band mapping, and the reasons.
 * Combination logic (§5.3/§5.4) lives in the offline intel pack's comboRules — this engine simply
 * folds every IntelHit's weight in (and honours forcesCritical + the context-mismatch floor), so
 * there is one source of combination truth and no double-counting.
 */
class RuleScoringEngine : ScoringEngine {

    override fun score(app: AppRecord, intelHits: List<IntelEngine.IntelHit>, mlProbability: Float?): RiskResult {
        val reasons = ArrayList<Reason>()
        var raw = 0.0
        val mult = installerMultiplier(app.installer)

        // §5.1/§5.2 — granted permissions by category (special access handled separately).
        val byCat = LinkedHashMap<Category, MutableList<String>>()
        val usedCats = HashSet<Category>()
        for (p in app.permissions) {
            val cat = p.category ?: continue
            if (!p.granted || cat == Category.SPECIAL_ACCESS) continue
            byCat.getOrPut(cat) { mutableListOf() }.add(p.name.substringAfterLast('.'))
            if (p.usedInCode) usedCats.add(cat)
        }
        for ((cat, perms) in byCat) {
            val used = cat in usedCats
            val contribution = cat.baseWeight * (if (used) USED_MULTIPLIER else 1.0) * mult
            raw += contribution
            reasons += Reason(
                text = buildString {
                    append("Can access ${cat.display.lowercase()}")
                    if (used) append(", and its code uses it")
                    append(".")
                },
                weight = contribution.roundToInt(),
                technical = perms.joinToString(", "),
            )
        }

        // §5.1 — special access (highest weight, 25 each).
        for ((text, tech) in specialAccessItems(app.specialAccess)) {
            val w = Category.SPECIAL_ACCESS.baseWeight * mult
            raw += w
            reasons += Reason(text, w.roundToInt(), tech)
        }

        // §5.2 — legacy target SDK.
        if (app.targetSdk in 1..22) {
            raw += LEGACY_SDK_BONUS
            reasons += Reason(
                "Targets an old Android version (API ${app.targetSdk}) with the weaker legacy permission model.",
                LEGACY_SDK_BONUS,
            )
        }

        // §5.2 — note the sideload (the multiplier is already applied above).
        if (app.installer == InstallerSource.SIDELOADED) {
            reasons += Reason("Installed from outside an app store (sideloaded).", 0, "no installer package")
        }

        // §5.5 / stretch #12 — static manifest checks.
        val mflags = app.manifestFlags
        if (Tokens.FLAG_DEBUGGABLE in mflags) {
            raw += 10; reasons += Reason("Ships as debuggable — its internals are exposed.", 10, "android:debuggable=true")
        }
        if (Tokens.FLAG_EXPORTED_UNGUARDED in mflags) {
            raw += 10; reasons += Reason("Exposes components to other apps with no permission guard.", 10, "exported component without android:permission")
        }
        if (Tokens.FLAG_CLEARTEXT in mflags) {
            raw += 5; reasons += Reason("Allows unencrypted (cleartext) network traffic.", 5, "usesCleartextTraffic=true")
        }
        if (Tokens.FLAG_ALLOW_BACKUP in mflags) {
            raw += 3; reasons += Reason("Allows its data to be backed up and extracted.", 3, "android:allowBackup=true")
        }

        // §5.3/§5.4/§5.5 — intel pack hits (combos, context mismatch, packers, target lists, C2, IOC).
        var forceCritical = false
        var floorHigh = false
        for (h in intelHits) {
            raw += h.weight
            if (h.forcesCritical) forceCritical = true
            if (h.ruleId == "combo.context_mismatch") floorHigh = true
            reasons += Reason(
                text = h.label + (h.family?.let { " [$it]" } ?: ""),
                weight = h.weight,
                technical = h.evidence,
            )
        }

        var score = raw.roundToInt().coerceIn(0, 100)
        var band = bandOf(score)

        // §5.4 — context mismatch is always at least High.
        if (floorHigh && band < RiskBand.HIGH) {
            band = RiskBand.HIGH
            if (score < 50) score = 50
        }
        // §5.5 — IOC / bad-signer hit forces Critical.
        if (forceCritical) {
            band = RiskBand.CRITICAL
            score = 100
        }

        reasons.sortByDescending { it.weight }
        return RiskResult(score = score, band = band, reasons = reasons, mlProbability = mlProbability)
    }

    private fun specialAccessItems(sa: SpecialAccess): List<Pair<String, String?>> {
        val items = ArrayList<Pair<String, String?>>()
        if (sa.accessibilityEnabled)
            items += "Has an Accessibility service enabled — can read the screen and tap on your behalf." to "special access (accessibility)"
        if (sa.deviceAdminActive)
            items += "Is an active Device Administrator — can lock the device and resist uninstall." to "special access (device admin)"
        if (sa.notificationListenerEnabled)
            items += "Can read all your notifications, including one-time codes." to "special access (notification listener)"
        if (sa.overlayGranted)
            items += "Can draw over other apps — used for fake login overlays." to "special access (overlay)"
        if (sa.requestInstallPackages)
            items += "Can install other apps on your device." to "special access (install packages)"
        if (sa.usageStatsGranted)
            items += "Can see which apps you open and when." to "special access (usage stats)"
        return items
    }

    private fun installerMultiplier(src: InstallerSource): Double = when (src) {
        InstallerSource.PLAY_STORE, InstallerSource.PREINSTALLED -> 1.0
        InstallerSource.OTHER_STORE -> 1.2
        InstallerSource.SIDELOADED, InstallerSource.UNKNOWN -> 1.5
    }

    private fun bandOf(score: Int): RiskBand = when {
        score >= 75 -> RiskBand.CRITICAL
        score >= 50 -> RiskBand.HIGH
        score >= 25 -> RiskBand.MEDIUM
        else -> RiskBand.LOW
    }

    private companion object {
        const val USED_MULTIPLIER = 1.5
        const val LEGACY_SDK_BONUS = 8
    }
}
