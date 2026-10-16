package com.prahari.auditor.core

/**
 * Prahari domain model — the contracts the whole app is built around.
 * (Data classes only; no behaviour. See engine/ for the pipeline that produces these.)
 */

/** Risk bands per PLAN §5.6. */
enum class RiskBand { LOW, MEDIUM, HIGH, CRITICAL }

/** Android permission protection levels (FR02). */
enum class ProtectionLevel { NORMAL, DANGEROUS, SIGNATURE, SPECIAL, UNKNOWN }

/** Where the app came from (affects scoring per PLAN §5.2). */
enum class InstallerSource { PLAY_STORE, OTHER_STORE, SIDELOADED, PREINSTALLED, UNKNOWN }

/**
 * One permission's three-state triangulation — the core differentiator (PLAN §2.3a):
 * declared (manifest) vs granted (runtime/AppOps) vs usedInCode (a matching dangerous API is
 * referenced in the DEX).
 */
data class PermissionState(
    val name: String,
    val category: Category?,
    val protection: ProtectionLevel,
    val declared: Boolean,
    val granted: Boolean,
    val usedInCode: Boolean,
)

/** Special-access grants (FR04) — the highest-weight category. */
data class SpecialAccess(
    val accessibilityEnabled: Boolean = false,
    val deviceAdminActive: Boolean = false,
    val notificationListenerEnabled: Boolean = false,
    val overlayDeclared: Boolean = false,
    val overlayGranted: Boolean = false,
    val requestInstallPackages: Boolean = false,
    val usageStatsGranted: Boolean = false,
)

/** One step of an attack-chain narrative (PLAN §2.4). */
data class AttackStep(val action: String, val evidence: String)

/** Static-RE findings for one app (PLAN §2.1–2.3). Null when the APK couldn't be deep-scanned. */
data class CodeEvidence(
    /** cap.* / ctx.* / src.* / flag.* tokens for the intel engine + combos. */
    val capabilityTokens: Set<String> = emptySet(),
    /** Human-readable dangerous-API hits found in the DEX. */
    val dangerousApiHits: List<String> = emptyList(),
    /** Smali class descriptors (for packer rules). */
    val dexClassNames: Set<String> = emptySet(),
    /** Bounded sample of DEX string constants (for target-list / C2 rules). */
    val dexStrings: List<String> = emptyList(),
    /** lib/*/*.so entry names. */
    val nativeLibNames: List<String> = emptyList(),
    val attackChain: List<AttackStep> = emptyList(),
    /** SHA-256 of the base APK (the RE stage reads the file, so it computes this). */
    val apkSha256: String? = null,
    /** True if the APK was readable and parsed; false ⇒ PackageManager-only fallback was used. */
    val deepScanned: Boolean = false,
)

/** One plain-language reason behind a score (FR05). `technical` is the analyst-mode evidence. */
data class Reason(val text: String, val weight: Int, val technical: String? = null)

/** The explained risk result for one app (FR05 + PLAN §5). */
data class RiskResult(
    val score: Int,
    val band: RiskBand,
    val reasons: List<Reason>,
    val mlProbability: Float? = null,
)

/** Everything known about one installed app after a scan. Icons are loaded by the UI, not stored. */
data class AppRecord(
    val packageName: String,
    val label: String,
    val versionName: String? = null,
    val versionCode: Long = 0,
    val installDateMillis: Long = 0,
    val installer: InstallerSource = InstallerSource.UNKNOWN,
    val targetSdk: Int = 0,
    val isSystem: Boolean = false,
    val apkPath: String? = null,
    val apkSha256: String? = null,
    val signerSha256: String? = null,
    /** Static manifest-flag tokens (stretch #12): flag.debuggable / flag.cleartext / flag.allow_backup /
     *  flag.exported_unguarded. */
    val manifestFlags: Set<String> = emptySet(),
    val permissions: List<PermissionState> = emptyList(),
    val specialAccess: SpecialAccess = SpecialAccess(),
    val codeEvidence: CodeEvidence? = null,
    val risk: RiskResult? = null,
) {
    /** Category → granted permissions in it (for the per-app category view, FR03). */
    fun grantedByCategory(): Map<Category, List<PermissionState>> =
        permissions.filter { it.granted && it.category != null }
            .groupBy { it.category!! }
}

/** A point-in-time record for the Trust Timeline + permission diff (FR09/FR10, PLAN §D5). */
data class ScanSnapshot(
    val packageName: String,
    val versionCode: Long,
    val scannedAtMillis: Long,
    val score: Int,
    val band: RiskBand,
    val grantedPermissions: Set<String>,
)
