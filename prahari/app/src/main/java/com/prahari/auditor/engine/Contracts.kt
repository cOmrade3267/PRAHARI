package com.prahari.auditor.engine

import com.prahari.auditor.core.AppRecord
import com.prahari.auditor.core.CapabilityMap
import com.prahari.auditor.core.Category
import com.prahari.auditor.core.CodeEvidence
import com.prahari.auditor.core.RiskResult
import com.prahari.auditor.core.ScanSnapshot
import com.prahari.auditor.core.TokenDeriver
import com.prahari.intel.IntelEngine

/**
 * The pipeline contracts + the [AppAuditor] orchestrator (PLAN §4).
 */

/** FR01 inventory + FR02/FR04 permission & special-access extraction (no deep RE, no scoring). */
interface InventoryScanner {
    suspend fun inventory(includeSystem: Boolean): List<AppRecord>
}

/** PLAN §2 static reverse engineering. Returns null when the APK can't be read (graceful fallback). */
interface ReverseEngineer {
    suspend fun analyze(app: AppRecord): CodeEvidence?
}

/** PLAN §5 rule scoring + explanations. The rule score is always the source of explanations. */
interface ScoringEngine {
    fun score(app: AppRecord, intelHits: List<IntelEngine.IntelHit>, mlProbability: Float?): RiskResult
}

/** PLAN §5.7 on-device ML second opinion. Returns null when no model is bundled. */
interface MalwareModel {
    fun scoreMalware(grantedPermissions: Set<String>): Float?
}

/** Persistence for scans + the Trust Timeline / permission diff (FR09/FR10). Caller supplies the clock. */
interface ScanRepository {
    suspend fun save(apps: List<AppRecord>, nowMillis: Long)
    suspend fun latest(): List<AppRecord>
    suspend fun history(packageName: String): List<ScanSnapshot>
}

/**
 * Orchestrator — wires the four engines + intel pack into one scan.
 * Flow per app: inventory → RE → enrich (apkSha256 + declared→granted→USED) → intel → ML → score.
 */
class AppAuditor(
    private val inventory: InventoryScanner,
    private val reverser: ReverseEngineer,
    private val intel: IntelEngine,
    private val model: MalwareModel,
    private val scoring: ScoringEngine,
    private val repo: ScanRepository,
) {
    /** Full device scan, ranked by risk (Q1). onProgress(done, total) drives the UI bar. */
    suspend fun runScan(
        includeSystem: Boolean,
        nowMillis: Long,
        onProgress: (Int, Int) -> Unit = { _, _ -> },
    ): List<AppRecord> {
        val base = inventory.inventory(includeSystem)
        val results = ArrayList<AppRecord>(base.size)
        base.forEachIndexed { i, app ->
            results += analyzeApp(app)
            onProgress(i + 1, base.size)
        }
        val ranked = results.sortedByDescending { it.risk?.score ?: 0 }
        repo.save(ranked, nowMillis)
        return ranked
    }

    /** Analyze a single package (used by install monitoring, FR09). Reuses the full scan so history
     *  is kept too; install events are rare so the extra work is fine. */
    suspend fun analyzeOne(packageName: String, nowMillis: Long): AppRecord? =
        runScan(includeSystem = true, nowMillis = nowMillis).firstOrNull { it.packageName == packageName }

    private suspend fun analyzeApp(app: AppRecord): AppRecord {
        val enriched = enrich(app, reverser.analyze(app))
        val intelHits = intel.evaluate(buildFacts(enriched))
        val granted = enriched.permissions.filter { it.granted }.map { it.name }.toSet()
        val risk = scoring.score(enriched, intelHits, model.scoreMalware(granted))
        return enriched.copy(risk = risk)
    }

    /** Fold RE output back into the AppRecord: APK hash + the declared→granted→USED flag. */
    private fun enrich(app: AppRecord, ev: CodeEvidence?): AppRecord {
        if (ev == null) return app.copy(codeEvidence = null)
        val usedCats: Set<Category> = ev.capabilityTokens.mapNotNull { CapabilityMap.categoryOf(it) }.toHashSet()
        val perms = app.permissions.map { it.copy(usedInCode = it.category != null && it.category in usedCats) }
        return app.copy(permissions = perms, codeEvidence = ev, apkSha256 = ev.apkSha256 ?: app.apkSha256)
    }

    private fun buildFacts(app: AppRecord): IntelEngine.AppFacts {
        val ev = app.codeEvidence
        return IntelEngine.AppFacts(
            packageName = app.packageName,
            // Inventory-derived tokens make the intel combo rules fire; RE tokens merge on top.
            tokens = TokenDeriver.tokens(app) + (ev?.capabilityTokens ?: emptySet()),
            permissions = app.permissions.filter { it.declared || it.granted }.map { it.name }.toSet(),
            dexClassNames = ev?.dexClassNames ?: emptySet(),
            dexStrings = ev?.dexStrings ?: emptyList(),
            nativeLibNames = ev?.nativeLibNames ?: emptyList(),
            signerSha256 = app.signerSha256,
            apkSha256 = app.apkSha256,
        )
    }
}
