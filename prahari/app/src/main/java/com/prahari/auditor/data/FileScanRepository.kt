package com.prahari.auditor.data

import android.content.Context
import com.prahari.auditor.core.AppRecord
import com.prahari.auditor.core.RiskBand
import com.prahari.auditor.core.ScanSnapshot
import com.prahari.auditor.engine.ScanRepository
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Durable scan history in a single JSON file in the app's private filesDir — enough to power the
 * Trust Timeline + permission diff (FR09/FR10) across restarts, with no build-time codegen.
 *
 * Deliberately NOT Room: adding a KSP/Room setup blind (uncompilable here) is a needless risk for a
 * scaffold. The ScanRepository contract is unchanged, so Room can replace this later without
 * touching callers. latest() is in-memory only (the user re-scans each launch); history() is durable.
 */
class FileScanRepository(context: Context) : ScanRepository {

    private val file = File(context.applicationContext.filesDir, "scan_history.json")
    private val lock = Any()
    @Volatile private var last: List<AppRecord> = emptyList()

    override suspend fun save(apps: List<AppRecord>, nowMillis: Long) {
        last = apps
        synchronized(lock) {
            val root = readRoot()
            for (a in apps) {
                val r = a.risk ?: continue
                val arr = root.optJSONArray(a.packageName) ?: JSONArray().also { root.put(a.packageName, it) }
                arr.put(
                    JSONObject()
                        .put("versionCode", a.versionCode)
                        .put("scannedAtMillis", nowMillis)
                        .put("score", r.score)
                        .put("band", r.band.name)
                        .put("granted", JSONArray(a.permissions.filter { it.granted }.map { it.name }))
                )
                if (arr.length() > MAX_SNAPSHOTS) {
                    val trimmed = JSONArray()
                    for (i in (arr.length() - MAX_SNAPSHOTS) until arr.length()) trimmed.put(arr.get(i))
                    root.put(a.packageName, trimmed)
                }
            }
            runCatching { file.writeText(root.toString()) }
        }
    }

    override suspend fun latest(): List<AppRecord> = last

    override suspend fun history(packageName: String): List<ScanSnapshot> = synchronized(lock) {
        val arr = readRoot().optJSONArray(packageName) ?: return emptyList()
        (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            ScanSnapshot(
                packageName = packageName,
                versionCode = o.optLong("versionCode"),
                scannedAtMillis = o.optLong("scannedAtMillis"),
                score = o.optInt("score"),
                band = runCatching { RiskBand.valueOf(o.optString("band", "LOW")) }.getOrDefault(RiskBand.LOW),
                grantedPermissions = o.optJSONArray("granted").toStringSet(),
            )
        }
    }

    private fun readRoot(): JSONObject = try {
        if (file.exists()) JSONObject(file.readText()) else JSONObject()
    } catch (_: Exception) {
        JSONObject()
    }

    private fun JSONArray?.toStringSet(): Set<String> {
        if (this == null) return emptySet()
        val out = HashSet<String>(length())
        for (i in 0 until length()) out.add(getString(i))
        return out
    }

    private companion object {
        const val MAX_SNAPSHOTS = 20
    }
}
