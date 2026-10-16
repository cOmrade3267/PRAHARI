package com.prahari.auditor.core

/**
 * FR10 permission diff: what sensitive access an app gained between its two most recent scans.
 * Feeds the "an update added new sensitive permissions" alert and the Trust Timeline (PLAN §D5).
 */
object PermissionDiff {

    /** Permissions newly granted in the latest snapshot vs the previous one. */
    fun newlyGranted(history: List<ScanSnapshot>): Set<String> {
        if (history.size < 2) return emptySet()
        val sorted = history.sortedBy { it.scannedAtMillis }
        val prev = sorted[sorted.size - 2].grantedPermissions
        val curr = sorted[sorted.size - 1].grantedPermissions
        return curr - prev
    }

    /** Of the newly granted permissions, those in a non-trivial category (worth alerting on). */
    fun newlySensitive(history: List<ScanSnapshot>): Set<String> =
        newlyGranted(history).filter { name ->
            val c = PermissionCatalog.categoryOf(name)
            c != null && c != Category.NETWORK
        }.toSet()
}
