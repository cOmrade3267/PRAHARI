package com.prahari.auditor.core

/**
 * Derives the intel/combo capability tokens from inventory facts, so the offline intel pack's
 * combination rules (overlay+accessibility, context-mismatch, etc.) fire from inventory alone —
 * before the ReverseEngineer is implemented. When RE lands, its richer tokens are merged on top
 * (see AppAuditor.buildFacts), so nothing here needs to change.
 */
object TokenDeriver {

    private val UTILITY_WORDS = listOf(
        "flashlight", "torch", "calculator", "calc", "wallpaper", "qr", "scanner",
        "battery", "cleaner", "compass", "ringtone", "keyboard", "photo editor",
    )
    private val SECURITY_WORDS = listOf("antivirus", "security", "mobile device management", "mdm", "cleaner pro")

    fun tokens(app: AppRecord): Set<String> {
        val t = HashSet<String>()
        val sa = app.specialAccess
        if (sa.accessibilityEnabled) t += Tokens.ACCESSIBILITY
        if (sa.deviceAdminActive) t += Tokens.DEVICE_ADMIN
        if (sa.notificationListenerEnabled) t += Tokens.NOTIF_LISTENER
        if (sa.overlayGranted || sa.overlayDeclared) t += Tokens.OVERLAY
        if (sa.requestInstallPackages) t += Tokens.INSTALL_PACKAGES
        // (usage-stats has no combo rule yet, so it needs no token; it still scores 25 in RuleScoringEngine)

        val granted = app.permissions.filter { it.granted }.map { it.name.substringAfterLast('.') }.toHashSet()
        val declared = app.permissions.map { it.name.substringAfterLast('.') }.toHashSet()
        if ("READ_SMS" in granted || "RECEIVE_SMS" in granted) t += Tokens.SMS_READ
        if ("SEND_SMS" in granted) t += Tokens.SMS_SEND
        if ("INTERNET" in declared) t += Tokens.NETWORK
        if ("RECEIVE_BOOT_COMPLETED" in declared) t += Tokens.BOOT_PERSISTENCE
        if (granted.any { it in setOf("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION") })
            t += Tokens.LOCATION
        if ("RECORD_AUDIO" in granted) t += Tokens.MIC
        if ("CAMERA" in granted) t += Tokens.CAMERA
        if ("READ_CONTACTS" in granted) t += Tokens.CONTACTS
        if ("READ_CALL_LOG" in granted) t += Tokens.CALL_LOG

        when (app.installer) {
            InstallerSource.PLAY_STORE -> t += Tokens.SRC_PLAYSTORE
            InstallerSource.OTHER_STORE -> t += Tokens.SRC_OTHER_STORE
            InstallerSource.SIDELOADED -> t += Tokens.SRC_SIDELOADED
            else -> { /* preinstalled / unknown → no installer token */ }
        }

        val label = app.label.lowercase()
        if (UTILITY_WORDS.any { label.contains(it) }) t += Tokens.CATEGORY_UTILITY
        if (SECURITY_WORDS.any { label.contains(it) }) t += Tokens.CATEGORY_SECURITY

        // static manifest flags (stretch #12), already as flag.* tokens
        t += app.manifestFlags

        return t
    }
}
