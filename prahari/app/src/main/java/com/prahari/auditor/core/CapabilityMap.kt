package com.prahari.auditor.core

/**
 * Maps a code-derived capability token (what the DEX actually references) to the permission
 * category it exercises. Used to set PermissionState.usedInCode so the scoring engine can apply the
 * declared→granted→USED ×1.5 multiplier (PLAN §2.3a / §5.2). Capabilities with no permission
 * category (dynamic code, reflection, process exec, …) return null and only feed the intel engine.
 */
object CapabilityMap {
    fun categoryOf(capToken: String): Category? = when (capToken) {
        Tokens.ACCESSIBILITY, Tokens.OVERLAY, Tokens.INSTALL_PACKAGES,
        Tokens.DEVICE_ADMIN, Tokens.NOTIF_LISTENER -> Category.SPECIAL_ACCESS
        Tokens.SMS_READ, Tokens.SMS_SEND -> Category.SMS
        Tokens.CONTACTS, Tokens.CALL_LOG -> Category.CONTACTS_CALL
        Tokens.CAMERA, Tokens.MIC -> Category.CAMERA_MIC
        Tokens.LOCATION -> Category.LOCATION
        Tokens.NETWORK -> Category.NETWORK
        Tokens.BOOT_PERSISTENCE -> Category.BACKGROUND_PERSISTENCE
        else -> null // screen_capture, dynamic_code, reflection, process_exec, enumerate_packages, clipboard
    }
}
