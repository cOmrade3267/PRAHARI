package com.prahari.auditor.core

/**
 * The nine mandatory permission categories (PS §2) and the capability-token vocabulary the
 * intel combo rules expect (see ../intel/README.md). Stub mappings — fill the full tables during
 * the build.
 */
enum class Category(val display: String, val baseWeight: Int) {
    SPECIAL_ACCESS("Special access", 25),       // highest weight
    SMS("SMS", 15),
    CONTACTS_CALL("Contacts & call logs", 12),
    CAMERA_MIC("Camera & microphone", 12),
    LOCATION("Location", 10),
    PHONE_IDENTITY("Phone & identity", 8),
    STORAGE_MEDIA("Storage & media", 8),
    BACKGROUND_PERSISTENCE("Background & persistence", 6),
    NETWORK("Network", 3),
}

object PermissionCatalog {
    /**
     * Map an Android permission name to its category.
     * TODO(build): complete this table for every permission in PS §2.
     */
    fun categoryOf(permission: String): Category? = when (permission.substringAfterLast('.')) {
        "READ_SMS", "RECEIVE_SMS", "SEND_SMS" -> Category.SMS
        "READ_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG" -> Category.CONTACTS_CALL
        "CAMERA", "RECORD_AUDIO" -> Category.CAMERA_MIC
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION" -> Category.LOCATION
        "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE" -> Category.PHONE_IDENTITY
        "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE" -> Category.STORAGE_MEDIA
        "RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" -> Category.BACKGROUND_PERSISTENCE
        "INTERNET", "ACCESS_NETWORK_STATE" -> Category.NETWORK
        "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "PACKAGE_USAGE_STATS" -> Category.SPECIAL_ACCESS
        else -> null // TODO(build): classify the rest
    }
}

/** Canonical capability tokens the RE engine emits and the intel combo rules consume. */
object Tokens {
    const val ACCESSIBILITY = "cap.accessibility_service"
    const val OVERLAY = "cap.overlay"
    const val SMS_READ = "cap.sms_read"
    const val SMS_SEND = "cap.sms_send"
    const val DEVICE_ADMIN = "cap.device_admin"
    const val NOTIF_LISTENER = "cap.notification_listener"
    const val INSTALL_PACKAGES = "cap.install_packages"
    const val DYNAMIC_CODE = "cap.dynamic_code"
    const val SCREEN_CAPTURE = "cap.screen_capture"
    const val NETWORK = "cap.network"
    const val BOOT_PERSISTENCE = "cap.boot_persistence"
    const val LOCATION = "cap.location"
    const val MIC = "cap.mic"
    const val CAMERA = "cap.camera"
    const val CONTACTS = "cap.contacts"
    const val CALL_LOG = "cap.call_log"
    const val CLIPBOARD = "cap.clipboard"
    const val REFLECTION = "cap.reflection"
    const val PROCESS_EXEC = "cap.process_exec"
    const val ENUMERATE_PACKAGES = "cap.enumerate_packages"

    const val CATEGORY_UTILITY = "ctx.category_utility"
    const val CATEGORY_SECURITY = "ctx.category_security"

    const val SRC_SIDELOADED = "src.sideloaded"
    const val SRC_PLAYSTORE = "src.playstore"
    const val SRC_OTHER_STORE = "src.other_store"

    const val FLAG_DEBUGGABLE = "flag.debuggable"
    const val FLAG_CLEARTEXT = "flag.cleartext"
    const val FLAG_DEBUG_SIGNED = "flag.debug_signed"
    const val FLAG_ALLOW_BACKUP = "flag.allow_backup"
    const val FLAG_EXPORTED_UNGUARDED = "flag.exported_unguarded"
}
