package com.prahari.auditor.scanner

import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.ComponentInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Build
import android.provider.Settings
import com.prahari.auditor.core.AppRecord
import com.prahari.auditor.core.InstallerSource
import com.prahari.auditor.core.PermissionCatalog
import com.prahari.auditor.core.PermissionState
import com.prahari.auditor.core.ProtectionLevel
import com.prahari.auditor.core.SpecialAccess
import com.prahari.auditor.core.Tokens
import com.prahari.auditor.engine.InventoryScanner
import java.security.MessageDigest

/**
 * Real FR01/FR02/FR04 inventory. Enumerates user (optionally system) apps via PackageManager and
 * extracts: metadata, declared-vs-granted permissions with protection levels, installer source,
 * signer-cert SHA-256, and special access.
 *
 * `usedInCode` stays false here — that is the ReverseEngineer's job. APK hashing is also left to
 * the RE stage (it reads the file); inventory only does the cheap PackageManager-sourced signer hash.
 *
 * Special access via AppOps (overlay/install/usage) is best-effort: querying another package's op
 * can be refused on some OEMs, in which case we fall back to "declared" and leave the grant false
 * (PLAN §7). Accessibility / notification-listener / device-admin reads are reliable.
 */
class DeviceInventoryScanner(context: Context) : InventoryScanner {

    private val appContext = context.applicationContext
    private val pm: PackageManager = appContext.packageManager
    private val appOps = appContext.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager

    @Suppress("DEPRECATION")
    override suspend fun inventory(includeSystem: Boolean): List<AppRecord> {
        val flags = PackageManager.GET_PERMISSIONS or
            (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES
             else PackageManager.GET_SIGNATURES)
        val packages = pm.getInstalledPackages(flags)

        // Device-wide special-access sources, read once.
        val accessibilityPkgs = enabledComponentPackages(Settings.Secure.getString(
            appContext.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES))
        val notifListenerPkgs = enabledComponentPackages(Settings.Secure.getString(
            appContext.contentResolver, "enabled_notification_listeners"))
        val deviceAdminPkgs = activeDeviceAdminPackages()

        val out = ArrayList<AppRecord>(packages.size)
        for (pi in packages) {
            val ai = pi.applicationInfo ?: continue
            val isSystem = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
            if (isSystem && !includeSystem) continue

            val pkg = pi.packageName
            val requested = pi.requestedPermissions ?: emptyArray()
            val grantFlags = pi.requestedPermissionsFlags ?: IntArray(0)

            val permissions = requested.mapIndexed { i, name ->
                val granted = i < grantFlags.size &&
                    (grantFlags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                PermissionState(
                    name = name,
                    category = PermissionCatalog.categoryOf(name),
                    protection = protectionLevelOf(name),
                    declared = true,
                    granted = granted,
                    usedInCode = false, // set by ReverseEngineer
                )
            }

            val declaredSet = requested.toHashSet()
            val special = SpecialAccess(
                accessibilityEnabled = pkg in accessibilityPkgs,
                deviceAdminActive = pkg in deviceAdminPkgs,
                notificationListenerEnabled = pkg in notifListenerPkgs,
                overlayDeclared = "android.permission.SYSTEM_ALERT_WINDOW" in declaredSet,
                overlayGranted = opAllowed(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, ai.uid, pkg),
                requestInstallPackages = "android.permission.REQUEST_INSTALL_PACKAGES" in declaredSet &&
                    opAllowed(AppOpsManager.OPSTR_REQUEST_INSTALL_PACKAGES, ai.uid, pkg),
                usageStatsGranted = opAllowed(AppOpsManager.OPSTR_GET_USAGE_STATS, ai.uid, pkg),
            )

            out += AppRecord(
                packageName = pkg,
                label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(pkg),
                versionName = pi.versionName,
                versionCode = if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode else pi.versionCode.toLong(),
                installDateMillis = pi.firstInstallTime,
                installer = installerSource(pkg, isSystem),
                targetSdk = ai.targetSdkVersion,
                isSystem = isSystem,
                apkPath = ai.sourceDir,
                apkSha256 = null, // filled by ReverseEngineer (it reads the APK)
                signerSha256 = signerSha256(pi),
                manifestFlags = manifestFlags(ai, pkg),
                permissions = permissions,
                specialAccess = special,
                codeEvidence = null,
                risk = null,
            )
        }
        return out
    }

    // ---- permission protection ----

    @Suppress("DEPRECATION")
    private fun protectionLevelOf(name: String): ProtectionLevel = try {
        val level = pm.getPermissionInfo(name, 0).protectionLevel
        val base = level and PermissionInfo.PROTECTION_MASK_BASE
        when {
            (level and PermissionInfo.PROTECTION_FLAG_APPOP) != 0 -> ProtectionLevel.SPECIAL
            base == PermissionInfo.PROTECTION_DANGEROUS -> ProtectionLevel.DANGEROUS
            base == PermissionInfo.PROTECTION_SIGNATURE -> ProtectionLevel.SIGNATURE
            base == PermissionInfo.PROTECTION_NORMAL -> ProtectionLevel.NORMAL
            else -> ProtectionLevel.UNKNOWN
        }
    } catch (_: Exception) {
        ProtectionLevel.UNKNOWN // custom / undeclared permission not resolvable
    }

    // ---- special access sources ----

    private fun enabledComponentPackages(flat: String?): Set<String> {
        if (flat.isNullOrBlank()) return emptySet()
        return flat.split(':')
            .mapNotNull { ComponentName.unflattenFromString(it)?.packageName }
            .toHashSet()
    }

    private fun activeDeviceAdminPackages(): Set<String> = try {
        val dpm = appContext.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        dpm.activeAdmins?.map { it.packageName }?.toHashSet() ?: emptySet()
    } catch (_: Exception) {
        emptySet()
    }

    @Suppress("DEPRECATION")
    private fun opAllowed(op: String, uid: Int, pkg: String): Boolean = try {
        val mode = if (Build.VERSION.SDK_INT >= 29) appOps.unsafeCheckOpNoThrow(op, uid, pkg)
        else appOps.checkOpNoThrow(op, uid, pkg)
        mode == AppOpsManager.MODE_ALLOWED
    } catch (_: Exception) {
        false // some OEMs refuse cross-package op queries → treat as not-granted
    }

    // ---- static manifest checks (stretch #12) ----

    @Suppress("DEPRECATION")
    private fun manifestFlags(ai: ApplicationInfo, pkg: String): Set<String> {
        val t = HashSet<String>()
        if (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) t += Tokens.FLAG_DEBUGGABLE
        if (ai.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0) t += Tokens.FLAG_ALLOW_BACKUP
        if (ai.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0) t += Tokens.FLAG_CLEARTEXT
        if (hasExportedUnguarded(pkg)) t += Tokens.FLAG_EXPORTED_UNGUARDED
        return t
    }

    @Suppress("DEPRECATION")
    private fun hasExportedUnguarded(pkg: String): Boolean = try {
        val f = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS
        val pi = pm.getPackageInfo(pkg, f)
        val comps = ArrayList<ComponentInfo>()
        pi.activities?.let { comps.addAll(it) }
        pi.services?.let { comps.addAll(it) }
        pi.receivers?.let { comps.addAll(it) }
        val compUnguarded = comps.any { it.exported && it.permission == null }
        val provUnguarded = pi.providers?.any {
            it.exported && it.readPermission == null && it.writePermission == null
        } ?: false
        compUnguarded || provUnguarded
    } catch (_: Exception) {
        false
    }

    // ---- installer + signer ----

    @Suppress("DEPRECATION")
    private fun installerSource(pkg: String, isSystem: Boolean): InstallerSource {
        val installer = try {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
            else pm.getInstallerPackageName(pkg)
        } catch (_: Exception) {
            null
        }
        return when {
            installer == "com.android.vending" -> InstallerSource.PLAY_STORE
            installer != null -> InstallerSource.OTHER_STORE
            isSystem -> InstallerSource.PREINSTALLED
            else -> InstallerSource.SIDELOADED
        }
    }

    @Suppress("DEPRECATION")
    private fun signerSha256(pi: PackageInfo): String? = try {
        val sigs = if (Build.VERSION.SDK_INT >= 28) pi.signingInfo?.apkContentsSigners else pi.signatures
        sigs?.firstOrNull()?.let { sha256Hex(it.toByteArray()) }
    } catch (_: Exception) {
        null
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(bytes)
        val sb = StringBuilder(d.size * 2)
        for (b in d) {
            val v = b.toInt() and 0xFF
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0x0F])
        }
        return sb.toString()
    }
}
