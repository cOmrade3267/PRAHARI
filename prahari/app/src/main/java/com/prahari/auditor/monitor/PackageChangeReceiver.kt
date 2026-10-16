package com.prahari.auditor.monitor

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import com.prahari.auditor.core.AppRecord
import com.prahari.auditor.core.RiskBand
import com.prahari.auditor.di.ServiceLocator
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * FR09 install monitoring. Fires on install/update of any app (PACKAGE_ADDED/REPLACED are exempt
 * from the Android 8+ implicit-broadcast limits), rescans just that package, and raises a
 * notification if it lands High/Critical. All on-device; no network.
 */
class PackageChangeReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_PACKAGE_ADDED && action != Intent.ACTION_PACKAGE_REPLACED) return
        // Skip the ADDED half of an update (REPLACED covers it).
        if (action == Intent.ACTION_PACKAGE_ADDED && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
        val pkg = intent.data?.schemeSpecificPart ?: return
        if (pkg == context.packageName) return

        val appContext = context.applicationContext
        val pending = goAsync()
        scope.launch {
            try {
                val record = ServiceLocator.auditor(appContext)
                    .analyzeOne(pkg, System.currentTimeMillis())
                val band = record?.risk?.band
                if (record != null && (band == RiskBand.HIGH || band == RiskBand.CRITICAL)) {
                    InstallNotifier.notify(appContext, record)
                }
            } catch (_: Exception) {
                // best-effort; never crash on a broadcast
            } finally {
                pending.finish()
            }
        }
    }

    private companion object {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    }
}

/** Posts a one-off risk alert. Silently no-ops if POST_NOTIFICATIONS isn't granted (API 33+). */
object InstallNotifier {
    private const val CHANNEL_ID = "prahari_risk_alerts"

    fun notify(context: Context, app: AppRecord) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Risk alerts", NotificationManager.IMPORTANCE_HIGH)
            )
        }
        val launch = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: Intent()
        val contentPi = PendingIntent.getActivity(
            context, 0, launch,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        @Suppress("DEPRECATION")
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(context, CHANNEL_ID)
        else Notification.Builder(context)
        val notification = builder
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("${app.risk?.band?.name ?: "HIGH"} risk app installed")
            .setContentText("${app.label} scored ${app.risk?.score ?: ""}. Tap to review.")
            .setAutoCancel(true)
            .setContentIntent(contentPi)
            .build()
        try {
            nm.notify(app.packageName.hashCode(), notification)
        } catch (_: SecurityException) {
            // POST_NOTIFICATIONS not granted — ignore.
        }
    }
}
