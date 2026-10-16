package com.prahari.auditor.di

import android.content.Context
import com.prahari.auditor.data.FileScanRepository
import com.prahari.auditor.engine.AppAuditor
import com.prahari.auditor.engine.ScanRepository
import com.prahari.auditor.ml.TfLiteMalwareModel
import com.prahari.auditor.reversing.StaticReverseEngineer
import com.prahari.auditor.scanner.DeviceInventoryScanner
import com.prahari.auditor.scoring.RuleScoringEngine
import com.prahari.intel.IntelEngine

/**
 * Dead-simple manual DI. The [AppAuditor] and the UI share ONE [ScanRepository] instance, so history
 * written during a scan is read back by the Trust Timeline. All on-device, no network.
 */
object ServiceLocator {
    @Volatile private var repo: ScanRepository? = null
    @Volatile private var auditor: AppAuditor? = null

    fun repository(context: Context): ScanRepository = repo ?: synchronized(this) {
        repo ?: FileScanRepository(context.applicationContext).also { repo = it }
    }

    fun auditor(context: Context): AppAuditor = auditor ?: synchronized(this) {
        auditor ?: build(context.applicationContext).also { auditor = it }
    }

    private fun build(app: Context): AppAuditor {
        val intel = IntelEngine.fromAssets(app) // assets are bundled; a throw means a packaging problem
        return AppAuditor(
            inventory = DeviceInventoryScanner(app),
            reverser = StaticReverseEngineer(app),
            intel = intel,
            model = TfLiteMalwareModel(app),
            scoring = RuleScoringEngine(),
            repo = repository(app),
        )
    }
}
