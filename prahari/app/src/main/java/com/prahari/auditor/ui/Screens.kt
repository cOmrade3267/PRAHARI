package com.prahari.auditor.ui

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.prahari.auditor.core.AppRecord
import com.prahari.auditor.core.RiskBand
import com.prahari.auditor.core.SpecialAccess
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.roundToInt

/** Root: navigation between the Q1 dashboard and the Q2/Q3 detail screen. */
@Composable
fun PrahariApp() {
    val nav = rememberNavController()
    val vm: ScanViewModel = viewModel()
    NavHost(navController = nav, startDestination = "dashboard") {
        composable("dashboard") {
            DashboardScreen(vm, onOpen = { pkg -> nav.navigate("detail/$pkg") })
        }
        composable(
            route = "detail/{pkg}",
            arguments = listOf(navArgument("pkg") { type = NavType.StringType }),
        ) { entry ->
            val pkg = entry.arguments?.getString("pkg").orEmpty()
            AppDetailScreen(vm, pkg, onBack = { nav.popBackStack() })
        }
    }
}

/** Q1 — "Which of my apps can do the most harm?" Ranked list after a scan. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(vm: ScanViewModel, onOpen: (String) -> Unit) {
    val s by vm.state.collectAsState()
    Scaffold(topBar = { TopAppBar(title = { Text("Prahari — App Risk Auditor") }) }) { pad ->
        Column(
            Modifier.padding(pad).fillMaxSize().padding(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = { vm.scan() }, enabled = !s.scanning) {
                    Text(if (s.scanning) "Scanning…" else "Scan device")
                }
                Spacer(Modifier.width(16.dp))
                Checkbox(checked = s.includeSystem, onCheckedChange = { vm.setIncludeSystem(it) })
                Text("System apps")
            }
            if (s.scanning && s.total > 0) {
                Spacer(Modifier.height(8.dp))
                LinearProgressIndicator(
                    progress = { s.done / s.total.toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text("${s.done} / ${s.total}", style = MaterialTheme.typography.bodySmall)
            }
            s.message?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }
            Spacer(Modifier.height(12.dp))
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(s.apps, key = { it.packageName }) { app ->
                    AppRow(app) { onOpen(app.packageName) }
                }
            }
        }
    }
}

@Composable
private fun AppRow(app: AppRecord, onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().clickable { onClick() }) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(app.label, style = MaterialTheme.typography.titleMedium)
                Text(app.packageName, style = MaterialTheme.typography.bodySmall)
            }
            BandChip(app.risk?.band, app.risk?.score)
        }
    }
}

/** Q2/Q3 — "Why is it flagged?" and "What can I do now?" */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppDetailScreen(vm: ScanViewModel, pkg: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val app = vm.appByPackage(pkg)
    val history by vm.history.collectAsState()
    val newlySensitive by vm.newlySensitive.collectAsState()
    LaunchedEffect(pkg) { vm.loadHistory(pkg) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(app?.label ?: "App") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { pad ->
        if (app == null) {
            Box(Modifier.padding(pad).fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("App not found in the last scan.")
            }
            return@Scaffold
        }
        Column(
            Modifier.padding(pad).fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        ) {
            BandChip(app.risk?.band, app.risk?.score)
            Spacer(Modifier.height(6.dp))
            Text(app.packageName, style = MaterialTheme.typography.bodySmall)

            Spacer(Modifier.height(16.dp))
            Text("Why flagged", style = MaterialTheme.typography.titleMedium)
            val reasons = app.risk?.reasons.orEmpty()
            if (reasons.isEmpty()) {
                Text("Nothing notable flagged — this app looks low-risk.")
            } else {
                reasons.forEach { r ->
                    Text("•  ${r.text}")
                    r.technical?.let { Text("     $it", style = MaterialTheme.typography.bodySmall) }
                }
            }

            // Attack-chain narrative (from static RE)
            val chain = app.codeEvidence?.attackChain.orEmpty()
            if (chain.isNotEmpty()) {
                Spacer(Modifier.height(16.dp))
                Text("If malicious, this app could", style = MaterialTheme.typography.titleMedium)
                chain.forEachIndexed { i, step ->
                    Text("${i + 1}.  ${step.action}")
                    Text("      ${step.evidence}", style = MaterialTheme.typography.bodySmall)
                }
            }

            // Special access
            val sa = specialAccessSummary(app.specialAccess)
            if (sa.isNotEmpty()) {
                Spacer(Modifier.height(16.dp))
                Text("Special access", style = MaterialTheme.typography.titleMedium)
                sa.forEach { Text("•  $it") }
            }

            // ML second opinion (hidden when no model bundled)
            app.risk?.mlProbability?.let { p ->
                Spacer(Modifier.height(16.dp))
                Text("Model second opinion", style = MaterialTheme.typography.titleMedium)
                Text("On-device model: ${(p * 100).roundToInt()}% likely harmful — the rule score above stays authoritative.")
            }

            // Deep-scan availability (honesty when the APK couldn't be read)
            if (app.codeEvidence == null || app.codeEvidence?.deepScanned == false) {
                Spacer(Modifier.height(16.dp))
                Text(
                    "Deep code scan unavailable for this app on this device — scored from permissions only.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Spacer(Modifier.height(16.dp))
            Text("What can I do now?", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { context.startActivity(appSettingsIntent(app.packageName)) }) {
                    Text("App settings")
                }
                OutlinedButton(onClick = { context.startActivity(uninstallIntent(app.packageName)) }) {
                    Text("Uninstall")
                }
            }
            // Permission diff (FR10)
            if (newlySensitive.isNotEmpty()) {
                Spacer(Modifier.height(16.dp))
                Text("New sensitive access since last scan", style = MaterialTheme.typography.titleMedium)
                newlySensitive.forEach { Text("•  ${it.substringAfterLast('.')}") }
            }

            // Trust Timeline (PLAN §D5) — permission/risk history across scans & updates
            if (history.size > 1) {
                Spacer(Modifier.height(16.dp))
                Text("Trust timeline", style = MaterialTheme.typography.titleMedium)
                history.sortedByDescending { it.scannedAtMillis }.forEach { s ->
                    Text(
                        "${formatTime(s.scannedAtMillis)} · v${s.versionCode} · ${s.band} (${s.score}) · ${s.grantedPermissions.size} granted",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}

private fun formatTime(millis: Long): String =
    SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(millis))

@Composable
private fun BandChip(band: RiskBand?, score: Int?) {
    val (label, color) = when (band) {
        RiskBand.CRITICAL -> "CRITICAL" to Color(0xFFB00020)
        RiskBand.HIGH -> "HIGH" to Color(0xFFD9641E)
        RiskBand.MEDIUM -> "MEDIUM" to Color(0xFFB08900)
        RiskBand.LOW -> "LOW" to Color(0xFF2E7D32)
        null -> "—" to Color.Gray
    }
    Surface(color = color.copy(alpha = 0.15f), shape = RoundedCornerShape(8.dp)) {
        Text(
            text = label + (score?.let { "  $it" } ?: ""),
            color = color,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
        )
    }
}

private fun specialAccessSummary(sa: SpecialAccess): List<String> = buildList {
    if (sa.accessibilityEnabled) add("Accessibility service enabled (can read the screen and tap for you)")
    if (sa.deviceAdminActive) add("Active Device Administrator")
    if (sa.notificationListenerEnabled) add("Reads all notifications")
    if (sa.overlayGranted) add("Can draw over other apps (overlay)")
    if (sa.requestInstallPackages) add("Can install other apps")
    if (sa.usageStatsGranted) add("Can see your app-usage history")
}

private fun appSettingsIntent(pkg: String): Intent =
    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", pkg, null))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

private fun uninstallIntent(pkg: String): Intent =
    Intent(Intent.ACTION_DELETE, Uri.fromParts("package", pkg, null))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
