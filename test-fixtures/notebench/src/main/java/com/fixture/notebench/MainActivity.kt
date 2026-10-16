package com.fixture.notebench

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

/**
 * FIXTURE 4 — "NoteBench" (expected: LOW) — the benign control.
 *
 * A genuinely harmless utility: no dangerous permissions, no dangerous API references.
 * Its only job is to prove the auditor discriminates and does not flag clean apps.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val tv = TextView(this)
        tv.setPadding(48, 96, 48, 48)
        tv.text = "TEST FIXTURE (benign control)\n“NoteBench” (expected: LOW)\n\n" +
            "A clean utility with only ACCESS_NETWORK_STATE and VIBRATE and no sensitive API " +
            "calls. The auditor should rate this LOW — it is the negative control that proves " +
            "no false positives."
        setContentView(tv)
        // Deliberately nothing dangerous anywhere in this app.
    }
}
