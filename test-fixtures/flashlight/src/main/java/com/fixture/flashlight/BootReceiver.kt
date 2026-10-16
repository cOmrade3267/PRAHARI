package com.fixture.flashlight

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Declared for the boot-persistence signal. Does nothing. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) { /* inert */ }
}
