package com.fixture.flashlight

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent

/** Declared so the auditor sees a BIND_ACCESSIBILITY_SERVICE component. Does nothing. */
class FakeAccessibilityService : AccessibilityService() {
    override fun onAccessibilityEvent(event: AccessibilityEvent?) { /* inert */ }
    override fun onInterrupt() { /* inert */ }
}
