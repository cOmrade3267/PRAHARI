# Prahari — Inert Test Fixtures

Four tiny Android apps that **look dangerous but do nothing**, used as deterministic, safe, repeatable targets for the RE spike (`../spike-re`) and for the final auditor's demo. No real malware is used or distributed — these are original, inert apps.

## Why they're safe

Every dangerous API call lives inside a method guarded by an **opaque, always-false** condition:

```kotlin
private val NEVER: Boolean = System.nanoTime() == 1L   // never true at runtime
fun capabilitiesNeverRun() {
    if (!NEVER) return
    // dangerous references compiled here, but never executed
}
```

`System.nanoTime()` never returns `1`, so the body never runs — but the compiler **cannot prove** that, so it emits the real bytecode. With `minifyEnabled = false`, R8/D8 strips nothing, so a static analyzer (dexlib2) sees the full dangerous API surface while the app is completely inert. Each app also states "INERT TEST FIXTURE" on screen, and all use `com.fixture.*` package ids.

## The four fixtures

| Module | Pretends to be | Expected band | Key declared permissions | Dangerous API refs the matcher should hit |
|---|---|---|---|---|
| `flashlight` | Flashlight Pro (torch) | **CRITICAL** | SMS (read/recv/send), SYSTEM_ALERT_WINDOW, BIND_ACCESSIBILITY_SERVICE (service), REQUEST_INSTALL_PACKAGES, RECEIVE_BOOT_COMPLETED, CONTACTS, INTERNET | `SmsManager->sendTextMessage`, `->performGlobalAction`, `getInstalledPackages`, `HttpURLConnection`, `PackageInstaller`, `ClipboardManager` |
| `quickcalc` | QuickCalc (calculator) | **HIGH/CRITICAL** | INTERNET, REQUEST_INSTALL_PACKAGES, RECEIVE_BOOT_COMPLETED | `DexClassLoader`, `InMemoryDexClassLoader`, `Cipher`, `Base64`, `Method->invoke`, `Class->forName`, `Runtime->exec`, `ProcessBuilder`, `HttpURLConnection`, `PackageInstaller` |
| `wallpaper` | Aurora Wallpaper | **HIGH** | FINE+BACKGROUND_LOCATION, RECORD_AUDIO, CAMERA, CONTACTS, READ_CALL_LOG, INTERNET, FOREGROUND_SERVICE | `LocationManager->requestLocationUpdates`, `MediaProjectionManager`, `ClipboardManager`, `getInstalledPackages`, `HttpURLConnection`, `Socket` |
| `notebench` | NoteBench (notes/benchmark) | **LOW** (benign control) | ACCESS_NETWORK_STATE, VIBRATE | *(none — proves no false positives)* |

Each malicious fixture also sets `android:usesCleartextTraffic="true"`, and `flashlight` sets `android:debuggable="true"` plus `allowBackup=true` — extra static-manifest signals (stretch #12 in the plan).

### How they exercise the plan's combination rules (`../PLAN.md §5.3–5.4`)
- **flashlight** → context mismatch (torch + SMS/accessibility), accessibility+overlay, accessibility+SMS+persistence, install-packages.
- **quickcalc** → dynamic code loading + install-packages (dropper), context mismatch (calculator + install).
- **wallpaper** → context mismatch (wallpaper + location/mic/contacts), tracking + screen capture + exfil.
- **notebench** → nothing fires; stays Low.

## Build & install

**Android Studio:** `File ▸ Open` the `test-fixtures` folder, let it sync, then Run each module (pick the module in the run-config dropdown) onto your device/emulator. All four install side by side (distinct app ids).

**CLI (after the wrapper exists — open once in Studio, or `gradle wrapper --gradle-version 8.7`):**
```bash
./gradlew assembleDebug            # builds all four debug APKs
./gradlew :flashlight:installDebug :quickcalc:installDebug :wallpaper:installDebug :notebench:installDebug
```
Debug APKs land in `<module>/build/outputs/apk/debug/`.

## Using them to validate the matcher

1. Install the fixtures on the test device.
2. Run the spike (`../spike-re`) and tap **Run analysis**.
3. In the report's `[2] OTHER INSTALLED APPS` section, confirm:
   - `flashlight`, `quickcalc`, `wallpaper` each list the expected **capability hits** above.
   - `notebench` shows **no** dangerous hits.
4. That pass/fail per fixture is your matcher's unit test — deterministic and repeatable, with nothing harmful on the device.

> These are **fixtures**, not products. They exist only to give the analyzer known-answer inputs.
