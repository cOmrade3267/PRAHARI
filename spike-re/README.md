# Prahari — Reverse-Engineering Spike

A throwaway, **pre-event de-risking** Android app for PS-01. It exists to answer one question before the 6-hour clock starts:

> Can we, on a real phone, with **no root and no network**, open an installed app's APK, read its real manifest permissions, and walk its DEX bytecode to see which dangerous APIs the code actually calls?

If yes, **Tier A of the plan is green** (`../PLAN.md`). If other-app APKs turn out to be unreadable on a given device, the spike tells you that too — so you ship the PackageManager-only fallback instead of discovering it live.

## What it proves

1. **`net.dongliu:apk-parser` runs on Android** → real `<uses-permission>` list straight from the binary manifest.
2. **`org.smali:dexlib2` runs on Android** → enumerate called method references and match them against a "dangerous API surface" (SmsManager, AccessibilityService, DexClassLoader, MediaProjection, HttpURLConnection, reflection, …).
3. **APK readability on this device** → it analyses its own APK first (always works), then probes up to 8 other installed apps and prints a `readable X / N` verdict.
4. SHA-256 of each APK + signer-cert SHA-256 (via `PackageManager`) — the inputs for the offline threat-intel layer.

The app declares **no `INTERNET` permission** — proving the "strictly offline" claim from the start.

## Prerequisites (already present on this machine)

- Android Studio (installed)
- Android SDK at `C:\Users\Skyworth\AppData\Local\Android\Sdk` (picked up via `local.properties`)
- JDK 17 (AGP 8.5 needs 17)
- A phone with USB debugging **or** an emulator. A **physical phone with real apps installed** is the better test — it has more varied APKs and shows true OEM behaviour.

## Run it

**Android Studio (recommended):**
1. `File ▸ Open` → select the `spike-re` folder.
2. Let Gradle sync. It downloads Gradle 8.7 (per the wrapper) and resolves the two RE libraries — **this sync is itself the main thing we're de-risking.** If sync succeeds, the libraries are Android-compatible.
3. Pick your device/emulator, press **Run** (▶).
4. Tap **Run analysis**. Read the on-screen report, and/or `View ▸ Tool Windows ▸ Logcat` filtered to tag **`RESpike`**.

**CLI:** this folder ships no `gradle-wrapper.jar` (binary). Either open once in Android Studio (it creates the wrapper), or, with a system Gradle installed, run `gradle wrapper --gradle-version 8.7` once, then `./gradlew installDebug`.

## Reading the result

```
[1] SELF APK  (pipeline proof — must succeed)
  ✓ self: com.prahari.spike
      permissions  : 1 declared
      dex refs     : 1843 method calls scanned in 220 ms
      capability hits: none of the watched dangerous APIs
...
READABILITY VERDICT: 8 / 8 other-app APKs parsed on this device.
=> Deep scan of other apps WORKS here. Tier A is green on this build.
```

- **Self APK succeeds + dex refs > 0** → both libraries work on Android. ✅ The core technical risk is retired.
- **READABILITY VERDICT high** → `sourceDir` deep scan works on this OEM/Android build. Record the device + Android version.
- **READABILITY VERDICT 0** → other-app APKs are sandboxed on this build. Self-APK still works; the full auditor falls back to `PackageManager`-only analysis for those apps (it loses only the "Used-in-code" signal, not the whole scan). Test a second device before judging day.

Run it on **every device you might demo on** and keep a small table of results — that table *is* the de-risking deliverable.

## If the Gradle sync fails (expected spike outcomes, with fixes)

| Symptom | Fix |
|---|---|
| `2 files found with path 'META-INF/…'` | Add that exact path to `app/build.gradle.kts` → `packaging { resources { excludes += "…" } }`. |
| `Could not find org.smali:dexlib2:2.5.2` | It's on Maven Central (already a repo). If a proxy blocks it, try `com.android.tools.smali:smali-dexlib2:3.0.5` **and** change imports from `org.jf.dexlib2.*` to `com.android.tools.smali.dexlib2.*`. |
| Guava `NoClassDefFound` / duplicate class at runtime | Confirm the **`-android`** Guava variant is the one resolved (`./gradlew :app:dependencies`). |
| `Unsupported class file major version` / Java 8 API missing | Core-library desugaring is already on; ensure you built with JDK 17. |
| `OutOfMemoryError` while scanning | Lower `maxOtherApps` in `ReverseEngineer.runFullSpike(...)`, or raise `org.gradle.jvmargs`. |
| Compose compiler version error | Keep Kotlin **1.9.24** ↔ compose compiler **1.5.14** paired. |

## Files

- `app/src/main/java/com/prahari/spike/ReverseEngineer.kt` — the RE engine (apk-parser + dexlib2 + hashing + readability probe).
- `app/src/main/java/com/prahari/spike/MainActivity.kt` — minimal Compose UI (button → report).
- `app/src/main/AndroidManifest.xml` — `QUERY_ALL_PACKAGES`, **no INTERNET**.

> Scope note: this is a **spike**, not the product. It throws everything into one screen on purpose. The real module structure lives in `../PLAN.md §4`.
