# Prahari — On-Device App Risk Auditor (PS-01)

A strictly-offline Android app that finds suspicious apps by what their **code can actually do** —
not just what they declare. Everything runs on the phone; the app declares **no `INTERNET`
permission**, so it is provably unable to exfiltrate anything.

## What's in this folder

| Path | What it is |
|---|---|
| `PLAN.md` | The full build plan + §5 scoring rubric + hour-by-hour + risk register |
| `prahari/` | **The app.** Android Studio project — scan, reverse-engineer, intel, ML, score, persist, monitor |
| `test-fixtures/` | **The 4 demo apps** — inert "evil-looking" apps (Flashlight/QuickCalc/Aurora + benign NoteBench) |
| `intel/` | The offline threat-intel pack (bundled into the app) |
| `ml/` | The TFLite trainer (NATICUSdroid) — run once to produce the optional model |
| `spike-re/` | The throwaway RE spike that proved the dexlib2/apk-parser approach |

## Run it on your phone over USB

**1. Prepare the phone**
- Settings → About phone → tap *Build number* 7× to unlock Developer options.
- Developer options → enable **USB debugging**. Connect via USB and accept the RSA prompt.

**2. Install the 4 demo apps** (so the scan has known-answer targets)
- Open `test-fixtures/` in Android Studio → let it sync.
- In the run-config dropdown, Run each module onto the phone: `flashlight`, `quickcalc`, `wallpaper`, `notebench` (they install side by side; each says "INERT TEST FIXTURE" on screen).
- CLI alternative (after one Studio sync creates the wrapper): `./gradlew installDebug` in each, or `adb install <module>/build/outputs/apk/debug/*.apk`.

**3. (Optional) add the ML second opinion**
- `cd ml && python -m venv .venv && <activate> && pip install -r requirements.txt`
- `python -I train_naticusdroid.py` → copy `ml/out/model.tflite` and `ml/out/features.json` into `prahari/app/src/main/assets/ml/`.
- Skip this and the app still runs; the ML gauge just stays hidden.

**4. Run the auditor**
- Open `prahari/` in Android Studio → sync → select your phone → **Run** (▶). Approve the notification prompt (for install alerts).

## Demo flow (what to show)

1. **Scan device** → the dashboard ranks apps by risk (Q1). The fixtures should land:
   **Flashlight Pro = Critical**, **QuickCalc / Aurora Wallpaper = High**, **NoteBench = Low** (the benign control proves no false positives).
2. Open **Flashlight Pro** → the detail screen answers **Q2** (plain "Why flagged" reasons + the
   attack-chain narrative + special access + manifest flags) and **Q3** (App settings / Uninstall).
3. **Install monitoring:** uninstall then re-install a fixture (or `adb install -r`) → a High/Critical
   notification fires. Re-scan and open the app to see the **Trust timeline** and any new permissions.
4. **The offline proof:** show `prahari/app/src/main/AndroidManifest.xml` — no `INTERNET` permission.

## Notes

- Scanning other apps' APKs needs **no root**. A few OEM builds restrict reading another app's
  `sourceDir`; Prahari degrades to a permissions-only score for those and says so on the detail screen.
- No real malware is used — the fixtures are original, inert apps whose dangerous API calls are
  compiled but guarded off.
- Toolchain: Android Studio (JDK 17), Gradle 8.7, Kotlin 1.9.24. First sync downloads Gradle and
  creates the wrapper.
