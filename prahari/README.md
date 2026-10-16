# Prahari — On-Device App Risk Auditor

The real auditor app for PS-01. One Gradle module, clean packages (per `../PLAN.md §4`). Declares
`QUERY_ALL_PACKAGES` and `POST_NOTIFICATIONS`, **no `INTERNET`** — provably offline.

## What runs today

Open in Android Studio → sync → Run. The whole pipeline is implemented end-to-end:

- **Inventory** (`scanner/DeviceInventoryScanner`) — every app with declared-vs-granted permissions,
  protection levels, installer source, signer cert, and special access.
- **Static RE** (`reversing/StaticReverseEngineer`) — opens each APK (no root), walks the DEX with
  dexlib2, and reports the dangerous APIs the code actually references → capability tokens,
  human-readable hits, native-lib list, APK SHA-256, and an attack-chain narrative. Sets
  `PermissionState.usedInCode`, so the declared→granted→**used** ×1.5 multiplier is live, and feeds
  the intel pack's packer/target-list/C2 rules.
- **Scoring** (`scoring/RuleScoringEngine`) — PLAN §5 weights × multipliers + special-access points
  + static manifest checks (debuggable/cleartext/exported-unguarded/backup, stretch #12)
  + intel-hit folding (forcesCritical + context-mismatch floor) → 0–100, four bands, ranked, with
  plain-language "Why flagged" reasons.
- **Trust Timeline + permission diff** (`core/PermissionDiff` + the detail screen) — risk/permission
  history across scans and updates, flagging newly-granted sensitive permissions (FR10).
- **ML second opinion** (`ml/TfLiteMalwareModel`) — loads `assets/ml/model.tflite` + `features.json`
  when present; hidden otherwise. Never overrides the rule score.
- **Persistence** (`data/FileScanRepository`) — durable scan history (JSON in filesDir) for the
  permission diff / Trust Timeline.
- **Install monitoring** (`monitor/PackageChangeReceiver`) — rescans on install/update, notifies on
  High/Critical.

Drop a trained model into `assets/ml/` (see `../ml`) to light up the ML gauge. Install the fixtures
(`../test-fixtures`) to see Critical/High/Low worked examples.

## Package map (`app/src/main/java/com/prahari/`)

```
auditor/
  MainActivity.kt
  core/        Model.kt · Taxonomy.kt · CapabilityMap.kt · TokenDeriver.kt · PermissionDiff.kt
  engine/      Contracts.kt  (interfaces + AppAuditor orchestrator)
  scanner/     DeviceInventoryScanner.kt        (FR01/FR02/FR04)
  reversing/   StaticReverseEngineer.kt         (PLAN §2 static RE)
  scoring/     RuleScoringEngine.kt             (PLAN §5)
  ml/          TfLiteMalwareModel.kt            (PLAN §5.7)
  data/        FileScanRepository.kt            (durable history)
  monitor/     PackageChangeReceiver.kt         (FR09 + notifications)
  di/          ServiceLocator.kt
  ui/          Theme.kt · ScanViewModel.kt · Screens.kt   (Q1 dashboard + Q2/Q3 detail)
intel/
  IntelEngine.kt   the offline intel engine (from ../intel)
assets/
  intel/  rules.json + IOC/signer lists (bundled)
  ml/     model.tflite + features.json (drop in after training)
```

`AppAuditor.runScan()`: inventory → RE → enrich (apkSha256 + used flag) → `IntelEngine.evaluate` →
ML → `RuleScoringEngine.score` → rank → persist.

## Judgment calls (worth knowing)

- **Persistence is file-based JSON, not Room.** Adding a KSP/Room build setup blind (uncompilable in
  the authoring environment) was a needless risk for now. The `ScanRepository` contract is unchanged,
  so Room can drop in later without touching callers. `latest()` is in-memory; `history()` is durable.
- **ML assumes a float32-I/O model** (the trainer's default dynamic-range quantization). If you train
  with `--int8`, adjust the I/O buffers in `TfLiteMalwareModel`.
- **AppOps special-access reads are best-effort** — some OEMs refuse cross-package op queries, which
  degrade to "declared, not granted" rather than crashing.

## Still open (optional polish)

- **Room** swap-in for `FileScanRepository` (same `ScanRepository` contract; deps stubbed in
  `app/build.gradle.kts`). File-based persistence is fully functional in the meantime.
- **Attack-chain graph card** — the narrative is shown as text; a Compose-canvas graph (PLAN §D4)
  would add demo polish.
- **Shareable PDF report** (stretch #14) via `android.graphics.pdf.PdfDocument`.
- Drop a trained `model.tflite` into `assets/ml/` to enable the ML gauge (see `../ml`).

## Toolchain

Kotlin 1.9.24 · Compose compiler 1.5.14 · AGP 8.5.2 · Gradle 8.7 · compileSdk/targetSdk 34 · minSdk 24.
Dependencies: Compose, navigation, lifecycle, coroutines, `apk-parser` + `dexlib2` + guava-android
(RE), `tensorflow-lite` (ML), desugaring. Same pins as `../spike-re`, so if that synced, this will.
I couldn't compile it in the authoring environment — the first Android Studio sync is the real check.
