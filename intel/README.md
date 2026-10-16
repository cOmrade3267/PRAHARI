# Prahari — Offline Threat-Intel Pack

A fully offline, bundle-in-`assets/` intelligence layer that turns the auditor's static facts into attributed risk hits. It is the honest, offline replacement for PS stretch #11 (online hash lookup): **no network, ever** — the APK declares no `INTERNET` permission.

```
intel/
  assets/intel/rules.json        → bundle at app/src/main/assets/intel/rules.json
  assets/intel/ioc_hashes.txt     → APK/DEX SHA-256 IOC list (ships empty of real malware)
  assets/intel/bad_signers.txt    → signing-cert SHA-256 list (ships empty of real malware)
  kotlin/com/prahari/intel/IntelEngine.kt  → drop into the :intel package
  tools/populate_ioc.ps1          → fill the IOC list with your own fixtures' hashes (truthful)
```

## What it detects

| Rule type | Signal | Input it needs |
|---|---|---|
| **IOC hash** | APK SHA-256 on the offline list → **force Critical** | `apkSha256` |
| **Bad signer** | signing-cert SHA-256 on the list → **force Critical** | `signerSha256` |
| **Packers** | commercial protector class markers (Jiagu, Bangcle/SecNeo, Legu, Ijiami, Baidu, Ali, DexProtector…) | `dexClassNames` |
| **Native packers** | protector `.so` name markers | `nativeLibNames` |
| **Target lists** | app embeds ≥N known banking/crypto package names (overlay-trojan trait) | `dexStrings` |
| **C2 patterns** | hardcoded IPs, abused TLDs, Telegram-bot / pastebin dead-drops, dynamic-DNS (all heuristic) | `dexStrings` |
| **Combination rules** | overlay+accessibility, accessibility+SMS+device-admin, dropper, admin-abuse, context-mismatch, spyware, screen-remote | `tokens` + `permissions` |

Every hit carries `{ruleId, label, weight, family, evidence}` so the scoring engine can both **score** (add the weight; IOC/signer `forcesCritical`) and **explain** (print the evidence in the "Why flagged" panel).

## `rules.json` schema (v1)

- `packers[]` — `{id, label, classPrefixes[], weight}`; fires if any `classPrefix` prefixes any DEX class descriptor (`Lcom/foo/Bar;`).
- `nativePackers[]` — `{id, label, libNameContains[], weight}`; substring match on native lib entry names.
- `targetLists[]` — `{id, label, packageNames[], threshold, weight, family}`; fires when ≥`threshold` names appear in DEX strings.
- `c2Patterns[]` — `{id, label, regex, weight, heuristic}`; regex is matched case-insensitively against a bounded view of DEX strings.
- `comboRules[]` — `{id, label, allOf[], anyOf[], noneOf[], weight, family}`; set logic over the **token universe**.
- `iocHashFile` / `badSignerFile` / `iocWeight` / `badSignerWeight`.

### Token vocabulary (for `comboRules`)
The caller assembles `AppFacts.tokens`; the engine also auto-adds `perm.<SHORT>` for every permission (e.g. `android.permission.READ_SMS` → `perm.READ_SMS`). Canonical tokens the RE/inventory layer should emit:

- **Capabilities:** `cap.accessibility_service`, `cap.overlay`, `cap.sms_read`, `cap.sms_send`, `cap.device_admin`, `cap.notification_listener`, `cap.install_packages`, `cap.dynamic_code`, `cap.screen_capture`, `cap.network`, `cap.boot_persistence`, `cap.location`, `cap.mic`, `cap.camera`, `cap.contacts`, `cap.call_log`, `cap.clipboard`, `cap.reflection`, `cap.process_exec`, `cap.enumerate_packages`
- **Context:** `ctx.category_utility` (torch/calc/wallpaper/qr/battery), `ctx.category_security` (AV/MDM — suppresses `combo.admin_abuse`)
- **Installer:** `src.sideloaded`, `src.playstore`, `src.other_store`
- **Flags:** `flag.debuggable`, `flag.cleartext`, `flag.debug_signed`

## Integrating with the RE engine

`IntelEngine` consumes `AppFacts`. The spike (`../spike-re`) already produces most of it; to feed the intel engine fully, extend the dexlib2 pass to also collect:
- **class names** — iterate `dexFile.classes` and keep `classDef.type` (the `Lx/y/Z;` descriptor);
- **string constants** — collect `StringReference` values (bound the count/length as the engine does);
- **native libs** — list `lib/*/*.so` entries from the APK zip.

Then build facts and evaluate:

```kotlin
val intel = IntelEngine.fromAssets(context)            // loads assets/intel/*
val hits  = intel.evaluate(
    IntelEngine.AppFacts(
        packageName   = pkg,
        tokens        = capabilityTokens,              // cap.* / ctx.* / src.* / flag.*
        permissions   = declaredOrGrantedPermissions,  // full names
        dexClassNames = dexClassDescriptors,
        dexStrings    = dexStringSample,
        nativeLibNames= nativeSoNames,
        signerSha256  = signerSha256,
        apkSha256     = apkSha256,
    )
)
// scoring: sum hit.weight; if any hit.forcesCritical → band = Critical; show hit.evidence in "Why flagged"
```

## Honesty & safety notes (important for judging and for the no-malware rule)

- **Packer markers** and **target package names** are real, public identifiers (the kind tools like APKiD detect, and ordinary app IDs) — not malware, and not copied from any GPL ruleset.
- **C2 patterns** are heuristics and *will* occasionally match benign apps (e.g. a legit app using a `.top` domain). They are weighted low and labelled "(heuristic)". Keep the rule score as the explanation source; never present a heuristic hit as proof.
- **IOC / bad-signer lists ship empty of real-malware entries.** Fabricating "known-bad" hashes would be dishonest and is disallowed. Populate them truthfully with your own fixtures (`tools/populate_ioc.ps1`) and/or publicly published IOC hashes.

## Demo with the fixtures (`../test-fixtures`)

After `populate_ioc.ps1` adds the fixtures' hashes, the fixtures light up multiple layers at once:

| Fixture | Intel hits you should see |
|---|---|
| `flashlight` | `combo.overlay_accessibility`, `combo.context_mismatch`, `combo.sms_stealer`, plus an IOC-hash hit (planted) |
| `quickcalc` | `combo.dropper`, `combo.sideloaded_dangerous` (if sideloaded), IOC-hash hit |
| `wallpaper` | `combo.spyware`, `combo.context_mismatch`, IOC-hash hit |
| `notebench` | none — stays Low |

> The packer/target-list/C2 rules won't fire on the fixtures (they aren't packed and embed no target list); to demo those, point the auditor at an app that genuinely carries those traits, or add a small fixture that embeds a target-list string array.
