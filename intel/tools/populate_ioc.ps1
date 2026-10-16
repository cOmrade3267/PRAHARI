<#
  populate_ioc.ps1 — append the inert test fixtures' APK SHA-256 to the IOC list as planted,
  clearly-labelled demo samples. Run AFTER building the fixtures:

      cd ..\..\test-fixtures ; .\gradlew assembleDebug        # (or build them in Android Studio)
      cd ..\intel\tools      ; .\populate_ioc.ps1

  Truthful by construction: it only ever adds hashes of YOUR OWN inert fixtures, each tagged
  "(inert demo fixture)". It never invents entries and skips hashes already present.
#>

$ErrorActionPreference = 'Stop'

$here      = Split-Path -Parent $MyInvocation.MyCommand.Path
$iocFile   = Join-Path $here '..\assets\intel\ioc_hashes.txt'
$fixtures  = Join-Path $here '..\..\test-fixtures'

if (-not (Test-Path $fixtures)) { Write-Error "test-fixtures not found at $fixtures"; return }

$apks = Get-ChildItem -Path $fixtures -Recurse -Filter '*.apk' |
        Where-Object { $_.FullName -match '\\build\\outputs\\apk\\debug\\' }

if (-not $apks) {
    Write-Warning "No debug APKs found. Build the fixtures first (./gradlew assembleDebug)."
    return
}

$existing = @()
if (Test-Path $iocFile) { $existing = Get-Content $iocFile }

$added = 0
foreach ($apk in $apks) {
    $hash = (Get-FileHash -Algorithm SHA256 -Path $apk.FullName).Hash.ToLower()
    if ($existing -match $hash) { Write-Host "skip (already present): $($apk.Name)"; continue }
    $module = ($apk.FullName -split '\\test-fixtures\\')[1].Split('\')[0]
    $line = "$hash  fixture:$module (inert demo fixture)"
    Add-Content -Path $iocFile -Value $line -Encoding utf8
    Write-Host "added: $line"
    $added++
}
Write-Host "`nDone. $added fixture hash(es) appended to $iocFile"
