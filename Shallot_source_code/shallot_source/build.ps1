# build.ps1 - Build the Shallot.exe distributable on Windows.
#
# Prerequisites on the build machine:
#   * Python 3.12 or newer (https://www.python.org/downloads/)
#   * Internet access (so we can pip install pyinstaller and cryptography)
#   * Shallot.ico in this folder (already shipped with the source)
#
# Usage:
#   1. Open PowerShell in the project root (the folder containing this file).
#   2. Make sure your live directory server is reachable from this machine.
#   3. Run:
#         powershell -ExecutionPolicy Bypass -File .\build.ps1 `
#             -DirectoryServerUrl http://185.5.52.229:7071
#
# After a successful build the distributable will be at:
#   dist\Shallot\
#
# Inside that folder:
#   Shallot.exe                     - the windowed launcher
#   Shallot.ico                     - app icon
#   _internal\                      - bundled Python + libraries (do not modify)
#   extension\                      - Chrome extension (loaded via chrome://extensions)
#   directory_config.json           - pinned directory URL + signing key
#
# Hand the user the entire `dist\Shallot\` folder. They need
# nothing else installed.
#
# ----------------------------------------------------------------------

param(
    [Parameter(Mandatory=$true)]
    [string]$DirectoryServerUrl,

    # Skip the pip install steps if you've already installed deps in
    # the active Python environment. Useful for repeat local builds.
    [switch]$SkipDeps,

    # Wipe the build/ and dist/ folders before building. Recommended
    # when changing code; safe to skip for incremental rebuilds.
    [switch]$Clean = $true
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  Building Shallot.exe distributable" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  Project root        : $ProjectRoot"
Write-Host "  Directory server URL: $DirectoryServerUrl"
if (Test-Path "Shallot.ico") {
    Write-Host "  Icon                : Shallot.ico (will be embedded)" -ForegroundColor Green
} else {
    Write-Host "  Icon                : (none - drop Shallot.ico in this folder)" -ForegroundColor Yellow
}
Write-Host ""

# 1. Sanity check: Python is available.
try {
    $pyVersion = (& python --version 2>&1).ToString()
    Write-Host "[1/6] Found Python: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python is not on PATH. Install Python 3.12 from python.org and re-run." -ForegroundColor Red
    exit 1
}

# 2. Install dependencies.
if (-not $SkipDeps) {
    Write-Host "[2/6] Installing build dependencies (pyinstaller, cryptography)..." -ForegroundColor Green
    & python -m pip install --upgrade pip
    & python -m pip install --upgrade pyinstaller cryptography
    if ($LASTEXITCODE -ne 0) { Write-Host "pip install failed."; exit 1 }
} else {
    Write-Host "[2/6] Skipping dependency install (-SkipDeps)" -ForegroundColor Yellow
}

# 3. Bake directory_config.json.
Write-Host "[3/6] Pinning directory config from $DirectoryServerUrl..." -ForegroundColor Green
& python tools\install_client.py $DirectoryServerUrl
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: install_client.py failed. Is the directory server up at $DirectoryServerUrl?" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path "directory_config.json")) {
    Write-Host "ERROR: install_client.py did not produce directory_config.json." -ForegroundColor Red
    exit 1
}
$cfg = Get-Content "directory_config.json" | ConvertFrom-Json
Write-Host "      Pinned URL: $($cfg.directory_server_url)"
Write-Host "      Pinned key: $($cfg.directory_signing_pub_key_b64.Substring(0, 16))..."

# 4. Optional clean.
if ($Clean) {
    Write-Host "[4/6] Cleaning previous build artifacts..." -ForegroundColor Green
    Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
} else {
    Write-Host "[4/6] Keeping previous build artifacts (-Clean:`$false)" -ForegroundColor Yellow
}

# 5. PyInstaller.
Write-Host "[5/6] Running PyInstaller..." -ForegroundColor Green
& python -m PyInstaller --noconfirm Shallot.spec
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: PyInstaller build failed." -ForegroundColor Red
    exit 1
}
$ExePath = Join-Path $ProjectRoot "dist\Shallot\Shallot.exe"
if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: Expected $ExePath was not produced." -ForegroundColor Red
    exit 1
}

# 6. Copy extension/, directory_config.json, and the icon next to the exe.
Write-Host "[6/6] Copying extension/, directory_config.json, and icon next to Shallot.exe..." -ForegroundColor Green
$DistRoot = Join-Path $ProjectRoot "dist\Shallot"

# extension/
$ExtSrc = Join-Path $ProjectRoot "extension"
$ExtDst = Join-Path $DistRoot "extension"
if (Test-Path $ExtDst) { Remove-Item -Recurse -Force $ExtDst }
Copy-Item -Recurse $ExtSrc $ExtDst

# directory_config.json
Copy-Item (Join-Path $ProjectRoot "directory_config.json") (Join-Path $DistRoot "directory_config.json") -Force

# Icon - copy alongside the exe so users see the file and so iconbitmap()
# in the GUI can find it via bundle_resource_root() if loading from
# sys._MEIPASS fails.
$IconSrc = Join-Path $ProjectRoot "Shallot.ico"
if (Test-Path $IconSrc) {
    Copy-Item $IconSrc (Join-Path $DistRoot "Shallot.ico") -Force
}

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  Build complete." -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  Distributable folder: $DistRoot"
Write-Host ""
Write-Host "  To test, run:"
Write-Host "      cd `"$DistRoot`""
Write-Host "      .\Shallot.exe"
Write-Host ""
Write-Host "  To deliver to a user, zip the entire Shallot folder."
Write-Host ""
