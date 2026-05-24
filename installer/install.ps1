#Requires -Version 5.1
<#
.SYNOPSIS
    Lancer installer — copies binaries, creates shortcuts, registers uninstaller.
    Called automatically by Lancer-Setup.exe after file extraction.
#>

$ErrorActionPreference = "Stop"

$ExtractDir  = $PSScriptRoot           # folder where IExpress extracted us
$InstallRoot = Join-Path $env:LOCALAPPDATA "Lancer"
$BinDir      = Join-Path $InstallRoot  "bin"
$Version     = "0.1.0"

# ── Banner ──────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host "    Lancer $Version — Windows Installer"        -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host ""

# ── Confirm ─────────────────────────────────────────────────────────────────
$reply = Read-Host "  Install Lancer to '$BinDir'? [Y/n]"
if ($reply -match '^[Nn]') {
    Write-Host "  Installation cancelled." -ForegroundColor Yellow
    exit 0
}

# ── Create install directory ─────────────────────────────────────────────────
Write-Host ""
Write-Host "  [1/5] Creating install directory..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

# ── Copy binaries ─────────────────────────────────────────────────────────────
Write-Host "  [2/5] Copying binaries..." -ForegroundColor Green
$exeNames = @("lancer-gui.exe", "lancer-api.exe", "lancer.exe")
$copied = 0
foreach ($exe in $exeNames) {
    $src = Join-Path $ExtractDir $exe
    if (Test-Path $src) {
        Copy-Item -Force $src $BinDir
        Write-Host "        $exe" -ForegroundColor DarkGray
        $copied++
    }
}
if ($copied -eq 0) {
    Write-Host "  ERROR: No binaries found in '$ExtractDir'" -ForegroundColor Red
    Write-Host "  Expected lancer-gui.exe and lancer-api.exe." -ForegroundColor Red
    Read-Host "  Press Enter to exit"
    exit 1
}
# Copy any support files
foreach ($f in @("LICENSE", "README.md", "lancer.ico")) {
    $src = Join-Path $ExtractDir $f
    if (Test-Path $src) { Copy-Item -Force $src $BinDir }
}

# ── Desktop & Start Menu shortcuts ────────────────────────────────────────────
Write-Host "  [3/5] Creating shortcuts..." -ForegroundColor Green
$guiExe = Join-Path $BinDir "lancer-gui.exe"
if (Test-Path $guiExe) {
    $wsh = New-Object -ComObject WScript.Shell

    $icoPath = Join-Path $BinDir "lancer.ico"

    # Desktop
    $desktop  = [Environment]::GetFolderPath("Desktop")
    $lnkDesk  = Join-Path $desktop "Lancer.lnk"
    $sc = $wsh.CreateShortcut($lnkDesk)
    $sc.TargetPath       = $guiExe
    $sc.WorkingDirectory = $BinDir
    $sc.Description      = "Lancer Web Security Toolkit"
    if (Test-Path $icoPath) { $sc.IconLocation = "$icoPath,0" }
    $sc.Save()
    Write-Host "        Desktop shortcut: $lnkDesk" -ForegroundColor DarkGray

    # Start Menu
    $startMenu = [Environment]::GetFolderPath("StartMenu")
    $smDir     = Join-Path $startMenu "Programs\Lancer"
    New-Item -ItemType Directory -Force -Path $smDir | Out-Null
    $lnkSM = Join-Path $smDir "Lancer.lnk"
    $sc2 = $wsh.CreateShortcut($lnkSM)
    $sc2.TargetPath       = $guiExe
    $sc2.WorkingDirectory = $BinDir
    $sc2.Description      = "Lancer Web Security Toolkit"
    if (Test-Path $icoPath) { $sc2.IconLocation = "$icoPath,0" }
    $sc2.Save()
    Write-Host "        Start Menu: $lnkSM" -ForegroundColor DarkGray
}

# ── Add BinDir to user PATH ────────────────────────────────────────────────────
Write-Host "  [4/5] Updating PATH..." -ForegroundColor Green
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($null -eq $currentPath) { $currentPath = "" }
$pathParts   = $currentPath -split ';' | Where-Object { $_ }
if ($pathParts -notcontains $BinDir) {
    $pathParts += $BinDir
    [Environment]::SetEnvironmentVariable("Path", ($pathParts -join ';'), "User")
    Write-Host "        Added '$BinDir' to user PATH." -ForegroundColor DarkGray
} else {
    Write-Host "        PATH already contains Lancer." -ForegroundColor DarkGray
}

# ── Write uninstaller & register in Add/Remove Programs ───────────────────────
Write-Host "  [5/5] Registering uninstaller..." -ForegroundColor Green

$uninstallScript = Join-Path $BinDir "Uninstall-Lancer.ps1"
@"
#Requires -Version 5.1
`$BinDir      = "$BinDir"
`$InstallRoot = "$InstallRoot"
`$Desktop     = [Environment]::GetFolderPath('Desktop')
`$StartMenu   = [Environment]::GetFolderPath('StartMenu')

Write-Host 'Uninstalling Lancer...' -ForegroundColor Cyan

# Remove shortcuts
Remove-Item -Force (Join-Path `$Desktop 'Lancer.lnk') -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path `$StartMenu 'Programs\Lancer') -ErrorAction SilentlyContinue

# Remove from PATH
`$p = [Environment]::GetEnvironmentVariable('Path', 'User') -split ';' |
      Where-Object { `$_ -and `$_ -ne `$BinDir }
[Environment]::SetEnvironmentVariable('Path', (`$p -join ';'), 'User')

# Remove install directory
Remove-Item -Recurse -Force `$InstallRoot -ErrorAction SilentlyContinue

# Remove registry entry
Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Lancer' -Recurse -Force -ErrorAction SilentlyContinue

Write-Host 'Lancer has been uninstalled.' -ForegroundColor Green
Start-Sleep 2
"@ | Set-Content -Path $uninstallScript -Encoding UTF8

# Launcher bat so Add/Remove Programs can call it without PS policy issues
$uninstallBat = Join-Path $BinDir "Uninstall-Lancer.bat"
@"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Uninstall-Lancer.ps1"
"@ | Set-Content -Path $uninstallBat -Encoding ASCII

$regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Lancer"
New-Item -Path $regKey -Force | Out-Null
Set-ItemProperty $regKey "DisplayName"      "Lancer"
Set-ItemProperty $regKey "DisplayVersion"   $Version
Set-ItemProperty $regKey "Publisher"        "Lancer Security"
Set-ItemProperty $regKey "InstallLocation"  $BinDir
Set-ItemProperty $regKey "UninstallString"  "`"$uninstallBat`""
Set-ItemProperty $regKey "NoModify"         1 -Type DWord
Set-ItemProperty $regKey "NoRepair"         1 -Type DWord
Write-Host "        Registered in Add/Remove Programs." -ForegroundColor DarkGray

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host "    Lancer installed successfully!" -ForegroundColor Green
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Location : $BinDir" -ForegroundColor White
Write-Host "  Desktop  : Lancer shortcut created" -ForegroundColor White
Write-Host "  To run   : Double-click Lancer on your Desktop" -ForegroundColor White
Write-Host ""
Write-Host "  The proxy listens on 127.0.0.1:8080 by default." -ForegroundColor DarkGray
Write-Host "  Configure your browser to use it as HTTP/HTTPS proxy." -ForegroundColor DarkGray
Write-Host ""
Read-Host "  Press Enter to close"
