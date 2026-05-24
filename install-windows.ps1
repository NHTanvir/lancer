# Windows installer for Lancer.
# Installs binaries to %LOCALAPPDATA%\Lancer\bin and adds it to PATH.
# Usage:  powershell -ExecutionPolicy Bypass -File install-windows.ps1
#         powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Uninstall
param(
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

$InstallRoot = Join-Path $env:LOCALAPPDATA "Lancer"
$BinDir      = Join-Path $InstallRoot "bin"
$DistDir     = Join-Path $PSScriptRoot "dist\lancer-windows-x86_64\bin"

function Add-ToUserPath {
    param([string]$Dir)
    $current = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @()
    if ($current) { $parts = $current -split ';' | Where-Object { $_ } }
    if ($parts -notcontains $Dir) {
        $parts += $Dir
        [Environment]::SetEnvironmentVariable("Path", ($parts -join ';'), "User")
        Write-Host "Added $Dir to user PATH."
    } else {
        Write-Host "$Dir already on PATH."
    }
}

function Remove-FromUserPath {
    param([string]$Dir)
    $current = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $current) { return }
    $parts = $current -split ';' | Where-Object { $_ -and $_ -ne $Dir }
    [Environment]::SetEnvironmentVariable("Path", ($parts -join ';'), "User")
}

if ($Uninstall) {
    if (Test-Path $InstallRoot) {
        Write-Host "Removing $InstallRoot ..."
        Remove-Item -Recurse -Force $InstallRoot
    }
    Remove-FromUserPath $BinDir
    $shortcut = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\Lancer.lnk"
    if (Test-Path $shortcut) { Remove-Item -Force $shortcut }
    Write-Host "Lancer uninstalled."
    return
}

if (-not (Test-Path $DistDir)) {
    Write-Error "Build first: run build-windows.bat. Expected: $DistDir"
    exit 1
}

Write-Host "Installing Lancer to $InstallRoot ..."
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Copy-Item -Force -Recurse "$DistDir\*" $BinDir
Add-ToUserPath $BinDir

# Start Menu shortcut for the GUI (if it exists)
$guiPath = Join-Path $BinDir "lancer-gui.exe"
if (Test-Path $guiPath) {
    $startMenu = [Environment]::GetFolderPath("StartMenu")
    $programs  = Join-Path $startMenu "Programs"
    New-Item -ItemType Directory -Force -Path $programs | Out-Null
    $shortcut = Join-Path $programs "Lancer.lnk"
    $wsh = New-Object -ComObject WScript.Shell
    $sc = $wsh.CreateShortcut($shortcut)
    $sc.TargetPath = $guiPath
    $sc.WorkingDirectory = $BinDir
    $sc.Save()
    Write-Host "Start Menu shortcut created."
}

Write-Host ""
Write-Host "Done. Open a NEW shell, then:"
Write-Host "  lancer --help"
Write-Host "  lancer-api --listen 127.0.0.1:9191 --project ./demo.lancer"
