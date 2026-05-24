#Requires -Version 5.1
param(
    [Parameter(Mandatory)][string]$StageDir,
    [Parameter(Mandatory)][string]$OutDir,
    [string]$Version = "0.1.0"
)
$ErrorActionPreference = "Stop"

$OutExe  = Join-Path $OutDir "Lancer-Setup.exe"
$SedFile = Join-Path $OutDir "lancer-installer.sed"

function Invoke-ZipFallback {
    Write-Host "  Creating portable zip instead..." -ForegroundColor Yellow
    $zipPath = Join-Path $OutDir ("Lancer-" + $Version + "-Windows.zip")
    Compress-Archive -Force -Path (Join-Path $StageDir "*") -DestinationPath $zipPath
    $size = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
    Write-Host ""
    Write-Host ("  Zip created: " + $zipPath + "  (" + $size + " MB)") -ForegroundColor Yellow
    Write-Host "  To install: extract the zip, then run install.ps1" -ForegroundColor DarkGray
}

$files = @(Get-ChildItem -Path $StageDir -File | Select-Object -ExpandProperty Name)
if ($files.Count -eq 0) { Write-Error "Stage directory '$StageDir' is empty." }
Write-Host ("  Packaging " + $files.Count + " files into Lancer-Setup.exe...") -ForegroundColor Cyan

$fileLines = ""
$srcLines  = ""
for ($i = 0; $i -lt $files.Count; $i++) {
    $fileLines += "FILE$i=" + $files[$i] + "`r`n"
    $srcLines  += "%FILE$i%=`r`n"
}
$fileLines = $fileLines.TrimEnd()
$srcLines  = $srcLines.TrimEnd()

$sedContent = "[Version]`r`n" +
    "Class=IEXPRESS`r`n" +
    "SEDVersion=3`r`n" +
    "[Options]`r`n" +
    "PackagePurpose=InstallApp`r`n" +
    "ShowInstallProgramWindow=1`r`n" +
    "HideExtractAnimation=0`r`n" +
    "UseLongFileName=1`r`n" +
    "InsideCompressed=0`r`n" +
    "CAB_FixedSize=0`r`n" +
    "CAB_ResvCodeSigning=0`r`n" +
    "RebootMode=I`r`n" +
    "InstallPrompt=%InstallPrompt%`r`n" +
    "DisplayLicense=%DisplayLicense%`r`n" +
    "FinishMessage=%FinishMessage%`r`n" +
    "TargetName=%TargetName%`r`n" +
    "FriendlyName=%FriendlyName%`r`n" +
    "AppLaunched=%AppLaunched%`r`n" +
    "PostInstallCmd=%PostInstallCmd%`r`n" +
    "AdminQuietInstCmd=%AdminQuietInstCmd%`r`n" +
    "UserQuietInstCmd=%UserQuietInstCmd%`r`n" +
    "SourceFiles=SourceFiles`r`n" +
    "[Strings]`r`n" +
    "InstallPrompt=Do you want to install Lancer " + $Version + " on this computer?`r`n" +
    "DisplayLicense=`r`n" +
    "FinishMessage=Lancer " + $Version + " has been installed successfully!`r`n" +
    "TargetName=" + $OutExe + "`r`n" +
    "FriendlyName=Lancer " + $Version + " Setup`r`n" +
    "AppLaunched=run-install.bat`r`n" +
    "PostInstallCmd=<None>`r`n" +
    "AdminQuietInstCmd=`r`n" +
    "UserQuietInstCmd=`r`n" +
    $fileLines + "`r`n" +
    "[SourceFiles]`r`n" +
    "SourceFiles0=" + $StageDir + "\`r`n" +
    "[SourceFiles0]`r`n" +
    $srcLines + "`r`n"

[System.IO.File]::WriteAllText($SedFile, $sedContent, [System.Text.Encoding]::ASCII)
Write-Host ("  SED file written: " + $SedFile) -ForegroundColor DarkGray

$iexpress = "$env:windir\System32\IExpress.exe"
if (-not (Test-Path $iexpress)) {
    Write-Host "  IExpress not found -- falling back to zip." -ForegroundColor Yellow
    Invoke-ZipFallback
    exit 0
}

Write-Host "  Running IExpress (may take 30-120 s for large binaries)..." -ForegroundColor DarkGray
if (Test-Path $OutExe) { Remove-Item -Force $OutExe }

$proc = Start-Process -FilePath $iexpress -ArgumentList ("/N /Q `"" + $SedFile + "`"") -PassThru -NoNewWindow
if ($null -eq $proc) {
    Write-Host "  Could not start IExpress." -ForegroundColor Yellow
    Invoke-ZipFallback
    exit 0
}

$deadline = (Get-Date).AddSeconds(120)
while (-not (Test-Path $OutExe)) {
    if ((Get-Date) -gt $deadline) { break }
    Start-Sleep -Seconds 2
}
Start-Sleep -Seconds 2

if (Test-Path $OutExe) {
    $size = [math]::Round((Get-Item $OutExe).Length / 1MB, 1)
    Write-Host ""
    Write-Host ("  Installer created: " + $OutExe + "  (" + $size + " MB)") -ForegroundColor Green
    Write-Host "  Done!" -ForegroundColor Green
    exit 0
}

Write-Host "  IExpress finished but output not found -- falling back to zip." -ForegroundColor Yellow
Invoke-ZipFallback
