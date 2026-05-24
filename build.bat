@echo off
setlocal enabledelayedexpansion
title Lancer Build + Installer

REM ============================================================
REM  build.bat  -- Double-click to build Lancer and produce
REM               a single-file Windows installer:
REM
REM    build\Lancer-Setup.exe
REM
REM  Requirements:
REM    - Rust / Cargo   https://rustup.rs
REM    - Node.js / npm  https://nodejs.org
REM    - Visual C++ Build Tools (2019/2022)
REM ============================================================

set "REPO=%~dp0"
set "REPO=%REPO:~0,-1%"
set "BUILD=%REPO%\build"
set "STAGE=%BUILD%\stage"
set "VERSION=0.1.0"

echo.
echo  ================================================
echo    Lancer  Build + Installer Creator
echo  ================================================
echo.
echo  Repo   : %REPO%
echo  Output : %BUILD%\Lancer-Setup.exe
echo.

REM ── Locate cargo ──────────────────────────────────────────────────────────
where cargo >nul 2>&1
if errorlevel 1 (
    set "CARGO=%USERPROFILE%\.cargo\bin\cargo.exe"
    if not exist "!CARGO!" (
        echo  ERROR: cargo not found.
        echo  Install Rust from https://rustup.rs then re-run.
        echo.
        pause & exit /b 1
    )
) else (
    set "CARGO=cargo"
)

REM ── Locate npm ────────────────────────────────────────────────────────────
where npm >nul 2>&1
if errorlevel 1 (
    echo  ERROR: npm not found.
    echo  Install Node.js from https://nodejs.org then re-run.
    echo.
    pause & exit /b 1
)

REM ════════════════════════════════════════════════════════════════
echo  [1/5]  Building Svelte frontend (SPA)...
echo  ──────────────────────────────────────
pushd "%REPO%\crates\lancer-gui\web"
if not exist node_modules (
    echo         Installing npm packages (first run)...
    call npm install --silent
    if errorlevel 1 ( popd & echo  ERROR: npm install failed & pause & exit /b 1 )
)
call npm run build
if errorlevel 1 ( popd & echo  ERROR: Svelte build failed & pause & exit /b 1 )
popd
echo         Done.
echo.

REM ════════════════════════════════════════════════════════════════
echo  [2/5]  Building Rust release binaries...
echo  ─────────────────────────────────────────
echo         (first build may take several minutes)
echo.
"!CARGO!" build --release -p lancer-gui -p lancer-api
if errorlevel 1 ( echo. & echo  ERROR: cargo build failed & pause & exit /b 1 )
echo.
echo         Done.
echo.

REM ════════════════════════════════════════════════════════════════
echo  [3/5]  Staging files...
echo  ────────────────────────

if not exist "%BUILD%"  mkdir "%BUILD%"
if exist "%STAGE%"      rmdir /s /q "%STAGE%"
mkdir "%STAGE%"

copy /Y "%REPO%\target\release\lancer-gui.exe" "%STAGE%\" >nul
if errorlevel 1 ( echo  ERROR: lancer-gui.exe missing & pause & exit /b 1 )
echo         lancer-gui.exe

copy /Y "%REPO%\target\release\lancer-api.exe" "%STAGE%\" >nul
if errorlevel 1 ( echo  ERROR: lancer-api.exe missing & pause & exit /b 1 )
echo         lancer-api.exe

if exist "%REPO%\target\release\lancer.exe" (
    copy /Y "%REPO%\target\release\lancer.exe" "%STAGE%\" >nul
    echo         lancer.exe
)
if exist "%REPO%\LICENSE"   ( copy /Y "%REPO%\LICENSE"   "%STAGE%\" >nul & echo         LICENSE   )
if exist "%REPO%\README.md" ( copy /Y "%REPO%\README.md" "%STAGE%\" >nul & echo         README.md )
if exist "%REPO%\crates\lancer-gui\assets\lancer.ico" (
    copy /Y "%REPO%\crates\lancer-gui\assets\lancer.ico" "%STAGE%\" >nul
    echo         lancer.ico
)
copy /Y "%REPO%\installer\install.ps1" "%STAGE%\" >nul
if errorlevel 1 ( echo  ERROR: installer\install.ps1 not found & pause & exit /b 1 )
echo         install.ps1
echo.

REM ════════════════════════════════════════════════════════════════
echo  [4/5]  Bundling payload zip...
echo  ────────────────────────────────

set "PAYLOAD=%BUILD%\lancer-payload.zip"
if exist "%PAYLOAD%" del /f /q "%PAYLOAD%"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "Compress-Archive -Force -Path '%STAGE%\*' -DestinationPath '%PAYLOAD%'"
if errorlevel 1 ( echo  ERROR: zip creation failed & pause & exit /b 1 )
echo         lancer-payload.zip created.
echo.

REM ════════════════════════════════════════════════════════════════
echo  [5/5]  Building self-extracting installer...
echo  ─────────────────────────────────────────────

set LANCER_INSTALLER_ZIP=%PAYLOAD%
"!CARGO!" build --release -p lancer-setup
if errorlevel 1 ( echo. & echo  ERROR: lancer-setup build failed & pause & exit /b 1 )

set "SETUP=%BUILD%\Lancer-Setup.exe"
copy /Y "%REPO%\target\release\lancer-setup.exe" "%SETUP%" >nul
if errorlevel 1 ( echo  ERROR: lancer-setup.exe not found in target\release & pause & exit /b 1 )

REM Clean up intermediate files -- keep only the final installer
del /f /q "%PAYLOAD%"         >nul 2>&1
rmdir /s /q "%STAGE%"         >nul 2>&1
del /f /q "%BUILD%\*.sed"     >nul 2>&1

echo.
echo  ================================================
echo    All done!  Installer ready:
echo.
echo    %SETUP%
echo.
echo    Double-click on any Windows PC to install.
echo  ================================================
echo.

explorer "%BUILD%"
pause
endlocal
