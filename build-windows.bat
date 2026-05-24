@echo off
REM Windows release build for Lancer.
REM Output: target\release\lancer.exe, lancer-api.exe, lancer-gui.exe
REM Then packages them into dist\lancer-windows-x86_64\

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1

echo === Building Svelte SPA ===
pushd crates\lancer-gui\web
if not exist node_modules call npm install
if errorlevel 1 (popd & exit /b 1)
call npm run build
if errorlevel 1 (popd & exit /b 1)
popd

echo === Building Lancer (release) for Windows x86_64 ===
cargo build --release --workspace --no-default-features --bins
if errorlevel 1 exit /b 1

echo === Packaging ===
set DIST=dist\lancer-windows-x86_64
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\bin"

copy target\release\lancer.exe "%DIST%\bin\" >nul
copy target\release\lancer-api.exe "%DIST%\bin\" >nul
copy target\release\lancer-gui.exe "%DIST%\bin\" >nul 2>nul
copy LICENSE "%DIST%\" >nul 2>nul
copy README.md "%DIST%\" >nul 2>nul

echo === Done. Binaries: %DIST%\bin ===
dir "%DIST%\bin"
exit /b 0
