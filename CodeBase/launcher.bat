@echo off
REM launcher.bat — Windows CLI parity entrypoint delegating to dev.bat (CN-DIR-2026-004)
cd /d "%~dp0"
if not "%~1"=="" (
    call dev.bat %*
    exit /b %errorlevel%
)
echo ==================================================
echo  CyberNest Labs // AutoDorker Launcher (Windows)
echo ==================================================
echo  1) setup    - Provision .venv ^& verify tools
echo  2) build    - Compile Rust/Go binaries ^& seed DB
echo  3) run      - Launch 127.0.0.1:8090 Gateway
echo  4) cli      - Diagnostic ^& WAL backup check
echo  5) simulate - Ephemeral mock HTTP E2E audit
echo  6) test     - Run Rust + Go + Python test suites
echo  7) fmt      - Format Rust ^& Go sources
set /p CHOICE="Select [1-7]: "
if "%CHOICE%"=="1" call dev.bat setup
if "%CHOICE%"=="2" call dev.bat build
if "%CHOICE%"=="3" call dev.bat run
if "%CHOICE%"=="4" call dev.bat cli
if "%CHOICE%"=="5" call dev.bat simulate
if "%CHOICE%"=="6" call dev.bat test
if "%CHOICE%"=="7" call dev.bat fmt
