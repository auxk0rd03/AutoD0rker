@echo off
REM dev.bat — CN-DIR-2026-004 Windows 10/11 Parity Orchestrator for AutoDorker
setlocal enabledelayedexpansion

cd /d "%~dp0"
set "APP_NAME=autodorker"
set "CACHE_DIR=%LOCALAPPDATA%\%APP_NAME%"
set "LOG_FILE=%CACHE_DIR%\session.log"
set "BIND_ADDR=127.0.0.1:8090"
if not defined AUTODORKER_DB_PATH set "AUTODORKER_DB_PATH=%CD%\data\autodorker_state.db"
if not defined AUTODORKER_DORKSET_PATH set "AUTODORKER_DORKSET_PATH=%CD%\..\Docs\DorkSet.csv"

set "CMD=%~1"
if "%CMD%"=="" set "CMD=help"

if /I "%CMD%"=="setup" goto cmd_setup
if /I "%CMD%"=="build" goto cmd_build
if /I "%CMD%"=="run" goto cmd_run
if /I "%CMD%"=="serve" goto cmd_run
if /I "%CMD%"=="cli" goto cmd_cli
if /I "%CMD%"=="simulate" goto cmd_simulate
if /I "%CMD%"=="test" goto cmd_test
if /I "%CMD%"=="fmt" goto cmd_fmt

echo Usage: dev.bat {setup^|build^|run^|serve^|cli [url]^|simulate^|test^|fmt}
exit /b 1

:ensure_venv
if not exist ".venv\Scripts\python.exe" (
    echo [SETUP] Provisioning Python .venv...
    python -m venv .venv || exit /b 1
    .venv\Scripts\pip.exe install --upgrade pip >nul
    .venv\Scripts\pip.exe install -r requirements.txt || exit /b 1
)
exit /b 0

:cmd_setup
echo [SETUP] Checking toolchain prerequisites (go, cargo, python)...
where go >nul 2>&1 || (echo [ERR_HALT] go missing & exit /b 1)
where cargo >nul 2>&1 || (echo [ERR_HALT] cargo missing & exit /b 1)
where python >nul 2>&1 || (echo [ERR_HALT] python missing & exit /b 1)
call :ensure_venv || exit /b 1
if not exist "bin" mkdir bin
if not exist "data\backups" mkdir data\backups
if not exist "data\Output" mkdir data\Output
echo [OK] Toolchain and .venv verified.
exit /b 0

:cmd_build
echo [BUILD] Compiling Rust dork_spider engine (release)...
pushd crates\dork_spider
cargo build --release || (popd & exit /b 1)
popd
if not exist "bin" mkdir bin
copy /Y crates\dork_spider\target\release\dork_spider.exe bin\dork_spider.exe >nul

echo [BUILD] Compiling Go loopback gateway (GOFIPS=1 / GOFIPS140=v1.0.0)...
pushd cmd\gateway
set "GOFIPS=1"
set "GOFIPS140=v1.0.0"
go build -ldflags="-s -w" -o ..\..\bin\gateway.exe . || (popd & exit /b 1)
popd

if exist "%AUTODORKER_DORKSET_PATH%" (
    echo [SEED] Ingesting 295 DorkSet rules into SQLite3 WAL catalog...
    bin\dork_spider.exe --ingest-csv "%AUTODORKER_DORKSET_PATH%" --db "%AUTODORKER_DB_PATH%" || exit /b 1
)
if exist ".venv\Scripts\python.exe" (
    echo [SBOM] Regenerating CycloneDX 1.5, SPDX 2.3, and SBOM.md...
    .venv\Scripts\python.exe -m py_engine.cli --generate-sbom >nul
)
echo [OK] Polyglot binaries staged in bin\
exit /b 0

:cmd_run
call :ensure_venv || exit /b 1
if not exist "bin\gateway.exe" call :cmd_build || exit /b 1
if not exist "bin\dork_spider.exe" call :cmd_build || exit /b 1
if not exist "%CACHE_DIR%" mkdir "%CACHE_DIR%"
echo [LAUNCH] Binding %APP_NAME% strictly to http://%BIND_ADDR%
bin\gateway.exe --bind "%BIND_ADDR%"
exit /b %errorlevel%

:cmd_cli
call :ensure_venv || exit /b 1
if not exist "bin\dork_spider.exe" call :cmd_build || exit /b 1
if "%~2"=="" (
    bin\dork_spider.exe --ingest-csv "%AUTODORKER_DORKSET_PATH%" --db "%AUTODORKER_DB_PATH%"
) else (
    bin\dork_spider.exe --scan --target "%~2" --db "%AUTODORKER_DB_PATH%" --json
)
exit /b %errorlevel%

:cmd_simulate
call :ensure_venv || exit /b 1
if not exist "bin\dork_spider.exe" call :cmd_build || exit /b 1
.venv\Scripts\python.exe -m unittest tests.test_exports_e2e -v
exit /b %errorlevel%

:cmd_test
call :ensure_venv || exit /b 1
pushd crates\dork_spider
cargo test --locked || (popd & exit /b 1)
popd
pushd cmd\gateway
go test -v ./... || (popd & exit /b 1)
popd
pushd tests
go test -v ./... || (popd & exit /b 1)
popd
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
exit /b %errorlevel%

:cmd_fmt
pushd crates\dork_spider
cargo fmt
popd
pushd cmd\gateway
go fmt ./...
popd
pushd tests
go fmt ./...
popd
exit /b 0
