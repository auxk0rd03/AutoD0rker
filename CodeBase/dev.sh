#!/bin/sh
# dev.sh — CN-DIR-2026-004 Compliant POSIX Orchestrator for AutoDorker
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

if ! command -v go >/dev/null 2>&1 && [ -x "/usr/local/go/bin/go" ]; then
    PATH="$PATH:/usr/local/go/bin"
    export PATH
fi

APP_NAME="autodorker"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/${APP_NAME}"
LOG_FILE="${CACHE_DIR}/session.log"
PID_FILE="${CACHE_DIR}/gateway.pid"
BIND_ADDR="${AUTODORKER_BIND_ADDR:-127.0.0.1:8090}"
DB_PATH="${AUTODORKER_DB_PATH:-${SCRIPT_DIR}/data/autodorker_state.db}"
DORK_CSV="${AUTODORKER_DORKSET_PATH:-${SCRIPT_DIR}/../Docs/DorkSet.csv}"

init_secure_runtime_dir() {
    # CWE-377 Mitigation: Refuse symlinked cache/log/pid paths and enforce 0700 permissions
    if [ -L "$CACHE_DIR" ]; then
        printf '[ERR_HALT] Security violation: %s is a symbolic link (CWE-377).\n' "$CACHE_DIR" >&2
        exit 1
    fi
    mkdir -p "$CACHE_DIR"
    chmod 0700 "$CACHE_DIR"

    for f in "$LOG_FILE" "$PID_FILE"; do
        if [ -L "$f" ]; then
            printf '[ERR_HALT] Security violation: %s is a symbolic link (CWE-377).\n' "$f" >&2
            exit 1
        fi
    done
    umask 0077
    : > "$LOG_FILE"
}

ensure_venv() {
    if [ ! -x ".venv/bin/python" ]; then
        printf '[SETUP] Provisioning Python .venv...\n'
        python3 -m venv .venv
        .venv/bin/pip install --upgrade pip >/dev/null
        .venv/bin/pip install -r requirements.txt
    fi
}

cmd_setup() {
    printf '[SETUP] Checking toolchain prerequisites (go, cargo, python3)...\n'
    for tool in go cargo rustc python3; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            printf '[ERR_HALT] Required tool missing: %s\n' "$tool" >&2
            exit 1
        fi
    done
    ensure_venv
    mkdir -p bin data/backups data/Output
    printf '[OK] Toolchain and .venv verified.\n'
}

cmd_build() {
    printf '[BUILD] Compiling Rust dork_spider engine (release)...\n'
    (cd crates/dork_spider && cargo build --release)
    mkdir -p bin
    cp crates/dork_spider/target/release/dork_spider bin/dork_spider
    chmod 0750 bin/dork_spider

    printf '[BUILD] Compiling Go loopback gateway (GOFIPS=1 // GOFIPS140=v1.0.0)...\n'
    (cd cmd/gateway && GOFIPS=1 GOFIPS140=v1.0.0 go build -ldflags="-s -w" -o ../../bin/gateway .)
    chmod 0750 bin/gateway

    if [ -f "$DORK_CSV" ]; then
        printf '[SEED] Ingesting 295 DorkSet rules into SQLite3 WAL catalog...\n'
        ./bin/dork_spider --ingest-csv "$DORK_CSV" --db "$DB_PATH"
    fi
    if [ -x ".venv/bin/python" ]; then
        printf '[SBOM] Regenerating CycloneDX 1.5, SPDX 2.3, and SBOM.md...\n'
        .venv/bin/python -m py_engine.cli --generate-sbom >/dev/null
    fi
    printf '[OK] Polyglot binaries staged in ./bin/\n'
}

cmd_run() {
    init_secure_runtime_dir
    ensure_venv
    if [ ! -x "bin/gateway" ] || [ ! -x "bin/dork_spider" ]; then
        cmd_build
    fi

    # CWE-114 PID lock check
    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat "$PID_FILE" 2>/dev/null || true)
        if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
            printf '[ERR_HALT] Gateway already running with PID %s (CWE-114).\n' "$OLD_PID" >&2
            exit 1
        fi
    fi

    printf '[LAUNCH] Binding %s strictly to http://%s\n' "$APP_NAME" "$BIND_ADDR"
    AUTODORKER_DB_PATH="$DB_PATH" ./bin/gateway --bind "$BIND_ADDR" >>"$LOG_FILE" 2>&1 &
    GATEWAY_PID=$!
    printf '%s\n' "$GATEWAY_PID" > "$PID_FILE"
    printf '[PID_LOCK] Process %s recorded in %s (CWE-114)\n' "$GATEWAY_PID" "$PID_FILE"
    trap 'rm -f "$PID_FILE"; kill "$GATEWAY_PID" 2>/dev/null || true' INT TERM
    wait "$GATEWAY_PID"
    rm -f "$PID_FILE"
}

cmd_cli() {
    ensure_venv
    if [ ! -x "bin/dork_spider" ]; then
        cmd_build
    fi
    if [ $# -ge 1 ] && [ -n "$1" ]; then
        printf '[CLI] Executing headless AutoDorker audit for: %s\n' "$1"
        ./bin/dork_spider --scan --target "$1" --db "$DB_PATH" --json
    else
        printf '[CLI] Running CMMC 2.0 L2 & SQLite WAL catalog verification...\n'
        ./bin/dork_spider --ingest-csv "$DORK_CSV" --db "$DB_PATH"
        ./scripts/sys_telemetry.sh "$DB_PATH"
        ./scripts/backup_and_sign.sh "$DB_PATH" data/backups
    fi
}

cmd_simulate() {
    ensure_venv
    if [ ! -x "bin/dork_spider" ]; then
        cmd_build
    fi
    printf '[SIMULATE] Running ephemeral local mock HTTP server batch simulation...\n'
    .venv/bin/python -m unittest tests.test_exports_e2e -v
}

cmd_test() {
    ensure_venv
    printf '[TEST] Running Rust AST & Shannon Entropy suite (cargo test)...\n'
    (cd crates/dork_spider && cargo test --locked)

    printf '[TEST] Running Go SSRF & Input Sanitizer suite (go test)...\n'
    (cd cmd/gateway && go test -v ./...)
    (cd tests && go test -v ./...)

    printf '[TEST] Running Python E2E AST, .MD & .DOCX verification suite...\n'
    .venv/bin/python -m unittest discover -s tests -p "test_*.py" -v
    printf '[OK] All polyglot verification suites passed.\n'
}

cmd_fmt() {
    printf '[FMT] Formatting Rust & Go source trees...\n'
    (cd crates/dork_spider && cargo fmt)
    (cd cmd/gateway && go fmt ./...)
    (cd tests && go fmt ./...)
    printf '[OK] Formatting complete.\n'
}

case "${1:-help}" in
    setup) cmd_setup ;;
    build) cmd_build ;;
    run|serve) cmd_run ;;
    cli) shift; cmd_cli "${1:-}" ;;
    simulate) cmd_simulate ;;
    test) cmd_test ;;
    fmt) cmd_fmt ;;
    *)
        printf 'Usage: %s {setup|build|run|serve|cli [url]|simulate|test|fmt}\n' "$0"
        exit 1
        ;;
esac
