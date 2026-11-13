#!/bin/sh
# dev.sh — CN-DIR-2026-004 Compliant POSIX Orchestrator for AutoDorker
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

# AutoDorker runs strictly unprivileged on 127.0.0.1:8090; running under sudo resets PATH/HOME (hiding ~/.cargo/bin) and creates root-owned artifacts.
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    printf '[ERR_HALT] Do not run %s with sudo (AutoDorker binds unprivileged 127.0.0.1:8090 and uses user-scoped ~/.cargo + .venv).\n' "$0" >&2
    printf '[HINT] Re-run without sudo as %s: ./dev.sh %s\n' "$SUDO_USER" "${1:-build}" >&2
    exit 1
fi

prepend_path_dir() {
    [ -d "$1" ] || return 0
    case ":$PATH:" in
        *":$1:"*) ;;
        *) PATH="$1:$PATH"; export PATH ;;
    esac
}

prepend_path_dir "/usr/local/go/bin"
prepend_path_dir "${CARGO_HOME:-$HOME/.cargo}/bin"

APP_NAME="autodorker"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/${APP_NAME}"
LOG_FILE="${CACHE_DIR}/session.log"
PID_FILE="${CACHE_DIR}/gateway.pid"
BIND_ADDR="${AUTODORKER_BIND_ADDR:-127.0.0.1:8090}"
DB_PATH="${AUTODORKER_DB_PATH:-${SCRIPT_DIR}/data/autodorker_state.db}"
DORK_CSV="${AUTODORKER_DORKSET_PATH:-${SCRIPT_DIR}/../Docs/DorkSet.csv}"

check_runtime_symlinks() {
    # CWE-377 Mitigation: Refuse symlinked cache/log/pid paths before reading or writing.
    for path in "$CACHE_DIR" "$LOG_FILE" "$PID_FILE"; do
        if [ -L "$path" ]; then
            printf '[ERR_HALT] Security violation: %s is a symbolic link (CWE-377).\n' "$path" >&2
            exit 1
        fi
    done
}

init_secure_runtime_dir() {
    check_runtime_symlinks
    mkdir -p "$CACHE_DIR"
    chmod 0700 "$CACHE_DIR"
    umask 0077
}

get_live_gateway_pid() {
    [ -f "$PID_FILE" ] || return 1
    [ ! -L "$PID_FILE" ] || return 1
    CAND_PID=$(tr -d '[:space:]' < "$PID_FILE" 2>/dev/null || true)
    case "$CAND_PID" in
        ''|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$CAND_PID" 2>/dev/null || return 1
    # Verify PID belongs to gateway (avoid false lock on recycled PIDs after reboot).
    if [ -r "/proc/${CAND_PID}/comm" ]; then
        PROC_COMM=$(cat "/proc/${CAND_PID}/comm" 2>/dev/null || true)
    elif command -v ps >/dev/null 2>&1; then
        PROC_COMM=$(ps -p "$CAND_PID" -o comm= 2>/dev/null || true)
    else
        PROC_COMM="gateway"
    fi
    case "$PROC_COMM" in
        *gateway*) printf '%s\n' "$CAND_PID"; return 0 ;;
        *) return 1 ;;
    esac
}

ensure_venv() {
    if [ ! -x ".venv/bin/python" ]; then
        printf '[SETUP] Provisioning Python .venv...\n'
        python3 -m venv .venv
        .venv/bin/pip install --upgrade pip >/dev/null
        .venv/bin/pip install -r requirements.txt
    fi
}

require_tools() {
    for tool in "$@"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            printf '[ERR_HALT] Required tool missing from PATH: %s (check ~/.cargo/bin and /usr/local/go/bin)\n' "$tool" >&2
            exit 1
        fi
    done
}

cmd_setup() {
    printf '[SETUP] Checking toolchain prerequisites (go, cargo, rustc, python3)...\n'
    require_tools go cargo rustc python3
    ensure_venv
    mkdir -p bin data/backups data/Output
    printf '[OK] Toolchain and .venv verified.\n'
}

cmd_build() {
    require_tools cargo rustc go
    printf '[BUILD] Compiling Rust dork_spider engine (release)...\n'
    (cd crates/dork_spider && cargo build --release --locked)
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

cmd_status() {
    check_runtime_symlinks
    LIVE_PID=$(get_live_gateway_pid || true)
    if [ -n "$LIVE_PID" ]; then
        printf '[STATUS] AutoDorker gateway running (PID %s) -> http://%s (log: %s)\n' "$LIVE_PID" "$BIND_ADDR" "$LOG_FILE"
        return 0
    fi
    printf '[STATUS] AutoDorker gateway stopped.\n'
}

cmd_stop() {
    check_runtime_symlinks
    LIVE_PID=$(get_live_gateway_pid || true)
    if [ -z "$LIVE_PID" ]; then
        rm -f "$PID_FILE"
        printf '[STOP] No running AutoDorker gateway found.\n'
        return 0
    fi
    printf '[STOP] Stopping AutoDorker gateway PID %s...\n' "$LIVE_PID"
    kill -TERM "$LIVE_PID" 2>/dev/null || true
    WAIT_ITERS=0
    while kill -0 "$LIVE_PID" 2>/dev/null && [ "$WAIT_ITERS" -lt 10 ]; do
        sleep 1
        WAIT_ITERS=$((WAIT_ITERS + 1))
    done
    if kill -0 "$LIVE_PID" 2>/dev/null; then
        printf '[WARN] Gateway PID %s did not exit cleanly on SIGTERM; inspect process manually.\n' "$LIVE_PID" >&2
        exit 1
    fi
    rm -f "$PID_FILE"
    printf '[STOP] Gateway stopped and PID lock cleared.\n'
}

cmd_run() {
    init_secure_runtime_dir
    ensure_venv
    if [ ! -x "bin/gateway" ] || [ ! -x "bin/dork_spider" ]; then
        cmd_build
    fi

    # CWE-114 PID lock check BEFORE resetting session.log so live gateway logs remain intact.
    OLD_PID=$(get_live_gateway_pid || true)
    if [ -n "$OLD_PID" ]; then
        printf '[ERR_HALT] Gateway already running with PID %s (CWE-114).\n' "$OLD_PID" >&2
        printf '[HINT] Open http://%s // Lifecycle: ./dev.sh status | ./dev.sh stop | ./dev.sh restart\n' "$BIND_ADDR" >&2
        exit 1
    fi
    rm -f "$PID_FILE"
    : > "$LOG_FILE"

    printf '[LAUNCH] Binding %s strictly to http://%s\n' "$APP_NAME" "$BIND_ADDR"
    AUTODORKER_DB_PATH="$DB_PATH" ./bin/gateway --bind "$BIND_ADDR" >>"$LOG_FILE" 2>&1 &
    GATEWAY_PID=$!
    printf '%s\n' "$GATEWAY_PID" > "$PID_FILE"
    printf '[PID_LOCK] Process %s recorded in %s (CWE-114)\n' "$GATEWAY_PID" "$PID_FILE"
    trap 'rm -f "$PID_FILE"; kill "$GATEWAY_PID" 2>/dev/null || true' INT TERM
    wait "$GATEWAY_PID"
    rm -f "$PID_FILE"
}

cmd_restart() {
    cmd_stop
    cmd_run
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
    require_tools cargo go python3
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
    require_tools cargo gofmt go
    printf '[FMT] Formatting Rust & Go source trees...\n'
    (cd crates/dork_spider && cargo fmt)
    gofmt -w webassets.go
    (cd cmd/gateway && go fmt ./...)
    (cd tests && go fmt ./...)
    printf '[OK] Formatting complete.\n'
}

cmd_package() {
    ensure_venv
    if [ ! -x "bin/gateway" ] || [ ! -x "bin/dork_spider" ]; then
        cmd_build
    fi
    OUT_TAR="${1:-bin/autodorker-release-linux.tar.gz}"
    printf '[PKG] Packaging self-contained release archive -> %s\n' "$OUT_TAR"
    ./bin/gateway --package-release "$OUT_TAR"
}

case "${1:-help}" in
    setup) cmd_setup ;;
    build) cmd_build ;;
    run|serve) cmd_run ;;
    status) cmd_status ;;
    stop) cmd_stop ;;
    restart) cmd_restart ;;
    cli) shift; cmd_cli "${1:-}" ;;
    simulate) cmd_simulate ;;
    test) cmd_test ;;
    package) shift; cmd_package "${1:-}" ;;
    fmt) cmd_fmt ;;
    *)
        printf 'Usage: %s {setup|build|run|serve|status|stop|restart|cli [url]|simulate|test|package [out.tar.gz]|fmt}\n' "$0"
        exit 1
        ;;
esac
