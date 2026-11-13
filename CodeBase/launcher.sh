#!/bin/sh
# launcher.sh — Unified Linux CLI entrypoint delegating to dev.sh (CN-DIR-2026-004)
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

if [ $# -ge 1 ]; then
    exec ./dev.sh "$@"
fi

printf '==================================================\n'
printf ' CyberNest Labs // AutoDorker Launcher (POSIX)\n'
printf '==================================================\n'
printf ' 1) setup    - Provision .venv & verify tools\n'
printf ' 2) build    - Compile Rust/Go binaries & seed DB\n'
printf ' 3) run      - Launch 127.0.0.1:8090 Gateway\n'
printf ' 4) status   - Show Gateway PID & URL status\n'
printf ' 5) stop     - Stop running Gateway cleanly\n'
printf ' 6) restart  - Restart Gateway with fresh binaries\n'
printf ' 7) cli      - Diagnostic & WAL backup check\n'
printf ' 8) simulate - Ephemeral mock HTTP E2E audit\n'
printf ' 9) test     - Run Rust + Go + Python test suites\n'
printf '10) package  - Build standalone release tarball\n'
printf '11) fmt      - Format Rust & Go sources\n'
printf 'Select [1-11]: '
read -r CHOICE

case "$CHOICE" in
    1) exec ./dev.sh setup ;;
    2) exec ./dev.sh build ;;
    3) exec ./dev.sh run ;;
    4) exec ./dev.sh status ;;
    5) exec ./dev.sh stop ;;
    6) exec ./dev.sh restart ;;
    7) exec ./dev.sh cli ;;
    8) exec ./dev.sh simulate ;;
    9) exec ./dev.sh test ;;
    10) exec ./dev.sh package ;;
    11) exec ./dev.sh fmt ;;
    *) printf 'Invalid selection.\n'; exit 1 ;;
esac
