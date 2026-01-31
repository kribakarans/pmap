#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=./lib/validators.sh
source "$SCRIPT_DIR/lib/validators.sh"

echo "=============================================="
echo "  COMPREHENSIVE CRASH ANALYSIS TEST SUITE"
echo "=============================================="
echo ""

ensure_analyzer
ensure_crash_demo_compiled

rm -f "$PROJECT_DIR"/crash_dump_*.{maps,regs} 2>/dev/null

run_case() {
    local label="$1"
    local mode="$2"
    local before
    local map
    local reg
    local pc
    local pid

    echo "TEST: $label"
    echo "----------------------------------------------"
    before=$(latest_dump || true)
    run_crash_demo "$mode"

    map=$(latest_dump)
    if [[ -z "$map" || "$map" == "$before" ]]; then
        echo "✗ No crash dump generated"
        echo ""
        return 1
    fi

    reg="${map%.maps}.regs"
    if [[ ! -f "$reg" ]]; then
        echo "✗ Register dump missing: $reg"
        echo ""
        return 1
    fi

    pid=$(pid_from_dump "$map")
    pc=$(reg_value "$reg" "rip")

    echo "✓ Dump: $map"
    echo "  PID: $pid"
    echo "  PC:  $pc"
    echo ""

    if [[ -n "$pc" ]]; then
        run_pmap "$map" --pc "0x$pc" | head -40
        echo ""
        run_addr2line "$map" "$pc" || true
    fi

    echo ""
    return 0
}

pass_count=0
fail_count=0

run_case "SIGSEGV (NULL pointer dereference)" "" && pass_count=$((pass_count + 1)) || fail_count=$((fail_count + 1))
run_case "SIGFPE (divide by zero)" "divzero" && pass_count=$((pass_count + 1)) || fail_count=$((fail_count + 1))
run_case "SIGABRT (abort call)" "abort" && pass_count=$((pass_count + 1)) || fail_count=$((fail_count + 1))

echo "=============================================="
echo "  TEST SUMMARY"
echo "=============================================="
echo ""
echo "Passed: $pass_count"
echo "Failed: $fail_count"
echo ""

