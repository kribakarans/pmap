#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=./lib/validators.sh
source "$SCRIPT_DIR/lib/validators.sh"

REPORT_NAME="crash_verify.html"

echo "=== HTML Crash Report Test ==="

ensure_analyzer
ensure_crash_demo_compiled

echo "[1/2] Run crash demo (generates crash_dump_*.maps/.regs)"
run_crash_demo

echo "[2/2] Generate HTML report with crash context"
MAP=$(latest_dump)
if [[ -z "$MAP" ]]; then
	fail "No crash dumps found"
fi

REG="${MAP%.maps}.regs"
ensure_file "$REG" "Register dump"

PC=$(reg_value "$REG" "rip")
SP=$(reg_value "$REG" "rsp")
FP=$(reg_value "$REG" "rbp")

generate_html_report "$MAP" "$PC" "$SP" "$FP" "$REPORT_NAME"

echo "--- HTML checks ---"
validate_html_report "$REPORT_NAME"

echo ""
echo "✓ HTML report saved to: $REPORT_NAME"
