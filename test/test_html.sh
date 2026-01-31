#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=./lib/validators.sh
source "$SCRIPT_DIR/lib/validators.sh"

REPORT_NAME="crash_verify.html"
SYSTEMD_REPORT="systemd_verify.html"

echo "=== HTML Crash Report Test ==="

ensure_analyzer
ensure_html_tool
ensure_crash_demo_compiled

echo "[1/3] Run crash demo (generates crash_dump_*.maps/.regs)"
run_crash_demo

echo "[2/3] Generate HTML report with crash context"
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

echo "[3/3] Generate HTML report from PID (systemd)"
SYSTEMD_PID=$(pidof systemd | awk '{print $1}')
if [[ -z "$SYSTEMD_PID" ]]; then
	fail "systemd process not found"
fi

python3 "$HTML_TOOL" --pid "$SYSTEMD_PID" --html "$SYSTEMD_REPORT"
validate_html_report "$SYSTEMD_REPORT" basic

echo ""
echo "✓ HTML report saved to: $REPORT_NAME"
echo "✓ HTML report saved to: $SYSTEMD_REPORT"
