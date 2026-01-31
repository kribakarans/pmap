#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPORT_NAME="crash_verify.html"

echo "=== HTML Crash Report Test ==="
echo "Workspace: $ROOT_DIR"

echo "[1/3] Build crash demo"
(cd "$ROOT_DIR" && make)

echo "[2/3] Run crash demo (generates crash_dump_*.maps/.regs)"
(cd "$ROOT_DIR" && timeout 5 ./test/crash_demo.out 2>&1 | tail -3) || true

echo "[3/3] Generate HTML report with crash context"
MAP=$(command ls -1t "$ROOT_DIR"/crash_dump_*.maps | head -1)
PID=${MAP##*/}
PID=${PID#crash_dump_}
PID=${PID%.maps}
REG="$ROOT_DIR/crash_dump_${PID}.regs"

PC=$(grep '^rip:' "$REG" | awk '{print $2}')
SP=$(grep '^rsp:' "$REG" | awk '{print $2}')
FP=$(grep '^rbp:' "$REG" | awk '{print $2}')

(cd "$ROOT_DIR" && ./memmap_analyzer.py "$MAP" --pc 0x$PC --sp 0x$SP --fp 0x$FP --html "$REPORT_NAME")

echo "--- HTML checks ---"
grep -q "Crash Context Analysis" "$ROOT_DIR/$REPORT_NAME" && echo "✓ Crash section present"
grep -q "Program Counter (PC)" "$ROOT_DIR/$REPORT_NAME" && echo "✓ PC details present"
grep -q "Stack Pointer (SP)" "$ROOT_DIR/$REPORT_NAME" && echo "✓ SP details present"
grep -q "Frame Pointer (FP)" "$ROOT_DIR/$REPORT_NAME" && echo "✓ FP details present"
grep -q "addr2line" "$ROOT_DIR/$REPORT_NAME" && echo "✓ addr2line present"
grep -q "crash-marker" "$ROOT_DIR/$REPORT_NAME" && echo "✓ crash markers present"

echo "\n✓ HTML report saved to: $ROOT_DIR/$REPORT_NAME"
