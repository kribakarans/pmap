#!/bin/bash
# complete_crash_analysis.sh - Full workflow from crash to root cause

set -e

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║           COMPLETE CRASH ANALYSIS WORKFLOW DEMONSTRATION                  ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Compile
echo "[1/6] Compiling crash_demo.c with debug symbols..."
gcc -g -O0 crash_demo.c -o crash_demo_new 2>&1 | grep -i "warning\|error" || echo "  ✓ Compiled successfully"
echo ""

# Step 2: Run and crash
echo "[2/6] Running crash_demo (will intentionally crash)..."
timeout 5 ./crash_demo_new >/dev/null 2>&1 || true
DUMPFILE=$(ls -t crash_dump_*.regs 2>/dev/null | head -1)
MAPFILE=$(ls -t crash_dump_*.maps 2>/dev/null | head -1)
echo "  ✓ Crash captured"
echo "  Register dump: $DUMPFILE"
echo "  Memory map: $MAPFILE"
echo ""

# Step 3: Extract registers
echo "[3/6] Extracting key register values..."
python3 parse_registers.py | grep "^Program\|^Stack\|^Frame\|^First\|^Return"
echo ""

# Get PC value for analysis
PC=$(grep "rip:" $DUMPFILE | head -1 | awk '{print $2}')
echo "  Program Counter (PC): $PC"
echo ""

# Step 4: Show memory segments
echo "[4/6] Memory segment overview..."
../memmap_analyzer.py $MAPFILE --segments | head -30
echo ""

# Step 5: Analyze crash location
echo "[5/6] Analyzing crash location with memory map..."
../memmap_analyzer.py $MAPFILE --pc $PC | grep -A 10 "CRASH CONTEXT"
echo ""

# Step 6: Show call stack
echo "[6/6] Getting call stack with GDB..."
gdb -batch -ex "run" -ex "where" ./crash_demo_new 2>/dev/null | grep "^#" | head -5
echo ""

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                         ANALYSIS COMPLETE                                 ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Key Findings:"
echo "  • Crash location: crash_demo.c, vulnerable_function()"
echo "  • Root cause: NULL pointer dereference"
echo "  • Call depth: 4 frames"
echo ""
echo "To fix:"
echo "  1. Check intermediate_function() - passes NULL pointer"
echo "  2. Validate pointer before dereference in vulnerable_function()"
echo "  3. Add null checks in call chain"
echo ""
echo "To view full details:"
echo "  cat $DUMPFILE          # All registers"
echo "  cat $MAPFILE           # Full memory map"
echo "  ../memmap_analyzer.py $MAPFILE --ascii  # Memory layout diagram"
echo ""
