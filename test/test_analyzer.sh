#!/bin/bash
# Quick testing script for the memory map analyzer

set -e

echo "=== Memory Map Analyzer - Testing Suite ==="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="$SCRIPT_DIR/../memmap_analyzer.py"
SAMPLE_DUMP="$SCRIPT_DIR/memmap.txt"

if [ ! -f "$ANALYZER" ]; then
    echo "Error: memmap_analyzer.py not found at $ANALYZER"
    exit 1
fi

if [ ! -f "$SAMPLE_DUMP" ]; then
    echo "Error: memmap.txt not found at $SAMPLE_DUMP"
    exit 1
fi

# Test 1: Basic analysis (all views)
echo "Test 1: Basic analysis (all views)"
echo "Command: ./memmap_analyzer.py memmap.txt"
echo "---"
python3 "$ANALYZER" "$SAMPLE_DUMP" | head -50
echo "... (truncated)"
echo ""

# Test 2: Segment overview only
echo "Test 2: Segment overview only"
echo "Command: ./memmap_analyzer.py memmap.txt --segments"
echo "---"
python3 "$ANALYZER" "$SAMPLE_DUMP" --segments | head -30
echo ""

# Test 3: ASCII layout only
echo "Test 3: ASCII layout only"
echo "Command: ./memmap_analyzer.py memmap.txt --ascii"
echo "---"
python3 "$ANALYZER" "$SAMPLE_DUMP" --ascii | head -40
echo ""

# Test 4: PC (Program Counter) analysis
echo "Test 4: PC analysis"
echo "Command: ./memmap_analyzer.py memmap.txt --pc 0xf79e245c"
echo "---"
python3 "$ANALYZER" "$SAMPLE_DUMP" --pc 0xf79e245c 2>&1 | grep -A 10 "Program Counter"
echo ""

# Test 5: LR (Link Register) analysis
echo "Test 5: LR analysis"
echo "Command: ./memmap_analyzer.py memmap.txt --lr 0xf79e7f10"
echo "---"
python3 "$ANALYZER" "$SAMPLE_DUMP" --lr 0xf79e7f10 2>&1 | grep -A 10 "Link Register"
echo ""

# Test 6: SP (Stack Pointer) analysis
echo "Test 6: SP analysis"
echo "Command: ./memmap_analyzer.py memmap.txt --sp 0xff8b0000"
echo "---"
python3 "$ANALYZER" "$SAMPLE_DUMP" --sp 0xff8b0000 2>&1 | grep -A 10 "Stack Pointer"
echo ""

# Test 7: Full crash context
echo "Test 7: Full crash context (all registers)"
echo "Command: ./memmap_analyzer.py memmap.txt --pc 0xf79e245c --lr 0xf79e7f10 --sp 0xff8b0000 --fp 0xff8b0010"
echo "---"
python3 "$ANALYZER" "$SAMPLE_DUMP" --pc 0xf79e245c --lr 0xf79e7f10 --sp 0xff8b0000 --fp 0xff8b0010 2>&1 | head -80
echo ""

# Test 8: Error handling - unknown option
echo "Test 8: Error handling - unknown option"
echo "Command: ./memmap_analyzer.py memmap.txt --unknown"
echo "---"
python3 "$ANALYZER" "$SAMPLE_DUMP" --unknown 2>&1 | head -5
echo ""

# Test 9: Error handling - no file
echo "Test 9: Error handling - no file"
echo "Command: ./memmap_analyzer.py --ascii"
echo "---"
python3 "$ANALYZER" --ascii 2>&1 | head -5
echo ""

echo "=== Testing Complete ==="
echo ""
echo "Usage Examples:"
echo "  ./memmap_analyzer.py memmap.txt"
echo "  ./memmap_analyzer.py memmap.txt --segments"
echo "  ./memmap_analyzer.py memmap.txt --ascii"
echo "  ./memmap_analyzer.py memmap.txt --pc 0xf79e245c"
echo "  ./memmap_analyzer.py memmap.txt --pc 0xf79e245c --lr 0xf79e7f10 --sp 0xff8b0000"
