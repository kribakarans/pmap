#!/usr/bin/env bash
# Quick unit tests for the memory map analyzer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

echo "=== Memory Map Analyzer - Unit Tests ==="
echo ""

ensure_analyzer
ensure_sample_dump

run_section() {
    local title="$1"
    shift
    echo "$title"
    echo "---"
    eval "$*"
    echo ""
}

run_section "Test 1: Basic analysis (all views)" \
    "run_pmap \"$SAMPLE_DUMP\" | head -50; echo '... (truncated)'"

run_section "Test 2: Segment overview only" \
    "run_pmap \"$SAMPLE_DUMP\" --grouped | head -30"

run_section "Test 3: ASCII layout only" \
    "run_pmap \"$SAMPLE_DUMP\" --ascii | head -40"

run_section "Test 4: PC analysis" \
    "run_pmap \"$SAMPLE_DUMP\" --pc 0xf79e245c 2>&1 | grep -A 10 'Program Counter'"

run_section "Test 5: LR analysis" \
    "run_pmap \"$SAMPLE_DUMP\" --lr 0xf79e7f10 2>&1 | grep -A 10 'Link Register'"

run_section "Test 6: SP analysis" \
    "run_pmap \"$SAMPLE_DUMP\" --sp 0xff8b0000 2>&1 | grep -A 10 'Stack Pointer'"

run_section "Test 7: Full crash context (all registers)" \
    "run_pmap \"$SAMPLE_DUMP\" --pc 0xf79e245c --lr 0xf79e7f10 --sp 0xff8b0000 --fp 0xff8b0010 2>&1 | head -80"

run_section "Test 8: Error handling - unknown option" \
    "run_pmap \"$SAMPLE_DUMP\" --unknown 2>&1 | head -5 || true"

run_section "Test 9: Error handling - no file" \
    "run_pmap --ascii 2>&1 | head -5 || true"

echo "=== Unit Tests Complete ==="
