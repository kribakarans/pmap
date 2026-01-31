#!/usr/bin/env bash

if [[ "${PMAP_TEST_COMMON_SH:-}" == "1" ]]; then
    return 0
fi
PMAP_TEST_COMMON_SH=1

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="$(cd "$TEST_DIR/.." && pwd)"
ANALYZER="$PROJECT_DIR/pmap.py"
HTML_TOOL="$PROJECT_DIR/pmap2html.py"
SAMPLE_DUMP="$PROJECT_DIR/memmap.txt"
CRASH_DEMO="$TEST_DIR/crash_demo.out"
CRASH_SRC="$TEST_DIR/crash_demo.c"

fail() {
    echo "Error: $*" >&2
    exit 1
}

ensure_file() {
    local path="$1"
    local label="$2"
    if [[ ! -f "$path" ]]; then
        fail "$label not found at $path"
    fi
}

ensure_analyzer() {
    ensure_file "$ANALYZER" "pmap.py"
}

ensure_html_tool() {
    ensure_file "$HTML_TOOL" "pmap2html.py"
}

ensure_sample_dump() {
    ensure_file "$SAMPLE_DUMP" "memmap.txt"
}

ensure_crash_demo_compiled() {
    if [[ ! -f "$CRASH_DEMO" ]] || [[ "$CRASH_SRC" -nt "$CRASH_DEMO" ]]; then
        echo "Compiling crash_demo.c..."
        gcc -g -O0 -Wall "$CRASH_SRC" -o "$CRASH_DEMO"
    fi
}

run_crash_demo() {
    local mode="${1:-}"
    if [[ -n "$mode" ]]; then
        timeout 10 "$CRASH_DEMO" "$mode" 2>&1 || true
    else
        timeout 10 "$CRASH_DEMO" 2>&1 || true
    fi
}

latest_dump() {
    local pattern="$PROJECT_DIR/crash_dump_*.maps"
    ls -1t $pattern 2>/dev/null | head -1
}

reg_value() {
    local regfile="$1"
    local regname="$2"
    grep "^${regname}:" "$regfile" | awk '{print $2}' | head -1
}

signal_value() {
    local regfile="$1"
    grep "^Signal:" "$regfile" | awk '{print $2}' | head -1
}

pid_from_dump() {
    local dumpfile="$1"
    basename "$dumpfile" | sed 's/crash_dump_\([0-9]*\)\..*/\1/'
}

run_pmap() {
    "$ANALYZER" "$@"
}

generate_html_report() {
    local mapfile="$1"
    local pc="$2"
    local sp="$3"
    local fp="$4"
    local output="$5"
    python3 "$HTML_TOOL" "$mapfile" --pc "0x$pc" --sp "0x$sp" --fp "0x$fp" --html "$output"
}
