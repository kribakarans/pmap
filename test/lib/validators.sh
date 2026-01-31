#!/usr/bin/env bash

if [[ "${PMAP_TEST_VALIDATORS_SH:-}" == "1" ]]; then
    return 0
fi
PMAP_TEST_VALIDATORS_SH=1

validate_html_report() {
    local htmlfile="$1"
    local mode="${2:-crash}"
    local missing=0
    local checks=()

    if [[ "$mode" == "basic" ]]; then
        checks=(
            "Process Map Analysis"
            "Memory Layout Visualization"
        )
    else
        checks=(
            "Crash Context Analysis"
            "Program Counter (PC)"
            "Stack Pointer (SP)"
            "Frame Pointer (FP)"
            "addr2line"
            "crash-marker"
        )
    fi

    for check in "${checks[@]}"; do
        if grep -q "$check" "$htmlfile"; then
            echo "✓ $check"
        else
            echo "✗ Missing: $check"
            missing=1
        fi
    done

    return $missing
}

addr2line_command() {
    local mapfile="$1"
    local pc="$2"
    run_pmap "$mapfile" --pc "0x$pc" 2>/dev/null | sed -n 's/.*Debug command: //p' | head -1
}

run_addr2line() {
    local mapfile="$1"
    local pc="$2"
    local cmd
    cmd=$(addr2line_command "$mapfile" "$pc")
    if [[ -n "$cmd" ]]; then
        echo "Running: $cmd -f -p"
        eval "$cmd -f -p"
        return 0
    fi
    return 1
}
