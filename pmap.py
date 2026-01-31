#!/usr/bin/env python3
"""
pmap - Process Memory Map Analysis Tool:
Enhanced visualization and crash context analysis
"""

import sys

from lib.api import (
    SegmentType, MemorySegment, MemoryMap, CrashContext,
    MemoryMapParser, CrashAnalyzer, MemoryMapVisualizer
)


def print_help(prog: str):
    """Print detailed helper prompt"""
    print(
        f"""Usage: {prog} <memory_dump_file> [options]

Linux crash analysis tool for /proc/<pid>/maps dumps.

Output Options (each shows only its specific report):
    --report             -- Show all reports (default if no options given)
    --table              -- Show memory map table view only
    --stats              -- Show memory statistics only
    --grouped            -- Show memory map grouped by binary only
    --ascii              -- Show ASCII memory layout only
    --security           -- Show security analysis only

Crash Analysis Options (shows crash context analysis only):
    --pc <addr>          -- Program counter address (hex)
    --lr <addr>          -- Link register address (hex)
    --sp <addr>          -- Stack pointer address (hex)
    --fp <addr>          -- Frame pointer address (hex)

Help:
    -h, --help           -- Show this help menu

Examples:
    {prog} memmap.txt                         # Show all reports
    {prog} memmap.txt --report                # Show all reports (explicit)
    {prog} memmap.txt --table                 # Show only table view
    {prog} memmap.txt --ascii                 # Show only ASCII map
    {prog} memmap.txt --pc 0xf79e245c         # Show only crash analysis for PC
    {prog} memmap.txt --stats --security      # Show stats and security reports

For HTML visualization:
    pmap2html.py memmap.txt --pc 0xaddr --html report.html
"""
    )


def main():
    """Main entry point"""
    # Check for help flag
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        print_help(sys.argv[0])
        sys.exit(0 if len(sys.argv) >= 2 else 1)
    
    # Check that first argument is a filename, not a flag
    if sys.argv[1].startswith('-'):
        print(f"Error: No memory dump file specified", file=sys.stderr)
        print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
        sys.exit(1)
    
    filename = sys.argv[1]
    
    # Validate command line options
    valid_flags = {
        '--report', '--table', '--stats', '--grouped', '--ascii', '--security',
        '--pc', '--lr', '--sp', '--fp'
    }
    
    # Check for invalid options
    skip_next = False
    for i, arg in enumerate(sys.argv[2:], 2):  # Start from index 2 (skip filename)
        if skip_next:
            skip_next = False
            continue
        
        if arg.startswith('--'):
            if arg not in valid_flags:
                print(f"Error: Unknown option '{arg}'", file=sys.stderr)
                print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
                sys.exit(1)
            
            # Skip next arg if it's an address value for crash options
            if arg in {'--pc', '--lr', '--sp', '--fp'} and i + 1 < len(sys.argv):
                skip_next = True
    
    # Parse command line options
    show_report = '--report' in sys.argv
    show_table = '--table' in sys.argv
    show_stats = '--stats' in sys.argv
    show_grouped = '--grouped' in sys.argv
    show_ascii = '--ascii' in sys.argv
    show_security = '--security' in sys.argv
    
    crash_ctx = CrashContext()
    has_crash_opts = False
    
    for i, arg in enumerate(sys.argv):
        if arg == '--pc' and i + 1 < len(sys.argv):
            crash_ctx.pc = int(sys.argv[i + 1], 16)
            has_crash_opts = True
        elif arg == '--lr' and i + 1 < len(sys.argv):
            crash_ctx.lr = int(sys.argv[i + 1], 16)
            has_crash_opts = True
        elif arg == '--sp' and i + 1 < len(sys.argv):
            crash_ctx.sp = int(sys.argv[i + 1], 16)
            has_crash_opts = True
        elif arg == '--fp' and i + 1 < len(sys.argv):
            crash_ctx.fp = int(sys.argv[i + 1], 16)
            has_crash_opts = True
    
    # Parse memory map
    memmap = MemoryMapParser.parse_file(filename)
    
    # Determine what to display
    # If no options given, default to --report
    any_option = (show_report or show_table or show_stats or show_grouped or 
                  show_ascii or show_security or has_crash_opts)
    
    if not any_option:
        show_report = True
    
    # Show requested reports
    if show_report:
        # Show all reports
        MemoryMapVisualizer.print_table(memmap)
        MemoryMapVisualizer.print_statistics(memmap)
        MemoryMapVisualizer.print_grouped_by_binary(memmap)
        MemoryMapVisualizer.print_ascii_layout(memmap, crash_ctx)
        if has_crash_opts:
            CrashAnalyzer.analyze_crash(memmap, crash_ctx)
        CrashAnalyzer.check_security(memmap)
    else:
        # Show only requested reports
        if show_table:
            MemoryMapVisualizer.print_table(memmap)
        
        if show_stats:
            MemoryMapVisualizer.print_statistics(memmap)
        
        if show_grouped:
            MemoryMapVisualizer.print_grouped_by_binary(memmap)
        
        if show_ascii:
            MemoryMapVisualizer.print_ascii_layout(memmap, crash_ctx)
        
        if has_crash_opts:
            CrashAnalyzer.analyze_crash(memmap, crash_ctx)
        
        if show_security:
            CrashAnalyzer.check_security(memmap)


if __name__ == '__main__':
    main()
