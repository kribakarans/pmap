#!/usr/bin/env python3
"""
pmap - Process Memory Map Analysis Tool:
Enhanced visualization and crash context analysis
"""

import sys
import os
import signal

# Handle broken pipe gracefully (when output is piped to head/tail)
signal.signal(signal.SIGPIPE, signal.SIG_IGN)

from lib.api import (
    SegmentType, MemorySegment, MemoryMap, CrashContext,
    MemoryMapParser, CrashAnalyzer, MemoryMapVisualizer
)


def print_help(prog: str):
    """Print detailed helper prompt"""
    print(
        f"""Usage: {prog} <memory_dump_file> [options]
       {prog} --pid <pid> [options]

Visualize /proc/<pid>/maps dumps.

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

Input Options:
    --pid <pid>          -- Read /proc/<pid>/maps from a running process

Help:
    -h, --help           -- Show this help menu

Examples:
    {prog} test/pmap-sample.txt                         # Show all reports
    {prog} --pid 1                                       # Analyze PID 1 (systemd)
    {prog} test/pmap-sample.txt --report                # Show all reports (explicit)
    {prog} test/pmap-sample.txt --table                 # Show only table view
    {prog} test/pmap-sample.txt --ascii                 # Show only ASCII map
    {prog} test/pmap-sample.txt --pc 0xf79e245c         # Show only crash analysis for PC
    {prog} test/pmap-sample.txt --stats --security      # Show stats and security reports

For HTML visualization:
    pmap2html.py test/pmap-sample.txt --pc 0xaddr --html report.html
    pmap2html.py --pid 1 --html report.html
"""
    )


def main():
    """Main entry point"""
    # Check for help flag
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        print_help(sys.argv[0])
        sys.exit(0 if len(sys.argv) >= 2 else 1)
    args = sys.argv[1:]

    # Parse --pid if provided
    pid = None
    if '--pid' in args:
        pid_index = args.index('--pid')
        if pid_index + 1 >= len(args):
            print(f"Error: --pid requires a value", file=sys.stderr)
            print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
            sys.exit(1)
        pid = int(args[pid_index + 1])
        args = args[:pid_index] + args[pid_index + 2:]

    # Determine input source
    filename = None
    if pid is None:
        if not args or args[0].startswith('-'):
            print(f"Error: No memory dump file specified", file=sys.stderr)
            print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
            sys.exit(1)
        filename = args[0]
        args = args[1:]
    else:
        if args and not args[0].startswith('-'):
            print(f"Error: Provide either a file or --pid, not both", file=sys.stderr)
            print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
            sys.exit(1)

    # Validate command line options
    valid_flags = {
        '--report', '--table', '--stats', '--grouped', '--ascii', '--security',
        '--pc', '--lr', '--sp', '--fp'
    }

    crash_ctx = CrashContext()
    has_crash_opts = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith('--'):
            if arg not in valid_flags:
                print(f"Error: Unknown option '{arg}'", file=sys.stderr)
                print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
                sys.exit(1)

            if arg in {'--pc', '--lr', '--sp', '--fp'}:
                if i + 1 >= len(args):
                    print(f"Error: {arg} requires a value", file=sys.stderr)
                    print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
                    sys.exit(1)
                value = args[i + 1]
                if arg == '--pc':
                    crash_ctx.pc = int(value, 16)
                elif arg == '--lr':
                    crash_ctx.lr = int(value, 16)
                elif arg == '--sp':
                    crash_ctx.sp = int(value, 16)
                elif arg == '--fp':
                    crash_ctx.fp = int(value, 16)
                has_crash_opts = True
                i += 2
                continue
        i += 1

    # Parse command line options
    show_report = '--report' in args
    show_table = '--table' in args
    show_stats = '--stats' in args
    show_grouped = '--grouped' in args
    show_ascii = '--ascii' in args
    show_security = '--security' in args

    # Parse memory map
    if pid is not None:
        memmap = MemoryMapParser.parse_pid(pid)
    else:
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
    try:
        main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        finally:
            os._exit(0)
