#!/usr/bin/env python3
"""
pmap2html - Standalone HTML report generator for process memory maps.
"""

import sys

from lib.api import (
    MemoryMap, CrashContext, MemoryMapParser, HTMLGenerator
)


def print_help(prog: str):
    """Print help information"""
    print(
        f"""Usage: {prog} <memory_dump_file> [options]
       {prog} --pid <pid> [options]

HTML report generator for Linux process memory maps.

Options:
    --html <output.html>   -- Output HTML file (default: report.html or <process>_report.html)

Crash Analysis Options:
    --pc <addr>            -- Program counter address (hex)
    --lr <addr>            -- Link register address (hex)
    --sp <addr>            -- Stack pointer address (hex)
    --fp <addr>            -- Frame pointer address (hex)

Input Options:
    --pid <pid>             -- Read /proc/<pid>/maps from a running process

Help:
    -h, --help             -- Show this help menu

Examples:
    {prog} test/pmap-sample.txt                                           # Default: report.html
    {prog} test/pmap-sample.txt --html crash_report.html                 # Custom filename
    {prog} --pid 1                                                         # PID 1 (systemd) → systemd_report.html
    {prog} --pid 1 --html systemd_map.html                               # PID with custom filename
    {prog} test/pmap-sample.txt --pc 0xf79e245c --sp 0xff8c1000 --html crash.html

For CLI text analysis:
    pmap.py test/pmap-sample.txt --table
    pmap.py test/pmap-sample.txt --pc 0xaddr
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
        '--html', '--pc', '--lr', '--sp', '--fp'
    }

    html_output = None
    crash_ctx = CrashContext()

    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith('--'):
            if arg not in valid_flags:
                print(f"Error: Unknown option '{arg}'", file=sys.stderr)
                print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
                sys.exit(1)

            if i + 1 >= len(args):
                print(f"Error: {arg} requires a value", file=sys.stderr)
                print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
                sys.exit(1)

            value = args[i + 1]
            if arg == '--html':
                html_output = value
            elif arg == '--pc':
                crash_ctx.pc = int(value, 16)
            elif arg == '--lr':
                crash_ctx.lr = int(value, 16)
            elif arg == '--sp':
                crash_ctx.sp = int(value, 16)
            elif arg == '--fp':
                crash_ctx.fp = int(value, 16)
            i += 2
            continue
        i += 1

    # Parse memory map
    if pid is not None:
        memmap = MemoryMapParser.parse_pid(pid)
    else:
        memmap = MemoryMapParser.parse_file(filename)
    
    # Generate default filename if not specified
    if not html_output:
        if memmap.process_name:
            html_output = f"{memmap.process_name}_report.html"
        else:
            html_output = "report.html"
    
    # Generate HTML
    HTMLGenerator.generate_html(memmap, crash_ctx, html_output)


if __name__ == '__main__':
    main()
