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

HTML report generator for Linux process memory maps.

Required Options:
    --html <output.html>   -- Generate HTML visualization file

Crash Analysis Options:
    --pc <addr>            -- Program counter address (hex)
    --lr <addr>            -- Link register address (hex)
    --sp <addr>            -- Stack pointer address (hex)
    --fp <addr>            -- Frame pointer address (hex)

Help:
    -h, --help             -- Show this help menu

Examples:
    {prog} test/pmap-sample.txt --html report.html
    {prog} test/pmap-sample.txt --pc 0xf79e245c --sp 0xff8c1000 --html crash_report.html

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
    
    # Check that first argument is a filename, not a flag
    if sys.argv[1].startswith('-'):
        print(f"Error: No memory dump file specified", file=sys.stderr)
        print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
        sys.exit(1)
    
    filename = sys.argv[1]
    
    # Validate command line options
    valid_flags = {
        '--html', '--pc', '--lr', '--sp', '--fp'
    }
    
    # Check for invalid options and validate
    skip_next = False
    has_html = '--html' in sys.argv
    
    for i, arg in enumerate(sys.argv[2:], 2):
        if skip_next:
            skip_next = False
            continue
        
        if arg.startswith('--'):
            if arg not in valid_flags:
                print(f"Error: Unknown option '{arg}'", file=sys.stderr)
                print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
                sys.exit(1)
            
            # Skip next arg if it's a value
            if i + 1 < len(sys.argv):
                skip_next = True
    
    # Check for required --html option
    if not has_html:
        print(f"Error: --html option is required", file=sys.stderr)
        print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
        sys.exit(1)
    
    # Parse options
    html_output = None
    crash_ctx = CrashContext()
    
    for i, arg in enumerate(sys.argv):
        if arg == '--html' and i + 1 < len(sys.argv):
            html_output = sys.argv[i + 1]
        elif arg == '--pc' and i + 1 < len(sys.argv):
            crash_ctx.pc = int(sys.argv[i + 1], 16)
        elif arg == '--lr' and i + 1 < len(sys.argv):
            crash_ctx.lr = int(sys.argv[i + 1], 16)
        elif arg == '--sp' and i + 1 < len(sys.argv):
            crash_ctx.sp = int(sys.argv[i + 1], 16)
        elif arg == '--fp' and i + 1 < len(sys.argv):
            crash_ctx.fp = int(sys.argv[i + 1], 16)
    
    # Parse memory map
    memmap = MemoryMapParser.parse_file(filename)
    
    # Generate HTML
    HTMLGenerator.generate_html(memmap, crash_ctx, html_output)


if __name__ == '__main__':
    main()
