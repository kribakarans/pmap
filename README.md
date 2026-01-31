# Linux Crash Analysis Tool

A comprehensive Python tool for parsing and visualizing Linux process memory dumps (`/proc/<pid>/maps` format) with crash context analysis capabilities.

## Features

- **Memory Map Parsing**: Parse `/proc/<pid>/maps` format dumps
- **Segment Classification**: Automatically classify segments (CODE, DATA, HEAP, STACK, etc.)
- **Visual Representation**:
  - Tabular view with full pathnames (no truncation)
  - ASCII memory layout diagram
  - Grouped by binary view
  - Statistics and distribution
  - Segment overview box layout
- **Crash Context Analysis**:
  - Resolve PC (Program Counter), LR (Link Register), SP, FP to binaries
  - Generate `addr2line` commands for debugging
  - Identify suspicious memory regions
  - Stack pointer validation
- **Security Analysis**: Detect writable+executable regions
- **HTML Report**: Compact, color-coded, crash markers, grouped view
- **Pure Python**: No compilation needed, works on any system with Python 3.7+

## Installation

No installation required! Just ensure Python 3.7+ is available:

```bash
chmod +x memmap_analyzer.py
```

## Usage

```bash
# Basic analysis (includes all reports)
python3 memmap_analyzer.py memmap.txt

# Crash context analysis
python3 memmap_analyzer.py memmap.txt --pc 0xf79e245c --lr 0xf79e7f10

# With all registers
python3 memmap_analyzer.py memmap.txt --pc 0xf79e245c --lr 0xf79e7f10 --sp 0xff8c0000 --fp 0xff8c0010

# HTML report (default filename: <mapfile>.html)
python3 memmap_analyzer.py memmap.txt --html

# HTML report with custom filename
python3 memmap_analyzer.py memmap.txt --pc 0xf79e245c --html crash_report.html
```

### Command-Line Options

```
python3 memmap_analyzer.py <memory_dump_file> [OPTIONS]

Output Options (each shows only its specific report):
  --report             Show all reports (default if no options given)
  --table              Show memory map table view only
  --stats              Show memory statistics only
  --grouped            Show memory map grouped by binary only
  --segments           Show segment overview visualization only
  --ascii              Show ASCII memory layout only
  --security           Show security analysis only
  --html [file]        Generate HTML visualization (defaults to <mapfile>.html)

Crash Analysis Options (shows crash context analysis only):
  --pc <addr>          Program counter address (hex)
  --lr <addr>          Link register address (hex)
  --sp <addr>          Stack pointer address (hex)
  --fp <addr>          Frame pointer address (hex)
```

## Output Examples

### Memory Map Table (Full Pathnames - No Truncation)

```
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                                                         MEMORY MAP - TABULAR VIEW                                           
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Process: amxrt               PID: 12044      Segments: 105   Total Size: 3,932,160 bytes
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Start Addr     End Addr       Size         Perms  Type       Binary/Mapping
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0098b000     0x0098c000           4096  r-xp   CODE       /usr/bin/amxrt
0x0098c000     0x0098d000           4096  r--p   RODATA     /usr/bin/amxrt
0x0098d000     0x0098e000           4096  rw-p   DATA       /usr/bin/amxrt
0xf797f000     0xf7982000          12288  r-xp   CODE       /usr/lib/amx/tr181-device/modules/mod-device-mgmnt.so
0xf7982000     0xf7983000           4096  r--p   RODATA     /usr/lib/amx/tr181-device/modules/mod-device-mgmnt.so
0xf7983000     0xf7984000           4096  rw-p   DATA       /usr/lib/amx/tr181-device/modules/mod-device-mgmnt.so
...
```

### ASCII Memory Layout

```
══════════════════════════════════════════════════════════════════════════════════════
                        MEMORY LAYOUT - ASCII VISUALIZATION                          
══════════════════════════════════════════════════════════════════════════════════════

High Memory
     ↑
     │
0xffff1000 ──┬─ r-xp  VDSO     [vectors]                        
             │
0xffff0000 ──┴─ (size: 4096 bytes)
     │
0xff8c1000 ──┬─ rw-p  STACK    [stack]                          ← SP
             │
0xff8a0000 ──┴─ (size: 135168 bytes)
...
```

### Crash Analysis

```
══════════════════════════════════════════════════════════════════════════════════════
                             CRASH CONTEXT ANALYSIS                                   
══════════════════════════════════════════════════════════════════════════════════════

Program Counter (PC):
  Address: 0x00000000f79e245c
  Segment: /lib/libubus.so.20230605 [CODE]
  Permissions: r-xp
  Offset in segment: 0x245c
  Debug command: addr2line -e /lib/libubus.so.20230605 0x245c

Link Register (LR):
  Address: 0x00000000f79e7f10
  Segment: /lib/libubox.so.20230523 [CODE]
  Permissions: r-xp
  Offset in segment: 0xf10
  Debug command: addr2line -e /lib/libubox.so.20230523 0xf10
```

### Memory Statistics

```
══════════════════════════════════════════════════════════════════════════════════════
                          MEMORY STATISTICS                                   
══════════════════════════════════════════════════════════════════════════════════════
Segment Type    Count    Total Size           Percentage
──────────────────────────────────────────────────────────────────────────────────────
ANON            5               81920 bytes    2.08%
CODE            32          2,801,664 bytes   71.25%
DATA            32            389,120 bytes    9.89%
HEAP            2             741,376 bytes   18.85%
RODATA          33            204,800 bytes    5.21%
STACK           1             135,168 bytes    3.44%
VDSO            2               8,192 bytes    0.21%
──────────────────────────────────────────────────────────────────────────────────────
TOTAL           105         3,932,160 bytes  100.00%
```

### Grouped by Binary

```
══════════════════════════════════════════════════════════════════════════════════════
                       MEMORY MAP - GROUPED BY BINARY                          
══════════════════════════════════════════════════════════════════════════════════════

📦 /usr/bin/amxrt
   Total size: 12,288 bytes (3 segments)
   0x0098b000-0x0098c000  r-xp   CODE        4096 bytes
   0x0098c000-0x0098d000  r--p   RODATA      4096 bytes
   0x0098d000-0x0098e000  rw-p   DATA        4096 bytes

📦 [heap]
   Total size: 741,376 bytes (2 segments)
   0x0214f000-0x0218a000  rw-p   HEAP      241664 bytes
   0x0218a000-0x02204000  rw-p   HEAP      499712 bytes
...
```

## Input Format

The tool accepts memory dumps in `/proc/<pid>/maps` format:

```
0098b000-0098c000 r-xp 00000000 b3:04 6081                               /usr/bin/amxrt
0098c000-0098d000 r--p 00000000 b3:04 6081                               /usr/bin/amxrt
0098d000-0098e000 rw-p 00001000 b3:04 6081                               /usr/bin/amxrt
0214f000-0218a000 rw-p 00000000 00:00 0                                  [heap]
ff8a0000-ff8c1000 rw-p 00000000 00:00 0                                  [stack]
```

To capture a memory dump from a running process:

```bash
cat /proc/<pid>/maps > memdump.txt
```

## Segment Classification

The tool automatically classifies memory segments:

- **CODE**: Executable segments (r-xp)
- **DATA**: File-backed writable segments (rw-p)
- **RODATA**: Read-only data (r--p)
- **HEAP**: Marked as [heap]
- **STACK**: Marked as [stack]
- **ANON**: Anonymous writable mappings
- **VDSO**: Virtual dynamic shared objects ([vdso], [sigpage], [vectors])

## Use Cases

1. **Crash Analysis**: Determine which library/binary caused a crash
2. **Debug Symbol Resolution**: Generate correct addr2line commands
3. **Memory Layout Visualization**: Understand process memory organization
4. **Security Auditing**: Detect writable+executable regions
5. **ASLR Analysis**: View actual runtime memory addresses
6. **Forensics**: Analyze memory dumps from core files or system snapshots

## Requirements

- Python 3.7+
- Standard library only (no external dependencies)

## Sample Output

See [memmap.txt](memmap.txt) for example input data from an ARM-based Linux system running the `amxrt` process.

## Examples

### Analyze a crash from GDB

```bash
# In GDB
(gdb) info registers
# Note the PC, LR, SP values
(gdb) info proc mappings > /tmp/crash_maps.txt

# Analyze
python3 memmap_analyzer.py /tmp/crash_maps.txt --pc 0xXXXXXXXX --lr 0xXXXXXXXX
```

### Generate HTML report

```bash
python3 memmap_analyzer.py memmap.txt --html
python3 memmap_analyzer.py memmap.txt --pc 0x1234 --sp 0x5678 --html crash_report.html
```

### Security audit

The tool automatically checks for security issues like writable+executable regions:

```
══════════════════════════════════════════════════════════════════════════════════════
                          SECURITY ANALYSIS                                   
══════════════════════════════════════════════════════════════════════════════════════

✓ No suspicious writable+executable regions found.
```

## Quick Reference

### Common Commands

```bash
# Basic analysis
python3 memmap_analyzer.py memmap.txt

# Crash analysis with registers
python3 memmap_analyzer.py memmap.txt --pc 0xf79e245c --lr 0xf79e7f10 --sp 0xff8b0000 --fp 0xff8b0010

# HTML report (default filename: memmap.txt.html)
python3 memmap_analyzer.py memmap.txt --html
```

## Helper Scripts

- **Build + crash + HTML verification**: [test/test_html.sh](test/test_html.sh)
  - Compiles crash demo, runs it, generates HTML with crash context, and validates output.
- **Full test suite**: [run_all_tests.sh](run_all_tests.sh)
  - Runs SIGSEGV/SIGFPE/SIGABRT tests and validates analysis output.
- **Batch HTML generation**: [generate_html_reports.sh](generate_html_reports.sh)
  - Generates HTML reports from available crash dumps.

## Demo Crash Program

- **Source**: [test/crash_demo.c](test/crash_demo.c)
- **Binary**: test/crash_demo.out (built via Makefile)
- **Build**:
  ```bash
  make
  ```

### Understanding addr2line Output

When the tool shows:
```
Debug command: addr2line -e /lib/libubus.so.20230605 0x245c
```

Run this command to get the source file and line number where the crash occurred.

## License

This tool is provided as-is for educational and debugging purposes.
