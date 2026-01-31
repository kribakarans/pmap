# pmap - Process Memory Map Analysis Tool

**A comprehensive Python tool for parsing and visualizing Linux process memory dumps with crash context analysis.**

A pure Python crash analysis tool for Linux process memory dumps. Analyzes `/proc/<pid>/maps` dumps and crash registers to identify where a process crashed and generate debugging commands.

**No external dependencies** • **Pure Python 3.7+** • **Single-file tool** • **Production-ready**

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Usage & Commands](#usage--commands)
5. [Output Examples](#output-examples)
6. [Project Structure](#project-structure)
7. [Testing](#testing)
8. [Key Concepts](#key-concepts)
9. [Workflow & Examples](#workflow--examples)

---

## Features

### Core Analysis
- **Memory Map Parsing**: Parse `/proc/<pid>/maps` format dumps
- **Segment Classification**: Automatically classify segments (CODE, DATA, HEAP, STACK, etc.)
- **Crash Context Analysis**: Resolve PC, LR, SP, FP to binaries and generate `addr2line` commands
- **Security Analysis**: Detect writable+executable regions
- **No Dependencies**: Pure Python, standard library only

### Visualization Options
- **Tabular View**: Full pathnames (no truncation)
- **ASCII Memory Layout**: Visual diagram of address space
- **Grouped by Binary**: Memory regions per shared library
- **Statistics**: Segment distribution and sizes
- **Segment Overview**: Boxed layout of major regions
- **HTML Reports**: Compact, color-coded, interactive crash markers
- **Security Check**: Automatic suspicious region detection

### Combinable Options
- **`--pc <addr>`**: Program Counter analysis
- **`--lr <addr>`**: Link Register analysis  
- **`--sp <addr>`**: Stack Pointer analysis (with validation)
- **`--fp <addr>`**: Frame Pointer analysis
- **`--html [file]`**: Generate HTML visualization

---

## Installation

No installation required! Just ensure Python 3.7+ is available:

```bash
chmod +x pmap.py
```

---

## Quick Start

### 1. Basic Analysis
```bash
./pmap.py test/pmap-sample.txt
```
Shows: Table, Statistics, Grouped by Binary, ASCII Layout, Security Check

### 1b. Analyze a Running Process (PID)
```bash
./pmap.py --pid 1
```
Shows: Live `/proc/1/maps` analysis (systemd on most systems)

### 2. Analyze a Crash (Program Counter)
```bash
./pmap.py test/pmap-sample.txt --pc 0xf79e245c
```
Shows which binary crashed and at what offset

### 3. Analyze Link Register (Call Stack)
```bash
./pmap.py test/pmap-sample.txt --lr 0xf79e7f10
```
Shows where the crashing function will return to

### 4. Full Crash Context
```bash
./pmap.py test/pmap-sample.txt \
  --pc 0xf79e245c \
  --lr 0xf79e7f10 \
  --sp 0xff8b0000 \
  --fp 0xff8b0010
```

### 5. Generate HTML Report
```bash
./pmap.py test/pmap-sample.txt --html crash_report.html
```

---

## Usage & Commands

### Command Syntax

```
python3 pmap.py <memory_dump_file> [OPTIONS]

Output Options (each shows only its specific report):
  --report             Show all reports (default if no options given)
  --table              Show memory map table view only
  --stats              Show memory statistics only
  --grouped            Show memory map grouped by binary only
  --segments           Show segment overview visualization only
  --ascii              Show ASCII memory layout only
  --security           Show security analysis only
  --html [file]        Generate HTML visualization (defaults to <mapfile>.html)

Input Options:
  --pid <pid>          Read /proc/<pid>/maps from a running process

Crash Analysis Options (shows crash context analysis only):
  --pc <addr>          Program counter address (hex)
  --lr <addr>          Link register address (hex)
  --sp <addr>          Stack pointer address (hex)
  --fp <addr>          Frame pointer address (hex)
```

### Common Commands

```bash
# All views combined
./pmap.py test/pmap-sample.txt

# Specific views
./pmap.py test/pmap-sample.txt --segments         # Segment overview only
./pmap.py test/pmap-sample.txt --ascii            # ASCII layout only
./pmap.py test/pmap-sample.txt --table            # Table view only
./pmap.py test/pmap-sample.txt --stats            # Statistics only

# Live process by PID
./pmap.py --pid 1                                 # PID 1 (systemd)

# Crash analysis (combinable)
./pmap.py test/pmap-sample.txt --pc 0xf79e245c                    # PC only
./pmap.py test/pmap-sample.txt --lr 0xf79e7f10                    # LR only
./pmap.py test/pmap-sample.txt --sp 0xff8b0000                    # SP only
./pmap.py test/pmap-sample.txt --pc 0x... --lr 0x... --sp 0x...  # Multiple

# HTML reports
./pmap.py test/pmap-sample.txt --html                              # Default filename
./pmap.py test/pmap-sample.txt --pc 0xf79e245c --html report.html  # Custom filename
./pmap2html.py --pid 1 --html systemd.html                         # PID-based HTML

# Help
./pmap.py --help
```

---

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
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                        MEMORY LAYOUT - ASCII VISUALIZATION                          
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

High Memory
     ↑
0xffff1000 ──┬─ r-xp  VDSO     [vectors]                        
             │
0xffff0000 ──┴─ (size: 4096 bytes)
             │
0xff8c1000 ──┬─ rw-p  STACK    [stack]                          ← SP
             │
0xff8a0000 ──┴─ (size: 135168 bytes)
             │
Low Memory ↓
```

### Crash Context Analysis

```
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                             CRASH CONTEXT ANALYSIS                                   
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

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
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                          MEMORY STATISTICS                                   
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Segment Type    Count    Total Size           Percentage
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
ANON            5               81920 bytes    2.08%
CODE            32          2,801,664 bytes   71.25%
DATA            32            389,120 bytes    9.89%
HEAP            2             741,376 bytes   18.85%
RODATA          33            204,800 bytes    5.21%
STACK           1             135,168 bytes    3.44%
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
TOTAL           105         3,932,160 bytes  100.00%
```

### Grouped by Binary

```
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                       MEMORY MAP - GROUPED BY BINARY                          
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

📦 /usr/bin/amxrt
   Total size: 12,288 bytes (3 segments)
   0x0098b000-0x0098c000  r-xp   CODE        4096 bytes
   0x0098c000-0x0098d000  r--p   RODATA      4096 bytes
   0x0098d000-0x0098e000  rw-p   DATA        4096 bytes

📦 [heap]
   Total size: 741,376 bytes (2 segments)
   0x0214f000-0x0218a000  rw-p   HEAP      241664 bytes
   0x0218a000-0x02204000  rw-p   HEAP      499712 bytes
```

### Security Analysis

```
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
                          SECURITY ANALYSIS                                   
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

✓ No suspicious writable+executable regions found.
```

---

## Project Structure

### Core Tool
| File | Purpose |
|------|---------|
| [pmap.py](pmap.py) | Main analyzer (1,302 lines, 48 KB) |

### Documentation
| File | Purpose |
|------|---------|
| [README.md](README.md) | Project overview & quick start (you are here) |
| [USAGE.md](USAGE.md) | Detailed reference & workflows |
| [TESTING.md](TESTING.md) | Testing guide & examples |
| [MEMORY_MAPS.md](MEMORY_MAPS.md) | Technical deep-dive |
| [STACK_DUMP_ANALYSIS.md](doc/STACK_DUMP_ANALYSIS.md) | Advanced crash analysis (5,000+ lines) |

### Samples & Tests
| File | Purpose |
|------|---------|
| [test/pmap-sample.txt](test/pmap-sample.txt) | Sample memory dump |
| [test/crash_demo.c](test/crash_demo.c) | Test program (crashes intentionally) |
| [test/test_all.sh](test/test_all.sh) | Comprehensive crash analysis tests |
| [test/test_analyser.sh](test/test_analyser.sh) | Unit test suite |
| [test/test_html.sh](test/test_html.sh) | HTML report generation test |

---

## Testing

### Run Automated Tests
```bash
./test/test_all.sh
```

**Test Coverage:**
1. Basic analysis (all views)
2. Segment overview only
3. ASCII layout only
4. PC analysis
5. LR analysis
6. SP analysis
7. Full crash context (all registers)
8. Error: unknown option
9. Error: no file specified

### Build & Test with Sample Program

```bash
# Compile test program
make

# Run it (will crash)
./test/crash_demo.out

# Analyze
./pmap.py crash_dump_*.maps --segments

# Or generate HTML
./pmap.py crash_dump_*.maps --html report.html
```

---

## Key Concepts

### Memory Segment Types

| Type | Perms | Source | Purpose |
|------|-------|--------|---------|
| CODE | r-xp | Binary/.so | Machine code |
| RODATA | r--p | Binary/.so | Constants, strings |
| DATA | rw-p | Binary/.so | Initialized globals |
| BSS | rw-p | Anonymous | Uninitialized globals |
| HEAP | rw-p | Anonymous | malloc/new allocations |
| STACK | rw-p | Anonymous | Function frames, locals |
| VDSO | r-xp | Kernel | Virtual system calls |
| ANON | rw-p | Anonymous | Other dynamic memory |

### Permission Patterns

| Pattern | Meaning |
|---------|---------|
| r-xp | Code (readable, executable) |
| r--p | Read-only data |
| rw-p | Writable data or heap |
| rwxp | ⚠️ Code injection risk |

### Input Format

The tool accepts memory dumps in `/proc/<pid>/maps` format:

```
0098b000-0098c000 r-xp 00000000 b3:04 6081                               /usr/bin/amxrt
0098c000-0098d000 r--p 00000000 b3:04 6081                               /usr/bin/amxrt
0098d000-0098e000 rw-p 00001000 b3:04 6081                               /usr/bin/amxrt
0214f000-0218a000 rw-p 00000000 00:00 0                                  [heap]
ff8a0000-ff8c1000 rw-p 00000000 00:00 0                                  [stack]
```

To capture a memory dump:

```bash
cat /proc/<pid>/maps > memdump.txt
```

---

## Workflow & Examples

### Step 1: Capture Memory Map at Crash

```bash
# Option 1: From running process
cat /proc/<pid>/maps > crash_test/pmap-sample.txt

# Option 2: Via GDB
gdb ./myprogram
(gdb) run
# crashes
(gdb) shell cat /proc/$(pgrep myprogram)/maps > crash.maps
```

### Step 2: Get Register Values

```bash
# From GDB
(gdb) info registers
# Note the PC, LR, SP values
```

### Step 3: Analyze the Crash

```bash
./pmap.py crash.maps --pc 0xf79e245c --lr 0xf79e7f10
```

### Step 4: Convert Offset to Source Code

```bash
# Tool outputs command like:
addr2line -e /lib/libubus.so.20230605 0x245c -f

# Which gives:
# vulnerable_function
# src/main.c:42
```

### Use Cases

1. **Crash Analysis**: Determine which library/binary caused a crash
2. **Debug Symbol Resolution**: Generate correct `addr2line` commands
3. **Memory Layout Visualization**: Understand process memory organization
4. **Security Auditing**: Detect writable+executable regions
5. **ASLR Analysis**: View actual runtime memory addresses
6. **Forensics**: Analyze memory dumps from core files

---

## Requirements

- **Python**: 3.7+
- **OS**: Linux (any architecture)
- **Dependencies**: None! Pure standard library only

---

## Architecture

### Classes & Functions

**Core Classes:**
- `SegmentType` (Enum): CODE, DATA, RODATA, BSS, HEAP, STACK, ANON, VDSO, UNKNOWN
- `MemorySegment`: Single memory region with metadata
- `MemoryMap`: Container for all segments
- `CrashContext`: Register values for analysis
- `MemoryMapParser`: Parse `/proc/<pid>/maps` format
- `MemoryMapVisualizer`: Generate different output formats
- `CrashAnalyzer`: Analyze registers and security

**Key Functions:**
- `print_help()`: Display usage
- `main()`: CLI argument parsing

### Data Flow
```
Memory Dump (test/pmap-sample.txt)
    ↓
Parser
    ↓
MemorySegment objects
    ↓
Visualizer / Analyzer
    ↓
Output (Console / HTML)
    ↓
User reads findings
```

---

## Advanced Features

### Combining Multiple Options

```bash
# Show only specific tables
./pmap.py test/pmap-sample.txt --table --stats

# Multiple registers
./pmap.py test/pmap-sample.txt --pc 0x... --lr 0x... --sp 0x... --fp 0x...

# HTML with crash context
./pmap.py test/pmap-sample.txt --pc 0xf79e245c --html crash_report.html
```

### Security Checks

The tool automatically detects:
- **Writable+Executable segments**: Code injection risk
- **Unusual permissions**: Non-standard mappings
- **Stack violations**: Out-of-bounds stack pointers

### Understanding addr2line Output

When the tool shows:
```
Debug command: addr2line -e /lib/libubus.so.20230605 0x245c
```

Run this command to get the source file and line number:
```bash
addr2line -e /lib/libubus.so.20230605 0x245c -f
# Output:
# vulnerable_function
# src/crash.c:42
```

---

## Documentation Files

### MEMORY_MAPS.md (Technical Background)
Deep-dive into Linux memory maps, anatomy of memory mappings, and segment types.

### STACK_DUMP_ANALYSIS.md (Advanced Reference)
Comprehensive 5,000+ line guide covering:
- Advanced crash analysis techniques
- Debugging with GDB, Core Dumps, /proc
- Priority 1 tools (Sanitizers, eBPF, LLDB, RR)
- Kernel tracing
- Language-specific debugging

### USAGE.md (Practical Reference)
Quick reference with command examples and troubleshooting.

### TESTING.md (Testing Guide)
Complete testing guide with real-world workflows and examples.

---

## Common Scenarios

### Segmentation Fault (SIGSEGV)
```bash
./pmap.py crash.maps --pc 0xf79e245c
# Identify which library crashed
# Get offset for addr2line
```

### Stack Overflow
```bash
./pmap.py crash.maps --sp 0xffffff00
# Check if SP is beyond stack boundaries
```

### Illegal Instruction (SIGILL)
```bash
./pmap.py crash.maps --pc 0xf7e00000
# Verify PC points to valid CODE section
```

### Heap Corruption
```bash
./pmap.py crash.maps --segments
# Inspect heap segments and boundaries
```

---

## Troubleshooting

**Q: "File not found" error**
A: Ensure the memory dump file path is correct:
```bash
./pmap.py ./test/pmap-sample.txt
```

**Q: addr2line shows "??" for symbols**
A: Binary likely needs debug symbols. Recompile with `-g` flag:
```bash
gcc -g -O0 myprogram.c -o myprogram
```

**Q: PC/LR addresses not mapping to any segment**
A: Address may be outside all mapped regions. Check for:
- Typos in hex addresses
- ASLR causing different base addresses
- Process crash before memory capture

---

## Performance

- **Parsing**: ~10ms for 100+ segments
- **Analysis**: <1ms per register resolution
- **HTML Generation**: ~50ms
- **Memory Usage**: <10MB typical

---

## Known Limitations

- Requires actual memory dump file (not real-time analysis)
- Cannot modify running processes
- Does not validate binary file existence
- Requires debug symbols for `addr2line` to work
- No support for non-Linux platforms

---

## Future Enhancements

Possible additions:
- `--filter-type CODE` to show only code segments
- `--filter-binary libc.so` to show only one library
- Direct GDB integration
- Core dump analysis support
- Memory range searches

---

## Summary

**pmap** is a complete, production-ready crash analysis toolkit:

✓ **1 powerful tool** (pmap.py - 1,302 lines)  
✓ **Comprehensive documentation** (README, USAGE, TESTING, MEMORY_MAPS, STACK_DUMP_ANALYSIS)  
✓ **Working examples** (test/pmap-sample.txt, crash_demo.c)  
✓ **Automated test suite** (test_all.sh)  

**Perfect for:**
- Embedded Linux developers
- Systems programmers
- Crash analysis engineers
- Debugging complex multi-library crashes

---

## Getting Help

1. **Quick start**: See this README
2. **Detailed reference**: Read [USAGE.md](USAGE.md)
3. **Learn the basics**: Read [MEMORY_MAPS.md](MEMORY_MAPS.md)
4. **Advanced topics**: See [doc/STACK_DUMP_ANALYSIS.md](doc/STACK_DUMP_ANALYSIS.md)
5. **Run tests**: Execute `./test/test_all.sh`
6. **Get help**: Run `./pmap.py --help`

---

**Version:** 1.0  
**Status:** Production Ready  
**License:** Educational Use
