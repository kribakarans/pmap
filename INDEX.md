# Memory Map Analyzer - Project Index

## Project Overview

A pure Python crash analysis tool for Linux process memory dumps. Analyzes `/proc/<pid>/maps` dumps and crash registers to identify where a process crashed and generate debugging commands.

**No external dependencies** • **Pure Python 3.7+** • **Single-file tool**

---

## File Structure

### Core Tool

| File | Purpose |
|------|---------|
| [memmap_analyzer.py](memmap_analyzer.py) | Main analyzer tool (586 lines, fully featured) |

### Documentation

| File | Purpose |
|------|---------|
| [README.md](README.md) | Project overview, features, installation |
| [MEMORY_MAPS.md](MEMORY_MAPS.md) | Technical article on Linux memory maps and crash analysis |
| [TESTING_GUIDE.md](TESTING_GUIDE.md) | Complete testing guide with workflows and examples |
| [USAGE.md](USAGE.md) | Quick reference and real-world usage examples |

### Sample Code

| File | Purpose |
|------|---------|
| [crash_demo.c](crash_demo.c) | Example program that crashes intentionally for testing |

### Test Data & Scripts

| File | Purpose |
|------|---------|
| [memmap.txt](memmap.txt) | Sample memory dump for testing (105 segments) |
| [test_analyzer.sh](test_analyzer.sh) | Automated test suite (9 test cases) |

---

## Quick Start

### 1. Basic Analysis
```bash
./memmap_analyzer.py memmap.txt
```
Shows: Table, Statistics, Grouped by Binary, ASCII Layout, Security Check

### 2. Analyze a Crash (Program Counter)
```bash
./memmap_analyzer.py memmap.txt --pc 0xf79e245c
```
Shows which binary crashed and at what offset

### 3. Analyze Link Register (Call Stack)
```bash
./memmap_analyzer.py memmap.txt --lr 0xf79e7f10
```
Shows where the crashing function will return to

### 4. Full Crash Context
```bash
./memmap_analyzer.py memmap.txt \
  --pc 0xf79e245c \
  --lr 0xf79e7f10 \
  --sp 0xff8b0000 \
  --fp 0xff8b0010
```
Shows complete crash analysis with all registers

### 5. Run Automated Tests
```bash
./test/test_analyzer.sh
```
Runs 9 comprehensive test cases

---

## Tool Features

### Core Analysis
- ✅ Parse `/proc/<pid>/maps` format
- ✅ Classify memory segments (CODE, DATA, HEAP, STACK, etc.)
- ✅ Resolve register addresses to memory regions
- ✅ Generate `addr2line` commands for source lookup
- ✅ Detect security issues (writable+executable segments)

### Visualization Options
- **Default (no flags)**: Complete analysis with all views
- **`--segments`**: Quick segment overview in boxes
- **`--ascii`**: Memory layout diagram (High ↔ Low address)
- **`--pc <addr>`**: Program Counter analysis
- **`--lr <addr>`**: Link Register analysis
- **`--sp <addr>`**: Stack Pointer analysis (with stack validation)
- **`--fp <addr>`**: Frame Pointer analysis
- **Combinable**: Use multiple flags together

### Error Handling
- ✅ Unknown option detection
- ✅ Missing file detection
- ✅ Graceful error messages
- ✅ Help menu with `-h` or `--help`

---

## Command Reference

### Help
```bash
./memmap_analyzer.py --help
```

### Display Options
```bash
./memmap_analyzer.py memmap.txt                    # All views
./memmap_analyzer.py memmap.txt --segments         # Segment overview only
./memmap_analyzer.py memmap.txt --ascii            # ASCII layout only
```

### Register Analysis (Combinable)
```bash
./memmap_analyzer.py memmap.txt --pc 0xf79e245c                    # PC only
./memmap_analyzer.py memmap.txt --lr 0xf79e7f10                    # LR only
./memmap_analyzer.py memmap.txt --sp 0xff8b0000                    # SP only
./memmap_analyzer.py memmap.txt --fp 0xff8b0010                    # FP only
./memmap_analyzer.py memmap.txt --pc 0x... --lr 0x... --sp 0x...  # Multiple
```

---

## Understanding the Output

### Segment Overview (--segments)
```
┌────────────────────────────────────────┐
│ Stack                                  │
│ 0xff8a0000-0xff8c1000  rw-p STACK ...│
├────────────────────────────────────────┤
│ Shared Libs                            │
│ 0xf79e0000-0xf79e5000  r-xp CODE   ...│
├────────────────────────────────────────┤
│ Heap                                   │
│ 0x0214f000-0x0218a000  rw-p HEAP   ...│
└────────────────────────────────────────┘
```

### Crash Analysis (--pc, --lr, --sp, --fp)
```
Program Counter (PC):
  Address: 0x00000000f79e245c
  Segment: /lib/libubus.so.20230605 [CODE]
  Permissions: r-xp
  Offset in segment: 0x245c
  Debug command: addr2line -e /lib/libubus.so.20230605 0x245c
```

### Security Analysis (Automatic)
```
SECURITY ANALYSIS:
✓ No suspicious writable+executable regions found.

OR

⚠️  WRITABLE+EXECUTABLE: 0x08048000-0x0804a000 rwxp /usr/bin/myapp
```

---

## Typical Workflow

### 1. Capture Memory Map at Crash
```bash
# While process is running/crashed:
cat /proc/<pid>/maps > crash_memmap.txt

# Or capture via GDB:
gdb ./myprogram
(gdb) run
# crashes
(gdb) shell cat /proc/$(pgrep myprogram)/maps > crash.maps
```

### 2. Get Register Values
```bash
# From GDB:
gdb ./myprogram
(gdb) info registers

# From crash handler:
# Your code logs PC, LR, SP, FP
```

### 3. Analyze the Crash
```bash
./memmap_analyzer.py crash.maps --pc 0xf79e245c --lr 0xf79e7f10
```

### 4. Convert Offset to Source Code
```bash
# Tool outputs command like:
addr2line -e /lib/libubus.so 0x245c -f

# Which tells you:
# vulnerable_function
# src/main.c:42
```

---

## File Purposes

### memmap_analyzer.py (586 lines)

**Core Classes:**
- `SegmentType` (Enum): CODE, DATA, RODATA, BSS, HEAP, STACK, ANON, VDSO, UNKNOWN
- `MemorySegment`: Single memory region with metadata
- `MemoryMap`: Container for all segments
- `CrashContext`: Register values for analysis
- `CrashLocation`: Resolved crash address
- `MemoryMapParser`: Parse `/proc/<pid>/maps` format
- `MemoryMapVisualizer`: Generate different output formats
- `CrashAnalyzer`: Analyze registers and security

**Functions:**
- `print_help()`: Display usage and examples
- `main()`: CLI argument parsing and orchestration

---

## Memory Map Concepts

### Segment Types

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

---

## Testing

### Run All Tests
```bash
./test_analyzer.sh
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

### Test with Sample C Program

```bash
gcc -g -O0 crash_demo.c -o crash_demo
./crash_demo
# Program crashes and saves memory map
./memmap_analyzer.py crash_dump_*.maps --segments
```

---

## Documentation Files

### MEMORY_MAPS.md (16 KB, 470 lines)
**Technical education article for systems programmers**

Contents:
- What is a memory map and why it matters
- Anatomy of a memory map entry (with field-by-field breakdown)
- Common memory segment types (Code, Data, Heap, Stack, etc.)
- Skeleton of a process memory layout (with ASCII diagram)
- Memory maps in crash debugging (workflow)
- What NOT covered (scoping document)

### TESTING_GUIDE.md (8.4 KB, 350 lines)
**Comprehensive testing guide with real-world examples**

Contents:
- What the tool is for (crash debugging use cases)
- Sample C program (intentional crash)
- How to capture memory maps (GDB, signal handlers, manual)
- How to extract registers from crashes
- Step-by-step real-world examples
- Interpreting analyzer output
- Common findings (stack overflow, heap corruption, NULL deref)
- Complete workflow summary

### USAGE.md (8.8 KB, 380 lines)
**Quick reference and practical examples**

Contents:
- Summary of tool purpose
- All test command examples
- Real-world workflow (5 steps)
- Output format explanations
- Security checks
- Real examples from memmap.txt
- Troubleshooting guide
- Next steps

---

## Architecture

### Data Flow
```
Memory Dump (memmap.txt)
        ↓
    Parser
        ↓
MemorySegment objects
        ↓
    Visualizer / Analyzer
        ↓
    Output (Console)
        ↓
    User reads findings
        ↓
addr2line command (external)
        ↓
    Source code location
```

### Class Relationships
```
MemoryMap
  └── List[MemorySegment]
        └── SegmentType (Enum)
        └── Properties: readable, writable, executable

CrashContext
  ├── pc: int
  ├── lr: int
  ├── sp: int
  └── fp: int

MemoryMapParser
  └── parse_file() → MemoryMap
  └── parse_line() → MemorySegment

MemoryMapVisualizer
  ├── print_table()
  ├── print_ascii_layout()
  ├── print_grouped_by_binary()
  ├── print_statistics()
  └── print_segments_overview()

CrashAnalyzer
  ├── analyze_crash()
  ├── _analyze_register()
  ├── _analyze_backtrace()
  └── check_security()
```

---

## Dependencies

**None!** Pure Python standard library only:
- `re` (regex parsing)
- `sys` (CLI arguments)
- `dataclasses` (MemorySegment, MemoryMap, etc.)
- `typing` (Type hints)
- `enum` (SegmentType)

No pip packages required.

---

## Platform Support

**Tested on:**
- Linux (ARM-based, x86-64)
- Python 3.7+

**Memory map format:**
- `/proc/<pid>/maps` (Linux standard)
- Portable across ARM, x86-64, RISC-V, etc.

---

## Known Limitations

- Requires actual memory dump file (not real-time analysis)
- Cannot modify running processes
- Does not validate binary file existence
- Requires debug symbols for `addr2line` to work properly
- No support for core dump extraction (use external tools)

---

## Future Enhancements

Possible additions:
- `--filter-type CODE` to show only code segments
- `--filter-binary libc.so` to show only one library
- Direct GDB integration
- Core dump analysis support
- Memory range searches
- Symbol file integration

---

## Summary

This is a **complete, production-ready crash analysis toolkit** consisting of:

✅ **1 powerful tool** (memmap_analyzer.py)
✅ **4 comprehensive guides** (README, MEMORY_MAPS, TESTING, USAGE)
✅ **2 working examples** (memmap.txt, crash_demo.c)
✅ **1 automated test suite** (test_analyzer.sh)

**Perfect for:**
- Embedded Linux developers
- Systems programmers
- Crash analysis engineers
- Debugging complex multi-library crashes

---

## Getting Help

1. **Quick start:** See [USAGE.md](USAGE.md)
2. **Learn the basics:** Read [MEMORY_MAPS.md](MEMORY_MAPS.md)
3. **Run tests:** Execute `./test_analyzer.sh`
4. **Get help:** Run `./memmap_analyzer.py --help`

---

**Last Updated:** January 31, 2026  
**Version:** 1.0  
**Status:** Production Ready
