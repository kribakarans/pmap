# Test Suite

This directory contains all testing-related files for the Memory Map Analyzer.

## Files

- **test_analyzer.sh** — Automated test suite (9 test cases)
- **crash_demo.c** — Example C program that crashes intentionally
- **memmap.txt** — Sample ARM memory dump (105 segments, real data)
- **TESTING_GUIDE.md** — Complete testing guide with workflows

## Quick Start

### Run All Tests

```bash
cd /home/labuser/workspace/memmap
./test/test_analyzer.sh
```

### Build and Run the Crash Demo

```bash
gcc -g -O0 test/crash_demo.c -o crash_demo
./crash_demo
# Program will crash and save memory map to crash_dump_*.maps
```

### Test on Sample Data

```bash
./memmap_analyzer.py test/memmap.txt --segments
./memmap_analyzer.py test/memmap.txt --pc 0xf79e245c --lr 0xf79e7f10
```

## Test Coverage

The automated test suite includes:

1. **Basic analysis** — All output views (table, stats, ASCII, grouped)
2. **Segment overview** — Quick boxed visualization
3. **ASCII layout** — Memory address diagram
4. **PC analysis** — Program counter location
5. **LR analysis** — Link register location
6. **SP analysis** — Stack pointer validation
7. **Full crash context** — All registers combined
8. **Error handling** — Unknown option detection
9. **Error handling** — Missing file detection

## Documentation

See [TESTING_GUIDE.md](TESTING_GUIDE.md) for:
- Detailed testing workflows
- How to capture real crash memory maps
- How to extract register values from crashes
- Real-world debugging scenarios
- Complete crash analysis examples

## Sample Data

**memmap.txt** is a real memory dump from an ARM-based Linux process (amxrt, PID 12044) containing:
- 105 memory segments
- Multiple shared libraries
- Heap and stack regions
- Data and code sections

Useful for testing the analyzer without needing a real crash.

## Building the Crash Demo

Requirements:
- GCC compiler
- glibc development headers
- Linux system with /proc filesystem

Build:
```bash
gcc -g -O0 crash_demo.c -o crash_demo
```

Run:
```bash
./crash_demo
```

The program will:
1. Install signal handlers
2. Run for a few seconds
3. Trigger a segmentation fault (NULL pointer dereference)
4. Auto-capture memory map to `crash_dump_<PID>.maps`

## Using Test Results

After running tests, analyze findings:

```bash
# Analyze the sample crash
./memmap_analyzer.py test/memmap.txt --pc 0xf79e245c

# Convert offset to source code
addr2line -e /lib/libubus.so.20230605 0x245c
```
