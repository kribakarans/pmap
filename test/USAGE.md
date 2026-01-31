# Testing and Usage Guide for Memory Map Analyzer

## Quick Summary

The **Memory Map Analyzer** is a crash debugging tool that:

1. **Reads** a memory dump from `/proc/<pid>/maps`
2. **Analyzes** register addresses (PC, LR, SP, FP) against memory segments
3. **Identifies** which binary/library crashed and at what offset
4. **Generates** `addr2line` commands to find source code locations
5. **Detects** security issues (writable+executable segments)

---

## Test Commands

### Run All Tests

```bash
./test/test_all.sh
```

This runs 9 test cases automatically and shows output for each.

### Individual Test Commands

#### Test 1: Full Analysis (Default)
```bash
./pmap.py test/test/pmap-sample.txt
```
Shows: Table, Statistics, Grouped by Binary, ASCII Layout, Security Check

#### Test 2: Segment Overview Only
```bash
./pmap.py test/pmap-sample.txt --segments
```
Shows: Quick boxed view of all segments organized by type

#### Test 3: ASCII Layout Only
```bash
./pmap.py test/pmap-sample.txt --ascii
```
Shows: Memory address diagram (High ↔ Low memory)

#### Test 4: Program Counter (PC) Analysis
```bash
./pmap.py test/pmap-sample.txt --pc 0xf79e245c
```
**Output:**
```
Program Counter (PC):
  Address: 0x00000000f79e245c
  Segment: /lib/libubus.so.20230605 [CODE]
  Permissions: r-xp
  Offset in segment: 0x245c
  Debug command: addr2line -e /lib/libubus.so.20230605 0x245c
```

**What it tells you:** The crash is in `/lib/libubus.so` at offset 0x245c

#### Test 5: Link Register (LR) Analysis
```bash
./pmap.py test/pmap-sample.txt --lr 0xf79e7f10
```

**What it tells you:** Where execution will return to (the calling function)

#### Test 6: Stack Pointer (SP) Analysis
```bash
./pmap.py test/pmap-sample.txt --sp 0xff8b0000
```

**What it tells you:** Is the stack pointer within the stack segment? (Detects stack overflow)

#### Test 7: Frame Pointer (FP) Analysis
```bash
./pmap.py test/pmap-sample.txt --fp 0xff8b0010
```

**What it tells you:** Base address of the current stack frame

#### Test 8: Full Crash Context
```bash
./pmap.py test/pmap-sample.txt \
  --pc 0xf79e245c \
  --lr 0xf79e7f10 \
  --sp 0xff8b0000 \
  --fp 0xff8b0010
```

**Combined output shows:**
- Which binary/library crashed (PC)
- Call stack context (LR)
- Stack health (SP, FP)
- Security issues
- addr2line commands for each address

#### Test 9: Error Handling - Unknown Option
```bash
./pmap.py test/pmap-sample.txt --unknown
```

**Output:**
```
Error: Unknown option '--unknown'
Usage: pmap.py [options] <memory_dump_file>
...
```

#### Test 10: Error Handling - No File
```bash
./pmap.py --ascii
```

**Output:**
```
Error: No memory dump file specified
Usage: pmap.py [options] <memory_dump_file>
...
```

---

## Real-World Workflow

### Step 1: Compile Your Program with Debug Symbols

```bash
gcc -g -O0 test/crash_demo.c -o crash_demo
```

### Step 2: Run and Let It Crash

```bash
./crash_demo
```

(The program has a signal handler that captures the memory map)

### Step 3: Find the Memory Map File

```bash
ls crash_dump_*.maps
```

### Step 4: Analyze the Crash

```bash
# Get quick overview
./pmap.py crash_dump_12345.maps --segments

# Analyze the crash (you get PC/LR from gdb or logs)
./pmap.py crash_dump_12345.maps \
  --pc 0x56559234 \
  --lr 0x56559250
```

### Step 5: Convert Offset to Source

```bash
# From the analyzer output, you get a command like:
addr2line -e ./crash_demo 0x1234 -f

# Output:
# vulnerable_function
# crash_demo.c:15
```

**Now you know exactly where the crash is!**

---

## Sample C Program

A crash demo program is included: [crash_demo.c](crash_demo.c)

### Build and Test It

```bash
gcc -g -O0 crash_demo.c -o crash_demo
./crash_demo
```

It will:
1. Run for a few seconds
2. Intentionally crash (NULL pointer dereference)
3. Auto-capture memory map to `crash_dump_<PID>.maps`

### Analyze the Crash

```bash
./pmap.py crash_dump_*.maps --segments
```

---

## Understanding the Output

### Segment Overview (--segments)

```
┌─────────────────────────────────────────────┐
│ Stack                                       │
│ 0xff8a0000-0xff8c1000  rw-p STACK  [stack] │
├─────────────────────────────────────────────┤
│ Shared Libs                                 │
│ 0xf79e0000-0xf79e5000  r-xp CODE  /lib/... │
│ 0xf79e5000-0xf79e6000  r--p RODATA /lib/..│
├─────────────────────────────────────────────┤
│ Heap                                        │
│ 0x0214f000-0x0218a000  rw-p HEAP  [heap]  │
├─────────────────────────────────────────────┤
│ BSS / Data                                  │
│ 0x0098d000-0x0098e000  rw-p DATA  /usr/... │
├─────────────────────────────────────────────┤
│ Code (.text)                                │
│ 0x0098b000-0x0098c000  r-xp CODE  /usr/... │
└─────────────────────────────────────────────┘
```

**How to read it:**
- Each box is a memory region type
- Address range shows where it lives in memory
- Permissions: r=read, w=write, x=execute, p=private
- Type: CODE, RODATA, DATA, HEAP, STACK, etc.
- Binary: What file backs this memory

### Tabular View (default)

```
Start Addr     End Addr       Size         Perms  Type       Binary/Mapping
0x0098b000     0x0098c000           4096  r-xp   CODE       /usr/bin/amxrt
0x0098c000     0x0098d000           4096  r--p   RODATA     /usr/bin/amxrt
0x0214f000     0x0218a000         241664  rw-p   HEAP       [heap]
```

### ASCII Layout (--ascii)

```
High Memory
     ↑
     │
0xff8c1000 ──┬─ rw-p  STACK    [stack]
             │
0xff8a0000 ──┴─ (size: 135,168 bytes)
     │
0xf79e0000 ──┬─ r-xp  CODE     /lib/libubus.so
             │
0xf79e5000 ──┴─ (size: 20,480 bytes)
     ↓
Low Memory
```

### Crash Analysis Output

```
Program Counter (PC):
  Address: 0x00000000f79e245c
  Segment: /lib/libubus.so.20230605 [CODE]
  Permissions: r-xp
  Offset in segment: 0x245c
  Debug command: addr2line -e /lib/libubus.so.20230605 0x245c
```

**How to use the debug command:**
```bash
addr2line -e /lib/libubus.so.20230605 0x245c
# Output: src/main.c:123
# This is the source line where the crash occurred
```

---

## Troubleshooting

### "No such file or directory: test/pmap-sample.txt"

Make sure you're in the right directory:
```bash
cd /home/labuser/workspace/memmap
./pmap.py test/pmap-sample.txt
```

### "Unknown option --foo"

Check valid options with:
```bash
./pmap.py --help
```

### "Error: No memory dump file specified"

First argument must be a file, not a flag:
```bash
# Wrong:
./pmap.py --pc 0x1234

# Right:
./pmap.py test/pmap-sample.txt --pc 0x1234
```

### addr2line returns "??:0"

Debug symbols are missing. Recompile with `-g`:
```bash
gcc -g -O0 myprogram.c -o myprogram
```

---

## Real Examples from test/pmap-sample.txt

### Finding a Crash in libubox

```bash
./pmap.py test/pmap-sample.txt --pc 0xf79e7f10
```

**Output shows:**
```
Address: 0x00000000f79e7f10
Segment: /lib/libubox.so.20230523 [CODE]
Offset in segment: 0xf10
Debug command: addr2line -e /lib/libubox.so.20230523 0xf10
```

### Detecting Stack Issues

```bash
./pmap.py test/pmap-sample.txt --sp 0xff8b0000 --fp 0xff8b0010
```

**Output shows:**
```
Stack Pointer (SP):
  Segment: [stack] [STACK]    ✓ Good
  Offset in segment: 0x10000

Frame Pointer (FP):
  Segment: [stack] [STACK]    ✓ Good
  Offset in segment: 0x10010
```

### Security Check

The tool always reports:
```
SECURITY ANALYSIS:
✓ No suspicious writable+executable regions found.
```

Or if there's a problem:
```
⚠️  WRITABLE+EXECUTABLE: 0x08048000-0x0804a000 rwxp /usr/bin/myapp
```

---

## Next Steps

1. **Run the test suite:** `./test_all.sh`
2. **Test on the sample:** `./pmap.py test/pmap-sample.txt --pc 0xf79e245c`
3. **Read the article:** See [ARTICLE_MEMORY_MAPS.md](ARTICLE_MEMORY_MAPS.md)
4. **Create your crash program:** Use [crash_demo.c](crash_demo.c) as a template
5. **Analyze real crashes:** Capture memory maps and use the analyzer

---

## Reference

- **Tool:** [pmap.py](pmap.py)
- **Documentation:** [TESTING_GUIDE.md](test/TESTING_GUIDE.md)
- **Article:** [MEMORY_MAPS.md](MEMORY_MAPS.md)
- **Sample Crash Program:** [test/crash_demo.c](test/crash_demo.c)
- **Automated Tests:** [test/test_all.sh](test/test_all.sh)
