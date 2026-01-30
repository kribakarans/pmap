# Testing the Memory Map Analyzer

## What is the Tool For?

The memory map analyzer helps debug **Linux process crashes** by correlating:

1. **Register addresses** (PC, LR, SP, FP) from a crash dump
2. **Memory mappings** (`/proc/<pid>/maps`) of the process
3. **Binary offsets** to pinpoint where the crash occurred

### Typical Crash Scenario

When a process crashes, you get:
- A signal (SIGSEGV, SIGILL, SIGABRT)
- Register snapshots (where was the CPU executing?)
- A memory map (where is each binary/library loaded?)

The analyzer combines these to answer: **"Which function in which binary crashed?"**

---

## Sample C Program: Intentional Crash

Create [crash_demo.c](crash_demo.c):

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

// Function that will crash
void vulnerable_function(int *ptr) {
    printf("In vulnerable_function, attempting dereference...\n");
    *ptr = 42;  // Dereference null or invalid pointer → SIGSEGV
}

// Function that calls the vulnerable function
void intermediate_function(void) {
    printf("In intermediate_function\n");
    int *null_ptr = NULL;
    vulnerable_function(null_ptr);
}

int main(int argc, char *argv[]) {
    printf("=== Crash Demo Program ===\n");
    printf("PID: %d\n", getpid());
    printf("This program will crash intentionally.\n\n");
    
    // Simulate some work
    for (int i = 0; i < 3; i++) {
        printf("Iteration %d\n", i + 1);
    }
    
    // Trigger the crash
    intermediate_function();
    
    return 0;
}
```

### Compile and Test

```bash
gcc -g -O0 crash_demo.c -o crash_demo
```

**Flags explanation:**
- `-g`: Include debug symbols (for `addr2line` and debuggers)
- `-O0`: No optimization (to preserve function calls and stack frames)

---

## Step 1: Capture the Memory Map at Crash Time

### Option A: Using GDB (Easiest)

```bash
gdb ./crash_demo
(gdb) run
# Program crashes with SIGSEGV
(gdb) shell cat /proc/$(pgrep -f "crash_demo")/maps > crash_memmap.txt
(gdb) info registers
# Note the PC, LR, SP values
(gdb) quit
```

### Option B: Using a Signal Handler

Modify `crash_demo.c` to capture the memory map before crashing:

```c
#include <signal.h>
#include <unistd.h>

void signal_handler(int sig) {
    char cmd[256];
    sprintf(cmd, "cat /proc/%d/maps > /tmp/crash_%d.maps", getpid(), sig);
    system(cmd);
    
    printf("\nSignal %d caught! Memory map saved.\n", sig);
    exit(1);
}

int main(int argc, char *argv[]) {
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    // ... rest of code
}
```

### Option C: Manually During Development

If you know the PID, capture the map in another terminal:

```bash
# Terminal 1: Run the program
./crash_demo

# Terminal 2: Capture its memory map
cat /proc/$(pgrep crash_demo)/maps > crash_memmap.txt
```

---

## Step 2: Extract Register Values

### From GDB

```bash
gdb ./crash_demo
(gdb) run
# Crashes
(gdb) info registers
```

Output on ARM:
```
pc             0xf79e245c  0xf79e245c
lr             0xf79e7f10  0xf79e7f10
sp             0xff8b0000  0xff8b0000
fp             0xff8b0010  0xff8b0010
```

### From Core Dump

```bash
gdb ./crash_demo core.123456
(gdb) info registers
```

### From Crash Logs

If your application logs the registers on signal:

```c
void signal_handler(int sig) {
    ucontext_t *context = (ucontext_t *)arg;
    
    #ifdef __arm__
    unsigned long pc = context->uc_mcontext.arm_pc;
    unsigned long lr = context->uc_mcontext.arm_lr;
    unsigned long sp = context->uc_mcontext.arm_sp;
    #endif
    
    printf("CRASH: PC=0x%lx LR=0x%lx SP=0x%lx\n", pc, lr, sp);
}
```

---

## Step 3: Run the Memory Map Analyzer

### Basic Analysis (All Views)

```bash
./memmap_analyzer.py crash_memmap.txt
```

**Output includes:**
- Tabular memory map (all segments)
- Memory statistics (size breakdown by type)
- Segments grouped by binary
- ASCII visualization (memory layout diagram)

### Find Where the Crash Happened

```bash
./memmap_analyzer.py crash_memmap.txt --pc 0xf79e245c
```

**Output shows:**
```
Program Counter (PC):
  Address: 0x00000000f79e245c
  Segment: /lib/libubus.so.20230605 [CODE]
  Permissions: r-xp
  Offset in segment: 0x245c
  Debug command: addr2line -e /lib/libubus.so.20230605 0x245c
```

This tells you: **Crash is in libubus.so at offset 0x245c**

### Analyze Link Register (Return Address)

```bash
./memmap_analyzer.py crash_memmap.txt --lr 0xf79e7f10
```

**Tells you where to return when the crashing function ends** (helps reconstruct call stack)

### Check Stack and Frame Pointers

```bash
./memmap_analyzer.py crash_memmap.txt --sp 0xff8b0000 --fp 0xff8b0010
```

**Verifies:**
- SP (Stack Pointer) is in the stack segment
- FP (Frame Pointer) points to valid stack memory
- Detects stack overflow: if SP is outside `[stack]` region

### Full Crash Analysis

```bash
./memmap_analyzer.py crash_memmap.txt \
  --pc 0xf79e245c \
  --lr 0xf79e7f10 \
  --sp 0xff8b0000 \
  --fp 0xff8b0010
```

**Combined output shows:**
- Which binaries/libraries are involved in the crash
- Offset within each binary for `addr2line` lookup
- Security issues (writable+executable segments)
- Warnings (SP outside stack, RWX segments)

---

## Step 4: Convert Offsets to Source Code

Using the offset from the analyzer:

```bash
addr2line -e /lib/libubus.so.20230605 0x245c
# Output: libubus.c:123
# Tells you the crash is in libubus.c at line 123
```

Or with debugging info:

```bash
addr2line -e crash_demo 0x1234 -f
# Output:
# vulnerable_function
# crash_demo.c:15
```

---

## Real-World Example: Step-by-Step

### Create the crash program:

```bash
cat > crash_test.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void level3(int *ptr) {
    printf("Level 3: dereferencing bad pointer\n");
    *ptr = 99;  // CRASH HERE
}

void level2(int *ptr) {
    printf("Level 2: calling level3\n");
    level3(ptr);
}

void level1(void) {
    printf("Level 1: calling level2\n");
    int *bad = (int *)0xDEADBEEF;
    level2(bad);
}

int main(void) {
    printf("Starting crash test. PID: %d\n", getpid());
    level1();
    return 0;
}
EOF

gcc -g -O0 crash_test.c -o crash_test
```

### Capture crash context:

```bash
# Terminal 1
./crash_test

# Terminal 2 (quickly)
pid=$(pgrep crash_test)
cat /proc/$pid/maps > test_memmap.txt
```

### Run the analyzer:

```bash
./memmap_analyzer.py test_memmap.txt --pc 0x56559234
# Shows which .so or binary crashed

# Get the exact source:
addr2line -e ./crash_test 0x1234
# Output: crash_test.c:8
```

---

## Test Command Reference

| Command | Use Case | Example |
|---------|----------|---------|
| `--pc <addr>` | Find where crash happened | `--pc 0xf79e245c` |
| `--lr <addr>` | Find where to return to | `--lr 0xf79e7f10` |
| `--sp <addr>` | Verify stack pointer is valid | `--sp 0xff8b0000` |
| `--fp <addr>` | Check frame pointer | `--fp 0xff8b0010` |
| `--segments` | Quick segment overview | `--segments` |
| `--ascii` | Memory layout visualization | `--ascii` |
| `--pc + --lr` | Full crash context | `--pc 0x... --lr 0x...` |
| `--pc + --lr + --sp` | Crash + stack info | All three together |

---

## Security Checks

The analyzer also flags dangerous conditions:

```
SECURITY ANALYSIS:
⚠️  WRITABLE+EXECUTABLE: 0x08048000-0x0804a000 rwxp /usr/bin/myapp
```

**This means:** A code section is writable, which allows:
- Code injection attacks
- Self-modifying code (unusual)

---

## Common Findings

### Example 1: Stack Overflow

```
SP = 0xfffce000 → [stack] ✓ OK
FP = 0xfffce010 → [stack] ✓ OK
PC = 0xfffce800 → NOT MAPPED ✗ CRASH!

Conclusion: Stack pointer advanced beyond stack boundary
```

### Example 2: Heap Corruption

```
PC = 0x56559234 → ./myapp (main binary) [CODE]
LR = 0xf7ab2345 → /lib/libc.so [CODE]

addr2line -e /lib/libc.so 0x2345
# Output: malloc.c:456 (memory allocator error)

Conclusion: malloc detected heap corruption
```

### Example 3: NULL Dereference

```
PC = 0x56559100 → ./myapp [CODE]
Offset in segment: 0x1100

addr2line -e ./myapp 0x1100
# vulnerable_function.c:45: *ptr = value;

Conclusion: Attempted to write to invalid address
```

---

## Summary: The Complete Workflow

1. **Program crashes** → Capture memory map + registers
2. **Run analyzer** → Identify which binary and offset
3. **Use addr2line** → Get source file and line number
4. **Check context** → PC/LR/SP/FP tell the story
5. **Fix the bug** → Now you know exactly where to look

The analyzer is the **bridge** between a raw crash address and human-readable debugging information.

