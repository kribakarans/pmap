# Testing Guide - Complete Testing & Crash Analysis

Comprehensive guide for testing pmap and analyzing real-world crashes on Linux systems.

## Table of Contents

1. [Overview](#overview)
2. [Sample Crash Program](#sample-crash-program)
3. [Capturing Crash Context](#capturing-crash-context)
4. [Analyzing Crashes](#analyzing-crashes)
5. [Register Dumps](#register-dumps)
6. [Architecture-Specific Examples](#architecture-specific-examples)
7. [Real-World Workflows](#real-world-workflows)
8. [Automated Testing](#automated-testing)
9. [Test Cases](#test-cases)

---

## Overview

The tool helps debug **Linux process crashes** by correlating:

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

## Sample Crash Program

The test suite includes `crash_demo.c`, a demonstration program with intentional crashes.

### Basic Version

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

### Advanced Version (With Signal Handler)

The actual `crash_demo.c` includes signal handlers to capture:
- CPU registers (PC, LR, SP, FP, etc.)
- Memory map (`/proc/<pid>/maps`)
- Call stack context

### Compile the Program

```bash
gcc -g -O0 crash_demo.c -o crash_demo
```

**Flags explanation:**
- `-g`: Include debug symbols (for `addr2line` and debuggers)
- `-O0`: No optimization (to preserve function calls and stack frames)

---

## Capturing Crash Context

### Option A: Using GDB (Recommended)

```bash
gdb ./crash_demo
(gdb) run
# Program crashes with SIGSEGV
(gdb) shell cat /proc/$(pgrep -f "crash_demo")/maps > crash_test/pmap-sample.txt
(gdb) info registers
# Note the PC, LR, SP values
(gdb) quit
```

**GDB commands for register extraction:**

```bash
(gdb) info registers                    # All registers
(gdb) print $pc                         # Just PC
(gdb) print $sp                         # Just SP
(gdb) where                             # Call stack
(gdb) frame 0                           # Current frame details
```

### Option B: Signal Handler Approach

Modify `crash_demo.c` to capture the memory map before crashing:

```c
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>

void signal_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *context = (ucontext_t *)ctx;
    char cmd[256];
    
    // Capture memory map
    sprintf(cmd, "cat /proc/%d/maps > /tmp/crash_%d.maps", getpid(), sig);
    system(cmd);
    
    // Extract and print registers
    #ifdef __x86_64__
    unsigned long pc = context->uc_mcontext.gregs[16];
    unsigned long sp = context->uc_mcontext.gregs[15];
    unsigned long fp = context->uc_mcontext.gregs[10];
    printf("CRASH: PC=0x%lx SP=0x%lx FP=0x%lx\n", pc, sp, fp);
    #endif
    
    exit(1);
}

int main(int argc, char *argv[]) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;
    
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    
    // ... rest of code
}
```

### Option C: Manual Capture During Development

If you know the PID, capture the map in another terminal:

```bash
# Terminal 1: Run the program
./crash_demo

# Terminal 2: Capture its memory map
cat /proc/$(pgrep crash_demo)/maps > crash_test/pmap-sample.txt
```

---

## Analyzing Crashes

### Step 1: Get Register Values

**From GDB:**
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

**From Core Dump:**
```bash
gdb ./crash_demo core.123456
(gdb) info registers
```

**From Application Logging:**
```c
void signal_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *context = (ucontext_t *)ctx;
    
    #ifdef __arm__
    unsigned long pc = context->uc_mcontext.arm_pc;
    unsigned long lr = context->uc_mcontext.arm_lr;
    unsigned long sp = context->uc_mcontext.arm_sp;
    #endif
    
    printf("CRASH: PC=0x%lx LR=0x%lx SP=0x%lx\n", pc, lr, sp);
}
```

### Step 2: Run the Memory Map Analyzer

**Basic Analysis (All Views):**

```bash
./pmap.py crash_test/pmap-sample.txt
```

Output includes:
- Tabular memory map (all segments)
- Memory statistics (size breakdown by type)
- Segments grouped by binary
- ASCII visualization (memory layout diagram)

**Find Where the Crash Happened:**

```bash
./pmap.py crash_test/pmap-sample.txt --pc 0xf79e245c
```

Output:
```
Program Counter (PC):
  Address: 0x00000000f79e245c
  Segment: /lib/libubus.so.20230605 [CODE]
  Permissions: r-xp
  Offset in segment: 0x245c
  Debug command: addr2line -e /lib/libubus.so.20230605 0x245c
```

This tells you: **Crash is in libubus.so at offset 0x245c**

**Analyze Link Register (Return Address):**

```bash
./pmap.py crash_test/pmap-sample.txt --lr 0xf79e7f10
```

Tells you where to return when the crashing function ends.

**Check Stack and Frame Pointers:**

```bash
./pmap.py crash_test/pmap-sample.txt --sp 0xff8b0000 --fp 0xff8b0010
```

Verifies:
- SP (Stack Pointer) is in the stack segment
- FP (Frame Pointer) points to valid stack memory
- Detects stack overflow: if SP is outside `[stack]` region

**Full Crash Analysis:**

```bash
./pmap.py crash_test/pmap-sample.txt \
  --pc 0xf79e245c \
  --lr 0xf79e7f10 \
  --sp 0xff8b0000 \
  --fp 0xff8b0010
```

Combined output shows:
- Which binaries/libraries are involved in the crash
- Offset within each binary for `addr2line` lookup
- Security issues (writable+executable segments)
- Warnings (SP outside stack, RWX segments)

### Step 3: Convert Offsets to Source Code

Using the offset from the analyzer:

```bash
addr2line -e /lib/libubus.so.20230605 0x245c
# Output: libubus.c:123
```

Or with debugging info:

```bash
addr2line -e crash_demo 0x1234 -f
# Output:
# vulnerable_function
# crash_demo.c:15
```

---

## Register Dumps

### Self-Dumping Register Values

Linux signal handlers can access CPU context directly via `ucontext_t`.

### Architecture Support

**x86-64 (gregs array indices):**
```
rip: [16]  (Program Counter)
rsp: [15]  (Stack Pointer)
rbp: [10]  (Frame Pointer)
rax: [13], rbx: [11], rcx: [14], rdx: [12]
rsi: [9],  rdi: [8]
r8-r15: [0-7]
```

**ARM64:**
```
pc:  context->uc_mcontext.pc
lr:  context->uc_mcontext.regs[30]
sp:  context->uc_mcontext.sp
x0-x30: context->uc_mcontext.regs[0-30]
```

**ARM (32-bit):**
```
pc:  context->uc_mcontext.arm_pc
lr:  context->uc_mcontext.arm_lr
sp:  context->uc_mcontext.arm_sp
fp:  context->uc_mcontext.arm_fp
r0-r15: context->uc_mcontext.arm_r[0-15]
```

### Example Register Dump

```
=== CRASH CONTEXT ===
Signal: 11 (SIGSEGV)
PID: 2755982

=== CPU REGISTERS (x86-64) ===
rip: 0000610303db57f2 (Program Counter - where crash occurred)
rsp: 00007fff60ec6e20 (Stack Pointer)
rbp: 00007fff60ec6e30 (Frame Pointer)
rax: 0000000000000000
rbx: 0000000000000000
... (all other registers)
```

### Key Register Values

| Register | Purpose | Example |
|----------|---------|---------|
| **PC/RIP** | Program Counter | Where the crash occurred |
| **SP/RSP** | Stack Pointer | Top of current call stack |
| **FP/RBP** | Frame Pointer | Current function's frame boundary |
| **LR** | Link Register (ARM) | Return address after function |
| **RAX/X0** | First return value | Function return or function argument |
| **RDI/X0-X7** | Function arguments | Parameters to current function |

---

## Architecture-Specific Examples

### x86-64 Example

**Program crashes in malloc():**

```bash
# Analyze
./pmap.py crash.maps --pc 0x7f1234567890

# Get source
addr2line -e /lib/libc.so.6 0x1890
# Output: malloc.c:456

# This indicates heap corruption
```

**Stack overflow detection:**

```bash
./pmap.py crash.maps --sp 0xfffce000 --fp 0xfffce010

# If SP > stack segment end, stack overflow detected
```

### ARM (32-bit) Example

**SIGSEGV in shared library:**

```bash
./pmap.py crash.maps --pc 0xf79e245c --lr 0xf79e7f10

# PC in /lib/libc.so, LR in /lib/libm.so
# Indicates crash during library function call
```

### ARM64 Example

**Illegal instruction in main binary:**

```bash
./pmap.py crash.maps --pc 0x0000aaaa12345678

# PC points to CODE section of main binary
addr2line -e ./myapp 0x5678
# Output: crash_site.c:42
```

---

## Real-World Workflows

### Complete Workflow: From Crash to Fix

**Step 1: Program crashes**
```bash
./myapp
# Segmentation fault (signal 11)
```

**Step 2: Capture context**
```bash
# Terminal 2
cat /proc/$(pgrep myapp)/maps > crash_maps.txt
```

**Step 3: Run analyzer**
```bash
./pmap.py crash_maps.txt --pc 0xf79e245c
```

**Step 4: Get source location**
```bash
addr2line -e /lib/libubus.so 0x245c -f
# vulnerable_function
# vulnerable.c:42
```

**Step 5: Fix and recompile**
```bash
nano vulnerable.c  # Fix line 42
gcc -g -O0 vulnerable.c -o libvulnerable.so
```

**Step 6: Test**
```bash
./myapp
# Now works without crash
```

### Comparing Different Crash Types

**NULL pointer dereference:**
```bash
# PC points to dereference instruction
./pmap.py crash.maps --pc 0xf79e245c
# Check source: likely *ptr = value or ptr->field
```

**Stack overflow:**
```bash
./pmap.py crash.maps --sp 0xffffff00
# SP near/beyond stack boundary
```

**Division by zero:**
```bash
# PC points to division instruction
./pmap.py crash.maps --pc 0xf79e2500
# Check source: likely x / y where y == 0
```

**Heap corruption:**
```bash
./pmap.py crash.maps --pc 0xf7123456 --segments
# PC likely in malloc/free functions
```

### Deep Call Stack Analysis

```bash
# Capture multiple frame pointers
./pmap.py crash.maps --pc 0x... --lr 0x... --sp 0x... --fp 0x...

# Get full backtrace
gdb ./crash_demo
(gdb) run
(gdb) where
# Shows: Frame 0 (crash), Frame 1 (caller), Frame 2 (caller's caller), etc.
```

---

## Automated Testing

### Run All Tests

```bash
./test/test_all.sh
```

This runs:
1. Basic analysis (all views)
2. Segment overview only
3. ASCII layout only
4. PC analysis
5. LR analysis
6. SP analysis
7. Full crash context (all registers)
8. Error handling (unknown option)
9. Error handling (no file specified)

### Run Unit Tests Only

```bash
./test/test_analyser.sh
```

### HTML Report Generation

```bash
./test/test_html.sh
```

This:
1. Compiles the crash demo
2. Triggers the crash
3. Generates HTML report with crash context
4. Validates the output

### Generate Batch Reports

```bash
./test/test_all.sh
```

Runs the complete end-to-end test flow:
- Build crash program
- Trigger crashes (SIGSEGV, SIGFPE, SIGABRT)
- Capture maps and registers
- Run analyzer with crash context
- Resolve source locations via addr2line

---

## Test Cases

### Test 1: Basic Memory Map Analysis

```bash
./pmap.py test/pmap-sample.txt
```

**Expected output:**
- Tabular view with all segments
- Memory statistics
- Grouped by binary
- ASCII layout
- Security analysis

### Test 2: Program Counter Only

```bash
./pmap.py test/pmap-sample.txt --pc 0xf79e245c
```

**Expected output:**
- Which binary contains PC address
- Offset within binary
- Suggestions for addr2line usage

### Test 3: Multiple Registers

```bash
./pmap.py test/pmap-sample.txt --pc 0xf79e245c --lr 0xf79e7f10 --sp 0xff8b0000
```

**Expected output:**
- Analysis for each register
- Stack validation
- Security warnings

### Test 4: HTML Report

```bash
./pmap.py test/pmap-sample.txt --html report.html
```

**Expected output:**
- HTML file created
- Visualization with crash markers
- Grouped memory view
- Clickable segments

### Test 5: Segment-Only View

```bash
./pmap.py test/pmap-sample.txt --segments
```

**Expected output:**
- Box diagram of major segments
- Memory addresses and sizes
- No other views

### Test 6: Statistics Only

```bash
./pmap.py test/pmap-sample.txt --stats
```

**Expected output:**
- Table of segment types
- Counts and sizes
- Percentages

### Test 7: Error Handling - No File

```bash
./pmap.py
```

**Expected output:**
- Error message
- Usage information

### Test 8: Error Handling - Invalid Option

```bash
./pmap.py test/pmap-sample.txt --invalid
```

**Expected output:**
- Error message
- Help text

### Test 9: Security Check

```bash
./pmap.py test/pmap-sample.txt --security
```

**Expected output:**
- List of suspicious regions (if any)
- OK message if no issues found

### Test 10: Real Crash Analysis

```bash
make                                    # Build crash_demo
./test/crash_demo.out                  # Trigger crash
./pmap.py crash_dump_*.maps --pc 0x... # Analyze using actual PC from crash
```

---

## Debugging with GDB

### Attach to Running Process

```bash
gdb -p <PID>
(gdb) info registers              # See current registers
(gdb) where                        # Backtrace
(gdb) frame 0                      # Details of current frame
(gdb) locals                       # Local variables
(gdb) print *ptr                   # Inspect specific variable
```

### Analyze Core Dump

```bash
gdb ./myapp core.12345
(gdb) where
(gdb) info registers
(gdb) frame 0
(gdb) print ptr
```

### Conditional Breakpoints

```bash
(gdb) break vulnerable_function if ptr == NULL
(gdb) run
# Program stops only if condition is true
```

---

## Practical Debugging Tips

### 1. Always Compile with Debug Symbols

```bash
gcc -g -O0 myapp.c  # Keep symbols, no optimization
```

### 2. Use Address Sanitizer to Catch Issues Early

```bash
gcc -fsanitize=address myapp.c
./a.out
# Detects heap overflow, use-after-free, etc.
```

### 3. Use Valgrind for Memory Analysis

```bash
valgrind ./myapp
# Reports memory leaks, invalid accesses
```

### 4. Check Stack Traces Automatically

```c
#include <execinfo.h>
#include <stdio.h>

void print_backtrace() {
    void *addrlist[10];
    int addrlen = backtrace(addrlist, 10);
    backtrace_symbols_fd(addrlist, addrlen, 1);
}

void signal_handler(int sig) {
    printf("Signal %d caught:\n", sig);
    print_backtrace();
    exit(1);
}
```

### 5. Use strace for System Call Tracing

```bash
strace ./myapp
# Shows all system calls made before crash
```

---

## Summary

The complete testing workflow:

1. **Write reproducible crash test** → crash_demo.c
2. **Capture crash context** → maps + registers
3. **Run analyzer** → pmap.py with registers
4. **Get source location** → addr2line
5. **Review and fix code** → Apply patch
6. **Verify fix** → No more crash
7. **Commit** → Add to version control

This guide provides all tools and techniques needed for effective crash analysis on Linux systems.

---

## Additional Resources

- [MEMORY_MAPS.md](MEMORY_MAPS.md) — Linux memory mapping details
- [USAGE.md](USAGE.md) — Complete tool reference
- [STACK_DUMP_ANALYSIS.md](STACK_DUMP_ANALYSIS.md) — Advanced analysis techniques
- GDB manual: `man gdb`
- addr2line manual: `man addr2line`
- signal handler docs: `man signal` / `man sigaction`
- ucontext docs: `man getcontext`
