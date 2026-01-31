# Stack Dump Analysis Methods for Running Linux Processes

## Table of Contents
1. [Introduction](#introduction)
2. [Quick Start Guide](#quick-start-guide) **START HERE**
3. [Command Cheat Sheet](#command-cheat-sheet)
4. [Real Crash Examples](#real-crash-examples)
5. [Debug Symbols & DWARF Information](#debug-symbols--dwarf-information)
6. [Thread Deadlock Analysis Patterns](#thread-deadlock-analysis-patterns)
7. [Memory Leak Detection Patterns](#memory-leak-detection-patterns)
8. [Common Crash Signatures](#common-crashes)
9. [Flame Graph Interpretation](#flame-graph-interpretation)
10. [Docker & Container Debugging](#docker--container-debugging)
11. [Systemd & Journald Integration](#systemd--journald-integration)
12. [Architecture-Specific Debugging](#architecture-specific-debugging)
13. [Remote Debugging & GDB Server](#remote-debugging--gdb-server)
14. [Language-Specific Crash Analysis](#language-specific-crash-analysis)
15. [Automated Crash Reporting Systems](#automated-crash-reporting-systems)
16. [Performance Profiling Comparison](#performance-profiling-comparison)
17. [Advanced Troubleshooting Scenarios](#advanced-troubleshooting-scenarios)
18. [Compiler Sanitizers (ASan, TSan, MSan, UBSan)](#compiler-sanitizers-asan-tsan-msan-ubsan) **CRITICAL**
19. [Kernel-Level Tracing (eBPF, kprobes, uprobes)](#kernel-level-tracing-ebpf-kprobes-uprobes) **CRITICAL**
20. [LLDB Debugger (LLVM/Apple Alternative)](#lldb-debugger-llvmapple-alternative) **CRITICAL**
21. [RR Record & Replay Debugger](#rr-record--replay-debugger) **CRITICAL**
22. [Method 1: GDB Attachment](#method-1-gdb-attachment)
23. [Method 2: Core Dumps](#method-2-core-dumps)
24. [Method 3: /proc Filesystem](#method-3-proc-filesystem)
25. [Method 4: strace/ltrace](#method-4-straceItrace)
26. [Method 5: perf Profiler](#method-5-perf-profiler)
27. [Comparison Table](#comparison-table)
28. [Integration with Crash Analyzer](#integration-with-crash-analyzer)
29. [Best Practices](#best-practices)
30. [Troubleshooting](#troubleshooting)

---

## Introduction

A **stack dump** (or backtrace) shows the chain of function calls that led to the current point of execution in a running process. It's essential for debugging, profiling, and root-cause analysis.

### Why Stack Dumps Matter
- **Crash Analysis**: Understand which function was executing when the crash occurred
- **Performance Profiling**: Identify performance bottlenecks
- **Deadlock Detection**: See which threads are stuck and where
- **Memory Leak Investigation**: Track allocation call chains

### Key Concepts
- **Stack Frame**: Memory region containing function parameters, local variables, and return address
- **Return Address**: Address of instruction after function call
- **Frame Pointer (FP)**: Points to current stack frame (register rbp/fp)
- **Stack Pointer (SP)**: Points to top of stack (register rsp/sp)
- **Program Counter (PC)**: Current instruction being executed

---

## Quick Start Guide

> **For busy developers:** Find your scenario, run the command, get results in 5 minutes.

### Scenario 1: Process Crashed - Get Core Dump

**Problem:** Process died, need to understand why.

**Solution:**
```bash
# Step 1: Check if core dump exists
ls -la core.*

# Step 2a: If yes, analyze immediately
gdb ./your_binary core.12345
(gdb) bt                    # See stack trace
(gdb) info registers        # See CPU state
(gdb) detach

# Step 2b: If no, re-run with dumps enabled
ulimit -c unlimited
./your_binary               # Let it crash again
ls -la core.*               # Should exist now
```

**Result:** Full stack trace showing exact crash location.

---

### Scenario 2: Process Running Now - Need Current Stack

**Problem:** Process is hung or slow, need to see what it's doing RIGHT NOW.

**Solution:**
```bash
# Get PID
pidof your_binary
# or: ps aux | grep your_binary

# Get stack without stopping process
gdb -batch -p <PID> -ex "bt" -ex "detach" 2>/dev/null

# Get all thread stacks
gdb -batch -p <PID> -ex "thread apply all bt" -ex "detach" 2>/dev/null
```

**Result:** Instant view of what's executing (non-blocking).

---

### Scenario 3: Find Performance Bottleneck

**Problem:** App is slow, burning CPU, need to know where time is spent.

**Solution:**
```bash
# Get PID
PID=$(pidof your_binary)

# Profile for 10 seconds
sudo perf record -p $PID -g -F 99 -- sleep 10

# View results
sudo perf report

# Or generate visual flamegraph
sudo perf script | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > perf.svg
# Open perf.svg in browser
```

**Result:** See exactly which functions consume most CPU time.

---

### Scenario 4: Debug Deadlock (Multi-threaded Process)

**Problem:** Process appears hung, multiple threads not responding.

**Solution:**
```bash
PID=$(pidof your_binary)

# Get all thread stacks
gdb -batch -p $PID -ex "info threads" -ex "thread apply all bt" -ex "detach" 2>/dev/null

# Look for patterns:
# - Thread 1: stuck on pthread_mutex_lock (address 0x555555757000)
# - Thread 2: stuck on pthread_mutex_lock (address 0x555555758000)
# - Thread 1 holds: 0x555555758000
# - Thread 2 holds: 0x555555757000
# → Circular lock dependency! (Deadlock detected)
```

**Result:** Identify which threads hold which locks.

---

### Scenario 5: Find Memory Leak

**Problem:** Memory grows over time, need to find where allocations happen.

**Solution:**
```bash
PID=$(pidof your_binary)

# Profile malloc calls for 30 seconds
sudo perf record -p $PID -g -e malloc --call-graph dwarf -F 100 -- sleep 30

# See which functions allocate most memory
sudo perf report --stdio | head -50

# Or trace malloc/free ratio
ltrace -p $PID -e malloc -e free -o alloc.log &
sleep 10
killall ltrace

# Count allocations vs frees
awk '/malloc.*=/ { alloc++ } /free\(/ { free++ } END { print "Malloc:", alloc, "Free:", free }' alloc.log
```

**Result:** Identify functions that allocate without freeing.

---

### Scenario 6: Trace System Calls (Debugging Unexpected Behavior)

**Problem:** App behaves oddly - opening wrong files, network issues, etc.

**Solution:**
```bash
PID=$(pidof your_binary)

# Trace specific syscalls (less verbose than tracing all)
strace -p $PID -e trace=open,openat,read,write -o trace.txt

# Wait a few seconds for behavior to manifest
sleep 5

# Analyze
cat trace.txt | tail -50  # See most recent calls
```

**Result:** See exact sequence of system calls.

---

## Command Cheat Sheet

Copy-paste commands for common tasks. **No reading required!**

### GDB Quick Reference
```bash
gdb -p <PID>                          # Attach to running process
gdb -batch -p <PID> -ex "bt"          # Get stack trace (non-blocking)
gdb -batch -p <PID> -ex "thread apply all bt"  # All threads
gdb ./binary core.file                # Analyze core dump

# Inside GDB:
(gdb) bt                              # Stack trace (current thread)
(gdb) bt full                         # Stack + local variables
(gdb) thread apply all bt             # Stack trace all threads
(gdb) info locals                     # Local variables in current frame
(gdb) info registers                  # All CPU registers
(gdb) frame 1                         # Select frame 1
(gdb) x/10i $pc                       # Disassemble at PC
(gdb) detach                          # Detach without killing
(gdb) quit                            # Exit
```

### Core Dump Quick Reference
```bash
ulimit -c unlimited                   # Enable core dumps
ls -la core.*                         # Find cores
file core.*                           # Identify core file
gdb ./binary core.*                   # Analyze
gzip core.* --fast                    # Compress for storage
```

### /proc Quick Reference
```bash
cat /proc/<PID>/maps                  # Memory layout
cat /proc/<PID>/status                # Process info
cat /proc/<PID>/smaps                 # Detailed memory
hexdump -C /proc/<PID>/mem            # Read memory
ps aux | grep <PID>                   # Quick process info
```

### strace Quick Reference
```bash
strace -p <PID>                       # Trace all syscalls
strace -p <PID> -e trace=open,read    # Trace specific syscalls
strace -p <PID> -o trace.txt          # Save to file
strace -p <PID> -T -f                 # Show duration + follow forks
strace -p <PID> -e signal             # Trace signals only
```

### ltrace Quick Reference
```bash
ltrace -p <PID>                       # Trace library calls
ltrace -p <PID> -C                    # Demangle C++ symbols
ltrace -p <PID> -e malloc             # Trace malloc only
ltrace -p <PID> -c                    # Count function calls
ltrace -p <PID> -o trace.txt          # Save to file
```

### perf Quick Reference
```bash
sudo perf record -p <PID> -g -- sleep 10   # Record samples
sudo perf report                           # View results
sudo perf script                           # Raw output
sudo perf stat -p <PID> -- sleep 5         # Statistics
sudo perf record -p <PID> -e malloc -g     # Profile malloc
```

### System/Process Quick Reference
```bash
ps aux | grep <name>                  # Find process
pidof <name>                          # Get PID quickly
ps -eLf | grep <PID>                  # Show all threads
kill -3 <PID>                         # Send SIGQUIT (core dump)
kill -SEGV <PID>                      # Intentional SIGSEGV
dmesg | tail                          # Kernel messages (OOM, crashes)
```

---

## Real Crash Examples

### Example 1: Segmentation Fault (NULL Pointer)

**Crash Output:**
```
Segmentation fault (core dumped)
```

**Analysis with GDB:**
```bash
gdb ./myapp core.12345
(gdb) bt
#0  0x0000555555554a50 in process_data () at main.c:45
#1  0x0000555555554b20 in main () at main.c:120

(gdb) frame 0
#0  0x0000555555554a50 in process_data () at main.c:45
45      int result = *ptr->value;

(gdb) info locals
ptr = 0x0
buffer = 0x555555757050

(gdb) list 40,50
40   void process_data(char *data) {
41       struct Node *ptr = find_node(data);
42       
43       // BUG: No NULL check!
44       int result = ptr->value;  // ← CRASHES HERE (ptr is NULL)
45   }
```

**Root Cause:** Line 45 dereferences NULL pointer (find_node returned NULL but not checked).

**Fix:**
```c
void process_data(char *data) {
    struct Node *ptr = find_node(data);
    
    if (!ptr) {  // ← ADD THIS CHECK
        printf("Error: Node not found\n");
        return;
    }
    
    int result = ptr->value;  // Now safe
}
```

---

### Example 2: Stack Overflow (Infinite Recursion)

**Crash Output:**
```
Stack overflow (Segmentation fault)
Memory usage: continuously growing to max
```

**Analysis with perf:**
```bash
sudo perf record -p <PID> -g -- sleep 5
sudo perf report

# Output shows deeply nested stack:
#   100.00%  myapp  [.] recursive_function
#     99.50%  myapp  [.] recursive_function
#       99.00%  myapp  [.] recursive_function
#         ... (repeated 1000+ times)
```

**GDB Analysis:**
```bash
gdb -p <PID>
(gdb) bt | head -100
#0  0x0000555555554a50 in recursive_function () at main.c:25
#1  0x0000555555554a60 in recursive_function () at main.c:30
#2  0x0000555555554a60 in recursive_function () at main.c:30
#3  0x0000555555554a60 in recursive_function () at main.c:30
... (same function repeating)

(gdb) list 20,35
20  void recursive_function(int depth) {
21      printf("Depth: %d\n", depth);
22      // BUG: No base case!
23      recursive_function(depth + 1);  // ← INFINITE RECURSION
24  }
```

**Root Cause:** Function calls itself without termination condition.

**Fix:**
```c
void recursive_function(int depth) {
    if (depth > 1000) {  // ← ADD BASE CASE
        return;
    }
    printf("Depth: %d\n", depth);
    recursive_function(depth + 1);
}
```

---

### Example 3: Deadlock (Multi-threaded)

**Symptoms:**
```
Process hangs indefinitely
All threads stuck
CPU at 0% (waiting on lock)
```

**GDB Analysis:**
```bash
gdb -p <PID>
(gdb) thread apply all bt

Thread 2 (Thread 0x7ffff7fdd700 (LWP 2222)):
#0  0x00007ffff7bc4f40 in pthread_mutex_lock () from /lib64/libpthread.so.6
#1  0x0000555555554c50 in worker_thread () at main.c:42
42      pthread_mutex_lock(&lock_B);  // ← BLOCKED

Thread 1 (Thread 0x7ffff7ff8700 (LWP 2221)):
#0  0x00007ffff7bc4f40 in pthread_mutex_lock () from /lib64/libpthread.so.6
#1  0x0000555555554b50 in main () at main.c:20
20      pthread_mutex_lock(&lock_A);  // ← BLOCKED
```

**Lock Analysis:**
```
Timeline:
  Thread 1: Acquires lock_A (line 15)
  Thread 2: Acquires lock_B (line 35)
  
  Thread 1: Tries to acquire lock_B (line 20) → WAITS for Thread 2
  Thread 2: Tries to acquire lock_A (line 42) → WAITS for Thread 1
  
  Result: DEADLOCK (circular wait)
```

**Code:**
```c
// Thread 1
pthread_mutex_lock(&lock_A);      // Has lock_A
do_work_A();
pthread_mutex_lock(&lock_B);      // ← Waits for B (held by Thread 2)

// Thread 2
pthread_mutex_lock(&lock_B);      // Has lock_B
do_work_B();
pthread_mutex_lock(&lock_A);      // ← Waits for A (held by Thread 1)
```

**Fix: Always acquire locks in same order**
```c
// Thread 1
pthread_mutex_lock(&lock_A);      // Always lock A first
pthread_mutex_lock(&lock_B);      // Then lock B
do_work_A_and_B();
pthread_mutex_unlock(&lock_B);
pthread_mutex_unlock(&lock_A);

// Thread 2 (SAME ORDER)
pthread_mutex_lock(&lock_A);      // Always lock A first
pthread_mutex_lock(&lock_B);      // Then lock B
do_work_B_and_A();
pthread_mutex_unlock(&lock_B);
pthread_mutex_unlock(&lock_A);
```

---

### Example 4: Memory Leak

**Symptoms:**
```
Memory usage grows over time
RSS keeps increasing: 10MB → 50MB → 200MB → OOM
No corresponding decrease
Eventually: Killed by OS
```

**perf Analysis:**
```bash
sudo perf record -p <PID> -g -e malloc -- sleep 60
sudo perf report --stdio | head -40

# Output:
#   25.50%  myapp  [.] allocate_buffer
#   18.30%  myapp  [.] process_request
#   12.20%  libc   [.] malloc
```

**GDB Breakpoint Analysis:**
```bash
gdb ./myapp
(gdb) break malloc if size > 1024
(gdb) run

# When breakpoint hits:
(gdb) bt
#0  0x00007ffff7a0d000 in malloc () from /lib64/libc.so.6
#1  0x0000555555554c50 in allocate_buffer () at main.c:100
#2  0x0000555555554d20 in process_request () at main.c:150
#3  0x0000555555554e00 in main () at main.c:200
```

**Code:**
```c
void process_request(int request_id) {
    char *buffer = malloc(4096);      // Allocates
    
    if (validate(buffer) < 0) {
        return;  // ← LEAKED! buffer never freed
    }
    
    process_data(buffer);
    free(buffer);  // Only reached if validate succeeds
}
```

**Fix:**
```c
void process_request(int request_id) {
    char *buffer = malloc(4096);
    
    if (validate(buffer) < 0) {
        free(buffer);  // ← FREE BEFORE RETURN
        return;
    }
    
    process_data(buffer);
    free(buffer);
}

// Or use error handling pattern:
void process_request(int request_id) {
    char *buffer = malloc(4096);
    int result = -1;
    
    if (validate(buffer) >= 0) {
        result = process_data(buffer);
    }
    
    free(buffer);  // ← ALWAYS FREED
    return result;
}
```

---



### Overview
**GNU Debugger (GDB)** is the most comprehensive method for live process debugging. It allows you to:
- Pause execution at any time
- Inspect variables and memory
- Set breakpoints
- Execute arbitrary commands
- Walk the entire call stack

### Prerequisites
```bash
# Install GDB
sudo apt-get install gdb

# Process must be running
# Your user must have permission to debug (same user or root)

# Optional: Install debug symbols for better analysis
sudo apt-get install <package-name>-dbg
```

### Step-by-Step Usage

#### 1. **Attach to Running Process**
```bash
# Get the PID first
ps aux | grep process_name
# or
pidof process_name

# Attach with GDB
gdb -p <PID>

# Or attach and keep running without breaking
gdb -p <PID> -batch -ex "thread apply all bt" -ex "quit"
```

#### 2. **Get Backtrace (Single Thread)**
```gdb
(gdb) bt
#0  0x00007ffff7a05aa0 in __select () from /lib64/libc.so.6
#1  0x0000555555554b50 in wait_for_input () at main.c:42
#2  0x0000555555554c20 in main () at main.c:58

(gdb) bt full
#0  0x00007ffff7a05aa0 in __select () from /lib64/libc.so.6
  No locals.
#1  0x0000555555554b50 in wait_for_input () at main.c:42
  timeout = 5
  fd_set = {bits = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
#2  0x0000555555554c20 in main () at main.c:58
  retval = 0
  argc = 1
  argv = 0x7fffffffe6e8
```

#### 3. **Get All Thread Stacks**
```gdb
(gdb) thread apply all bt

Thread 3 (Thread 0x7ffff77fe700 (LWP 12345)):
#0  0x00007ffff7a05aa0 in __select () from /lib64/libc.so.6
#1  0x0000555555554b50 in thread_worker () at worker.c:120
#2  0x00007ffff7bc6ea5 in start_thread () from /lib64/libpthread.so.6

Thread 2 (Thread 0x7ffff7ffd700 (LWP 12346)):
#0  0x00007ffff7a0f123 in pthread_cond_wait@@GLIBC_2.3.2 () from /lib64/libpthread.so.6
#1  0x0000555555554d50 in thread_pool_worker () at pool.c:85

Thread 1 (Thread 0x7ffff7ff8700 (LWP 12344)):
#0  0x00007ffff7a05aa0 in __select () from /lib64/libc.so.6
#1  0x0000555555554b50 in main () at main.c:58
```

#### 4. **Inspect Specific Frame**
```gdb
(gdb) frame 1
#1  0x0000555555554b50 in wait_for_input () at main.c:42
42      timeout = select(fd, &rfds, NULL, NULL, &tv);

(gdb) info locals
timeout = 5
fd = 0
rfds = {bits = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
tv = {tv_sec = 0, tv_usec = 500000}

(gdb) info args
(No arguments)
```

#### 5. **Continue Debugging Without Stopping Process**
```gdb
(gdb) detach
Detaching from program: /usr/bin/myapp, process 12345
(gdb) quit
```

### Example Session

```bash
$ ps aux | grep my_server
user  12345  0.2  1.5 1024000 30000 ?  Sl  10:30  0:05 ./my_server

$ gdb -p 12345
GNU gdb (GDB) 11.1
...
(gdb) thread apply all bt

Thread 2 (Thread 0x7ffff76d9700 (LWP 12346)):
#0  0x00007ffff7a0f123 in pthread_cond_wait () from /lib64/libpthread.so.6
#1  0x0000555555554d50 in queue_wait () at queue.c:85
#2  0x0000555555554e20 in worker_thread () at worker.c:42
#3  0x00007ffff7bc6ea5 in start_thread () from /lib64/libpthread.so.6

Thread 1 (Thread 0x7ffff7ff8700 (LWP 12345)):
#0  0x00007ffff7a05aa0 in __select () from /lib64/libc.so.6
#1  0x0000555555554b50 in event_loop () at main.c:120
#2  0x0000555555554c20 in main () at main.c:58

(gdb) detach
(gdb) quit
```

### Advantages
- **Most comprehensive** - Full variable inspection, memory examination  
- **Non-intrusive** - Doesn't require code changes  
- **Real-time** - Debug live running process  
- **Multi-threaded** - Inspect all threads  
- **Source-level debugging** - Shows actual code lines (with debug symbols)  

### Disadvantages
- **Requires permissions** - Must be same user or root  
- **Pauses execution** - Stops process while debugging (unless using non-stop mode)  
- **Requires debug symbols** - Unstripped binaries needed for full info  
- **Development-oriented** - Not ideal for production crash analysis  
- **Learning curve** - Complex tool with many commands  

### Limitations
- Some processes refuse debugging (e.g., with `PR_SET_DUMPABLE=0`)
- SELinux may block debugging
- Stripped binaries show only addresses, not function names

---

## Debug Symbols & DWARF Information

### Overview
Debug symbols are metadata embedded in binaries that map machine code back to source code. **DWARF** (Debugging With Attributed Record Formats) is the standard format used by Linux tools to store this information.

### Symbol Levels

**Unstripped Binary (Full Symbols)**
```bash
$ gcc -g -O0 program.c -o program
$ readelf --debug-dump=info program | head -20
  Abbrev Number: 1 (DW_TAG_compile_unit)
    DW_AT_producer    : GNU C17
    DW_AT_language    : C (ID: 1)
    DW_AT_name        : program.c
    DW_AT_comp_dir    : /home/user
```

**Stripped Binary (No Symbols)**
```bash
$ strip program
$ readelf --debug-dump=info program
Section '.debug_info' not found
(No symbol information available)
```

**Separated Debug Symbols**
```bash
$ gcc -g program.c -o program
$ objcopy --only-keep-debug program program.debug
$ objcopy --strip-debug program
# Result: program (no symbols) + program.debug (all symbols)
```

### Using Debug Symbols Effectively

**Extract full symbol information:**
```bash
# Show all function names and line numbers
addr2line -e program 0x1234 -f -C
# Output: function_name
#         /path/to/source.c:42

# Inspect DWARF information at a specific address
gdb -batch -ex "file program" -ex "info line *0x1234"

# Show variable locations in scope
gdb -batch -ex "file program" -ex "list *0x1234"
```

**Optimize storage with separate debug:**
```bash
# For distribution with minimal binary size
objcopy --only-keep-debug my_binary my_binary.debug
objcopy --strip-debug my_binary
# Install my_binary in /usr/bin
# Install my_binary.debug in /usr/lib/debug/usr/bin/my_binary.debug
```

### Debug Info Levels

| Flag | Size | Info | Use Case |
|------|------|------|----------|
| `-g` | +20% | All variables, types, lines | Development |
| `-g1` | +5% | Function names, lines only | Production binaries |
| `-g3` | +25% | Full info + preprocessor macros | Deep debugging |
| None | Minimal | Machine code only | Stripped binaries |

### Common Issues

**Problem: "Cannot find line info"**
- Cause: Binary compiled with `-fomit-frame-pointer` or `-O3`
- Solution: Rebuild with `-fno-omit-frame-pointer -g`

**Problem: "addr2line shows ?? instead of function"**
- Cause: Binary is PIE (Position Independent Executable)
- Solution: Use `gdb` or `perf` which handle PIE correctly

**Problem: Source file paths wrong in debug info**
- Cause: Compiled on different machine with different paths
- Solution: Use `gdb` with `directory` command or `addr2line -s` for relative paths

### Symbol Version Mismatches

```bash
# Check symbol versions in binary
readelf -sV program | grep VERSION

# Verify symbol consistency
nm -D program | wc -l
objdump -T program | wc -l

# Debug symbol conflicts
gdb -batch -ex "file program" -ex "set print symbol-loading on"
```

---

## Thread Deadlock Analysis Patterns

### Overview
Deadlocks occur when threads are blocked waiting for resources held by each other. Identifying the circular dependency is key to resolution.

### Classic Deadlock Pattern

```
Thread 1:  Lock(A) → [waiting for B]
Thread 2:  Lock(B) → [waiting for A]
           └─ Circular: A ←→ B
```

### Detection with GDB

**List all threads and their state:**
```bash
$ gdb -p $(pgrep stuck_app)
(gdb) thread apply all bt
Thread 2 (Thread 0x7ffff77fe700 (LWP 1234)):
#0  0x00007ffff7bc4f50 in pthread_mutex_lock@GLIBC_2.2.5 () from /lib64/libc.so.6
#1  0x0000555555554a5c in thread_func () at deadlock.c:45
#2  0x00007ffff7bc4000 in start_thread () from /lib64/libc.so.6

Thread 1 (Thread 0x7ffff7fdf700 (LWP 1233)):
#0  0x00007ffff7bc4f50 in pthread_mutex_lock@GLIBC_2.2.5 () from /lib64/libc.so.6
#1  0x0000555555554a10 in main () at deadlock.c:60
#2  0x00007ffff7bc2000 in __libc_start_main () from /lib64/libc.so.6
```

**Inspect specific thread state:**
```bash
(gdb) thread 2
(gdb) frame 1
#1  0x0000555555554a5c in thread_func () at deadlock.c:45
45  pthread_mutex_lock(&lock_b);  # Thread 2 blocked here

(gdb) thread 1
(gdb) frame 1
#1  0x0000555555554a10 in main () at deadlock.c:60
60  pthread_mutex_lock(&lock_a);  # Thread 1 blocked here
```

**Identify lock holder:**
```bash
(gdb) p lock_a.__data.__owner
$1 = 1233  # Thread 1 holds lock_a
(gdb) p lock_b.__data.__owner
$2 = 1234  # Thread 2 holds lock_b
# Circular dependency confirmed!
```

### Deadlock Patterns to Watch

**Pattern 1: Nested Lock Acquisition (Lock Ordering)**
```c
// DEADLOCK-PRONE
Thread 1: lock(A) → lock(B)
Thread 2: lock(B) → lock(A)  // Different order!

// FIX: Always lock in same order
Thread 1: lock(A) → lock(B)
Thread 2: lock(A) → lock(B)  // Same order
```

**Pattern 2: Reader-Writer Deadlock**
```c
// DEADLOCK-PRONE
pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

void writer_thread() {
    pthread_rwlock_wrlock(&rwlock);  // Thread W waits for readers
    // Can't proceed if Thread R holds read lock
}

void reader_thread() {
    pthread_rwlock_rdlock(&rwlock);  // Thread R acquires read lock
    // Holds lock indefinitely
}
```

**Pattern 3: Condition Variable Missed Signal**
```c
// DEADLOCK-PRONE
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
int ready = 0;

void waiter() {
    pthread_mutex_lock(&mutex);
    while (!ready) {
        pthread_cond_wait(&cond, &mutex);  // Waits forever
    }
    pthread_mutex_unlock(&mutex);
}

void signaler() {
    pthread_mutex_lock(&mutex);
    ready = 1;
    pthread_cond_broadcast(&cond);  // NEVER CALLED
    pthread_mutex_unlock(&mutex);
}
```

### Detection Commands

**Using ptrace to monitor lock waits:**
```bash
# Trace which locks are being acquired
strace -e futex -p $(pgrep stuck_app) 2>&1 | head -50
# Output shows threads waiting on futex (kernel lock)

futex(0x555555557000, FUTEX_WAIT, 1, NULL) = 0
futex(0x555555557010, FUTEX_WAIT, 1, NULL) = 0  # Stuck here
```

**Check /proc for blocked state:**
```bash
$ cat /proc/$(pgrep stuck_app)/status
State:    S (sleeping)
$ cat /proc/$(pgrep stuck_app)/stat | awk '{print $38, $39, $40}'
# Field 38-40: processor and wait channel
```

**Real-time deadlock monitoring:**
```bash
# Use perf with context switches
perf trace -e switch,futex --call-graph=dwarf -- sleep 30

# Watch for futex WAIT events without corresponding WAKE
perf script | grep -E "futex.*FUTEX_(WAIT|WAKE)"
```

### Resolution Strategies

| Issue | Detection | Fix |
|-------|-----------|-----|
| Lock order | Thread backtraces | Enforce consistent ordering |
| Missing signal | Thread waits on cond_var | Verify signal always called |
| Resource timeout | Strace shows ETIMEDOUT | Use `pthread_cond_timedwait` |
| Forgotten unlock | Thread holds lock indefinitely | Use RAII locks / `lock_guard` |

---

## Memory Leak Detection Patterns

### Overview
Memory leaks occur when allocated memory is never freed. Patterns vary by allocation type and scope.

### Leak Categories

**Category 1: Unreferenced Heap Blocks**
```c
void function() {
    char *buffer = malloc(4096);
    // ... use buffer ...
    // LEAK! No free() before return
}
```

**Category 2: Lost Pointer (Orphaned Memory)**
```c
void function() {
    char *ptr1 = malloc(1024);
    char *ptr2 = malloc(1024);
    ptr1 = ptr2;  // LEAK! Old ptr1 block is orphaned
    free(ptr2);
}
```

**Category 3: Early Return Without Cleanup**
```c
int function() {
    char *buffer = malloc(4096);
    if (validate(buffer) < 0) {
        return -1;  // LEAK! buffer never freed
    }
    // ... rest of code ...
    free(buffer);
    return 0;
}
```

**Category 4: Exception/Signal Path Leak**
```c
void signal_handler(int sig) {
    // Global state not cleaned up
    // malloc'd buffers never freed
    exit(1);  // LEAK!
}
```

### Detection with Valgrind

**Run with leak checking:**
```bash
$ valgrind --leak-check=full --show-leak-kinds=all \
           --track-origins=yes \
           --log-file=valgrind-out.txt \
           ./my_program

==1234== HEAP SUMMARY:
==1234== in use at exit: 2,048 bytes in 2 blocks
==1234== total heap alloc+freed: 10,240 bytes in 10 blocks
==1234== 2,048 bytes in 2 blocks are definitely lost
```

**Full leak report:**
```bash
==1234== 1,024 bytes in 1 blocks are definitely lost in loss record 1
==1234==    at 0x4C2DB8F: malloc (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==1234==    by 0x40053C: allocate_buffer (leak_demo.c:45)
==1234==    by 0x400559: main (leak_demo.c:60)
```

### Detection with mtrace

```bash
# Run program with mtrace
$ MALLOC_TRACE=/tmp/trace.log ./my_program

# Analyze trace
$ mtrace ./my_program /tmp/trace.log
- 0x60c8f0 Free 0x60c8c0
- 0x60c90d Free 0x60c8c0
Memory not freed:
---------
  Address     Size     Caller
0x60c8c0      1024  at 0x40053c
```

### Heap Profiling Pattern Analysis

**Pattern 1: Unbounded Growth**
```bash
# Check heap size over time
while true; do
    echo "$(date): $(pmap $(pgrep app) | grep heap | awk '{print $2}')"
    sleep 5
done
# Output:
# ... 2:00 PM: 10M
# ... 2:05 PM: 15M  (5MB growth)
# ... 2:10 PM: 20M  (5MB growth every 5 min)
#             → Leak confirmed!
```

**Pattern 2: Allocation Callstack Ranking**
```bash
# Use perf to rank top allocation sites
$ valgrind --tool=massif --massif-out-file=massif.out ./my_program
$ ms_print massif.out | grep -A 30 "PEAK"

    n        time(B)         total(B)   useful-heap(B) extra-heap(B)    stacks(B)
99.76%   1,234,567        1,234,100        1,200,000           34,100             0
   0.15%      1,850          1,850            1,820              30             0
   0.09%      1,100          1,100            1,100               0             0

# Top leak at largest peak
   n        time(B)         total(B)   useful-heap(B) extra-heap(B) stacks(B)
   0  0B             0B             0B             0B        0B
   1  100,000B       100,000B       100,000B            0B        0B
 1                              : 0x4C2DB8F: malloc (...)
 1                              :  0x400123: create_buffer (leak_demo.c:10)
 1                              :  0x400200: main (leak_demo.c:50)
```

### /proc Analysis for Leaks

```bash
# Monitor RSS (resident set size)
$ watch -n 1 'ps aux | grep my_program | grep -v grep'

# Before: RSS=10MB
# After 1min: RSS=15MB
# After 2min: RSS=20MB
# Pattern: Continuous growth → leak

# Deep dive into memory map
$ cat /proc/$(pgrep my_program)/smaps | grep -E "^[0-9a-f]|Rss"
# Sum up Rss for heap sections
$ cat /proc/$(pgrep my_program)/smaps | grep -B1 "\[heap\]" | tail -2
```

### gdb-based Leak Detection

```bash
# Breakpoint on malloc/free to track allocations
$ gdb ./my_program
(gdb) break malloc
(gdb) commands
> silent
> printf "ALLOC: %p size=1024\n", $rax
> continue
> end

(gdb) break free
(gdb) commands
> silent
> printf "FREE: %p\n", $rdi
> continue
> end

# Run and filter for unmatched allocs
(gdb) run | grep -E "^ALLOC|^FREE"
```

### Resolution Checklist

| Issue | Detection | Fix |
|-------|-----------|-----|
| Missing free() | Valgrind shows "definitely lost" | Add free(ptr) before return |
| Exception path | Leak in signal handler | Use try-finally or RAII |
| Lost pointer | Valgrind shows orphaned block | Track all pointers before reassign |
| Double-free | SEGV on free, Valgrind errors | Check if already freed |
| Large heap | `pmap` shows growing heap | Profile with massif |

---

## Common Crash Signatures

### Overview
Crash signatures identify recurring failure patterns by examining the crash stack, memory state, and error context.

### Signature Pattern 1: NULL Pointer Dereference

**Identifying Features:**
- PC points to instruction with memory access
- Crash address is 0x0 or very low (< 0x1000)
- Backtrace shows attempted field access

**GDB Inspection:**
```bash
$ gdb ./program core.dump
(gdb) bt
#0  0x00007ffff7a52f50 in __strlen_avx2 () from /lib64/libc.so.6
#1  0x0000555555554a7c in print_user () at main.c:45
#2  0x0000555555554a90 in main () at main.c:50

(gdb) frame 1
#1  0x0000555555554a7c in print_user () at main.c:45
45  printf("%s\n", user->name);  # NULL pointer dereference

(gdb) print user
$1 = (struct User *) 0x0
```

**Common Sources:**
- Missing NULL check after malloc/calloc
- Uninitialized pointers
- Function returns NULL on error (caller ignores)

```c
// Source pattern
struct Node *find_node(int id) {
    for (int i = 0; i < count; i++) {
        if (nodes[i].id == id) return &nodes[i];
    }
    return NULL;  // Not found
}

// Crash when not found
void delete_node(int id) {
    struct Node *node = find_node(id);
    free(node->data);  // CRASH if NULL
}

// Fix
void delete_node(int id) {
    struct Node *node = find_node(id);
    if (!node) return;  // Check for NULL
    free(node->data);
}
```

### Signature Pattern 2: Stack Buffer Overflow

**Identifying Features:**
- Crash in strcpy, sprintf, or memcpy
- Stack variables corrupted (rbp, return address)
- PC points outside code segment (corrupted return address)

**GDB Inspection:**
```bash
(gdb) bt
#0  0x41414141 in ?? ()  # Corrupted address (0x41 = 'A')
#1  0x42424242 in ?? ()  # Corrupted address (0x42 = 'B')

(gdb) frame 0
#0  0x41414141 in ?? ()
Cannot find frame

(gdb) x/10x $rsp
0x7ffffffde800: 0x41414141 0x41414141 0x41414141 0x41414141
# Stack full of 'A' bytes
```

**Source Pattern:**
```c
void vulnerable() {
    char buffer[256];
    strcpy(buffer, user_input);  // No bounds check!
}

// Fix
void safe_version() {
    char buffer[256];
    strncpy(buffer, user_input, 255);  // Bounds limited
    buffer[255] = '\0';
}
```

### Signature Pattern 3: Use-After-Free

**Identifying Features:**
- PC in freed memory region
- Backtrace shows malloc'd object being used
- Valgrind detects "free" followed by access

**GDB Inspection:**
```bash
$ valgrind ./program
==1234== Invalid read of size 8
==1234==    at 0x4C2E8F0: strcmp (vg_replace_libc.so.X:strcmp.c:450)
==1234==    by 0x400123: process_user (main.c:30)
==1234==    by 0x400200: main (main.c:60)
==1234==  Address 0x52f2040 is 0 bytes inside a block of size 256 free'd
==1234==    at 0x4C2A6A0: free (vg_replace_libc.so.X:vgpreload_memcheck.c:505)
==1234==    by 0x400110: cleanup (main.c:25)
```

**Source Pattern:**
```c
struct User *user = malloc(sizeof(struct User));
free(user);
printf("%s\n", user->name);  // USE AFTER FREE!

// Fix: Set to NULL after free
struct User *user = malloc(sizeof(struct User));
free(user);
user = NULL;  // Prevent accidental reuse
```

### Signature Pattern 4: Infinite Loop / Hang

**Identifying Features:**
- Same PC address in all threads (stuck at one instruction)
- Backtrace shows spinning on lock or condition

**perf Detection:**
```bash
$ perf record -F 99 -p $(pgrep hanging_app) -- sleep 10
$ perf report | head -30
    30.45%  hanging_app  [kernel]              [k] spin_loop
    25.33%  hanging_app  hanging_app           [.] wait_for_lock
    20.12%  hanging_app  libc.so.6             [.] pthread_mutex_lock
```

**Source Pattern:**
```c
// INFINITE LOOP
while (1) {
    if (ready) break;
    // No sleep, busy-spinning
}

// Fix: Add sleep or condition wait
while (!ready) {
    sleep(1);  // Or use pthread_cond_wait
}
```

### Signature Pattern 5: Segmentation Fault at High Address

**Identifying Features:**
- PC near 0xFFFFFFFF...
- Stack exhausted (all frames show same function)
- `ulimit -s` shows small stack size

**GDB Inspection:**
```bash
(gdb) bt | tail -20
#100  0x00007ffff7a52f50 in recursive_function () at main.c:10
#101  0x00007ffff7a52f50 in recursive_function () at main.c:10
#102  0x00007ffff7a52f50 in recursive_function () at main.c:10
#103  0x00007ffff7a52f50 in recursive_function () at main.c:10
# Repeating frames = stack overflow!
```

**Source Pattern:**
```c
// Stack overflow
void recursive_function(int n) {
    recursive_function(n + 1);  // No base case
}

// Fix: Add termination
void recursive_function(int n) {
    if (n > 1000) return;  // Base case
    recursive_function(n + 1);
}
```

### Crash Signature Summary Table

| Signature | Error | Stack | Memory | Fix |
|-----------|-------|-------|--------|-----|
| NULL deref | SIGSEGV | user->field = NULL | Low address | NULL check |
| Buffer overflow | SIGSEGV | corrupted rbp | Stack | Use strncpy |
| Use-after-free | SIGSEGV/SIGABRT | arbitrary | Freed heap | Set NULL |
| Stack overflow | SIGSEGV | repeating frames | High address | Add base case |
| Division by zero | SIGFPE | normal | varies | Check divisor |

---

## Flame Graph Interpretation

### Overview
Flame graphs are time-stacked visualizations showing which functions consume CPU time and how deep the call stack goes.

### Reading a Flame Graph

```
            total_time
              └─────────────────────────┐
                                        │
     function_a (50%)    function_b (30%)   function_c (20%)
         │                    │                  │
         ├─ called by: main   ├─ called by: main  └─ called by: main
         │  width = time      │  width = time     width = time
         │  height = stack    │  height = stack   height = stack
         │  depth = 1         │  depth = 1        depth = 1
```

**Key Rules:**
- **Width**: Horizontal span shows total CPU time spent in function
- **Height**: Vertical stack height shows call depth
- **Color**: Random or gradient (CPU-friendly colors, not semantic)
- **Left-to-right ordering**: No semantic meaning, just space optimization

### Generated from perf

```bash
# Capture performance data
$ perf record -F 99 -g ./my_program
$ perf script > /tmp/perf.txt

# Install FlameGraph tools
$ git clone https://github.com/brendangregg/FlameGraph
$ cd FlameGraph

# Generate flame graph
$ cat /tmp/perf.txt | ./stackcollapse-perf.pl > /tmp/perf.folded
$ ./flamegraph.pl /tmp/perf.folded > /tmp/flame.svg

# View in browser
$ firefox /tmp/flame.svg
```

### Flame Graph Analysis Patterns

**Pattern 1: Flat Top (Wide, Shallow Blocks)**
```
┌────────────────────────────────────┐
│        main (50% width)            │
├────────────────────────────────────┤
│  function_a (25%)  function_b (25%)│
├─────────────┬──────────────────────┤
│ libc (20%)  │    kernel (5%)       │
└─────────────┴──────────────────────┘

Interpretation:
- No deep recursion
- Multiple functions called directly from main
- Relatively balanced CPU distribution
```

**Pattern 2: Tall, Narrow Stack (Deep Recursion)**
```
                 │
            ┌────┴────┐
            │ func_5  │
            └────┬────┘
                 │
            ┌────┴────┐
            │ func_4  │
            └────┬────┘
                 │
            ┌────┴────┐
            │ func_3  │
            └────┬────┘
                 │
            ┌────┴────┐
            │ func_2  │
            └────┬────┘
                 │
            ┌────┴────┐
            │ func_1  │
            └────┬────┘
                 │
            ┌────┴────┐
            │  main   │
            └─────────┘

Interpretation:
- Deep call chain, narrow width = little time spent
- Likely waiting on I/O or lock
- Not a performance bottleneck
```

**Pattern 3: Large Hot Spot (Wide Block, Specific Location)**
```
┌────────────────────────────────────────────────────────┐
│         compute_algorithm (80% CPU time)               │
│  ┌──────────────────────────────────────────────────┐  │
│  │       inner_loop (70% CPU time)                  │  │
│  │  ┌─────────────────────────────────────────┐     │  │
│  │  │  tight_math_operation (60% CPU time)    │     │  │
│  │  └─────────────────────────────────────────┘     │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘

Interpretation:
- Clear hot spot: tight_math_operation
- Optimization focus: algorithm, vectorization, cache
- Actionable: Replace algorithm or use SIMD
```

### Common Patterns to Investigate

**Pattern: "Off-CPU" Time (Not in User Code)**
```
┌──────────────────────────────────────────┐
│              main                        │
├──────┬───────────┬──────────┬────────────┤
│ user │  kernel   │  futex   │   epoll    │
│ 30%  │   20%     │   20%    │   30%      │
└──────┴───────────┴──────────┴────────────┘

Interpretation:
- 70% time NOT in user code
- Likely I/O-bound or lock-bound
- Not CPU bottleneck, but resource contention
- Solution: Async I/O, better locking strategy
```

**Pattern: Malloc/Free Hot Spot**
```
┌─────────────────────────────────────┐
│              main                   │
├─────────────┬───────────────────────┤
│  user code  │     memory mgmt       │
│    30%      │        70%            │
│             ├────────┬──────────────┤
│             │ malloc │    free      │
│             │  35%   │     35%      │
└─────────────┴────────┴──────────────┘

Interpretation:
- Excessive allocation/deallocation
- Solution: Object pooling, pre-allocate buffers
```

### Creating Custom Flame Graphs

**For GDB backtrace collection:**
```bash
# Collect samples via GDB
$ gdb -batch -x /dev/stdin ./program << 'EOF'
set pagination off
run
while 1
  thread apply all bt
  shell sleep 0.1
  signal SIGINT
end
EOF

# Save to perf format and graph
$ perf script > perf.txt
```

**For custom profiler data:**
```bash
# Sample format:
# function_a;function_b;function_c 100
# (semicolon-separated stack, then sample count)

main;malloc;libc 50
main;free;libc 30
main;process;loop 150

# Save as stacks.txt, then convert:
$ /path/to/flamegraph.pl stacks.txt > flame.svg
```

### Flame Graph CLI Interpretation

**Simple perf stat output:**
```bash
$ perf stat ./my_program
 Performance counter stats for './my_program':
    2,000.123456 task-clock:u (msec)
       50,234,567 cycles:u
       10,234,567 instructions:u
          2.5 IPC
       10,000,000 cache-references:u
          500,000 cache-misses:u    # 5.0% cache miss rate

Interpretation:
- 2,000 ms execution time
- 2.5 instructions per cycle (good)
- 5% cache miss rate (acceptable for most workloads)
```

### Optimization Based on Flame Graphs

| Flame Pattern | Cause | Optimization |
|--------------|-------|--------------|
| Wide malloc block | Excessive allocation | Pool objects, pre-allocate |
| Deep, narrow stack | I/O wait | Async I/O, batching |
| Repeated kernel calls | System call overhead | Buffer syscalls, use events |
| Uneven block widths | Load imbalance | Parallelize work units |
| High cache-miss rate | Memory layout | Structure packing, NUMA |

---

### Overview
A **core dump** is a file snapshot of a process's memory at the moment of crash. It allows post-mortem analysis without needing to debug the live process.

### Prerequisites
```bash
# Check current core dump limits
ulimit -a | grep core
# Output: core file size          (blocks, -c) 0

# Enable unlimited core dumps
ulimit -c unlimited

# Verify it's enabled
ulimit -c
# Output: unlimited

# Optional: Configure where core files are saved
echo "/var/crash/core.%e.%p" | sudo tee /proc/sys/kernel/core_pattern
# e = executable name, p = PID
```

### Core Dump Configuration

#### System-Wide Configuration (Persistent)
```bash
# Edit sysctl configuration
sudo nano /etc/sysctl.conf

# Add/modify these lines:
kernel.core_pattern = /var/crash/core.%e.%p.%h.%t
kernel.core_uses_pid = 1
fs.suid_dumpable = 1

# Apply changes
sudo sysctl -p
```

**Pattern Specifiers:**
- `%e` - executable name
- `%p` - PID
- `%h` - hostname
- `%t` - timestamp (seconds since epoch)
- `%u` - UID
- `%g` - GID
- `%%` - literal %

#### Per-Process Configuration
```bash
# In your crash-enabled program:
#include <sys/prctl.h>

int main() {
    // Enable core dumps for this process
    prctl(PR_SET_DUMPABLE, 1);
    
    // Process code...
}
```

### Step-by-Step Usage

#### 1. **Enable Core Dumps**
```bash
ulimit -c unlimited
export LD_LIBRARY_PATH=/path/to/libs

# Run your process
./my_app
```

#### 2. **Trigger Crash (Optional - Let it Fail Naturally)**
```bash
# Example crash test program
./test/crash_demo.out
# Alternatively: kill -SEGV <PID>

# Generates: crash_dump_<PID>.maps and crash_dump_<PID>.regs
```

#### 3. **Analyze with GDB**
```bash
# Find the core file
ls -la core.* /var/crash/core.*

# Analyze with GDB
gdb /path/to/binary /path/to/core.file

# Get backtrace
(gdb) bt
(gdb) bt full
(gdb) thread apply all bt

# Get crash location
(gdb) info registers
(gdb) x/10i $pc
```

#### 4. **Extract Register Information**
```bash
# From core dump via GDB
(gdb) info registers

rax            0x0                 0
rbx            0x0                 0
rcx            0xffffffffffffffff  -1
rdx            0x0                 0
rsi            0x0                 0
rdi            0x0                 0
rbp            0x7ffffffde970      0x7ffffffde970
rsp            0x7ffffffde950      0x7ffffffde950
r8             0x0                 0
r9             0x0                 0
r10            0x0                 0
r11            0x246               582
r12            0x555555554c00      93824992235520
r13            0x0                 0
r14            0x0                 0
r15            0x0                 0
rip            0x55555555486d      0x55555555486d
...
```

### Example Complete Workflow

```bash
#!/bin/bash
# enable_cores_and_crash.sh

# Step 1: Enable core dumps
ulimit -c unlimited

# Step 2: Run vulnerable program
./test/crash_demo.out &
PID=$!

# Step 3: Wait for crash
sleep 2

# Step 4: Find core file
CORE_FILE=$(find /var/crash -name "core.*" -newer /tmp -type f | head -1)
if [ -z "$CORE_FILE" ]; then
    CORE_FILE=$(ls -t core.* 2>/dev/null | head -1)
fi

echo "Core file: $CORE_FILE"

# Step 5: Analyze with GDB (batch mode)
gdb -batch \
    -ex "file ./test/crash_demo.out" \
    -ex "core-file $CORE_FILE" \
    -ex "bt full" \
    -ex "info registers" \
    -ex "info threads" \
    > crash_analysis.txt

cat crash_analysis.txt
```

### Extracting Data from Core Dumps

```bash
# Extract memory map from core file
readelf -x .note.linuxcore $CORE_FILE  # Limited info

# Better: Use GDB to extract memory regions
gdb -batch \
    -ex "core-file core.file" \
    -ex "maintenance info sections" | grep -E "^\s+\[" > memory_layout.txt

# Dump specific memory region
gdb -batch \
    -ex "core-file core.file" \
    -ex "dump memory stack.bin 0x7fffffff0000 0x7ffffffff000"
```

### Advantages
- **Post-mortem analysis** - Analyze crash anytime after it happens  
- **Comprehensive snapshot** - All memory and registers captured  
- **Shareable** - Can send core file to another machine for analysis  
- **Archivable** - Keep historical crash data  
- **Parseable** - Can extract registers and memory maps programmatically  

### Disadvantages
- **Large file size** - Core dumps can be GBs in size  
- **No live interaction** - Can't inspect variables interactively  
- **Storage concerns** - Needs significant disk space  
- **Privacy/security** - Contains entire memory dump (sensitive data)  
- **Not real-time** - Only captures state at crash moment  

### Core Dump Size Optimization

```bash
# Compress core files automatically
sudo bash -c 'echo "|/bin/gzip -c > /var/crash/core.%e.%p.%h.%t.gz" > /proc/sys/kernel/core_pattern'

# Alternative: Manual compression
ulimit -c unlimited
./my_app
# After crash:
gzip core.* --fast
```

---

## Docker & Container Debugging

### Overview
Containers present unique debugging challenges due to isolation, ephemeral storage, and limited tooling. This section covers debugging containerized applications.

### Debugging Running Containers

**Attach to container process:**
```bash
# Get container ID and PID
CONTAINER_ID=$(docker ps | grep my_app | awk '{print $1}')
PID=$(docker inspect -f '{{.State.Pid}}' $CONTAINER_ID)

# Attach GDB to container process from host
sudo gdb -p $PID
(gdb) bt
(gdb) info threads
(gdb) continue
```

**Execute GDB inside container:**
```bash
# For containers with gdb installed
docker exec -it $CONTAINER_ID bash
root@container# gdb -p $(pgrep my_app)
(gdb) bt
(gdb) quit
exit
```

**Map debugger from host:**
```bash
# Mount host debugger into container
docker run -it \
  -v /usr/bin/gdb:/usr/bin/gdb:ro \
  -v /usr/lib/debug:/usr/lib/debug:ro \
  --cap-add=SYS_PTRACE \
  --security-opt="apparmor=unconfined" \
  my_image

# Inside container:
gdb -p $(pgrep my_app)
```

### Core Dumps in Containers

**Enable core dumps:**
```bash
# In Dockerfile
RUN ulimit -c unlimited

# Or in docker-compose.yml
services:
  my_app:
    ulimits:
      core: -1  # Unlimited

# Or via docker run
docker run --ulimit core=-1 my_image
```

**Extract core dump:**
```bash
# Core dumps typically write to / in container
docker exec $CONTAINER_ID ls -la / | grep core

# Copy to host
docker cp $CONTAINER_ID:/core /tmp/core.dump

# Analyze on host with correct binary
gdb /path/to/my_app /tmp/core.dump
```

### Container Image Analysis

**Extract debug symbols from image:**
```bash
# Create container without running
CONTAINER_ID=$(docker create my_image)

# Copy binary and debug symbols
docker cp $CONTAINER_ID:/usr/bin/my_app /tmp/my_app
docker cp $CONTAINER_ID:/usr/lib/debug /tmp/debug_symbols

# Analyze
gdb /tmp/my_app
(gdb) set debug-file-directory /tmp/debug_symbols
(gdb) file /tmp/my_app
```

**Inspect image layers:**
```bash
# Show all binary dependencies in image
docker history my_image --no-trunc
# Shows parent images and install commands

# List all files in image
docker run --rm my_image find / -type f -name "*.so*" | head -20
```

### Container-Specific Issues

**Issue: Signals not propagating**
```bash
# Problem: Container receives SIGTERM but app doesn't
# Solution: Use exec form in Dockerfile
# WRONG:
CMD ["sh", "-c", "my_app"]  # Shell PID 1, app in child

# RIGHT:
CMD ["my_app"]  # app is PID 1, gets signals directly
```

**Issue: /proc/pid/maps empty or unavailable**
```bash
# Problem: Cannot access /proc from host when container uses different PID namespace
# Solution: Use host PID namespace
docker run --pid=host my_image

# Or attach from host:
sudo cat /proc/$CONTAINER_PID/maps
```

**Issue: Timezone/locale crashes**
```bash
# Check container's TZ environment
docker exec $CONTAINER_ID date
docker exec $CONTAINER_ID locale

# Fix in Dockerfile
ENV TZ=UTC
RUN localedef -i en_US -f UTF-8 en_US.UTF-8
```

### Debugging with docker-compose

```yaml
version: '3'
services:
  my_app:
    image: my_image
    cap_add:
      - SYS_PTRACE
    security_opt:
      - "apparmor=unconfined"
    environment:
      - MALLOC_CHECK_=3  # Glibc malloc debugging
    ulimits:
      core: -1
    volumes:
      - ./debug_symbols:/usr/lib/debug:ro
      - ./gdb:/usr/bin/gdb:ro
```

### Registry/Image Debugging

```bash
# Pull layer filesystem without running
skopeo copy docker://my_image:latest dir:///tmp/my_image_dir

# Extract specific layer
cd /tmp/my_image_dir
tar -xf $(ls *.tar | head -1) -C /tmp/extracted_layer

# Inspect binaries
readelf -h /tmp/extracted_layer/usr/bin/my_app
ldd /tmp/extracted_layer/usr/bin/my_app
```

---

## Systemd & Journald Integration

### Overview
Systemd's journald daemon captures all logs and crash information. Integration with crash analysis provides system-wide context.

### Accessing Crash Data from journald

**View all crash logs:**
```bash
# Recent crashes
journalctl -x --priority=err
journalctl -u my_service | grep -E "crashed|SIGSEGV|SIGABRT"

# Full crash context
journalctl -u my_service -n 500 | tail -100
```

**Extract core dump info:**
```bash
# List available core dumps
coredumpctl list

# Dump details:
# TIME    PID USER GID SIG COREFILE
# Mon...  1234 user 1000 11 /var/lib/systemd/coredump/core.my_app.1234.gzip

# Extract specific crash
coredumpctl dump 1234 > /tmp/core.dump
gunzip /tmp/core.dump.gz

# Analyze
gdb /usr/bin/my_app /tmp/core.dump
```

**Real-time monitoring:**
```bash
# Follow crashes as they happen
journalctl -u my_service -f | grep -i "crash\|signal"

# Alert on specific signals
journalctl -u my_service -f | while read line; do
    if echo "$line" | grep -q "SIGSEGV"; then
        echo "ALERT: Segfault in my_service" | mail admin@example.com
    fi
done
```

### Systemd Service Crash Recovery

**Auto-restart on crash:**
```ini
# /etc/systemd/system/my_service.service
[Unit]
Description=My Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/my_app
Restart=on-failure
RestartSec=5
StartLimitInterval=600
StartLimitBurst=5  # Max 5 restarts in 10 minutes

StandardError=journal
StandardOutput=journal
```

**Capture crash dumps:**
```ini
[Service]
# Enable core dumps
LimitCORE=infinity
CoreDumpLocation=/var/lib/systemd/coredump

# Environment variables for debugging
Environment="MALLOC_CHECK_=3"
Environment="GLIBCXX_FORCE_NEW=1"  # C++ debugging
```

**Custom crash handlers:**
```bash
# /etc/systemd/system/crash-handler.service
[Unit]
Description=Crash Handler

[Service]
Type=oneshot
ExecStart=/usr/local/bin/handle_crash.sh

# Triggered by main service crash
Triggers=my_service.service
```

### Journald Log Parsing for Crashes

**Extract stack traces:**
```bash
# Save full journal for analysis
journalctl -u my_service > /tmp/service.log

# Parse stack traces
grep -A 50 "stack trace\|backtrace\|0x[0-9a-f]" /tmp/service.log

# Extract addresses for addr2line
grep -oE "0x[0-9a-f]+" /tmp/service.log | sort | uniq
```

**Memory analysis from journald:**
```bash
# Track memory growth
journalctl -u my_service | grep -i "rss\|memory" | tail -20

# Correlate with crashes
journalctl -u my_service | grep -B 20 "SIGSEGV" | grep -i "memory"
```

### Integration with Metrics

**Export crash events to monitoring:**
```bash
# Parse and forward to Prometheus
journalctl -u my_service -f | while read line; do
    if echo "$line" | grep -q "SIGSEGV"; then
        curl -X POST http://prometheus:9090/api/v1/labels \
             -d 'crash_event{service="my_service",signal="SIGSEGV"} 1'
    fi
done
```

**Structured logging for crash events:**
```c
// In your application
#include <systemd/sd-journal.h>

void crash_handler(int sig) {
    sd_journal_print(LOG_CRIT, 
        "Signal=%d PC=0x%lx SP=0x%lx",
        sig, pc_value, sp_value);
    sd_journal_send(
        "MESSAGE=Application crashed",
        "SIGNAL=%d", sig,
        "PRIORITY=%i", LOG_CRIT,
        NULL);
}
```

---

## Architecture-Specific Debugging

### Overview
Different CPU architectures have different register layouts, instruction sets, and calling conventions. This affects crash analysis significantly.

### x86-64 Architecture

**Register mapping:**
```
RAX: Accumulator (return values)
RBX: Base register (callee-saved)
RCX: Counter (function argument 4, Linux x86-64 ABI)
RDX: Data (function argument 3, syscall error flag)
RSI: Source index (function argument 2)
RDI: Destination index (function argument 1)
RBP: Base pointer (frame pointer, callee-saved)
RSP: Stack pointer (function argument 0 return address)

RIP: Instruction pointer (PC = Program Counter)
```

**Call convention (System V AMD64 ABI):**
```
Arguments: RDI, RSI, RDX, RCX, R8, R9, then stack
Return: RAX (first 8 bytes), RDX:RAX (16 bytes)
Callee-saved: RBX, RBP, R12-R15
Caller-saved: RAX, RCX, RDX, RSI, RDI, R8-R11
```

**Crash analysis example:**
```bash
$ gdb ./program core
(gdb) info registers
rax            0x0     0
rbx            0x555555554000  93824992059392
rcx            0xffffffff      -1
rdx            0x0     0
rsi            0x0     0
rdi            0x555555554abc  93824992060092
rbp            0x7ffffffde800  0x7ffffffde800  # FP points to frame
rsp            0x7ffffffde7f0  0x7ffffffde7f0  # SP near FP
r12            0x555555554000  93824992059392
r13            0x0     0
r14            0x0     0
r15            0x0     0
rip            0x555555554789  0x555555554789  # PC at crash
eflags         0x10206 [ PF IF RF ]

# Crash at address 0x555555554789
# Arguments were in RDI (0x555555554abc)
```

### ARM64 (AArch64) Architecture

**Register mapping:**
```
X0-X7:    Arguments and return values
X8:       Indirect result address
X9-X15:   Temporary registers (caller-saved)
X16-X17:  Intra-procedure-call registers
X18:      Platform register
X19-X28:  Callee-saved general purpose
X29:      Frame pointer (FP)
X30:      Link register (LR = return address)
SP:       Stack pointer
PC:       Program counter (read-only)
```

**Call convention (ARM64 ABI):**
```
Arguments: X0-X7 (float args in V0-V7)
Return: X0-X7
Callee-saved: X19-X28, SP, PC
Caller-saved: X0-X18, X30
```

**Crash analysis example:**
```bash
$ gdb ./program core
(gdb) info registers
x0             0x0     0
x1             0x0     0
x2             0x1000  4096
x29            0xfffffffff000  # FP at top of current frame
x30            0xaaaaaaaa1234  # LR (return address)
sp             0xfffffffde7f0  # SP
pc             0xaaaaaaaa5678  # PC at crash

# Crash in ARM64: look at LR for calling function
(gdb) x/i 0xaaaaaaaa1234
0xaaaaaaaa1234 <function_name+0x44>: mov x0, x19
```

**ARM64-specific GDB commands:**
```bash
# Show vector registers (NEON)
(gdb) info registers all
v0             {u8 = ...}
# Vector registers can hold float operations

# SVE (Scalable Vector Extension) registers
(gdb) p $z0
# SVE registers for vectorized code
```

### ARM32 (32-bit) Architecture

**Register mapping:**
```
R0-R3:     Arguments and scratch
R4-R11:    General purpose (some callee-saved)
R12:       Intra-procedure-call scratch
R13 (SP):  Stack pointer
R14 (LR):  Link register (return address)
R15 (PC):  Program counter
CPSR:      Current program status register
```

**Crash analysis:**
```bash
$ gdb ./program core
(gdb) info registers
r0             0x0     0
r1             0x1000  4096
r14            0x40001234      # LR (return address)
r15            0x40005678      # PC (crash location)
cpsr           0x60000010      # Status register

# Thumb mode detection (T bit in CPSR)
(gdb) p/x $cpsr & 0x20
$1 = 0x20    # Thumb mode enabled
```

### RISC-V Architecture

**Register mapping:**
```
X0:        Zero register
X1:        Return address (RA)
X2:        Stack pointer (SP)
X3-X4:     Global pointer, thread pointer
X5-X7:     Temporary
X8-X9:     Saved temporary
X10-X17:   Arguments and return values
X18-X27:   Saved general purpose
X28-X31:   Temporary
```

**RISC-V debugging:**
```bash
# GDB with RISC-V target
(gdb) set architecture riscv:rv64i
(gdb) target remote :3333  # GDB Server port
(gdb) info registers
```

### Cross-Architecture Comparison

| Arch | PC Reg | SP Reg | FP Reg | Arg Count | Callee-Saved |
|------|--------|--------|--------|-----------|--------------|
| x86-64 | RIP | RSP | RBP | 6 (regs) | 5 |
| ARM64 | PC | SP | X29 | 8 (regs) | 10 |
| ARM32 | R15 | R13 | R11 | 4 (regs) | 8 |
| RISC-V | PC | X2 | X8 | 8 (regs) | 12 |
| PPC64 | NIP | R1 | R31 | 8 (regs) | 18 |

---

## Remote Debugging & GDB Server

### Overview
Remote debugging allows analyzing crashes on embedded systems, headless servers, or specialized hardware without direct access.

### GDB Server Setup

**Start gdbserver on target:**
```bash
# Attach to running process
gdbserver localhost:3333 --attach $(pgrep my_app)

# Or start program with gdbserver
gdbserver localhost:3333 /usr/bin/my_app arg1 arg2

# Multi-threaded support
gdbserver --multi localhost:3333
```

**Connect from host:**
```bash
$ gdb /path/to/binary
(gdb) target remote target_ip:3333
(gdb) bt
(gdb) continue
(gdb) disconnect
```

### SSH Tunneling for Remote GDB

**Over encrypted SSH tunnel:**
```bash
# Open tunnel on local machine
ssh -L 3333:localhost:3333 user@target_host

# In separate terminal, connect GDB
gdb
(gdb) target remote localhost:3333
(gdb) bt
```

**Two-way tunnel setup:**
```bash
# Terminal 1: SSH tunnel and start gdbserver
ssh -L 3333:localhost:3333 -R 9999:localhost:9999 user@target
# On target: gdbserver localhost:3333 /usr/bin/my_app

# Terminal 2: Connect local GDB
gdb /path/to/binary
(gdb) target remote localhost:3333
```

### Core Dump Analysis Over Network

**Transfer core dump to analysis machine:**
```bash
# From target (embedded system)
scp core.dump user@analysis_machine:/tmp/core.dump

# On analysis machine
gdb /path/to/binary /tmp/core.dump
(gdb) bt
(gdb) info locals
```

**Stream core dump over SSH:**
```bash
# Pipe directly without disk
ssh user@target_host "cat core.dump" > /tmp/remote_core

# Or use gdb remote protocol
gdb /path/to/binary
(gdb) target remote | ssh user@target gdbserver - /proc/$PID/exe
```

### Network Debugging Best Practices

**Bandwidth optimization:**
```bash
# Only download necessary symbols
gdb -symbols /minimal_symbols/my_app -core /tmp/core.dump

# Or build separate minimal binary for symbols
strip --keep-file-symbols my_app -o my_app.min
scp user@target:my_app.min .
```

**Security considerations:**
```bash
# Use key-based authentication
gdb
(gdb) target remote remote_user@secure.target.com:3333

# Encrypt traffic over SSH
ssh -L 3333:127.0.0.1:3333 user@target_host

# Firewall only gdbserver port to specific IPs
sudo ufw allow from analysis_machine to any port 3333
```

### Automated Remote Crash Collection

```bash
#!/bin/bash
# Remote crash collector script

TARGET_HOST="embedded.device.local"
TARGET_USER="root"
ANALYSIS_DIR="/tmp/crash_analysis"

# Check for new crashes
ssh $TARGET_USER@$TARGET_HOST "find /var/crash -mmin -5 -name 'core.*'" | while read core_file; do
    echo "New crash detected: $core_file"
    
    # Transfer core dump
    scp $TARGET_USER@$TARGET_HOST:$core_file $ANALYSIS_DIR/
    
    # Get process info
    ssh $TARGET_USER@$TARGET_HOST "ps aux | grep $(basename $core_file)" > $ANALYSIS_DIR/ps.log
    
    # Collect stack trace
    gdb -batch \
        -ex "file /usr/bin/my_app" \
        -ex "core-file $ANALYSIS_DIR/$(basename $core_file)" \
        -ex "thread apply all bt" \
        > $ANALYSIS_DIR/backtrace.txt
    
    echo "Analysis saved to $ANALYSIS_DIR"
done
```

---

## Language-Specific Crash Analysis

### Overview
Different programming languages have different runtime environments, which affects crash analysis techniques.

### C/C++ Crash Analysis

**C++ specific issues (name mangling):**
```bash
# Mangled names appear in crash dumps
# Example: _ZN5MyLib8MyClass8methodEPKc

# Use addr2line with -C flag (demangle)
addr2line -e binary 0x1234 -C -f
# Output: MyLib::MyClass::method(char const*)

# Or use c++filt
echo "_ZN5MyLib8MyClass8methodEPKc" | c++filt
# Output: MyLib::MyClass::method(char const*)
```

**STL container crashes:**
```bash
# Common: std::vector iterator invalidation
# Crash: *vector_iterator = value (where vector was resized)

# Detect in GDB
(gdb) frame 2
#2 0x555555554a7c in std::vector<int>::operator[] ()
    at /usr/include/c++/11/bits/stl_vector.h:1234

# STL debugging mode (slow but comprehensive)
g++ -D_GLIBCXX_DEBUG -g program.cpp -o program_debug
```

**Exception stack traces:**
```bash
# Compile with exception info
g++ -g -rdynamic program.cpp -o program
# -rdynamic exports all symbols for backtraces

# GDB catch exceptions
(gdb) catch throw
Breakpoint 1 at ...
(gdb) continue
# Breakpoint 1, __cxa_throw () at ...
(gdb) bt
```

### Python Crash Analysis

**Segfault in Python C extension:**
```bash
# Python error indicates C extension crash
# Example: Segmentation fault (core dumped)

# Debug Python interpreter
gdb python
(gdb) run /path/to/script.py
(gdb) bt
# Will show Python frames + C frames mixed

# With Python debugging symbols
# Debian: apt install python3-dbg
gdb python3-dbg
```

**Python-specific info:**
```bash
(gdb) py-list          # Show Python source
(gdb) py-bt            # Python-aware backtrace
(gdb) py-print locals  # Local variables in Python scope
(gdb) py-locals        # Detailed Python locals
```

### Go Crash Analysis

**Go runtime crashes:**
```bash
# Go embeds stack traces in panic output
# Example: "fatal error: unexpected signal during runtime execution"

# Analyze Go stack traces
go tool pprof -http=:8080 cpu.prof

# Runtime crashes
# Compile with debug info
go build -gcflags="-N -l" -ldflags="-s=false"

# GDB debugging Go
gdb ./binary
(gdb) runtime-evaluate   # Go runtime inspection
(gdb) goroutine 1 bt     # Backtrace specific goroutine
```

**Goroutine deadlock detection:**
```bash
# Go's deadlock detection
fatal error: all goroutines are asleep - deadlock!

# Analyze with pprof
go tool trace trace.out  # Shows goroutine blocking events
```

### Rust Crash Analysis

**Rust panic stack trace:**
```bash
# Rust panics include stack traces
thread 'main' panicked at 'index out of bounds',
src/main.rs:42:5
stack backtrace:
   0: rust_backtrace::trace
             at src/trace.rs:123
   1: main
             at src/main.rs:42
```

**Debug Rust binaries:**
```bash
# Compile with debug info
cargo build  # Includes debug symbols

# Crash analysis
gdb ./target/debug/program
(gdb) bt
(gdb) frame 1
#1 0x555555554a7c in program::main () at src/main.rs:42
```

**Memory safety features:**
```bash
# Rust catches many memory errors at runtime
# AddressSanitizer for additional checks
RUSTFLAGS="-Z sanitizer=address" cargo +nightly build

# Thread Sanitizer
RUSTFLAGS="-Z sanitizer=thread" cargo +nightly build
```

### Java/JVM Crash Analysis

**JVM crash log (hs_err_pid*.log):**
```
#
# A fatal error has been detected by the Java Runtime Environment:
#
#  SIGSEGV (0xb) at pc=0x00007f1234567890, pid=1234, tid=0x7f12

# Stack: [0x7f100000, 0x7f200000], sp=0x7f199990, free space=1020k
# Native frames: (J=compiled Java code, j=interpreted, Vv=VM code, C=native code)
```

**Analyze in GDB:**
```bash
# Get binary path from hs_err file
gdb /path/to/java
(gdb) symbol-file libjvm.so
(gdb) target remote :3333  # If using gdbserver
```

### Summary Table

| Language | Crash Format | Analysis Tool | Key Feature |
|----------|--------------|---------------|-------------|
| C/C++ | SIGSEGV | gdb, valgrind | Name mangling, STL debug |
| Python | Python trace + core | gdb py-\* | Python frame awareness |
| Go | Panic output | pprof, trace | Goroutine context |
| Rust | Panic + backtrace | cargo, gdb | Memory safety checks |
| Java | hs_err_pid.log | jdb, crash dump analyzer | JIT info, GC state |

---

## Automated Crash Reporting Systems

### Overview
Production systems need automated crash detection, collection, and reporting for quick response.

### systemd-based Crash Reporting

**Systemd coredumpctl integration:**
```bash
#!/bin/bash
# Automated crash reporter

CRASH_DIR="/var/lib/systemd/coredump"
NOTIFY_EMAIL="ops@example.com"

# Monitor for new crashes
inotifywait -m -e create $CRASH_DIR | while read path event filename; do
    echo "New crash: $filename"
    
    # Extract info
    coredumpctl dump $filename > /tmp/crash.dump 2>&1
    
    # Generate report
    {
        echo "=== CRASH REPORT ==="
        echo "File: $filename"
        echo "Time: $(date)"
        echo ""
        echo "=== BACKTRACE ==="
        gdb -batch -ex "core-file /tmp/crash.dump" \
                   -ex "thread apply all bt" 2>/dev/null
    } | tee /tmp/crash_report.txt
    
    # Send notification
    mail -s "CRASH: $filename" $NOTIFY_EMAIL < /tmp/crash_report.txt
done
```

### Signal Handler Crash Logging

```c
#include <signal.h>
#include <execinfo.h>
#include <stdio.h>

#define BACKTRACE_SIZE 128

void crash_handler(int sig) {
    fprintf(stderr, "=== CRASH ===\n");
    fprintf(stderr, "Signal: %d\n", sig);
    fprintf(stderr, "PID: %d\n", getpid());
    fprintf(stderr, "Time: %s\n", ctime(&now));
    
    void *addrlist[BACKTRACE_SIZE];
    int addrlen = backtrace(addrlist, BACKTRACE_SIZE);
    
    fprintf(stderr, "Backtrace:\n");
    backtrace_symbols_fd(addrlist, addrlen, STDERR_FILENO);
    
    // Save to file for later analysis
    FILE *f = fopen("/var/crash/crash.log", "a");
    fprintf(f, "[CRASH] %s signal=%d addrlen=%d\n",
            ctime(&now), sig, addrlen);
    fclose(f);
    
    // Let systemd handle core dump
    signal(sig, SIG_DFL);
    raise(sig);
}
```

### Remote Crash Aggregation

**Central crash collector:**
```bash
#!/bin/bash
# Runs on central monitoring server

CRASH_DB="/var/lib/crash_reports/database"
mkdir -p $CRASH_DB

# Listen for crash reports from agents
nc -l -p 9999 | while read report; do
    HASH=$(echo "$report" | md5sum | cut -d' ' -f1)
    echo "$report" > "$CRASH_DB/$HASH.txt"
    
    # If same crash repeated
    if [ -f "$CRASH_DB/$HASH.count" ]; then
        COUNT=$(($(cat $CRASH_DB/$HASH.count) + 1))
    else
        COUNT=1
    fi
    echo $COUNT > "$CRASH_DB/$HASH.count"
    
    # Alert if repeated crashes
    if [ $COUNT -gt 5 ]; then
        echo "CRITICAL: Crash repeated $COUNT times" | \
            mail -s "CRASH SPIKE" ops@example.com
    fi
done
```

**Agent crash reporter:**
```bash
#!/bin/bash
# Runs on each monitored system

CENTRAL_SERVER="monitoring.example.com"
CENTRAL_PORT="9999"

# Watch for crashes
coredumpctl list -F | while read; do
    # Collect crash data
    REPORT=$(coredumpctl dump | head -50)
    
    # Send to central server
    echo "$REPORT" | nc -w 5 $CENTRAL_SERVER $CENTRAL_PORT
done
```

### Crash Analytics Dashboard

```python
#!/usr/bin/env python3
# Crash analytics processor

import json
import os
from collections import defaultdict

crash_dir = "/var/lib/crash_reports/database"
stats = defaultdict(int)

for crash_file in os.listdir(crash_dir):
    if crash_file.endswith(".txt"):
        with open(os.path.join(crash_dir, crash_file)) as f:
            content = f.read()
            
            # Extract signal type
            if "SIGSEGV" in content:
                stats["SIGSEGV"] += 1
            elif "SIGABRT" in content:
                stats["SIGABRT"] += 1
            elif "SIGFPE" in content:
                stats["SIGFPE"] += 1
                
            # Extract function name
            for line in content.split('\n'):
                if "0x" in line and "in " in line:
                    func = line.split("in ")[-1]
                    stats[f"func_{func}"] += 1

# Output JSON for dashboard
print(json.dumps(stats, indent=2))
```

---

## Performance Profiling Comparison

### Overview
Different profiling tools provide complementary data. Understanding when to use each is critical.

### Tool Comparison Matrix

| Tool | Overhead | Setup | Precision | Best For |
|------|----------|-------|-----------|----------|
| perf | ~1-2% | Simple | Instruction-level | CPU bottlenecks |
| Valgrind | ~10-50x | Simple | Memory-operation level | Memory leaks |
| gperftools | ~1-5% | Instrumentation | Function-level | Malloc profiling |
| eBPF/perf | <1% | Complex kernel | Kernel event level | System call analysis |
| GDB | Indefinite | Breakpoints | Line-level | Interactive debugging |

### Perf vs Valgrind

**When to use perf:**
```bash
# CPU profiling - see where time is spent
perf record -F 99 -g ./my_app
perf report  # Shows top functions by CPU %

# Best for: optimization, bottleneck finding
# Overhead: ~1-2%, safe for production
```

**When to use Valgrind:**
```bash
# Memory profiling - detect leaks and errors
valgrind --leak-check=full ./my_app

# Best for: correctness, memory errors
# Overhead: ~10-50x slower, only for testing
```

**Example scenario:**
```
1. User reports: "App is slow"
   → Use perf: Identify CPU hotspot (1% overhead)
   
2. User reports: "Memory grows over time"
   → Use Valgrind: Find leak (10x overhead, but finds the bug)
   
3. User reports: "Intermittent crashes"
   → Use GDB: Set breakpoints near crash (100% overhead, but you control it)
```

### Specialized Tool Selection

**For I/O bottlenecks:**
```bash
# iotop - I/O by process
iotop -o  # Only processes with I/O

# perf with block I/O events
perf record -e block:block_rq_issue,block:block_rq_complete ./my_app
perf report

# Alternative: latency tracing
echo 1 > /proc/sys/kernel/latency_trace
trace-cmd record -e sched,syscalls ./my_app
```

**For lock contention:**
```bash
# perf with lock events
perf record -e contention:contention_begin ./my_app
perf report

# Or futex tracing
strace -e futex ./my_app 2>&1 | grep WAIT

# LockStat (requires CONFIG_LOCK_STAT)
cat /proc/lock_stat
```

**For cache misses:**
```bash
# perf with cache events
perf record -e cache-references,cache-misses ./my_app
perf report

# Shows miss rate:
# 1% miss rate: good
# 5% miss rate: acceptable
# >10% miss rate: investigate
```

### Profiling Workflow

```
1. High-Level Analysis (Perf)
   perf stat ./my_app  # Shows CPU time, cache misses, branch mispredicts
   → Identifies bottleneck class

2. Detailed Analysis (Perf Record + Report)
   perf record -g ./my_app
   perf report
   → Shows which functions in that class

3. Source-Level Analysis (Perf Annotate)
   perf annotate function_name
   → Shows exact source lines

4. Memory Verification (Valgrind)
   valgrind --leak-check=full ./my_app
   → Confirms no leaks in optimized code
```

### Production Profiling Best Practices

```bash
#!/bin/bash
# Safe production profiling script

APP="my_service"
DURATION=60
SAMPLE_FREQ=99  # Hz

# 1. Capture with minimal overhead
perf record -F $SAMPLE_FREQ -g \
    --output=/tmp/perf_prod.data \
    -p $(pgrep $APP) \
    sleep $DURATION

# 2. Analyze locally
perf report --input=/tmp/perf_prod.data

# 3. Generate flame graph
perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg

# 4. Clean up
rm /tmp/perf_prod.data
```

---

## Advanced Troubleshooting Scenarios

### Overview
Complex real-world scenarios often require combining multiple techniques and tools.

### Scenario 1: Intermittent Crash (Heisenbug)

**Problem: Crashes randomly, hard to reproduce**

```bash
# Step 1: Enable core dumps for all crashes
ulimit -c unlimited

# Step 2: Run under stress to trigger
stress-ng --cpu 4 --vm 2 --timeout 3600 &
/usr/bin/my_app

# Step 3: Collect all core dumps
ls -ltr core.* | tail -5

# Step 4: Analyze multiple dumps for pattern
for f in core.*; do
    gdb -batch -ex "core-file $f" -ex "thread apply all bt" \
        /usr/bin/my_app | grep -E "^#0|^#1|^#2" >> /tmp/patterns.txt
done

# Step 5: Correlate with system events
dmesg | tail -100 | grep -E "ERROR|OOM"
```

**Using conditional breakpoints (GDB):**
```bash
# Set breakpoint that only triggers under certain conditions
gdb ./my_app
(gdb) break malloc_function
(gdb) commands
> silent
> if (size > 1000000)
>   printf "Large allocation: %d bytes\n", size
> end
> continue
> end

(gdb) run
# Runs until condition met or crash
```

### Scenario 2: Performance Regression

**Problem: App was fast yesterday, slow today**

```bash
# Step 1: Baseline measurement
perf stat ./my_app  # Record metrics

# Step 2: Compare with git history
git log --oneline -10
git diff HEAD~5 -- performance_critical.c

# Step 3: Bisect to find breaking commit
git bisect start
git bisect bad HEAD
git bisect good HEAD~10
# Test each version...

# Step 4: Profile before/after
perf record -g --output=before.data (previous commit)
perf record -g --output=after.data (current commit)
perf diff before.data after.data
```

### Scenario 3: Memory Leak in Production

**Problem: Memory grows but can't use Valgrind (10x overhead)**

```bash
# Step 1: Monitor real memory growth
watch -n 10 'ps aux | grep my_app | grep -v grep'

# Step 2: Profile heap (low overhead)
gperftools-malloc ./my_app
# Sets HEAPPROFILE environment variable

# Step 3: Analyze heap snapshots
pprof /usr/bin/my_app profile.0001.heap  # First snapshot
pprof /usr/bin/my_app profile.0100.heap  # Later snapshot
pprof --base=profile.0001.heap profile.0100.heap

# Step 4: Focus on leaking functions
# pprof will show which functions allocated memory
# that wasn't freed
```

### Scenario 4: System-Wide Performance Issue

**Problem: Service slow due to system load**

```bash
# Step 1: Full system profiling
perf record -F 99 -a -g  # All CPUs
sleep 60
perf report

# Step 2: Identify non-application processes
perf report | grep -v my_app

# Step 3: Check kernel events
perf record -e syscalls:* -a
perf report | grep syscalls

# Step 4: Check CPU cache hierarchy
perf stat -e cache-references,cache-misses,\
LLC-loads,LLC-load-misses,LLC-stores,LLC-prefetches \
./my_app

# Step 5: Check NUMA effects (if applicable)
numastat -p $(pgrep my_app)
```

### Scenario 5: Crash in Third-Party Library

**Problem: Crash in libc, but our code looks fine**

```bash
# Step 1: Verify it's actually the library's fault
gdb -batch -ex "core-file core.dump" \
    -ex "frame 0" -ex "info line" /usr/bin/my_app
# Shows exact address in libc

# Step 2: Check library version
ldd /usr/bin/my_app | grep libc
file /lib64/libc.so.6  # Check version

# Step 3: Report with minimal reproduction
# Create test that only uses that library function

# Step 4: Workaround if library bug confirmed
# Use LD_PRELOAD to intercept and wrap the function:
#   - Add safety checks
#   - Avoid triggering condition
#   - Or upgrade library
```

### Scenario 6: Multi-threaded Deadlock

**Problem: Application hangs**

```bash
# Step 1: Attach GDB to running process
gdb -p $(pgrep my_app)

# Step 2: Get all thread backtraces
(gdb) thread apply all bt

# Step 3: Identify waiting threads
# Look for pthread_mutex_lock, pthread_cond_wait

# Step 4: Find lock holders
(gdb) print all_locks  # If available in source
# Or manually check: grep mutex_lock in bt output

# Step 5: Analyze circular dependency
Thread 1: waiting on lock_A (held by Thread 2)
Thread 2: waiting on lock_B (held by Thread 1)
# Classic deadlock!

# Step 6: Force unlock for recovery (if needed)
(gdb) call pthread_mutex_unlock(&lock_a)
(gdb) continue
```

---

### Conclusion Update

The complete stack dump analysis guide now covers:

1. **Immediate Access** (Quick Start + Cheat Sheet): Answer in 5 minutes
2. **Deep Dive** (5 Methods): Comprehensive technique coverage  
3. **Expert Patterns** (Debug Symbols, Deadlocks, Leaks, Crashes, Flame Graphs): Advanced diagnosis
4. **Real-World Scenarios** (Docker, Systemd, Architecture, Remote, Languages, Automation, Profiling, Troubleshooting): Production-ready solutions

---

## Compiler Sanitizers (ASan, TSan, MSan, UBSan)

### Overview
**Sanitizers** are compiler instrumentation tools that detect bugs at runtime by inserting checks into code. They catch crashes BEFORE they happen in production by detecting undefined behavior, race conditions, and memory errors during development and testing.

### Why Sanitizers Matter
- **Prevention**: Find bugs during development instead of production
- **Precision**: Pinpoint exact source line causing issue
- **Zero-code-change**: Just recompile with flags
- **CI/CD Integration**: Automated bug detection in pipelines

### AddressSanitizer (ASan)

**Detects:**
- Buffer overflows (stack and heap)
- Use-after-free
- Use-after-return
- Use-after-scope
- Double-free
- Memory leaks

**Compile with ASan:**
```bash
# GCC or Clang
gcc -fsanitize=address -g -O1 program.c -o program_asan
clang -fsanitize=address -g -O1 program.c -o program_asan

# Run instrumented binary
./program_asan
```

**Example Output:**
```
=================================================================
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000eff0
READ of size 4 at 0x60300000eff0 thread T0
    #0 0x555555554a7c in process_data main.c:45
    #1 0x555555554a90 in main main.c:50
    #2 0x7ffff7a03bf6 in __libc_start_main

0x60300000eff0 is located 0 bytes inside of 1024-byte region [0x60300000eff0,0x60300000f3f0)
freed by thread T0 here:
    #0 0x7ffff7a91f50 in free
    #1 0x555555554a10 in cleanup main.c:30

previously allocated by thread T0 here:
    #0 0x7ffff7a92050 in malloc
    #1 0x555555554980 in allocate_buffer main.c:20
```

**Interpreting ASan Reports:**
1. Error type: "heap-use-after-free"
2. Access location: "main.c:45"
3. Freed at: "main.c:30"
4. Allocated at: "main.c:20"

**ASan Options:**
```bash
# Detailed reports
ASAN_OPTIONS=verbosity=1:log_path=asan.log ./program_asan

# Detect leaks at exit
ASAN_OPTIONS=detect_leaks=1 ./program_asan

# Abort on first error
ASAN_OPTIONS=abort_on_error=1 ./program_asan

# Check initialization order
ASAN_OPTIONS=check_initialization_order=1 ./program_asan
```

### ThreadSanitizer (TSan)

**Detects:**
- Data races
- Deadlocks (some cases)
- Thread leaks
- Unprotected shared variable access

**Compile with TSan:**
```bash
gcc -fsanitize=thread -g -O1 program.c -o program_tsan
clang -fsanitize=thread -g -O1 program.c -o program_tsan

# Run
./program_tsan
```

**Example Output:**
```
==================
WARNING: ThreadSanitizer: data race (pid=12345)
  Write of size 4 at 0x7ffff7fff000 by thread T2:
    #0 writer_thread main.c:30
    #1 pthread_start ...

  Previous write of size 4 at 0x7ffff7fff000 by thread T1:
    #0 writer_thread main.c:30
    #1 pthread_start ...

  Location is global 'shared_counter' of size 4 at 0x7ffff7fff000 (main+0x000000000000)

  Thread T2 (tid=12347, running) created by main thread at:
    #0 pthread_create ...
    #1 main main.c:50

  Thread T1 (tid=12346, finished) created by main thread at:
    #0 pthread_create ...
    #1 main main.c:49

SUMMARY: ThreadSanitizer: data race main.c:30 in writer_thread
==================
```

**Common Race Patterns Detected:**
```c
// Pattern 1: Unprotected shared variable
int shared_counter = 0;  // RACE!

void* thread_func(void* arg) {
    shared_counter++;  // Multiple threads increment without lock
    return NULL;
}

// Fix: Add mutex
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
void* thread_func_fixed(void* arg) {
    pthread_mutex_lock(&mutex);
    shared_counter++;
    pthread_mutex_unlock(&mutex);
    return NULL;
}
```

**TSan Options:**
```bash
# Suppress known races
TSAN_OPTIONS=suppressions=tsan.supp ./program_tsan

# Example tsan.supp:
# race:known_racy_function
# race:^third_party_lib.*

# Log to file
TSAN_OPTIONS=log_path=tsan.log ./program_tsan

# Second deadlock detection
TSAN_OPTIONS=second_deadlock_stack=1 ./program_tsan
```

### MemorySanitizer (MSan)

**Detects:**
- Uninitialized memory reads
- Use of undefined values

**Compile with MSan:**
```bash
clang -fsanitize=memory -g -O1 program.c -o program_msan

# Run
./program_msan
```

**Example Output:**
```
==12345==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x555555554a7c in process main.c:40
    #1 0x555555554a90 in main main.c:50

  Uninitialized value was created by an allocation of 'buffer' in the stack frame
    #0 0x555555554980 in main main.c:45

SUMMARY: MemorySanitizer: use-of-uninitialized-value main.c:40 in process
```

**Common MSan Findings:**
```c
int main() {
    int value;  // Uninitialized
    
    if (value > 10) {  // MSan ERROR: reading uninitialized 'value'
        printf("Large\n");
    }
    
    // Fix:
    int value_fixed = 0;  // Initialize
    if (value_fixed > 10) {
        printf("Large\n");
    }
}
```

### UndefinedBehaviorSanitizer (UBSan)

**Detects:**
- Signed integer overflow
- Division by zero
- Null pointer dereference
- Array bounds overflow
- Misaligned pointers
- Invalid type casts

**Compile with UBSan:**
```bash
gcc -fsanitize=undefined -g program.c -o program_ubsan
clang -fsanitize=undefined -g program.c -o program_ubsan

# Run
./program_ubsan
```

**Example Output:**
```
main.c:25:10: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
main.c:30:5: runtime error: division by zero
main.c:35:10: runtime error: load of misaligned address 0x7ffff7fff003 for type 'int', which requires 4 byte alignment
```

**UBSan Sub-sanitizers:**
```bash
# Specific checks
-fsanitize=shift           # Shift errors
-fsanitize=integer-divide-by-zero
-fsanitize=null
-fsanitize=bounds          # Array bounds
-fsanitize=alignment
-fsanitize=float-divide-by-zero

# All undefined behavior checks
-fsanitize=undefined
```

### Sanitizer Comparison

| Sanitizer | Overhead | Platform | Detects | Best For |
|-----------|----------|----------|---------|----------|
| ASan | ~2x slowdown | Linux, macOS | Memory errors | Development, CI |
| TSan | ~5-15x slowdown | Linux, macOS | Data races | Multi-threaded code |
| MSan | ~3x slowdown | Linux only | Uninitialized reads | Memory correctness |
| UBSan | ~1.2x slowdown | All | Undefined behavior | All projects |

### CI/CD Integration

**GitHub Actions Example:**
```yaml
name: Sanitizer CI
on: [push, pull_request]
jobs:
  asan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build with ASan
        run: |
          gcc -fsanitize=address -g program.c -o program_asan
      - name: Run tests
        run: ./program_asan
        env:
          ASAN_OPTIONS: log_path=asan.log:abort_on_error=1
      - name: Upload logs
        if: failure()
        uses: actions/upload-artifact@v2
        with:
          name: asan-logs
          path: asan.log*
```

**Jenkins Pipeline:**
```groovy
pipeline {
    agent any
    stages {
        stage('Sanitizer Build') {
            parallel {
                stage('ASan') {
                    steps {
                        sh 'gcc -fsanitize=address program.c -o program_asan'
                        sh 'ASAN_OPTIONS=log_path=asan.log ./program_asan'
                    }
                }
                stage('TSan') {
                    steps {
                        sh 'gcc -fsanitize=thread program.c -o program_tsan'
                        sh 'TSAN_OPTIONS=log_path=tsan.log ./program_tsan'
                    }
                }
            }
        }
    }
}
```

### Best Practices

1. **Use in Development**: Run with sanitizers locally before committing
2. **Separate Builds**: Don't combine sanitizers (use one at a time)
3. **CI Integration**: Run ASan/UBSan on every commit, TSan nightly
4. **Fix Immediately**: Don't ignore sanitizer warnings
5. **Suppress Carefully**: Only suppress known false positives

---

## Kernel-Level Tracing (eBPF, kprobes, uprobes)

### Overview
Kernel-level tracing allows inspection of system behavior without modifying or recompiling code. These tools trace kernel functions (kprobes), user-space functions (uprobes), and custom programs (eBPF) for real-time production debugging.

### Why Kernel Tracing Matters
- **Zero Overhead When Off**: No instrumentation until activated
- **Production Safe**: Non-invasive, can trace live systems
- **Complete Visibility**: See kernel + userspace interactions
- **Performance Analysis**: Identify bottlenecks at system boundary

### kprobes (Kernel Probes)

**What kprobes Do:**
- Dynamically insert probes into kernel functions
- Trace kernel execution paths
- Capture function arguments and return values
- No kernel recompilation needed

**Enable kprobes:**
```bash
# Check if kprobes available
grep CONFIG_KPROBES /boot/config-$(uname -r)
# Should show: CONFIG_KPROBES=y

# List available kernel functions
cat /proc/kallsyms | grep " T " | head -20
```

**Using kprobes with ftrace:**
```bash
# Navigate to trace directory
cd /sys/kernel/debug/tracing

# List available events
cat available_filter_functions | grep do_sys_open

# Enable kprobe on do_sys_open (file open syscall)
echo 'p:myprobe do_sys_open filename=+0(%si):string' > kprobe_events

# Enable tracing
echo 1 > events/kprobes/myprobe/enable

# Trigger activity (open files)
ls /tmp

# Read trace
cat trace
# Output:
# ls-12345 [000] .... 12345.678: myprobe: (do_sys_open+0x0/0x200) filename="/tmp"
# ls-12345 [000] .... 12345.679: myprobe: (do_sys_open+0x0/0x200) filename="/tmp/file.txt"

# Disable
echo 0 > events/kprobes/myprobe/enable
echo > kprobe_events
```

**kprobe Syntax:**
```bash
# Probe at function entry
echo 'p:probe_name function_name arg1=%di arg2=%si' > kprobe_events

# Probe at function return
echo 'r:probe_name function_name retval=$retval' > kprobe_events

# Probe at offset within function
echo 'p:probe_name function_name+0x10' > kprobe_events

# x86-64 register arguments:
# %di = 1st arg (rdi)
# %si = 2nd arg (rsi)
# %dx = 3rd arg (rdx)
# %cx = 4th arg (rcx)
# $retval = return value
```

### uprobes (User-Space Probes)

**What uprobes Do:**
- Dynamically insert probes into user-space functions
- Trace application execution without recompilation
- Capture function calls and returns

**Using uprobes:**
```bash
cd /sys/kernel/debug/tracing

# Probe malloc in libc
echo 'p:malloc_probe /lib/x86_64-linux-gnu/libc.so.6:malloc size=%di:u64' > uprobe_events

# Enable
echo 1 > events/uprobes/malloc_probe/enable

# Run program
./my_app

# Check trace
cat trace
# Output shows all malloc calls with sizes:
# my_app-12345 [001] .... 12345.678: malloc_probe: (0x7f1234567890) size=1024
# my_app-12345 [001] .... 12345.679: malloc_probe: (0x7f1234567890) size=4096

# Disable
echo 0 > events/uprobes/malloc_probe/enable
echo > uprobe_events
```

**Probe Custom Application Functions:**
```bash
# Find function address in your binary
nm -D /path/to/my_app | grep my_function
# Output: 0000000000001234 T my_function

# Or use objdump
objdump -t /path/to/my_app | grep my_function

# Create uprobe
echo 'p:my_probe /path/to/my_app:0x1234' > uprobe_events

# Enable and trace
echo 1 > events/uprobes/my_probe/enable
cat trace
```

### eBPF (Extended Berkeley Packet Filter)

**What eBPF Is:**
- Programmable kernel-level execution engine
- Write C-like programs that run in kernel space
- Safely attach to kernel events, functions, and tracepoints
- Most powerful tracing tool available

**eBPF Architecture:**
```
User Space:           [eBPF Program (C)] → [Compiler (clang)] → [BPF bytecode]
                                                                      ↓
Kernel Space:         [BPF Verifier] → [JIT Compiler] → [Execution]
                                                              ↓
                      [Maps: Data exchange between kernel & user]
```

**Simple eBPF Program (using bpftrace):**
```bash
# Install bpftrace
sudo apt install bpftrace  # Ubuntu
sudo dnf install bpftrace  # Fedora

# Trace open() syscalls
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_open { printf("%s opened %s\n", comm, str(args->filename)); }'

# Output:
# ls opened /etc/ld.so.cache
# cat opened /home/user/file.txt
```

**Count Function Calls:**
```bash
# Count calls to malloc
sudo bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc { @calls = count(); }'

# After Ctrl+C, shows:
# @calls: 15234
```

**Measure Function Latency:**
```bash
# Measure read() syscall latency
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_read {
    @start[tid] = nsecs;
}
tracepoint:syscalls:sys_exit_read /@start[tid]/ {
    @latency_us = hist((nsecs - @start[tid]) / 1000);
    delete(@start[tid]);
}'

# Output: Histogram of read() latencies in microseconds
# @latency_us:
# [0]                  123 |@@@@@@@@                                        |
# [1]                  456 |@@@@@@@@@@@@@@@@@@@@@@@@                        |
# [2, 4)               789 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
```

**Advanced eBPF (using BCC toolkit):**
```bash
# Install BCC
sudo apt install bpfcc-tools  # Ubuntu

# Trace which processes are calling sync()
sudo /usr/share/bcc/tools/trace 'sys_sync "%s called sync", comm'

# Profile CPU usage by function
sudo /usr/share/bcc/tools/profile -F 99 -f 30

# Trace all file opens
sudo /usr/share/bcc/tools/opensnoop

# Trace TCP connections
sudo /usr/share/bcc/tools/tcpconnect

# Memory allocation flame graph
sudo /usr/share/bcc/tools/stackcount -P -p $(pgrep my_app) malloc > malloc.stacks
flamegraph.pl malloc.stacks > malloc_flame.svg
```

**Custom eBPF Program:**
```c
// trace_crash.c - Trace program crashes
#include <uapi/linux/ptrace.h>

// Map to count crashes per PID
BPF_HASH(crashes, u32);

int trace_crash(struct pt_regs *ctx, int sig) {
    if (sig == SIGSEGV || sig == SIGABRT) {
        u32 pid = bpf_get_current_pid_tgid();
        u64 *count = crashes.lookup(&pid);
        if (count) {
            (*count)++;
        } else {
            u64 one = 1;
            crashes.update(&pid, &one);
        }
    }
    return 0;
}
```

**Compile and run:**
```bash
# Using python BCC
python3 << 'EOF'
from bcc import BPF

# Load eBPF program
b = BPF(src_file="trace_crash.c")
b.attach_kprobe(event="do_send_sig_info", fn_name="trace_crash")

print("Tracing crashes... Ctrl+C to exit")
try:
    b.trace_print()
except KeyboardInterrupt:
    pass

# Print crash counts
print("\nCrash counts by PID:")
for k, v in b["crashes"].items():
    print(f"PID {k.value}: {v.value} crashes")
EOF
```

### trace-cmd (Ftrace Frontend)

**Easy interface to ftrace:**
```bash
# Install
sudo apt install trace-cmd

# Record all scheduler events for 10 seconds
sudo trace-cmd record -e sched -o trace.dat sleep 10

# Analyze
trace-cmd report trace.dat | less

# Record specific function
sudo trace-cmd record -p function -l do_sys_open

# Record with stack traces
sudo trace-cmd record -p function --func-stack -l my_function
```

### Performance Analysis Workflow

**Find Slow System Calls:**
```bash
# Trace all syscalls with timing
sudo bpftrace -e '
tracepoint:raw_syscalls:sys_enter {
    @start[tid] = nsecs;
}
tracepoint:raw_syscalls:sys_exit /@start[tid]/ {
    $duration = nsecs - @start[tid];
    if ($duration > 100000000) {  // > 100ms
        printf("Slow syscall %d: %d ms\n", args->id, $duration / 1000000);
    }
    delete(@start[tid]);
}'
```

**Find Memory-Hungry Functions:**
```bash
# Track malloc sizes by stack
sudo /usr/share/bcc/tools/stackcount -P -U malloc:malloc
```

**Network Latency Analysis:**
```bash
# TCP round-trip time
sudo /usr/share/bcc/tools/tcprtt
```

### Best Practices

1. **Start Simple**: Use bpftrace for ad-hoc queries
2. **Production Safe**: eBPF is verified safe by kernel
3. **Overhead Awareness**: Minimize probe frequency
4. **Use BCC Tools**: Pre-built tools for common tasks
5. **Combine with Traditional Tools**: Use with perf, strace for complete picture

---

## LLDB Debugger (LLVM/Apple Alternative)

### Overview
**LLDB** is the LLVM project's debugger, default on macOS/iOS and increasingly used on Linux. It's an alternative to GDB with similar capabilities but different command syntax.

### Why LLDB Matters
- **macOS Default**: Required for macOS/iOS development
- **Swift Support**: Native Swift debugging
- **Modern Architecture**: Built on LLVM infrastructure
- **Python Scripting**: Extensible via Python API

### LLDB vs GDB Command Mapping

| Task | GDB | LLDB |
|------|-----|------|
| Start debugging | `gdb program` | `lldb program` |
| Set breakpoint | `break main` | `breakpoint set --name main` or `b main` |
| Run program | `run arg1 arg2` | `run arg1 arg2` |
| Step over | `next` | `next` or `n` |
| Step into | `step` | `step` or `s` |
| Continue | `continue` | `continue` or `c` |
| Backtrace | `bt` | `bt` or `thread backtrace` |
| Print variable | `print var` | `print var` or `p var` |
| Disassemble | `disassemble` | `disassemble` or `di` |
| Info registers | `info registers` | `register read` |
| Quit | `quit` | `quit` or `q` |

### Basic LLDB Usage

**Start debugging:**
```bash
# Debug executable
lldb ./program

# Attach to running process
lldb -p $(pgrep program)
lldb -p 12345

# Load core dump
lldb -c core.12345 ./program
```

**Set breakpoints:**
```bash
(lldb) breakpoint set --name main
(lldb) b main  # Short form

# Breakpoint by file:line
(lldb) breakpoint set --file main.c --line 42
(lldb) b main.c:42

# Breakpoint by address
(lldb) breakpoint set --address 0x555555554a7c
(lldb) br s -a 0x555555554a7c

# Conditional breakpoint
(lldb) breakpoint set --name malloc --condition 'size > 1000'

# List breakpoints
(lldb) breakpoint list
(lldb) br l
```

**Execution control:**
```bash
(lldb) run arg1 arg2
(lldb) r

# Run without stopping at entry
(lldb) process launch --

# Continue
(lldb) continue
(lldb) c

# Step over
(lldb) next
(lldb) n

# Step into
(lldb) step
(lldb) s

# Finish current function
(lldb) finish
(lldb) f
```

**Examining state:**
```bash
# Backtrace
(lldb) thread backtrace
(lldb) bt

# All threads
(lldb) thread backtrace all
(lldb) bt all

# Select frame
(lldb) frame select 2
(lldb) f 2

# Print variable
(lldb) print my_var
(lldb) p my_var

# Print with expression
(lldb) expression my_var * 2

# Print memory
(lldb) memory read 0x7ffffffde800
(lldb) x 0x7ffffffde800

# Registers
(lldb) register read
(lldb) reg read rax rbx

# Disassemble
(lldb) disassemble --name main
(lldb) di -n main
```

### Advanced LLDB Features

**Watchpoints (data breakpoints):**
```bash
# Watch variable for changes
(lldb) watchpoint set variable my_var
(lldb) w s v my_var

# Watch memory address
(lldb) watchpoint set expression -- 0x7ffffffde800
(lldb) w s e 0x7ffffffde800

# Watch with size
(lldb) watchpoint set expression -w write -s 4 -- 0x7ffffffde800
```

**Python Scripting:**
```python
# In LLDB
(lldb) script
Python Interactive Interpreter. To exit, type 'quit()', 'exit()' or Ctrl-D.
>>> lldb.debugger.GetSelectedTarget()
<lldb.SBTarget; proxy of <Swig Object of type 'lldb::SBTarget *' at 0x...> >
>>> lldb.frame.FindVariable("my_var")
<lldb.SBValue; proxy of <Swig Object of type 'lldb::SBValue *' at 0x...> >
>>> quit()
```

**Custom Commands:**
```bash
# Create alias
(lldb) command alias bfl breakpoint set -f %1 -l %2
(lldb) bfl main.c 42  # Now creates breakpoint

# Save aliases
(lldb) settings set target.save-jit-to-disk true
```

### macOS Specific Debugging

**Attach to macOS process:**
```bash
# May need to disable SIP (System Integrity Protection) for some processes
lldb -p $(pgrep Safari)

# Or use sudo
sudo lldb -p 12345
```

**Debug iOS app:**
```bash
# From Xcode command line tools
lldb --attach-name MyApp
```

**Core dumps on macOS:**
```bash
# Enable core dumps
ulimit -c unlimited

# Core files location on macOS
ls /cores/core.*

# Debug
lldb -c /cores/core.12345 /path/to/binary
```

### Swift Debugging

**Swift-specific commands:**
```bash
# Print Swift variable
(lldb) po mySwiftVar

# Swift expression
(lldb) expression -- import Foundation
(lldb) expression -- let x = 42
(lldb) po x

# View Swift types
(lldb) type lookup MySwiftClass
```

### LLDB Integration with IDE

**VSCode:**
```json
// launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "lldb",
            "request": "launch",
            "name": "Debug with LLDB",
            "program": "${workspaceFolder}/program",
            "args": [],
            "cwd": "${workspaceFolder}"
        }
    ]
}
```

**Xcode:**
- LLDB is built-in, default debugger
- Use Debug Navigator for visual debugging
- Console shows LLDB prompt for direct commands

---

## RR Record & Replay Debugger

### Overview
**rr** (Record and Replay) is a debugging tool that records program execution and allows deterministic replay. It solves the hardest debugging problem: **intermittent crashes** (Heisenbugs) by capturing the exact execution that caused the crash.

### Why RR Matters
- **Deterministic Replay**: Exact same execution every time
- **Time-Travel Debugging**: Step backwards in execution
- **Intermittent Bug Solving**: Record once, debug many times
- **No Source Changes**: Works with existing binaries

### Installation

```bash
# Ubuntu/Debian
sudo apt install rr

# Fedora
sudo dnf install rr

# Build from source
git clone https://github.com/rr-debugger/rr
cd rr
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

**System Requirements:**
```bash
# Check CPU support (needs hardware performance counters)
rr check

# Output should be:
# rr: Syscall buffering is enabled. rr should work fine.

# Adjust perf_event_paranoid if needed
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

### Basic RR Workflow

**1. Record Program Execution:**
```bash
# Record normal execution
rr record ./program arg1 arg2

# Output:
# rr: Saving execution to trace directory `/home/user/.local/share/rr/program-0'.
# ... program executes ...
# rr: Saving trace to `/home/user/.local/share/rr/program-0'.
```

**2. Replay with Debugger:**
```bash
# Replay last recorded execution
rr replay

# Or specify trace directory
rr replay /home/user/.local/share/rr/program-0

# Drops into GDB-like interface
(rr) continue
(rr) break crash_function
(rr) continue
# ... program reaches breakpoint ...
(rr) backtrace
```

**3. Time-Travel Debugging:**
```bash
# Replay with time-travel
rr replay

(rr) continue
# Program crashes

(rr) reverse-continue
# Steps BACKWARDS to previous breakpoint/crash

(rr) reverse-next
# Steps backwards one line

(rr) reverse-finish
# Goes back to function entry
```

### Advanced RR Usage

**Record with Chaos Mode (Find race conditions):**
```bash
# Randomize thread scheduling to expose race conditions
rr record --chaos ./program

# Record multiple times
for i in {1..100}; do
    rr record --chaos -o trace_$i ./program
done

# Replay failed runs
rr replay trace_45
```

**Conditional Recording:**
```bash
# Record until specific event
rr record --syscall-buffer-size=100000 ./program

# Record with signal handling
rr record --continue-through-signal=SIGUSR1 ./program
```

**Inspect Trace Without Debugger:**
```bash
# Show trace statistics
rr dump /home/user/.local/share/rr/program-0

# Output:
# Event count: 12345678
# Syscalls: 5678
# Signal count: 0
```

### Real-World Heisenbug Example

**Problem:** Program crashes randomly, can't reproduce

```bash
# Step 1: Run under rr until it crashes
while true; do
    rr record ./flaky_program
    if [ $? -ne 0 ]; then
        echo "Crash captured!"
        break
    fi
done

# Step 2: Replay the crash
rr replay

(rr) continue
# Program will crash at exact same point

(rr) backtrace
#0  0x0000555555554a7c in process_data (data=0x0) at main.c:45
#1  0x0000555555554a90 in main () at main.c:50

(rr) print data
$1 = (void *) 0x0  # NULL pointer!

# Step 3: Time-travel to see how it became NULL
(rr) reverse-continue
# Goes backward to where data was set

(rr) print data
$2 = (void *) 0x12345678  # Was valid

(rr) next
# Executes next line

(rr) print data
$3 = (void *) 0x0  # Became NULL here!

(rr) list
42    if (condition) {
43        data = allocate_buffer();
44    } else {
45        data = NULL;  # BUG: Should handle this case!
46    }

# Found root cause: data set to NULL without check
```

### Multi-Process Recording

```bash
# Record with all child processes
rr record -f ./parent_program

# Replay specific process
rr replay -f
# Shows list of processes
# Select process to debug
```

### RR with CI/CD

**Automated Crash Recording:**
```bash
#!/bin/bash
# test_with_rr.sh

TEST_CMD="./program --test-mode"
MAX_ATTEMPTS=100

for i in $(seq 1 $MAX_ATTEMPTS); do
    echo "Attempt $i..."
    
    rr record -o trace_$i $TEST_CMD
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -ne 0 ]; then
        echo "CRASH CAPTURED in trace_$i"
        
        # Generate backtrace automatically
        rr replay trace_$i <<EOF > backtrace_$i.txt
continue
backtrace
quit
EOF
        
        # Upload trace for later analysis
        tar czf trace_$i.tar.gz ~/.local/share/rr/trace_$i
        aws s3 cp trace_$i.tar.gz s3://crash-bucket/
        
        exit 1
    fi
done

echo "No crash in $MAX_ATTEMPTS attempts"
```

### RR Performance Tips

**Minimize Overhead:**
```bash
# Reduce syscall buffering (faster but larger traces)
rr record --syscall-buffer-size=1000000 ./program

# Skip non-critical areas
rr record --no-syscall-buffer ./program
```

**Trace Management:**
```bash
# List all traces
ls ~/.local/share/rr/

# Delete old traces
rr rm program-0
# Or manually
rm -rf ~/.local/share/rr/program-*

# Pack trace for sharing
rr pack ~/.local/share/rr/program-0
# Creates program-0.trace file
```

### Limitations

- **Overhead**: ~2x slower than native execution
- **Disk Space**: Traces can be large (100MB - 1GB+)
- **Single Machine**: Can't replay on different hardware
- **No Network**: Some network syscalls not supported

## Method 3: /proc Filesystem

### Overview
The Linux `/proc` filesystem provides real-time access to process memory and registers **without stopping the process**. This is the foundation of your crash analysis tool.

### Key Files

```
/proc/<PID>/
├── maps          # Memory mappings
├── mem           # Process memory contents
├── regs          # CPU registers (architecture-specific)
├── cmdline       # Command line arguments
├── status        # Process status info
├── stat          # Process statistics
├── smaps         # Detailed memory mappings
└── stack         # Kernel stack (limited info)
```

### Step-by-Step Usage

#### 1. **Get Memory Mappings**
```bash
# View memory layout
cat /proc/<PID>/maps

# Example output:
555555554000-555555558000 r-xp 00000000 08:01 2101234   /usr/bin/myapp
555555757000-555555759000 r--p 00003000 08:01 2101234   /usr/bin/myapp
555555759000-55555575a000 rw-p 00005000 08:01 2101234   /usr/bin/myapp
7ffff7a00000-7ffff7bca000 r-xp 00000000 08:01 2101235   /lib64/libc.so.6
7ffff7fdd000-7ffff7fff000 rw-p 00000000 00:00 0        [heap]
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0        [stack]
```

#### 2. **Extract Process Registers (Signal Handler)**
Your `crash_demo.c` shows the approach:

```c
#include <signal.h>
#include <ucontext.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

void signal_handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *ucp = (ucontext_t *)context;
    struct mcontext *mcp = &ucp->uc_mcontext;
    
    // Extract registers (x86-64)
    unsigned long pc = mcp->gregs[REG_RIP];
    unsigned long sp = mcp->gregs[REG_RSP];
    unsigned long fp = mcp->gregs[REG_RBP];
    unsigned long lr = 0; // x86-64 doesn't have LR like ARM
    
    // Save registers
    FILE *regs_file = fopen("crash_dump.regs", "w");
    fprintf(regs_file, "PC=0x%lx\n", pc);
    fprintf(regs_file, "SP=0x%lx\n", sp);
    fprintf(regs_file, "FP=0x%lx\n", fp);
    fclose(regs_file);
    
    // Save memory map
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cp /proc/%d/maps crash_dump.maps", getpid());
    system(cmd);
    
    exit(1);
}

int main() {
    struct sigaction sa;
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    
    // ... rest of code
}
```

#### 3. **Read Process Memory Directly**
```bash
# Read specific memory region
# Requires: same user or root

# Get stack region from maps
STACK_START=$(grep '\[stack\]' /proc/<PID>/maps | awk '{print $1}' | cut -d- -f1)
STACK_END=$(grep '\[stack\]' /proc/<PID>/maps | awk '{print $1}' | cut -d- -f2)

# Read stack bytes
hexdump -C -s 0x$STACK_START -n 1024 /proc/<PID>/mem

# Or dump to file
dd if=/proc/<PID>/mem of=stack_dump.bin \
    skip=$((16#$STACK_START)) \
    bs=1 \
    count=$((16#$STACK_END - 16#$STACK_START)) 2>/dev/null
```

#### 4. **Get Process Status Information**
```bash
cat /proc/<PID>/status

# Output example:
Name:	myapp
Umask:	0022
State:	S (sleeping)
Tgid:	12345
Pid:	12345
VmPeak:	  1234 kB
VmSize:	  1200 kB
VmRSS:	   800 kB
Threads:	5
```

#### 5. **Get Detailed Memory Info**
```bash
# Shows memory regions with more detail
cat /proc/<PID>/smaps | head -30

# Output:
555555554000-555555558000 r-xp 00000000 08:01 2101234   /usr/bin/myapp
Size:                  16 kB
Rss:                   16 kB
Pss:                   16 kB
Shared_Clean:          16 kB
Shared_Dirty:           0 kB
Private_Clean:          0 kB
Private_Dirty:          0 kB
Referenced:            16 kB
Anonymous:              0 kB
LazyFree:               0 kB
...
```

### Automated Process State Capture

```bash
#!/bin/bash
# crash_capture.sh - Capture process state without stopping it

PID=$1

if [ -z "$PID" ]; then
    echo "Usage: $0 <PID>"
    exit 1
fi

# Create output directory
CRASH_DIR="crash_analysis_${PID}_$(date +%s)"
mkdir -p "$CRASH_DIR"

# Capture memory maps
cp /proc/$PID/maps "$CRASH_DIR/test/pmap-sample.txt"

# Capture process info
cat /proc/$PID/status > "$CRASH_DIR/process_status.txt"

# Capture detailed memory info
cat /proc/$PID/smaps > "$CRASH_DIR/detailed_maps.txt"

# Analyze memory map
python3 pmap.py "$CRASH_DIR/test/pmap-sample.txt" --report

echo "Analysis saved to: $CRASH_DIR/"
```

### Advantages
- **Non-invasive** - Doesn't stop or modify the process  
- **Real-time** - Can read current state anytime  
- **Lightweight** - No special tools needed beyond standard utilities  
- **Scriptable** - Easily automated  
- **Programmatic** - Foundation for automated crash analysis tools  

### Disadvantages
- **Permission-dependent** - Often need same user or root  
- **No variable inspection** - Limited to memory and registers  
- **Snapshot inconsistency** - Process keeps running, data may be inconsistent  
- **Limited stack info** - `/proc/<PID>/stack` shows only kernel stack  
- **Memory interpretation** - Must manually parse binary data  

### Permission Requirements

```bash
# Check if you can read process info
ls -la /proc/<PID>/

# Try to read as regular user
cat /proc/<PID>/maps

# If denied, try with sudo
sudo cat /proc/<PID>/maps

# Or enable ptrace for your user
# This allows debugging without sudo
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

---

## Method 4: strace/ltrace

### Overview
**strace** traces system calls and signals, while **ltrace** traces library function calls. Both show the execution flow without needing to pause the process.

### Prerequisites
```bash
sudo apt-get install strace ltrace
```

### Using strace

#### Basic Usage
```bash
# Trace all system calls
strace -p <PID>

# Output:
select(10, [3 4 5], [], [], {tv_sec=5, tv_usec=0}) = 1 (out of 5) (Signals: 1/0)
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x0} ---
+++ killed by SIGSEGV +++
```

#### Filtered Tracing
```bash
# Trace only specific syscalls
strace -p <PID> -e trace=open,read,write

# Trace network calls
strace -p <PID> -e trace=network

# Trace file operations
strace -p <PID> -e trace=openat,close,read,write

# Trace memory operations
strace -p <PID> -e trace=mmap,munmap,brk
```

#### Capture to File
```bash
# Write output to file
strace -p <PID> -o trace_output.txt

# Follow child processes
strace -p <PID> -f -o trace_output.txt

# Show timestamps
strace -p <PID> -t -o trace_output.txt

# Show duration of each call
strace -p <PID> -T -o trace_output.txt
```

#### Full Example
```bash
$ strace -p 12345 -e trace=open,read,write,mmap -T

mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fd2000 <0.000023>
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0", 832) = 832 <0.000015>
mmap(NULL, 3939216, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7ffff7a00000 <0.000031>
mmap(0x7ffff7bca000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1ca000) = 0x7ffff7bca000 <0.000022>
```

### Using ltrace

#### Basic Usage
```bash
# Trace library calls
ltrace -p <PID>

# Output:
__libc_start_main(0x555555554a70, 1, 0x7fffffffe6e8, 0x555555554c70 <unfinished ...>
strlen("hello") = 5
printf("Result: %d\n", 42) = 10
malloc(1024) = 0x555555757050
strcpy(0x555555757050, "test") = 0x555555757050
free(0x555555757050) = <void>
```

#### Filtering Library Calls
```bash
# Trace only specific libraries
ltrace -p <PID> -l libc.so.6

# Trace calls matching pattern
ltrace -p <PID> -C  # Demangle C++

# Ignore certain calls
ltrace -p <PID> --demangle --indent=2
```

#### Capture to File with Analysis
```bash
#!/bin/bash
# analyze_trace.sh

PID=$1

# Capture trace
ltrace -p $PID -C -e '~printf' -o trace.txt 2>&1

# Analyze the trace
echo "=== Function Call Summary ==="
grep -o '[a-zA-Z_][a-zA-Z0-9_]*(' trace.txt | sort | uniq -c | sort -rn | head -20

echo -e "\n=== Memory Operations ==="
grep -E 'malloc|free|calloc|realloc' trace.txt | head -20

echo -e "\n=== File Operations ==="
grep -E 'fopen|fread|fwrite|fclose' trace.txt | head -20
```

### Advantages
- **Shows execution flow** - See what functions are called  
- **Non-intrusive** - Doesn't require code changes  
- **Call count** - Shows how often functions are called  
- **Return values** - Captures function return values  
- **Performance analysis** - With `-T`, shows time per call  

### Disadvantages
- **Not a real stack** - Shows call sequence, not current stack  
- **Output heavy** - Can generate massive logs  
- **Performance impact** - Tracing slows process significantly  
- **No variable inspection** - Limited to function names and parameters  
- **Requires running process** - Can't analyze after crash  

### Performance Impact

```bash
# strace adds significant overhead (5-20x slowdown typical)
time ./myapp                  # Original: ~1 second
time strace ./myapp           # Traced: ~10-20 seconds

# Use selective tracing to reduce overhead
strace -e trace=open ./myapp  # Only syscalls we care about
```

---

## Method 5: perf Profiler

### Overview
**perf** is the Linux performance profiler. It uses CPU sampling to capture stack traces during program execution, showing where the process spends its time.

### Prerequisites
```bash
sudo apt-get install linux-tools-generic

# Check if perf is available
perf --version
```

### Basic Usage

#### Record Stack Samples
```bash
# Sample at 99 Hz for 10 seconds (default: 1000 Hz)
sudo perf record -p <PID> -g -F 99 -- sleep 10

# Output: perf.data (binary format)
```

#### View Results
```bash
# Interactive view
sudo perf report -i perf.data

# Annotated view
sudo perf annotated

# Timeline view
sudo perf script -i perf.data | less
```

#### Flame Graph Generation
```bash
# Install flamegraph tools
git clone https://github.com/brendangregg/FlameGraph.git

# Generate samples
sudo perf record -p <PID> -g -F 99 -- sleep 30

# Convert to flamegraph format
sudo perf script -i perf.data > /tmp/perf.txt
cd FlameGraph
./stackcollapse-perf.pl /tmp/perf.txt > /tmp/perf.folded
./flamegraph.pl /tmp/perf.folded > /tmp/perf.svg

# View: open perf.svg in browser
```

### Advanced Profiling

#### Find Hotspots (Where Process Spends Time)
```bash
# Record with high frequency
sudo perf record -p <PID> -g -F 999 -- sleep 5

# Show top functions by samples
sudo perf report -i perf.data --stdio

# Output:
# Samples: 50K of event 'cpu-clock'
# Event count (approx.): 50000
#
#   56.23%  myapp    [.] compute_heavy()
#   23.45%  libc     [.] __libc_malloc
#   12.34%  myapp    [.] allocate_memory()
#    8.00%  kernel   [k] page_fault_handler
```

#### Trace Specific Function
```bash
# Trace function entry/exit
sudo perf trace -p <PID> -e probe_myapp:compute_heavy

# Manual instrumentation
sudo perf probe -x ./myapp 'compute_heavy:%return'
sudo perf record -p <PID> -g -e probe_myapp:compute_heavy -- sleep 10
```

#### Memory Profiling
```bash
# Profile memory allocation
sudo perf record -p <PID> -g -e mem:* -- sleep 10

# Sample memory events
sudo perf record -p <PID> -g -e page-faults -- sleep 10

# Show memory usage
sudo perf report -i perf.data --stdio | grep mem
```

### Real-World Example: Find Memory Leak

```bash
#!/bin/bash
# find_memory_leak.sh

PID=$1
DURATION=30

echo "Profiling memory allocations for $DURATION seconds..."
sudo perf record -p $PID -g -e 'malloc' --call-graph dwarf -F 100 -- sleep $DURATION

echo -e "\n=== Top Memory Allocators ==="
sudo perf report -i perf.data --stdio | head -50

echo -e "\n=== Flamegraph of allocations ==="
sudo perf script -i perf.data > /tmp/mem_perf.txt
~/FlameGraph/stackcollapse-perf.pl /tmp/mem_perf.txt > /tmp/mem_perf.folded
~/FlameGraph/flamegraph.pl /tmp/mem_perf.folded > /tmp/mem_profile.svg
echo "Generated: /tmp/mem_profile.svg"
```

### Advantages
- **Production-safe** - Very low overhead (~1-5%)  
- **Sampling-based** - Captures representative data without pausing  
- **Visual output** - Flamegraphs are intuitive  
- **Comprehensive** - Captures CPU, memory, cache, I/O events  
- **Root-cause analysis** - Shows exactly where time/memory is spent  

### Disadvantages
- **Sampling error** - May miss infrequent events  
- **Low time resolution** - Not for nanosecond-level analysis  
- **Complex output** - Requires interpretation  
- **Requires permissions** - Usually needs sudo/root  
- **Flamegraph tool setup** - Extra steps for visualization  

### Reducing Overhead

```bash
# Lower sampling frequency to reduce overhead
sudo perf record -p <PID> -g -F 10 -- sleep 60

# Record only specific events
sudo perf record -p <PID> -e cache-misses -- sleep 10

# Use event-based sampling instead of time-based
sudo perf record -p <PID> -c 1000000 -e cycles -- sleep 10
```

---

## Comparison Table

| Method | **Speed** | **Overhead** | **Stops Process** | **No Setup** | **Source Code** | **Real-time** | **Requires Root** | **Best For** |
|--------|-----------|------------|------------------|-------------|----------------|--------------|-----------------|-------------|
| **GDB** | Slow | High | Yes | Yes | Full | Live | No (unless root) | Detailed debugging |
| **Core Dump** | N/A | N/A | N/A | No | Full | No | No | Post-mortem analysis |
| **/proc** | Fast | None | No | Yes | No | Yes | Depends | Quick snapshots |
| **strace** | Slow | 5-20x | No | Yes | Minimal | No | Depends | System call analysis |
| **ltrace** | Slow | 3-10x | No | Yes | Minimal | No | Depends | Library call analysis |
| **perf** | Fast | 1-5% | No | No | Yes (with symbols) | Live | Usually | Performance profiling |

---

## Integration with Crash Analysis Tools

### Combining Methods with Memory Map Analysis

#### Method 1: GDB + pmap

```bash
#!/bin/bash
# gdb_analyzer.sh

BINARY=$1
CORE=$2

# Extract registers from core dump via GDB
gdb -batch \
    -ex "core-file $CORE" \
    -ex "info registers" \
    -ex "thread apply all bt" > gdb_output.txt

# Extract values
PC=$(grep "rip" gdb_output.txt | awk '{print $2}')
SP=$(grep "rsp" gdb_output.txt | awk '{print $2}')
FP=$(grep "rbp" gdb_output.txt | awk '{print $2}')

# Get memory map (already in core, but can extract from binary)
readelf -l $BINARY > binary_layout.txt

# Use your analyzer with extracted data
python3 pmap.py /proc/$$/maps \
    --pc $PC --sp $SP --fp $FP --html crash_analysis.html
```

#### Method 2: strace + Your Analyzer

```bash
#!/bin/bash
# strace_analyzer.sh

PID=$1

# Capture initial state
cp /proc/$PID/maps memmap_before.txt

# Run strace
timeout 10 strace -p $PID -o trace.txt

# Capture final state
cp /proc/$PID/maps memmap_after.txt

# Analyze memory changes
diff -u memmap_before.txt memmap_after.txt

# Analyze memory map
python3 pmap.py memmap_after.txt --table --stats
```

#### Method 3: perf + pmap

```bash
#!/bin/bash
# perf_analyzer.sh

PID=$1

# Get initial process info
cp /proc/$PID/maps initial_maps.txt

# Profile for 10 seconds
sudo perf record -p $PID -g -F 99 -- sleep 10

# Get final maps
cp /proc/$PID/maps final_maps.txt

# Show memory layout changes
echo "=== Memory Layout Changes ==="
diff -u initial_maps.txt final_maps.txt | grep "^[+-]" | grep -v "^[+-][+-][+-]"

# Generate detailed visualization
python3 pmap.py final_maps.txt --ascii --grouped --html profile_analysis.html
```

### Complete Workflow: Crash Detection + Analysis

```bash
#!/bin/bash
# detect_and_analyze_crash.sh
#
# Comprehensive workflow combining multiple methods

BINARY=$1
TIMEOUT=${2:-30}

echo "[*] Starting crash detection workflow..."

# Step 1: Enable core dumps
ulimit -c unlimited

# Step 2: Run with strace in background to catch crash
echo "[*] Running process with strace..."
strace -e trace=open,mmap,signal -f ./$BINARY > strace.log 2>&1 &
PID=$!

# Step 3: Monitor in parallel with perf
echo "[*] Profiling with perf..."
sudo perf record -p $PID -g -F 99 -- sleep $TIMEOUT &
PERF_PID=$!

# Step 4: Periodically capture memory state
for i in $(seq 1 5); do
    sleep $((TIMEOUT/5))
    cp /proc/$PID/maps "memmap_snapshot_$i.txt"
done

# Step 5: Wait for process
wait $PID
EXIT_CODE=$?

# Step 6: Collect core dump if crashed
if [ $EXIT_CODE -ne 0 ]; then
    echo "[!] Process crashed (exit code: $EXIT_CODE)"
    
    # Find core file
    CORE_FILE=$(ls -t core.* 2>/dev/null | head -1)
    if [ -n "$CORE_FILE" ]; then
        echo "[*] Found core file: $CORE_FILE"
        
        # Extract registers
        gdb -batch -ex "core-file $CORE_FILE" -ex "info registers" > crash_regs.txt
        
        # Analyze memory map
        python3 pmap.py memmap_snapshot_5.txt \
            --ascii --grouped --html crash_full_analysis.html
    fi
fi

# Step 7: Generate comprehensive report
echo "[*] Generating comprehensive analysis..."

python3 << 'EOF'
import os
import re

print("=" * 80)
print("CRASH ANALYSIS REPORT")
print("=" * 80)

# Parse strace output
if os.path.exists("strace.log"):
    print("\n=== System Call Summary ===")
    with open("strace.log") as f:
        lines = f.readlines()
        # Find signal/crash
        for line in lines:
            if "SIGSEGV" in line or "killed by" in line:
                print(f"CRASH: {line.strip()}")
                
# Parse registers
if os.path.exists("crash_regs.txt"):
    print("\n=== Crash Registers ===")
    with open("crash_regs.txt") as f:
        for line in f:
            if any(x in line for x in ['rip', 'rsp', 'rbp', 'rax', 'rbx']):
                print(line.rstrip())

# Memory changes
print("\n=== Memory Mapping Changes ===")
if os.path.exists("memmap_snapshot_1.txt") and os.path.exists("memmap_snapshot_5.txt"):
    with open("memmap_snapshot_1.txt") as f:
        initial_lines = len(f.readlines())
    with open("memmap_snapshot_5.txt") as f:
        final_lines = len(f.readlines())
    print(f"Segments changed: {initial_lines} → {final_lines}")

print("\n=== Generated Outputs ===")
print("- crash_full_analysis.html (Interactive visualization)")
print("- strace.log (System call trace)")
print("- perf.data (Performance data)")

EOF

echo "[+] Analysis complete!"
```

---

## Best Practices

### 1. **Choose the Right Method**

```bash
# Quick snapshot of running process?
→ Use /proc filesystem

# Need full debugging capabilities?
→ Use GDB attachment

# Analyzing after crash?
→ Use core dumps

# Tracing specific behavior?
→ Use strace/ltrace

# Finding performance bottlenecks?
→ Use perf

# Complete end-to-end crash analysis?
→ Use your crash_demo.c + analyzer combination
```

### 2. **Optimize for Your Environment**

```bash
# Development: Full debug info + GDB
gcc -g -O0 -Wall myapp.c -o myapp

# Production: Minimal overhead with perf
gcc -g -O2 myapp.c -o myapp
# Run with perf (only 1-5% overhead)

# Both: Symbol servers
gcc -g -O2 myapp.c -o myapp
objcopy --only-keep-debug myapp myapp.debug
objcopy --strip-debug myapp
```

### 3. **Preserve Debug Information**

```bash
# Include debug symbols in binary
gcc -g -O2 app.c -o app

# Or in separate file
gcc -g -O2 app.c -o app
objcopy --only-keep-debug app app.debug
strip app
export DEBUGINFOD_URLS="https://debuginfod.elfutils.org"

# perf can use debuginfod automatically
sudo perf report  # Will find symbols automatically
```

### 4. **Automate Data Collection**

```bash
#!/bin/bash
# automated_crash_monitor.sh
#
# Continuously monitor for crashes and auto-analyze

BINARY=$1
CRASH_DIR="crashes"

mkdir -p $CRASH_DIR

while true; do
    # Run with crash capture
    ulimit -c unlimited
    
    # Run binary (will crash)
    ./$BINARY
    CRASH_CODE=$?
    
    if [ $CRASH_CODE -ne 0 ]; then
        # Found a crash
        TIMESTAMP=$(date +%s)
        CRASH_SUBDIR="$CRASH_DIR/crash_$TIMESTAMP"
        mkdir -p $CRASH_SUBDIR
        
        # Collect data
        cp /proc/self/maps "$CRASH_SUBDIR/test/pmap-sample.txt"
        
        # Find and copy core dump
        CORE=$(ls -t core.* 2>/dev/null | head -1)
        if [ -n "$CORE" ]; then
            mv $CORE "$CRASH_SUBDIR/"
        fi
        
        # Analyze
        python3 pmap.py "$CRASH_SUBDIR/test/pmap-sample.txt" \
            --html "$CRASH_SUBDIR/analysis.html"
        
        echo "Crash recorded: $CRASH_SUBDIR"
    fi
    
    sleep 1
done
```

### 5. **Combine Multiple Methods**

```bash
#!/bin/bash
# multi_method_analysis.sh
#
# Use multiple methods to get complete picture

PID=$1

echo "=== Method 1: Current Memory State ===" 
cat /proc/$PID/maps

echo -e "\n=== Method 2: Process Statistics ==="
cat /proc/$PID/status | grep -E "^(Vm|Threads|State)"

echo -e "\n=== Method 3: Thread Information (GDB) ==="
gdb -batch -p $PID -ex "thread apply all bt" -ex "detach" 2>/dev/null | tail -20

echo -e "\n=== Method 4: Call Trace (ltrace) ==="
timeout 2 ltrace -p $PID 2>/dev/null | head -20 &

echo -e "\n=== Method 5: Performance Sampling (perf) ==="
timeout 5 sudo perf record -p $PID -g -F 99 -- sleep 2 2>/dev/null
sudo perf report -i perf.data --stdio 2>/dev/null | head -20
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: Permission Denied (GDB)

```bash
# Error: "Could not attach to process."

# Solution 1: Run as same user
ps aux | grep myapp
# Verify your user matches

# Solution 2: Enable ptrace without sudo
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Solution 3: Run as root (last resort)
sudo gdb -p <PID>
```

#### Issue 2: No Core Dump Generated

```bash
# Problem: Process crashes but no core file

# Check if core dumps enabled
ulimit -c
# If output is "0", they're disabled

# Enable them
ulimit -c unlimited
ulimit -c  # Verify: should show "unlimited"

# Set persistent limit in /etc/security/limits.conf
* soft core unlimited
* hard core unlimited

# Reboot or:
sysctl -w kernel.core_pattern=core.%e.%p

# Check core_pattern
cat /proc/sys/kernel/core_pattern
```

#### Issue 3: GDB Shows No Source Code

```bash
# Problem: bt shows addresses, not source lines

# Solution: Recompile with debug symbols
gcc -g -O0 myapp.c -o myapp

# Or install debug packages
sudo apt-get install <package-name>-dbg

# Check if symbols present:
objdump -t myapp | head

# Strip symbols removes them:
strip myapp  # Don't do this if you want debugging!
```

#### Issue 4: /proc Access Denied

```bash
# Problem: "cat /proc/<PID>/maps: Permission denied"

# Solution: Run as same user or root
# The process must be owned by your user or you must be root

# Check process owner
ls -la /proc/<PID>/
stat /proc/<PID>/maps

# Run target process as yourself
# Or use:
sudo cat /proc/<PID>/maps
```

#### Issue 5: perf: Operation Not Permitted

```bash
# Problem: "perf record: Operation not permitted"

# Solution 1: Run with sudo
sudo perf record -p <PID> -g -- sleep 10

# Solution 2: Enable unprivileged perf
sudo sysctl kernel.perf_event_paranoid=-1

# Solution 3: Restrict to user events only
perf record --user-only -p <PID> -g -- sleep 10

# Check current setting
cat /proc/sys/kernel/perf_event_paranoid
```

#### Issue 6: strace Output Too Large

```bash
# Problem: Trace generates GB of output

# Solution 1: Reduce events
strace -p <PID> -e trace=open,mmap  # Only specific calls

# Solution 2: Use filters
strace -p <PID> -e write | grep -E "interesting_pattern"

# Solution 3: Limit duration
timeout 5 strace -p <PID> > trace.txt

# Solution 4: Redirect stderr efficiently
strace -p <PID> -o trace.txt 2>&1
```

### Validation Checklist

```bash
#!/bin/bash
# validate_setup.sh
#
# Verify your environment for crash analysis

echo "=== Crash Analysis Environment Check ==="

echo -n "1. GDB installed: "
which gdb > /dev/null && echo "[OK]" || echo "[MISSING] (install: apt install gdb)"

echo -n "2. Core dumps enabled: "
[ "$(ulimit -c)" != "0" ] && echo "[OK]" || echo "[MISSING] (run: ulimit -c unlimited)"

echo -n "3. /proc access: "
[ -r /proc/$$/maps ] && echo "[OK]" || echo "[MISSING] (check permissions)"

echo -n "4. strace installed: "
which strace > /dev/null && echo "[OK]" || echo "[MISSING] (install: apt install strace)"

echo -n "5. perf installed: "
which perf > /dev/null && echo "[OK]" || echo "[MISSING] (install: apt install linux-tools)"

echo -n "6. ltrace installed: "
which ltrace > /dev/null && echo "[OK]" || echo "[MISSING] (install: apt install ltrace)"

echo -n "7. Python3: "
which python3 > /dev/null && echo "[OK]" || echo "[MISSING] (install: apt install python3)"

echo -n "8. Debug symbols available: "
[ -n "$(which objdump)" ] && echo "[OK]" || echo "[MISSING] (install: apt install binutils)"

echo -e "\n=== Setup Status ==="
echo "Ready for crash analysis: ALL checks should show [OK]"
```

---

## Conclusion

Choosing the right stack dump method depends on your use case:

| **Scenario** | **Best Method** | **Why** |
|-------------|-----------------|---------|
| **Active debugging** | GDB | Full control and variable inspection |
| **Crash investigation** | Core Dumps | Complete memory snapshot for analysis |
| **Quick monitoring** | /proc | Non-invasive, instant snapshots |
| **Understanding behavior** | strace | Shows exactly what syscalls are executed |
| **Performance issues** | perf | Identifies bottlenecks with low overhead |
| **Automated analysis** | Your crash_demo.c | Captures registers + memory maps automatically |
| **Production safety** | perf + /proc | Minimal overhead, no process interruption |
| **Complete picture** | Combine all | Different methods show different perspectives |

Your **crash analysis tool** integrates best with:
1. **Signal-based capture** (crash_demo.c) → /proc extraction
2. **Core dump analysis** → GDB extraction
3. **Performance profiling** → perf data with your visualization

This provides comprehensive, layered debugging capabilities from development to production!
