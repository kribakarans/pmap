# Self-Dumping Register Values

This guide explains how to capture CPU register values at crash time directly from your C program.

## Overview

When a process crashes, the CPU context (registers) contains critical debugging information:
- **PC/RIP**: Program Counter - exact instruction that crashed
- **SP/RSP**: Stack Pointer - where stack currently points
- **FP/RBP**: Frame Pointer - current function frame
- **LR/Return Address**: Where execution returns after current function
- **Other registers**: Function arguments, return values, temporary data

## Implementation

The updated `crash_demo.c` demonstrates self-dumping using Linux signal handlers with context.

### Key Code Pattern

```c
#include <signal.h>
#include <ucontext.h>

/* Signal handler that receives CPU context */
void signal_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *context = (ucontext_t *)ctx;
    mcontext_t *mctx = &context->uc_mcontext;
    
    /* Access registers based on architecture */
    #ifdef __x86_64__
        unsigned long pc = mctx->gregs[16];   /* RIP */
        unsigned long sp = mctx->gregs[15];   /* RSP */
        unsigned long fp = mctx->gregs[10];   /* RBP */
    #endif
}

int main() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;  /* Enable context */
    
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
}
```

### Architecture Support

The updated `crash_demo.c` supports:

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

## Usage

### 1. Compile with Debug Symbols

```bash
gcc -g -O0 crash_demo.c -o crash_demo
```

The `-g` flag includes debug symbols needed for `addr2line`.

### 2. Run and Trigger Crash

```bash
./crash_demo
```

This generates:
- `crash_dump_<PID>.regs` — Register values
- `crash_dump_<PID>.maps` — Memory map

### 3. Example Output

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

### 4. Analyze with Memory Map

```bash
# Show memory segments
./memmap_analyzer.py crash_dump_*.maps --segments

# Analyze crash location using PC
./memmap_analyzer.py crash_dump_*.maps --pc 0x610303db57f2

# Get ASCII memory layout
./memmap_analyzer.py crash_dump_*.maps --ascii
```

### 5. Use with GDB for More Details

```bash
# Get full backtrace
gdb ./crash_demo
(gdb) run
(gdb) where

# Extract specific variable values
(gdb) info registers
(gdb) print *ptr
(gdb) frame 0
(gdb) locals
```

## Key Register Values

| Register | Purpose | Example |
|----------|---------|---------|
| **PC/RIP** | Program Counter | Where the crash occurred |
| **SP/RSP** | Stack Pointer | Top of current call stack |
| **FP/RBP** | Frame Pointer | Current function's frame boundary |
| **LR** | Link Register (ARM) | Return address after function |
| **RAX/X0** | First return value | Function return or function argument |
| **RDI/X0-X7** | Function arguments | Parameters to current function |

## Debugging Workflow

### From Crash Dump

```bash
# Step 1: Extract PC value from register dump
cat crash_dump_*.regs | grep "rip:"
# Output: rip: 0000610303db57f2

# Step 2: Use PC to find crash location
./memmap_analyzer.py crash_dump_*.maps --pc 0x610303db57f2

# Step 3: Get source location with addr2line
addr2line -e ./crash_demo 0x57f2

# Step 4: Open source file
nano crash_demo.c +29
```

### From Live Crash

```bash
# Step 1: Attach GDB to running process
gdb -p <PID>

# Step 2: Get backtrace
(gdb) where

# Step 3: Show current register state
(gdb) info registers

# Step 4: Inspect variables
(gdb) frame 0
(gdb) locals
(gdb) print *ptr
```

## Comparing Register Dumps

**Test on Different Crashes:**

```bash
# NULL pointer dereference
./crash_demo          # PC points to dereference instruction

# Divide by zero
# (Modify vulnerable_function to: int x = 1 / 0;)
gcc -g -O0 crash_demo_div0.c -o crash_demo_div0
./crash_demo_div0     # PC points to division instruction

# Stack overflow
# (Modify to use recursion)
gcc -g -O0 crash_demo_stack.c -o crash_demo_stack
./crash_demo_stack    # SP near stack limit, segfault in alloca
```

## Common Patterns

**Function Call:**
```
rbp: frame boundary
rsp: below rbp (stack grows down)
return address: [rsp] on x86-64
```

**Deep Call Stack:**
```
Frame 0: rip = vulnerable_function
Frame 1: rbp = intermediate_function's frame
Frame 2: rbp = entry_function's frame
Frame 3: rbp = main's frame
```

**Register Corruption:**
```
If registers show unexpected values:
- Heap corruption might overwrite stack
- Use ASan to detect: gcc -fsanitize=address crash_demo.c
```

## Portability

This approach works on:
- ✅ Linux (all architectures with ucontext.h)
- ✅ x86-64, ARM64, ARM (32-bit), MIPS, PowerPC
- ✅ GCC, Clang, musl, glibc
- ✅ Containers and embedded systems

Not supported on:
- ❌ Windows (use Windows exceptions instead)
- ❌ macOS (use Mach kernels APIs)
- ❌ Systems without signal.h (rare)

## Best Practices

1. **Always compile with `-g` for debug symbols**
   ```bash
   gcc -g -O0 myapp.c
   ```

2. **Use `-O0` to avoid instruction reordering**
   ```bash
   gcc -g -O0 myapp.c  # Accurate PC values
   gcc -g -O2 myapp.c  # Inlining may confuse addr2line
   ```

3. **Save dumps immediately on crash**
   ```c
   system("cat /proc/$$/maps > dump_$$.maps");
   ```

4. **Include timestamps for multiple crashes**
   ```bash
   crash_dump_2755982_t1.regs
   crash_dump_2755982_t2.regs
   ```

5. **Keep binaries with symbols for analysis**
   ```bash
   # Don't strip debug symbols in production
   gcc -g myapp.c  # Keep debug symbols
   strip -s myapp  # Removes only standalone debug info
   ```

## See Also

- [REAL_WORLD_ANALYSIS.md](REAL_WORLD_ANALYSIS.md) — Full crash analysis walkthrough
- [../USAGE.md](../USAGE.md) — Tool usage guide
- [../MEMORY_MAPS.md](../MEMORY_MAPS.md) — Memory map format details
- `man sigaction` — Signal handler documentation
- `man ucontext` — CPU context structure
- `man addr2line` — Address to source line conversion
