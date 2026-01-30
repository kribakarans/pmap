# Register Dumping & Crash Analysis - Complete Reference

This guide explains how to self-dump register values from a crashing Linux program and use them for crash analysis.

## Quick Answer

**To self-dump register values on crash:**

```c
#include <signal.h>
#include <ucontext.h>

void signal_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *context = (ucontext_t *)ctx;
    mcontext_t *mctx = &context->uc_mcontext;
    
    // x86-64 example
    printf("PC (RIP): 0x%lx\n", mctx->gregs[16]);
    printf("SP (RSP): 0x%lx\n", mctx->gregs[15]);
    
    exit(1);
}

int main() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;  // ← CRITICAL: Enables context
    
    sigaction(SIGSEGV, &sa, NULL);
}
```

**Key: `SA_SIGINFO` flag enables receiving CPU context in signal handler**

---

## Complete File Structure

```
test/
├── crash_demo.c                    ← Program that crashes and dumps registers
├── crash_demo_new                  ← Compiled binary
├── crash_dump_*.regs               ← Captured register values
├── crash_dump_*.maps               ← Captured memory map
│
├── REGISTER_DUMP_GUIDE.md          ← Overview and usage guide
├── REGISTER_EXAMPLES.md            ← Code for x86-64, ARM, ARM64, MIPS, PowerPC
├── parse_registers.py              ← Tool to extract key registers
├── complete_crash_analysis.sh      ← Full workflow automation
│
├── REAL_WORLD_ANALYSIS.md          ← Detailed crash analysis example
├── TESTING_GUIDE.md                ← Test suite documentation
└── README.md                        ← Test directory overview
```

---

## Architecture-Specific Register Locations

### x86-64 (Intel/AMD 64-bit)

```c
mcontext_t *mctx = &context->uc_mcontext;

unsigned long pc  = mctx->gregs[16];  // RIP - Program Counter
unsigned long sp  = mctx->gregs[15];  // RSP - Stack Pointer
unsigned long fp  = mctx->gregs[10];  // RBP - Frame Pointer
unsigned long arg = mctx->gregs[8];   // RDI - First argument
unsigned long ret = mctx->gregs[13];  // RAX - Return value
```

### ARM64 (AArch64)

```c
unsigned long pc = context->uc_mcontext.pc;         // Program Counter
unsigned long sp = context->uc_mcontext.sp;         // Stack Pointer
unsigned long lr = context->uc_mcontext.regs[30];   // Link Register
unsigned long arg = context->uc_mcontext.regs[0];   // X0 - First argument
```

### ARM (32-bit)

```c
unsigned long pc  = (unsigned long)context->uc_mcontext.arm_pc;
unsigned long sp  = (unsigned long)context->uc_mcontext.arm_sp;
unsigned long fp  = (unsigned long)context->uc_mcontext.arm_fp;
unsigned long lr  = (unsigned long)context->uc_mcontext.arm_lr;
```

### MIPS, PowerPC, and Others

See `REGISTER_EXAMPLES.md` for complete details.

---

## Step-by-Step Workflow

### 1. Compile with Debug Symbols

```bash
gcc -g -O0 crash_demo.c -o crash_demo
```

**Important flags:**
- `-g`: Include debug symbols (needed for addr2line)
- `-O0`: No optimization (keeps instructions in order)

### 2. Run and Trigger Crash

```bash
./crash_demo
```

**Output files generated:**
```
crash_dump_2759006.regs    ← Register values
crash_dump_2759006.maps    ← Memory map
```

### 3. Extract Key Registers

```bash
python3 parse_registers.py

# Output:
Architecture: x86-64
Total registers captured: 19

=== KEY REGISTERS FOR DEBUGGING ===
Program Counter (PC)           0x000060a1a36637f2
Stack Pointer (SP)             0x00007fff60ec6e20
Frame Pointer (FP)             0x00007fff60ec6e30
First Arg (RDI)                0x0000000000000000  ← NULL pointer!
Return Value (RAX)             0x0000000000000000
```

### 4. Analyze with Memory Map

```bash
../memmap_analyzer.py crash_dump_*.maps --pc 0x000060a1a36637f2

# Shows:
# - Which memory segment contains PC
# - Permissions (should be CODE/r-xp)
# - Binary name and offset
# - Security warnings (writable+executable, etc.)
```

### 5. Find Source Code Line

```bash
addr2line -e ./crash_demo 0x7f2

# Output: crash_demo.c:106
```

### 6. Get Call Stack

```bash
gdb -batch -ex "run" -ex "where" ./crash_demo

# Output:
#0  0x00005555555557f2 in vulnerable_function (ptr=0x0)
#1  0x0000555555555848 in intermediate_function ()
#2  0x0000555555555876 in entry_function ()
#3  0x00005555555559eb in main ()
```

---

## Example: NULL Pointer Crash Analysis

**Source Code:**
```c
void vulnerable_function(int *ptr) {
    *ptr = 42;  // Line 106 - CRASH HERE
}

void intermediate_function(void) {
    int *bad_pointer = NULL;
    vulnerable_function(bad_pointer);  // Line 116
}
```

**Crash Context:**
```
Signal: 11 (SIGSEGV)
PC: 0x000060a1a36637f2
SP: 0x00007fff60ec6e20
RDI (1st arg): 0x0000000000000000  ← NULL pointer!
```

**Analysis Steps:**
1. ✓ PC shows we're in CODE segment (r-xp)
2. ✓ addr2line maps PC to line 106 (dereference)
3. ✓ RDI is NULL (first argument)
4. ✓ Call stack shows intermediate_function called vulnerable_function
5. ✓ Root cause: NULL pointer passed as argument

**Fix:**
```c
void vulnerable_function(int *ptr) {
    if (!ptr) {
        fprintf(stderr, "Error: NULL pointer\n");
        return;
    }
    *ptr = 42;  // Safe now
}
```

---

## Register Meanings

| Register | x86-64 | ARM64 | Purpose |
|----------|--------|-------|---------|
| PC | RIP | PC | Program Counter - where crash happened |
| SP | RSP | SP | Stack Pointer - top of stack |
| FP | RBP | X29 | Frame Pointer - function frame boundary |
| LR | [RSP] | X30 | Link Register - return address |
| Arg 1 | RDI | X0 | First function argument |
| Arg 2 | RSI | X1 | Second function argument |
| Arg 3 | RDX | X2 | Third function argument |
| Arg 4 | RCX | X3 | Fourth function argument |
| Return | RAX | X0 | Return value |

---

## Integration with memmap_analyzer

The register dumps integrate seamlessly with the memory map analyzer:

```bash
# Show memory segments
./memmap_analyzer.py crash_dump_*.maps --segments

# Analyze crash location
./memmap_analyzer.py crash_dump_*.maps --pc 0x555555555352

# Show ASCII memory layout
./memmap_analyzer.py crash_dump_*.maps --ascii
```

---

## Common Crash Patterns

### NULL Pointer Dereference
```
Registers show: Register = 0x0
addr2line shows: Dereference instruction (mov, add, etc.)
Fix: Add null pointer check
```

### Stack Overflow
```
Registers show: SP near stack limit or unmapped region
Memory map shows: SEGV in stack segment near boundary
Fix: Reduce stack usage or increase stack size
```

### Buffer Overflow
```
Registers show: Register contains modified address
Memory map shows: SEGV in BSS/DATA segment
Fix: Add bounds checking or use safer functions
```

### Use-After-Free
```
Registers show: Address points to freed memory
Memory map shows: SEGV in heap region (freed)
Fix: Don't use pointers after free()
```

---

## Files and Their Purpose

### Core Documentation

**REGISTER_DUMP_GUIDE.md** (15 KB)
- Overview of register dumping
- Architecture support matrix
- Best practices and patterns
- Debugging workflow
- Production integration tips

**REGISTER_EXAMPLES.md** (20 KB)
- Code snippets for every architecture
- Complete register field mappings
- Portable macro approach
- Reusable crash_handler.h template
- Compilation commands for cross-compilation

### Tools

**crash_demo.c**
- Intentionally crashes with NULL pointer
- Automatically captures registers and memory map
- Shows best practices for signal handlers
- Multi-architecture support

**parse_registers.py**
- Parses crash_dump_*.regs files
- Extracts key registers (PC, SP, FP, etc.)
- Shows integration with memmap_analyzer
- Python 3 only, no dependencies

**complete_crash_analysis.sh**
- Automated 6-step workflow:
  1. Compile with debug symbols
  2. Run and capture crash
  3. Extract registers
  4. Show memory segments
  5. Analyze crash location
  6. Get call stack

### Real-World Example

**REAL_WORLD_ANALYSIS.md** (14 KB)
- Complete crash from start to finish
- GDB commands and output
- Memory segment analysis
- Root cause identification
- Fix demonstration
- Verification steps

---

## Debugging Commands Reference

```bash
# Capture register dump
./crash_demo
cat crash_dump_*.regs

# Parse registers
python3 parse_registers.py

# Memory analysis
../memmap_analyzer.py crash_dump_*.maps --segments
../memmap_analyzer.py crash_dump_*.maps --pc 0xADDRESS
../memmap_analyzer.py crash_dump_*.maps --ascii

# Source code lookup
addr2line -e ./crash_demo 0xADDRESS

# GDB interactive
gdb ./crash_demo
(gdb) run
(gdb) where
(gdb) info registers
(gdb) frame 0
(gdb) locals

# Disassembly
objdump -d ./crash_demo | grep -A5 "555555555352"

# Full workflow
./complete_crash_analysis.sh
```

---

## Key Concepts

**CPU Context (ucontext_t)**
- Captured by kernel on signal delivery
- Contains all registers at crash time
- Must use SA_SIGINFO to access in signal handler

**Signal Handler Signature**
```c
void handler(int sig, siginfo_t *info, void *ctx)
```
- `sig`: Signal number (11 = SIGSEGV)
- `info`: Signal information (fault address, etc.)
- `ctx`: CPU context (cast to ucontext_t*)

**Register Field Names**
- x86-64: `gregs[index]` array with numeric indices
- ARM64: `regs[0-30]`, `pc`, `sp` special fields
- ARM: `arm_pc`, `arm_sp`, `arm_fp`, `arm_r[0-15]`

**Debug Symbol Requirements**
- Compile with `-g` flag
- Don't strip symbols in production
- Keep binaries with debug symbols for analysis

---

## Architecture Specific Details

### x86-64 gregs[] Indices
```
[0-7]:   R8-R15
[8]:     RDI
[9]:     RSI
[10]:    RBP
[11]:    RBX
[12]:    RDX
[13]:    RAX
[14]:    RCX
[15]:    RSP
[16]:    RIP
```

### ARM64 Register Layout
```
regs[0-7]:    X0-X7 (arguments)
regs[8-18]:   X8-X18 (temps/saved)
regs[19-28]:  X19-X28 (saved)
regs[29]:     X29 (FP)
regs[30]:     X30 (LR)
pc:           Program Counter
sp:           Stack Pointer
```

---

## Production Integration

To add register dumping to your application:

1. **Create reusable header:**
   ```c
   #include "crash_handler.h"
   install_crash_handler();
   ```

2. **Minimal overhead:**
   - Single signal handler setup
   - Only runs on crash
   - ~50 lines of code

3. **No dependencies:**
   - Uses standard library only
   - Works on all Linux systems
   - No third-party libraries needed

4. **Automatic collection:**
   - No manual interaction required
   - Works in production
   - Captures full context

---

## See Also

- [REGISTER_DUMP_GUIDE.md](REGISTER_DUMP_GUIDE.md) — Complete usage guide
- [REGISTER_EXAMPLES.md](REGISTER_EXAMPLES.md) — Architecture-specific code
- [REAL_WORLD_ANALYSIS.md](REAL_WORLD_ANALYSIS.md) — Full example analysis
- [parse_registers.py](parse_registers.py) — Register extraction tool
- [crash_demo.c](crash_demo.c) — Working example program
- [complete_crash_analysis.sh](complete_crash_analysis.sh) — Automated workflow

---

## Getting Started

```bash
# 1. Read this file first (you are here)

# 2. Look at the example program
cat crash_demo.c

# 3. Compile and run
gcc -g -O0 crash_demo.c -o crash_demo
./crash_demo

# 4. Extract registers
python3 parse_registers.py

# 5. Analyze with memory map
../memmap_analyzer.py crash_dump_*.maps --pc 0xADDRESS

# 6. Find source line
addr2line -e ./crash_demo 0xADDRESS

# 7. Automated workflow
./complete_crash_analysis.sh
```

---

**Last Updated:** 2026-01-31  
**Architecture Support:** x86-64, ARM64, ARM, MIPS, PowerPC  
**Tested On:** Linux kernel 5.x+, glibc 2.30+
