# Register Dump Code Examples by Architecture

This file shows the exact code needed to capture and dump registers on different Linux architectures.

## Generic Pattern (All Architectures)

```c
#include <signal.h>
#include <ucontext.h>
#include <stdio.h>

void signal_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *context = (ucontext_t *)ctx;
    
    /* Your register extraction code here */
    
    exit(1);
}

int main() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;  /* CRITICAL: Enable context parameter */
    
    sigaction(SIGSEGV, &sa, NULL);
}
```

## x86-64 (Intel/AMD 64-bit)

Register locations in `gregs[]` array:

```c
#ifdef __x86_64__
    mcontext_t *mctx = &context->uc_mcontext;
    
    /* Program counter and stack */
    unsigned long pc  = mctx->gregs[16];  /* RIP - instruction pointer */
    unsigned long sp  = mctx->gregs[15];  /* RSP - stack pointer */
    unsigned long fp  = mctx->gregs[10];  /* RBP - frame pointer */
    
    /* General purpose registers */
    unsigned long rax = mctx->gregs[13];  /* Return value */
    unsigned long rbx = mctx->gregs[11];  /* Callee-saved */
    unsigned long rcx = mctx->gregs[14];  /* Function argument */
    unsigned long rdx = mctx->gregs[12];  /* Function argument */
    unsigned long rsi = mctx->gregs[9];   /* Function argument */
    unsigned long rdi = mctx->gregs[8];   /* Function argument */
    
    /* R8-R15 registers */
    unsigned long r8  = mctx->gregs[0];   /* Function argument */
    unsigned long r9  = mctx->gregs[1];   /* Function argument */
    unsigned long r10 = mctx->gregs[2];   /* Scratch */
    unsigned long r11 = mctx->gregs[3];   /* Scratch */
    unsigned long r12 = mctx->gregs[4];   /* Callee-saved */
    unsigned long r13 = mctx->gregs[5];   /* Callee-saved */
    unsigned long r14 = mctx->gregs[6];   /* Callee-saved */
    unsigned long r15 = mctx->gregs[7];   /* Callee-saved */
    
    printf("RIP: 0x%016lx\n", pc);
    printf("RSP: 0x%016lx\n", sp);
#endif
```

Example output:
```
RIP: 0x0000555555555352 (where crash happened)
RSP: 0x00007fffffffdb30 (current stack position)
RBP: 0x00007fffffffdb40 (function frame)
RDI: 0x0000000000000000 (NULL pointer passed)
RAX: 0x0000000000000000 (zero return value)
```

## ARM64 (AArch64 - 64-bit ARM)

Register locations in `regs[]` array and special fields:

```c
#elif defined(__aarch64__)
    /* PC and special registers */
    unsigned long pc = context->uc_mcontext.pc;   /* Program counter */
    unsigned long sp = context->uc_mcontext.sp;   /* Stack pointer */
    unsigned long lr = context->uc_mcontext.regs[30];  /* Link register (x30) */
    
    /* General purpose registers (x0-x28) */
    unsigned long *regs = context->uc_mcontext.regs;
    
    unsigned long x0  = regs[0];   /* First arg, return value */
    unsigned long x1  = regs[1];   /* Second arg */
    unsigned long x2  = regs[2];   /* Third arg */
    unsigned long x3  = regs[3];   /* Fourth arg */
    unsigned long x7  = regs[7];   /* Arg 8, syscall number */
    
    unsigned long x29 = regs[29];  /* Frame pointer */
    unsigned long x30 = regs[30];  /* Link register */
    
    printf("PC: 0x%016lx\n", pc);
    printf("LR: 0x%016lx\n", lr);
    printf("SP: 0x%016lx\n", sp);
    printf("X0: 0x%016lx (first arg/return)\n", x0);
    
    /* Print all registers */
    for (int i = 0; i < 31; i++) {
        printf("x%-2d: 0x%016lx\n", i, regs[i]);
    }
#endif
```

Example output:
```
PC: 0x000000000000a5c0
LR: 0x000000000000a4f0
SP: 0x0000ffffc5b02350
X0: 0x0000000000000000
x0 : 0x0000555555557000
x1 : 0x0000000000000001
... (x2-x30 follow)
```

## ARM (32-bit ARMv7)

Register locations in `arm_*` fields:

```c
#elif defined(__arm__)
    /* PC and stack */
    unsigned long pc  = (unsigned long)context->uc_mcontext.arm_pc;
    unsigned long sp  = (unsigned long)context->uc_mcontext.arm_sp;
    unsigned long fp  = (unsigned long)context->uc_mcontext.arm_fp;
    unsigned long lr  = (unsigned long)context->uc_mcontext.arm_lr;
    unsigned long ip  = (unsigned long)context->uc_mcontext.arm_ip;
    
    /* General purpose registers (r0-r15) */
    unsigned long *r = context->uc_mcontext.arm_r;
    
    unsigned long r0  = r[0];   /* First arg, return */
    unsigned long r1  = r[1];   /* Second arg */
    unsigned long r2  = r[2];   /* Third arg */
    unsigned long r3  = r[3];   /* Fourth arg */
    unsigned long r12 = r[12];  /* Intra-procedure scratch */
    
    printf("PC: 0x%08x (Program Counter)\n", (unsigned int)pc);
    printf("LR: 0x%08x (Link Register)\n", (unsigned int)lr);
    printf("SP: 0x%08x (Stack Pointer)\n", (unsigned int)sp);
    printf("FP: 0x%08x (Frame Pointer)\n", (unsigned int)fp);
    
    for (int i = 0; i < 16; i++) {
        printf("r%-2d: 0x%08x\n", i, (unsigned int)r[i]);
    }
#endif
```

Example output:
```
PC: 0x00008a5c (where crash happened)
LR: 0x00008a4f (return address)
SP: 0xbef02350 (stack top)
FP: 0xbef02378 (frame boundary)
r0 : 0x00000000 (NULL pointer)
```

## MIPS (32-bit and 64-bit)

Register locations:

```c
#elif defined(__mips__)
    unsigned long *gregs = (unsigned long *)context->uc_mcontext.gregs;
    
    /* MIPS specific registers */
    unsigned long pc = context->uc_mcontext.pc;
    unsigned long sp = gregs[MIPS_REG_SP];   /* $sp = $29 */
    unsigned long fp = gregs[MIPS_REG_FP];   /* $fp = $30 */
    unsigned long ra = gregs[MIPS_REG_RA];   /* $ra = $31 */
    
    unsigned long a0 = gregs[MIPS_REG_A0];   /* First arg */
    unsigned long a1 = gregs[MIPS_REG_A1];   /* Second arg */
    
    printf("PC: 0x%lx\n", pc);
    printf("RA: 0x%lx\n", ra);
    printf("SP: 0x%lx\n", sp);
#endif
```

## PowerPC (32-bit and 64-bit)

Register locations:

```c
#elif defined(__powerpc__)
    unsigned long *regs = (unsigned long *)context->uc_mcontext.gp_regs;
    
    unsigned long pc  = regs[32];  /* NIP - Next Instruction Pointer */
    unsigned long sp  = regs[1];   /* R1 - Stack Pointer */
    unsigned long fp  = regs[31];  /* R31 - Frame Pointer */
    
    unsigned long r0  = regs[0];
    unsigned long r3  = regs[3];   /* First arg, return value */
    unsigned long r4  = regs[4];   /* Second arg */
    
    printf("NIP: 0x%lx\n", pc);
    printf("R1:  0x%lx\n", sp);
    printf("R31: 0x%lx\n", fp);
#endif
```

## Portable Macro Approach

For maximum portability, use this pattern:

```c
#define GET_PC(ctx) \
    ({ unsigned long __pc; \
       __builtin_choose_expr(__is_x86_64, \
           (__pc = ((ucontext_t*)ctx)->uc_mcontext.gregs[16]), \
           __builtin_choose_expr(__is_arm64, \
               (__pc = ((ucontext_t*)ctx)->uc_mcontext.pc), \
               (__pc = 0))); \
       __pc; })

#define GET_SP(ctx) \
    ({ unsigned long __sp; \
       __builtin_choose_expr(__is_x86_64, \
           (__sp = ((ucontext_t*)ctx)->uc_mcontext.gregs[15]), \
           __builtin_choose_expr(__is_arm64, \
               (__sp = ((ucontext_t*)ctx)->uc_mcontext.sp), \
               (__sp = 0))); \
       __sp; })

void signal_handler(int sig, siginfo_t *info, void *ctx) {
    unsigned long pc = GET_PC(ctx);
    unsigned long sp = GET_SP(ctx);
    printf("PC: 0x%lx, SP: 0x%lx\n", pc, sp);
}
```

## Complete Example Template

Save as `crash_handler.h`:

```c
#ifndef CRASH_HANDLER_H
#define CRASH_HANDLER_H

#include <signal.h>
#include <ucontext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned long pc;   /* Program Counter */
    unsigned long sp;   /* Stack Pointer */
    unsigned long fp;   /* Frame Pointer */
    unsigned long lr;   /* Link Register (ARM) */
    unsigned long arg0; /* First argument */
    unsigned long ret;  /* Return value */
} crash_regs_t;

static crash_regs_t extract_registers(ucontext_t *ctx) {
    crash_regs_t regs = {0};
    mcontext_t *mctx = &ctx->uc_mcontext;
    
#ifdef __x86_64__
    regs.pc = mctx->gregs[16];
    regs.sp = mctx->gregs[15];
    regs.fp = mctx->gregs[10];
    regs.arg0 = mctx->gregs[8];   /* rdi */
    regs.ret = mctx->gregs[13];   /* rax */
#elif defined(__aarch64__)
    regs.pc = ctx->uc_mcontext.pc;
    regs.sp = ctx->uc_mcontext.sp;
    regs.fp = ctx->uc_mcontext.regs[29];
    regs.lr = ctx->uc_mcontext.regs[30];
    regs.arg0 = ctx->uc_mcontext.regs[0];
    regs.ret = ctx->uc_mcontext.regs[0];
#elif defined(__arm__)
    regs.pc = (unsigned long)ctx->uc_mcontext.arm_pc;
    regs.sp = (unsigned long)ctx->uc_mcontext.arm_sp;
    regs.fp = (unsigned long)ctx->uc_mcontext.arm_fp;
    regs.lr = (unsigned long)ctx->uc_mcontext.arm_lr;
    regs.arg0 = ctx->uc_mcontext.arm_r[0];
    regs.ret = ctx->uc_mcontext.arm_r[0];
#endif
    
    return regs;
}

static void signal_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *context = (ucontext_t *)ctx;
    crash_regs_t regs = extract_registers(context);
    
    printf("=== CRASH HANDLER ===\n");
    printf("Signal: %d\n", sig);
    printf("PC: 0x%lx\n", regs.pc);
    printf("SP: 0x%lx\n", regs.sp);
    printf("FP: 0x%lx\n", regs.fp);
    
    exit(1);
}

static void install_crash_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;
    
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
}

#endif
```

Usage:

```c
#include "crash_handler.h"

int main() {
    install_crash_handler();
    
    int *p = NULL;
    *p = 42;  /* Will be caught by handler */
    
    return 0;
}
```

## Compilation

```bash
# x86-64
gcc -g -O0 myapp.c -o myapp

# ARM64
aarch64-linux-gnu-gcc -g -O0 myapp.c -o myapp

# ARM (32-bit)
arm-linux-gnueabihf-gcc -g -O0 myapp.c -o myapp

# Cross-compile hint: make sure ucontext.h is available
echo '#include <ucontext.h>' | gcc -E -  # Test availability
```

## Verifying Capture Works

```bash
# Compile
gcc -g -O0 test.c -o test

# Run (captures registers and memory map)
./test

# Check output files
ls -la crash_dump_*
cat crash_dump_*.regs
cat crash_dump_*.maps

# Parse with Python
python3 parse_registers.py
```

## Key Differences by Architecture

| Architecture | PC Field | SP Field | FP Field | Call Path |
|--------------|----------|----------|----------|-----------|
| x86-64 | gregs[16] (RIP) | gregs[15] (RSP) | gregs[10] (RBP) | Stack grows down |
| ARM64 | uc_mcontext.pc | uc_mcontext.sp | regs[29] | Stack grows down |
| ARM 32 | arm_pc | arm_sp | arm_fp | Stack grows down |
| MIPS | pc field | gregs[MIPS_REG_SP] | gregs[MIPS_REG_FP] | Stack grows down |
| PowerPC | gp_regs[32] | gp_regs[1] | gp_regs[31] | Stack grows down |

## Debugging Captured Registers

```bash
# Show register dump
cat crash_dump_2755982.regs

# Extract PC value
grep "rip:" crash_dump_*.regs | head -1

# Use with memmap_analyzer
./memmap_analyzer.py crash_dump_*.maps --pc 0x555555555352

# Lookup in source
addr2line -e ./myapp 0x555555555352

# Disassemble at crash location
objdump -d ./myapp | grep -A5 "555555555352"
```

## See Also

- Linux kernel ucontext.h documentation
- GDB documentation on register context
- CPU architecture ABI documentation (x86-64, ARM, etc.)
- `man signal-safety` for signal handler restrictions
