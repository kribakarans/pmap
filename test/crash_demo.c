#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/ucontext.h>

/* Print register values based on architecture */
void print_registers(ucontext_t *context, FILE *fp) {
    if (!context) return;
    
    mcontext_t *mctx = &context->uc_mcontext;
    
#ifdef __x86_64__
    /* x86-64 registers using gregs array indices */
    fprintf(fp, "=== CPU REGISTERS (x86-64) ===\n");
    fprintf(fp, "rip: %016llx (Program Counter - where crash occurred)\n", (unsigned long long)mctx->gregs[16]);  /* REG_RIP */
    fprintf(fp, "rsp: %016llx (Stack Pointer)\n", (unsigned long long)mctx->gregs[15]);  /* REG_RSP */
    fprintf(fp, "rbp: %016llx (Frame Pointer)\n", (unsigned long long)mctx->gregs[10]);  /* REG_RBP */
    fprintf(fp, "rax: %016llx\n", (unsigned long long)mctx->gregs[13]);  /* REG_RAX */
    fprintf(fp, "rbx: %016llx\n", (unsigned long long)mctx->gregs[11]);  /* REG_RBX */
    fprintf(fp, "rcx: %016llx\n", (unsigned long long)mctx->gregs[14]);  /* REG_RCX */
    fprintf(fp, "rdx: %016llx\n", (unsigned long long)mctx->gregs[12]);  /* REG_RDX */
    fprintf(fp, "rsi: %016llx\n", (unsigned long long)mctx->gregs[9]);   /* REG_RSI */
    fprintf(fp, "rdi: %016llx\n", (unsigned long long)mctx->gregs[8]);   /* REG_RDI */
    fprintf(fp, "r8:  %016llx\n", (unsigned long long)mctx->gregs[0]);   /* REG_R8 */
    fprintf(fp, "r9:  %016llx\n", (unsigned long long)mctx->gregs[1]);   /* REG_R9 */
    fprintf(fp, "r10: %016llx\n", (unsigned long long)mctx->gregs[2]);   /* REG_R10 */
    fprintf(fp, "r11: %016llx\n", (unsigned long long)mctx->gregs[3]);   /* REG_R11 */
    fprintf(fp, "r12: %016llx\n", (unsigned long long)mctx->gregs[4]);   /* REG_R12 */
    fprintf(fp, "r13: %016llx\n", (unsigned long long)mctx->gregs[5]);   /* REG_R13 */
    fprintf(fp, "r14: %016llx\n", (unsigned long long)mctx->gregs[6]);   /* REG_R14 */
    fprintf(fp, "r15: %016llx\n", (unsigned long long)mctx->gregs[7]);   /* REG_R15 */
    
#elif defined(__aarch64__)
    /* ARM64 registers */
    fprintf(fp, "=== CPU REGISTERS (ARM64) ===\n");
    fprintf(fp, "pc  : %016llx (Program Counter)\n", context->uc_mcontext.pc);
    fprintf(fp, "lr  : %016llx (Link Register)\n", context->uc_mcontext.regs[30]);
    fprintf(fp, "sp  : %016llx (Stack Pointer)\n", context->uc_mcontext.sp);
    for (int i = 0; i < 31; i++) {
        fprintf(fp, "x%-2d: %016llx", i, context->uc_mcontext.regs[i]);
        if ((i + 1) % 2 == 0) fprintf(fp, "\n");
        else fprintf(fp, "  ");
    }
    
#elif defined(__arm__)
    /* ARM (32-bit) registers */
    fprintf(fp, "=== CPU REGISTERS (ARM 32-bit) ===\n");
    fprintf(fp, "pc  : %08x (Program Counter)\n", (unsigned int)mctx->arm_pc);
    fprintf(fp, "lr  : %08x (Link Register)\n", (unsigned int)mctx->arm_lr);
    fprintf(fp, "sp  : %08x (Stack Pointer)\n", (unsigned int)mctx->arm_sp);
    fprintf(fp, "fp  : %08x (Frame Pointer)\n", (unsigned int)mctx->arm_fp);
    for (int i = 0; i < 16; i++) {
        fprintf(fp, "r%-2d: %08x", i, (unsigned int)mctx->arm_r[i]);
        if ((i + 1) % 4 == 0) fprintf(fp, "\n");
        else fprintf(fp, "  ");
    }
    
#else
    fprintf(fp, "=== CPU REGISTERS (unknown architecture) ===\n");
    fprintf(fp, "Register dumping not supported for this architecture\n");
#endif
    
    fprintf(fp, "\n");
}

/* Signal handler to capture memory map and registers */
void signal_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *context = (ucontext_t *)ctx;
    char cmd[512];
    char regfile[256];
    FILE *fp;
    
    printf("\n[CRASH HANDLER] Signal %d caught at PID %d\n", sig, getpid());
    
    /* Save registers to file */
    sprintf(regfile, "crash_dump_%d.regs", getpid());
    fp = fopen(regfile, "w");
    if (fp) {
        fprintf(fp, "=== CRASH CONTEXT ===\n");
        fprintf(fp, "Signal: %d (%s)\n", sig, 
                sig == SIGSEGV ? "SIGSEGV" : 
                sig == SIGABRT ? "SIGABRT" : 
                sig == SIGFPE ? "SIGFPE" : "Unknown");
        fprintf(fp, "PID: %d\n\n", getpid());
        
        print_registers(context, fp);
        
        fclose(fp);
        printf("[CRASH HANDLER] Register dump saved to %s\n", regfile);
    }
    
    /* Capture memory map */
    sprintf(cmd, "cat /proc/%d/maps > crash_dump_%d.maps 2>&1", getpid(), getpid());
    system(cmd);
    printf("[CRASH HANDLER] Memory map saved to crash_dump_%d.maps\n", getpid());
    
    exit(1);
}

/* Intentionally vulnerable function */
void vulnerable_function(int *ptr) {
    printf("  → vulnerable_function: attempting to dereference invalid pointer\n");
    fflush(stdout);
    
    /* This will crash if ptr is NULL or invalid */
    *ptr = 42;
    printf("  (this line will never execute)\n");
}

/* Intermediate function in the call stack */
void intermediate_function(void) {
    printf(" → intermediate_function: calling vulnerable_function\n");
    fflush(stdout);
    
    int *bad_pointer = NULL;  /* This will cause the crash */
    vulnerable_function(bad_pointer);
}

/* Function that triggers SIGABRT */
void abort_function(void) {
    printf(" → abort_function: triggering SIGABRT\n");
    fflush(stdout);
    
    /* NOTE: SIGABRT is always delivered asynchronously by the kernel,
     * so the PC will point to libc's signal delivery code, not user code.
     * For a crash that points to user code, use SIGSEGV or SIGFPE instead.
     */
    raise(SIGABRT);
    
    printf("  (this line will never execute)\n");
}

/* Function that triggers SIGFPE - this WILL point to user code */
void divide_by_zero_function(void) {
    printf(" → divide_by_zero_function: triggering SIGFPE\n");
    fflush(stdout);
    
    volatile int zero = 0;
    volatile int result = 42 / zero;  /* This instruction will trigger SIGFPE */
    
    printf("  Result: %d (this line will never execute)\n", result);
}

/* Entry point of a crash chain */
void entry_function(void) {
    printf("→ entry_function: calling intermediate_function\n");
    fflush(stdout);
    
    intermediate_function();
}

int main(int argc, char *argv[]) {
    printf("=== Linux Crash Demo Program ===\n");
    printf("PID: %d\n", getpid());
    printf("This program will intentionally crash to demonstrate crash analysis.\n\n");
    
    /* Install signal handlers with context (SA_SIGINFO) */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;
    
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    
    printf("Signal handlers installed (with register capture).\n");
    printf("Starting crash chain...\n\n");
    fflush(stdout);
    
    /* Simulate some work before crashing */
    for (int i = 0; i < 3; i++) {
        printf("Iteration %d...\n", i + 1);
        sleep(1);
    }
    
    printf("\nTrigger the crash:\n");
    fflush(stdout);
    
    /* Choose crash type based on argument */
    if (argc > 1 && strcmp(argv[1], "abort") == 0) {
        printf("→ Triggering SIGABRT...\n");
        fflush(stdout);
        abort_function();
    } else if (argc > 1 && strcmp(argv[1], "divzero") == 0) {
        printf("→ Triggering SIGFPE (divide by zero)...\n");
        fflush(stdout);
        divide_by_zero_function();
    } else {
        printf("→ Triggering SIGSEGV (NULL pointer dereference)...\n");
        fflush(stdout);
        entry_function();
    }
    
    /* Never reached */
    return 0;
}
