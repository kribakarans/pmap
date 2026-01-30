#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/* Signal handler to capture memory map before exit */
void signal_handler(int sig) {
    char cmd[512];
    printf("\n[CRASH HANDLER] Signal %d caught at PID %d\n", sig, getpid());
    
    /* Capture memory map */
    sprintf(cmd, "cat /proc/%d/maps > crash_dump_%d.maps 2>&1", getpid(), getpid());
    system(cmd);
    printf("[CRASH HANDLER] Memory map saved to crash_dump_%d.maps\n", getpid());
    
    /* Print where we crashed */
    printf("[CRASH HANDLER] Signal: %s\n", sig == SIGSEGV ? "SIGSEGV" : "SIGABRT");
    
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
    
    /* Install signal handlers */
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGFPE, signal_handler);
    
    printf("Signal handlers installed.\n");
    printf("Starting crash chain...\n\n");
    fflush(stdout);
    
    /* Simulate some work before crashing */
    for (int i = 0; i < 3; i++) {
        printf("Iteration %d...\n", i + 1);
        sleep(1);
    }
    
    printf("\nTrigger the crash:\n");
    fflush(stdout);
    
    /* This will trigger a segmentation fault */
    entry_function();
    
    /* Never reached */
    return 0;
}
