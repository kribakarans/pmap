# Understanding Linux Process Memory Maps in Crash Analysis

## Introduction

When a Linux process crashes, debugging the root cause requires understanding how the process's virtual memory was organized at the time of failure. The `/proc/<pid>/maps` file is a fundamental artifact that captures this memory organization, providing a detailed snapshot of every active memory region in a running (or crashed) process.

A **memory map** is a structured listing of all virtual address regions allocated to a process, including their permissions, backing storage, and associated binaries or files. For systems programmers, embedded Linux developers, and crash-analysis engineers, the memory map is often the first document to examine after a segmentation fault, abort signal, or watchdog timer reset.

### Why Memory Maps Matter

Memory maps serve several critical purposes in crash analysis:

- **Locating the crash site**: By intersecting a crash address (typically stored in the Program Counter register) with memory segments, you can immediately identify which binary or library caused the failure.
- **Understanding memory layout**: Maps reveal the complete virtual address space, showing where code, data, heap, stack, and shared libraries reside.
- **Security assessment**: Maps expose dangerous conditions such as writable code sections or misaligned stack boundaries.
- **Decoding register values**: Crash dumps often include register snapshots (PC, LR, SP, FP). Memory maps allow you to resolve register addresses to human-readable binary offsets.

### Typical Crash Scenarios

Memory maps are invaluable in several common failure modes:

- **Segmentation faults (SIGSEGV)**: A process attempts to read/write/execute an unmapped address or violates region permissions.
- **Illegal instruction (SIGILL)**: Execution jumps to an invalid code region, identified via PC address lookup in the map.
- **Stack overflow**: The stack pointer advances beyond the stack boundary, which the map clearly shows.
- **Watchdog timer resets**: Embedded systems often capture memory maps before forced resets; maps help correlate hang addresses with stalled code regions.
- **Silent data corruption**: Maps help identify which data structures occupy specific heap ranges when corruption is suspected.

---

## Basic Outline of a Crash Memory Dump

### Where Memory Map Data Comes From

The `/proc/<pid>/maps` file is maintained by the Linux kernel and is readable by any user with permission to inspect the process. It is updated continuously as the process maps and unmaps memory.

When a process crashes, the map can be obtained in several ways:

- **Debugger breakpoint**: Developers using `gdb` or similar debuggers can inspect `/proc/<pid>/maps` while the process is stopped.
- **Core dump analysis**: When a core dump is generated (via `ulimit -c unlimited`), it embeds a snapshot of the memory map from the moment of crash.
- **Logging frameworks**: Crash-handler libraries often log `/proc/<pid>/maps` to syslog or local files before terminating.
- **System monitoring tools**: Embedded Linux systems may capture maps periodically or on-demand via `cat /proc/<pid>/maps > crash_log.txt`.

### How Memory Maps Appear in Crash Logs

A typical crash log contains:

1. **Process metadata** (PID, executable name, timestamp)
2. **Register snapshot** (PC, LR, SP, FP on ARM; RIP, RSP, RBP on x86-64)
3. **Memory map listing** (the output of `/proc/<pid>/maps`)
4. **Optional backtrace** (return addresses extracted from the stack)

Example structure:

```
[CRASH] Process: /usr/bin/myapp PID: 1234 Signal: SIGSEGV
[CRASH] PC=0xf79e245c LR=0xf79e7f10 SP=0xff8b0000 FP=0xff8b0010
[CRASH] Memory map follows:
f6a2f000-f6a30000 r-xp 00000000 b3:04 6432 /lib/libc-2.28.so
f6a30000-f6a31000 rw-p 00001000 b3:04 6432 /lib/libc-2.28.so
...
```

The memory map is paired with registers because they are mutually dependent: the map tells you *where* memory is, and the registers tell you *what was executing* when the crash occurred.

---

## Anatomy of a Memory Map Entry

Each line in `/proc/<pid>/maps` represents a contiguous region of virtual memory. Understanding the structure is essential for extracting debugging information.

### Example Entry

```
f6833000-f6838000 r-xp 00000000 b3:04 6432 /lib/libatomic.so.1.2.0
```

### Field Breakdown

| Field | Example | Meaning |
|-------|---------|---------|
| **Start address** | `f6833000` | Hexadecimal virtual address of region start |
| **End address** | `f6838000` | Hexadecimal virtual address of region end (exclusive) |
| **Permissions** | `r-xp` | Read (r), Write (w), Execute (x), Private (p) or Shared (s) |
| **Offset** | `00000000` | Byte offset into the backing file (0 for anonymous) |
| **Device** | `b3:04` | Major and minor device number (e.g., disk partition) |
| **Inode** | `6432` | Inode number of the backing file |
| **Pathname** | `/lib/libatomic.so.1.2.0` | Full path to the backing file, or `[anon]` for anonymous |

### Interpreting the Example

```
f6833000-f6838000 r-xp 00000000 b3:04 6432 /lib/libatomic.so.1.2.0
```

- **Size**: `0xf6838000 - 0xf6833000 = 0x5000 = 20,480 bytes`
- **Purpose**: Executable code (r-xp) from a shared library
- **Backing**: Loaded from `/lib/libatomic.so.1.2.0` starting at file offset 0
- **Scope**: Private mapping (not shared with other processes)

### Permission String Format

The permission field always has exactly 4 characters:

- **Position 1 (r/-)**: Readable? `r` = yes, `-` = no
- **Position 2 (w/-)**: Writable? `w` = yes, `-` = no
- **Position 3 (x/-)**: Executable? `x` = yes, `-` = no
- **Position 4 (p/s)**: Private or Shared? `p` = private (COW), `s` = shared

### Common Permission Patterns

| Pattern | Interpretation |
|---------|-----------------|
| `r-xp` | Executable code segment (from binary or library) |
| `r--p` | Read-only data (constants, string tables) |
| `rw-p` | Writable data (globals, static storage, heap) |
| `---p` | Guard page or unmapped region |
| `rwxp` | Writable AND executable (suspicious, rare) |

### Anonymous vs. File-Backed

- **File-backed**: Pathname is a real filesystem path (e.g., `/lib/libc.so`). The kernel loads data from this file.
- **Anonymous**: Pathname is `[anon]` or empty. Memory is allocated from zero-initialized kernel buffers. Common for heap, stack, and dynamically allocated memory.

---

## Common Memory Segment Types

Modern processes typically contain the following segment types, each serving a distinct purpose:

### Code Segment (.text)

- **Permissions**: `r-xp` (readable, executable, private)
- **Backing**: File-backed from binary or shared library
- **Purpose**: Machine instructions executed by the CPU
- **Example**: `0x08048000-0x0804a000 r-xp 00000000 08:01 1234 /usr/bin/myapp`

### Read-Only Data Segment (.rodata)

- **Permissions**: `r--p` (readable, private)
- **Backing**: File-backed
- **Purpose**: Immutable constants, string literals, vtables
- **Example**: `0x0804a000-0x0804c000 r--p 00002000 08:01 1234 /usr/bin/myapp`

### Initialized Data Segment (.data)

- **Permissions**: `rw-p` (readable, writable, private)
- **Backing**: File-backed
- **Purpose**: Global and static variables with explicit initializers
- **Example**: `0x0804c000-0x0804d000 rw-p 00004000 08:01 1234 /usr/bin/myapp`

### Uninitialized Data Segment (BSS)

- **Permissions**: `rw-p` (readable, writable, private)
- **Backing**: Anonymous (appears as `[anon]`)
- **Purpose**: Global and static variables implicitly initialized to zero
- **Note**: Often appears immediately after `.data` or with a specific `[anon]` label
- **Example**: `0x0804d000-0x0804e000 rw-p 00000000 00:00 0 [anon]`

### Heap Segment

- **Permissions**: `rw-p` (readable, writable, private)
- **Backing**: Anonymous
- **Purpose**: Dynamically allocated memory (`malloc`, `new`)
- **Labeled as**: `[heap]`
- **Example**: `0x0804e000-0x08050000 rw-p 00000000 00:00 0 [heap]`

### Stack Segment

- **Permissions**: `rw-p` (readable, writable, private)
- **Backing**: Anonymous
- **Purpose**: Function call frames, local variables, return addresses
- **Labeled as**: `[stack]`
- **Location**: Typically at the high end of the address space
- **Example**: `0xbffdf000-0xc0000000 rw-p 00000000 00:00 0 [stack]`

### Shared Library Segments

Shared libraries (`.so` files) appear as multiple segments:

- **Code section**: `r-xp` (from the `.text` section of the `.so`)
- **Data section**: `rw-p` (from the `.data` and BSS sections)

Each library may span multiple address ranges:

```
f6a2f000-f6a6e000 r-xp 00000000 b3:04 1024 /lib/libc-2.28.so
f6a6e000-f6a72000 rw-p 0003f000 b3:04 1024 /lib/libc-2.28.so
```

### Special Segments

- **VDSO** (`[vdso]`): Virtual Dynamic Shared Object, kernel-managed memory for fast syscalls
- **VSYSCALL** (`[vsyscall]`): Deprecated fast syscall interface on x86-64
- **Guard pages**: Unmapped regions (e.g., between stack and heap) used to catch overflow

---

## Skeleton of a Process Memory Layout

Virtual memory in a typical 32-bit process is organized hierarchically from low addresses (0x00000000) to high addresses (0xffffffff). A conceptual skeleton is shown below:

```
High Memory (0xffffffff)
┌─────────────────────────────┐
│      Kernel Space           │  Not directly accessible from userspace
├─────────────────────────────┤
│ [stack]                     │  Stack segment
│ (grows downward)            │
├─────────────────────────────┤
│                             │
│ (gap, unmapped)             │  Guard region
│                             │
├─────────────────────────────┤
│ Shared Libraries            │  Multiple .so files
│ (/lib/libc.so, etc.)        │
│ (grows variable)            │
├─────────────────────────────┤
│ [heap]                      │  Heap segment
│ (grows upward)              │
├─────────────────────────────┤
│ BSS / Data                  │  .bss and .data sections
│ (rw-p)                      │
├─────────────────────────────┤
│ .rodata                     │  Read-only data
│ (r--p)                      │
├─────────────────────────────┤
│ .text (Code)                │  Code segment
│ (r-xp)                      │
├─────────────────────────────┤
│ Program Headers             │  ELF metadata
│ (r-xp)                      │
├─────────────────────────────┤
│ [vdso]                      │  Virtual Dynamic Shared Object
│                             │
└─────────────────────────────┘
Low Memory (0x00000000)
```

### Key Observations

- **Address ordering**: Not all processes follow this exact layout; the kernel may randomize addresses (ASLR).
- **Multiple .so regions**: Each shared library typically occupies several non-contiguous segments (code, initialized data, BSS).
- **Heap grows upward**: Heap allocations expand toward higher addresses.
- **Stack grows downward**: As the stack grows, the stack pointer decreases (on most architectures).
- **Gaps**: Unmapped regions between segments serve as guard zones to catch buffer overflows.

---

## Memory Maps in Crash Debugging

### Resolving Crash Addresses to Memory Regions

When a crash occurs, the CPU's Program Counter (PC) register holds the address of the instruction that caused the failure. The memory map allows you to determine:

1. **Which region owns the PC address?**
   - Search the memory map for an entry where `start ≤ PC < end`
   
2. **What binary/library does the region belong to?**
   - Check the pathname field of the matching entry
   
3. **What is the offset within the binary?**
   - Compute: `offset = PC - start`

### Example: Resolving a Crash Address

**Given:**
- PC = `0xf79e245c` (Program Counter from crash register snapshot)
- Memory map entry: `f79e0000-f79e6000 r-xp 00000000 b3:04 4096 /lib/libubus.so.20230605`

**Analysis:**
- Start address: `0xf79e0000`
- End address: `0xf79e6000`
- Is PC in range? Yes: `0xf79e0000 ≤ 0xf79e245c < 0xf79e6000`
- Backing binary: `/lib/libubus.so.20230605`
- Offset within binary: `0xf79e245c - 0xf79e0000 = 0x245c`
- **Conclusion**: The crash occurred in `/lib/libubus.so.20230605 at offset 0x245c`

### From Address to Source Code

Once you have the binary name and offset, the next step is address-to-symbol translation:

1. Extract the offset within the binary (as shown above).
2. Use debugging tools (such as `addr2line`, `objdump`, or `nm`) to map the offset to:
   - Function name
   - Source file
   - Line number (if debug symbols are present)

This process is the bridge between a raw crash address and human-readable source code.

### Using Multiple Registers for Context

Crash dumps typically include multiple registers:

- **PC (Program Counter)**: The instruction that was executing
- **LR/RA (Link Register/Return Address)**: Where execution will resume after the current function
- **SP (Stack Pointer)**: Top of the stack, points to the most recent frame
- **FP/BP (Frame Pointer)**: Base of the current stack frame

By resolving all these addresses, you can reconstruct the call stack and understand the sequence of function calls leading to the crash.

---

## What This Article Does Not Cover

While memory maps are fundamental to crash analysis, they are part of a larger ecosystem. The following topics are intentionally excluded from this article:

- **Core dumps**: File format, creation, and extraction of memory contents
- **Symbol files**: Debug symbol tables (DWARF, stabs) and symbol stripping
- **DWARF internals**: Stack unwinding, variable location lists, and CFI (Call Frame Information)
- **Heap debugging**: Memory allocator state, corruption detection, and heap profilers
- **Runtime analysis**: Instrumentation, tracing, and dynamic analysis tools
- **Compiler optimizations**: Impact of optimization levels on stack frames and register usage

These topics deserve dedicated documentation; understanding memory maps is a prerequisite for engaging with any of them.

---

## Conclusion

The Linux process memory map is a foundational artifact in systems debugging. By understanding the structure and interpretation of `/proc/<pid>/maps`, you gain immediate access to:

- **Crash location identification**: Pinpointing which binary and function failed
- **Memory layout visualization**: Understanding how code, data, and dynamic memory coexist
- **Security assessment**: Detecting dangerous permission combinations
- **Debugging integration**: Converting raw addresses to human-readable symbols

Memory maps alone do not solve crashes—they must be combined with:

- **Symbol files** (to convert offsets to function names and source lines)
- **Backtraces** (to understand the call chain)
- **Source code inspection** (to understand intent and detect logic errors)
- **Reproducibility** (to test fixes in the actual failure scenario)

However, the memory map is where the investigation begins. It answers the first critical question: *Where was the process when it crashed?*

By mastering the interpretation of memory maps, you equip yourself with a skill that applies across architectures, kernels, and projects—making you a more effective debugger and more resilient systems engineer.

