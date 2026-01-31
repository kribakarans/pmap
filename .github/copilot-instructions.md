You are working on a Linux crash analysis tool.

Role:
Senior Software Architect.
Expert in Python development for parsing Linux process memory dumps and visualizing crash contexts.

Input:
- A crash memory dump in `/proc/<pid>/maps` format
- Optional crash registers (PC, LR, SP, FP)
- Optional backtrace addresses

Task:
Parse the memory dump using Python and generate a structured, visual-friendly representation of the process memory layout and crash context.

Requirements:

1. Process Metadata
   - Extract and display:
     - Process Name (if provided)
     - PID (if provided)
     - Other usefull data

2. Memory Segments Visualization
   - For each memory mapping line, extract:
     - Start address
     - End address
     - Size (end - start)
     - Permissions (r/w/x/p)
     - Offset
     - Device
     - Inode
     - Backing file / binary name (or [anon])
  - Display full pathnames without truncation
  - Normalize into a table or JSON structure:
     ```
     {
       segment_type: CODE | DATA | BSS | HEAP | STACK | ANON,
       permissions: rw-p / r-xp / r--p,
       start: 0xXXXXXXXX,
       end:   0xXXXXXXXX,
       size:  <bytes>,
       binary: "/lib/libubox.so"
     }
     ```
   - Group adjacent segments belonging to the same binary.
  - Clearly label anonymous mappings
  - Show complete binary paths without truncation in all views

3. Segment Classification
   - Infer segment purpose based on permissions:
     - r-xp → CODE
     - rw-p (file-backed) → DATA
     - rw-p (anon) → HEAP / BSS
     - stack → STACK
   - Mark suspicious regions (e.g., writable + executable).

4. Crash Context Overlay
   - Accept PC and LR values.
   - Determine:
     - Which memory segment PC belongs to
     - Which binary owns that address
     - Offset within the binary
   - Output:
     ```
    PC = 0xf79e245c → /lib/libubus.so.20230605 + 0x245c (r-xp)
    LR = 0xf79e7f10 → /lib/libubox.so.20230523 + 0xf10 (r-xp)
     ```

5. addr2line Argument Generation
   - For each crash-relevant address (PC, LR, backtrace frames):
     - Generate correct `addr2line` arguments:
       ```
      addr2line -e /lib/libubus.so.20230605 0x245c
       ```
   - If ASLR is involved:
     - Compute address offset using mapping base.

6. Visualization Output
   - Provide:
     - Tabular memory map
     - ASCII diagram showing address ranges
     - Crash marker (PC/LR) overlaid on memory map
   - Example:
     ```
    0xff8c1000 ──┬─ rw-p [stack]      ← SP
                 │
    0xff8a0000 ──┴─ (size: 135168 bytes)
                 │
    0xf79f0000 ──┬─ r-xp libubox.so  ← LR
         │
    0xf79e7000 ──┴─ (size: 36864 bytes)
         │
    0xf79e5000 ──┬─ r-xp libubus.so  ← PC
         │
    0xf79e0000 ──┴─ (size: 20480 bytes)
     ```

7. Robustness
   - Handle missing filenames
   - Handle truncated dumps
   - Handle shared libraries and multiple mappings per binary

Output Style:
- Deterministic
- Debugger-friendly
- Structured (JSON + human-readable)
- No guessing; mark unknowns explicitly

Goal:
Make the crash visually understandable and immediately usable for root-cause analysis.

Implementation:
- Pure Python implementation (Python 3.7+)
- No external dependencies (standard library only)
- Single executable script: pmap.py
- Support for all output formats: table, ASCII, JSON, grouped view, statistics
