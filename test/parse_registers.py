#!/usr/bin/env python3
"""
Quick reference: Extract register values from crash dumps.

Shows how to:
1. Parse crash_dump_*.regs files
2. Extract key registers (PC, SP, FP, etc.)
3. Correlate with memory map for source location
"""

import re
import sys
from pathlib import Path

def parse_register_dump(regs_file):
    """Parse crash_dump_*.regs file"""
    with open(regs_file) as f:
        content = f.read()
    
    registers = {}
    arch = None
    
    # Detect architecture
    if "x86-64" in content:
        arch = "x86-64"
        pattern = r'(\w+):\s+([0-9a-f]+)'
    elif "ARM64" in content:
        arch = "ARM64"
        pattern = r'(\w+)\s+:\s+([0-9a-f]+)'
    else:
        arch = "unknown"
    
    # Extract register values
    for line in content.split('\n'):
        match = re.search(pattern, line)
        if match:
            reg_name = match.group(1).lower()
            reg_value = match.group(2)
            registers[reg_name] = '0x' + reg_value
    
    return arch, registers

def extract_key_registers(registers):
    """Extract most important registers for debugging"""
    key_regs = {}
    
    # x86-64 names
    if 'rip' in registers:
        key_regs['Program Counter (PC)'] = registers.get('rip')
        key_regs['Stack Pointer (SP)'] = registers.get('rsp')
        key_regs['Frame Pointer (FP)'] = registers.get('rbp')
        key_regs['First Arg (RDI)'] = registers.get('rdi')
        key_regs['Return Value (RAX)'] = registers.get('rax')
    
    # ARM64 names
    elif 'pc' in registers:
        key_regs['Program Counter (PC)'] = registers.get('pc')
        key_regs['Stack Pointer (SP)'] = registers.get('sp')
        key_regs['Frame Pointer (FP)'] = registers.get('x29')
        key_regs['Link Register (LR)'] = registers.get('x30')
        key_regs['First Arg (X0)'] = registers.get('x0')
    
    return key_regs

def main():
    regs_files = sorted(Path('.').glob('crash_dump_*.regs'))
    
    if not regs_files:
        print("No register dumps found. Run crash_demo first:")
        print("  ./crash_demo")
        return 1
    
    latest = regs_files[-1]
    print(f"Parsing: {latest}")
    print()
    
    arch, all_regs = parse_register_dump(latest)
    key_regs = extract_key_registers(all_regs)
    
    print(f"Architecture: {arch}")
    print(f"Total registers captured: {len(all_regs)}")
    print()
    
    print("=== KEY REGISTERS FOR DEBUGGING ===")
    for name, value in key_regs.items():
        print(f"{name:30s} {value}")
    print()
    
    # Show how to use PC value
    pc = key_regs.get('Program Counter (PC)')
    if pc:
        print(f"To analyze crash location, use:")
        print(f"  ./memmap_analyzer.py crash_dump_*.maps --pc {pc}")
        print()
        print(f"Or with addr2line:")
        print(f"  addr2line -e ./crash_demo {pc}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
