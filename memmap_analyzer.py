#!/usr/bin/env python3
"""
Linux Crash Analysis Tool - Python Version
Enhanced visualization and crash context analysis
"""

import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


class SegmentType(Enum):
    """Memory segment classification"""
    CODE = "CODE"
    DATA = "DATA"
    RODATA = "RODATA"
    BSS = "BSS"
    HEAP = "HEAP"
    STACK = "STACK"
    ANON = "ANON"
    VDSO = "VDSO"
    UNKNOWN = "UNKNOWN"


@dataclass
class MemorySegment:
    """Represents a memory segment from /proc/pid/maps"""
    start: int
    end: int
    size: int
    perms: str
    offset: int
    dev_major: int
    dev_minor: int
    inode: int
    pathname: str
    seg_type: SegmentType = SegmentType.UNKNOWN
    
    @property
    def is_readable(self) -> bool:
        return 'r' in self.perms
    
    @property
    def is_writable(self) -> bool:
        return 'w' in self.perms
    
    @property
    def is_executable(self) -> bool:
        return 'x' in self.perms
    
    @property
    def is_private(self) -> bool:
        return 'p' in self.perms
    
    def classify(self):
        """Classify segment type based on permissions and pathname"""
        if self.pathname == "[heap]":
            self.seg_type = SegmentType.HEAP
        elif self.pathname == "[stack]":
            self.seg_type = SegmentType.STACK
        elif self.pathname in ["[vdso]", "[sigpage]", "[vectors]"]:
            self.seg_type = SegmentType.VDSO
        elif self.is_executable:
            self.seg_type = SegmentType.CODE
        elif self.is_readable and not self.is_writable:
            self.seg_type = SegmentType.RODATA
        elif self.is_writable:
            if not self.pathname:
                self.seg_type = SegmentType.ANON
            else:
                self.seg_type = SegmentType.DATA
        else:
            self.seg_type = SegmentType.UNKNOWN


@dataclass
class MemoryMap:
    """Process memory map"""
    pid: int = 0
    process_name: str = ""
    segments: List[MemorySegment] = field(default_factory=list)
    
    @property
    def total_size(self) -> int:
        return sum(seg.size for seg in self.segments)
    
    def find_segment(self, addr: int) -> Optional[MemorySegment]:
        """Find segment containing the given address"""
        for seg in self.segments:
            if seg.start <= addr < seg.end:
                return seg
        return None
    
    def get_segments_by_binary(self, binary: str) -> List[MemorySegment]:
        """Get all segments belonging to a binary"""
        return [seg for seg in self.segments if seg.pathname == binary]


@dataclass
class CrashContext:
    """Crash register context"""
    pc: Optional[int] = None
    lr: Optional[int] = None
    sp: Optional[int] = None
    fp: Optional[int] = None
    backtrace: List[int] = field(default_factory=list)


@dataclass
class CrashLocation:
    """Resolved crash location"""
    addr: int
    segment: MemorySegment
    offset_in_segment: int
    offset_in_binary: int
    
    def generate_addr2line_cmd(self) -> str:
        """Generate addr2line command for debugging"""
        if not self.segment.pathname or self.segment.pathname.startswith('['):
            return f"# addr2line not applicable for {self.segment.pathname or 'anonymous mapping'}"
        
        return f"addr2line -e {self.segment.pathname} 0x{self.offset_in_segment:x}"


class MemoryMapParser:
    """Parser for /proc/pid/maps format"""
    
    MAPS_RE = re.compile(
        r'([0-9a-f]+)-([0-9a-f]+)\s+'  # start-end
        r'([rwxp-]+)\s+'                # perms
        r'([0-9a-f]+)\s+'               # offset
        r'([0-9a-f]+):([0-9a-f]+)\s+'  # device
        r'(\d+)\s*'                     # inode
        r'(.*)?'                        # pathname (optional)
    )
    
    @staticmethod
    def parse_file(filename: str) -> MemoryMap:
        """Parse a memory map file"""
        memmap = MemoryMap()
        
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip comments
                if line.startswith('#'):
                    # Try to extract PID from comment
                    if '/proc/' in line:
                        pid_match = re.search(r'/proc/(\d+)/', line)
                        if pid_match:
                            memmap.pid = int(pid_match.group(1))
                    continue
                
                if not line:
                    continue
                
                segment = MemoryMapParser.parse_line(line)
                if segment:
                    memmap.segments.append(segment)
        
        # Try to guess process name from first segment
        if memmap.segments and memmap.segments[0].pathname:
            path = memmap.segments[0].pathname
            if '/' in path:
                memmap.process_name = path.split('/')[-1]
            else:
                memmap.process_name = path
        
        return memmap
    
    @staticmethod
    def parse_line(line: str) -> Optional[MemorySegment]:
        """Parse a single line from /proc/pid/maps"""
        match = MemoryMapParser.MAPS_RE.match(line)
        if not match:
            return None
        
        start = int(match.group(1), 16)
        end = int(match.group(2), 16)
        perms = match.group(3)
        offset = int(match.group(4), 16)
        dev_major = int(match.group(5), 16)
        dev_minor = int(match.group(6), 16)
        inode = int(match.group(7))
        pathname = match.group(8).strip() if match.group(8) else ""
        
        segment = MemorySegment(
            start=start,
            end=end,
            size=end - start,
            perms=perms,
            offset=offset,
            dev_major=dev_major,
            dev_minor=dev_minor,
            inode=inode,
            pathname=pathname
        )
        
        segment.classify()
        return segment


class MemoryMapVisualizer:
    """Visualization tools for memory maps"""
    
    @staticmethod
    def print_table(memmap: MemoryMap):
        """Print memory map in tabular format"""
        print()
        print("=" * 130)
        print(f"MEMORY MAP - TABULAR VIEW".center(130))
        print("=" * 130)
        print(f"Process: {memmap.process_name:<20} PID: {memmap.pid:<10} "
              f"Segments: {len(memmap.segments):<5} Total Size: {memmap.total_size:,} bytes")
        print("=" * 130)
        print(f"{'Start Addr':<14} {'End Addr':<14} {'Size':<12} {'Perms':<6} "
              f"{'Type':<10} {'Binary/Mapping':<60}")
        print("-" * 130)
        
        for seg in memmap.segments:
            name = seg.pathname if seg.pathname else "[anon]"
            print(f"0x{seg.start:08x}     0x{seg.end:08x}     "
                  f"{seg.size:>10}  {seg.perms:<6} {seg.seg_type.value:<10} "
                  f"{name}")
        
        print("=" * 130)
        print()
    
    @staticmethod
    def print_ascii_layout(memmap: MemoryMap, crash_ctx: Optional[CrashContext] = None):
        """Print ASCII visualization of memory layout"""
        print()
        print("=" * 90)
        print("MEMORY LAYOUT - ASCII VISUALIZATION".center(90))
        print("=" * 90)
        print()
        print("High Memory")
        print("     ↑")
        print("     │")
        
        for seg in reversed(memmap.segments):
            name = seg.pathname if seg.pathname else "[anon]"
            
            # Check for crash markers
            markers = []
            if crash_ctx:
                if crash_ctx.pc and seg.start <= crash_ctx.pc < seg.end:
                    markers.append("PC")
                if crash_ctx.lr and seg.start <= crash_ctx.lr < seg.end:
                    markers.append("LR")
                if crash_ctx.sp and seg.start <= crash_ctx.sp < seg.end:
                    markers.append("SP")
                if crash_ctx.fp and seg.start <= crash_ctx.fp < seg.end:
                    markers.append("FP")
            
            marker_str = " ← " + " ".join(markers) if markers else ""
            
            print(f"0x{seg.end:08x} ──┬─ {seg.perms:<5} {seg.seg_type.value:<8} "
                f"{name}{marker_str}")
            print("             │")
            print(f"0x{seg.start:08x} ──┴─ (size: {seg.size:,} bytes)")
            print("     │")
        
        print("     ↓")
        print("Low Memory")
        print()
    
    @staticmethod
    def print_grouped_by_binary(memmap: MemoryMap):
        """Print memory map grouped by binary"""
        print()
        print("=" * 90)
        print("MEMORY MAP - GROUPED BY BINARY".center(90))
        print("=" * 90)
        print()
        
        # Group segments by binary
        binaries: Dict[str, List[MemorySegment]] = {}
        for seg in memmap.segments:
            key = seg.pathname if seg.pathname else "[anon]"
            if key not in binaries:
                binaries[key] = []
            binaries[key].append(seg)
        
        for binary, segments in binaries.items():
            total_size = sum(seg.size for seg in segments)
            print(f"📦 {binary}")
            print(f"   Total size: {total_size:,} bytes ({len(segments)} segments)")
            
            for seg in segments:
                print(f"   0x{seg.start:08x}-0x{seg.end:08x}  {seg.perms:<5}  "
                      f"{seg.seg_type.value:<8}  {seg.size:>10} bytes")
            print()
    
    @staticmethod
    def print_statistics(memmap: MemoryMap):
        """Print memory statistics"""
        print()
        print("=" * 90)
        print("MEMORY STATISTICS".center(90))
        print("=" * 90)
        print()
        
        # Count by type
        type_stats = {}
        for seg in memmap.segments:
            seg_type = seg.seg_type.value
            if seg_type not in type_stats:
                type_stats[seg_type] = {'count': 0, 'size': 0}
            type_stats[seg_type]['count'] += 1
            type_stats[seg_type]['size'] += seg.size
        
        print(f"{'Segment Type':<15} {'Count':<8} {'Total Size':<20} {'Percentage'}")
        print("-" * 70)
        
        for seg_type, stats in sorted(type_stats.items()):
            percentage = (stats['size'] / memmap.total_size * 100) if memmap.total_size > 0 else 0
            print(f"{seg_type:<15} {stats['count']:<8} {stats['size']:>15,} bytes  "
                  f"{percentage:>6.2f}%")
        
        print("-" * 70)
        print(f"{'TOTAL':<15} {len(memmap.segments):<8} {memmap.total_size:>15,} bytes  100.00%")
        print()

    @staticmethod
    def print_segments_overview(memmap: MemoryMap):
        """Print high-level segment overview box with segment contents"""
        print()
        print("SEGMENT OVERVIEW".center(90))

        main_path = None
        for seg in memmap.segments:
            if seg.pathname and seg.pathname.startswith('/'):
                if seg.pathname.endswith('/' + memmap.process_name) or seg.pathname.split('/')[-1] == memmap.process_name:
                    main_path = seg.pathname
                    break

        def is_shared_lib(seg: MemorySegment) -> bool:
            if not seg.pathname or seg.pathname.startswith('['):
                return False
            if main_path and seg.pathname == main_path:
                return False
            return ('.so' in seg.pathname) or ('/lib/' in seg.pathname) or ('/usr/lib/' in seg.pathname)

        def fmt_seg(seg: MemorySegment) -> str:
            name = seg.pathname if seg.pathname else "[anon]"
            return f"0x{seg.start:08x}-0x{seg.end:08x}  {seg.perms:<4} {seg.seg_type.value:<6} {name}"

        sections = [
            ("Stack", [seg for seg in memmap.segments if seg.seg_type == SegmentType.STACK]),
            ("Shared Libs", [seg for seg in memmap.segments if is_shared_lib(seg)]),
            ("Heap", [seg for seg in memmap.segments if seg.seg_type == SegmentType.HEAP]),
            (
                "BSS / Data",
                [
                    seg for seg in memmap.segments
                    if (seg.seg_type in {SegmentType.DATA, SegmentType.ANON, SegmentType.BSS, SegmentType.RODATA})
                    and seg.seg_type != SegmentType.HEAP
                    and not is_shared_lib(seg)
                ],
            ),
            (
                "Code (.text)",
                [seg for seg in memmap.segments if seg.seg_type == SegmentType.CODE and not is_shared_lib(seg)],
            ),
        ]

        content_lines = []
        for title, segs in sections:
            content_lines.append(title)
            if segs:
                content_lines.extend(fmt_seg(seg) for seg in segs)
            else:
                content_lines.append("(n/a)")

        width = max(len(line) for line in content_lines) if content_lines else 0
        width = max(width, len("SEGMENT OVERVIEW"))

        def box_line(text: str) -> str:
            return f"│ {text.ljust(width)} │"

        print(f"┌{'─' * (width + 2)}┐")
        first = True
        for title, segs in sections:
            if not first:
                print(f"├{'─' * (width + 2)}┤")
            first = False
            print(box_line(title))
            if segs:
                for seg in segs:
                    print(box_line(fmt_seg(seg)))
            else:
                print(box_line("(n/a)"))
        print(f"└{'─' * (width + 2)}┘")
        print()


class CrashAnalyzer:
    """Crash context analysis"""
    
    @staticmethod
    def analyze_crash(memmap: MemoryMap, crash_ctx: CrashContext):
        """Analyze crash context"""
        print()
        print("=" * 90)
        print("CRASH CONTEXT ANALYSIS".center(90))
        print("=" * 90)
        print()
        
        if crash_ctx.pc is not None:
            CrashAnalyzer._analyze_register(memmap, "Program Counter (PC)", crash_ctx.pc)
        
        if crash_ctx.lr is not None:
            CrashAnalyzer._analyze_register(memmap, "Link Register (LR)", crash_ctx.lr)
        
        if crash_ctx.sp is not None:
            CrashAnalyzer._analyze_register(memmap, "Stack Pointer (SP)", crash_ctx.sp, check_stack=True)
        
        if crash_ctx.fp is not None:
            CrashAnalyzer._analyze_register(memmap, "Frame Pointer (FP)", crash_ctx.fp)
        
        if crash_ctx.backtrace:
            CrashAnalyzer._analyze_backtrace(memmap, crash_ctx.backtrace)
    
    @staticmethod
    def _analyze_register(memmap: MemoryMap, name: str, addr: int, check_stack: bool = False):
        """Analyze a single register value"""
        print(f"{name}:")
        print(f"  Address: 0x{addr:016x}")
        
        seg = memmap.find_segment(addr)
        if seg:
            offset = addr - seg.start
            binary = seg.pathname if seg.pathname else "[anon]"
            
            print(f"  Segment: {binary} [{seg.seg_type.value}]")
            print(f"  Permissions: {seg.perms}")
            print(f"  Offset in segment: 0x{offset:x}")
            
            # Generate addr2line command
            if seg.pathname and not seg.pathname.startswith('['):
                print(f"  Debug command: addr2line -e {seg.pathname} 0x{offset:x}")
            
            # Check for warnings
            if check_stack and seg.seg_type != SegmentType.STACK:
                print(f"  ⚠️  WARNING: Stack pointer not in stack segment!")
            
            if seg.is_writable and seg.is_executable:
                print(f"  ⚠️  WARNING: Segment is both writable and executable!")
        else:
            print(f"  ⚠️  ERROR: Address not found in any mapped segment!")
        
        print()
    
    @staticmethod
    def _analyze_backtrace(memmap: MemoryMap, backtrace: List[int]):
        """Analyze backtrace addresses"""
        print("Backtrace Analysis:")
        print()
        
        for i, addr in enumerate(backtrace):
            seg = memmap.find_segment(addr)
            if seg:
                offset = addr - seg.start
                binary = seg.pathname if seg.pathname else "[anon]"
                print(f"  #{i}: 0x{addr:016x} → {binary} + 0x{offset:x} [{seg.seg_type.value}]")
            else:
                print(f"  #{i}: 0x{addr:016x} → NOT MAPPED")
        
        print()
    
    @staticmethod
    def check_security(memmap: MemoryMap):
        """Check for security issues"""
        print()
        print("=" * 90)
        print("SECURITY ANALYSIS".center(90))
        print("=" * 90)
        print()
        
        issues = []
        
        # Check for RWX segments
        for seg in memmap.segments:
            if seg.is_writable and seg.is_executable:
                issues.append(f"⚠️  WRITABLE+EXECUTABLE: 0x{seg.start:08x}-0x{seg.end:08x} "
                            f"{seg.perms} {seg.pathname or '[anon]'}")
        
        if issues:
            print("Security issues found:")
            for issue in issues:
                print(f"  {issue}")
        else:
            print("✓ No suspicious writable+executable regions found.")
        
        print()


def print_help(prog: str):
    """Print detailed helper prompt"""
    print(
                f"""Usage: {prog} [options] <memory_dump_file>
Linux crash analysis tool for /proc/<pid>/maps dumps.

Options:
    --pc <addr>          -- Program counter address (hex)
    --lr <addr>          -- Link register address (hex)
    --sp <addr>          -- Stack pointer address (hex)
    --fp <addr>          -- Frame pointer address (hex)
    --segments           -- Show segment overview visualization only
    --ascii              -- Show ASCII memory layout only
    -h, --help           -- Show this help menu

Examples:
    {prog} memmap.txt
    {prog} memmap.txt --segments
    {prog} memmap.txt --ascii
    {prog} memmap.txt --pc 0xf79e245c --lr 0xf79e7f10
    {prog} memmap.txt --pc 0xf79e245c
    {prog} memmap.txt --lr 0xf79e7f10
    {prog} memmap.txt --sp 0xff8b0000
    {prog} memmap.txt --fp 0xff8b0010
    {prog} memmap.txt --pc 0xf79e245c --lr 0xf79e7f10 --sp 0xff8b0000
    {prog} memmap.txt --pc 0xf79e245c --lr 0xf79e7f10 --sp 0xff8b0000 --fp 0xff8b0010
"""
    )


def main():
    """Main entry point"""
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        print_help(sys.argv[0])
        sys.exit(0 if len(sys.argv) >= 2 else 1)
    
    # Check that first argument is a filename, not a flag
    if sys.argv[1].startswith('-'):
        print(f"Error: No memory dump file specified", file=sys.stderr)
        print_help(sys.argv[0])
        sys.exit(1)
    
    filename = sys.argv[1]
    
    # Validate command line options
    valid_flags = {'--pc', '--lr', '--sp', '--fp', '--segments', '--ascii'}
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg.startswith('--') and arg not in valid_flags:
            print(f"Error: Unknown option '{arg}'", file=sys.stderr)
            print_help(sys.argv[0])
            sys.exit(1)
    
    # Parse command line options
    show_segments = '--segments' in sys.argv
    show_ascii = '--ascii' in sys.argv
    crash_ctx = CrashContext()
    
    for i, arg in enumerate(sys.argv):
        if arg == '--pc' and i + 1 < len(sys.argv):
            crash_ctx.pc = int(sys.argv[i + 1], 16)
        elif arg == '--lr' and i + 1 < len(sys.argv):
            crash_ctx.lr = int(sys.argv[i + 1], 16)
        elif arg == '--sp' and i + 1 < len(sys.argv):
            crash_ctx.sp = int(sys.argv[i + 1], 16)
        elif arg == '--fp' and i + 1 < len(sys.argv):
            crash_ctx.fp = int(sys.argv[i + 1], 16)
    
    # Parse memory map
    memmap = MemoryMapParser.parse_file(filename)
    
    # Determine what to display
    if show_segments:
        # Only segment overview
        MemoryMapVisualizer.print_segments_overview(memmap)
    elif show_ascii:
        # Only ASCII layout
        MemoryMapVisualizer.print_ascii_layout(memmap, crash_ctx)
    else:
        # Default: all outputs
        MemoryMapVisualizer.print_table(memmap)
        MemoryMapVisualizer.print_statistics(memmap)
        MemoryMapVisualizer.print_grouped_by_binary(memmap)
        MemoryMapVisualizer.print_ascii_layout(memmap, crash_ctx)
    
    # Crash analysis if provided
    if any([crash_ctx.pc, crash_ctx.lr, crash_ctx.sp, crash_ctx.fp]):
        CrashAnalyzer.analyze_crash(memmap, crash_ctx)
    
    # Security check
    CrashAnalyzer.check_security(memmap)


if __name__ == '__main__':
    main()
