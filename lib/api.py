"""
Core APIs for Linux crash analysis and memory map visualization.

This module provides all common models, parsers, analyzers, and generators
for both CLI (pmap.py) and HTML (pmap2html.py) tools.
"""

import re
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

        return f"addr2line -f -C -i -e {self.segment.pathname} 0x{self.offset_in_segment:x}"


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
    def parse_pid(pid: int) -> MemoryMap:
        """Parse a memory map directly from a running process ID"""
        maps_path = f"/proc/{pid}/maps"
        memmap = MemoryMapParser.parse_file(maps_path)
        memmap.pid = pid

        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                memmap.process_name = f.read().strip()
        except OSError:
            pass

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


# ============================================================================
# CRASH ANALYZER
# ============================================================================

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
            # For addr2line, we need: (Address - Segment_Base) + File_Offset
            if seg.pathname and not seg.pathname.startswith('['):
                addr2line_offset = offset + seg.offset
                print(f"  Debug command: addr2line -f -C -i -e {seg.pathname} 0x{addr2line_offset:x}")
            
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


# ============================================================================
# MEMORY MAP VISUALIZER (CLI/Text Output)
# ============================================================================

class MemoryMapVisualizer:
    """Visualization tools for memory maps"""
    
    @staticmethod
    def print_table(memmap: MemoryMap):
        """Print memory map in tabular format"""
        try:
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
        except BrokenPipeError:
            raise
    
    @staticmethod
    def print_ascii_layout(memmap: MemoryMap, crash_ctx: Optional[CrashContext] = None):
        """Print ASCII visualization of memory layout"""
        try:
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
        except BrokenPipeError:
            raise
    
    @staticmethod
    def print_grouped_by_binary(memmap: MemoryMap):
        """Print memory map grouped by binary"""
        try:
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
                    print(f"   0x{seg.start:08x}-0x{seg.end:08x}  {seg.perms}  "
                          f"{seg.seg_type.value:<8}  {seg.size:>10} bytes")
                print()
        except BrokenPipeError:
            # Handle pipe closing gracefully (e.g., when piped to head)
            raise
    
    @staticmethod
    def print_statistics(memmap: MemoryMap):
        """Print memory map statistics"""
        try:
            print()
            print("=" * 90)
            print("MEMORY MAP STATISTICS".center(90))
            print("=" * 90)
            print()
            
            # Calculate statistics by segment type
            type_stats: Dict[str, Dict[str, int]] = {}
            for seg in memmap.segments:
                seg_type = seg.seg_type.value
                if seg_type not in type_stats:
                    type_stats[seg_type] = {'count': 0, 'size': 0}
                type_stats[seg_type]['count'] += 1
                type_stats[seg_type]['size'] += seg.size
            
            print(f"Total Segments: {len(memmap.segments)}")
            print(f"Total Memory:   {memmap.total_size:,} bytes ({memmap.total_size / (1024*1024):.2f} MB)")
            print()
            print(f"{'Segment Type':<15} {'Count':<10} {'Total Size':<20} {'Percentage':<10}")
            print("-" * 90)
            
            for seg_type in sorted(type_stats.keys()):
                stats = type_stats[seg_type]
                percentage = (stats['size'] / memmap.total_size) * 100
                size_mb = stats['size'] / (1024 * 1024)
                print(f"{seg_type:<15} {stats['count']:<10} "
                      f"{stats['size']:>12,} bytes ({size_mb:>6.2f} MB)  {percentage:>6.2f}%")
            
            print()
        except BrokenPipeError:
            raise


# ============================================================================
# HTML GENERATOR
# ============================================================================

class HTMLGenerator:
    """Generate HTML visualization of memory maps"""

    SEGMENT_COLORS = {
        SegmentType.CODE: "#4CAF50",
        SegmentType.DATA: "#2196F3",
        SegmentType.RODATA: "#9C27B0",
        SegmentType.BSS: "#FF9800",
        SegmentType.HEAP: "#F44336",
        SegmentType.STACK: "#00BCD4",
        SegmentType.ANON: "#9E9E9E",
        SegmentType.VDSO: "#795548",
        SegmentType.UNKNOWN: "#607D8B",
    }

    @staticmethod
    def generate_html(memmap: MemoryMap, crash_ctx: Optional[CrashContext], output_file: str):
        """Generate comprehensive HTML visualization"""
        import os
        from datetime import datetime

        if not memmap.segments:
            print("Error: No memory segments to visualize")
            return

        min_addr = min(seg.start for seg in memmap.segments)
        max_addr = max(seg.end for seg in memmap.segments)
        total_range = max_addr - min_addr

        html_content = HTMLGenerator._generate_html_content(
            memmap, crash_ctx, min_addr, max_addr, total_range
        )

        with open(output_file, 'w') as f:
            f.write(html_content)

        print(f"\nHTML visualization saved to: {output_file}")
        print(f"  Open in browser: file://{os.path.abspath(output_file)}\n")

    @staticmethod
    def link_to_report(html_output: str):
        """Link output file to report.html for easy access"""
        import os
        import shutil

        if html_output == "report.html":
            return

        try:
            # Remove existing report.html if it exists
            if os.path.exists("report.html"):
                os.remove("report.html")
            # Create symlink to the generated report
            os.symlink(os.path.abspath(html_output), "report.html")
            print(f"Linked to: report.html")
        except Exception as e:
            # If symlink fails (e.g., on Windows), try creating a copy
            try:
                shutil.copy(html_output, "report.html")
                print(f"Copied to: report.html")
            except Exception as copy_err:
                print(f"Could not link/copy to report.html: {copy_err}", file=sys.stderr)

    @staticmethod
    def _generate_html_content(memmap: MemoryMap, crash_ctx: Optional[CrashContext],
                               min_addr: int, max_addr: int, total_range: int) -> str:
        """Generate complete HTML content"""
        import os
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        segments_html = HTMLGenerator._generate_segments_html(
            memmap, crash_ctx, min_addr, total_range
        )

        stats_html = HTMLGenerator._generate_statistics_html(memmap)
        crash_html = HTMLGenerator._generate_crash_html(memmap, crash_ctx)
        files_html = HTMLGenerator._generate_files_html(memmap)
        table_html = HTMLGenerator._generate_table_html(memmap)

        # Load template from webui/pmap.html.in (shared with JavaScript webapp)
        template_path = os.path.join(os.path.dirname(__file__), "..", "webui", "pmap.html.in")
        with open(template_path, "r", encoding="utf-8") as template_file:
            template = template_file.read()

        replacements = {
            "TITLE": f"pmap2html - {memmap.process_name or 'Process'}",
            "PROCESS_NAME": memmap.process_name or "Unknown",
            "PID": str(memmap.pid or "N/A"),
            "GENERATED": timestamp,
            "STATS_HTML": stats_html,
            "CRASH_HTML": crash_html,
            "FILES_HTML": files_html,
            "MEMORY_VIS": segments_html,
            "LEGEND_HTML": HTMLGenerator._generate_legend_html(),
            "DETAILS_TABLE": table_html,
            "LOW_ADDR": f"0x{min_addr:016x}",
            "HIGH_ADDR": f"0x{max_addr:016x}",
        }

        for key, value in replacements.items():
            template = template.replace(f"{{{{{key}}}}}", value)

        return template

    @staticmethod
    def _generate_segments_html(memmap: MemoryMap, crash_ctx: Optional[CrashContext],
                                min_addr: int, total_range: int) -> str:
        """Generate HTML for memory segments in grouped box style"""

        crash_addrs: Dict[int, str] = {}
        if crash_ctx:
            if crash_ctx.pc is not None:
                crash_addrs[crash_ctx.pc] = "PC"
            if crash_ctx.lr is not None:
                crash_addrs[crash_ctx.lr] = "LR"
            if crash_ctx.sp is not None:
                crash_addrs[crash_ctx.sp] = "SP"
            if crash_ctx.fp is not None:
                crash_addrs[crash_ctx.fp] = "FP"

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

        def format_segment(seg: MemorySegment) -> str:
            color = HTMLGenerator.SEGMENT_COLORS.get(seg.seg_type, "#607D8B")
            name = seg.pathname if seg.pathname else "[anon]"

            markers_html = ""
            for addr, label in crash_addrs.items():
                if seg.start <= addr < seg.end:
                    markers_html += f' <span class="crash-marker" title="0x{addr:016x}">{label}</span>'

            type_colored = f'{seg.seg_type.value}'
            
            # Format size in human-readable format
            size_kb = seg.size / 1024
            if size_kb >= 1024:
                size_str = f"{size_kb / 1024:.2f} MB"
            else:
                size_str = f"{size_kb:.2f} KB"

            return f'''<tr class="segment-row" style="background-color: {color}33;">
                <td class="segment-addr" style="border-left: 3px solid {color};">0x{seg.start:016x}-0x{seg.end:016x} ({size_str})</td>
                <td class="segment-perms">{seg.perms}</td>
                <td class="segment-type">{type_colored}</td>
                <td class="segment-path">{name}{markers_html}</td>
            </tr>'''

        groups = [
            (
                "Code (.text)",
                [seg for seg in memmap.segments if seg.seg_type == SegmentType.CODE and not is_shared_lib(seg)],
            ),
            (
                "BSS / Data",
                [
                    seg for seg in memmap.segments
                    if (seg.seg_type in {SegmentType.DATA, SegmentType.ANON, SegmentType.BSS, SegmentType.RODATA})
                    and seg.seg_type != SegmentType.HEAP
                    and not is_shared_lib(seg)
                ],
            ),
            ("Heap", [seg for seg in memmap.segments if seg.seg_type == SegmentType.HEAP]),
            ("Shared Libraries", [seg for seg in memmap.segments if is_shared_lib(seg)]),
            ("Stack", [seg for seg in memmap.segments if seg.seg_type == SegmentType.STACK]),
        ]

        html_parts = []
        for title, segments in groups:
            if not segments:
                continue

            html_parts.append(
                f'<tr class="segment-group-row"><td class="segment-group-header" colspan="4">{title}</td></tr>'
            )
            for seg in sorted(segments, key=lambda s: s.start):
                html_parts.append(format_segment(seg))

        return "\n".join(html_parts)

    @staticmethod
    def _generate_legend_html() -> str:
        """Generate legend HTML with segment type descriptions"""
        descriptions = {
            SegmentType.CODE: "Executable code (.text section)",
            SegmentType.DATA: "Initialized data (.data section)",
            SegmentType.RODATA: "Read-only data (.rodata section)",
            SegmentType.BSS: "Uninitialized data (.bss section)",
            SegmentType.HEAP: "Dynamic memory allocation area",
            SegmentType.STACK: "Thread stack (local variables)",
            SegmentType.ANON: "Anonymous memory mapping",
            SegmentType.VDSO: "Virtual dynamic shared object",
            SegmentType.UNKNOWN: "Unknown or special segment",
        }

        legend_items = []
        for seg_type, color in HTMLGenerator.SEGMENT_COLORS.items():
            desc = descriptions.get(seg_type, "")
            legend_items.append(f"""
                <div class="legend-item">
                    <div class="legend-color" style="background-color: {color};"></div>
                    <div class="legend-text"><strong>{seg_type.value}</strong>: {desc}</div>
                </div>""")
        return "\n".join(legend_items)

    @staticmethod
    def _generate_statistics_html(memmap: MemoryMap) -> str:
        """Generate statistics HTML"""
        type_stats = {}
        for seg in memmap.segments:
            seg_type = seg.seg_type.value
            if seg_type not in type_stats:
                type_stats[seg_type] = {'count': 0, 'size': 0}
            type_stats[seg_type]['count'] += 1
            type_stats[seg_type]['size'] += seg.size

        stats_cards = []
        stats_cards.append(f"""
            <div class="stat-card">
                <h3>Total Segments</h3>
                <div class="value">{len(memmap.segments)}</div>
            </div>""")

        stats_cards.append(f"""
            <div class="stat-card">
                <h3>Total Memory</h3>
                <div class="value">{memmap.total_size / (1024*1024):.1f} MB</div>
            </div>""")

        stats_cards.append(f"""
            <div class="stat-card">
                <h3>CODE</h3>
                <div class="value">{type_stats.get(SegmentType.CODE.value, {}).get('size', 0) / 1024:.0f} KB</div>
            </div>""")

        stats_cards.append(f"""
            <div class="stat-card">
                <h3>DATA</h3>
                <div class="value">{type_stats.get(SegmentType.DATA.value, {}).get('size', 0) / 1024:.0f} KB</div>
            </div>""")

        stats_cards.append(f"""
            <div class="stat-card">
                <h3>HEAP</h3>
                <div class="value">{type_stats.get(SegmentType.HEAP.value, {}).get('size', 0) / 1024:.0f} KB</div>
            </div>""")

        stats_cards.append(f"""
            <div class="stat-card">
                <h3>BINARIES</h3>
                <div class="value">{len({seg.pathname for seg in memmap.segments if seg.pathname and not seg.pathname.startswith('[')})}</div>
            </div>""")

        stats_cards.append(f"""
            <div class="stat-card">
                <h3>STACK</h3>
                <div class="value">{type_stats.get(SegmentType.STACK.value, {}).get('size', 0) / 1024:.0f} KB</div>
            </div>""")

        stats_cards.append(f"""
            <div class="stat-card">
                <h3>ANON</h3>
                <div class="value">{type_stats.get(SegmentType.ANON.value, {}).get('size', 0) / 1024:.0f} KB</div>
            </div>""")

        return f"""
            <div class="section">
                <h2 class="section-title">📈 Memory Stats</h2>
                <div class="stats-grid">
                    {" ".join(stats_cards)}
                </div>
            </div>"""

    @staticmethod
    def _generate_files_html(memmap: MemoryMap) -> str:
        """Generate files section HTML"""
        files = {}
        for seg in memmap.segments:
            if not seg.pathname or seg.pathname.startswith('['):
                continue
            entry = files.setdefault(seg.pathname, {"types": set(), "size": 0, "segments": 0})
            entry["types"].add(seg.seg_type)
            entry["size"] += seg.size
            entry["segments"] += 1

        def pick_type(types):
            priority = [
                SegmentType.CODE,
                SegmentType.DATA,
                SegmentType.RODATA,
                SegmentType.BSS,
                SegmentType.HEAP,
                SegmentType.STACK,
                SegmentType.ANON,
                SegmentType.VDSO,
                SegmentType.UNKNOWN,
            ]
            for seg_type in priority:
                if seg_type in types:
                    return seg_type
            return SegmentType.UNKNOWN

        if not files:
            return """
                <div class="section">
                    <h2 class="section-title">📁 Files</h2>
                    <div class="crash-detail">No file-backed mappings found.</div>
                </div>"""

        rows = []
        for pathname in sorted(files.keys()):
            info = files[pathname]
            seg_type = pick_type(info["types"])
            color = HTMLGenerator.SEGMENT_COLORS.get(seg_type, "#607D8B")
            rows.append(f"""
                <tr style=\"background-color: {color}33;\">
                    <td style=\"border-left: 3px solid {color};\">{pathname}</td>
                    <td class=\"monospace\">{info['segments']}</td>
                    <td class=\"monospace\">{info['size']:,}</td>
                    <td class=\"monospace\">{seg_type.value}</td>
                </tr>""")

        return f"""
            <div class="section">
                <h2 class="section-title">📁 Files</h2>
                <div style=\"overflow-x: auto;\">
                    <table class=\"files-table\">
                        <thead>
                            <tr>
                                <th>File</th>
                                <th>Segments</th>
                                <th>Total Size (bytes)</th>
                                <th>Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>"""

    @staticmethod
    def _generate_crash_html(memmap: MemoryMap, crash_ctx: Optional[CrashContext]) -> str:
        """Generate crash analysis HTML"""
        if not crash_ctx or (crash_ctx.pc is None and crash_ctx.lr is None and
                            crash_ctx.sp is None and crash_ctx.fp is None):
            return ""

        crash_details = []

        def analyze_addr(name: str, addr: int):
            seg = memmap.find_segment(addr)
            if seg:
                offset = addr - seg.start
                binary = seg.pathname if seg.pathname else "[anon]"
                addr2line = ""
                if seg.pathname and not seg.pathname.startswith('['):
                    addr2line_offset = offset + seg.offset
                    addr2line = f"<br>Debug: <code>addr2line -f -C -i -e {binary} 0x{addr2line_offset:x}</code>"

                return f"""
                    <div class="crash-detail">
                        <strong>{name}:</strong> 0x{addr:016x}<br>
                        Segment: {binary} [{seg.seg_type.value}]<br>
                        Permissions: {seg.perms} | Offset: 0x{offset:x}
                        {addr2line}
                    </div>"""
            return f"""
                    <div class="crash-detail">
                        <strong>{name}:</strong> 0x{addr:016x}<br>
                        <span style="color: red;">⚠️ Address not found in any mapped segment!</span>
                    </div>"""

        if crash_ctx.pc is not None:
            crash_details.append(analyze_addr("Program Counter (PC)", crash_ctx.pc))
        if crash_ctx.lr is not None:
            crash_details.append(analyze_addr("Link Register (LR)", crash_ctx.lr))
        if crash_ctx.sp is not None:
            crash_details.append(analyze_addr("Stack Pointer (SP)", crash_ctx.sp))
        if crash_ctx.fp is not None:
            crash_details.append(analyze_addr("Frame Pointer (FP)", crash_ctx.fp))

        return f"""
            <div class="section">
                <h2 class="section-title">🔍 Crash Context</h2>
                <div class="crash-info">
                    <h3>Register Analysis</h3>
                    {"".join(crash_details)}
                </div>
            </div>"""

    @staticmethod
    def _generate_table_html(memmap: MemoryMap) -> str:
        """Generate detailed segment table"""
        rows = []
        for seg in memmap.segments:
            name = seg.pathname if seg.pathname else "[anon]"
            color = HTMLGenerator.SEGMENT_COLORS.get(seg.seg_type, "#607D8B")
            rows.append(f"""
                <tr>
                    <td class="monospace">0x{seg.start:016x}</td>
                    <td class="monospace">0x{seg.end:016x}</td>
                    <td>{seg.size:,}</td>
                    <td class="monospace">{seg.perms}</td>
                    <td><span style="color: {color}; font-weight: bold;">●</span> {seg.seg_type.value}</td>
                    <td style="font-size: 0.85em;">{name}</td>
                </tr>""")

        return f"""
            <div class="section">
                <h2 class="section-title">📋 Detailed Segment</h2>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>Start Address</th>
                                <th>End Address</th>
                                <th>Size (bytes)</th>
                                <th>Permissions</th>
                                <th>Type</th>
                                <th>Binary/Mapping</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(rows)}
                        </tbody>
                    </table>
                </div>
            </div>"""
