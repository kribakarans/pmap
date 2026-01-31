#!/usr/bin/env python3
"""
pmap - Process Memory Map Analysis Tool:
Enhanced visualization and crash context analysis
"""

import re
import sys
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum
from datetime import datetime


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
        
        # Calculate memory range for visualization
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
        
        print(f"\n✓ HTML visualization saved to: {output_file}")
        print(f"  Open in browser: file://{os.path.abspath(output_file)}\n")
    
    @staticmethod
    def _generate_html_content(memmap: MemoryMap, crash_ctx: Optional[CrashContext], 
                               min_addr: int, max_addr: int, total_range: int) -> str:
        """Generate complete HTML content"""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Generate segment HTML
        segments_html = HTMLGenerator._generate_segments_html(
            memmap, crash_ctx, min_addr, total_range
        )
        
        # Generate statistics
        stats_html = HTMLGenerator._generate_statistics_html(memmap)
        
        # Generate crash analysis
        crash_html = HTMLGenerator._generate_crash_html(memmap, crash_ctx)
        
        # Generate segment details table
        table_html = HTMLGenerator._generate_table_html(memmap)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Process Map Analysis - {memmap.process_name or 'Process'}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 10px;
            color: #333;
            font-size: 15px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 5px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 15px 20px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 1.8em;
            margin-bottom: 5px;
        }}
        
        .header .info {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 15px;
        }}
        
        .section {{
            margin-bottom: 20px;
        }}
        
        .section-title {{
            font-size: 1.4em;
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 5px;
            margin-bottom: 10px;
        }}
        
        .memory-viz {{
            background: #f8f9fa;
            border-radius: 5px;
            padding: 10px;
            position: relative;
        }}
        
        .memory-scale {{
            display: flex;
            flex-direction: column;
            margin-bottom: 5px;
            font-family: monospace;
            font-size: 0.85em;
            color: #666;
            gap: 0px;
        }}
        
        .memory-scale-top {{
            margin-bottom: 3px;
        }}
        
        .memory-scale-bottom {{
            margin-top: 3px;
        }}
        
        .memory-container {{
            background: white;
            border: 2px solid #2c3e50;
            border-radius: 3px;
            overflow-y: auto;
            overflow-x: auto;
            max-height: 600px;
            font-family: monospace;
        }}
        
        .segment-group {{
            border-bottom: 2px solid #2c3e50;
        }}
        
        .segment-group:last-child {{
            border-bottom: none;
        }}
        
        .segment-group-header {{
            background: #34495e;
            color: white;
            padding: 6px 12px;
            font-weight: bold;
            font-size: 0.95em;
            border-bottom: 2px solid #2c3e50;
        }}
        
        .segment {{
            padding: 3px 12px;
            font-size: 0.85em;
            border-bottom: 1px solid #ecf0f1;
            line-height: 1.5;
            white-space: nowrap;
            min-width: max-content;
        }}
        
        .segment:last-child {{
            border-bottom: none;
        }}
        
        .segment-addr {{
            display: inline-block;
            width: 230px;
            color: #1f2a33;
        }}
        
        .segment-perms {{
            display: inline-block;
            width: 45px;
            font-weight: bold;
            color: #1f2a33;
        }}
        
        .segment-type {{
            display: inline-block;
            width: 65px;
            font-weight: 600;
            color: #1f2a33;
        }}
        
        .segment-path {{
            display: inline-block;
            color: #2b2b2b;
        }}
        
        .crash-marker {{
            display: inline-block;
            padding: 2px 6px;
            background: #ff0000;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            font-size: 0.8em;
            margin-left: 6px;
            box-shadow: 0 1px 3px rgba(255,0,0,0.5);
        }}
        
        .legend {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 6px;
            margin-top: 8px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: flex-start;
            gap: 5px;
            font-size: 0.8em;
            line-height: 1.3;
        }}
        
        .legend-color {{
            flex-shrink: 0;
            width: 18px;
            height: 12px;
            border-radius: 2px;
            border: 1px solid rgba(0,0,0,0.2);
            margin-top: 2px;
        }}
        
        .legend-text {{
            flex: 1;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
            gap: 8px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 10px;
            border-radius: 4px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        }}
        
        .stat-card h3 {{
            font-size: 0.7em;
            opacity: 0.9;
            margin-bottom: 4px;
            text-transform: uppercase;
        }}
        
        .stat-card .value {{
            font-size: 1.4em;
            font-weight: bold;
        }}
        
        .crash-info {{
            background: #fff3cd;
            border-left: 3px solid #ff9800;
            padding: 8px 10px;
            border-radius: 3px;
            margin-bottom: 8px;
        }}
        
        .crash-info h3 {{
            color: #ff6f00;
            margin-bottom: 6px;
            font-size: 0.95em;
        }}
        
        .crash-detail {{
            font-family: monospace;
            background: white;
            padding: 6px 8px;
            border-radius: 2px;
            margin: 3px 0;
            font-size: 0.8em;
            line-height: 1.4;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
            font-size: 0.75em;
        }}
        
        table th {{
            background: #2c3e50;
            color: white;
            padding: 6px 8px;
            text-align: left;
            position: sticky;
            top: 0;
            font-size: 0.9em;
        }}
        
        table td {{
            padding: 4px 8px;
            border-bottom: 1px solid #eee;
        }}
        
        table tbody tr:hover {{
            background: #f8f9fa;
        }}
        
        .monospace {{
            font-family: monospace;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 8px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
            font-size: 0.75em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Process Map Analysis</h1>
            <div class="info">
                Process: <strong>{memmap.process_name or 'Unknown'}</strong> | 
                PID: <strong>{memmap.pid or 'N/A'}</strong> | 
                Generated: <strong>{timestamp}</strong>
            </div>
        </div>
        
        <div class="content">
            {stats_html}
            
            {crash_html}
            
            <div class="section">
                <h2 class="section-title">📊 Memory Layout Visualization</h2>
                <div class="memory-viz">
                    <div class="memory-scale">
                        <span class="memory-scale-top">⬇️ High Memory: 0x{max_addr:016x}</span>
                    </div>
                    <div class="memory-container">
                        {segments_html}
                    </div>
                    <div class="memory-scale">
                        <span class="memory-scale-bottom">⬆️ Low Memory: 0x{min_addr:016x}</span>
                    </div>
                    <div class="legend">
                        {HTMLGenerator._generate_legend_html()}
                    </div>
                </div>
            </div>
            
            {table_html}
        </div>
        
        <div class="footer">
            Generated by Process Map Analyzer v1.0
        </div>
    </div>
</body>
</html>"""
    
    @staticmethod
    def _generate_segments_html(memmap: MemoryMap, crash_ctx: Optional[CrashContext], 
                                min_addr: int, total_range: int) -> str:
        """Generate HTML for memory segments in grouped box style"""
        
        # Track which addresses have crash markers
        crash_addrs = {}
        if crash_ctx:
            if crash_ctx.pc is not None:
                crash_addrs[crash_ctx.pc] = "PC"
            if crash_ctx.lr is not None:
                crash_addrs[crash_ctx.lr] = "LR"
            if crash_ctx.sp is not None:
                crash_addrs[crash_ctx.sp] = "SP"
            if crash_ctx.fp is not None:
                crash_addrs[crash_ctx.fp] = "FP"
        
        # Helper function to determine if a segment is a shared library
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
            
            # Check if any crash markers are in this segment
            markers_html = ""
            for addr, label in crash_addrs.items():
                if seg.start <= addr < seg.end:
                    markers_html += f' <span class="crash-marker" title="0x{addr:016x}">{label}</span>'
            
            type_colored = f'<span>{seg.seg_type.value}</span>'
            
            # Apply brighter translucent background color based on segment type
            return f'''<div class="segment" style="background-color: {color}33; border-left: 3px solid {color};">
                <span class="segment-addr">0x{seg.start:08x}-0x{seg.end:08x}</span>
                <span class="segment-perms">{seg.perms}</span>
                <span class="segment-type">{type_colored}</span>
                <span class="segment-path">{name}</span>{markers_html}
            </div>'''
        
        # Group segments
        groups = [
            ("Stack", [seg for seg in memmap.segments if seg.seg_type == SegmentType.STACK]),
            ("Shared Libraries", [seg for seg in memmap.segments if is_shared_lib(seg)]),
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
        
        html_parts = []
        for title, segments in groups:
            if not segments:
                continue
            
            group_html = f'<div class="segment-group">'
            group_html += f'<div class="segment-group-header">{title}</div>'
            for seg in segments:
                group_html += format_segment(seg)
            group_html += '</div>'
            html_parts.append(group_html)
        
        return "\n".join(html_parts)
    
    @staticmethod
    def _generate_legend_html() -> str:
        """Generate legend HTML with segment type descriptions"""
        # Descriptions for each segment type
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
        # Count by type
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
        
        for seg_type in [SegmentType.CODE, SegmentType.DATA, SegmentType.HEAP, SegmentType.STACK]:
            if seg_type.value in type_stats:
                stats = type_stats[seg_type.value]
                stats_cards.append(f"""
                    <div class="stat-card">
                        <h3>{seg_type.value}</h3>
                        <div class="value">{stats['size'] / 1024:.0f} KB</div>
                    </div>""")
        
        return f"""
            <div class="section">
                <h2 class="section-title">📈 Statistics</h2>
                <div class="stats-grid">
                    {" ".join(stats_cards)}
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
            else:
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
                <h2 class="section-title">🔍 Crash Context Analysis</h2>
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
                <h2 class="section-title">📋 Detailed Segment Table</h2>
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


def print_help(prog: str):
    """Print detailed helper prompt"""
    print(
                f"""Usage: {prog} <memory_dump_file> [options]

Linux crash analysis tool for /proc/<pid>/maps dumps.

Output Options (each shows only its specific report):
    --report             -- Show all reports (default if no options given)
    --table              -- Show memory map table view only
    --stats              -- Show memory statistics only
    --grouped            -- Show memory map grouped by binary only
    --segments           -- Show segment overview visualization only
    --ascii              -- Show ASCII memory layout only
    --security           -- Show security analysis only
    --html <file>        -- Generate HTML visualization to specified file
                         -- If no filename given, defaults to report.html

Crash Analysis Options (shows crash context analysis only):
    --pc <addr>          -- Program counter address (hex)
    --lr <addr>          -- Link register address (hex)
    --sp <addr>          -- Stack pointer address (hex)
    --fp <addr>          -- Frame pointer address (hex)

Help:
    -h, --help           -- Show this help menu

Examples:
    {prog} memmap.txt                         # Show all reports
    {prog} memmap.txt --report                # Show all reports (explicit)
    {prog} memmap.txt --table                 # Show only table view
    {prog} memmap.txt --ascii                 # Show only ASCII map
    {prog} memmap.txt --segments              # Show only segment overview
    {prog} memmap.txt --html output.html      # Generate HTML visualization
    {prog} memmap.txt --html                  # Generate HTML to report.html (default)
    {prog} memmap.txt --pc 0xf79e245c         # Show only crash analysis for PC
    {prog} memmap.txt --pc 0x1234 --html crash.html  # HTML with crash markers
    {prog} memmap.txt --stats --security      # Show stats and security reports
"""
    )


def main():
    """Main entry point"""
    # Check for help flag
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        print_help(sys.argv[0])
        sys.exit(0 if len(sys.argv) >= 2 else 1)
    
    # Check that first argument is a filename, not a flag
    if sys.argv[1].startswith('-'):
        print(f"Error: No memory dump file specified", file=sys.stderr)
        print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
        sys.exit(1)
    
    filename = sys.argv[1]
    
    # Validate command line options
    valid_flags = {
        '--report', '--table', '--stats', '--grouped', '--segments', '--ascii', '--security',
        '--pc', '--lr', '--sp', '--fp', '--html'
    }
    
    # Check for invalid options
    skip_next = False
    for i, arg in enumerate(sys.argv[2:], 2):  # Start from index 2 (skip filename)
        if skip_next:
            skip_next = False
            continue
        
        if arg.startswith('--'):
            if arg not in valid_flags:
                print(f"Error: Unknown option '{arg}'", file=sys.stderr)
                print(f"Run '{sys.argv[0]} --help' for usage information.", file=sys.stderr)
                sys.exit(1)
            
            # Skip next arg if it's an address value for crash options or filename for html
            if arg in {'--pc', '--lr', '--sp', '--fp', '--html'} and i + 1 < len(sys.argv):
                skip_next = True
    
    # Parse command line options
    show_report = '--report' in sys.argv
    show_table = '--table' in sys.argv
    show_stats = '--stats' in sys.argv
    show_grouped = '--grouped' in sys.argv
    show_segments = '--segments' in sys.argv
    show_ascii = '--ascii' in sys.argv
    show_security = '--security' in sys.argv
    
    html_output = None
    crash_ctx = CrashContext()
    has_crash_opts = False
    
    for i, arg in enumerate(sys.argv):
        if arg == '--pc' and i + 1 < len(sys.argv):
            crash_ctx.pc = int(sys.argv[i + 1], 16)
            has_crash_opts = True
        elif arg == '--lr' and i + 1 < len(sys.argv):
            crash_ctx.lr = int(sys.argv[i + 1], 16)
            has_crash_opts = True
        elif arg == '--sp' and i + 1 < len(sys.argv):
            crash_ctx.sp = int(sys.argv[i + 1], 16)
            has_crash_opts = True
        elif arg == '--fp' and i + 1 < len(sys.argv):
            crash_ctx.fp = int(sys.argv[i + 1], 16)
            has_crash_opts = True
        elif arg == '--html':
            # Check if next argument exists and is not a flag
            if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith('--'):
                html_output = sys.argv[i + 1]
            else:
                html_output = f"{os.path.basename(filename)}.html"
    
    # Parse memory map
    memmap = MemoryMapParser.parse_file(filename)
    
    # Handle HTML output
    if html_output:
        HTMLGenerator.generate_html(memmap, crash_ctx, html_output)
        return
    
    # Determine what to display
    # If no options given, default to --report
    any_option = (show_report or show_table or show_stats or show_grouped or 
                  show_segments or show_ascii or show_security or has_crash_opts)
    
    if not any_option:
        show_report = True
    
    # Show requested reports
    if show_report:
        # Show all reports
        MemoryMapVisualizer.print_table(memmap)
        MemoryMapVisualizer.print_statistics(memmap)
        MemoryMapVisualizer.print_grouped_by_binary(memmap)
        MemoryMapVisualizer.print_ascii_layout(memmap, crash_ctx)
        if has_crash_opts:
            CrashAnalyzer.analyze_crash(memmap, crash_ctx)
        CrashAnalyzer.check_security(memmap)
    else:
        # Show only requested reports
        if show_table:
            MemoryMapVisualizer.print_table(memmap)
        
        if show_stats:
            MemoryMapVisualizer.print_statistics(memmap)
        
        if show_grouped:
            MemoryMapVisualizer.print_grouped_by_binary(memmap)
        
        if show_segments:
            MemoryMapVisualizer.print_segments_overview(memmap)
        
        if show_ascii:
            MemoryMapVisualizer.print_ascii_layout(memmap, crash_ctx)
        
        if has_crash_opts:
            CrashAnalyzer.analyze_crash(memmap, crash_ctx)
        
        if show_security:
            CrashAnalyzer.check_security(memmap)


if __name__ == '__main__':
    main()
