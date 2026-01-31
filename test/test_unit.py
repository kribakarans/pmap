#!/usr/bin/env python3
"""
Unit tests for pmap memory analysis tool
"""

import sys
import os

# Add parent directory to path to import lib module
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from lib.api import (
    SegmentType, MemorySegment, MemoryMap, CrashContext,
    MemoryMapParser, CrashAnalyzer, MemoryMapVisualizer, HTMLGenerator
)


def test_segment_classification():
    """Test segment type classification"""
    print("Test 1: Segment Classification... ", end="")
    
    # Test heap
    seg = MemorySegment(0x1000, 0x2000, 0x1000, "rw-p", 0, 0, 0, 0, "[heap]")
    seg.classify()
    assert seg.seg_type == SegmentType.HEAP
    
    # Test stack
    seg = MemorySegment(0x1000, 0x2000, 0x1000, "rw-p", 0, 0, 0, 0, "[stack]")
    seg.classify()
    assert seg.seg_type == SegmentType.STACK
    
    # Test code
    seg = MemorySegment(0x1000, 0x2000, 0x1000, "r-xp", 0, 0, 0, 0, "/lib/libc.so")
    seg.classify()
    assert seg.seg_type == SegmentType.CODE
    
    # Test rodata
    seg = MemorySegment(0x1000, 0x2000, 0x1000, "r--p", 0, 0, 0, 0, "/lib/libc.so")
    seg.classify()
    assert seg.seg_type == SegmentType.RODATA
    
    # Test data
    seg = MemorySegment(0x1000, 0x2000, 0x1000, "rw-p", 0, 0, 0, 0, "/lib/libc.so")
    seg.classify()
    assert seg.seg_type == SegmentType.DATA
    
    print("PASS")


def test_memory_map_parser():
    """Test memory map file parsing"""
    print("Test 2: Memory Map Parser... ", end="")
    
    # Look for test file in test directory
    test_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pmap-sample.txt")
    if not os.path.exists(test_file):
        print("SKIP (no test file)")
        return
    
    memmap = MemoryMapParser.parse_file(test_file)
    
    assert len(memmap.segments) > 0, "Should parse segments"
    assert memmap.total_size > 0, "Should calculate total size"
    assert memmap.process_name != "", "Should extract process name"
    
    print(f"PASS ({len(memmap.segments)} segments)")


def test_find_segment():
    """Test finding segment by address"""
    print("Test 3: Find Segment by Address... ", end="")
    
    memmap = MemoryMap()
    memmap.segments = [
        MemorySegment(0x1000, 0x2000, 0x1000, "r-xp", 0, 0, 0, 0, "/bin/test"),
        MemorySegment(0x3000, 0x4000, 0x1000, "rw-p", 0, 0, 0, 0, "[stack]"),
    ]
    
    # Test finding valid segment
    seg = memmap.find_segment(0x1500)
    assert seg is not None
    assert seg.start == 0x1000
    assert seg.end == 0x2000
    
    # Test finding invalid address
    seg = memmap.find_segment(0x5000)
    assert seg is None
    
    print("PASS")


def test_crash_context():
    """Test crash context creation"""
    print("Test 4: Crash Context... ", end="")
    
    ctx = CrashContext()
    ctx.pc = 0xf79e245c
    ctx.lr = 0xf79e7f10
    ctx.sp = 0xff8b0000
    ctx.fp = 0xff8b0010
    
    assert ctx.pc == 0xf79e245c
    assert ctx.lr == 0xf79e7f10
    assert ctx.sp == 0xff8b0000
    assert ctx.fp == 0xff8b0010
    
    print("PASS")


def test_segment_properties():
    """Test segment property methods"""
    print("Test 5: Segment Properties... ", end="")
    
    seg = MemorySegment(0x1000, 0x2000, 0x1000, "rwxp", 0, 0, 0, 0, "test")
    
    assert seg.is_readable == True
    assert seg.is_writable == True
    assert seg.is_executable == True
    assert seg.is_private == True
    
    seg2 = MemorySegment(0x1000, 0x2000, 0x1000, "r--s", 0, 0, 0, 0, "test")
    assert seg2.is_readable == True
    assert seg2.is_writable == False
    assert seg2.is_executable == False
    assert seg2.is_private == False
    
    print("PASS")


def test_memory_map_functions():
    """Test memory map utility functions"""
    print("Test 6: Memory Map Utilities... ", end="")
    
    memmap = MemoryMap()
    memmap.segments = [
        MemorySegment(0x1000, 0x2000, 0x1000, "r-xp", 0, 0, 0, 0, "/lib/libc.so"),
        MemorySegment(0x2000, 0x3000, 0x1000, "rw-p", 0, 0, 0, 0, "/lib/libc.so"),
        MemorySegment(0x4000, 0x5000, 0x1000, "rw-p", 0, 0, 0, 0, "[heap]"),
    ]
    
    # Test total size
    assert memmap.total_size == 0x3000
    
    # Test get segments by binary
    libc_segs = memmap.get_segments_by_binary("/lib/libc.so")
    assert len(libc_segs) == 2
    
    heap_segs = memmap.get_segments_by_binary("[heap]")
    assert len(heap_segs) == 1
    
    print("PASS")


def test_html_generator_colors():
    """Test HTML generator has color mappings"""
    print("Test 7: HTML Generator Colors... ", end="")
    
    assert SegmentType.CODE in HTMLGenerator.SEGMENT_COLORS
    assert SegmentType.DATA in HTMLGenerator.SEGMENT_COLORS
    assert SegmentType.STACK in HTMLGenerator.SEGMENT_COLORS
    assert SegmentType.HEAP in HTMLGenerator.SEGMENT_COLORS
    
    print("PASS")


def test_parser_regex():
    """Test memory map parser regex"""
    print("Test 8: Parser Regex... ", end="")
    
    # Test valid line
    line = "0098b000-0098c000 r-xp 00000000 b3:04 6081  /usr/bin/amxrt"
    seg = MemoryMapParser.parse_line(line)
    
    assert seg is not None
    assert seg.start == 0x0098b000
    assert seg.end == 0x0098c000
    assert seg.perms == "r-xp"
    assert seg.pathname == "/usr/bin/amxrt"
    
    # Test anonymous mapping
    line2 = "0214f000-0218a000 rw-p 00000000 00:00 0    [heap]"
    seg2 = MemoryMapParser.parse_line(line2)
    assert seg2 is not None
    assert seg2.pathname == "[heap]"
    
    print("PASS")


def main():
    """Run all unit tests"""
    print("=" * 70)
    print("PMAP UNIT TESTS")
    print("=" * 70)
    print()
    
    tests = [
        test_segment_classification,
        test_memory_map_parser,
        test_find_segment,
        test_crash_context,
        test_segment_properties,
        test_memory_map_functions,
        test_html_generator_colors,
        test_parser_regex,
    ]
    
    passed = 0
    failed = 0
    skipped = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"FAIL - {e}")
            failed += 1
        except Exception as e:
            if "SKIP" in str(e):
                skipped += 1
            else:
                print(f"ERROR - {e}")
                failed += 1
    
    print()
    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    print("=" * 70)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
