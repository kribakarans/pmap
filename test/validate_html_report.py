#!/usr/bin/env python3
"""
Validate that generated HTML report matches the source /proc/<pid>/maps data.

Usage:
  python3 test/validate_html_report.py <maps_file> <html_report>

Exit codes:
  0 - no mismatches
  1 - mismatches found or parse failure
"""

import sys
import os
import html as html_module
from html.parser import HTMLParser
from typing import List

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from lib.api import MemoryMapParser


class TableExtractor(HTMLParser):
    """Extract text values from the detailed segment table tbody."""

    def __init__(self) -> None:
        super().__init__()
        self.in_tbody = False
        self.in_td = False
        self.current_td = []
        self.current_row: List[str] = []
        self.rows: List[List[str]] = []

    def handle_starttag(self, tag, attrs):
        if tag == "tbody":
            self.in_tbody = True
        if self.in_tbody and tag == "td":
            self.in_td = True
            self.current_td = []

    def handle_endtag(self, tag):
        if tag == "tbody":
            self.in_tbody = False
        if self.in_tbody and tag == "td":
            self.in_td = False
            text = html_module.unescape("".join(self.current_td)).strip()
            self.current_row.append(text)
        if self.in_tbody and tag == "tr":
            if self.current_row:
                self.rows.append(self.current_row)
            self.current_row = []

    def handle_data(self, data):
        if self.in_td:
            self.current_td.append(data)


def parse_html_table(html_path: str) -> List[List[str]]:
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    parser = TableExtractor()
    parser.feed(content)
    return parser.rows


def normalize_name(name: str) -> str:
    return name.strip()


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python3 test/validate_html_report.py <maps_file> <html_report>")
        return 1

    maps_file, html_file = sys.argv[1], sys.argv[2]

    memmap = MemoryMapParser.parse_file(maps_file)
    html_rows = parse_html_table(html_file)

    if not memmap.segments:
        print("ERROR: No segments parsed from maps file.")
        return 1

    if not html_rows:
        print("ERROR: No table rows parsed from HTML report.")
        return 1

    mismatches = []

    if len(memmap.segments) != len(html_rows):
        mismatches.append(
            f"Segment count mismatch: maps={len(memmap.segments)} html={len(html_rows)}"
        )

    compare_count = min(len(memmap.segments), len(html_rows))

    for idx in range(compare_count):
        seg = memmap.segments[idx]
        row = html_rows[idx]

        if len(row) < 6:
            mismatches.append(f"Row {idx} has insufficient columns: {row}")
            continue

        html_start = row[0]
        html_end = row[1]
        html_size = row[2].replace(",", "")
        html_perms = row[3]
        html_type = row[4].replace("●", "").strip()
        html_name = normalize_name(row[5])

        expected_start = f"0x{seg.start:016x}"
        expected_end = f"0x{seg.end:016x}"
        expected_size = str(seg.size)
        expected_perms = seg.perms
        expected_type = seg.seg_type.value
        expected_name = normalize_name(seg.pathname if seg.pathname else "[anon]")

        if html_start != expected_start:
            mismatches.append(f"Row {idx} start: html={html_start} maps={expected_start}")
        if html_end != expected_end:
            mismatches.append(f"Row {idx} end: html={html_end} maps={expected_end}")
        if html_size != expected_size:
            mismatches.append(f"Row {idx} size: html={html_size} maps={expected_size}")
        if html_perms != expected_perms:
            mismatches.append(f"Row {idx} perms: html={html_perms} maps={expected_perms}")
        if html_type != expected_type:
            mismatches.append(f"Row {idx} type: html={html_type} maps={expected_type}")
        if html_name != expected_name:
            mismatches.append(f"Row {idx} name: html={html_name} maps={expected_name}")

    if mismatches:
        print("MISMATCHES FOUND:")
        for msg in mismatches:
            print(f"- {msg}")
        return 1

    print("OK: HTML report matches maps data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
