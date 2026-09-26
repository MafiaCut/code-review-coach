"""
Unified diff parser.
Parses a unified diff string and returns a list of DiffLine objects
representing added lines only. Deleted lines are ignored (they are
already gone). No code is executed; this is pure text processing.
"""
from __future__ import annotations

import re
from typing import List

from .rules import DiffLine, _lang

_HUNK_HEADER = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@')
_DIFF_FILE = re.compile(r'^\+\+\+ [ab]/(.*)')


def parse_diff(diff_text: str) -> List[DiffLine]:
    """
    Parse a unified diff and return DiffLine objects for every added line
    in Python and JavaScript/TypeScript files. Lines from other file types
    are returned with language='unknown' but still included so callers can
    filter if desired.

    Security note: the diff text is treated as untrusted input. We only
    read it; we never execute it.
    """
    lines: List[DiffLine] = []
    current_file = "unknown"
    current_lang = "unknown"
    new_line_no = 0

    for raw_line in diff_text.splitlines():
        # --- new file header ---
        m = _DIFF_FILE.match(raw_line)
        if m:
            current_file = m.group(1).strip()
            current_lang = _lang(current_file)
            new_line_no = 0
            continue

        # --- hunk header: reset line counter ---
        m = _HUNK_HEADER.match(raw_line)
        if m:
            new_line_no = int(m.group(1))
            continue

        # --- context line (no leading +/-): advance counter ---
        if raw_line.startswith(" "):
            new_line_no += 1
            continue

        # --- removed line: do NOT advance new-file counter ---
        if raw_line.startswith("-") and not raw_line.startswith("---"):
            continue

        # --- added line ---
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            content = raw_line[1:]  # strip the leading '+'
            lines.append(DiffLine(
                filename=current_file,
                line_number=new_line_no,
                content=content,
                language=current_lang,
            ))
            new_line_no += 1
            continue

    return lines


def filter_supported(diff_lines: List[DiffLine]) -> List[DiffLine]:
    """Return only lines from supported languages (Python, JS/TS, requirements, package.json)."""
    return [dl for dl in diff_lines if dl.language in (
        "python", "javascript", "typescript", "requirements", "package_json"
    )]
