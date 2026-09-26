"""Safe, hunk-aware unified-diff parsing."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .rules import DiffLine, _lang

_HUNK_HEADER = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
)


@dataclass
class DiffHunk:
    """One contiguous hunk, including added, removed, and context lines."""

    filename: str
    hunk_id: int
    old_start: int
    new_start: int
    lines: List[DiffLine] = field(default_factory=list)

    @property
    def added_lines(self) -> List[DiffLine]:
        return [line for line in self.lines if line.kind == "added"]


@dataclass
class DiffDocument:
    """Structured representation of a unified diff."""

    hunks: List[DiffHunk] = field(default_factory=list)

    @property
    def added_lines(self) -> List[DiffLine]:
        return [line for hunk in self.hunks for line in hunk.added_lines]


def _new_path(header: str) -> str:
    """Extract and safely decode a path from a ``+++`` header."""
    value = header[4:].split("\t", 1)[0].strip()
    if value.startswith('"') and value.endswith('"'):
        try:
            decoded = ast.literal_eval(value)
            if isinstance(decoded, str):
                value = decoded
        except (SyntaxError, ValueError):
            pass
    if value == "/dev/null":
        return "unknown"
    return value[2:] if value.startswith("b/") else value


def parse_diff_document(diff_text: str) -> DiffDocument:
    """Parse untrusted diff text into files and isolated hunks without executing it."""
    document = DiffDocument()
    current_file = "unknown"
    current_lang = "unknown"
    current_hunk: Optional[DiffHunk] = None
    old_line_no = 0
    new_line_no = 0
    next_hunk_id = 1

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ "):
            current_file = _new_path(raw_line)
            current_lang = _lang(current_file)
            current_hunk = None
            continue

        match = _HUNK_HEADER.match(raw_line)
        if match:
            old_line_no = int(match.group(1))
            new_line_no = int(match.group(3))
            current_hunk = DiffHunk(
                filename=current_file,
                hunk_id=next_hunk_id,
                old_start=old_line_no,
                new_start=new_line_no,
            )
            next_hunk_id += 1
            document.hunks.append(current_hunk)
            continue

        if current_hunk is None or not raw_line:
            continue

        marker = raw_line[0]
        if marker == "\\":  # ``No newline at end of file`` marker
            continue
        if marker == "+":
            current_hunk.lines.append(DiffLine(
                current_file, new_line_no, raw_line[1:], current_lang,
                kind="added", hunk_id=current_hunk.hunk_id,
            ))
            new_line_no += 1
        elif marker == "-":
            current_hunk.lines.append(DiffLine(
                current_file, None, raw_line[1:], current_lang,
                kind="removed", old_line_number=old_line_no,
                hunk_id=current_hunk.hunk_id,
            ))
            old_line_no += 1
        elif marker == " ":
            current_hunk.lines.append(DiffLine(
                current_file, new_line_no, raw_line[1:], current_lang,
                kind="context", old_line_number=old_line_no,
                hunk_id=current_hunk.hunk_id,
            ))
            old_line_no += 1
            new_line_no += 1

    return document


def parse_diff(diff_text: str) -> List[DiffLine]:
    """Return added lines, preserving the original public API."""
    return parse_diff_document(diff_text).added_lines


def filter_supported(diff_lines: List[DiffLine]) -> List[DiffLine]:
    """Return lines belonging to supported file types."""
    supported = {"python", "javascript", "typescript", "requirements", "package_json"}
    return [line for line in diff_lines if line.language in supported]
