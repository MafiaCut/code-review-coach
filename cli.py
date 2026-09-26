"""
Command-line interface for the Intelligent Code Review Coach.

Usage:
    python cli.py [--input file.patch] [--format text|json|summary]
    git diff HEAD~1 | python cli.py
    python cli.py --input my.patch --format json

Exit codes:
    0  – APPROVE or APPROVE_WITH_NOTES
    1  – REQUEST_CHANGES or NEEDS_DISCUSSION
"""
from __future__ import annotations

import argparse
import json
import sys
import os

# Ensure the project root is on the path when run directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer.engine import analyze_diff, result_to_dict, ReviewResult
from analyzer.i18n import resolve_lang, CATEGORY_LABELS
from code_review_coach import __version__

VERSION = __version__

# ── ANSI colour helpers ──────────────────────────────────────────────────────

def _use_colour() -> bool:
    return sys.stdout.isatty() and (
        os.name != "nt" or os.environ.get("TERM") is not None
    )

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[31m"
_YELLOW = "\033[33m"
_GREEN  = "\033[32m"
_CYAN   = "\033[36m"
_GREY   = "\033[90m"

_SEV_COLOUR = {
    "critical": "\033[91m",   # bright red
    "high":     "\033[31m",   # red
    "medium":   "\033[33m",   # yellow
    "low":      "\033[32m",   # green
    "info":     "\033[36m",   # cyan
}

_REC_COLOUR = {
    "APPROVE":            "\033[92m",  # bright green
    "APPROVE_WITH_NOTES": "\033[32m",  # green
    "NEEDS_DISCUSSION":   "\033[33m",  # yellow
    "REQUEST_CHANGES":    "\033[91m",  # bright red
}

_CAT_LABELS = {
    "secrets":                   "Exposed Secret",
    "unsafe_input":              "Unsafe Input",
    "error_handling":            "Error Handling",
    "likely_bug":                "Likely Bug",
    "weak_tests":                "Weak Tests",
    "logging_sensitive":         "Sensitive Logging",
    "dangerous_deserialization": "Dangerous Deserialization",
    "path_traversal":            "Path Traversal",
    "insecure_dependency":       "Insecure Dependency",
}


def _c(text: str, colour: str) -> str:
    if _use_colour():
        return f"{colour}{text}{_RESET}"
    return text


# ── Formatters ───────────────────────────────────────────────────────────────

# UI string overrides per language
_UI_STRINGS = {
    "en": {
        "title":          "Code Review Coach",
        "files_reviewed": "Files reviewed",
        "lines_analyzed": "Lines analyzed",
        "findings_count": "Findings",
        "no_issues":      "[OK] No issues detected.",
        "findings_hdr":   "FINDINGS",
        "main_risks":     "MAIN RISKS",
        "next_steps":     "NEXT STEPS",
        "fix_prefix":     "Fix",
        "matched_prefix": ">> matched",
        "findings_word":  "finding(s)",
    },
    "es": {
        "title":          "Asistente de Revision de Codigo",
        "files_reviewed": "Archivos revisados",
        "lines_analyzed": "Lineas analizadas",
        "findings_count": "Hallazgos",
        "no_issues":      "[OK] No se detectaron problemas.",
        "findings_hdr":   "HALLAZGOS",
        "main_risks":     "RIESGOS PRINCIPALES",
        "next_steps":     "PROXIMOS PASOS",
        "fix_prefix":     "Solucion",
        "matched_prefix": ">> coincidencia",
        "findings_word":  "hallazgo(s)",
    },
}


def format_summary(result: ReviewResult, lang: str = "en") -> str:
    s = result.summary
    ui = _UI_STRINGS.get(lang, _UI_STRINGS["en"])
    counts = " ".join(
        f"{n} {sev}" for sev, n in s.by_severity.items() if n > 0
    ) or f"0 {ui['findings_word']}"
    return f"{s.recommendation} - {s.total_findings} {ui['findings_word']} [{counts}]"


def format_json(result: ReviewResult, lang: str = "en") -> str:
    return json.dumps(result_to_dict(result, lang=lang), indent=2)


def format_text(result: ReviewResult, lang: str = "en") -> str:
    lines: list[str] = []
    s = result.summary
    ui = _UI_STRINGS.get(lang, _UI_STRINGS["en"])
    cats = CATEGORY_LABELS.get(lang, CATEGORY_LABELS["en"])

    rec_col = _REC_COLOUR.get(s.recommendation, "")
    lines.append(_c(f"\n{'=' * 60}", _BOLD))
    lines.append(_c(f"  {ui['title']} - {s.recommendation}", _BOLD + rec_col))
    lines.append(_c(f"{'=' * 60}", _BOLD))
    lines.append(f"  {s.recommendation_reason}")
    lines.append(f"  {ui['files_reviewed']} : {', '.join(result.files_reviewed) or '(none)'}")
    lines.append(f"  {ui['lines_analyzed']} : {result.lines_analyzed}")
    lines.append(f"  {ui['findings_count']}       : {s.total_findings}")
    lines.append("")

    if not result.findings:
        lines.append(_c(f"  {ui['no_issues']}", _GREEN))
        lines.append("")
        return "\n".join(lines)

    # Findings — use translated explanation/fix from result_to_dict
    translated_findings = result_to_dict(result, lang=lang)["findings"]
    lines.append(_c(f"  {ui['findings_hdr']}", _BOLD))
    lines.append(_c("  " + "-" * 56, _GREY))
    for i, f_dict in enumerate(translated_findings, 1):
        sev_col = _SEV_COLOUR.get(f_dict["severity"], "")
        cat_label = cats.get(f_dict["category"], f_dict["category"])
        loc = f_dict["filename"] + (f":{f_dict['line_number']}" if f_dict["line_number"] else "")
        lines.append(
            f"\n  [{i}] {_c(f_dict['severity'].upper(), sev_col)}  "
            f"{_c(cat_label, _CYAN)}  {_c(loc, _GREY)}"
        )
        lines.append(f"      {f_dict['explanation']}")
        if f_dict.get("matched_text"):
            lines.append(_c(f"      {ui['matched_prefix']}: {f_dict['matched_text'][:80]}", _GREY))
        lines.append(_c(f"      {ui['fix_prefix']}: {f_dict['recommended_fix']}", _GREEN))

    lines.append("")
    lines.append(_c(f"  {ui['main_risks']}", _BOLD))
    for r in s.main_risks:
        lines.append(f"  * {r}")
    lines.append("")
    lines.append(_c(f"  {ui['next_steps']}", _BOLD))
    for step in s.next_steps:
        lines.append(f"  >> {step}")
    lines.append("")
    lines.append(_c("-" * 60, _GREY))
    return "\n".join(lines)


# ── Exit code ────────────────────────────────────────────────────────────────

def exit_code(result: ReviewResult) -> int:
    return 0 if result.summary.recommendation in ("APPROVE", "APPROVE_WITH_NOTES") else 1


# ── Main ─────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    # Ensure stdout can handle the full UTF-8 range on Windows (cp1252 is the default)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="review-coach",
        description="Intelligent Code Review Coach - static analysis for Git diffs.",
    )
    parser.add_argument(
        "--input", "-i",
        metavar="FILE",
        help="Path to a unified diff file. Reads from stdin if omitted.",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "summary"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--lang", "-l",
        choices=["en", "es"],
        default="en",
        help="Output language: en (English, default) or es (Spanish).",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {VERSION}"
    )
    args = parser.parse_args(argv)
    lang = resolve_lang(args.lang)

    # Read diff
    if args.input:
        try:
            with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
                diff_text = fh.read()
        except OSError as e:
            print(f"ERROR: Cannot read '{args.input}': {e}", file=sys.stderr)
            return 2
    else:
        if sys.stdin.isatty():
            prompt_msg = (
                "Pega un diff unificado y presiona Ctrl-Z Enter (Windows) / Ctrl-D (Unix):"
                if lang == "es" else
                "Paste a unified diff and press Ctrl-D (Unix) / Ctrl-Z Enter (Windows):"
            )
            print(prompt_msg, file=sys.stderr)
        diff_text = sys.stdin.read()

    result = analyze_diff(diff_text, lang=lang)

    if args.format == "json":
        print(format_json(result, lang=lang))
    elif args.format == "summary":
        print(format_summary(result, lang=lang))
    else:
        print(format_text(result, lang=lang))

    return exit_code(result)


if __name__ == "__main__":
    sys.exit(main())
