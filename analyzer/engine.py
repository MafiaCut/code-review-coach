"""
Review engine: orchestrates parsing, rule execution, and summary generation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any

from .i18n import (
    NO_ISSUES, NORMAL_REVIEW, category_label, category_next_step,
    category_risk, get_rec_reason, translate_finding, resolve_lang,
)
from .parser import DiffDocument, parse_diff_document, filter_supported
from .rules import RULE_REGISTRY, FileContext, Finding, SEVERITY_ORDER


@dataclass
class ReviewSummary:
    total_findings: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    main_risks: List[str]
    next_steps: List[str]
    recommendation: str      # APPROVE | REQUEST_CHANGES | NEEDS_DISCUSSION
    recommendation_reason: str


@dataclass
class ReviewResult:
    findings: List[Finding]
    summary: ReviewSummary
    files_reviewed: List[str]
    lines_analyzed: int


# ─────────────────────────────────────────────
# Summary generation (rule-based, no LLM)
# ─────────────────────────────────────────────

def _build_summary(findings: List[Finding], lang: str = "en") -> ReviewSummary:
    by_severity: Dict[str, int] = {}
    by_category: Dict[str, int] = {}

    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1

    seen_cats: set = set()
    main_risks: List[str] = []
    next_steps: List[str] = []

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    for f in sorted_findings:
        if f.category not in seen_cats:
            seen_cats.add(f.category)
            risk = category_risk(f.category, lang)
            step = category_next_step(f.category, lang)
            if risk:
                main_risks.append(risk)
            if step:
                next_steps.append(step)

    if not findings:
        main_risks = [NO_ISSUES.get(lang, NO_ISSUES["en"])]
        next_steps = [NORMAL_REVIEW.get(lang, NORMAL_REVIEW["en"])]

    critical = by_severity.get("critical", 0)
    high = by_severity.get("high", 0)
    medium = by_severity.get("medium", 0)

    if critical > 0:
        recommendation = "REQUEST_CHANGES"
        reason = get_rec_reason(lang, "critical", critical)
    elif high > 0:
        recommendation = "REQUEST_CHANGES"
        reason = get_rec_reason(lang, "high", high)
    elif medium > 0:
        recommendation = "NEEDS_DISCUSSION"
        reason = get_rec_reason(lang, "medium", medium)
    elif findings:
        recommendation = "APPROVE_WITH_NOTES"
        reason = get_rec_reason(lang, "low")
    else:
        recommendation = "APPROVE"
        reason = get_rec_reason(lang, "none")

    return ReviewSummary(
        total_findings=len(findings),
        by_severity=by_severity,
        by_category=by_category,
        main_risks=main_risks,
        next_steps=next_steps,
        recommendation=recommendation,
        recommendation_reason=reason,
    )


# ─────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────

def _build_file_contexts(document: DiffDocument) -> Dict[tuple, FileContext]:
    """Build an isolated context for every supported hunk in the diff."""
    contexts: Dict[tuple, FileContext] = {}
    for hunk in document.hunks:
        supported = filter_supported(hunk.lines)
        context = FileContext(supported)
        if context.added_lines:
            contexts[(hunk.filename, hunk.hunk_id)] = context
    return contexts


def analyze_diff(diff_text: str, lang: str = "en") -> ReviewResult:
    """
    Parse a unified diff, run all rules, and return a ReviewResult.
    The diff text is treated as untrusted input and is never executed.
    lang: 'en' (default) or 'es' — controls all human-readable output.
    """
    lang = resolve_lang(lang)
    document = parse_diff_document(diff_text)
    supported_lines = filter_supported(document.added_lines)

    file_contexts = _build_file_contexts(document)

    findings: List[Finding] = []
    for rule in RULE_REGISTRY:
        if rule.requires_context:
            for ctx in file_contexts.values():
                findings.extend(rule.run(ctx.added_lines, ctx=ctx))
        else:
            findings.extend(rule.run(supported_lines))

    deduped: Dict[tuple, Finding] = {}
    for f in findings:
        key = (f.filename, f.line_number, f.category)
        if key not in deduped or SEVERITY_ORDER.get(f.severity, 99) < SEVERITY_ORDER.get(deduped[key].severity, 99):
            deduped[key] = f

    final_findings = sorted(
        deduped.values(),
        key=lambda f: (f.filename, f.line_number or 0, SEVERITY_ORDER.get(f.severity, 99)),
    )

    files_reviewed = sorted({dl.filename for dl in supported_lines})
    summary = _build_summary(final_findings, lang=lang)

    return ReviewResult(
        findings=final_findings,
        summary=summary,
        files_reviewed=files_reviewed,
        lines_analyzed=len(supported_lines),
    )


def result_to_dict(result: ReviewResult, lang: str = "en") -> Dict[str, Any]:
    """Serialize ReviewResult to a JSON-safe dict, translating findings to lang."""
    lang = resolve_lang(lang)
    return {
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "category_label": category_label(f.category, lang),
                "filename": f.filename,
                "line_number": f.line_number,
                "explanation": translate_finding(f.category, f.explanation, f.recommended_fix, lang)[0],
                "recommended_fix": translate_finding(f.category, f.explanation, f.recommended_fix, lang)[1],
                "matched_text": f.matched_text,
            }
            for f in result.findings
        ],
        "summary": {
            "total_findings": result.summary.total_findings,
            "by_severity": result.summary.by_severity,
            "by_category": result.summary.by_category,
            "main_risks": result.summary.main_risks,
            "next_steps": result.summary.next_steps,
            "recommendation": result.summary.recommendation,
            "recommendation_reason": result.summary.recommendation_reason,
        },
        "files_reviewed": result.files_reviewed,
        "lines_analyzed": result.lines_analyzed,
        "lang": lang,
        "llm_enhanced": False,
    }
