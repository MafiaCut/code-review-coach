"""
Optional LLM enhancement layer for the Code Review Coach.

When LLM_API_URL, LLM_API_KEY, and LLM_MODEL_ID environment variables are set,
enhance_summary() sends the structured findings (NOT the diff content) to the LLM
and replaces the rule-based summary narrative with a richer AI-generated one.

If any variable is missing, or if the LLM call times out or errors, the original
rule-based summary is returned unchanged — the core flow is unaffected.

Compatible with IBM watsonx.ai (POST /ml/v1/text/generation) and any
OpenAI-compatible chat completions endpoint.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    api_url: str
    api_key: str
    model_id: str
    timeout_seconds: int = 15
    max_tokens: int = 400


def _load_config() -> Optional[LLMConfig]:
    """Build LLMConfig from environment variables. Returns None if incomplete."""
    url = os.environ.get("LLM_API_URL", "").strip()
    key = os.environ.get("LLM_API_KEY", "").strip()
    model = os.environ.get("LLM_MODEL_ID", "").strip()
    if not (url and key and model):
        return None
    return LLMConfig(api_url=url, api_key=key, model_id=model)


def _build_prompt(findings_summary: dict) -> str:
    """
    Build a structured prompt from findings metadata.
    The raw diff is NEVER included — only finding categories, severities,
    explanations, and file names are sent to the LLM.
    """
    lang = findings_summary.get("lang", "en")
    if lang == "es":
        intro = [
            "Eres un ingeniero de software senior realizando una revision de codigo.",
            "La herramienta de analisis estatico encontro los siguientes problemas.",
            "Escribe un resumen de revision conciso (max 120 palabras) que cubra:",
            "1. El riesgo mas critico y por que importa.",
            "2. La senal general de calidad del codigo.",
            "3. Un proximo paso claro para el desarrollador.",
            "Se directo y especifico. No inventes problemas que no esten en la lista de abajo.",
            "Responde SOLO en espanol.",
        ]
        findings_header = "=== HALLAZGOS ==="
        summary_header = "=== RESUMEN ==="
        rec_label = "Recomendacion"
        total_label = "Total de hallazgos"
        close = "Escribe solo el parrafo narrativo, sin encabezados."
    else:
        intro = [
            "You are a senior software engineer performing a code review.",
            "The automated static analysis tool found the following issues.",
            "Write a concise review summary (max 120 words) covering:",
            "1. The most critical risk and why it matters.",
            "2. The overall code quality signal.",
            "3. One clear next step for the developer.",
            "Be direct and specific. Do not invent issues not listed below.",
        ]
        findings_header = "=== FINDINGS ==="
        summary_header = "=== SUMMARY ==="
        rec_label = "Recommendation"
        total_label = "Total findings"
        close = "Write only the review narrative paragraph, no headings."

    lines = intro + ["", findings_header]
    for i, f in enumerate(findings_summary.get("findings", [])[:20], 1):
        lines.append(
            f"{i}. [{f['severity'].upper()}] {f['category']} "
            f"in {f['filename']} - {f['explanation'][:120]}"
        )
    lines += [
        "",
        summary_header,
        f"{rec_label}: {findings_summary['summary']['recommendation']}",
        f"{total_label}: {findings_summary['summary']['total_findings']}",
        "",
        close,
    ]
    return "\n".join(lines)


def _call_llm(prompt: str, config: LLMConfig) -> str:
    """
    Call the LLM API. Supports:
    - IBM watsonx.ai  (POST /ml/v1/text/generation)
    - OpenAI-compatible  (POST /v1/chat/completions)

    Returns the generated text or raises an exception.
    """
    url = config.api_url.rstrip("/")

    # Detect API style by URL path
    if "/ml/v1" in url or "watsonx" in url.lower():
        # IBM watsonx.ai format
        payload = {
            "model_id": config.model_id,
            "input": prompt,
            "parameters": {
                "max_new_tokens": config.max_tokens,
                "temperature": 0.3,
            },
        }
        auth_header = f"Bearer {config.api_key}"
        result_key = ("results", 0, "generated_text")
    else:
        # OpenAI-compatible format
        payload = {
            "model": config.model_id,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": config.max_tokens,
            "temperature": 0.3,
        }
        auth_header = f"Bearer {config.api_key}"
        result_key = ("choices", 0, "message", "content")

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type":  "application/json",
            "Authorization": auth_header,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=config.timeout_seconds) as resp:
        body = json.loads(resp.read())

    # Navigate to the generated text using result_key tuple
    value = body
    for key in result_key:
        if isinstance(value, list):
            value = value[key]
        else:
            value = value[key]
    return str(value).strip()


def enhance_summary(
    result_dict: dict,
    config: Optional[LLMConfig] = None,
) -> tuple[dict, bool]:
    """
    Optionally enhance the summary narrative with an LLM.

    Args:
        result_dict: The JSON-serializable dict from result_to_dict().
        config: LLMConfig instance. If None, loads from environment variables.

    Returns:
        (possibly_enhanced_dict, llm_enhanced_bool)

    The input dict is never mutated; a shallow copy with the updated summary
    narrative is returned if enhancement succeeds.
    """
    if config is None:
        config = _load_config()
    if config is None:
        return result_dict, False

    try:
        prompt = _build_prompt(result_dict)
        narrative = _call_llm(prompt, config)
        # Inject the narrative into a copy of the summary
        import copy
        enhanced = copy.deepcopy(result_dict)
        enhanced["summary"]["llm_narrative"] = narrative
        return enhanced, True
    except Exception as e:
        logger.warning("LLM enhancement failed (falling back to rule-based summary): %s", e)
        return result_dict, False
