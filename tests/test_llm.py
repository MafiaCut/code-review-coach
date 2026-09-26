"""
Tests for the optional LLM enhancement layer.
Uses unittest.mock to avoid real API calls.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock
from analyzer.llm import enhance_summary, LLMConfig, _load_config, _build_prompt, _call_llm


SAMPLE_RESULT = {
    "findings": [
        {
            "severity": "critical",
            "category": "secrets",
            "filename": "auth.py",
            "line_number": 5,
            "explanation": "Hardcoded password detected.",
            "recommended_fix": "Use environment variables.",
            "matched_text": "password = 'hunter2'",
        }
    ],
    "summary": {
        "total_findings": 1,
        "by_severity": {"critical": 1},
        "by_category": {"secrets": 1},
        "main_risks": ["Credentials in git history."],
        "next_steps": ["Rotate and remove."],
        "recommendation": "REQUEST_CHANGES",
        "recommendation_reason": "1 critical finding.",
    },
    "files_reviewed": ["auth.py"],
    "lines_analyzed": 5,
}


class TestLLMConfig:
    def test_load_config_returns_none_when_missing(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LLM_API_URL", None)
            os.environ.pop("LLM_API_KEY", None)
            os.environ.pop("LLM_MODEL_ID", None)
            config = _load_config()
        assert config is None

    def test_load_config_returns_config_when_set(self):
        with patch.dict(os.environ, {
            "LLM_API_URL": "https://example.com/ml/v1/text/generation",
            "LLM_API_KEY": "my_key",
            "LLM_MODEL_ID": "ibm/granite-13b-chat",
        }):
            config = _load_config()
        assert config is not None
        assert config.api_url == "https://example.com/ml/v1/text/generation"
        assert config.model_id == "ibm/granite-13b-chat"


class TestBuildPrompt:
    def test_prompt_contains_findings(self):
        prompt = _build_prompt(SAMPLE_RESULT)
        assert "secrets" in prompt
        assert "critical" in prompt.lower() or "CRITICAL" in prompt
        assert "auth.py" in prompt

    def test_prompt_contains_recommendation(self):
        prompt = _build_prompt(SAMPLE_RESULT)
        assert "REQUEST_CHANGES" in prompt

    def test_prompt_does_not_contain_diff_content(self):
        # The diff text itself should never be included
        prompt = _build_prompt(SAMPLE_RESULT)
        assert "diff --git" not in prompt
        assert "@@" not in prompt


class TestEnhanceSummary:
    def test_no_config_returns_original_unchanged(self):
        with patch("analyzer.llm._load_config", return_value=None):
            enhanced, llm_used = enhance_summary(SAMPLE_RESULT)
        assert enhanced is SAMPLE_RESULT
        assert llm_used is False

    def test_env_vars_missing_returns_original(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LLM_API_URL", None)
            os.environ.pop("LLM_API_KEY", None)
            os.environ.pop("LLM_MODEL_ID", None)
            enhanced, llm_used = enhance_summary(SAMPLE_RESULT)
        assert llm_used is False
        assert "llm_narrative" not in enhanced.get("summary", {})

    def test_llm_success_adds_narrative(self):
        config = LLMConfig(
            api_url="https://watsonx.example.com/ml/v1/text/generation",
            api_key="key",
            model_id="ibm/granite",
        )
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({
            "results": [{"generated_text": "This change has a critical secret leak."}]
        }).encode()

        with patch("analyzer.llm.urllib.request.urlopen", return_value=mock_resp):
            enhanced, llm_used = enhance_summary(SAMPLE_RESULT, config=config)

        assert llm_used is True
        assert enhanced["summary"]["llm_narrative"] == "This change has a critical secret leak."

    def test_llm_timeout_falls_back_gracefully(self):
        import urllib.error
        config = LLMConfig(api_url="https://watsonx.example.com/ml/v1", api_key="k", model_id="m")
        with patch("analyzer.llm.urllib.request.urlopen",
                   side_effect=TimeoutError("timed out")):
            enhanced, llm_used = enhance_summary(SAMPLE_RESULT, config=config)
        assert llm_used is False
        assert enhanced is SAMPLE_RESULT

    def test_llm_error_falls_back_gracefully(self):
        import urllib.error
        config = LLMConfig(api_url="https://example.com/v1/chat/completions",
                           api_key="k", model_id="gpt-4")
        with patch("analyzer.llm.urllib.request.urlopen",
                   side_effect=urllib.error.HTTPError(None, 500, "Server Error", {}, None)):
            enhanced, llm_used = enhance_summary(SAMPLE_RESULT, config=config)
        assert llm_used is False

    def test_original_dict_not_mutated(self):
        config = LLMConfig(api_url="https://watsonx.example.com/ml/v1", api_key="k", model_id="m")
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({
            "results": [{"generated_text": "AI narrative here."}]
        }).encode()

        import copy
        original = copy.deepcopy(SAMPLE_RESULT)
        with patch("analyzer.llm.urllib.request.urlopen", return_value=mock_resp):
            enhanced, _ = enhance_summary(SAMPLE_RESULT, config=config)

        # Original dict must not have been modified
        assert "llm_narrative" not in SAMPLE_RESULT["summary"]
        assert enhanced["summary"]["llm_narrative"] == "AI narrative here."


class TestOpenAICompatible:
    def test_openai_format_used_for_non_watsonx_url(self):
        config = LLMConfig(
            api_url="https://api.openai.com/v1/chat/completions",
            api_key="sk-test",
            model_id="gpt-4",
        )
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["data"] = json.loads(req.data)
            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.read.return_value = json.dumps({
                "choices": [{"message": {"content": "OpenAI narrative."}}]
            }).encode()
            return mock_resp

        with patch("analyzer.llm.urllib.request.urlopen", side_effect=fake_urlopen):
            enhanced, llm_used = enhance_summary(SAMPLE_RESULT, config=config)

        assert llm_used is True
        # Verify the OpenAI message format was used
        assert "messages" in captured["data"]
        assert captured["data"]["model"] == "gpt-4"
