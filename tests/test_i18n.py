"""
Tests for analyzer/i18n.py — language resolution, translation, and
integration with the analysis engine.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.i18n import (
    resolve_lang, translate_finding, get_rec_reason, category_label,
    CATEGORY_CATALOG, CATEGORY_LABELS, SUPPORTED_LANGS,
)
from analyzer.engine import analyze_diff, result_to_dict
from analyzer.rules import RULE_REGISTRY


# ── resolve_lang ────────────────────────────────────────────────

class TestResolveLang:
    def test_en_returns_en(self):
        assert resolve_lang("en") == "en"

    def test_es_returns_es(self):
        assert resolve_lang("es") == "es"

    def test_uppercase_normalised(self):
        assert resolve_lang("ES") == "es"
        assert resolve_lang("EN") == "en"

    def test_unknown_falls_back_to_en(self):
        assert resolve_lang("fr") == "en"
        assert resolve_lang("de") == "en"
        assert resolve_lang("zh") == "en"

    def test_empty_string_falls_back_to_en(self):
        assert resolve_lang("") == "en"

    def test_none_like_empty_falls_back_to_en(self):
        # resolve_lang expects a str; passing falsy string
        assert resolve_lang("  ") == "en"


# ── CATEGORY_LABELS ──────────────────────────────────────────────

class TestCategoryLabels:
    def test_all_supported_langs_present(self):
        for lang in SUPPORTED_LANGS:
            assert lang in CATEGORY_LABELS

    def test_all_categories_in_es(self):
        en_keys = set(CATEGORY_LABELS["en"].keys())
        es_keys = set(CATEGORY_LABELS["es"].keys())
        assert en_keys == es_keys

    def test_es_labels_not_same_as_en(self):
        # At least some labels should differ
        en = CATEGORY_LABELS["en"]
        es = CATEGORY_LABELS["es"]
        diffs = [k for k in en if en[k] != es[k]]
        assert len(diffs) > 0

    def test_rule_registry_categories_exist_in_catalog(self):
        assert {rule.category for rule in RULE_REGISTRY} == set(CATEGORY_CATALOG)

    def test_rule_ids_are_unique(self):
        rule_ids = [rule.rule_id for rule in RULE_REGISTRY]
        assert len(rule_ids) == len(set(rule_ids))

    def test_category_label_falls_back_for_unknown_category(self):
        assert category_label("custom_rule", "es") == "custom_rule"


# ── translate_finding ─────────────────────────────────────────────

class TestTranslateFinding:
    def test_en_returns_original(self):
        expl = "password detected in source"
        fix  = "Remove the literal value."
        out_expl, out_fix = translate_finding("secrets", expl, fix, "en")
        assert out_expl == expl
        assert out_fix  == fix

    def test_es_secrets_password_translated(self):
        expl = "Plain-text password detected."
        fix  = "Remove the literal value."
        out_expl, out_fix = translate_finding("secrets", expl, fix, "es")
        # Must be in Spanish and different from English
        assert out_expl != expl
        assert "contrase" in out_expl.lower() or "credencial" in out_expl.lower()

    def test_es_secrets_api_key_translated(self):
        expl = "API key detected in source file."
        fix  = "Move to env var."
        out_expl, out_fix = translate_finding("secrets", expl, fix, "es")
        assert out_expl != expl

    def test_es_unsafe_input_eval_translated(self):
        expl = "Use of eval() with potentially untrusted data."
        fix  = "Replace eval() with ast.literal_eval."
        out_expl, out_fix = translate_finding("unsafe_input", expl, fix, "es")
        assert "eval" in out_expl

    def test_es_no_match_falls_back_to_original(self):
        expl = "Some completely unknown explanation text."
        fix  = "Do something."
        out_expl, out_fix = translate_finding("secrets", expl, fix, "es")
        assert out_expl == expl
        assert out_fix  == fix

    def test_es_insecure_dependency_fix_translated_explanation_kept(self):
        # insecure_dependency keeps explanation (None in _FINDING_ES) but translates fix
        expl = "known-vulnerable package requests==2.19.0 (CVE-2023-32681)"
        fix  = "Upgrade to safe version."
        out_expl, out_fix = translate_finding("insecure_dependency", expl, fix, "es")
        # explanation preserved
        assert out_expl == expl
        # fix translated to Spanish
        assert out_fix != fix
        assert "actualiza" in out_fix.lower() or "dependencias" in out_fix.lower()


# ── get_rec_reason ────────────────────────────────────────────────

class TestGetRecReason:
    def test_en_critical(self):
        reason = get_rec_reason("en", "critical", 3)
        assert "3" in reason
        assert "critical" in reason.lower() or "resolved" in reason.lower()

    def test_es_critical(self):
        reason = get_rec_reason("es", "critical", 2)
        assert "2" in reason
        # Spanish text
        assert "cr" in reason.lower()  # crítico / críticos

    def test_en_none_level(self):
        reason = get_rec_reason("en", "none", 0)
        assert len(reason) > 0

    def test_es_none_level(self):
        reason = get_rec_reason("es", "none", 0)
        assert len(reason) > 0
        assert reason != get_rec_reason("en", "none", 0)

    def test_unknown_lang_falls_back_to_en(self):
        en_reason = get_rec_reason("en", "high", 1)
        fr_reason = get_rec_reason("fr", "high", 1)
        assert en_reason == fr_reason

    def test_placeholder_replaced(self):
        reason = get_rec_reason("en", "high", 5)
        assert "{n}" not in reason
        assert "5" in reason


# ── Engine integration ────────────────────────────────────────────

DIRTY_DIFF = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,5 @@
 import os
+PASSWORD = "s3cr3tpass"
+def run(cmd):
+    os.system(cmd)
"""

class TestEngineWithLang:
    def test_analyze_en_produces_english_summary(self):
        result = analyze_diff(DIRTY_DIFF, lang="en")
        reason = result.summary.recommendation_reason
        # English text
        assert "finding" in reason.lower() or "resolve" in reason.lower() or "no issue" in reason.lower()

    def test_analyze_es_produces_spanish_summary(self):
        result = analyze_diff(DIRTY_DIFF, lang="es")
        reason = result.summary.recommendation_reason
        # Should differ from English and contain Spanish text
        en_reason = analyze_diff(DIRTY_DIFF, lang="en").summary.recommendation_reason
        assert reason != en_reason

    def test_result_to_dict_en(self):
        result = analyze_diff(DIRTY_DIFF, lang="en")
        d = result_to_dict(result, lang="en")
        assert "findings" in d
        assert "summary" in d
        # Explanations in English
        for f in d["findings"]:
            assert isinstance(f["explanation"], str)
            assert len(f["explanation"]) > 0

    def test_result_contains_localized_category_labels(self):
        result = analyze_diff(DIRTY_DIFF, lang="es")
        payload = result_to_dict(result, lang="es")
        for finding in payload["findings"]:
            assert finding["category_label"] == category_label(finding["category"], "es")

    def test_result_to_dict_es_findings_translated(self):
        result = analyze_diff(DIRTY_DIFF, lang="es")
        d_es = result_to_dict(result, lang="es")
        d_en = result_to_dict(result, lang="en")
        # At least one finding explanation should differ between languages
        es_expls = {f["explanation"] for f in d_es["findings"]}
        en_expls = {f["explanation"] for f in d_en["findings"]}
        # If there are findings, at least some should differ
        if es_expls and en_expls:
            assert es_expls != en_expls, "All ES explanations identical to EN — translation not applied"
