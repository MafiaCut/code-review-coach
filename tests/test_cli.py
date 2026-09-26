"""
Tests for the CLI entry point (cli.py).
Invokes the CLI as a subprocess to verify exit codes, output format, and
correct behavior with --input and --format flags.
"""
import sys, os, json, subprocess, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from code_review_coach import __version__

CLI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cli.py")

DIRTY_DIFF = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,5 @@
 import os
+SECRET = "AKIAIOSFODNN7EXAMPLE"
+def run(cmd):
+    os.system(cmd)
"""

CLEAN_DIFF = """\
diff --git a/utils.py b/utils.py
--- a/utils.py
+++ b/utils.py
@@ -1,3 +1,6 @@
 import re
+
+def validate(email: str) -> bool:
+    if not isinstance(email, str):
+        raise TypeError('email must be a string')
+    return bool(re.match(r'.+@.+', email))
"""


def run_cli(*args, stdin_text=None):
    """Run cli.py with the given args and optional stdin. Returns (returncode, stdout, stderr)."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, CLI] + list(args),
        input=stdin_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestCLIExitCodes:
    def test_dirty_diff_exits_1(self):
        code, _, _ = run_cli("--format", "summary", stdin_text=DIRTY_DIFF)
        assert code == 1

    def test_clean_diff_exits_0(self):
        code, _, _ = run_cli("--format", "summary", stdin_text=CLEAN_DIFF)
        assert code == 0

    def test_empty_diff_exits_0(self):
        code, _, _ = run_cli("--format", "summary", stdin_text="")
        assert code == 0


class TestCLIFormats:
    def test_summary_format_one_line(self):
        _, out, _ = run_cli("--format", "summary", stdin_text=DIRTY_DIFF)
        lines = [l for l in out.strip().splitlines() if l.strip()]
        assert len(lines) == 1
        assert "REQUEST_CHANGES" in out or "NEEDS_DISCUSSION" in out

    def test_json_format_valid(self):
        _, out, _ = run_cli("--format", "json", stdin_text=DIRTY_DIFF)
        data = json.loads(out)
        assert "findings" in data
        assert "summary" in data
        assert isinstance(data["findings"], list)

    def test_json_format_clean(self):
        _, out, _ = run_cli("--format", "json", stdin_text=CLEAN_DIFF)
        data = json.loads(out)
        critical = data["summary"]["by_severity"].get("critical", 0)
        high = data["summary"]["by_severity"].get("high", 0)
        assert critical == 0
        assert high == 0

    def test_text_format_contains_findings(self):
        _, out, _ = run_cli("--format", "text", stdin_text=DIRTY_DIFF)
        assert "FINDINGS" in out or "finding" in out.lower()

    def test_text_format_clean_no_findings(self):
        _, out, _ = run_cli("--format", "text", stdin_text=CLEAN_DIFF)
        assert "No issues detected" in out or "0 finding" in out.lower()


class TestCLIInputFile:
    def test_input_file_flag(self, tmp_path):
        patch_file = tmp_path / "test.patch"
        patch_file.write_text(DIRTY_DIFF, encoding="utf-8")
        code, out, _ = run_cli("--input", str(patch_file), "--format", "summary")
        assert code == 1
        assert "REQUEST_CHANGES" in out or "NEEDS_DISCUSSION" in out

    def test_missing_file_exits_2(self):
        code, _, err = run_cli("--input", "/nonexistent/path.patch")
        assert code == 2
        assert "ERROR" in err or "Cannot read" in err


class TestCLIVersion:
    def test_version_flag(self):
        code, out, _ = run_cli("--version")
        assert code == 0
        assert __version__ in out


class TestCLISpanish:
    """Tests for --lang es flag: verifies Spanish output is produced."""

    def test_lang_es_summary_exits_1_on_dirty(self):
        code, _, _ = run_cli("--lang", "es", "--format", "summary", stdin_text=DIRTY_DIFF)
        assert code == 1

    def test_lang_es_summary_exits_0_on_clean(self):
        code, _, _ = run_cli("--lang", "es", "--format", "summary", stdin_text=CLEAN_DIFF)
        assert code == 0

    def test_lang_es_summary_contains_spanish(self):
        _, out, _ = run_cli("--lang", "es", "--format", "summary", stdin_text=DIRTY_DIFF)
        # The summary line must contain a Spanish recommendation token
        assert (
            "SOLICITAR CAMBIOS" in out
            or "REQUIERE" in out
            or "APROBAR" in out
            or "hallazgo" in out.lower()
        ), f"Expected Spanish summary text, got: {out!r}"

    def test_lang_es_text_format_contains_spanish(self):
        _, out, _ = run_cli("--lang", "es", "--format", "text", stdin_text=DIRTY_DIFF)
        # Text output should include at least one Spanish string
        assert (
            "hallazgo" in out.lower()
            or "resumen" in out.lower()
            or "categor" in out.lower()
            or "severidad" in out.lower()
        ), f"Expected Spanish text output, got: {out!r}"

    def test_lang_es_json_format_valid(self):
        _, out, _ = run_cli("--lang", "es", "--format", "json", stdin_text=DIRTY_DIFF)
        import json as _json
        data = _json.loads(out)
        assert "findings" in data
        assert "summary" in data

    def test_lang_es_json_findings_spanish_explanation(self):
        import json as _json
        _, out, _ = run_cli("--lang", "es", "--format", "json", stdin_text=DIRTY_DIFF)
        data = _json.loads(out)
        if data["findings"]:
            # At least one explanation should contain Spanish characters or words
            expls = " ".join(f["explanation"] for f in data["findings"])
            # Spanish translations include words like 'contrasena', 'sistema', 'arbitrario'
            # Check it differs from pure English by looking for known Spanish words
            assert any(
                word in expls.lower()
                for word in ["contrase", "arbitrar", "sistema", "peligros", "hallazgo",
                             "entrada", "inyecci", "credencial", "elimina"]
            ), f"Expected Spanish explanation text, got: {expls!r}"

    def test_lang_en_explicit_same_as_default(self):
        """Explicit --lang en should produce the same output as no --lang flag."""
        import json as _json
        _, out_en, _ = run_cli("--lang", "en", "--format", "json", stdin_text=DIRTY_DIFF)
        _, out_default, _ = run_cli("--format", "json", stdin_text=DIRTY_DIFF)
        data_en = _json.loads(out_en)
        data_default = _json.loads(out_default)
        assert data_en["summary"]["recommendation"] == data_default["summary"]["recommendation"]
        assert len(data_en["findings"]) == len(data_default["findings"])
