"""
Demo example 2: A relatively clean change — utility functions with proper practices.
This is entirely synthetic data with no real credentials or personal information.
"""

DEMO_CLEAN = """\
diff --git a/utils/formatter.py b/utils/formatter.py
index 0000000..aaabbbb 100644
--- a/utils/formatter.py
+++ b/utils/formatter.py
@@ -1,5 +1,42 @@
+\"\"\"
+Utility functions for formatting and validating user-facing strings.
+\"\"\"
+from __future__ import annotations
+
+import re
+import math
+import logging
+from typing import Optional
+
+logger = logging.getLogger(__name__)
+
+_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$')
+
+
+def validate_email(address: str) -> bool:
+    \"\"\"Return True if address looks like a valid e-mail address.\"\"\"
+    if not isinstance(address, str):
+        return False
+    return bool(_EMAIL_RE.match(address.strip()))
+
+
+def format_currency(amount: float, symbol: str = "$") -> str:
+    \"\"\"Format a numeric amount as a currency string.\"\"\"
+    if not isinstance(amount, (int, float)):
+        raise TypeError(f"amount must be numeric, got {type(amount).__name__}")
+    if math.isnan(amount) or math.isinf(amount):
+        raise ValueError("amount must be a finite number")
+    return f"{symbol}{amount:,.2f}"
+
+
+def truncate(text: str, max_length: int = 100, suffix: str = "...") -> str:
+    \"\"\"Truncate text to at most max_length characters, appending suffix if truncated.\"\"\"
+    if not isinstance(text, str):
+        raise TypeError("text must be a string")
+    if max_length <= 0:
+        raise ValueError("max_length must be positive")
+    if len(text) <= max_length:
+        return text
+    return text[: max_length - len(suffix)] + suffix
diff --git a/tests/test_formatter.py b/tests/test_formatter.py
index 0000000..bbbcccc 100644
--- a/tests/test_formatter.py
+++ b/tests/test_formatter.py
@@ -1,5 +1,38 @@
+import pytest
+from utils.formatter import validate_email, format_currency, truncate
+
+
+class TestValidateEmail:
+    def test_valid_address(self):
+        assert validate_email("user@example.com") is True
+
+    def test_missing_at_sign(self):
+        assert validate_email("notanemail") is False
+
+    def test_non_string_input(self):
+        assert validate_email(None) is False
+
+    def test_whitespace_trimmed(self):
+        assert validate_email("  user@example.com  ") is True
+
+
+class TestFormatCurrency:
+    def test_positive_amount(self):
+        assert format_currency(1234.5) == "$1,234.50"
+
+    def test_zero(self):
+        assert format_currency(0) == "$0.00"
+
+    def test_custom_symbol(self):
+        assert format_currency(99.9, symbol="€") == "€99.90"
+
+    def test_non_numeric_raises(self):
+        with pytest.raises(TypeError):
+            format_currency("not a number")
+
+
+class TestTruncate:
+    def test_no_truncation_needed(self):
+        assert truncate("hello", 10) == "hello"
+
+    def test_truncation_applied(self):
+        result = truncate("hello world", 8)
+        assert result == "hello..."
+        assert len(result) == 8
+
+    def test_invalid_max_length(self):
+        with pytest.raises(ValueError):
+            truncate("text", 0)
"""

DEMO_CLEAN_TITLE = "Demo 2 — Utility formatter (clean change)"
DEMO_CLEAN_DESCRIPTION = (
    "A synthetic addition of string utility functions with proper type checking, "
    "explicit error handling, and comprehensive unit tests. Serves as a baseline "
    "showing what a low-risk change looks like."
)
