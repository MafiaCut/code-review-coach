"""
Static analysis rules for the Code Review Coach.
Each rule is a function that receives a list of DiffLine objects and returns
a list of Finding objects. Rules never execute submitted code; they operate
purely on text pattern matching.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Callable, List, Optional

from packaging.version import InvalidVersion, Version


# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class DiffLine:
    """A single added line from a unified diff."""
    filename: str
    line_number: int          # line number in the new file (None if unknown)
    content: str              # raw line content (without the leading '+')
    language: str             # 'python' | 'javascript' | 'typescript' | 'unknown'


@dataclass
class Finding:
    severity: str             # critical | high | medium | low | info
    category: str             # secrets | unsafe_input | error_handling | likely_bug | weak_tests
    filename: str
    line_number: Optional[int]
    explanation: str
    recommended_fix: str
    matched_text: str = ""    # the snippet that triggered the rule


# ─────────────────────────────────────────────
# Context window
# ─────────────────────────────────────────────

class FileContext:
    """
    Ordered list of added DiffLines for a single file, with a helper that
    returns the raw content strings of lines immediately following a given
    index — enabling multi-line lookahead without executing any code.
    """
    def __init__(self, lines: List[DiffLine]) -> None:
        self._lines = lines

    def __iter__(self):
        return iter(self._lines)

    def __len__(self):
        return len(self._lines)

    def next_contents(self, idx: int, window: int = 3) -> List[str]:
        """Return the content strings of up to `window` lines after index idx."""
        end = min(idx + 1 + window, len(self._lines))
        return [self._lines[i].content for i in range(idx + 1, end)]

    def prev_contents(self, idx: int, window: int = 3) -> List[str]:
        """Return the content strings of up to `window` lines before index idx."""
        start = max(0, idx - window)
        return [self._lines[i].content for i in range(start, idx)]


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _lang(filename: str) -> str:
    # Exact filename matches first
    import os
    basename = os.path.basename(filename)
    if basename == "requirements.txt":
        return "requirements"
    if basename == "package.json":
        return "package_json"
    if filename.endswith(".py"):
        return "python"
    if filename.endswith((".js", ".jsx")):
        return "javascript"
    if filename.endswith((".ts", ".tsx")):
        return "typescript"
    return "unknown"


# ─────────────────────────────────────────────
# Entropy scoring helper
# ─────────────────────────────────────────────

def compute_entropy(s: str) -> float:
    """Shannon entropy of string s in bits per character. Returns 0 for empty strings."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# Regex to extract quoted strings of length >= 20 from a line
_QUOTED_LONG = re.compile(r'["\']([A-Za-z0-9+/=_\-!@#$%^&*]{20,})["\']')

# Entropy threshold: values above this are flagged (calibrated against demo diffs)
ENTROPY_THRESHOLD = 4.5


# ─────────────────────────────────────────────
# Rule: Exposed secrets
# ─────────────────────────────────────────────

_SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    (
        "Hardcoded password assignment",
        re.compile(
            r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']'
        ),
    ),
    (
        "Hardcoded API key assignment",
        re.compile(
            r'(?i)(api_?key|apikey|secret_?key|auth_?token|access_?token)\s*=\s*["\'][A-Za-z0-9+/=_\-]{8,}["\']'
        ),
    ),
    (
        "AWS access key ID pattern",
        re.compile(r'AKIA[0-9A-Z]{16}'),
    ),
    (
        "Generic high-entropy secret (long quoted string in assignment)",
        re.compile(
            r'(?i)(token|secret|credential|private_key)\s*=\s*["\'][A-Za-z0-9+/=_\-]{20,}["\']'
        ),
    ),
    (
        "Connection string with embedded password",
        re.compile(
            r'(?i)(mongodb|postgres|mysql|mssql|redis):\/\/[^:]+:[^@\s]{4,}@'
        ),
    ),
]


def rule_exposed_secrets(lines: List[DiffLine]) -> List[Finding]:
    findings: List[Finding] = []
    for dl in lines:
        # Skip comments and test fixture lines that use placeholder values
        stripped = dl.content.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            continue
        already_flagged = False
        for label, pattern in _SECRET_PATTERNS:
            m = pattern.search(dl.content)
            if m:
                findings.append(Finding(
                    severity="critical",
                    category="secrets",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation=(
                        f"{label} detected. Committing credentials to source control "
                        "exposes them in git history permanently, even after removal."
                    ),
                    recommended_fix=(
                        "Remove the literal value. Load secrets from environment variables "
                        "(os.environ / process.env) or a secrets manager (e.g. AWS Secrets Manager, "
                        "HashiCorp Vault). Add the file to .gitignore if it is a config file."
                    ),
                    matched_text=m.group(0)[:120],
                ))
                already_flagged = True
                break   # one finding per line is enough

        # Entropy pass: check quoted strings not already caught by name-based rules
        if not already_flagged:
            for em in _QUOTED_LONG.finditer(dl.content):
                candidate = em.group(1)
                if compute_entropy(candidate) > ENTROPY_THRESHOLD:
                    findings.append(Finding(
                        severity="high",
                        category="secrets",
                        filename=dl.filename,
                        line_number=dl.line_number,
                        explanation=(
                            f"High-entropy string detected (entropy: "
                            f"{compute_entropy(candidate):.2f} bits/char). "
                            "This string has the statistical profile of a generated secret, "
                            "API key, or token regardless of the variable name."
                        ),
                        recommended_fix=(
                            "If this is a real credential, remove it and use an environment "
                            "variable or secrets manager instead. If it is intentional "
                            "(e.g. a test vector), add a `# noqa: secrets` comment to suppress."
                        ),
                        matched_text=candidate[:60],
                    ))
                    break   # one entropy finding per line
    return findings


# ─────────────────────────────────────────────
# Rule: Unsafe input handling
# ─────────────────────────────────────────────

_UNSAFE_PYTHON = [
    (
        re.compile(r'\beval\s*\('),
        "Use of eval() with potentially untrusted data",
        "Replace eval() with a safe alternative (ast.literal_eval for data structures, "
        "or an explicit parser). eval() executes arbitrary code.",
    ),
    (
        re.compile(r'\bexec\s*\('),
        "Use of exec() with potentially untrusted data",
        "Avoid exec(). Refactor the logic to use data-driven dispatch instead.",
    ),
    (
        re.compile(r'\bsubprocess\.(call|run|Popen|check_output)\s*\(.*shell\s*=\s*True'),
        "subprocess called with shell=True – susceptible to shell injection",
        "Pass a list of arguments instead of a string, and set shell=False (the default). "
        "Validate and sanitize any user-supplied parts before inclusion.",
    ),
    (
        re.compile(r'\bos\.system\s*\('),
        "os.system() passes input directly to the shell",
        "Use subprocess.run() with a list of arguments and shell=False.",
    ),
    (
        re.compile(r'\.format\(.*request\.|f["\'].*{.*request\.'),
        "User-controlled data interpolated into a string without sanitization",
        "Validate and escape user input before embedding it in strings, especially "
        "SQL queries, HTML templates, or shell commands.",
    ),
    (
        re.compile(r'(?i)execute\s*\(\s*["\']?\s*select.*\+|execute\s*\(\s*f["\']'),
        "Possible SQL injection – query built with string concatenation",
        "Use parameterized queries: cursor.execute('SELECT … WHERE id = %s', (user_id,)).",
    ),
]

_UNSAFE_JS = [
    (
        re.compile(r'\beval\s*\('),
        "Use of eval() – executes arbitrary JavaScript",
        "Replace eval() with JSON.parse() for data, or restructure to avoid dynamic evaluation.",
    ),
    (
        re.compile(r'\.innerHTML\s*=\s*(?!["\'`][\s<])'),
        "Direct innerHTML assignment – potential XSS vector",
        "Use textContent for plain text, or sanitize with DOMPurify before setting innerHTML.",
    ),
    (
        re.compile(r'document\.write\s*\('),
        "document.write() can overwrite the page and enables XSS",
        "Use DOM manipulation methods (createElement, appendChild) instead.",
    ),
    (
        re.compile(r'(?i)child_process.*exec\s*\(.*\+|execSync\s*\(.*\+'),
        "Shell command built with string concatenation – injection risk",
        "Use execFile() with a fixed command and an array of arguments, "
        "never concatenate user input into a shell string.",
    ),
]

# Multi-line SQL: a string variable is built with += then passed to execute()
_SQL_CONCAT_BUILD = re.compile(r'(?i)(query|sql|stmt)\s*[+]=?\s*["\']|["\'][^"\']*\s*\+\s*\w')
_SQL_EXECUTE_CALL = re.compile(r'(?i)\.(execute|executemany)\s*\(')


def rule_unsafe_input(
    lines: List[DiffLine],
    ctx: Optional["FileContext"] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    lines_list = list(lines)
    # Track lines that look like they're building a SQL string for multi-line detection
    sql_building: dict = {}  # filename -> (idx, line_no) of last sql-building line

    for idx, dl in enumerate(lines_list):
        stripped = dl.content.strip()
        if stripped.startswith(("#", "//", "*", "/*", '"""', "'''")):
            continue
        checks = []
        if dl.language == "python":
            checks = _UNSAFE_PYTHON
        elif dl.language in ("javascript", "typescript"):
            checks = _UNSAFE_JS

        matched = False
        for pattern, explanation, fix in checks:
            m = pattern.search(dl.content)
            if m:
                findings.append(Finding(
                    severity="high",
                    category="unsafe_input",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation=explanation,
                    recommended_fix=fix,
                    matched_text=m.group(0)[:120],
                ))
                matched = True
                break

        if not matched and dl.language == "python":
            # Multi-line SQL: track string-building lines and fire when execute() follows
            if _SQL_CONCAT_BUILD.search(dl.content):
                sql_building[dl.filename] = (idx, dl.line_number)

            if _SQL_EXECUTE_CALL.search(dl.content) and dl.filename in sql_building:
                _build_idx, prev_lineno = sql_building.pop(dl.filename)
                # Only fire if the execute() is close to the build (within 5 lines)
                if dl.line_number is not None and prev_lineno is not None:
                    if dl.line_number - prev_lineno <= 5:
                        findings.append(Finding(
                            severity="high",
                            category="unsafe_input",
                            filename=dl.filename,
                            line_number=dl.line_number,
                            explanation="Possible SQL injection – query appears to be built via string "
                                        "concatenation across multiple lines before being passed to execute().",
                            recommended_fix="Use parameterized queries: "
                                            "cursor.execute('SELECT … WHERE id = %s', (user_id,)).",
                            matched_text=dl.content.strip()[:80],
                        ))

    return findings


# ─────────────────────────────────────────────
# Rule: Missing error handling
# ─────────────────────────────────────────────

_BARE_EXCEPT = re.compile(r'^\s*except\s*:')
_BROAD_EXCEPT = re.compile(r'^\s*except\s+Exception\s*:')
_SILENT_CATCH = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')   # catch(e) {}
_NO_AWAIT_CATCH = re.compile(r'await\s+\w+[.(](?!.*\.catch\()(?!.*try)')
_REQUESTS_NO_RAISE = re.compile(r'requests\.(get|post|put|patch|delete)\s*\(')
_FETCH_NO_CATCH = re.compile(r'\bfetch\s*\((?!.*\.catch\()(?!.*await.*try)')


def rule_error_handling(
    lines: List[DiffLine],
    ctx: Optional["FileContext"] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    lines_list = list(lines)  # ensure indexable

    for idx, dl in enumerate(lines_list):
        lang = dl.language

        if lang == "python":
            if _BARE_EXCEPT.match(dl.content):
                findings.append(Finding(
                    severity="medium",
                    category="error_handling",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation="Bare `except:` catches every exception including KeyboardInterrupt and SystemExit, "
                                "making the program hard to terminate and masking real errors.",
                    recommended_fix="Catch specific exceptions: `except (ValueError, IOError) as e:`. "
                                    "Log or re-raise unexpected exceptions.",
                    matched_text="except:",
                ))
            elif _BROAD_EXCEPT.match(dl.content):
                findings.append(Finding(
                    severity="low",
                    category="error_handling",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation="`except Exception:` is overly broad and may hide programming errors.",
                    recommended_fix="Catch the narrowest exception type that is expected at this call site.",
                    matched_text="except Exception:",
                ))
            elif _REQUESTS_NO_RAISE.search(dl.content) and "raise_for_status" not in dl.content:
                # Use context window: check the next 3 added lines of the same file
                nearby = []
                if ctx is not None:
                    nearby = ctx.next_contents(idx, window=3)
                else:
                    # Fallback: use the flat list (same file only)
                    nearby = [
                        lines_list[i].content
                        for i in range(idx + 1, min(idx + 4, len(lines_list)))
                        if lines_list[i].filename == dl.filename
                    ]
                nearby_text = " ".join(nearby)
                if "raise_for_status" not in nearby_text and ".ok" not in nearby_text:
                    findings.append(Finding(
                        severity="medium",
                        category="error_handling",
                        filename=dl.filename,
                        line_number=dl.line_number,
                        explanation="HTTP response status is not checked. A 4xx/5xx response will be silently ignored.",
                        recommended_fix="Call response.raise_for_status() immediately after the request, "
                                        "or check response.ok before processing the body.",
                        matched_text=dl.content.strip()[:80],
                    ))

        elif lang in ("javascript", "typescript"):
            if _SILENT_CATCH.search(dl.content):
                findings.append(Finding(
                    severity="medium",
                    category="error_handling",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation="Empty catch block silently swallows exceptions. Errors will be invisible at runtime.",
                    recommended_fix="Log the error (`console.error(e)`) at minimum, or propagate it with `throw e`. "
                                    "Handle the failure case explicitly.",
                    matched_text=dl.content.strip()[:80],
                ))
    return findings


# ─────────────────────────────────────────────
# Rule: Likely bugs
# ─────────────────────────────────────────────

# Flag `is` used with numeric literals or string literals only.
# `is True`, `is False`, `is None` are correct Python idioms and are excluded.
_IS_COMPARISON = re.compile(r'\bis\s+(\d+|["\'])')
_MUTABLE_DEFAULT = re.compile(r'def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|\(\))')
_EQUALITY_ASSIGN = re.compile(r'if\s+\w+\s*=\s+\w+')   # if x = y (Python syntax error but catches typos in JS)
_JS_TRIPLE_EQ = re.compile(r'[^=!]==[^=]')              # == instead of ===
_JS_TYPEOF = re.compile(r'typeof\s+\w+\s*[=!]=\s*["\'][^"\']+["\'](?<!=)')   # typeof x == 'string'
_PYTHON_FLOAT_EQ = re.compile(r'==\s*\d+\.\d+|\d+\.\d+\s*==')
_EXCEPT_PASS = re.compile(r'^\s*pass\s*$')


def rule_likely_bugs(lines: List[DiffLine]) -> List[Finding]:
    findings: List[Finding] = []
    prev_was_except = False

    for i, dl in enumerate(lines):
        lang = dl.language

        if lang == "python":
            m = _IS_COMPARISON.search(dl.content)
            if m:
                findings.append(Finding(
                    severity="medium",
                    category="likely_bug",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation=f"`is` tests object identity, not equality. "
                                f"`{m.group(0)}` may behave unexpectedly for non-singleton values.",
                    recommended_fix="Use `==` for equality comparisons. Reserve `is` for None checks.",
                    matched_text=m.group(0),
                ))

            m = _MUTABLE_DEFAULT.search(dl.content)
            if m:
                findings.append(Finding(
                    severity="high",
                    category="likely_bug",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation="Mutable default argument is shared across all calls. "
                                "Mutations in one call will affect subsequent calls unexpectedly.",
                    recommended_fix=f"Use `None` as default and initialize inside the function: "
                                    f"`if param is None: param = {m.group(1)}`",
                    matched_text=m.group(0)[:80],
                ))

            m = _PYTHON_FLOAT_EQ.search(dl.content)
            if m:
                findings.append(Finding(
                    severity="low",
                    category="likely_bug",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation="Direct floating-point equality comparison is unreliable due to rounding errors.",
                    recommended_fix="Use `math.isclose(a, b)` or compare with a tolerance: `abs(a - b) < 1e-9`.",
                    matched_text=m.group(0),
                ))

        elif lang in ("javascript", "typescript"):
            m = _JS_TRIPLE_EQ.search(dl.content)
            # Exclude comment lines
            stripped = dl.content.strip()
            if m and not stripped.startswith(("//", "*", "/*")):
                findings.append(Finding(
                    severity="low",
                    category="likely_bug",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation="Loose equality `==` performs type coercion which can produce surprising results "
                                "(e.g. `0 == ''` is true).",
                    recommended_fix="Use strict equality `===` (and `!==` for inequality).",
                    matched_text=m.group(0),
                ))

        # Track bare `except: pass`
        if "except" in dl.content and _BARE_EXCEPT.match(dl.content):
            prev_was_except = True
        elif prev_was_except and _EXCEPT_PASS.match(dl.content):
            findings.append(Finding(
                severity="medium",
                category="likely_bug",
                filename=dl.filename,
                line_number=dl.line_number,
                explanation="`except: pass` silently swallows all exceptions. Runtime errors will be invisible.",
                recommended_fix="At minimum log the exception. Remove the try/except if no recovery is possible.",
                matched_text="except: pass",
            ))
            prev_was_except = False
        else:
            prev_was_except = False

    return findings


# ─────────────────────────────────────────────
# Rule: Missing or weak tests
# ─────────────────────────────────────────────

_TEST_FILE = re.compile(r'(test_|_test\.|\.test\.|\.spec\.)')
_ASSERT_ONLY = re.compile(r'^\s*assert\s+True\b|assertTrue\s*\(\s*True\s*\)')
_TODO_TEST = re.compile(r'(?i)#\s*todo.*test|//\s*todo.*test')
_EMPTY_TEST = re.compile(r'def\s+test_\w+\s*\([^)]*\)\s*:\s*$')


def rule_weak_tests(lines: List[DiffLine]) -> List[Finding]:
    """Flag weak patterns inside test files."""
    findings: List[Finding] = []
    for dl in lines:
        if not _TEST_FILE.search(dl.filename):
            continue
        if _ASSERT_ONLY.search(dl.content):
            findings.append(Finding(
                severity="low",
                category="weak_tests",
                filename=dl.filename,
                line_number=dl.line_number,
                explanation="Assertion that is always True does not actually test any behavior.",
                recommended_fix="Assert a specific expected value against the function's actual output.",
                matched_text=dl.content.strip()[:80],
            ))
        if _TODO_TEST.search(dl.content):
            findings.append(Finding(
                severity="info",
                category="weak_tests",
                filename=dl.filename,
                line_number=dl.line_number,
                explanation="TODO comment indicates a test case that has not been written yet.",
                recommended_fix="Implement the missing test before merging.",
                matched_text=dl.content.strip()[:80],
            ))
    return findings


# ─────────────────────────────────────────────
# Rule: Logging sensitive data
# ─────────────────────────────────────────────

_LOG_SENSITIVE_PY = re.compile(
    r'(?i)(logging\.|logger\.|print\s*\()'
    r'.*\b(password|passwd|pwd|token|secret|api_?key|credential|auth)\b'
)
_LOG_SENSITIVE_JS = re.compile(
    r'(?i)(console\.(log|warn|error|info|debug)\s*\()'
    r'.*\b(password|passwd|token|secret|apikey|credential|auth)\b'
)


def rule_logging_sensitive(lines: List[DiffLine]) -> List[Finding]:
    """Flag logging calls that may leak sensitive variable values."""
    findings: List[Finding] = []
    for dl in lines:
        stripped = dl.content.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            continue
        pattern = None
        if dl.language == "python":
            pattern = _LOG_SENSITIVE_PY
        elif dl.language in ("javascript", "typescript"):
            pattern = _LOG_SENSITIVE_JS
        if pattern:
            m = pattern.search(dl.content)
            if m:
                findings.append(Finding(
                    severity="high",
                    category="logging_sensitive",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation=(
                        "A logging or print call appears to output a sensitive variable "
                        "(password, token, secret, or credential). Logs are frequently "
                        "stored in plain text and accessible to support teams or log aggregators."
                    ),
                    recommended_fix=(
                        "Remove sensitive values from log output. If debugging, use a "
                        "redacted placeholder: `logger.debug('auth attempt user=%s', username)`. "
                        "Never log the credential value itself."
                    ),
                    matched_text=dl.content.strip()[:80],
                ))
    return findings


# ─────────────────────────────────────────────
# Rule: Dangerous deserialization
# ─────────────────────────────────────────────

_PICKLE_LOADS = re.compile(r'\bpickle\.(loads?)\s*\(')
_YAML_UNSAFE = re.compile(r'\byaml\.load\s*\((?!.*Loader\s*=)')
_JS_PARSE_EVAL = re.compile(r'JSON\.parse\s*\(\s*eval\s*\(')


def rule_dangerous_deserialization(lines: List[DiffLine]) -> List[Finding]:
    """Flag use of unsafe deserialization that can execute arbitrary code."""
    findings: List[Finding] = []
    for dl in lines:
        stripped = dl.content.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            continue

        if dl.language == "python":
            m = _PICKLE_LOADS.search(dl.content)
            if m:
                findings.append(Finding(
                    severity="high",
                    category="dangerous_deserialization",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation=(
                        f"`pickle.{m.group(1)}()` deserializes arbitrary Python objects and can "
                        "execute code embedded in the payload. Never unpickle data from "
                        "an untrusted source."
                    ),
                    recommended_fix=(
                        "Replace pickle with a safe format like JSON or MessagePack. "
                        "If pickle is required, validate a cryptographic signature on the "
                        "payload before deserializing."
                    ),
                    matched_text=m.group(0)[:80],
                ))
                continue

            m = _YAML_UNSAFE.search(dl.content)
            if m:
                findings.append(Finding(
                    severity="high",
                    category="dangerous_deserialization",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation=(
                        "`yaml.load()` without a `Loader=` argument uses the unsafe full loader "
                        "which can instantiate arbitrary Python objects from YAML input."
                    ),
                    recommended_fix=(
                        "Use `yaml.safe_load(data)` for untrusted input, or pass "
                        "`Loader=yaml.SafeLoader` explicitly: `yaml.load(data, Loader=yaml.SafeLoader)`."
                    ),
                    matched_text=m.group(0)[:80],
                ))

        elif dl.language in ("javascript", "typescript"):
            m = _JS_PARSE_EVAL.search(dl.content)
            if m:
                findings.append(Finding(
                    severity="high",
                    category="dangerous_deserialization",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation=(
                        "`JSON.parse(eval(...))` evaluates the string as JavaScript before "
                        "parsing it, enabling code execution via crafted input."
                    ),
                    recommended_fix=(
                        "Use `JSON.parse()` directly on the raw string without wrapping in eval()."
                    ),
                    matched_text=m.group(0)[:80],
                ))
    return findings


# ─────────────────────────────────────────────
# Rule: Path traversal
# ─────────────────────────────────────────────

_PATH_TRAV_PY = [
    (
        re.compile(r'\bopen\s*\(\s*(request\.|user_|input_|param)'),
        "open() called directly with user-controlled path",
        "Validate and canonicalize the path with os.path.realpath() and confirm it "
        "starts with the expected base directory before opening.",
    ),
    (
        re.compile(r'\bos\.path\.join\s*\([^)]*\b(request\.|user_|input_|param)'),
        "os.path.join() with user-controlled component – path traversal risk",
        "Use os.path.realpath() to resolve the final path, then assert it starts with "
        "the allowed base directory: `assert real.startswith(base_dir)`.",
    ),
    (
        re.compile(r'\bsend_file\s*\(.*request\.'),
        "send_file() with user-controlled filename – arbitrary file disclosure risk",
        "Use flask.send_from_directory() with a fixed directory and a sanitized filename "
        "(werkzeug.utils.secure_filename). Never pass raw request values.",
    ),
]

_PATH_TRAV_JS = [
    (
        re.compile(r'fs\.(readFile|createReadStream|writeFile)\s*\(\s*(req\.|request\.|params\.)'),
        "fs operation with user-controlled path – path traversal risk",
        "Resolve and validate the path: use path.resolve() and confirm it begins with "
        "the expected root directory before any file operation.",
    ),
    (
        re.compile(r'path\.join\s*\(__dirname\s*,\s*(req\.|request\.|params\.)'),
        "path.join(__dirname, user_input) – path traversal risk",
        "Sanitize the user-supplied segment (strip leading '../'), then validate the "
        "resolved path is within the intended directory.",
    ),
]


def rule_path_traversal(lines: List[DiffLine]) -> List[Finding]:
    """Flag file operations that use user-controlled paths without sanitization."""
    findings: List[Finding] = []
    for dl in lines:
        stripped = dl.content.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            continue
        checks = []
        if dl.language == "python":
            checks = _PATH_TRAV_PY
        elif dl.language in ("javascript", "typescript"):
            checks = _PATH_TRAV_JS
        for pattern, explanation, fix in checks:
            m = pattern.search(dl.content)
            if m:
                findings.append(Finding(
                    severity="high",
                    category="path_traversal",
                    filename=dl.filename,
                    line_number=dl.line_number,
                    explanation=explanation,
                    recommended_fix=fix,
                    matched_text=m.group(0)[:80],
                ))
                break
    return findings


# ─────────────────────────────────────────────
# Rule: Insecure dependency versions
# ─────────────────────────────────────────────

# Table of known-vulnerable package version constraints
# Format: (package_name_lower, max_safe_version_exclusive, advisory_note)
_VULN_PACKAGES = [
    ("requests",  (2, 20, 0), "CVE-2018-18074 – credential exposure via redirect"),
    ("pyyaml",    (5, 4, 0),  "CVE-2020-14343 – arbitrary code execution via yaml.load()"),
    ("django",    (3, 2, 0),  "Multiple CVEs in Django < 3.2 (SQL injection, XSS, CSRF)"),
    ("flask",     (2, 3, 0),  "Multiple CVEs in Flask < 2.3 (Werkzeug session fixation, DoS)"),
    ("lodash",    (4, 17, 21),"CVE-2021-23337 – prototype pollution / command injection"),
    ("axios",     (0, 21, 2), "CVE-2021-3749 – ReDoS via crafted URL"),
    ("pillow",    (9, 0, 0),  "Multiple CVEs in Pillow < 9.0 (buffer overflow, DoS)"),
    ("cryptography", (41, 0, 0), "CVE-2023-23931 and others – memory corruption in < 41.0"),
]

_PINNED_VERSION_PY = re.compile(
    r'^([A-Za-z0-9_\-\.]+)\s*([=<>!~^]+)\s*([\d]+\.[\d]+(?:\.[\d]+)?)'
)
_PINNED_VERSION_JS = re.compile(
    r'"([A-Za-z0-9_\-@/]+)"\s*:\s*"[~^]?([\d]+\.[\d]+(?:\.[\d]+)?)"'
)


def _parse_version(ver_str: str) -> Optional[Version]:
    """Parse a PEP 440 version, normalizing equivalent forms such as 2.3/2.3.0."""
    try:
        return Version(ver_str)
    except InvalidVersion:
        return None


def _constraint_allows_vulnerable(operator: str, version: Version, safe: Version) -> bool:
    """Return whether a supported requirement constraint admits vulnerable versions."""
    if operator == "==":
        return version < safe
    if operator in ("<", "<="):
        return version <= safe
    if operator == "~=":
        return version < safe
    return False


def rule_insecure_dependency(lines: List[DiffLine]) -> List[Finding]:
    """Flag pinned dependency versions with known CVEs."""
    findings: List[Finding] = []
    for dl in lines:
        if dl.language not in ("requirements", "package_json"):
            continue
        stripped = dl.content.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue

        # Python requirements.txt
        if dl.language == "requirements":
            m = _PINNED_VERSION_PY.match(stripped)
            if not m:
                continue
            pkg_name = m.group(1).lower().replace("-", "_").replace(".", "_")
            operator = m.group(2)
            version = _parse_version(m.group(3))
            if version is None:
                continue
            for vuln_pkg, max_safe, note in _VULN_PACKAGES:
                norm = vuln_pkg.lower().replace("-", "_").replace(".", "_")
                safe_version = Version(".".join(str(x) for x in max_safe))
                if pkg_name == norm and _constraint_allows_vulnerable(operator, version, safe_version):
                    findings.append(Finding(
                        severity="high",
                        category="insecure_dependency",
                        filename=dl.filename,
                        line_number=dl.line_number,
                        explanation=(
                            f"{m.group(1)} {m.group(2)}{m.group(3)} is a known-vulnerable version. "
                            f"{note}."
                        ),
                        recommended_fix=(
                            f"Upgrade to {vuln_pkg}>={'.'.join(str(x) for x in max_safe)}. "
                            "Run `pip-audit` or `safety check` to scan all dependencies."
                        ),
                        matched_text=stripped[:80],
                    ))
                    break

        # package.json
        elif dl.language == "package_json":
            for m in _PINNED_VERSION_JS.finditer(dl.content):
                pkg_name = m.group(1).split("/")[-1].lower().replace("-", "_")
                version = _parse_version(m.group(2))
                if version is None:
                    continue
                for vuln_pkg, max_safe, note in _VULN_PACKAGES:
                    norm = vuln_pkg.lower().replace("-", "_")
                    safe_version = Version(".".join(str(x) for x in max_safe))
                    if pkg_name == norm and version < safe_version:
                        findings.append(Finding(
                            severity="high",
                            category="insecure_dependency",
                            filename=dl.filename,
                            line_number=dl.line_number,
                            explanation=(
                                f"{m.group(1)}@{m.group(2)} is a known-vulnerable version. "
                                f"{note}."
                            ),
                            recommended_fix=(
                                f"Upgrade to {vuln_pkg}@>={'.'.join(str(x) for x in max_safe)}. "
                                "Run `npm audit` to scan all dependencies."
                            ),
                            matched_text=m.group(0)[:80],
                        ))
                        break
    return findings


# ─────────────────────────────────────────────
# Rule registry
# ─────────────────────────────────────────────

ALL_RULES: List[Callable[[List[DiffLine]], List[Finding]]] = [
    rule_exposed_secrets,
    rule_unsafe_input,
    rule_error_handling,
    rule_likely_bugs,
    rule_weak_tests,
    rule_logging_sensitive,
    rule_dangerous_deserialization,
    rule_path_traversal,
    rule_insecure_dependency,
]
