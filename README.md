# Intelligent Code Review Coach

**IBM Bob Hackathon Prototype**

[![CI](https://github.com/MafiaCut/code-review-coach/actions/workflows/ci.yml/badge.svg)](https://github.com/MafiaCut/code-review-coach/actions/workflows/ci.yml)

A locally-runnable static-analysis tool that accepts a Git diff, identifies actionable security and quality issues, explains why each finding matters, recommends concrete fixes, and produces a concise review summary — all without executing any submitted code and without requiring any API keys or paid services.

---

## Quick start

### Prerequisites

- Python 3.9 or later (tested through Python 3.14)
- Git

### Install the tool

```bash
git clone https://github.com/MafiaCut/code-review-coach.git
cd code-review-coach
python -m pip install -e ".[web]"
```

This installs the `review-coach` and `review-coach-web` commands. For CLI-only use, omit the `web`
extra: `python -m pip install -e .`. You can also install the CLI directly
from GitHub with:

```bash
python -m pip install "git+https://github.com/MafiaCut/code-review-coach.git"
```

### Run the server

```bash
review-coach-web
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

### Run tests

```bash
python -m pip install -e ".[dev,web]"
python -m pytest tests/ -v
```

The exact test count changes as coverage grows; the CI badge shows the current
status on every push and pull request.

---

## Command-line use

Analyze a diff from standard input, a file, or a CI pipeline without starting
the web server:

```bash
git diff HEAD~1 | review-coach --format summary
review-coach --input change.patch --format text
review-coach --input change.patch --format json --lang es
python -m code_review_coach --version
```

`--format` accepts `text` (default), `json`, and `summary`. `--lang` accepts
`en` (default) and `es`. The command exits with `0` for `APPROVE` or
`APPROVE_WITH_NOTES`, `1` when review action is needed, and `2` when the input
file cannot be read.

---

## Project structure

```
code-review-coach/
├── app.py                  Backward-compatible web launcher
├── cli.py                  Backward-compatible CLI launcher
├── pyproject.toml          Package metadata and command entry points
├── requirements.txt       Runtime dependencies
├── requirements-dev.txt   Test, coverage, and lint tools
├── code_review_coach/     Installable application package
│   ├── cli.py              Packaged command-line interface
│   ├── web.py              Packaged Flask application
│   ├── demos/              Bundled synthetic examples
│   └── static/index.html   Bundled single-page UI
├── analyzer/
│   ├── __init__.py
│   ├── rules.py            All analysis rules (9 categories)
│   ├── parser.py           Unified diff parser
│   ├── engine.py           Orchestration + summary generation
│   ├── github.py           GitHub webhook integration
│   ├── i18n.py             English and Spanish output
│   └── llm.py              Optional LLM summary enhancement
├── tests/
│   └── test_*.py           Unit and integration tests
├── .github/workflows/      CI and dependency audit
└── evidence/
    └── README.md           Instructions for Bob IDE screenshots
```

---

## Supported languages and rule categories

| Language               | Secrets | Unsafe Input | Error Handling | Likely Bugs | Weak Tests       |
|------------------------|---------|--------------|----------------|-------------|------------------|
| Python                 | ✓       | ✓            | ✓              | ✓           | ✓                |
| JavaScript/TypeScript  | ✓       | ✓            | ✓              | ✓           | (file detection) |

### Rule details

| Category | What is detected |
|----------|-----------------|
| **Exposed secrets** | Hardcoded passwords, API keys, AWS key IDs, connection strings with embedded credentials |
| **Unsafe input** | `eval()`, `exec()`, `os.system()`, `subprocess(shell=True)`, `innerHTML` assignment, `document.write()`, shell injection in Node.js |
| **Error handling** | Bare `except:`, overly broad `except Exception:`, HTTP responses without `raise_for_status()`, empty JS `catch {}` |
| **Likely bugs** | `is` comparisons to non-singletons, mutable default arguments, float equality, loose JS `==` operator |
| **Weak tests** | `assert True` no-ops, TODO comment placeholders inside test files |
| **Sensitive logging** | Passwords, tokens, secrets, or credentials written to logs |
| **Dangerous deserialization** | Unsafe pickle, YAML, and JavaScript deserialization |
| **Path traversal** | Request-derived paths passed to file operations |
| **Insecure dependencies** | Vulnerable versions in `requirements.txt` and `package.json` |

---

## Demo script (repeatable)

### Demo 1 — Auth service with issues (~30 seconds)

1. Open [http://localhost:5000](http://localhost:5000).
2. Click **"Demo 1 — Auth service with multiple issues"**.
3. Click **Analyze Diff**.
4. Observe the **REQUEST CHANGES** recommendation.
5. Review findings across `auth/login.py` and `frontend/dashboard.ts`:
   - 2 critical (hardcoded credentials)
   - 3 high (eval, os.system, innerHTML XSS)
   - Several medium/low (bare except, loose equality, mutable default)
   - 1 info (TODO test placeholder)
6. Note the elapsed time in the meta strip at the bottom (typically < 5 ms).

### Demo 2 — Clean utility formatter (~30 seconds)

1. Click **"Demo 2 — Utility formatter (clean change)"**.
2. Click **Analyze Diff**.
3. Observe the **APPROVE** recommendation with 0 critical/high findings.
4. Meta strip shows 2 files reviewed, 0 critical findings.

### Manual review comparison

Time a manual review of the Demo 1 diff using this checklist:

| Manual checklist item | Estimated time |
|-----------------------|---------------|
| Scan for hardcoded credentials | ~2 min |
| Check for injection vulnerabilities | ~2 min |
| Review error handling | ~1 min |
| Look for common bug patterns | ~2 min |
| Assess test coverage | ~1 min |
| Write review summary | ~3 min |
| **Total** | **~11 min** |

The automated review completes in **< 5 ms** and produces the same checklist with file+line references and specific fix recommendations. Developer effort shifts from mechanical scanning to reviewing and acting on findings.

---

## API reference

### `POST /api/analyze`

```json
{ "diff": "<unified diff string>", "lang": "en" }
```

`lang` is optional and accepts `en` or `es`; unsupported values fall back to
English.

Response:

```json
{
  "findings": [
    {
      "severity": "critical",
      "category": "secrets",
      "filename": "auth/login.py",
      "line_number": 5,
      "explanation": "...",
      "recommended_fix": "...",
      "matched_text": "..."
    }
  ],
  "summary": {
    "total_findings": 12,
    "by_severity": { "critical": 2, "high": 3 },
    "by_category": { "secrets": 2 },
    "main_risks": ["..."],
    "next_steps": ["..."],
    "recommendation": "REQUEST_CHANGES",
    "recommendation_reason": "..."
  },
  "files_reviewed": ["auth/login.py", "frontend/dashboard.ts"],
  "lines_analyzed": 42,
  "elapsed_ms": 3.2,
  "lang": "en",
  "llm_enhanced": false
}
```

### `GET /api/demos`

Returns a list of available demo IDs, titles, and descriptions.

### `GET /api/demos/<id>`

Returns the full diff for a demo (`dirty` or `clean`).

---

## GitHub webhook

`POST /webhook/github` accepts GitHub `pull_request` events for the `opened`,
`synchronize`, and `reopened` actions. Configure these environment variables:

```bash
GITHUB_WEBHOOK_SECRET=<the webhook secret configured in GitHub>
GITHUB_TOKEN=<token with pull-request review permission>
```

The endpoint verifies `X-Hub-Signature-256`, fetches the PR diff, analyzes it,
and posts a review with inline comments. For local testing, expose the server
with a tunnel such as ngrok and use its HTTPS URL as the GitHub webhook URL.
Requests fail closed with HTTP 503 when `GITHUB_WEBHOOK_SECRET` is not set.
If `GITHUB_TOKEN` is absent, it returns the analysis JSON without posting a
review. Never commit either secret.

## Optional LLM summaries

The rule engine works fully offline. To add a concise natural-language summary,
set all three variables before starting the server:

```bash
LLM_API_URL=<watsonx or OpenAI-compatible completion endpoint>
LLM_API_KEY=<API key>
LLM_MODEL_ID=<model identifier>
```

The integration supports IBM watsonx.ai text generation endpoints and
OpenAI-compatible chat-completions endpoints. Only structured finding metadata
(severity, category, filename, and explanation) is sent; the submitted diff is
never sent to the LLM. Errors and timeouts fall back to the rule-based summary,
and the response exposes `llm_enhanced` to indicate whether enhancement ran.

---

## Security model

- The diff is treated as **untrusted text** throughout. It is parsed and matched against regex patterns only.
- No code from the submitted diff is evaluated, imported, or executed.
- Diff size is capped at 500 KB server-side.
- The tool deliberately avoids shell-out, dynamic imports, or any form of code execution on submitted content.

---

## Limitations

1. **Lightweight context only.** Rules can inspect nearby added lines, but there is no AST or full cross-file data-flow analysis.
2. **False positives possible.** Patterns may trigger on comments or string literals that are not actually executed paths.
3. **False negatives certain.** Complex control flow and data flow can still evade regex-based detection.
4. **Additions only.** Removed lines are not analyzed.
5. **No binary or non-text file support.**
6. **LLM enhancement is optional.** The core remains regex-based and offline; an enabled LLM can still produce imperfect prose.
7. **Not a replacement for a full SAST tool.** Intended as a fast first-pass reviewer, not a comprehensive security scanner.

---

## License

Code Review Coach is released under the [MIT License](LICENSE).

---

## Bob IDE evidence

Screenshots of Bob Agent sessions are stored in [`evidence/`](evidence/). See [`evidence/README.md`](evidence/README.md) for the full list of sessions to capture and naming conventions.
