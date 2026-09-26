# Improvements Plan — Intelligent Code Review Coach

## Overview

Six independent improvement areas, ordered from highest to lowest impact on analysis quality and usability. Each sub-task is self-contained and can be implemented, tested, and reviewed independently.

**Core constraint:** The diff is always treated as untrusted text. No submitted code is ever executed.

> Completion note (2026-09-26): all six sub-tasks are implemented and covered
> by the current test suite. The unchecked detail lists below are retained as
> the original planning record; the per-sub-task **Status** lines are the
> authoritative completion markers.

---

## Sub-Task 1 — Context Window for Rules

### Intent
Every rule currently inspects a single `DiffLine` in isolation. This causes false positives (e.g. `requests.get()` flagged even when `raise_for_status()` is on the very next line) and prevents detection of multi-line patterns (e.g. SQL query built across two lines). Adding a sliding context window of the surrounding added lines — without adding cross-file data structures — fixes the most common false positives immediately.

### Expected Outcomes
- `rule_error_handling`: no longer flags `requests.get()` when `raise_for_status()` appears within 3 added lines.
- `rule_unsafe_input`: can detect SQL injection built across 2–3 lines of string concatenation.
- All existing 49 tests continue to pass; new tests cover the lookahead cases.
- No regression on the clean demo (still APPROVE, 0 findings).

### Todo List
- [ ] Add a `context_lines: List[str]` optional field to `DiffLine` (or pass a window separately to rules that need it).
- [ ] Refactor `analyze_diff()` in `analyzer/engine.py` to build per-file ordered lists and pass each rule a `FileContext` object: ordered `DiffLine` list + a helper `lines_near(line_no, window=3)`.
- [ ] Update `rule_error_handling` to use the window: only fire the `requests` rule if none of the next 3 lines contain `raise_for_status` or `.ok`.
- [ ] Update `rule_unsafe_input` SQL rule to accumulate lines within the same function block and check for `cursor.execute(` after a string-building pattern.
- [ ] Add tests: `requests.get()` + `raise_for_status()` on next line → no finding; `requests.get()` alone → still finds.
- [ ] Add tests: multi-line SQL concatenation → finding; parameterized query → no finding.
- [ ] Run full test suite; fix any regressions.

### Relevant Context
- `analyzer/engine.py:126–158` — `analyze_diff()` currently passes the flat `supported_lines` list to every rule.
- `analyzer/rules.py:225–278` — `rule_error_handling()` checks `"raise_for_status" not in dl.content` on the same line only.
- `analyzer/rules.py:154–158` — SQL injection rule uses a single-line regex.
- `ALL_RULES` type signature: `Callable[[List[DiffLine]], List[Finding]]` — changing the signature must remain backward-compatible or all rules must be updated together.

### Status
[x] done

---

## Sub-Task 2 — New Rule Categories

### Intent
Add four new rule categories that cover common real-world issues not detected today: logging of sensitive data, dangerous deserialization, path traversal, and insecure dependency versions. Each fits cleanly into the existing rule function pattern.

### Expected Outcomes
- New category `logging_sensitive`: fires when `logger.*` or `print()` is called with a variable whose name contains `password`, `token`, `secret`, `key`, or `credential`.
- New category `dangerous_deserialization`: fires on `pickle.loads(`, `pickle.load(`, and `yaml.load(` without `Loader=` argument in Python; `JSON.parse(eval(` in JS/TS.
- New category `path_traversal`: fires on `open(user_`, `os.path.join(base, user_`, `send_file(request.`, and equivalent Node patterns (`fs.readFile(req.`, `path.join(__dirname, req.`).
- New category `insecure_dependency`: fires when a `requirements.txt` or `package.json` hunk adds a pinned version of a known-vulnerable package (initial list: `requests<2.20`, `pyyaml<5.4`, `django<3.2`, `flask<2.3`, `lodash<4.17.21`, `axios<0.21.2`).
- `_lang()` extended to return `"requirements"` for `requirements.txt` and `"package_json"` for `package.json` so the dependency rule can target those files.
- All new rules added to `ALL_RULES`.
- Tests added for each new category (positive and negative cases).

### Todo List
- [ ] Extend `_lang()` in `analyzer/rules.py` to recognise `requirements.txt` → `"requirements"` and `package.json` → `"package_json"`.
- [ ] Add `rule_logging_sensitive()` with patterns for Python `logging.*` / `print(` calls containing sensitive variable names.
- [ ] Add `rule_dangerous_deserialization()` with patterns for `pickle.loads(`, `pickle.load(`, `yaml.load(` (Python) and `JSON.parse(eval(` (JS/TS).
- [ ] Add `rule_path_traversal()` with patterns for unsafe `open()`, `os.path.join()`, `send_file()` (Python) and `fs.readFile`, `path.join` with request-derived arguments (JS/TS).
- [ ] Add `rule_insecure_dependency()` that matches pinned versions in `requirements` / `package_json` files against a hardcoded known-vulnerable version table.
- [ ] Register all four new rules in `ALL_RULES`.
- [ ] Add category labels and risk/step templates for the four new categories in `engine.py`.
- [ ] Write tests for each rule (at least 2 positive, 1 negative per rule).
- [ ] Run full test suite.

### Relevant Context
- `analyzer/rules.py:45–52` — `_lang()` to extend.
- `analyzer/rules.py:422–428` — `ALL_RULES` list to append to.
- `analyzer/engine.py:36–50` — `_CATEGORY_LABELS`, `_RISK_TEMPLATES`, `_STEP_TEMPLATES` to extend.
- `filter_supported()` in `analyzer/parser.py:72–74` currently only passes `python/javascript/typescript` lines — needs updating to also pass `requirements` and `package_json` lines.

### Status
[x] done

---

## Sub-Task 3 — Entropy Scoring for Secrets

### Intent
The current secret rules match on variable *names* only. A high Shannon entropy value in a quoted string is a strong, language-independent signal of a real secret regardless of the variable name. Adding an entropy check catches secrets assigned to innocuous variable names (`x = "aB3$kL9mQwRtYuIo..."`) and reduces false negatives without increasing false positives (low-entropy strings like `"hello"` score near 0).

### Expected Outcomes
- A `compute_entropy(s: str) -> float` utility function in `analyzer/rules.py` computes Shannon entropy of a string.
- `rule_exposed_secrets` gains an additional pass: for any added line that is not a comment and contains a quoted string of length ≥ 20, compute entropy; flag as `high` (not `critical`) if entropy > 4.5 bits/char.
- Existing critical-severity name-based rules are unchanged.
- The new entropy finding has `category="secrets"` and `severity="high"` with a clear explanation distinguishing it from name-based matches.
- Tests: high-entropy string flagged; natural English sentence not flagged; empty string not flagged; short string not flagged; existing name-based patterns still produce critical findings.

### Todo List
- [ ] Implement `compute_entropy(s: str) -> float` using the standard Shannon formula in `analyzer/rules.py`.
- [ ] Add a compiled regex to extract quoted strings of length ≥ 20 from a line.
- [ ] Add an entropy pass at the end of `rule_exposed_secrets`: skip if the line was already flagged by a name-based rule; compute entropy on each extracted quoted string; append an `info`→`high` finding if the threshold is exceeded.
- [ ] Choose and document the entropy threshold (recommended starting point: 4.5 bits/char, calibrated against the demo diffs).
- [ ] Add tests covering: genuine key-like string (entropy > 4.5) → flagged; English sentence → not flagged; short string → not flagged; name-based match on same line → only one finding.
- [ ] Run full test suite; verify clean demo still returns APPROVE.

### Relevant Context
- `analyzer/rules.py:91–118` — `rule_exposed_secrets()` to extend.
- Shannon entropy formula: `H = -sum(p * log2(p) for p in char_frequencies)`.
- Demo dirty diff secret: `"s3cur3P@ssw0rd!"` (length 15, borderline) and `"sk-prod-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"` (length 42, high entropy) — calibrate threshold against these.

### Status
[x] done

---

## Sub-Task 4 — CLI Mode

### Intent
A command-line interface lets the tool run in CI pipelines, pre-commit hooks, and developer terminals without starting a web server. The CLI must accept a diff via stdin or a file argument and output findings to stdout as plain text, JSON, or a compact summary.

### Expected Outcomes
- New file `cli.py` (or `__main__.py`) in the project root with an `argparse`-based interface.
- Invocable as `python -m code_review_coach` or `python cli.py`.
- Supports: `--input <file.patch>` (reads diff from file) and stdin fallback (reads from stdin if no `--input`).
- Supports `--format text|json|summary` (default: `text`).
  - `text`: human-readable findings list + summary, coloured with ANSI codes when stdout is a TTY.
  - `json`: same JSON structure as `/api/analyze`.
  - `summary`: one-line verdict only (e.g. `REQUEST_CHANGES — 14 findings [2 critical, 3 high]`).
- Exit code: `0` if recommendation is APPROVE or APPROVE_WITH_NOTES; `1` if REQUEST_CHANGES or NEEDS_DISCUSSION.
- `requirements.txt` unchanged (no new dependencies; `argparse` and `sys` are stdlib).
- Tests: at least one test that invokes the CLI via `subprocess.run` and checks exit code + stdout shape.
- `README.md` updated with CLI usage section.

### Todo List
- [ ] Create `code-review-coach/cli.py` with `argparse` parser: `--input`, `--format`, `--version`.
- [ ] Implement `format_text(result)` using ANSI colour codes when `sys.stdout.isatty()`.
- [ ] Implement `format_summary(result)` one-liner.
- [ ] Implement `format_json(result)` using `result_to_dict` from `analyzer/engine.py`.
- [ ] Set exit code based on `result.summary.recommendation`.
- [ ] Add `code-review-coach/__main__.py` with one line: `from cli import main; main()` so `python -m code_review_coach` works.
- [ ] Write tests in `tests/test_cli.py` using `subprocess.run` to invoke `python cli.py`.
- [ ] Update `README.md` with a CLI section.
- [ ] Run full test suite.

### Relevant Context
- `analyzer/engine.py:160–180` — `result_to_dict()` already serializes a `ReviewResult` to a JSON-safe dict.
- `run.py` and `app.py` — existing entry points to keep unchanged.
- Exit code convention follows standard Unix lint tools (0 = clean, 1 = issues found).

### Status
[x] done

---

## Sub-Task 5 — GitHub Webhook

### Intent
Add an endpoint that accepts a GitHub `pull_request` webhook event, fetches the PR diff from GitHub's API, runs analysis, and posts findings as inline review comments on the PR. This makes the tool activate automatically on every PR without any manual paste step.

### Expected Outcomes
- New Flask route `POST /webhook/github` in `app.py`.
- Validates the `X-Hub-Signature-256` HMAC header (secret configurable via `GITHUB_WEBHOOK_SECRET` environment variable). Rejects invalid signatures with 403.
- On `pull_request` events with action `opened`, `synchronize`, or `reopened`: fetches the diff from `https://api.github.com/repos/{owner}/{repo}/pulls/{number}` using `Accept: application/vnd.github.v3.diff`.
- Runs `analyze_diff()` on the fetched diff.
- Posts a PR review via `POST /repos/{owner}/{repo}/pulls/{number}/reviews` with:
  - A summary body (the recommendation + main risks).
  - Inline comments for each finding with `path`, `line`, `body` (explanation + fix).
- Uses the `GITHUB_TOKEN` environment variable for authentication. If absent, skips posting and returns the analysis as JSON instead (graceful degradation).
- Adds `requests` to `requirements.txt` (used for GitHub API calls; already present in the environment).
- Tests: mock the GitHub API calls; verify HMAC validation logic; verify graceful degradation when `GITHUB_TOKEN` is unset.
- `README.md` updated with webhook setup section.

### Todo List
- [ ] Add `requests` to `requirements.txt`.
- [ ] Create `analyzer/github.py` with: `verify_signature(payload, secret, signature)`, `fetch_pr_diff(owner, repo, pr_number, token)`, `post_review(owner, repo, pr_number, token, result)`.
- [ ] Add `POST /webhook/github` route to `app.py`: parse event type, validate HMAC, call `fetch_pr_diff`, call `analyze_diff`, call `post_review` (or return JSON if no token).
- [ ] Handle delivery headers (`X-GitHub-Event`, `X-GitHub-Delivery`) for logging.
- [ ] Write `tests/test_github.py` using `unittest.mock.patch` to mock `requests.get/post`; test valid/invalid HMAC; test graceful degradation.
- [ ] Update `README.md` with webhook setup instructions (ngrok for local testing, env vars needed).
- [ ] Run full test suite.

### Relevant Context
- `app.py:47–71` — existing analyze route as a model for the new webhook route.
- `analyzer/engine.py` — `analyze_diff()` and `result_to_dict()` are the only engine functions needed.
- GitHub diff API: `GET /repos/{owner}/{repo}/pulls/{number}` with `Accept: application/vnd.github.v3.diff`.
- GitHub review API: `POST /repos/{owner}/{repo}/pulls/{number}/reviews`.
- HMAC validation: `hmac.compare_digest(expected, received)` using `hashlib.sha256`.

### Status
[x] done

---

## Sub-Task 6 — Optional LLM Layer

### Intent
Wire an optional LLM (IBM watsonx.ai / Granite, or any OpenAI-compatible API) into the summary generation step. When a token is available, the structured findings from the rule engine are sent to the LLM to produce a natural-language summary with richer explanation. When the token is absent the current rule-based summary is used unchanged — the core flow is unaffected.

### Expected Outcomes
- New file `analyzer/llm.py` with a single public function `enhance_summary(result: ReviewResult, config: LLMConfig) -> ReviewSummary`.
- `LLMConfig` is a dataclass with `api_url`, `api_key`, `model_id`, `timeout_seconds`.
- Config is read from environment variables: `LLM_API_URL`, `LLM_API_KEY`, `LLM_MODEL_ID`. If any is absent, `enhance_summary` returns the original summary unchanged.
- The LLM prompt includes: language(s) reviewed, all findings serialized as structured text (not code), and asks for a short review narrative (max 150 words) and an enhanced risk list. Diff content is NOT sent to the LLM.
- `app.py` calls `enhance_summary` after `analyze_diff` if config is present; the `elapsed_ms` field covers the total including LLM time.
- A new `POST /api/analyze` response field `llm_enhanced: bool` indicates whether the LLM was used.
- If the LLM call times out or errors, fall back to the rule-based summary silently; log the error server-side.
- Tests: mock the HTTP call; test fallback on missing env vars; test fallback on LLM timeout.
- `README.md` updated with optional LLM configuration section.

### Todo List
- [ ] Create `analyzer/llm.py` with `LLMConfig` dataclass and `enhance_summary()`.
- [ ] Implement prompt construction: serialize findings to structured text (never raw diff content).
- [ ] Implement HTTP call using `urllib.request` (no new dependency needed).
- [ ] Implement timeout and error fallback.
- [ ] Wire into `app.py` `analyze()` handler: build `LLMConfig` from env vars; call `enhance_summary` if config is complete.
- [ ] Add `llm_enhanced` boolean to the API response and to `result_to_dict()`.
- [ ] Update the UI in `static/index.html` to display a small "AI-enhanced" badge on the summary when `llm_enhanced` is true.
- [ ] Write `tests/test_llm.py`: test no-op when env vars missing; test enhancement applied when mocked; test fallback on error.
- [ ] Update `README.md` with LLM config section (watsonx.ai and OpenAI-compatible endpoints).
- [ ] Run full test suite.

### Relevant Context
- `analyzer/engine.py:54–120` — `_build_summary()` is the function to optionally replace.
- `analyzer/engine.py:160–180` — `result_to_dict()` needs `llm_enhanced` field added.
- `app.py:60–71` — `analyze()` handler where `enhance_summary` is called after `analyze_diff`.
- IBM watsonx.ai inference endpoint: `POST /ml/v1/text/generation` (compatible with OpenAI chat completions format with model override).

### Status
[x] done

---

## Dependency and Ordering Notes

Sub-tasks are largely independent. The recommended implementation order is:

1. **Sub-Task 1** first — context windows reduce false positives in the existing rules and make the baseline cleaner for all subsequent work.
2. **Sub-Task 2** and **Sub-Task 3** can be done in either order or in parallel — both add to `rules.py` without touching the engine contract.
3. **Sub-Task 4** (CLI) depends only on the public `analyze_diff` / `result_to_dict` API — always safe to do.
4. **Sub-Task 5** (webhook) depends on Sub-Task 4 being done first is not required, but sharing the same `analyze_diff` entry point makes it straightforward.
5. **Sub-Task 6** (LLM) should be last — it wraps the summary layer and benefits from the cleaner findings produced by Sub-Tasks 1–3.
