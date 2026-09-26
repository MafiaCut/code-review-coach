"""
Flask backend for the Intelligent Code Review Coach.
Exposes a minimal JSON API:
  POST /api/analyze        – analyze a unified diff
  GET  /api/demos          – list available demo examples
  GET  /api/demos/<id>     – return the diff for a specific demo
  POST /webhook/github     – GitHub pull_request webhook (auto-review PRs)
  GET  /                   – serve the single-page UI
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory

from analyzer.engine import analyze_diff, result_to_dict
from analyzer.github import verify_signature, fetch_pr_diff, post_review
from analyzer.llm import enhance_summary
from .demos.demo_dirty import DEMO_DIRTY, DEMO_DIRTY_TITLE, DEMO_DIRTY_DESCRIPTION
from .demos.demo_clean import DEMO_CLEAN, DEMO_CLEAN_TITLE, DEMO_CLEAN_DESCRIPTION

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")

_DEMOS = {
    "dirty": {
        "id": "dirty",
        "title": DEMO_DIRTY_TITLE,
        "description": DEMO_DIRTY_DESCRIPTION,
        "diff": DEMO_DIRTY,
    },
    "clean": {
        "id": "clean",
        "title": DEMO_CLEAN_TITLE,
        "description": DEMO_CLEAN_DESCRIPTION,
        "diff": DEMO_CLEAN,
    },
}

MAX_DIFF_BYTES = 500_000   # 500 KB – reject obviously oversized payloads


@app.route("/")
def index():
    return send_from_directory(str(STATIC_DIR), "index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Accept a JSON body: {"diff": "<unified diff string>", "lang": "en"|"es"}
    Returns analysis results as JSON.
    The diff is treated as untrusted text; it is never executed.
    """
    body = request.get_json(silent=True)
    if not body or "diff" not in body:
        return jsonify({"error": "Request body must be JSON with a 'diff' key."}), 400

    diff_text = body["diff"]
    if not isinstance(diff_text, str):
        return jsonify({"error": "'diff' must be a string."}), 400

    if len(diff_text.encode()) > MAX_DIFF_BYTES:
        return jsonify({"error": f"Diff exceeds {MAX_DIFF_BYTES // 1024} KB limit."}), 413

    lang = body.get("lang", "en")

    t0 = time.perf_counter()
    result = analyze_diff(diff_text, lang=lang)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    payload = result_to_dict(result, lang=lang)
    payload, llm_enhanced = enhance_summary(payload)
    payload["elapsed_ms"] = elapsed_ms
    payload["llm_enhanced"] = llm_enhanced
    return jsonify(payload)


@app.route("/api/demos", methods=["GET"])
def list_demos():
    return jsonify([
        {"id": d["id"], "title": d["title"], "description": d["description"]}
        for d in _DEMOS.values()
    ])


@app.route("/api/demos/<demo_id>", methods=["GET"])
def get_demo(demo_id: str):
    demo = _DEMOS.get(demo_id)
    if not demo:
        return jsonify({"error": f"Demo '{demo_id}' not found."}), 404
    return jsonify(demo)


@app.route("/webhook/github", methods=["POST"])
def github_webhook():
    """
    Accept a GitHub pull_request webhook event.
    Validates the X-Hub-Signature-256 HMAC header, fetches the PR diff,
    runs analysis, and posts findings as inline PR review comments.

    Required environment variables:
        GITHUB_WEBHOOK_SECRET  – the secret configured in the GitHub webhook settings
        GITHUB_TOKEN           – a personal access token with repo / pull_requests scope

    If GITHUB_TOKEN is not set, the analysis result is returned as JSON instead
    of being posted to GitHub (graceful degradation).
    """
    # ── Validate HMAC signature ──────────────────────────────────────────────
    webhook_secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "").strip()
    if not webhook_secret:
        logger.error("GitHub webhook disabled: GITHUB_WEBHOOK_SECRET is not configured")
        return jsonify({"error": "GitHub webhook is not configured."}), 503

    sig = request.headers.get("X-Hub-Signature-256", "")
    if not verify_signature(request.data, webhook_secret, sig):
        logger.warning("GitHub webhook: invalid HMAC signature")
        return jsonify({"error": "Invalid signature."}), 403

    # ── Parse event type ────────────────────────────────────────────────────
    event_type = request.headers.get("X-GitHub-Event", "")
    delivery_id = request.headers.get("X-GitHub-Delivery", "unknown")
    logger.info("GitHub webhook delivery=%s event=%s", delivery_id, event_type)

    if event_type != "pull_request":
        return jsonify({"status": "ignored", "event": event_type}), 200

    payload = request.get_json(silent=True) or {}
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return jsonify({"status": "ignored", "action": action}), 200

    # ── Extract PR details ──────────────────────────────────────────────────
    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {})
    owner = repo.get("owner", {}).get("login", "")
    repo_name = repo.get("name", "")
    pr_number = pr.get("number")
    commit_sha = pr.get("head", {}).get("sha")

    if not (owner and repo_name and pr_number):
        return jsonify({"error": "Missing PR metadata in payload."}), 400

    # ── Fetch diff and analyze ───────────────────────────────────────────────
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        logger.warning("GITHUB_TOKEN not set – returning analysis as JSON (no PR comment posted)")
        # Graceful degradation: return analysis result without posting to GitHub
        try:
            diff_text = fetch_pr_diff(owner, repo_name, pr_number, "")
        except Exception as e:
            return jsonify({"error": f"Cannot fetch diff without GITHUB_TOKEN: {e}"}), 400
        result = analyze_diff(diff_text)
        d = result_to_dict(result)
        d["status"] = "analyzed_no_post"
        return jsonify(d)

    try:
        diff_text = fetch_pr_diff(owner, repo_name, pr_number, token)
    except Exception as e:
        logger.error("Failed to fetch PR diff: %s", e)
        return jsonify({"error": f"Failed to fetch PR diff: {e}"}), 502

    result = analyze_diff(diff_text)

    # ── Post review to GitHub ────────────────────────────────────────────────
    try:
        gh_response = post_review(owner, repo_name, pr_number, token, result, commit_sha)
        logger.info("Posted review for %s/%s#%s id=%s", owner, repo_name, pr_number,
                    gh_response.get("id"))
    except Exception as e:
        logger.error("Failed to post review: %s", e)
        d = result_to_dict(result)
        d["status"] = "analyzed_post_failed"
        d["post_error"] = str(e)
        return jsonify(d), 502

    d = result_to_dict(result)
    d["status"] = "reviewed"
    d["github_review_id"] = gh_response.get("id")
    return jsonify(d), 200


def main() -> None:
    """Run the bundled web interface."""
    # use_reloader=False avoids the Werkzeug reloader child-process
    # exit issue on Python 3.14 when running as __main__ directly.
    app.run(debug=False, port=5000, use_reloader=False)


if __name__ == "__main__":
    main()
