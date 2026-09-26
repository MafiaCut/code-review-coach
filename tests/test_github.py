"""
Tests for the GitHub webhook integration.
Uses unittest.mock to avoid real network calls.
"""
import sys, os, json, hashlib, hmac
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock
from analyzer.github import verify_signature, fetch_pr_diff, post_review, _build_review_body
from analyzer.engine import analyze_diff


# ── verify_signature tests ───────────────────────────────────────────────────

class TestVerifySignature:
    def _make_sig(self, payload: bytes, secret: str) -> str:
        digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def test_valid_signature(self):
        payload = b'{"action":"opened"}'
        secret = "my_webhook_secret"
        sig = self._make_sig(payload, secret)
        assert verify_signature(payload, secret, sig) is True

    def test_invalid_signature(self):
        payload = b'{"action":"opened"}'
        assert verify_signature(payload, "real_secret", "sha256=deadbeef") is False

    def test_tampered_payload(self):
        secret = "my_webhook_secret"
        sig = self._make_sig(b'original payload', secret)
        assert verify_signature(b'tampered payload', secret, sig) is False

    def test_missing_prefix(self):
        payload = b'{"action":"opened"}'
        secret = "my_webhook_secret"
        raw = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        # No "sha256=" prefix
        assert verify_signature(payload, secret, raw) is False

    def test_empty_signature(self):
        assert verify_signature(b"data", "secret", "") is False

    def test_empty_secret_still_works(self):
        """If no secret is configured, verify_signature is not called by the route,
        but calling it directly with empty string is handled gracefully."""
        payload = b'data'
        sig = self._make_sig(payload, "")
        assert verify_signature(payload, "", sig) is True


# ── fetch_pr_diff tests ──────────────────────────────────────────────────────

class TestFetchPrDiff:
    SAMPLE_DIFF = "diff --git a/app.py b/app.py\n+print('hello')\n"

    def test_fetch_returns_diff(self):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = self.SAMPLE_DIFF.encode("utf-8")

        with patch("analyzer.github.urllib.request.urlopen", return_value=mock_resp):
            diff = fetch_pr_diff("owner", "repo", 42, "token123")
        assert diff == self.SAMPLE_DIFF

    def test_fetch_raises_on_http_error(self):
        import urllib.error
        with patch("analyzer.github.urllib.request.urlopen",
                   side_effect=urllib.error.HTTPError(None, 404, "Not Found", {}, None)):
            with pytest.raises(urllib.error.HTTPError):
                fetch_pr_diff("owner", "repo", 999, "token123")


# ── post_review tests ────────────────────────────────────────────────────────

class TestPostReview:
    DIRTY_DIFF = (
        "diff --git a/auth.py b/auth.py\n"
        "--- a/auth.py\n+++ b/auth.py\n"
        "@@ -1 +1,3 @@\n import os\n"
        '+SECRET = "AKIAIOSFODNN7EXAMPLE"\n'
        "+os.system(cmd)\n"
    )

    def test_post_review_sends_request(self):
        result = analyze_diff(self.DIRTY_DIFF)
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({"id": 12345}).encode()

        with patch("analyzer.github.urllib.request.urlopen", return_value=mock_resp) as mock_open:
            response = post_review("owner", "repo", 1, "token", result, "abc123")
        assert response["id"] == 12345
        # Verify a POST request was made to the reviews endpoint
        call_args = mock_open.call_args[0][0]
        assert "/pulls/1/reviews" in call_args.full_url

    def test_review_body_contains_recommendation(self):
        result = analyze_diff(self.DIRTY_DIFF)
        body = _build_review_body(result)
        assert "REQUEST_CHANGES" in body or "APPROVE" in body or "NEEDS_DISCUSSION" in body

    def test_review_body_contains_findings_count(self):
        result = analyze_diff(self.DIRTY_DIFF)
        body = _build_review_body(result)
        assert "finding" in body.lower()


# ── Flask webhook route tests ────────────────────────────────────────────────

class TestGitHubWebhookRoute:
    WEBHOOK_SECRET = "test_secret_abc"

    def _make_payload(self, action="opened"):
        return json.dumps({
            "action": action,
            "pull_request": {
                "number": 7,
                "head": {"sha": "deadbeef"},
            },
            "repository": {
                "name": "my-repo",
                "owner": {"login": "octocat"},
            },
        }).encode()

    def _sign(self, payload: bytes) -> str:
        digest = hmac.new(self.WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def _get_client(self):
        import app as flask_app
        flask_app.app.config["TESTING"] = True
        return flask_app.app.test_client()

    def test_invalid_signature_returns_403(self):
        client = self._get_client()
        with patch.dict(os.environ, {"GITHUB_WEBHOOK_SECRET": self.WEBHOOK_SECRET}):
            resp = client.post(
                "/webhook/github",
                data=self._make_payload(),
                content_type="application/json",
                headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": "sha256=badhash"},
            )
        assert resp.status_code == 403

    def test_missing_webhook_secret_disables_endpoint(self):
        client = self._get_client()
        with patch.dict(os.environ, {"GITHUB_WEBHOOK_SECRET": ""}):
            resp = client.post(
                "/webhook/github",
                data=self._make_payload(),
                content_type="application/json",
                headers={"X-GitHub-Event": "pull_request"},
            )
        assert resp.status_code == 503

    def test_non_pr_event_ignored(self):
        client = self._get_client()
        payload = b'{}'
        with patch.dict(os.environ, {"GITHUB_WEBHOOK_SECRET": self.WEBHOOK_SECRET}):
            resp = client.post(
                "/webhook/github",
                data=payload,
                content_type="application/json",
                headers={
                    "X-GitHub-Event": "push",
                    "X-Hub-Signature-256": self._sign(payload),
                },
            )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ignored"

    def test_pr_action_closed_ignored(self):
        client = self._get_client()
        payload = self._make_payload(action="closed")
        with patch.dict(os.environ, {"GITHUB_WEBHOOK_SECRET": self.WEBHOOK_SECRET}):
            resp = client.post(
                "/webhook/github",
                data=payload,
                content_type="application/json",
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-Hub-Signature-256": self._sign(payload),
                },
            )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ignored"

    def test_graceful_degradation_no_token(self):
        """Without GITHUB_TOKEN, returns analysis as JSON (no post to GitHub)."""
        client = self._get_client()
        payload = self._make_payload()
        sample_diff = (
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
            "@@ -1 +1,2 @@\n import os\n+os.system(user_cmd)\n"
        )
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = sample_diff.encode()

        with patch.dict(os.environ, {
            "GITHUB_WEBHOOK_SECRET": self.WEBHOOK_SECRET,
            "GITHUB_TOKEN": "",
        }):
            with patch("app.fetch_pr_diff", return_value=sample_diff):
                resp = client.post(
                    "/webhook/github",
                    data=payload,
                    content_type="application/json",
                    headers={
                        "X-GitHub-Event": "pull_request",
                        "X-Hub-Signature-256": self._sign(payload),
                    },
                )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "analyzed_no_post"
        assert "findings" in data
