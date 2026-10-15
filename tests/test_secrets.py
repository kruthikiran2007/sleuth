"""Tests for secret scanning: every pattern gets a true positive and a
true negative. Redaction is verified so full secrets never leak into output."""

from sleuth import secrets as secrets_mod


def _types(hits):
    return {h["type"] for h in hits}


# --- true positives -------------------------------------------------------

def test_aws_access_key():
    hits = secrets_mod.scan_secrets("key = AKIAIOSFODNN7EXAMPLE")
    assert "aws_access_key" in _types(hits)


def test_github_token():
    hits = secrets_mod.scan_secrets("token ghp_" + "a" * 36)
    assert "github_token" in _types(hits)


def test_github_pat():
    hits = secrets_mod.scan_secrets("t=" + "github_pat_" + "b" * 82)
    assert "github_pat" in _types(hits)


def test_slack_token():
    hits = secrets_mod.scan_secrets("xoxb-123456789012-abcdefghij")
    assert "slack_token" in _types(hits)


def test_private_key():
    hits = secrets_mod.scan_secrets("-----BEGIN RSA PRIVATE KEY-----")
    assert "private_key" in _types(hits)


def test_generic_api_key():
    hits = secrets_mod.scan_secrets('api_key = "supersecretkey12345"')
    assert "generic_api_key" in _types(hits)


def test_password_in_url():
    hits = secrets_mod.scan_secrets("https://admin:s3cretpass@db.internal/x")
    assert "password_in_url" in _types(hits)


def test_discord_webhook():
    hits = secrets_mod.scan_secrets(
        "https://discord.com/api/webhooks/123456/abcDEF_-xyz")
    assert "discord_webhook" in _types(hits)


def test_google_api_key():
    hits = secrets_mod.scan_secrets("AIza" + "c" * 35)
    assert "google_api_key" in _types(hits)


def test_stripe_key():
    hits = secrets_mod.scan_secrets("sk_live_" + "d" * 24)
    assert "stripe_key" in _types(hits)


# --- true negatives (must NOT match) ----------------------------------------

def test_no_secrets_in_benign_text():
    text = ("hello world\nthis is a normal readme\n"
            "api_key is not set here\nversion 1.2.3")
    assert secrets_mod.scan_secrets(text) == []


def test_short_random_string_not_flagged():
    assert secrets_mod.scan_secrets("AKIA too short") == []
    assert secrets_mod.scan_secrets("ghp_short") == []


def test_url_without_password_not_flagged():
    hits = secrets_mod.scan_secrets("https://example.com/path?q=1")
    assert "password_in_url" not in _types(hits)


# --- redaction ---------------------------------------------------------------

def test_redact_hides_secret():
    preview = secrets_mod.redact("AKIAIOSFODNN7EXAMPLE")
    assert preview == "AKIA..."
    assert "IOSFODNN7EXAMPLE" not in preview


def test_redact_short_secret():
    assert secrets_mod.redact("abc") == "****"


def test_scan_output_never_contains_full_secret():
    secret = "ghp_" + "z" * 36
    hits = secrets_mod.scan_secrets("leaked: " + secret)
    assert hits, "expected a match"
    for h in hits:
        assert secret not in h["preview"]
        assert h["preview"].startswith("ghp_")
