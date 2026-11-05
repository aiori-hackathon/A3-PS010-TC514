import pytest

from netclass.redaction import REDACTED, redact_headers, redact_text, redact_url


def test_url_credentials_query_and_fragment_are_removed():
    assert redact_url("https://u:p@h.example/a/b?token=abc&x=1#frag") == (
        f"https://h.example/a/b?{REDACTED}"
    )
    assert redact_url("https://h.example/a") == "https://h.example/a"
    assert redact_url("not a url") == "not a url"


@pytest.mark.parametrize(
    "text, secret",
    [
        ("Authorization: Bearer abcdef123456", "abcdef123456"),
        ("sent token=SuperSecret99 to server", "SuperSecret99"),
        ("api_key=K3Y12345&x=1", "K3Y12345"),
        ("GET https://h.example/p?key=ZZZ failed", "ZZZ"),
        ("password: hunter22", "hunter22"),
        ("https://user:pw123456@h.example/x", "pw123456"),
    ],
)
def test_secrets_never_survive_redact_text(text, secret):
    assert secret not in redact_text(text)


def test_harmless_text_is_untouched():
    assert redact_text("HTTP 503 (expected 200)") == "HTTP 503 (expected 200)"
    assert redact_text("") == ""


def test_sensitive_headers_are_masked_and_others_kept():
    out = redact_headers({"Authorization": "Bearer x", "Cookie": "a=b", "ETag": '"abc"'})
    assert out == {"Authorization": REDACTED, "Cookie": REDACTED, "ETag": '"abc"'}
