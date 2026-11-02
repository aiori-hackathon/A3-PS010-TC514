"""What may be stored: no tokens, authorization headers or raw bodies."""
from netclass.audit.privacy import (
    MAX_TEXT_LENGTH,
    OMITTED_BODY,
    REDACTED,
    redact_text,
    safe_error_message,
    scrub,
)

SECRET = "tok_FIXTURE_0123456789abcdef"


def test_exact_secret_is_replaced_everywhere_in_a_string():
    text, n = redact_text(f"failed for {SECRET} and again {SECRET}", [SECRET])
    assert SECRET not in text and n == 2 and REDACTED in text


def test_token_shaped_text_is_redacted_even_when_unknown():
    for raw in (
        "GET https://x.invalid/lite/1.2.3.4?token=abcDEF123&x=1",
        "Authorization: Bearer abc.def.ghi",
        "bearer SECRETVALUE",
        "api_key=hunter2hunter2",
        "access-token: zzz999",
    ):
        text, n = redact_text(raw)
        assert n >= 1, raw
        for leaked in ("abcDEF123", "abc.def.ghi", "SECRETVALUE", "hunter2hunter2", "zzz999"):
            assert leaked not in text


def test_secret_keys_are_replaced_regardless_of_value_and_case():
    clean, n = scrub({"Authorization": "Basic xyz", "nested": {"Set-Cookie": "sid=1", "ok": "fine"}})
    assert clean == {"Authorization": REDACTED, "nested": {"Set-Cookie": REDACTED, "ok": "fine"}}
    assert n == 2


def test_body_keys_are_dropped_and_marked():
    clean, n = scrub({"response_body": "<html>raw</html>", "raw_body": b"x".decode(), "bytes": 5})
    assert clean["response_body"] == OMITTED_BODY and clean["raw_body"] == OMITTED_BODY
    assert clean["bytes"] == 5 and n == 2


def test_empty_secret_keys_are_not_counted_as_redactions():
    clean, n = scrub({"token": None, "password": ""})
    assert clean == {"token": None, "password": ""} and n == 0


def test_scrub_returns_a_copy_and_leaves_input_alone():
    original = {"a": [{"token": "t"}], "b": f"x {SECRET}"}
    snapshot = repr(original)
    clean, _ = scrub(original, [SECRET])
    assert repr(original) == snapshot
    assert clean["a"][0]["token"] == REDACTED and SECRET not in repr(clean)


def test_ordinary_values_pass_through_unchanged():
    doc = {"label": "Known Tor exit", "n": 3, "f": 1.5, "ok": True, "none": None, "list": ["a", 1]}
    clean, n = scrub(doc, [SECRET])
    assert clean == doc and n == 0


def test_very_long_text_is_truncated_visibly():
    clean, n = scrub({"x": "a" * (MAX_TEXT_LENGTH + 10)})
    assert clean["x"].endswith("...[truncated]") and n == 1


def test_short_exact_secrets_do_not_mangle_text():
    text, n = redact_text("abc abc", ["ab"])
    assert text == "abc abc" and n == 0


def test_safe_error_message_is_short_and_redacted():
    exc = RuntimeError(f"boom with {SECRET} " + "x" * 1000)
    message = safe_error_message(exc, [SECRET])
    assert message.startswith("RuntimeError: ") and SECRET not in message and len(message) < 400
