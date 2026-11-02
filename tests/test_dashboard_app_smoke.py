"""Optional Streamlit smoke test (skipped when Streamlit is not installed).

Uses Streamlit's headless AppTest: no browser, no server, no external network (loopback only).
"""
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

# Streamlit's event loop (notably asyncio on Windows) builds a local socket pair by connecting over
# loopback. The marker allows loopback only; external hosts and DNS stay blocked (network_guard.py).
pytestmark = pytest.mark.allow_loopback

APP = str(Path(__file__).resolve().parents[1] / "app.py")


@pytest.fixture
def clean_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETCLASS_DB_PATH", str(tmp_path / "data" / "audit.sqlite3"))
    for key in ("NETCLASS_AUDIT_ENABLED", "IPINFO_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    return tmp_path


def test_app_renders_without_a_lookup_or_a_database(clean_env):
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert [b.label for b in at.button] == ["Classify IP"]
    assert not (clean_env / "data").exists()  # opening the app created nothing


def test_invalid_input_is_reported_without_a_lookup(clean_env):
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.text_input(key="ps010_ip_input").set_value("not-an-ip").run()
    assert not at.exception
    assert any("not a valid" in e.value for e in at.error)
    at.button(key="ps010_classify").click().run()
    assert not at.exception and not (clean_env / "data").exists()
