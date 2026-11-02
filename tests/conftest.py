"""Test-suite guard: no test may reach the network.

Every adapter and fetcher test uses fakes or a stub transport. If any code path tries to open a
socket or resolve a name, the test fails loudly instead of silently depending on live internet.

A test marked ``@pytest.mark.allow_loopback`` may additionally connect to THIS machine (loopback
only); see ``network_guard.py``. Only the Streamlit smoke tests use it.
"""
import pytest

from network_guard import install


@pytest.fixture(autouse=True)
def _block_network(monkeypatch, request):
    allow = request.node.get_closest_marker("allow_loopback") is not None
    install(monkeypatch, allow_loopback=allow)
