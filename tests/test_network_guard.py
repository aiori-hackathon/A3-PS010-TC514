"""The network guard blocks everything by default and, when asked, only opens loopback."""
import socket

import pytest

import network_guard

EXTERNAL = ("93.184.216.34", 80)  # arbitrary public address; the guard raises before any traffic


def _tcp():
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_by_default_even_loopback_is_blocked():
    with _tcp() as s, pytest.raises(RuntimeError, match="network access is blocked"):
        s.connect(("127.0.0.1", 9))
    with pytest.raises(RuntimeError, match="blocked"):
        socket.getaddrinfo("localhost", 80)
    with pytest.raises(RuntimeError, match="blocked"):
        socket.create_connection(("127.0.0.1", 9))


@pytest.mark.allow_loopback
def test_marked_tests_still_cannot_reach_external_hosts():
    with _tcp() as s, pytest.raises(RuntimeError, match="network access is blocked"):
        s.connect(EXTERNAL)
    with pytest.raises(RuntimeError, match="blocked"):
        socket.getaddrinfo("example.com", 80)  # needs DNS: refused before any lookup
    with pytest.raises(RuntimeError, match="blocked"):
        socket.create_connection(EXTERNAL)
    with _tcp() as s, pytest.raises(RuntimeError, match="blocked"):
        s.connect(("2606:4700:4700::1111", 80, 0, 0))


@pytest.mark.allow_loopback
def test_marked_tests_can_use_loopback_and_socketpair():
    a, b = socket.socketpair()  # what asyncio's Windows event loop needs
    a.close()
    b.close()
    with _tcp() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with _tcp() as client:
            client.connect(server.getsockname())
            conn, _ = server.accept()
            conn.close()


def test_the_marker_is_registered_and_only_the_smoke_tests_use_it():
    from pathlib import Path

    root = Path(__file__).resolve().parent
    assert "allow_loopback" in (root.parent / "pytest.ini").read_text(encoding="utf-8")
    users = {
        p.name
        for p in root.glob("test_*.py")
        if "pytest.mark.allow_loopback" in p.read_text(encoding="utf-8") and p.name != Path(__file__).name
    }
    assert users == {"test_dashboard_app_smoke.py"}


def test_helper_classifies_hosts_conservatively():
    g = network_guard
    assert all(g.is_loopback_host(h) for h in ("127.0.0.1", "127.1.2.3", "::1", "localhost", b"localhost"))
    assert not any(g.is_loopback_host(h) for h in ("8.8.8.8", "example.com", "0.0.0.0", "", None, 5, "10.0.0.1"))
    assert g.is_local_address(("127.0.0.1", 80)) and g.is_local_address("/tmp/sock")
    assert not g.is_local_address(("93.184.216.34", 80)) and not g.is_local_address(())
