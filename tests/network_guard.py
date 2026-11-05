"""The test suite's network guard (stdlib only, so it can be tested on its own).

Default: every attempt to connect or resolve a name raises, exactly as before the loopback option existed.

With ``allow_loopback=True`` (used only by tests marked ``@pytest.mark.allow_loopback``) the guard
lets through connections to this machine and nothing else: a loopback IP literal (127.0.0.0/8,
::1), the name ``localhost``, or a local (AF_UNIX) path. Name resolution is allowed only for those
same hosts (and for ``None``, which asks for the local wildcard and performs no DNS lookup).
Every other host, including any name needing DNS, still raises. Streamlit's AppTest needs this on
Windows because asyncio's event loop creates a local socket pair by connecting over loopback.
"""
from __future__ import annotations

import ipaddress
import socket

BLOCK_MESSAGE = "network access is blocked in the test suite"


def is_loopback_host(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "ignore")
    if not isinstance(host, str):
        return False
    text = host.strip().lower().rstrip(".")
    if text == "localhost":
        return True
    try:
        return ipaddress.ip_address(text.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def is_local_address(address: object) -> bool:
    """True for a loopback (host, port, ...) tuple or a local AF_UNIX path."""
    if isinstance(address, tuple):
        return bool(address) and is_loopback_host(address[0])
    return isinstance(address, (str, bytes))  # AF_UNIX path: never leaves the machine


def _blocked(*args, **kwargs):
    raise RuntimeError(BLOCK_MESSAGE)


def install(monkeypatch, *, allow_loopback: bool = False) -> None:
    """Patch the socket module through a pytest-style ``monkeypatch`` (setattr only)."""
    if not allow_loopback:
        monkeypatch.setattr(socket.socket, "connect", _blocked)
        monkeypatch.setattr(socket, "getaddrinfo", _blocked)
        monkeypatch.setattr(socket, "create_connection", _blocked)
        return

    real_connect = socket.socket.connect
    real_getaddrinfo = socket.getaddrinfo
    real_create_connection = socket.create_connection

    def connect(self, address):
        if not is_local_address(address):
            raise RuntimeError(BLOCK_MESSAGE)
        return real_connect(self, address)

    def getaddrinfo(host, *args, **kwargs):
        if host is not None and not is_loopback_host(host):
            raise RuntimeError(BLOCK_MESSAGE)
        return real_getaddrinfo(host, *args, **kwargs)

    def create_connection(address, *args, **kwargs):
        if not is_local_address(address):
            raise RuntimeError(BLOCK_MESSAGE)
        return real_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", create_connection)
