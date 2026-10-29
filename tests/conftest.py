"""Keep every test away from the installed owner's policy and data."""
import ipaddress
import pytest
import socket
import sys


@pytest.fixture(autouse=True)
def isolated_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTFETCH_HOME", str(tmp_path / "isolated-policy"))
    monkeypatch.setenv("SIFTFETCH_DATA", str(tmp_path / "isolated-data"))
    monkeypatch.delenv("SIFTFETCH_DOWNLOAD_DIR", raising=False)
    monkeypatch.delenv("SIFTFETCH_ENABLED", raising=False)
    monkeypatch.delenv("SIFTFETCH_CONTACT_ALIAS", raising=False)
    # Loopback test servers (redirects, budgets, the egress proxy) are local
    # and stay in the suite; anything that leaves the machine fails the test.
    def loopback(address):
        host = address[0] if isinstance(address, tuple) and address else address
        if not isinstance(host, str):
            return False
        try:
            return ipaddress.ip_address(host.split("%")[0]).is_loopback
        except ValueError:
            return host == "localhost"
    def guard(original):
        def no_network(sock, address, *args, **kwargs):
            # Windows implements asyncio's internal wakeup pipe with socketpair.
            # This is process-local signaling, never a request to a service.
            caller = sys._getframe(1)
            if caller.f_code.co_name == "_fallback_socketpair" and caller.f_globals.get("__name__") == "socket":
                return original(sock, address, *args, **kwargs)
            if loopback(address):
                return original(sock, address, *args, **kwargs)
            raise AssertionError("No network in tests: use a loopback server or a mock transport")
        return no_network
    monkeypatch.setattr(socket.socket, "connect", guard(socket.socket.connect))
    monkeypatch.setattr(socket.socket, "connect_ex", guard(socket.socket.connect_ex))
    monkeypatch.setattr(socket.socket, "bind", guard(socket.socket.bind))
    real_getaddrinfo = socket.getaddrinfo
    def no_network(host, *args, **kwargs):
        if loopback((host.decode() if isinstance(host, bytes) else host,)):
            return real_getaddrinfo(host, *args, **kwargs)
        raise socket.gaierror("No DNS in tests: use a mock resolver")
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket, "getfqdn", lambda *args: socket.gethostname())
