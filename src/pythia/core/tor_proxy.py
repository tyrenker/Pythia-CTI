"""Tor proxy manager using stem for circuit rotation.

Gracefully degrades when Tor is not running or stem is not installed.
"""

from __future__ import annotations

import socket
from typing import Any


def _stem_available() -> bool:
    try:
        import stem  # noqa: F401

        return True
    except ImportError:
        return False


class TorProxyManager:
    """Wraps stem Controller for circuit management.

    If Tor is unavailable and tor_required=False, all methods are no-ops.
    """

    def __init__(
        self,
        control_host: str = "127.0.0.1",
        control_port: int = 9051,
        password: str | None = None,
    ) -> None:
        self._control_host = control_host
        self._control_port = control_port
        self._password = password
        self._controller: Any = None

    def _connect(self) -> bool:
        if not _stem_available():
            return False
        try:
            from stem import Signal
            from stem.control import Controller

            self._controller = Controller.from_port(
                address=self._control_host, port=self._control_port
            )
            self._controller.authenticate(password=self._password or "")
            _ = Signal  # imported for new_circuit
            return True
        except Exception:
            self._controller = None
            return False

    def is_available(self) -> bool:
        """Return True if the Tor SOCKS proxy port is reachable."""
        from pythia.core.config import get_settings

        settings = get_settings()
        host = settings.tor_host
        port = settings.tor_socks_port
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            return False

    def new_circuit(self) -> None:
        """Issue NEWNYM to stem to get a fresh Tor circuit."""
        if self._controller is None and not self._connect():
            return
        try:
            from stem import Signal

            self._controller.signal(Signal.NEWNYM)
        except Exception:
            self._controller = None

    def close(self) -> None:
        if self._controller is not None:
            import contextlib

            with contextlib.suppress(Exception):
                self._controller.close()
            self._controller = None
