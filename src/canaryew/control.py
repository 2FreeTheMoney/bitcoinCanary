"""Control socket: how the operator talks to the running service.

A unix domain socket with 0600 permissions, line-delimited JSON, three
commands: ``unlock``, ``ack``, ``status``. Chosen over the originally sketched
localhost HTTP unlock route because:

- Access control is the filesystem, not an auth layer we would have to build:
  only the service user (and root) can connect at all.
- The passphrase transits a kernel socket between two local processes and
  never touches a TCP stack, a request log, or a proxy.
- The web status surface can then be a *separate keyless process* -- it reads
  a redacted snapshot file and holds nothing derived from a key, so
  compromising it yields nothing.

Protocol: one JSON object per line in, one JSON object per line out, then the
connection closes. ``{"ok": true, ...}`` or ``{"ok": false, "error": "..."}``.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import socketserver
import threading
from pathlib import Path
from typing import Any, Callable, Final

logger = logging.getLogger("canaryew.control")

_MAX_REQUEST_BYTES: Final[int] = 64 * 1024
_IO_TIMEOUT: Final[float] = 30.0

Handler = Callable[[dict[str, Any]], dict[str, Any]]


class ControlError(RuntimeError):
    """Raised by the client when the service cannot be reached or errors."""


class _RequestHandler(socketserver.StreamRequestHandler):
    timeout = _IO_TIMEOUT

    def handle(self) -> None:
        server: ControlServer = self.server  # type: ignore[assignment]
        try:
            line = self.rfile.readline(_MAX_REQUEST_BYTES)
            request = json.loads(line.decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("request must be a JSON object")
        except Exception:
            self._reply({"ok": False, "error": "malformed request"})
            return

        try:
            response = server.dispatch(request)
        except Exception as exc:
            # Never leak a traceback (or passphrase-bearing request echo) to
            # the socket; log server-side, return a terse error.
            logger.exception("control command failed")
            response = {"ok": False, "error": f"{type(exc).__name__}"}
        self._reply(response)

    def _reply(self, payload: dict[str, Any]) -> None:
        try:
            self.wfile.write(json.dumps(payload).encode("utf-8") + b"\n")
        except OSError:
            pass


class ControlServer(socketserver.ThreadingUnixStreamServer):
    """Socket server bound to ``socket_path`` with owner-only permissions."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, socket_path: str | Path, handler: Handler) -> None:
        self._socket_path = Path(socket_path)
        self._handler = handler
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        self._socket_path.unlink(missing_ok=True)
        super().__init__(str(self._socket_path), _RequestHandler)
        os.chmod(self._socket_path, 0o600)
        self._thread: threading.Thread | None = None

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._handler(request)

    def start(self) -> None:
        """Serve in a daemon thread; returns immediately."""
        self._thread = threading.Thread(
            target=self.serve_forever, name="canaryew-control", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        # shutdown() blocks until serve_forever() acknowledges, so it must only
        # run if the serve thread was actually started -- otherwise it deadlocks.
        if self._thread is not None:
            self.shutdown()
            self._thread = None
        self.server_close()
        self._socket_path.unlink(missing_ok=True)


def send_command(
    socket_path: str | Path,
    request: dict[str, Any],
    *,
    timeout: float = _IO_TIMEOUT,
) -> dict[str, Any]:
    """Client side: send one command, return the parsed response.

    ``timeout`` is generous because ``unlock`` runs Argon2id (256 MiB, a
    fraction of a second on server hardware, longer on small boards) before
    replying.
    """
    path = Path(socket_path)
    if not path.exists():
        raise ControlError(
            f"Control socket {path} does not exist. Is the canaryew service running?"
        )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(path))
            client.sendall(json.dumps(request).encode("utf-8") + b"\n")
            chunks: list[bytes] = []
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if chunk.endswith(b"\n"):
                    break
    except OSError as exc:
        raise ControlError(f"Unable to reach the canaryew service: {exc}") from exc

    try:
        response = json.loads(b"".join(chunks).decode("utf-8"))
        if not isinstance(response, dict):
            raise ValueError
        return response
    except (ValueError, json.JSONDecodeError) as exc:
        raise ControlError("Malformed response from the canaryew service.") from exc
