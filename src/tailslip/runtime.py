"""Glue: a Session + HTTP server + Transport with clean setup and teardown."""

from __future__ import annotations

import sys
import threading
from typing import Callable, Optional

from .server import Request, Session, Value, make_server, serve_in_background
from .transports import Transport, TransportError
from .util import atomic_write, format_duration


def stderr_log(line: str) -> None:
    sys.stderr.write(f"tailslip: {line}\n")
    sys.stderr.flush()


class Handoff:
    def __init__(
        self,
        request: Request,
        transport: Transport,
        deliver: Callable[[Value], None],
        *,
        port: int = 0,
        log: Callable[[str], None] = stderr_log,
        quiet: bool = False,
        url_file: Optional[str] = None,
    ) -> None:
        self.request = request
        self.transport = transport
        self.port = port
        self.log = log
        self.url_file = url_file
        self.session = Session(
            request,
            deliver,
            identify=transport.identify,
            log=(lambda line: None) if quiet else log,
        )
        self.server = None
        self._stopped = False
        self._lock = threading.Lock()

    def _bind(self):
        if self.port:
            if not self.transport.port_available(self.port):
                raise TransportError(f"port {self.port} is already in use by the transport")
            return make_server(self.session, self.transport.bind_host, self.port)
        for _ in range(20):
            srv = make_server(self.session, self.transport.bind_host, 0)
            if self.transport.port_available(srv.server_address[1]):
                return srv
            srv.server_close()
        raise TransportError("could not find a free port")

    def start(self) -> str:
        self.server = self._bind()
        port = self.server.server_address[1]
        try:
            origin = self.transport.start(port)
        except BaseException:
            self.server.server_close()
            self.server = None
            raise
        self.session.public_origin = origin
        self.session.restart_clock()
        serve_in_background(self.server)
        url = self.session.url
        r = self.request
        self.log(f'waiting for "{r.label}"  (match code {self.session.match}, expires in {format_duration(r.timeout)})')
        audience = self.transport.audience()
        if audience:
            self.log(audience)
        self.log(f"open: {url}")
        if self.url_file:
            atomic_write(self.url_file, (url + "\n").encode())
        return url

    def wait(self) -> bool:
        """Block until a value was delivered (True) or the session expired (False)."""
        s = self.session
        while not s.finished.wait(0.2):
            if s.expired() or s.closed:
                return s.finished.is_set()
        return True

    def stop(self) -> None:
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
        self.session.close()
        try:
            self.transport.stop()
        finally:
            if self.server is not None:
                self.server.shutdown()
                self.server.server_close()
