"""The one-shot HTTP endpoint.

Request handling order, for every request:

1. path must be ``/<token>/`` or ``/<token>/submit`` (constant-time compare), else 404
2. the transport must accept the requester's identity (tailnet login), else 403
3. the session must still be open (not used, not expired), else 410
4. POST only: Content-Length present (411) and within the limit (413), the
   request must be same-origin (Origin / Sec-Fetch-Site) and carry the page's
   CSRF token (403), and the value must validate (400)
5. the value is delivered synchronously; only then is the session marked used

Values are never logged, echoed back, put in URLs, or kept after delivery.
"""

from __future__ import annotations

import hmac
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional
from urllib.parse import parse_qs, urlsplit

from . import page
from .util import match_code

KINDS = ("line", "secret", "text", "file")
DEFAULT_MAX_BYTES = {"line": 4096, "secret": 4096, "text": 256 * 1024, "file": 16 * 1024 * 1024}


@dataclass
class Request:
    """What is being asked for. Pure presentation + validation settings."""

    label: str = "A value is requested"
    prompt: str = ""
    kind: str = "line"
    link: Optional[str] = None
    link_text: str = "Open link"
    pattern: Optional[str] = None
    max_bytes: Optional[int] = None
    requester: str = ""
    timeout: float = 900.0
    submit_text: Optional[str] = None
    wait_for_link: bool = False  # exec mode: show a "waiting" page until set_link()


class Value:
    """A received value. Its repr never shows the content."""

    __slots__ = ("data", "filename")

    def __init__(self, data: bytes, filename: Optional[str] = None) -> None:
        self.data = data
        self.filename = filename

    def __repr__(self) -> str:
        return f"<Value {len(self.data)} bytes, redacted>"


class Identity:
    """Result of a transport identity check."""

    __slots__ = ("ok", "who")

    def __init__(self, ok: bool, who: str = "-") -> None:
        self.ok = ok
        self.who = who


def validate_link(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("link must be an absolute http(s) URL")
    return url


class Session:
    def __init__(
        self,
        request: Request,
        deliver: Callable[[Value], None],
        identify: Callable[[object], Identity] = lambda headers: Identity(True),
        log: Callable[[str], None] = lambda line: None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if request.kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        self.request = request
        self.deliver = deliver
        self.identify = identify
        self.log = log
        self.clock = clock
        self.token = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.match = match_code()
        self.base = f"/{self.token}/"
        self.max_bytes = request.max_bytes or DEFAULT_MAX_BYTES[request.kind]
        self.pattern = re.compile(request.pattern) if request.pattern else None
        self.deadline = clock() + request.timeout
        self.public_origin: Optional[str] = None
        self._link = validate_link(request.link) if request.link else None
        self._lock = threading.Lock()
        self.used = False
        self.closed = False
        self.finished = threading.Event()  # set after the success response is written

    # -- state ----------------------------------------------------------------------
    @property
    def link(self) -> Optional[str]:
        return self._link

    def set_link(self, url: str) -> None:
        self._link = validate_link(url)

    def remaining(self) -> float:
        return max(0.0, self.deadline - self.clock())

    def expired(self) -> bool:
        return self.clock() >= self.deadline

    def close(self) -> None:
        self.closed = True

    @property
    def url(self) -> str:
        return (self.public_origin or "") + self.base

    def check_token(self, candidate: str) -> bool:
        return hmac.compare_digest(candidate.encode("utf-8", "surrogateescape"), self.token.encode())

    def check_csrf(self, candidate: str) -> bool:
        return hmac.compare_digest(candidate.encode("utf-8", "surrogateescape"), self.csrf.encode())


class _Reject(Exception):
    def __init__(self, status: int, state: str, detail: Optional[str] = None, form_error: Optional[str] = None):
        super().__init__(state)
        self.status = status
        self.state = state
        self.detail = detail
        self.form_error = form_error


def _default_port(scheme: str) -> str:
    return {"http": "80", "https": "443"}.get(scheme, "")


def _norm_origin(origin: str) -> Optional[tuple]:
    p = urlsplit(origin.strip())
    if not p.scheme or not p.hostname:
        return None
    port = str(p.port) if p.port else _default_port(p.scheme)
    return (p.scheme.lower(), p.hostname.lower(), port)


class Handler(BaseHTTPRequestHandler):
    session: Session  # set on the subclass made by make_server
    server_version = "tailslip"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30  # per-connection socket timeout (slow-client guard)

    # never let http.server write request lines (which contain the token) anywhere
    def log_message(self, format, *args):  # noqa: A002
        pass

    # -- plumbing ---------------------------------------------------------------------
    def _send(self, status: int, body: str, nonce: str, extra: Optional[dict] = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        # same-origin (not no-referrer): browsers send `Origin: null` on POSTs from a
        # no-referrer page, which would defeat the Origin check. Cross-origin requests,
        # including the external sign-in link, still get no Referer at all.
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            f"default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; "
            "img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _state(self, status: int, state: str, detail: Optional[str] = None) -> None:
        nonce = secrets.token_urlsafe(16)
        requester = self.session.request.requester if state not in ("notfound",) else None
        self._send(status, page.render_state(state, nonce=nonce, requester=requester, detail=detail), nonce)

    def _form(self, status: int = 200, error: Optional[str] = None) -> None:
        s, r = self.session, self.session.request
        nonce = secrets.token_urlsafe(16)
        if r.wait_for_link and not s.link:
            body = page.render_waiting(
                nonce=nonce, label=r.label, requester=r.requester, match=s.match, remaining=s.remaining()
            )
        else:
            body = page.render_form(
                nonce=nonce,
                action=s.base + "submit",
                csrf=s.csrf,
                label=r.label,
                prompt=r.prompt,
                kind=r.kind,
                requester=r.requester,
                match=s.match,
                remaining=s.remaining(),
                link=s.link,
                link_text=r.link_text,
                pattern=r.pattern,
                submit_text=r.submit_text,
                max_bytes=s.max_bytes,
                error=error,
            )
        self._send(status, body, nonce)

    def _route(self) -> tuple:
        """Return (sub-path, identity) or raise _Reject."""
        self._who = "-"  # handlers are reused across keep-alive requests
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        segs = path.split("/")
        if len(segs) < 2 or not self.session.check_token(segs[1]):
            raise _Reject(404, "notfound")
        sub = "/".join(segs[2:])
        if sub not in ("", "submit"):
            raise _Reject(404, "notfound")
        ident = self.session.identify(self.headers)
        self._who = ident.who
        if not ident.ok:
            raise _Reject(403, "forbidden")
        return sub, ident

    def _open_or_reject(self) -> None:
        s = self.session
        if s.used:
            raise _Reject(410, "used")
        if s.closed or s.expired():
            raise _Reject(410, "expired")

    def _log(self, status: int, who: str = "-") -> None:
        # path is deliberately NOT logged: it contains the access token
        self.session.log(f"{self.command} {status} from {who}")

    # -- methods ------------------------------------------------------------------------
    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        who = "-"
        try:
            sub, ident = self._route()
            who = ident.who
            if sub != "":
                raise _Reject(404, "notfound")
            self._open_or_reject()
            self._form()
            self._log(200, who)
        except _Reject as rj:
            self._state(rj.status, rj.state, rj.detail)
            self._log(rj.status, getattr(self, "_who", who))

    def do_POST(self) -> None:
        who = "-"
        delivered = False
        self._body_consumed = False
        try:
            sub, ident = self._route()
            who = ident.who
            if sub != "submit":
                raise _Reject(404, "notfound")
            self._open_or_reject()
            if not self._same_origin():
                raise _Reject(403, "rejected")
            fields, filename = self._read_body()
            if not self.session.check_csrf(_first_text(fields.get("csrf"))):
                raise _Reject(403, "rejected")
            value = self._validate(fields, filename)
            with self.session._lock:
                self._open_or_reject()
                try:
                    self.session.deliver(value)
                except Exception as exc:  # do not consume the session on a host-side failure
                    self.session.log(f"delivery failed: {type(exc).__name__}")
                    raise _Reject(500, "failed")
                self.session.used = True
                delivered = True
            self.close_connection = True
            self._state(200, "done")
            self._log(200, who)
        except _Reject as rj:
            if not self._body_consumed:
                # an unread body would be parsed as the next request on this
                # keep-alive connection (reverse proxies reuse connections)
                self.close_connection = True
            if rj.form_error is not None:
                self._form(rj.status, error=rj.form_error)
            else:
                self._state(rj.status, rj.state, rj.detail)
            self._log(rj.status, getattr(self, "_who", who))
        finally:
            if delivered:
                self.session.finished.set()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    do_DELETE = do_PATCH = do_OPTIONS = do_PUT

    def _method_not_allowed(self) -> None:
        self.close_connection = True
        nonce = secrets.token_urlsafe(16)
        self._send(405, page.render_state("notfound", nonce=nonce), nonce, {"Allow": "GET, HEAD, POST"})

    # -- POST helpers -------------------------------------------------------------------------
    def _same_origin(self) -> bool:
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site is not None and fetch_site.strip().lower() not in ("same-origin", "none"):
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            # Non-browser clients (curl, scripts) send no Origin. CSRF is a browser
            # attack, and the path token + CSRF token are still required.
            return True
        if origin.strip().lower() == "null":
            return False
        o = _norm_origin(origin)
        if o is None:
            return False
        allowed = set()
        if self.session.public_origin:
            n = _norm_origin(self.session.public_origin)
            if n:
                allowed.add(n)
        host = self.headers.get("Host")
        if host:
            n = _norm_origin(f"{o[0]}://{host}")
            if n:
                allowed.add(n)
        return o in allowed

    def _read_body(self) -> tuple:
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise _Reject(411, "rejected", "Chunked uploads are not accepted.")
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            self.close_connection = True
            raise _Reject(411, "rejected", "Content-Length required.")
        try:
            length = int(raw_len)
        except ValueError:
            self.close_connection = True
            raise _Reject(400, "rejected")
        if length < 0:
            self.close_connection = True
            raise _Reject(400, "rejected")
        ctype = self.headers.get("Content-Type", "")
        # urlencoding can triple a value; multipart adds headers/boundaries
        limit = self.session.max_bytes * 3 + 8192
        if length > limit:
            self.close_connection = True  # don't read (or drain) an oversized body
            raise _Reject(413, "toolarge")
        body = self.rfile.read(length) if length else b""
        self._body_consumed = True
        if len(body) != length:
            self.close_connection = True
            raise _Reject(400, "rejected")
        mtype = ctype.split(";", 1)[0].strip().lower()
        if mtype == "application/x-www-form-urlencoded":
            try:
                qs = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=8)
            except (UnicodeDecodeError, ValueError):
                raise _Reject(400, "rejected")
            return {k: v[0] for k, v in qs.items()}, None
        if mtype == "multipart/form-data":
            return _parse_multipart(ctype, body)
        raise _Reject(415, "rejected", "Unsupported form encoding.")

    def _validate(self, fields: dict, filename: Optional[str]) -> Value:
        s, kind = self.session, self.session.request.kind
        if kind == "file":
            data = fields.get("file")
            if not isinstance(data, bytes) or filename is None:
                raise _Reject(400, "rejected", form_error="Choose a file to send.")
            if not data:
                raise _Reject(400, "rejected", form_error="That file is empty.")
            if len(data) > s.max_bytes:
                raise _Reject(413, "toolarge")
            return Value(data, filename)
        text = _first_text(fields.get("value"))
        if kind == "text":
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            if not text.strip():
                raise _Reject(400, "rejected", form_error="Nothing was entered.")
        else:
            text = text.strip()
            if not text:
                raise _Reject(400, "rejected", form_error="Nothing was entered.")
            if "\n" in text or "\r" in text:
                raise _Reject(400, "rejected", form_error="Enter a single line.")
        data = text.encode("utf-8")
        if len(data) > s.max_bytes:
            raise _Reject(413, "toolarge")
        if s.pattern is not None and not s.pattern.fullmatch(text):
            raise _Reject(400, "rejected", form_error="That doesn't match the expected format.")
        return Value(data)


def _first_text(v) -> str:
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    return v if isinstance(v, str) else ""


def _parse_multipart(ctype: str, body: bytes) -> tuple:
    m = Message()
    m["Content-Type"] = ctype
    boundary = m.get_param("boundary")
    if not isinstance(boundary, str) or not boundary or len(boundary) > 200:
        raise _Reject(400, "rejected")
    delim = b"--" + boundary.encode("latin-1")
    chunks = body.split(delim)
    if len(chunks) < 3 or len(chunks) > 10:
        raise _Reject(400, "rejected")
    fields: dict = {}
    filename: Optional[str] = None
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):
            break
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        head, sep, content = chunk.partition(b"\r\n\r\n")
        if not sep:
            raise _Reject(400, "rejected")
        if content.endswith(b"\r\n"):
            content = content[:-2]
        hm = Message()
        for line in head.decode("utf-8", "replace").split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                hm[k.strip()] = v.strip()
        name = hm.get_param("name", header="content-disposition")
        if not isinstance(name, str) or name in fields:
            continue
        fn = hm.get_param("filename", header="content-disposition")
        if name == "file" and isinstance(fn, str):
            filename = _safe_filename(fn)
        fields[name] = content
    return fields, filename


def _safe_filename(name: str) -> str:
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(c for c in name if c.isprintable() and c not in "\x7f")
    return name[:120] or "upload"


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, addr, handler, family):
        self.address_family = family
        super().__init__(addr, handler)


def make_server(session: Session, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    handler = type("BoundHandler", (Handler,), {"session": session})
    return _Server((host, port), handler, family)


def serve_in_background(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    t.start()
    return t
