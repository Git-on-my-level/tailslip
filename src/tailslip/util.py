"""Small helpers: durations, atomic 0600 writes, match codes, output redaction."""

from __future__ import annotations

import os
import re
import secrets
import tempfile

_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(ms|s|m|h)?")
_UNIT = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, None: 1.0}


def parse_duration(text: str) -> float:
    """Parse '90', '90s', '15m', '1h30m', '500ms' into seconds."""
    s = str(text).strip().lower()
    if not s:
        raise ValueError("empty duration")
    pos = 0
    total = 0.0
    for m in _DURATION_PART.finditer(s):
        if m.start() != pos:
            raise ValueError(f"invalid duration: {text!r}")
        total += float(m.group(1)) * _UNIT[m.group(2)]
        pos = m.end()
    if pos != len(s):
        raise ValueError(f"invalid duration: {text!r}")
    if total <= 0:
        raise ValueError("duration must be positive")
    return total


def format_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m" if s == 0 else f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h" if m == 0 else f"{h}h{m:02d}m"


def atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically with permissions ``mode``.

    The temp file is created 0600 in the destination directory (so the rename is
    atomic and the content is never world-readable, even briefly), fsynced, then
    renamed over the target. A pre-existing symlink at ``path`` is replaced, not
    followed.
    """
    path = os.path.abspath(path)
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tailslip-", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:  # best effort: persist the rename
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


_MATCH_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I/L


def match_code(length: int = 4) -> str:
    """Short code shown both in the terminal and on the page, so the human can
    confirm the page belongs to the process that asked."""
    return "".join(secrets.choice(_MATCH_ALPHABET) for _ in range(length))


class Redactor:
    """Streaming filter that replaces a secret with ``[redacted]`` in output,
    including occurrences split across chunk boundaries."""

    MARK = b"[redacted]"

    def __init__(self) -> None:
        self._secret = b""
        self._held = b""

    def set_secret(self, secret: bytes) -> None:
        self._secret = secret if len(secret) >= 2 else b""

    def feed(self, chunk: bytes) -> bytes:
        if not self._secret:
            out, self._held = self._held + chunk, b""
            return out
        buf = (self._held + chunk).replace(self._secret, self.MARK)
        keep = len(self._secret) - 1
        # hold back a tail that could be the start of a split secret
        tail_start = len(buf)
        for k in range(min(keep, len(buf)), 0, -1):
            if self._secret.startswith(buf[-k:]):
                tail_start = len(buf) - k
                break
        self._held = buf[tail_start:]
        return buf[:tail_start]

    def flush(self) -> bytes:
        out, self._held = self._held, b""
        return out


_ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")


def strip_ansi(data: bytes) -> bytes:
    return _ANSI.sub(b"", data)
