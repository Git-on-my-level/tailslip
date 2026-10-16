"""``tailslip exec``: run a command and feed it the received value.

Modes:

* ``pty`` (default): the command runs on a pseudo-terminal that tailslip owns, so
  programs that insist on a TTY prompt (``gcloud auth login --no-launch-browser``,
  ``ssh-keygen``, interactive installers) can be answered. Terminal echo is turned
  off and the value is scrubbed from the forwarded output as a second line of
  defence.
* ``stdin``: the value is written to the command's stdin, then stdin is closed.
* ``env``: tailslip waits for the value first, then runs the command with the
  value in one environment variable (visible to the same user via the process
  table on some systems; prefer pty/stdin for high-value secrets).

The command's output is forwarded to tailslip's stdout. With ``--url-regex``, the
first match in that output becomes the button on the page (for example the OAuth
URL a CLI prints). With ``--wait-for``, the value is only typed after that regex
appears (for example the prompt text).
"""

from __future__ import annotations

import os
import queue
import re
import select
import signal
import subprocess
import sys
import time
from typing import List, Optional

from .runtime import Handoff
from .server import Request, Value
from .transports import Transport
from .util import Redactor, strip_ansi

SCAN_WINDOW = 64 * 1024


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except InterruptedError:
            continue
        except BlockingIOError:
            select.select([], [fd], [], 1.0)
            continue
        view = view[n:]


def _spawn_pty(cmd: List[str], env: dict):
    import pty  # Unix only
    import termios

    pid, fd = pty.fork()
    if pid == 0:  # child
        try:
            attrs = termios.tcgetattr(0)
            attrs[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(0, termios.TCSANOW, attrs)
            try:
                import fcntl
                import struct

                # wide terminal so programs don't wrap long URLs themselves
                fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 1000, 0, 0))
            except (OSError, ImportError):
                pass
        except Exception:
            pass
        try:
            os.execvpe(cmd[0], cmd, env)
        except OSError as exc:
            os.write(2, f"tailslip: cannot run {cmd[0]}: {exc.strerror}\n".encode())
        os._exit(127)
    return pid, fd


def _kill(pid: int) -> None:
    for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 2.0)):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return
        end = time.monotonic() + wait
        while time.monotonic() < end:
            try:
                done, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                return
            if done:
                return
            time.sleep(0.05)


def run_exec(
    cmd: List[str],
    request: Request,
    transport: Transport,
    *,
    mode: str = "pty",
    env_name: Optional[str] = None,
    url_regex: Optional[str] = None,
    wait_for: Optional[str] = None,
    newline: bool = True,
    delay: float = 0.3,
    port: int = 0,
    quiet: bool = False,
    url_file: Optional[str] = None,
    log=None,
    out=None,
) -> int:
    out = out or sys.stdout.buffer
    env = dict(os.environ)
    pending: "queue.Queue[Value]" = queue.Queue()

    if mode == "env":
        return _run_env(cmd, request, transport, env, env_name or "TAILSLIP_VALUE", port, quiet, url_file, log)

    url_re = re.compile(url_regex.encode()) if url_regex else None
    wait_re = re.compile(wait_for.encode()) if wait_for else None
    request.wait_for_link = bool(url_re) and not request.link

    # spawn BEFORE the HTTP server starts threads (fork + threads do not mix)
    proc = None
    if mode == "pty":
        pid, out_fd = _spawn_pty(cmd, env)
        in_fd = out_fd
    elif mode == "stdin":
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        except OSError as exc:
            (log or (lambda s: None))(f"cannot run {cmd[0]}: {exc.strerror}")
            return 127
        pid, out_fd, in_fd = proc.pid, proc.stdout.fileno(), proc.stdin.fileno()
    else:
        raise ValueError(f"unknown mode {mode}")

    kwargs = {"port": port, "quiet": quiet, "url_file": url_file}
    if log:
        kwargs["log"] = log
    h = Handoff(request, transport, pending.put, **kwargs)
    log = h.log
    try:
        h.start()
    except BaseException:
        _kill(pid)
        raise

    redactor = Redactor()
    scan = b""
    link_found = url_re is None or request.link is not None
    prompt_seen = wait_re is None
    value: Optional[Value] = None
    injected = False
    eof = False
    rc: Optional[int] = None
    try:
        while True:
            if not injected and h.session.expired():
                log("timed out waiting for a value; stopping the command")
                h.stop()
                _kill(pid)
                return 3
            if h.session.finished.is_set():
                h.stop()  # single use: take the page down as soon as it delivered
            if not eof:
                r, _, _ = select.select([out_fd], [], [], 0.1)
                if r:
                    try:
                        chunk = os.read(out_fd, 65536)
                    except OSError:  # EIO: pty closed after the child exited
                        chunk = b""
                    if not chunk:
                        eof = True
                    else:
                        out.write(redactor.feed(chunk))
                        out.flush()
                        scan = (scan + chunk)[-SCAN_WINDOW:]
                        clean = strip_ansi(scan)
                        if url_re and not link_found:
                            m = url_re.search(clean)
                            if m:
                                try:
                                    h.session.set_link(m.group(0).decode("utf-8", "replace"))
                                    link_found = True
                                    log("captured link from command output; it is now on the page")
                                except ValueError:
                                    pass
                        if wait_re and not prompt_seen and wait_re.search(clean):
                            prompt_seen = True
            else:
                time.sleep(0.05)

            if value is None:
                try:
                    value = pending.get_nowait()
                    redactor.set_secret(value.data)
                except queue.Empty:
                    pass

            if value is not None and not injected and link_found and prompt_seen and not eof:
                time.sleep(delay)  # let the prompt finish drawing
                payload = value.data
                if newline and not payload.endswith(b"\n"):
                    payload += b"\n"
                try:
                    _write_all(in_fd, payload)
                except OSError as exc:
                    log(f"could not write to the command: {exc.strerror}")
                if mode == "stdin":
                    proc.stdin.close()
                injected = True
                value = None  # drop our reference; the redactor keeps the bytes it needs
                log("value sent to the command")

            if rc is None:
                if proc is not None:
                    rc = proc.poll()
                else:
                    try:
                        done, status = os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        done, status = pid, 0
                    if done:
                        rc = os.waitstatus_to_exitcode(status)
            if rc is not None and eof:
                break
            if rc is not None and not eof:
                # child gone: drain what is left, then stop
                r, _, _ = select.select([out_fd], [], [], 0.2)
                if not r:
                    break
    except KeyboardInterrupt:
        _kill(pid)
        raise
    finally:
        out.write(redactor.flush())
        out.flush()
        h.stop()
    if rc is None:
        rc = proc.wait() if proc is not None else os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    if not injected:
        log("the command exited before a value was sent")
    return rc


def _run_env(cmd, request, transport, env, env_name, port, quiet, url_file, log) -> int:
    pending: "queue.Queue[Value]" = queue.Queue()
    kwargs = {"port": port, "quiet": quiet, "url_file": url_file}
    if log:
        kwargs["log"] = log
    h = Handoff(request, transport, pending.put, **kwargs)
    h.start()
    try:
        if not h.wait():
            h.log("timed out waiting for a value")
            return 3
    finally:
        h.stop()
    value = pending.get_nowait()
    try:
        env[env_name] = value.data.decode("utf-8")
    except UnicodeDecodeError:
        h.log("value is not UTF-8 text; cannot pass it in an environment variable")
        return 1
    del value
    try:
        return subprocess.call(cmd, env=env)
    except OSError as exc:
        h.log(f"cannot run {cmd[0]}: {exc.strerror}")
        return 127
