"""Command-line interface. Status goes to stderr; stdout carries only the value
(``receive``) or the command's output (``exec``)."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import signal
import socket
import sys
from typing import List, Optional

from . import __version__
from .runtime import Handoff, stderr_log
from .server import KINDS, Request, Value, validate_link
from .transports import (
    LanTransport,
    LocalTransport,
    TailscaleTransport,
    Transport,
    TransportError,
    detect_tailscale,
    find_tailscale,
)
from .util import atomic_write, parse_duration

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_TIMEOUT = 0, 1, 2, 3


def _size(text: str) -> int:
    t = text.strip().upper().rstrip("B")
    mult = 1
    if t and t[-1] in "KMG":
        mult = {"K": 1024, "M": 1024**2, "G": 1024**3}[t[-1]]
        t = t[:-1]
    try:
        n = int(float(t) * mult)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid size: {text!r}")
    if n <= 0:
        raise argparse.ArgumentTypeError("size must be positive")
    return n


def _duration(text: str) -> float:
    try:
        return parse_duration(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def _link(text: str) -> str:
    try:
        return validate_link(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def _common() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("what to ask for")
    g.add_argument("--label", default=None, help="page title, e.g. 'GitHub one-time code'")
    g.add_argument("--prompt", default="", help="one or two sentences of instructions shown under the title")
    g.add_argument("--link", type=_link, help="URL for an optional action button (e.g. a sign-in page)")
    g.add_argument("--link-text", default="Open link", help="text of the action button")
    g.add_argument("--kind", choices=KINDS, default="line",
                   help="line (default), secret (masked, with reveal toggle), text (multi-line), file (upload)")
    g.add_argument("--secret", dest="kind", action="store_const", const="secret", help="same as --kind secret")
    g.add_argument("--text", dest="kind", action="store_const", const="text", help="same as --kind text")
    g.add_argument("--file", dest="kind", action="store_const", const="file", help="same as --kind file")
    g.add_argument("--pattern", help="regex the value must fully match, e.g. '[0-9]{6}'")
    g.add_argument("--max-bytes", type=_size, help="size limit (default 4K line/secret, 256K text, 16M file)")
    g.add_argument("--submit-text", help="text of the submit button (default 'Send')")
    g.add_argument("--from", dest="requester", help="who is asking, shown on the page (default: this host)")
    g.add_argument("--timeout", type=_duration, default=parse_duration("15m"),
                   help="give up after this long, e.g. 90s, 15m, 1h (default 15m)")

    t = p.add_argument_group("transport")
    t.add_argument("--transport", choices=("auto", "tailscale", "local", "lan"), default="auto",
                   help="auto (tailscale if running, else local), tailscale, local, lan")
    t.add_argument("--allow", action="append", default=[], metavar="LOGIN",
                   help="tailnet login allowed to submit; repeatable (default: this node's owner)")
    t.add_argument("--allow-any-tailnet-user", action="store_true",
                   help="accept any signed-in tailnet user instead of an allowlist")
    t.add_argument("--port", type=int, default=0, help="port to use (default: a free random port)")
    t.add_argument("--bind", help="bind address (local: 127.0.0.1; lan: 0.0.0.0)")
    t.add_argument("--public-host", help="lan: host or IP to put in the URL (default: detected)")
    t.add_argument("--tailscale-bin", help="path to the tailscale CLI")

    o = p.add_argument_group("output")
    o.add_argument("--url-file", help="also write the page URL to this file (0600)")
    o.add_argument("-q", "--quiet", action="store_true", help="don't log page requests")
    return p


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tailslip",
        description="Hand a value (code, token, passphrase, text, file) from a human on a web page "
        "to a waiting process, over your tailnet.",
    )
    p.add_argument("--version", action="version", version=f"tailslip {__version__}")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True
    common = _common()

    r = sub.add_parser("receive", parents=[common], help="wait for a value; print it or write it to a file",
                       description="Serve a one-time page, wait for a value, then write it to stdout or --out.")
    r.add_argument("-o", "--out", help="write the value to this file (atomic, mode 0600) instead of stdout")

    e = sub.add_parser("exec", parents=[common], help="run a command and type the value into it",
                       description="Run COMMAND, optionally show a URL from its output on the page, "
                       "and feed it the received value.",
                       usage="tailslip exec [options] -- COMMAND [ARGS...]")
    m = e.add_argument_group("exec")
    m.add_argument("--url-regex", help="regex; first match in the command output becomes the page's action button")
    m.add_argument("--wait-for", help="regex; type the value only after this appears in the output (e.g. a prompt)")
    mode = m.add_mutually_exclusive_group()
    mode.add_argument("--stdin", dest="mode", action="store_const", const="stdin",
                      help="write the value to the command's stdin instead of a pty")
    mode.add_argument("--env", dest="env_name", metavar="NAME",
                      help="wait for the value, then run the command with it in env var NAME")
    m.add_argument("--no-newline", action="store_true", help="don't append a newline after the value")
    m.add_argument("--delay", type=float, default=0.3, help="seconds to wait before typing (default 0.3)")
    e.add_argument("cmd", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)

    sub.add_parser("doctor", help="show what tailslip can detect about this machine")
    return p


def _host() -> str:
    return socket.gethostname().split(".")[0] or "this host"


def make_transport(args, log=stderr_log) -> Transport:
    kind = args.transport
    if args.allow and args.allow_any_tailnet_user:
        raise TransportError("use either --allow or --allow-any-tailnet-user, not both")
    if kind == "auto":
        kind = "tailscale" if detect_tailscale(args.tailscale_bin) else "local"
        if kind == "local":
            log("tailscale is not running here; serving on 127.0.0.1 only (see --transport)")
    if kind != "tailscale" and (args.allow or args.allow_any_tailnet_user):
        raise TransportError("--allow/--allow-any-tailnet-user only apply to --transport tailscale")
    if kind == "tailscale":
        if args.bind:
            raise TransportError("--bind is not used with tailscale (it always binds 127.0.0.1)")
        return TailscaleTransport(allow=args.allow, allow_any=args.allow_any_tailnet_user, binary=args.tailscale_bin)
    if kind == "local":
        bind = args.bind or "127.0.0.1"
        try:
            loopback = ipaddress.ip_address(bind).is_loopback
        except ValueError:
            loopback = bind == "localhost"
        if not loopback:
            raise TransportError("--transport local only binds loopback; use --transport lan to expose it")
        return LocalTransport(bind)
    return LanTransport(args.bind or "0.0.0.0", args.public_host)


def make_request(args, default_label: str, requester: str) -> Request:
    return Request(
        label=args.label or default_label,
        prompt=args.prompt,
        kind=args.kind,
        link=args.link,
        link_text=args.link_text,
        pattern=args.pattern,
        max_bytes=args.max_bytes,
        requester=args.requester or requester,
        timeout=args.timeout,
        submit_text=args.submit_text,
    )


def _deliver_to(out: Optional[str]):
    def to_file(v: Value) -> None:
        atomic_write(out, v.data)

    def to_stdout(v: Value) -> None:
        buf = sys.stdout.buffer
        buf.write(v.data)
        if sys.stdout.isatty() and not v.data.endswith(b"\n"):
            buf.write(b"\n")
        buf.flush()

    return to_file if out else to_stdout


def cmd_receive(args) -> int:
    if args.out:
        d = os.path.dirname(os.path.abspath(args.out))
        if not os.path.isdir(d):
            stderr_log(f"output directory does not exist: {d}")
            return EXIT_USAGE
    transport = make_transport(args)
    request = make_request(args, "A value is requested", _host())
    h = Handoff(request, transport, _deliver_to(args.out), port=args.port, quiet=args.quiet, url_file=args.url_file)
    h.start()
    try:
        ok = h.wait()
    finally:
        h.stop()
    if not ok:
        stderr_log("timed out; nothing was received")
        return EXIT_TIMEOUT
    if args.out:
        stderr_log(f"received; wrote {args.out} (mode 0600)")
    else:
        stderr_log("received")
    return EXIT_OK


def cmd_exec(args) -> int:
    from .execmode import run_exec

    cmd: List[str] = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        stderr_log("exec needs a command: tailslip exec [options] -- COMMAND [ARGS...]")
        return EXIT_USAGE
    mode = "env" if args.env_name else (args.mode or "pty")
    if mode == "env" and args.url_regex:
        stderr_log("--url-regex needs the command running first; it cannot be combined with --env")
        return EXIT_USAGE
    if mode == "pty" and os.name != "posix":
        stderr_log("pty mode needs a POSIX system; use --stdin or --env")
        return EXIT_USAGE
    transport = make_transport(args)
    request = make_request(args, "A value is requested", f"{os.path.basename(cmd[0])} on {_host()}")
    newline = not args.no_newline and args.kind in ("line", "secret")
    return run_exec(
        cmd, request, transport, mode=mode, env_name=args.env_name, url_regex=args.url_regex,
        wait_for=args.wait_for, newline=newline, delay=args.delay, port=args.port,
        quiet=args.quiet, url_file=args.url_file,
    )


def cmd_doctor(args) -> int:
    print(f"tailslip {__version__}  python {sys.version.split()[0]}  {sys.platform}")
    binary = find_tailscale(getattr(args, "tailscale_bin", None))
    print(f"tailscale cli : {binary or 'not found'}")
    if not binary:
        print("transport     : local (install Tailscale for tailnet hand-offs)")
        return EXIT_OK
    t = TailscaleTransport(binary=binary)
    try:
        st = t.status()
    except TransportError as exc:
        print(f"tailscale     : {exc}")
        print("transport     : local")
        return EXIT_OK
    print(f"backend state : {st.backend_state}")
    print(f"dns name      : {st.dns_name or '-'}")
    print(f"node owner    : {st.owner_login or ('(tagged node: ' + ', '.join(st.tags) + ')' if st.tags else '-')}")
    try:
        ports = sorted(t.serve_ports_in_use())
    except TransportError:
        ports = []
    print(f"serve ports   : {', '.join(map(str, ports)) or 'none'} (tailslip never touches these)")
    print(f"transport     : {'tailscale' if st.running else 'local'} (auto)")
    return EXIT_OK


def _on_signal(signum, frame):
    raise SystemExit(128 + signum)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for sig in (signal.SIGTERM, getattr(signal, "SIGHUP", None)):
        if sig is not None:
            try:
                signal.signal(sig, _on_signal)
            except (ValueError, OSError):  # not main thread / unsupported
                pass
    try:
        if args.command == "receive":
            return cmd_receive(args)
        if args.command == "exec":
            return cmd_exec(args)
        return cmd_doctor(args)
    except TransportError as exc:
        stderr_log(f"error: {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        stderr_log("interrupted")
        return 130
    except re.error as exc:
        stderr_log(f"error: bad regular expression: {exc}")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
