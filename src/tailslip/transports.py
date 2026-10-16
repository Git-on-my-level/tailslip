"""Transports decide where the page is reachable and who may use it.

A transport has four jobs:

* ``bind_host``       which local address the HTTP server binds
* ``start(port)``     make the page reachable; return the public origin
* ``identify(hdrs)``  accept or reject the requester (beyond the URL token)
* ``stop()``          undo whatever ``start`` did (idempotent)

Built in:

* ``tailscale``  bind 127.0.0.1, publish with ``tailscale serve`` (HTTPS, tailnet
  only), require the ``Tailscale-User-Login`` header that serve injects to be on
  an allowlist (default: the node owner). Recommended.
* ``local``      bind 127.0.0.1 only. Reach it from this machine or through an SSH
  tunnel (``ssh -L``). The URL token is the only credential.
* ``lan``        bind a LAN address over plain HTTP. The URL token is the only
  credential, and the value crosses the network unencrypted. Use only on a
  network you trust.

``tailscale funnel`` is deliberately not offered: funnel exposes the page to the
public internet, and funnel requests carry no identity headers, so the identity
guard could not work.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from typing import Callable, Iterable, List, Optional, Sequence

from .server import Identity

Runner = Callable[[Sequence[str], float], "subprocess.CompletedProcess[str]"]


class TransportError(RuntimeError):
    pass


def _run(argv: Sequence[str], timeout: float) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        list(argv), capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL
    )


class Transport:
    name = "base"
    bind_host = "127.0.0.1"

    def start(self, port: int) -> str:
        raise NotImplementedError

    def stop(self) -> None:
        pass

    def identify(self, headers) -> Identity:
        return Identity(True, "-")

    def audience(self) -> str:
        """Human description of who can open the page."""
        return ""

    def port_available(self, port: int) -> bool:
        return True


class LocalTransport(Transport):
    name = "local"

    def __init__(self, bind_host: str = "127.0.0.1") -> None:
        self.bind_host = bind_host
        self.port = 0

    def start(self, port: int) -> str:
        self.port = port
        host = f"[{self.bind_host}]" if ":" in self.bind_host else self.bind_host
        return f"http://{host}:{port}"

    def audience(self) -> str:
        return (
            "reachable from this machine only; from elsewhere, tunnel it: "
            f"ssh -L {self.port}:127.0.0.1:{self.port} <this-host>"
        )


class LanTransport(Transport):
    name = "lan"

    def __init__(self, bind_host: str = "0.0.0.0", public_host: Optional[str] = None) -> None:
        self.bind_host = bind_host
        self.public_host = public_host

    def start(self, port: int) -> str:
        host = self.public_host or (self.bind_host if self.bind_host not in ("0.0.0.0", "::") else guess_lan_ip())
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"http://{host}:{port}"

    def audience(self) -> str:
        return (
            "WARNING: plain HTTP on your local network. Anyone who can see the URL can "
            "submit, and anyone on the network path can read the value in transit."
        )


def guess_lan_ip() -> str:
    """Primary outbound IPv4 address. Connecting a UDP socket sends no packets."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def find_tailscale(explicit: Optional[str] = None) -> Optional[str]:
    for cand in (explicit, os.environ.get("TAILSLIP_TAILSCALE")):
        if cand:
            return cand
    found = shutil.which("tailscale")
    if found:
        return found
    mac = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
    return mac if os.path.exists(mac) else None


class TailscaleStatus:
    def __init__(self, raw: dict) -> None:
        self.raw = raw
        self.backend_state = raw.get("BackendState", "")
        me = raw.get("Self") or {}
        self.dns_name = (me.get("DNSName") or "").rstrip(".")
        self.host_name = me.get("HostName") or ""
        self.tags = list(me.get("Tags") or [])
        uid = me.get("UserID")
        user = (raw.get("User") or {}).get(str(uid)) or {}
        login = user.get("LoginName") or ""
        # a tagged node has no human owner; its "user" is a placeholder
        self.owner_login = "" if self.tags or login == "tagged-devices" else login

    @property
    def running(self) -> bool:
        return self.backend_state == "Running" and bool(self.dns_name)


class TailscaleTransport(Transport):
    name = "tailscale"
    bind_host = "127.0.0.1"

    def __init__(
        self,
        allow: Iterable[str] = (),
        allow_any: bool = False,
        binary: Optional[str] = None,
        runner: Runner = _run,
        status: Optional[TailscaleStatus] = None,
    ) -> None:
        self.binary = find_tailscale(binary)
        self.runner = runner
        self._status = status
        self.allow_any = allow_any
        self.allow: List[str] = [a.strip().lower() for a in allow if a.strip()]
        self.port: Optional[int] = None
        self._served = False

    # -- tailscale CLI ------------------------------------------------------------------
    def _ts(self, *args: str, timeout: float = 20.0) -> "subprocess.CompletedProcess[str]":
        if not self.binary:
            raise TransportError("tailscale CLI not found (install Tailscale or pass --tailscale-bin)")
        try:
            return self.runner([self.binary, *args], timeout)
        except subprocess.TimeoutExpired:
            raise TransportError(
                f"`tailscale {' '.join(args)}` timed out; if it printed a link to enable "
                "HTTPS/Serve for your tailnet, enable it in the admin console and retry"
            )
        except OSError as exc:
            raise TransportError(f"cannot run tailscale: {exc}")

    def status(self) -> TailscaleStatus:
        if self._status is None:
            cp = self._ts("status", "--self", "--peers=false", "--json")
            if cp.returncode != 0:
                raise TransportError(f"`tailscale status` failed: {cp.stderr.strip() or cp.stdout.strip()}")
            try:
                self._status = TailscaleStatus(json.loads(cp.stdout))
            except ValueError:
                raise TransportError("could not parse `tailscale status --json`")
        return self._status

    def serve_ports_in_use(self) -> set:
        cp = self._ts("serve", "status", "--json")
        if cp.returncode != 0 or not cp.stdout.strip():
            return set()
        try:
            data = json.loads(cp.stdout)
        except ValueError:
            return set()
        return {int(p) for p in (data.get("TCP") or {}).keys() if str(p).isdigit()}

    # -- Transport API ----------------------------------------------------------------------
    def prepare(self) -> None:
        st = self.status()
        if not st.running:
            raise TransportError(f"tailscale is not running (state: {st.backend_state or 'unknown'})")
        if not self.allow and not self.allow_any:
            if not st.owner_login:
                raise TransportError(
                    "this node is tagged and has no owner login; pass --allow LOGIN "
                    "(or --allow-any-tailnet-user)"
                )
            self.allow = [st.owner_login.lower()]

    def port_available(self, port: int) -> bool:
        return port not in self.serve_ports_in_use()

    def start(self, port: int) -> str:
        self.prepare()
        if not self.port_available(port):
            raise TransportError(f"tailscale serve already has a handler on port {port}; not touching it")
        cp = self._ts("serve", "--bg", "--yes", f"--https={port}", f"http://127.0.0.1:{port}")
        if cp.returncode != 0 and "not defined" in (cp.stderr or "") and "yes" in (cp.stderr or ""):
            # older CLIs without --yes
            cp = self._ts("serve", "--bg", f"--https={port}", f"http://127.0.0.1:{port}")
        if cp.returncode != 0:
            raise TransportError(f"`tailscale serve` failed: {(cp.stderr or cp.stdout).strip()}")
        self.port = port
        self._served = True
        return f"https://{self.status().dns_name}:{port}"

    def stop(self) -> None:
        if self._served and self.port is not None:
            self._served = False
            try:
                self._ts("serve", f"--https={self.port}", "off", timeout=15.0)
            except TransportError:
                pass

    def identify(self, headers) -> Identity:
        who = (headers.get("Tailscale-User-Login") or "").strip()
        if not who:
            # requests that did not come through `tailscale serve` from a user-owned
            # node (e.g. tagged nodes, or someone hitting 127.0.0.1 directly)
            return Identity(False, "-")
        if self.allow_any or who.lower() in self.allow:
            return Identity(True, who)
        return Identity(False, who)

    def audience(self) -> str:
        if self.allow_any:
            return "any signed-in tailnet user can submit"
        return "only " + ", ".join(self.allow) + " can submit"


def detect_tailscale(binary: Optional[str] = None) -> Optional[TailscaleStatus]:
    t = TailscaleTransport(binary=binary)
    if not t.binary:
        return None
    try:
        st = t.status()
    except TransportError:
        return None
    return st if st.running else None
