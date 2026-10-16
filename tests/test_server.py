import threading
import time
import unittest
from urllib.parse import urlencode

from helpers import csrf_of, multipart, request, submit

from tailslip.runtime import Handoff
from tailslip.server import Identity, Request
from tailslip.transports import LocalTransport, TailscaleStatus, TailscaleTransport

SECRET = "hunter2-Sup3rS3cret-value"


class Recorder:
    def __init__(self):
        self.values = []
        self.logs = []

    def deliver(self, v):
        self.values.append(v)

    def log(self, line):
        self.logs.append(line)


class FakeIdentityTransport(LocalTransport):
    """Local transport that applies the Tailscale identity rule, without tailscale."""

    def __init__(self, allow):
        super().__init__()
        self._ts = TailscaleTransport(allow=allow, binary="/nonexistent")

    def identify(self, headers):
        return self._ts.identify(headers)


class Base(unittest.TestCase):
    def start(self, transport=None, **req):
        self.rec = Recorder()
        req.setdefault("timeout", 30)
        req.setdefault("label", "Test code")
        req.setdefault("requester", "unit-test")
        self.h = Handoff(Request(**req), transport or LocalTransport(), self.rec.deliver, log=self.rec.log)
        self.url = self.h.start()
        self.addCleanup(self.h.stop)
        return self.url


class TestRouting(Base):
    def test_page_renders_with_safe_headers(self):
        url = self.start(prompt="Type the code", link="https://example.com/auth?a=1&b=2", link_text="Sign in")
        status, headers, html = request(url)
        self.assertEqual(status, 200)
        self.assertIn("Test code", html)
        self.assertIn("unit-test", html)
        self.assertIn('href="https://example.com/auth?a=1&amp;b=2"', html)
        self.assertIn(self.h.session.match, html)
        self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(headers["Referrer-Policy"], "same-origin")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertNotIn("Python", headers.get("Server", ""))
        self.assertNotIn("http://", html.replace("http://www.w3.org", ""))  # no external assets

    def test_wrong_path_404(self):
        url = self.start()
        base = url.rsplit("/", 2)[0]
        for path in ("/", "/nope/", "/" + self.h.session.token[:-1] + "x/", "/favicon.ico", self.h.session.base + "x"):
            status, _, html = request(base + path)
            self.assertEqual(status, 404, path)
            self.assertNotIn(self.h.session.csrf, html)

    def test_token_without_trailing_slash_is_ok(self):
        url = self.start()
        status, _, _ = request(url.rstrip("/"))
        self.assertEqual(status, 200)

    def test_html_escaping(self):
        url = self.start(label="<script>alert(1)</script>", prompt='"><img src=x>', requester="<b>x</b>")
        _, _, html = request(url)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<img src=x>", html)
        self.assertNotIn("<b>x</b>", html)

    def test_unsupported_method(self):
        url = self.start()
        status, headers, _ = request(url, "PUT", "x")
        self.assertEqual(status, 405)


class TestIdentity(Base):
    def test_wrong_identity_403(self):
        url = self.start(transport=FakeIdentityTransport(["alice@example.com"]))
        status, _, html = request(url, headers={"Tailscale-User-Login": "mallory@example.com"})
        self.assertEqual(status, 403)
        self.assertNotIn(self.h.session.csrf, html)
        self.assertNotIn("alice@example.com", html)  # don't reveal the allowlist

    def test_missing_identity_403(self):
        url = self.start(transport=FakeIdentityTransport(["alice@example.com"]))
        status, _, _ = request(url)
        self.assertEqual(status, 403)

    def test_post_with_wrong_identity_403_and_not_delivered(self):
        url = self.start(transport=FakeIdentityTransport(["alice@example.com"]))
        _, _, html = request(url, headers={"Tailscale-User-Login": "alice@example.com"})
        body = urlencode({"csrf": csrf_of(html), "value": SECRET})
        status, _, _ = request(url + "submit", "POST", body, {
            "Content-Type": "application/x-www-form-urlencoded", "Tailscale-User-Login": "mallory@example.com"})
        self.assertEqual(status, 403)
        self.assertEqual(self.rec.values, [])

    def test_right_identity_case_insensitive(self):
        url = self.start(transport=FakeIdentityTransport(["Alice@Example.com"]))
        hdr = {"Tailscale-User-Login": "alice@example.COM"}
        status, _, _ = submit(url, SECRET, headers=hdr, extra_get_headers=hdr)
        self.assertEqual(status, 200)
        self.assertEqual(self.rec.values[0].data, SECRET.encode())
        self.assertTrue(any("from alice@example.COM" in l for l in self.rec.logs))


class TestSingleUse(Base):
    def test_second_submit_410(self):
        url = self.start()
        _, _, html = request(url)
        token = csrf_of(html)
        status, _, page = submit(url, SECRET, csrf=token)
        self.assertEqual(status, 200)
        self.assertIn("Delivered", page)
        status, _, _ = submit_raw(url, "second", token)
        self.assertEqual(status, 410)
        status, _, _ = request(url)
        self.assertEqual(status, 410)
        self.assertEqual(len(self.rec.values), 1)
        self.assertTrue(self.h.session.finished.is_set())

    def test_concurrent_submits_deliver_once(self):
        url = self.start()
        _, _, html = request(url)
        token = csrf_of(html)
        results = []
        threads = [threading.Thread(target=lambda i=i: results.append(submit_raw(url, f"v{i}", token)[0])) for i in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sorted(results).count(200), 1)
        self.assertEqual(len(self.rec.values), 1)

    def test_delivery_failure_does_not_consume(self):
        url = self.start()
        calls = []

        def flaky(v):
            calls.append(v)
            if len(calls) == 1:
                raise OSError("disk full")
        self.h.session.deliver = flaky
        status, _, _ = submit(url, SECRET)
        self.assertEqual(status, 500)
        status, _, _ = submit(url, SECRET)
        self.assertEqual(status, 200)


def submit_raw(url, value, csrf, headers=None):
    body = urlencode({"csrf": csrf, "value": value})
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    h.update(headers or {})
    return request(url + "submit", "POST", body, h)


class TestCsrf(Base):
    def test_missing_or_wrong_csrf_403(self):
        url = self.start()
        for token in ("", "wrong", self.h.session.csrf[:-1]):
            status, _, _ = submit_raw(url, SECRET, token)
            self.assertEqual(status, 403)
        self.assertEqual(self.rec.values, [])

    def test_cross_origin_403(self):
        url = self.start()
        tok = self.h.session.csrf
        for hdrs in ({"Origin": "https://evil.example"}, {"Origin": "null"},
                     {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}):
            status, _, _ = submit_raw(url, SECRET, tok, hdrs)
            self.assertEqual(status, 403, hdrs)
        self.assertEqual(self.rec.values, [])

    def test_rejected_post_does_not_poison_keepalive_connection(self):
        import http.client
        from urllib.parse import urlsplit
        url = self.start()
        u = urlsplit(url)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
        body = urlencode({"csrf": self.h.session.csrf, "value": SECRET})
        hdr = {"Content-Type": "application/x-www-form-urlencoded"}
        c.request("POST", u.path + "submit", body, dict(hdr, Origin="https://evil.example"))
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 403)
        self.assertEqual(r.getheader("Connection"), "close")
        c.close()
        status, _, _ = submit_raw(url, SECRET, self.h.session.csrf)
        self.assertEqual(status, 200)

    def test_same_origin_ok(self):
        url = self.start()
        origin = url.split("/", 3)[:3]
        status, _, _ = submit_raw(url, SECRET, self.h.session.csrf,
                                  {"Origin": "/".join(origin), "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200)


class TestLimitsAndValidation(Base):
    def test_oversized_content_length_413_without_reading(self):
        url = self.start(max_bytes=64)
        status, _, _ = request(url + "submit", "POST", "x" * 100000,
                               {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 413)
        self.assertEqual(self.rec.values, [])

    def test_value_over_limit_413(self):
        url = self.start(max_bytes=16)
        status, _, _ = submit(url, "a" * 17)
        self.assertEqual(status, 413)
        status, _, _ = submit(url, "a" * 16)
        self.assertEqual(status, 200)

    def test_missing_content_length_411(self):
        url = self.start()
        import http.client
        from urllib.parse import urlsplit
        u = urlsplit(url)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
        c.putrequest("POST", u.path + "submit")
        c.putheader("Content-Type", "application/x-www-form-urlencoded")
        c.endheaders()
        r = c.getresponse()
        self.assertEqual(r.status, 411)
        c.close()

    def test_pattern_and_single_line(self):
        url = self.start(pattern="[0-9]{6}")
        status, _, html = submit(url, "12345")
        self.assertEqual(status, 400)
        self.assertIn("expected format", html)
        self.assertIn('pattern="[0-9]{6}"', html)
        status, _, _ = submit(url, "123456")
        self.assertEqual(status, 200)

    def test_line_rejects_newlines_and_strips(self):
        url = self.start()
        status, _, _ = submit(url, "a\nb")
        self.assertEqual(status, 400)
        status, _, _ = submit(url, "   ")
        self.assertEqual(status, 400)
        status, _, _ = submit(url, "  abc  ")
        self.assertEqual(status, 200)
        self.assertEqual(self.rec.values[0].data, b"abc")

    def test_text_kind_keeps_lines(self):
        url = self.start(kind="text")
        _, _, html = request(url)
        self.assertIn("<textarea", html)
        status, _, _ = submit(url, "line1\r\nline2\r\n")
        self.assertEqual(status, 200)
        self.assertEqual(self.rec.values[0].data, b"line1\nline2\n")

    def test_secret_kind_is_password_field(self):
        url = self.start(kind="secret")
        _, _, html = request(url)
        self.assertIn('type="password"', html)
        self.assertIn('id="reveal"', html)

    def test_file_upload(self):
        url = self.start(kind="file", max_bytes=1024)
        _, _, html = request(url)
        self.assertIn('enctype="multipart/form-data"', html)
        data = bytes(range(256)) + b"\r\n--not-a-boundary\r\n"
        body, ctype = multipart({"csrf": csrf_of(html)}, {"file": ("../../etc/id_ed25519", data)})
        status, _, _ = request(url + "submit", "POST", body, {"Content-Type": ctype})
        self.assertEqual(status, 200)
        self.assertEqual(self.rec.values[0].data, data)
        self.assertEqual(self.rec.values[0].filename, "id_ed25519")

    def test_file_over_limit(self):
        url = self.start(kind="file", max_bytes=10)
        _, _, html = request(url)
        body, ctype = multipart({"csrf": csrf_of(html)}, {"file": ("a.bin", b"x" * 11)})
        status, _, _ = request(url + "submit", "POST", body, {"Content-Type": ctype})
        self.assertEqual(status, 413)


class TestTimeoutAndLogs(Base):
    def test_expired_session_410_and_wait_returns_false(self):
        url = self.start(timeout=0.4)
        t0 = time.monotonic()
        self.assertFalse(self.h.wait())
        self.assertLess(time.monotonic() - t0, 3)
        status, _, _ = request(url)
        self.assertEqual(status, 410)

    def test_logs_never_contain_value_or_token(self):
        url = self.start()
        submit(url, SECRET)
        request(url)
        joined = "\n".join(self.rec.logs)
        self.assertTrue(self.rec.logs)
        self.assertNotIn(SECRET, joined)
        # the URL (with its token) is printed exactly once, in the start banner;
        # request log lines never repeat it
        self.assertEqual(joined.count(self.h.session.token), 1)
        joined = "\n".join(l for l in self.rec.logs if not l.startswith("open: "))
        self.assertNotIn(self.h.session.token, joined)
        self.assertNotIn(self.h.session.csrf, joined)

    def test_value_repr_is_redacted(self):
        url = self.start()
        submit(url, SECRET)
        self.assertNotIn(SECRET, repr(self.rec.values[0]))


class TestTailscaleTransport(unittest.TestCase):
    STATUS = {
        "BackendState": "Running",
        "Self": {"DNSName": "myhost.tailnet-name.ts.net.", "UserID": 7, "HostName": "myhost"},
        "User": {"7": {"LoginName": "alice@example.com"}},
    }

    def make(self, serve_status='{"TCP": {"443": {"HTTPS": true}}}', **kw):
        calls = []

        class CP:
            def __init__(self, out="", rc=0, err=""):
                self.stdout, self.returncode, self.stderr = out, rc, err

        def runner(argv, timeout):
            calls.append(list(argv[1:]))
            if argv[1:3] == ["serve", "status"]:
                return CP(serve_status)
            return CP()

        t = TailscaleTransport(binary="/fake/tailscale", runner=runner, status=TailscaleStatus(self.STATUS), **kw)
        return t, calls

    def test_default_allowlist_is_node_owner_and_serve_lifecycle(self):
        t, calls = self.make()
        origin = t.start(43123)
        self.assertEqual(origin, "https://myhost.tailnet-name.ts.net:43123")
        self.assertEqual(t.allow, ["alice@example.com"])
        self.assertIn(["serve", "--bg", "--yes", "--https=43123", "http://127.0.0.1:43123"], calls)
        self.assertFalse(any("funnel" in c for call in calls for c in call))
        t.stop()
        t.stop()  # idempotent
        self.assertEqual(calls.count(["serve", "--https=43123", "off"]), 1)

    def test_refuses_port_already_served(self):
        t, calls = self.make('{"TCP": {"43123": {"HTTPS": true}}}')
        with self.assertRaises(Exception):
            t.start(43123)
        self.assertFalse(any(c[:2] == ["serve", "--bg"] for c in calls))

    def test_identity_rules(self):
        t, _ = self.make(allow=["bob@example.com"])
        self.assertFalse(t.identify({}).ok)
        self.assertFalse(t.identify({"Tailscale-User-Login": "alice@example.com"}).ok)
        self.assertTrue(t.identify({"Tailscale-User-Login": "BOB@example.com"}).ok)
        t2, _ = self.make(allow_any=True)
        self.assertTrue(t2.identify({"Tailscale-User-Login": "anyone@example.com"}).ok)
        self.assertFalse(t2.identify({}).ok)

    def test_tagged_node_requires_explicit_allow(self):
        st = dict(self.STATUS)
        st["Self"] = dict(st["Self"], Tags=["tag:server"])
        t = TailscaleTransport(binary="/x", runner=lambda a, t: None, status=TailscaleStatus(st))
        with self.assertRaises(Exception):
            t.prepare()


if __name__ == "__main__":
    unittest.main()
