"""End-to-end: run the real CLI in a subprocess and drive the page over HTTP."""

import os
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

from helpers import SRC, request, submit

SECRET = "otp-Zq9-848213-xyzzy"


def launch(args, tmp):
    url_file = os.path.join(tmp, "url")
    env = dict(os.environ, PYTHONPATH=SRC, PYTHONUNBUFFERED="1")
    p = subprocess.Popen(
        [sys.executable, "-m", "tailslip", *args[:1], "--transport", "local", "--url-file", url_file, *args[1:]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )
    deadline = time.time() + 15
    while not os.path.exists(url_file):
        if p.poll() is not None or time.time() > deadline:
            if p.poll() is None:
                p.kill()
            out, err = p.communicate(timeout=10)
            raise AssertionError(f"tailslip did not start: rc={p.returncode} err={err.decode()}")
        time.sleep(0.05)
    with open(url_file) as f:
        url = f.read().strip()
    assert stat.S_IMODE(os.stat(url_file).st_mode) == 0o600
    return p, url


class TestReceive(unittest.TestCase):
    def test_stdout_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, url = launch(["receive", "--label", "OTP", "--timeout", "30s"], tmp)
            status, _, _ = submit(url, SECRET)
            self.assertEqual(status, 200)
            out, err = p.communicate(timeout=15)
            self.assertEqual(p.returncode, 0, err.decode())
            self.assertEqual(out, SECRET.encode())  # no trailing newline when piped
            self.assertNotIn(SECRET, err.decode())
            self.assertIn("received", err.decode())

    def test_out_file_is_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "token")
            p, url = launch(["receive", "--secret", "--out", target], tmp)
            status, _, _ = submit(url, SECRET)
            self.assertEqual(status, 200)
            out, err = p.communicate(timeout=15)
            self.assertEqual(p.returncode, 0, err.decode())
            self.assertEqual(out, b"")
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
            with open(target) as f:
                self.assertEqual(f.read(), SECRET)
            self.assertNotIn(SECRET, err.decode())

    def test_timeout_exit_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, url = launch(["receive", "--timeout", "1s"], tmp)
            out, err = p.communicate(timeout=15)
            self.assertEqual(p.returncode, 3)
            self.assertEqual(out, b"")
            self.assertIn("timed out", err.decode())
            with self.assertRaises(OSError):  # server is gone
                request(url)

    def test_url_token_never_in_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, url = launch(["receive", "--timeout", "20s"], tmp)
            try:
                ps = subprocess.run(["ps", "-ww", "-o", "args=", "-p", str(p.pid)], capture_output=True, text=True)
                token = url.rstrip("/").rsplit("/", 1)[1]
                self.assertNotIn(token, ps.stdout)
            finally:
                p.terminate()
                p.communicate(timeout=10)
            self.assertNotEqual(p.returncode, 0)


CHILD = textwrap.dedent(
    """
    import sys
    print("Go to the following link in your browser:\\n\\n    https://auth.example.com/o/oauth2/auth?client_id=abc&state=xyz\\n", flush=True)
    v = input("Enter verification code: ")
    print("got %d chars, ok=%s" % (len(v), v == sys.argv[1]), flush=True)
    """
)


@unittest.skipUnless(os.name == "posix", "pty mode is POSIX only")
class TestExec(unittest.TestCase):
    def test_pty_mode_with_url_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, url = launch(["exec", "--label", "Verification code",
                             "--url-regex", r"https://auth\.example\.com/\S+", "--link-text", "Sign in",
                             "--wait-for", "verification code", "--",
                             sys.executable, "-c", CHILD, SECRET], tmp)
            # the page shows the captured URL as a button once the child printed it
            deadline = time.time() + 10
            while True:
                status, _, html = request(url)
                if "auth.example.com" in html or time.time() > deadline:
                    break
                time.sleep(0.2)
            self.assertIn('href="https://auth.example.com/o/oauth2/auth?client_id=abc&amp;state=xyz"', html)
            self.assertIn("Sign in", html)
            status, _, _ = submit(url, SECRET)
            self.assertEqual(status, 200)
            out, err = p.communicate(timeout=20)
            self.assertEqual(p.returncode, 0, err.decode())
            self.assertIn(f"got {len(SECRET)} chars, ok=True", out.decode())
            # echo is off and output is scrubbed: the value never appears
            self.assertNotIn(SECRET, out.decode())
            self.assertNotIn(SECRET, err.decode())

    def test_stdin_mode(self):
        child = "import sys; d=sys.stdin.read(); print('len', len(d.strip()), d.strip()==sys.argv[1])"
        with tempfile.TemporaryDirectory() as tmp:
            p, url = launch(["exec", "--stdin", "--", sys.executable, "-c", child, SECRET], tmp)
            status, _, _ = submit(url, SECRET)
            self.assertEqual(status, 200)
            out, err = p.communicate(timeout=20)
            self.assertEqual(p.returncode, 0, err.decode())
            self.assertIn(f"len {len(SECRET)} True", out.decode())
            self.assertNotIn(SECRET, out.decode() + err.decode())

    def test_env_mode_and_exit_code_passthrough(self):
        child = "import os,sys; sys.exit(7 if os.environ['MY_TOKEN']==sys.argv[1] else 1)"
        with tempfile.TemporaryDirectory() as tmp:
            p, url = launch(["exec", "--env", "MY_TOKEN", "--", sys.executable, "-c", child, SECRET], tmp)
            status, _, _ = submit(url, SECRET)
            self.assertEqual(status, 200)
            out, err = p.communicate(timeout=20)
            self.assertEqual(p.returncode, 7, err.decode())

    def test_exec_timeout_kills_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, url = launch(["exec", "--timeout", "1s", "--", sys.executable, "-c", "import time; time.sleep(60)"], tmp)
            t0 = time.time()
            out, err = p.communicate(timeout=20)
            self.assertEqual(p.returncode, 3)
            self.assertLess(time.time() - t0, 15)

    def test_waiting_page_before_link(self):
        child = "import time; time.sleep(3); print('https://late.example.com/x'); input()"
        with tempfile.TemporaryDirectory() as tmp:
            p, url = launch(["exec", "--timeout", "20s", "--url-regex", r"https://late\.example\.com/\S+",
                             "--", sys.executable, "-c", child], tmp)
            try:
                status, _, html = request(url)
                self.assertEqual(status, 200)
                self.assertIn('http-equiv="refresh"', html)
                self.assertNotIn('name="csrf"', html)
            finally:
                p.terminate()
                p.communicate(timeout=10)


class TestUsage(unittest.TestCase):
    def run_cli(self, *args):
        env = dict(os.environ, PYTHONPATH=SRC)
        return subprocess.run([sys.executable, "-m", "tailslip", *args], capture_output=True, text=True, env=env, timeout=20)

    def test_allow_requires_tailscale(self):
        r = self.run_cli("receive", "--transport", "local", "--allow", "a@example.com")
        self.assertEqual(r.returncode, 1)
        self.assertIn("only apply to --transport tailscale", r.stderr)

    def test_local_refuses_non_loopback(self):
        r = self.run_cli("receive", "--transport", "local", "--bind", "0.0.0.0")
        self.assertEqual(r.returncode, 1)
        self.assertIn("--transport lan", r.stderr)

    def test_bad_link_rejected(self):
        r = self.run_cli("receive", "--link", "javascript:alert(1)")
        self.assertEqual(r.returncode, 2)

    def test_version(self):
        r = self.run_cli("--version")
        self.assertTrue(re.match(r"tailslip \d+\.\d+\.\d+", r.stdout))


if __name__ == "__main__":
    unittest.main()
