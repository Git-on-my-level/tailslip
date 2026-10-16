import os
import stat
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)

from tailslip.util import Redactor, atomic_write, format_duration, parse_duration, strip_ansi


class TestDuration(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_duration("90"), 90)
        self.assertEqual(parse_duration("15m"), 900)
        self.assertEqual(parse_duration("1h30m"), 5400)
        self.assertEqual(parse_duration("500ms"), 0.5)
        for bad in ("", "abc", "10x", "-5", "0", "m"):
            with self.assertRaises(ValueError, msg=bad):
                parse_duration(bad)

    def test_format(self):
        self.assertEqual(format_duration(900), "15m")
        self.assertEqual(format_duration(45), "45s")
        self.assertEqual(format_duration(5400), "1h30m")


class TestAtomicWrite(unittest.TestCase):
    def test_creates_0600_and_replaces(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "code.txt")
            old = os.umask(0)
            try:
                atomic_write(p, b"one")
            finally:
                os.umask(old)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            with open(p, "w") as f:
                f.write("x")
            os.chmod(p, 0o644)
            atomic_write(p, b"two")
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            with open(p, "rb") as f:
                self.assertEqual(f.read(), b"two")
            self.assertEqual(os.listdir(d), ["code.txt"])  # no temp files left

    def test_replaces_symlink_instead_of_following(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "target")
            with open(target, "w") as f:
                f.write("keep")
            link = os.path.join(d, "out")
            os.symlink(target, link)
            atomic_write(link, b"value")
            self.assertFalse(os.path.islink(link))
            with open(target) as f:
                self.assertEqual(f.read(), "keep")


class TestRedactor(unittest.TestCase):
    def test_redacts_across_chunks(self):
        r = Redactor()
        r.set_secret(b"SECRETVALUE")
        out = b""
        for chunk in (b"before SEC", b"RETVAL", b"UE after SECRETVALUE", b" end SECR"):
            out += r.feed(chunk)
        out += r.flush()
        self.assertNotIn(b"SECRETVALUE", out)
        self.assertEqual(out, b"before [redacted] after [redacted] end SECR")

    def test_passthrough_without_secret(self):
        r = Redactor()
        self.assertEqual(r.feed(b"abc"), b"abc")

    def test_strip_ansi(self):
        self.assertEqual(strip_ansi(b"\x1b[1mhttps://x\x1b[0m"), b"https://x")


if __name__ == "__main__":
    unittest.main()
