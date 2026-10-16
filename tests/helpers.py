import http.client
import os
import re
import sys
from urllib.parse import urlencode, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


def request(url, method="GET", body=None, headers=None, path=None):
    u = urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    try:
        conn.request(method, path if path is not None else (u.path or "/"), body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


def csrf_of(html):
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, "no csrf field on page"
    return m.group(1)


def submit(url, value, headers=None, csrf=None, extra_get_headers=None):
    """GET the form, then POST value with the page's CSRF token."""
    status, _, html = request(url, headers=extra_get_headers)
    assert status == 200, (status, html[:200])
    token = csrf if csrf is not None else csrf_of(html)
    body = urlencode({"csrf": token, "value": value})
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    h.update(headers or {})
    return request(url + "submit", "POST", body, h)


def multipart(fields, files):
    boundary = "----tailslipTestBoundary7MA4YWxkTrZu0gW"
    out = b""
    for k, v in fields.items():
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
    for k, (fn, data) in files.items():
        out += (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{fn}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return out, f"multipart/form-data; boundary={boundary}"
