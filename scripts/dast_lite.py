"""Passive header/cookie checks against a RUNNING local target.

A small stand-in for the ZAP baseline when Docker/Java are absent. It only
sends GET/POST requests to the URL you give it (default http://127.0.0.1:5000).
It is NOT ZAP; CI runs the real ZAP baseline.

Usage: python scripts/dast_lite.py http://127.0.0.1:5000 out.json
"""

from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

HEADER_CHECKS = {
    "Content-Security-Policy": "CSP header set (ZAP 10038)",
    "X-Content-Type-Options": "nosniff set (ZAP 10021)",
    "X-Frame-Options": "anti-clickjacking header set (ZAP 10020)",
}


def run(base: str) -> dict:
    if urllib.parse.urlparse(base).hostname not in ("127.0.0.1", "localhost"):
        raise SystemExit("dast_lite only targets localhost")
    checks = []
    with urllib.request.urlopen(base + "/") as r:
        headers = r.headers
    for h, label in HEADER_CHECKS.items():
        checks.append({"check": label, "passed": h in headers})
    checks.append({"check": "Server header hides version (ZAP 10036)",
                   "passed": "Werkzeug" not in headers.get("Server", "")})
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    data = urllib.parse.urlencode({"username": "alice", "password": "alice-pass-123"}).encode()
    resp = opener.open(base + "/login", data=data)
    raw = " ".join(resp.headers.get_all("Set-Cookie") or [])
    checks.append({"check": "Session cookie HttpOnly (ZAP 10010)", "passed": "HttpOnly" in raw})
    checks.append({"check": "Session cookie SameSite (ZAP 10054)", "passed": "SameSite" in raw})
    xss = "<script>alert(1)</script>"
    body = urllib.request.urlopen(base + "/greet?" + urllib.parse.urlencode({"name": xss})).read().decode()
    checks.append({"check": "Reflected input is escaped (ZAP 40012, active)", "passed": xss not in body})
    return {"target": base, "checks": checks}


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
    res = run(base.rstrip("/"))
    out = json.dumps(res, indent=2)
    if len(sys.argv) > 2:
        open(sys.argv[2], "w").write(out + "\n")
    print(out)
