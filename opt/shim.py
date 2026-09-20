#!/usr/bin/env python3
"""Decoy backend. Accepts any login, serves plausible JSON. Executes nothing, stores nothing."""
import json, secrets, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = ("127.0.0.1", 8099)
MAXBODY = 1 << 20  # 1 MiB; nginx logs the body, we only need to drain it

OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "OpsCenter Internal API", "version": "1.4.2"},
    "servers": [{"url": "/api/v1"}],
    "paths": {
        "/events": {"get": {"parameters": [
            {"name": "id", "in": "query", "schema": {"type": "integer"}},
            {"name": "from", "in": "query", "schema": {"type": "string"}}]}},
        "/events/{id}": {"get": {}, "delete": {}},
        "/users": {"get": {}, "post": {}},
        "/users/{id}": {"get": {}, "patch": {}},
        "/export": {"get": {"parameters": [
            {"name": "file", "in": "query", "schema": {"type": "string"}}]}},
        "/integrations": {"get": {}, "post": {}},
        "/integrations/test": {"post": {"description": "Send a test callback to the configured webhook URL"}},
        "/rules": {"get": {}, "post": {}},
        "/rules/preview": {"post": {"description": "Render an alert template"}},
        "/backup": {"get": {}},
        "/agents": {"get": {}},
        "/tokens": {"get": {}, "post": {}},
    },
}


def _json(n=3):
    return {"status": "ok", "count": n, "items": [
        {"id": 8841 + i, "host": "srv-app-%02d" % (i + 1), "severity": "medium",
         "rule": "auth.failed_login", "ts": "2026-09-09T06:%02d:00Z" % (10 + i)} for i in range(n)]}


class H(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def log_message(self, *a):
        pass  # nginx owns the log

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}):
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _drain(self):
        n = min(int(self.headers.get("Content-Length") or 0), MAXBODY)
        if n:
            self.rfile.read(n)

    def do_GET(self):
        p = self.path.split("?", 1)[0]
        if p.endswith("/openapi.json"):
            return self._send(200, json.dumps(OPENAPI, indent=2).encode())
        return self._send(200, json.dumps(_json()).encode())

    def do_POST(self):
        self._drain()
        p = self.path.split("?", 1)[0]
        if p in ("/login", "/auth/login", "/api/v1/login"):
            sid = secrets.token_hex(16)
            return self._send(302, b"", "text/html", [
                ("Set-Cookie", "sid=%s; Path=/; HttpOnly" % sid),
                ("Location", "/index.html")])
        return self._send(200, json.dumps({"status": "ok"}).encode())

    do_PUT = do_PATCH = do_DELETE = do_POST


def demo():
    """Self-check: routing decisions, no socket needed."""
    assert "/export" in OPENAPI["paths"]
    assert _json(2)["count"] == 2 and len(_json(2)["items"]) == 2
    assert json.loads(json.dumps(OPENAPI))["info"]["version"] == "1.4.2"
    print("shim self-check ok")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        ThreadingHTTPServer(BIND, H).serve_forever()
