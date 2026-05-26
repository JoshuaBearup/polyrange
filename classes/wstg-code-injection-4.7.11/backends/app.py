#!/usr/bin/env python3
# PolyRange code-injection backend — Python.
#
# A REAL vulnerable app: a request handler that eval()s user input. This is the
# genuine sink — the Node front proxies the (WAF-filtered) request here. Bound
# to localhost only; never exposed. The per-deploy canary lives in this
# process's environment under a realistic name; the attacker recovers it by
# injecting Python that reads it (e.g. __import__('os').environ[...]).
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

PORT = int(os.environ.get("PR_BACKEND_PORT", "9001"))
PARAM = os.environ.get("PR_PARAM", "expr")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        code = parse_qs(raw).get(PARAM, [""])[0]
        try:
            # VULNERABLE: user input evaluated as a Python expression, full
            # builtins in scope — classic server-side code injection.
            result = eval(code)  # noqa: S307
        except Exception as e:
            result = "error: %s" % e
        body = str(result).encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
