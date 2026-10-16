"""A canned-response appliance for trying the shared-host example without real hardware (stdlib only).

    python appliance.py routes.json [port]

routes.json maps "METHOD /path" (query string ignored) to {"status": 200, "json": ...} or {"text": ...};
"headers" adds response headers. Anything else is 404. It answers plain HTTP: test use only.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

with open(sys.argv[1]) as f:
    ROUTES = json.load(f)
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
NAME = sys.argv[3] if len(sys.argv) > 3 else "mock"


class Handler(BaseHTTPRequestHandler):
    def _answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        route = ROUTES.get(f"{self.command} {urlsplit(self.path).path}")
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        if "json" in route:
            body = json.dumps(route["json"]).replace("__NAME__", NAME).encode()
            ctype = "application/json"
        else:
            body = str(route.get("text", "")).replace("__NAME__", NAME).encode()
            ctype = route.get("content_type", "application/xml")
        self.send_response(int(route.get("status", 200)))
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (route.get("headers") or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = _answer

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(f"{NAME}: {fmt % args}\n")


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
