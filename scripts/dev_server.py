"""Local stand-in for the Vercel deployment: serves public/ and routes /api/analyze to the
same handler code, applying the security headers from vercel.json so the CSP is exercised.

    python scripts/dev_server.py            # http://localhost:3000
"""

from __future__ import annotations

import json
import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scamshield.web import MAX_BODY_BYTES, handle_get, handle_post  # noqa: E402

PUBLIC = ROOT / "public"
HEADERS = [(h["key"], h["value"]) for block in json.loads((ROOT / "vercel.json").read_text())["headers"] for h in block["headers"]]


class DevHandler(BaseHTTPRequestHandler):
    def _headers(self, status: int, ctype: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        for key, value in HEADERS:
            if key != "Strict-Transport-Security":  # plain http locally
                self.send_header(key, value)
        self.end_headers()

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self._headers(status, "application/json; charset=utf-8", len(data))
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/analyze":
            self._json(*handle_get())
            return
        target = (PUBLIC / (path.lstrip("/") or "index.html")).resolve()
        if target.is_dir():
            target = target / "index.html"
        if PUBLIC.resolve() not in target.parents and target != PUBLIC.resolve() or not target.is_file():
            self._json(404, {"error": "not found"})
            return
        data = target.read_bytes()
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        self._headers(200, ctype, len(data))
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/api/analyze":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("content-length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(413, {"error": "missing or oversized body"})
            return
        self._json(*handle_post(self.rfile.read(length), self.client_address[0]))

    def log_message(self, format: str, *args) -> None:
        sys.stderr.write(f"{self.command} {self.path.split('?')[0]} -> {args[1] if len(args) > 1 else ''}\n")


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    print(f"ScamShield web dev server on http://localhost:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), DevHandler).serve_forever()


if __name__ == "__main__":
    main()
