"""Vercel Python function: GET /api/analyze (service info + demo cases), POST /api/analyze (analyse a message).

All logic lives in scamshield/web.py so it can be tested and run locally without Vercel.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scamshield.logging_utils import configure_logging  # noqa: E402
from scamshield.web import MAX_BODY_BYTES, handle_get, handle_post  # noqa: E402

configure_logging()


class handler(BaseHTTPRequestHandler):  # noqa: N801 - name required by the Vercel runtime
    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _client_key(self) -> str:
        forwarded = self.headers.get("x-forwarded-for") or self.headers.get("x-real-ip") or ""
        return forwarded.split(",")[0].strip() or (self.client_address[0] if self.client_address else "anon")

    def do_GET(self) -> None:  # noqa: N802
        self._send(*handle_get())

    def do_POST(self) -> None:  # noqa: N802
        if "application/json" not in (self.headers.get("content-type") or ""):
            self._send(415, {"error": "Content-Type must be application/json"})
            return
        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send(413 if length > MAX_BODY_BYTES else 400, {"error": "missing or oversized body"})
            return
        self._send(*handle_post(self.rfile.read(length), self._client_key()))

    def log_message(self, format: str, *args) -> None:  # silence default access log (would include paths only, but keep logs structured)
        return
