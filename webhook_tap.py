#!/usr/bin/env python3
"""webhook-tap: a local HTTP request inspector for debugging webhooks.

Point a webhook / OAuth callback URL at http://localhost:8901/hook and watch
exactly what arrives: method, path, headers, body.

Usage:
    webhook-tap [--port 8901] [--log-file requests.log] [--quiet]
"""

import argparse
import json
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_PORT = 8901
BODY_LIMIT = 64 * 1024
REDACTED_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization"}

ACK_BODY = json.dumps({"ok": True, "tap": "webhook-tap"}).encode("utf-8")


def redact_headers(headers):
    """Return headers as a dict with sensitive values replaced by [redacted]."""
    out = {}
    for name, value in headers.items():
        if name.lower() in REDACTED_HEADERS:
            out[name] = "[redacted]"
        else:
            out[name] = value
    return out


def format_body(raw):
    """Decode body bytes; pretty-print JSON. Returns (text, truncated)."""
    truncated = len(raw) > BODY_LIMIT
    if truncated:
        raw = raw[:BODY_LIMIT]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    try:
        text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except (json.JSONDecodeError, ValueError):
        pass
    return text, truncated


def render_record(rec):
    """Render one captured record as plain colorless console text."""
    lines = [
        f"[{rec['ts']}] {rec['method']} {rec['path']}",
        "Headers:",
    ]
    for name, value in rec["headers"].items():
        lines.append(f"  {name}: {value}")
    lines.append("Body:")
    if rec["body"]:
        for body_line in rec["body"].splitlines() or [""]:
            lines.append(f"  {body_line}")
    else:
        lines.append("  (empty)")
    if rec["truncated"]:
        lines.append(f"  [truncated at {BODY_LIMIT} bytes]")
    lines.append("")
    return "\n".join(lines)


class TapHandler(BaseHTTPRequestHandler):
    """HTTP handler that records every request.

    Subclasses / tests can override ``record()`` to capture records in
    memory instead of printing them.
    """

    server_version = "webhook-tap/1.0"

    def record(self, rec):
        """Handle one captured record. Default: print to stdout."""
        sys.stdout.write(render_record(rec))
        sys.stdout.flush()

    def _read_body(self):
        """Read the request body, handling chunked transfer encoding."""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            return self._read_chunked()
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def _read_chunked(self):
        """Decode a chunked request body. Never raises."""
        chunks = []
        total = 0
        cap = 16 * 1024 * 1024  # sanity cap for a local debugging tool
        try:
            while True:
                line = self.rfile.readline(65536)
                if not line:
                    break
                size_str = line.decode("latin-1").split(";")[0].strip()
                try:
                    size = int(size_str, 16)
                except ValueError:
                    break
                if size == 0:
                    # consume optional trailers and the final empty line
                    while True:
                        trailer = self.rfile.readline(65536)
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    break
                if total + size > cap:
                    # don't desync the connection: stop reading further
                    self.close_connection = True
                    break
                chunks.append(self.rfile.read(size))
                total += size
                self.rfile.readline(65536)  # chunk-data CRLF
        except (OSError, ValueError):
            pass
        return b"".join(chunks)

    def _handle(self, send_body=True, status=200, extra_headers=None,
                content_type="application/json"):
        raw = self._read_body()
        body_text, truncated = format_body(raw)
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "path": self.path,
            "headers": redact_headers(self.headers),
            "body": body_text,
            "truncated": truncated,
        }
        self.record(rec)
        self.send_response(status)
        if content_type is not None:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(ACK_BODY)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if send_body:
            self.wfile.write(ACK_BODY)

    def do_HEAD(self):
        # Record the request; HEAD responses carry headers but no body.
        self._handle(send_body=False)

    def do_OPTIONS(self):
        # 204 + Allow header, no body.
        self._handle(send_body=False, status=204, extra_headers={
            "Allow": "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"},
            content_type=None)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def log_message(self, fmt, *args):  # keep output pipe-friendly
        return


class TapServer:
    """A tap server bound to 127.0.0.1. Runs in its own thread."""

    def __init__(self, port=DEFAULT_PORT, log_file=None, quiet=False,
                 handler_cls=TapHandler):
        self.port = port
        self.log_file = log_file
        self.quiet = quiet
        self.handler_cls = handler_cls
        self.httpd = None
        self._thread = None

    def start(self):
        server = self

        class _Handler(self.handler_cls):
            def record(self, rec):
                if server.log_file:
                    with open(server.log_file, "a", encoding="utf-8") as f:
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                if not server.quiet:
                    super().record(rec)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), _Handler)
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    @property
    def bound_port(self):
        return self.httpd.server_address[1]

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)


def build_parser():
    p = argparse.ArgumentParser(
        prog="webhook-tap",
        description="Local HTTP request inspector for debugging webhooks "
                    "and OAuth callbacks.",
    )
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help="port to listen on (default: %(default)s)")
    p.add_argument("--log-file", metavar="FILE",
                   help="append each request as JSONL to FILE")
    p.add_argument("--quiet", action="store_true",
                   help="suppress console output (requires --log-file)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.quiet and not args.log_file:
        build_parser().error("--quiet requires --log-file")
    server = TapServer(port=args.port, log_file=args.log_file,
                       quiet=args.quiet).start()
    print(f"webhook-tap listening on http://127.0.0.1:{server.bound_port}/ "
          f"(Ctrl-C to stop)", file=sys.stderr)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        print("webhook-tap stopped.", file=sys.stderr)


if __name__ == "__main__":
    main()
