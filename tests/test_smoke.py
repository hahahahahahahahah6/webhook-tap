"""Smoke tests for webhook-tap.

Spins up a real TapServer on an ephemeral port in a background thread and
exercises the HTTP surface end to end.
"""

import io
import json
import os
import tempfile
import unittest
import urllib.request

from webhook_tap import TapHandler, TapServer, format_body, redact_headers


class CaptureHandler(TapHandler):
    captured = None

    def record(self, rec):
        self.captured.append(rec)


def make_server(log_file=None, quiet=False):
    captured = []
    cls = type("H", (CaptureHandler,), {"captured": captured})
    server = TapServer(port=0, log_file=log_file, quiet=quiet,
                       handler_cls=cls).start()
    return server, captured


def request(port, method="POST", path="/hook", body=None, headers=None):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        headers=headers or {},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, resp.read()


class TestTapServer(unittest.TestCase):
    def test_post_json_captured(self):
        """POST JSON: captured method, path, and body match."""
        server, captured = make_server()
        try:
            body = json.dumps({"event": "ping", "n": 3}).encode()
            status, ack = request(server.bound_port, body=body,
                                 headers={"Content-Type": "application/json"})
            self.assertEqual(status, 200)
            self.assertEqual(len(captured), 1)
            rec = captured[0]
            self.assertEqual(rec["method"], "POST")
            self.assertEqual(rec["path"], "/hook")
            self.assertEqual(json.loads(rec["body"]), {"event": "ping", "n": 3})
        finally:
            server.stop()

    def test_get_works(self):
        """GET requests are captured too, with query strings intact."""
        server, captured = make_server()
        try:
            status, _ = request(server.bound_port, method="GET",
                               path="/oauth/callback?code=abc123")
            self.assertEqual(status, 200)
            self.assertEqual(captured[0]["method"], "GET")
            self.assertEqual(captured[0]["path"], "/oauth/callback?code=abc123")
            self.assertEqual(captured[0]["body"], "")
        finally:
            server.stop()

    def test_auth_header_redacted(self):
        """authorization and cookie values must not leak into records."""
        server, captured = make_server()
        try:
            request(server.bound_port, body=b"x",
                    headers={"Authorization": "Bearer supersecret",
                             "Cookie": "session=abc",
                             "X-Custom": "visible"})
            rec = captured[0]
            self.assertEqual(rec["headers"]["Authorization"], "[redacted]")
            self.assertEqual(rec["headers"]["Cookie"], "[redacted]")
            self.assertEqual(rec["headers"]["X-Custom"], "visible")
            dumped = json.dumps(rec)
            self.assertNotIn("supersecret", dumped)
        finally:
            server.stop()

    def test_jsonl_log_file(self):
        """--log-file appends one JSON object per request."""
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "requests.log")
            server, _ = make_server(log_file=log, quiet=True)
            try:
                request(server.bound_port, method="PUT", path="/pay",
                        body=b'{"amount": 5}')
            finally:
                server.stop()
            with open(log, encoding="utf-8") as f:
                lines = f.read().splitlines()
            self.assertEqual(len(lines), 1)
            rec = json.loads(lines[0])
            self.assertEqual(rec["method"], "PUT")
            self.assertIn("ts", rec)
            self.assertIn("headers", rec)

    def test_ack_body(self):
        """Server answers 200 with the documented JSON ack."""
        server, _ = make_server()
        try:
            status, ack = request(server.bound_port, method="DELETE",
                                  path="/anything")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(ack.decode()),
                             {"ok": True, "tap": "webhook-tap"})
        finally:
            server.stop()

    def test_body_truncation_flagged(self):
        """Bodies over 64KB are truncated and flagged."""
        server, captured = make_server()
        try:
            big = b"a" * (64 * 1024 + 100)
            request(server.bound_port, body=big)
            rec = captured[0]
            self.assertTrue(rec["truncated"])
            self.assertLessEqual(len(rec["body"].encode("utf-8")),
                                 64 * 1024 + 512)
        finally:
            server.stop()

    def test_redact_headers_helper(self):
        """Unit-level: redaction is case-insensitive."""
        out = redact_headers({"AUTHORIZATION": "x", "Accept": "y"})
        self.assertEqual(out["AUTHORIZATION"], "[redacted]")
        self.assertEqual(out["Accept"], "y")

    def test_format_body_non_json(self):
        """Unit-level: non-JSON bodies pass through unchanged."""
        text, truncated = format_body(b"name=foo&bar=baz")
        self.assertEqual(text, "name=foo&bar=baz")
        self.assertFalse(truncated)

    def test_json_pretty_printed(self):
        """Unit-level: JSON bodies are pretty-printed."""
        text, _ = format_body(b'{"a":1}')
        self.assertIn("\n", text)
        self.assertEqual(json.loads(text), {"a": 1})


if __name__ == "__main__":
    unittest.main()
