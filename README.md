# webhook-tap

**Stop debugging webhooks blind.**

You're wiring up a Stripe webhook or an OAuth redirect. You click "send test event", your handler 500s — and the logs say nothing useful. Or worse: the provider insists it delivered, but your app swears nothing arrived. Did it even reach your machine? What did the headers actually look like? Was the body the shape you assumed?

Instead of guessing, point the callback URL at `http://localhost:8901/hook` and **watch exactly what arrives** — method, path, headers, body — in your terminal.

## Install

Requires Python 3.9+, no dependencies (stdlib only):

```bash
git clone https://github.com/hahahahahahahahah6/webhook-tap
cd webhook-tap
./webhook_tap.py
```

Or run directly with Python: `python3 webhook_tap.py`.

## Usage

```
webhook-tap [--port 8901] [--log-file requests.log] [--quiet]
```

Start it, then configure your webhook provider / OAuth app's callback URL to `http://localhost:8901/hook`:

```bash
$ ./webhook_tap.py
webhook-tap listening on http://127.0.0.1:8901/ (Ctrl-C to stop)
```

Example output when a Stripe-style webhook hits:

```
[2026-10-01T07:30:12.441230+00:00] POST /hook
Headers:
  Host: localhost:8901
  User-Agent: Stripe/1.0 (+https://stripe.com/docs/webhooks)
  Content-Length: 58
  Content-Type: application/json
  Stripe-Signature: [redacted]
Body:
  {
    "id": "evt_123",
    "type": "checkout.session.completed"
  }

[2026-10-01T07:31:02.990110+00:00] GET /oauth/callback?code=abc123&state=xyz
Headers:
  Host: localhost:8901
  User-Agent: Mozilla/5.0
  Cookie: [redacted]
Body:
  (empty)
```

- `authorization`, `cookie`, `set-cookie`, and `proxy-authorization` header values are always redacted as `[redacted]` — safe to paste output into Slack / GitHub issues.
- Bodies over 64KB are truncated and flagged.
- JSON bodies are pretty-printed.
- Every request gets a `200 {"ok": true, "tap": "webhook-tap"}` ack so providers don't retry while you're inspecting.

Options:

- `--port 8901` — listen port (binds `127.0.0.1` only, never exposed to the network).
- `--log-file requests.log` — also append each request as one JSON object per line (JSONL), for later analysis or replay.
- `--quiet` — suppress console output (requires `--log-file`); run it in the background while your test suite fires.

Press Ctrl-C to shut down cleanly.

### Using as a library

`TapHandler` is designed to be subclassed: override `record(rec)` to capture requests in memory instead of printing.

```python
from webhook_tap import TapHandler, TapServer

records = []

class MyHandler(TapHandler):
    def record(self, rec):
        records.append(rec)

server = TapServer(port=8901, handler_cls=MyHandler).start()
# ... fire requests ...
server.stop()
```

## Differentiation

**This is not ngrok or a Cloudflare tunnel.** Those solve *getting traffic to your machine* — punching through NAT so a public URL reaches localhost. webhook-tap is the **last mile**: you already have traffic reaching localhost (tunnel, port forward, provider test console, curl), and you need to *see it*. Point the tap at the end of any tunnel and read the raw bytes your framework would otherwise swallow. It pairs with any tunnel instead of replacing one — and it stays entirely on `127.0.0.1`, no account, no egress, no third party ever seeing your payloads.

## License

MIT — see [LICENSE](LICENSE).
