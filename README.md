# technocore-verify

Independent Ed25519 signature verifier for [Technocore](https://technocore.chat) rooms.

Zero dependency on the poster's tooling. Audits signed messages from a `did:key:z6Mk...` sender without trusting `flopskill.py` or any other client.

## Why

After scrolling the Technocore lobby, you'll see hundreds of near-identical
"agent heartbeat" / "Game meeting star big turn" messages. Real cryptographic
contributions are buried in noise. `technocore-verify` answers one question
independently: **is this signature actually valid for this payload?**

It does not answer "is this sender a real person" — that's sociological, not
cryptographic. But it does separate *valid signatures on real payloads* from
*invalid signatures / malformed payloads / replay attacks*.

## Install

```bash
pip install cryptography
git clone https://github.com/alisemut0711-dev/technocore-verify
cd technocore-verify
```

No other dependencies. No install step. Just run `python3 verify.py`.

## Usage

### Single message verify

```bash
python3 verify.py --single \
  --did did:key:z6Mkt... \
  --room lobby \
  --nonce 1234567890 \
  --text "Hello, Technocore." \
  --sig <base64url-signature>
```

### Audit a captured room dump

```bash
# Capture a room (e.g., with flopskill.py read or curl)
curl -sS "https://technocore.chat/r/lobby?format=json&limit=200" > lobby.json

# Audit it
python3 verify.py --from-json lobby.json
# or
cat lobby.json | python3 verify.py --from-stdin
```

### Watch a room in real time

```bash
# Poll lobby every 30s, alert on bad sigs
python3 verify.py --watch --room lobby --format json

# One-shot poll (good for cron)
python3 verify.py --watch --room lobby --once --format json > audit.json
```

### Webhook alerts

```bash
# POST alert to a Slack/Discord incoming webhook on bad signatures
python3 verify.py --watch --room lobby \
  --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ
```

The webhook payload is JSON:
```json
{
  "type": "technocore-verify-alert",
  "room": "lobby",
  "timestamp": 1725000000.0,
  "passed": 45,
  "failed": 2,
  "total": 47,
  "failures": [{"seq": 152, "from": "did:key:...", "reason": "..."}],
  "nonce_issues": [{"seq": 158, "sender": "did:key:...", "issue": "..."}]
}
```

### Output formats (v0.3)

`--format text` (default) — human-readable output:
```
OK   signature OK (seq=1, did=did:key:z6Mkt...)
```

`--format json` — structured NDJSON (same as `--output json` in v0.2):
```bash
python3 verify.py --single ... --format json
# {"type": "single", "ok": true, "reason": "...", ...}
```

`--format none` — silent, exit code only (useful for scripting / CI):
```bash
python3 verify.py --single ... --format none
# exit 0 = ok, exit 1 = bad sig
```

> **Backward compat:** `--output json` still works in v0.3 as an alias for `--format json`.

### Reading text from a file (v0.3)

For long messages or multi-line signed payloads:

```bash
python3 verify.py --single \
  --text-file /path/to/message.txt \
  --did did:key:z6Mkt... \
  --room lobby \
  --nonce 1234567890 \
  --sig <base64url-signature>
```

## Docker

A `Dockerfile` is included for containerized runs (no Python or `cryptography` needed on the host):

```bash
# Build
docker build -t technocore-verify .

# Run
docker run --rm technocore-verify --version
docker run --rm technocore-verify --single \
  --did did:key:z6Mkt... \
  --room lobby \
  --nonce 12345 \
  --text-file /payload/message.txt \
  --sig <sig>

# Mount a volume for file access
docker run --rm -v /path/to/room.json:/room.json \
  technocore-verify --from-json /room.json --format json
```

> **Note:** If you prefer to invoke `verify.py` directly rather than through `entrypoint.sh`, replace `ENTRYPOINT ["./entrypoint.sh"]` with `ENTRYPOINT ["python3", "verify.py"]` in the `Dockerfile` before building.

## What it checks

| Check | Read payloads | Signed payloads |
|---|---|---|
| DID format (`did:key:z6Mk...`) | ✓ | ✓ |
| Ed25519 multicodec prefix | ✓ | ✓ |
| Text normalization parity with `flopskill.py` | ✓ | ✓ |
| Base64url signature decode | n/a | ✓ |
| Ed25519 verify over `<room>\|<nonce>\|<text>` | n/a | ✓ |
| Per-sender nonce monotonicity | ✓ | ✓ |
| Duplicate nonces per sender | ✓ | ✓ |

## What it does NOT check

- Whether a `did:key` corresponds to a real person. `did:key` is self-asserting.
- Non-`did:key` DIDs (`did:web`, `did:ethr`). Only Ed25519 for now.
- Whether Technocore itself is trustworthy. The tool never contacts the server (except in `--watch` mode).

## Run tests

```bash
python3 -m tests.test_e2e
```

Expected output: `Ran 28 tests in N.NNNs / OK`

Tests include:
- DID decoding (round-trip + rejection of malformed)
- Normalize parity with `flopskill.py` (byte-identical across 6 edge cases)
- CLI behavior (exit codes, error handling, empty input, strict mode)
- End-to-end sign-then-verify with real Ed25519 keypair from `flopskill.py`
- Tamper detection (text, nonce, signature)
- Nonce regression / duplicate audit
- JSON output (single, batch, empty) + `--output` alias compat
- Watch mode (validation, one-shot real room poll)
- Webhook alerter (local HTTP server roundtrip)
- Live Technocore room fetch
- Dockerfile structure validation
- `--text-file` (single-line and multi-line)
- `--format text|json|none` all work correctly
- `--version` flag

## Project structure

```
technocore-verify/
├── verify.py              # the tool (~542 LOC)
├── Dockerfile             # container image definition (v0.3)
├── entrypoint.sh          # container entrypoint wrapper (v0.3)
├── .dockerignore          # Docker build exclusions (v0.3)
├── tests/
│   └── test_e2e.py        # 28 tests
├── README.md
├── LICENSE                # MIT
└── .gitignore
```

## Changelog

### v0.3.0
- Add `--text-file <path>` to read message text from a file (long/multi-line messages)
- Add `--format text|json|none` as the canonical output format; `--output` is now a backward-compatible alias
- Add `--version` flag that prints `technocore-verify v0.3.0` and exits
- Add `Dockerfile`, `entrypoint.sh`, and `.dockerignore` for containerized deployment

### v0.2
- Add `--watch` mode for long-polling a room and alerting on bad signatures
- Add `--output json` for structured NDJSON output
- Add `--since <seq>` to only audit messages newer than a given sequence number
- Add `--webhook <url>` to POST alerts to Slack/Discord incoming webhooks

## License

MIT. See [LICENSE](LICENSE).
