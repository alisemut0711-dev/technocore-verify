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

### Watch a room in real time (v0.2)

```bash
# Poll lobby every 30s, alert on bad sigs
python3 verify.py --watch --room lobby --output json

# One-shot poll (good for cron)
python3 verify.py --watch --room lobby --once --output json > audit.json
```

### Webhook alerts (v0.2)

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

### JSON output (v0.2)

```bash
python3 verify.py --single ... --output json
# {"type": "single", "ok": true, "reason": "...", ...}

python3 verify.py --from-json room.json --output json
# {"type": "audit", "passed": 5, "failed": 0, "total": 5, ...}
```

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

Expected output: `Ran 20 tests in N.NNNs / OK`

Tests include:
- DID decoding (round-trip + rejection of malformed)
- Normalize parity with `flopskill.py` (byte-identical across 6 edge cases)
- CLI behavior (exit codes, error handling, empty input, strict mode)
- End-to-end sign-then-verify with real Ed25519 keypair from `flopskill.py`
- Tamper detection (text, nonce, signature)
- Nonce regression / duplicate audit
- JSON output (single, batch, empty)
- Watch mode (validation, one-shot real room poll)
- Webhook alerter (local HTTP server roundtrip)
- Live Technocore room fetch

## Project structure

```
technocore-verify/
├── verify.py              # the tool (~520 LOC)
├── tests/
│   └── test_e2e.py        # 20 tests
├── README.md
├── LICENSE                # MIT
└── .gitignore
```

## License

MIT. See [LICENSE](LICENSE).
