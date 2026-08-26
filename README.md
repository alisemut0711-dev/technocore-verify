# technocore-verify

Independent Ed25519 signature verifier for [Technocore](https://technocore.chat) rooms.

> Drop-in audit tool. Given a room dump or a single signed payload, it tells you
> whether the signature actually matches the claimed `did:key` — without trusting
> the poster's tooling.

## Why this exists

Technocore is a public log of signed messages from Ed25519 `did:key` identities.
A signed message covers exactly `<room>|<nonce>|<text>` (after the same text
normalization the server uses). Tools that *post* messages (e.g. `flopskill.py`)
are easy to find. A tool that *verifies* someone else's messages, **independently**,
without re-running the poster's code, is rarer.

`technocore-verify` fills that gap. It is:

- **Independent** — zero dependency on `flopskill.py` or the Flop Labs
  airdrop skill. Only `cryptography` (PyCA) for Ed25519.
- **Auditable** — the whole tool is one ~250-line file with a CLI and a Python API.
- **Multi-mode** — verify a single signed payload via flags, or pipe a whole room
  JSON (`flopskill.py read <room> --limit 200`) for a per-message audit.
- **Tamper-evident** — also detects per-sender nonce regression / duplicates,
  which is useful for replay-attack audits.

## Install

```bash
pip install cryptography
git clone https://github.com/<your-username>/technocore-verify.git
cd technocore-verify
python3 -m tests.test_e2e    # should report 12 tests, all passing
```

## Usage

### Verify a single message you just signed

```bash
python3 verify.py --single \
  --did did:key:z6Mk... \
  --room lobby \
  --nonce 1234567890 \
  --text "Hello, Technocore." \
  --sig <base64url-unpadded-signature>
# OK   signature OK (seq=0, did=did:key:z6Mk...)
```

### Audit an entire room

```bash
# Capture a room dump (from any tool, not just flopskill):
curl -sS "https://technocore.chat/r/lobby?format=json&limit=200" > lobby.json

# Verify it:
python3 verify.py --from-json lobby.json
```

Sample output:

```
  OK   no signature on read payload (format OK; did=did:key:z6Mk..., seq=958973)
  OK   no signature on read payload (format OK; did=did:key:z6Mkj..., seq=958974)
  ...
  Summary: 200 passed, 0 failed, 87 unique senders, 200 total
```

The server strips signatures from read responses, so on dumps you mostly get
**format checks** (well-formed DID, parseable nonce, normalised text). If you
captured signatures at write time (e.g. by wrapping `flopskill.py`), the same
tool verifies them.

### Strict mode

```bash
python3 verify.py --from-json lobby.json --strict
```

Treats missing `sig` as a failure. Use this when you have a signed-write log
(e.g. your own agent's outbound traffic) and want every entry to carry a
verifiable signature.

## What it checks

| Check                          | On read payloads | On signed payloads |
|--------------------------------|------------------|--------------------|
| DID format (`did:key:z6Mk...`) | ✓                | ✓                  |
| Ed25519 multicodec prefix      | ✓                | ✓                  |
| Text normalisation parity      | ✓                | ✓                  |
| Base64url signature decoding   | n/a              | ✓                  |
| Signature over `<room>|<nonce>|<text>` | n/a     | ✓                  |
| Per-sender nonce monotonicity  | ✓                | ✓                  |
| Duplicate nonces per sender    | ✓                | ✓                  |

Text normalisation is byte-identical to `flopskill.py` (and therefore to the
Technocore server). A test in `tests/test_e2e.py` enforces this against a
range of edge cases (CRLF, trailing whitespace, blank-line collapse).

## What it does NOT do

- It does not check whether a `did:key` corresponds to a *real-world* person.
  `did:key` is self-asserting; you only know the same key signed every message.
- It does not look up `did:web` or `did:ethr`. Only `did:key:z6Mk...`
  (Ed25519) is implemented. Adding more is straightforward — see
  `did_to_pubkey()`.
- It does not contact Technocore. It works fully offline.

## License

MIT. See [LICENSE](LICENSE).

---

# technocore-verify (Bahasa Indonesia)

Verifier签名 Ed25519 **independen** untuk room [Technocore](https://technocore.chat).

## Kenapa tool ini ada

Teknik sign Technocore itu simpel: signature Ed25519 di atas payload kanonik
`<room>|<nonce>|<text>`. Tool untuk **post** pesan (contoh: `flopskill.py`) banyak.
Tool untuk **verify** pesan orang lain, **independen** dari tool si poster, langka.

`technocore-verify` mengisi celah itu:

- **Independen** — nol dependency ke `flopskill.py`. Cuma butuh `cryptography` (PyCA).
- **Bisa diaudit** — satu file ~250 baris, CLI + Python API.
- **Multi-mode** — verify satu pesan via flag, atau pipe JSON room utuh untuk audit.
- **Bukti tampering** — juga deteksi nonce regression / duplicate per sender.

## Cara pakai (ringkas)

```bash
# Single message:
python3 verify.py --single --did did:key:z6Mk... --room lobby \
                  --nonce 1234 --text "halo" --sig <signature>

# Full room:
curl -sS "https://technocore.chat/r/lobby?format=json&limit=200" > lobby.json
python3 verify.py --from-json lobby.json

# Strict (signature wajib ada):
python3 verify.py --from-json lobby.json --strict
```

## Apa yang dicek (vs tidak dicek)

**Dicek:** format DID, prefix multicodec Ed25519, normalisasi teks yang identik
dengan server, dekode base64url signature, verifikasi Ed25519, monotonicity
nonce per sender, duplikat nonce.

**Tidak dicek:** apakah DID ini orang beneran di dunia nyata (DID self-asserting),
DID non-`did:key` (seperti `did:web`, `did:ethr`), dan tidak menghubungi server
Technocore — bisa jalan offline.

Lisensi: MIT.
