#!/usr/bin/env python3
"""End-to-end tests for verify.py.

Run from this directory:
  python3 -m tests.test_e2e
or:
  python3 tests/test_e2e.py
"""

import base64
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VERIFY = ROOT / "verify.py"
SKILL_DIR = Path("/root/.hermes/skills/flop-airdrop-skill")
FLOP = SKILL_DIR / "flopskill.py"
IDENTITY = SKILL_DIR / "identity.pem"
PASS_FILE = Path("/tmp/.flop-pass.txt")
VENV_PY = "/root/.flop-venv/bin/python"

if not Path(VENV_PY).exists():
    print(f"error: venv python missing at {VENV_PY}", file=sys.stderr)
    sys.exit(2)


def run(cmd, input_bytes=None, expect=0, timeout=30):
    r = subprocess.run(
        [VENV_PY, str(VERIFY), *cmd],
        capture_output=True, input=input_bytes, timeout=timeout,
    )
    if expect is not None and r.returncode != expect:
        raise AssertionError(
            f"cmd {cmd} exited {r.returncode} (expected {expect})\n"
            f"stdout:\n{r.stdout.decode(errors='replace')}\n"
            f"stderr:\n{r.stderr.decode(errors='replace')}\n"
        )
    return r


def _b58(data: bytes) -> str:
    a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = a[r] + out
    pad = sum(1 for b in data if b == 0)
    return "1" * pad + out


def _flopskill_did(pub_raw: bytes) -> str:
    """Mirror flopskill.did_from_pubkey exactly (for cross-checking)."""
    return "did:key:z" + _b58(b"\xed\x01" + pub_raw)


class TestDIDDecoding(unittest.TestCase):
    def test_known_did(self):
        from verify import did_to_pubkey
        did = "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5"
        self.assertEqual(len(did_to_pubkey(did)), 32)

    def test_unsupported(self):
        from verify import did_to_pubkey
        with self.assertRaises(ValueError):
            did_to_pubkey("did:key:z6Mkjp")
        with self.assertRaises(ValueError):
            did_to_pubkey("did:ethr:0xabc")
        with self.assertRaises(ValueError):
            did_to_pubkey("not-a-did")


class TestNormalizeParity(unittest.TestCase):
    def test_matches_flopskill(self):
        sys.path.insert(0, str(SKILL_DIR))
        import flopskill  # noqa
        from verify import normalize_text
        for c in [
            "hello", "  hello   \n", "line1\r\nline2\r\n",
            "a\n\n\n\nb", "trailing   \n\n", "",
        ]:
            self.assertEqual(normalize_text(c), flopskill.normalize_text(c), msg=repr(c))


class TestCLIBehavior(unittest.TestCase):
    def test_no_args_exits_2(self):
        r = run([], expect=2)
        self.assertIn("required", r.stderr.decode().lower())

    def test_missing_file_exits_2(self):
        r = run(["--from-json", "/nonexistent.json"], expect=2)

    def test_invalid_json_exits_2(self):
        r = run(["--from-stdin"], input_bytes=b"{not json", expect=2)

    def test_empty_room(self):
        r = run(["--from-stdin"], input_bytes=b'{"messages":[]}')
        self.assertIn("no messages", r.stdout.decode())

    def test_single_no_sig_passes(self):
        r = run([
            "--single", "--did",
            "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
            "--room", "lobby", "--nonce", "1234", "--text", "hi",
        ], expect=0)
        self.assertIn("OK", r.stdout.decode())

    def test_single_strict_no_sig_fails(self):
        r = run([
            "--single", "--strict", "--did",
            "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
            "--room", "lobby", "--nonce", "1234", "--text", "hi",
        ], expect=1)

    def test_single_bad_did_fails(self):
        r = run([
            "--single",
            "--did", "did:key:zBOGUS",
            "--room", "lobby", "--nonce", "1", "--text", "hi", "--sig", "AAAA",
        ], expect=1)
        self.assertIn("FAIL", r.stdout.decode())


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not IDENTITY.exists() or not PASS_FILE.exists():
            raise unittest.SkipTest("no identity.pem or passphrase available")

    def test_sign_then_verify(self):
        sys.path.insert(0, str(SKILL_DIR))
        import flopskill  # noqa
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        passphrase = PASS_FILE.read_text().strip().encode()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=b"flop-skill-salt", iterations=600_000)
        priv = serialization.load_pem_private_key(
            IDENTITY.read_bytes(), password=kdf.derive(passphrase),
        )
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        did = _flopskill_did(pub)

        # Sign a real message exactly the way flopskill does.
        room = "lobby"
        nonce = "9876543210"
        text = "verifier test ping"
        payload = f"{room}|{nonce}|{flopskill.normalize_text(text)}".encode()
        sig = priv.sign(payload)
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

        # Sanity: the DID we built must match the one flopskill prints.
        from verify import did_to_pubkey
        self.assertEqual(did_to_pubkey(did), pub)

        # Verify the signed message: must pass.
        r = run([
            "--single", "--did", did, "--room", room, "--nonce", nonce,
            "--text", text, "--sig", sig_b64, "--seq", "1",
        ], expect=0)
        self.assertIn("OK", r.stdout.decode())

        # Tamper with the text: must fail.
        r = run([
            "--single", "--did", did, "--room", room, "--nonce", nonce,
            "--text", text + "TAMPERED", "--sig", sig_b64, "--seq", "1",
        ], expect=1)
        self.assertIn("FAIL", r.stdout.decode())

        # Tamper with the nonce: must fail.
        r = run([
            "--single", "--did", did, "--room", room, "--nonce", "9999",
            "--text", text, "--sig", sig_b64, "--seq", "1",
        ], expect=1)
        self.assertIn("FAIL", r.stdout.decode())


class TestNonceAudit(unittest.TestCase):
    def test_room_json_with_issues(self):
        bad = {
            "messages": [
                {"seq": 1, "from": "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
                 "nonce": 100, "text": "a"},
                {"seq": 2, "from": "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
                 "nonce": 50, "text": "b"},  # regression
                {"seq": 3, "from": "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
                 "nonce": 50, "text": "c"},  # duplicate
            ]
        }
        r = run(["--from-stdin"], input_bytes=json.dumps(bad).encode(), expect=0)
        out = r.stdout.decode()
        self.assertIn("regression", out)
        self.assertIn("duplicate", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
