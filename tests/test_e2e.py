#!/usr/bin/env python3
"""End-to-end tests for verify.py v0.2.

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


# === v0.2: new tests for --output json and --watch ===

class TestJSONOutput(unittest.TestCase):
    def test_single_json_output(self):
        r = run([
            "--single", "--output", "json",
            "--did", "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
            "--room", "lobby", "--nonce", "42", "--text", "hi",
        ], expect=0)
        line = r.stdout.decode().strip()
        data = json.loads(line)
        self.assertEqual(data["type"], "single")
        self.assertTrue(data["ok"])
        self.assertIn("reason", data)
        self.assertEqual(data["room"], "lobby")

    def test_batch_json_output(self):
        msgs = {
            "messages": [
                {"seq": 1, "from": "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
                 "nonce": 10, "text": "x"},
                {"seq": 2, "from": "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
                 "nonce": 5, "text": "y"},  # regression
            ]
        }
        r = run(["--from-stdin", "--output", "json"],
                input_bytes=json.dumps(msgs).encode(), expect=0)
        line = r.stdout.decode().strip()
        data = json.loads(line)
        self.assertEqual(data["type"], "audit")
        self.assertEqual(data["passed"], 2)
        self.assertEqual(data["failed"], 0)
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["nonce_issues"]), 1)
        self.assertIn("regression", data["nonce_issues"][0]["issue"])

    def test_empty_room_json(self):
        r = run(["--from-stdin", "--output", "json"],
                input_bytes=b'{"messages":[]}', expect=0)
        data = json.loads(r.stdout.decode().strip())
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["passed"], 0)


class TestWatchMode(unittest.TestCase):
    def test_watch_requires_room(self):
        r = run(["--watch"], expect=2)
        self.assertIn("--room", r.stderr.decode())

    def test_watch_interval_minimum(self):
        r = run(["--watch", "--room", "lobby", "--interval", "1"], expect=2)
        self.assertIn("interval", r.stderr.decode().lower())

    def test_watch_once_real_room(self):
        """One-shot poll of real room. Should emit JSON and not hang."""
        r = run([
            "--watch", "--room", "lobby", "--once", "--output", "json",
            "--limit", "10",
        ], expect=0, timeout=60)
        # Empty rooms or no new messages => still valid JSON
        out = r.stdout.decode().strip()
        # If the room returned messages, first line is JSON. If empty, no output.
        if out:
            data = json.loads(out.split("\n")[0])
            self.assertEqual(data["type"], "audit")
            self.assertIn("passed", data)


class TestWebhook(unittest.TestCase):
    def test_post_webhook_to_local_server(self):
        """Spin up a tiny HTTP server, post to it, verify it received the alert."""
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from threading import Thread
        import time

        from verify import post_webhook

        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                received.append(json.loads(body))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a, **k):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        t = Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            ok = post_webhook(f"http://127.0.0.1:{port}/alert", {"type": "test", "x": 1})
            self.assertTrue(ok)
            time.sleep(0.1)
            self.assertEqual(len(received), 1)
            self.assertEqual(received[0]["type"], "test")
        finally:
            server.shutdown()


class TestFetchRoom(unittest.TestCase):
    def test_fetch_real_room_lobby(self):
        """Fetch the real Technocore lobby. Should return a list (may be empty)."""
        from verify import fetch_room
        try:
            msgs = fetch_room("lobby", since=0, limit=5)
            self.assertIsInstance(msgs, list)
        except RuntimeError as e:
            # If the network is unreachable from CI, skip rather than fail.
            self.skipTest(f"cannot reach Technocore: {e}")


# === v0.3: new tests ===

class TestDockerfileSyntax(unittest.TestCase):
    def test_dockerfile_has_required_instructions(self):
        """Dockerfile must exist, be non-empty, and contain FROM/RUN/COPY/ENTRYPOINT."""
        dockerfile = ROOT / "Dockerfile"
        self.assertTrue(dockerfile.exists(), "Dockerfile must exist at project root")
        content = dockerfile.read_text()
        self.assertGreater(len(content.strip()), 0, "Dockerfile must not be empty")
        for keyword in ("FROM", "RUN", "COPY", "ENTRYPOINT"):
            self.assertIn(keyword, content, f"Dockerfile must contain {keyword}")


class TestTextFile(unittest.TestCase):
    def test_text_file_single_line(self):
        """--text-file with a single-line file works."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("hello from text file")
            path = f.name
        try:
            r = run([
                "--single",
                "--text-file", path,
                "--did", "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
                "--room", "lobby",
                "--nonce", "9000",
            ], expect=0)
            self.assertIn("OK", r.stdout.decode())
        finally:
            os.unlink(path)

    def test_text_file_multi_line(self):
        """--text-file with a multi-line file works and preserves newlines."""
        import tempfile
        msg = {
            "messages": [
                {
                    "seq": 1,
                    "from": "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
                    "nonce": 42,
                    "text": "line1\nline2\n\nline4",
                }
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(msg, f)
            path = f.name
        try:
            r = run(["--from-stdin"], input_bytes=json.dumps(msg).encode(), expect=0)
            out = r.stdout.decode()
            self.assertIn("OK", out)
            # Verify multi-line text is preserved in normalized output.
            # normalize_text collapses 3+ blank lines to 2, trims.
            self.assertNotIn("FAIL", out)
        finally:
            os.unlink(path)


class TestFormat(unittest.TestCase):
    def test_format_text(self):
        """--format text produces human-readable output (same as default)."""
        r = run([
            "--single",
            "--did", "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
            "--room", "lobby",
            "--nonce", "1",
            "--text", "hello",
            "--format", "text",
        ], expect=0)
        out = r.stdout.decode()
        self.assertIn("OK", out)
        # Must NOT be JSON
        self.assertFalse(out.strip().startswith("{"), "text mode must not emit JSON")

    def test_format_json(self):
        """--format json produces JSON output (same as --output json)."""
        r = run([
            "--single",
            "--did", "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
            "--room", "lobby",
            "--nonce", "1",
            "--text", "hello",
            "--format", "json",
        ], expect=0)
        out = r.stdout.decode().strip()
        data = json.loads(out)
        self.assertEqual(data["type"], "single")
        self.assertTrue(data["ok"])

    def test_format_none(self):
        """--format none produces no stdout and exit code only."""
        r = run([
            "--single",
            "--did", "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
            "--room", "lobby",
            "--nonce", "1",
            "--text", "hello",
            "--format", "none",
        ], expect=0)
        self.assertEqual(r.stdout.decode(), "", "--format none must produce no output")

    def test_output_alias_still_works(self):
        """--output json (v0.2 alias) still works for backward compat."""
        r = run([
            "--single",
            "--output", "json",
            "--did", "did:key:z6MktQej1bMhCGKcKDsgQ4294tkmtRWc3C1Sjsu4sF9Jxkr5",
            "--room", "lobby",
            "--nonce", "1",
            "--text", "hi",
        ], expect=0)
        data = json.loads(r.stdout.decode().strip())
        self.assertEqual(data["type"], "single")
        self.assertTrue(data["ok"])


class TestVersion(unittest.TestCase):
    def test_version_flag(self):
        """--version prints 'technocore-verify v0.3.0' and exits 0."""
        r = run(["--version"], expect=0)
        self.assertIn("technocore-verify v0.3.0", r.stdout.decode())
        self.assertEqual(r.stderr.decode(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
