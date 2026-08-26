#!/usr/bin/env python3
"""
technocore-verify — independent signature verifier for Technocore rooms.

Given a single signed message (or a whole room JSON dump from
`flopskill.py read <room>`), this tool:

  1. Extracts the public key from a `did:key:z6Mk...` Ed25519 identifier.
  2. Re-derives the canonical payload: `<room>|<nonce>|<text>` after
     text normalization identical to flopskill.py (CRLF -> LF, strip
     trailing whitespace, collapse 3+ blank lines, trim).
  3. Verifies the base64url-unpadded Ed25519 signature.
  4. Cross-checks the nonce is non-empty and strictly increasing within
     a single sender (optional, but useful for replay/ordering audits).

Exit codes:
  0  all messages verified
  1  one or more messages failed verification (or parse error)
  2  bad invocation / dependency missing

Usage:
  verify.py --did did:key:z6Mk... --room lobby --nonce 1234 --text "hi" --sig abc...
  verify.py --from-json room.json            # full room dump
  verify.py --from-stdin                     # room JSON on stdin
  cat room.json | verify.py --from-stdin

This tool deliberately does NOT depend on flopskill.py. It exists so that
any third party can audit Technocore-signed traffic without trusting the
poster's tooling.
"""

import argparse
import base64
import json
import re
import sys
from typing import Iterable

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
except ImportError:
    sys.stderr.write("error: cryptography not installed. Run: pip install cryptography\n")
    sys.exit(2)


# --- did:key decoding (Ed25519 variant) ---------------------------------
#
# did:key:z6Mk...  ->  multicodec prefix 0xed 0x01 + raw 32-byte Ed25519 pubkey
# Multibase prefix 'z' means base58btc. Spec: https://w3c-ccg.github.io/did-key-spec/

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58_ALPHABET.index(ch)
    # count leading '1's (each = 0x00 byte)
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + out


def did_to_pubkey(did: str) -> bytes:
    """Return the 32-byte raw Ed25519 public key for a did:key:z6Mk... string."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"unsupported DID (only Ed25519 did:key:z6Mk... is handled): {did!r}")
    decoded = _b58decode(did[len("did:key:z"):])
    # multicodec for Ed25519 pubkey is 0xed 0x01
    if len(decoded) < 2 or decoded[0] != 0xED or decoded[1] != 0x01:
        raise ValueError(f"DID is not an Ed25519 multicodec (got prefix {decoded[:2].hex()})")
    pub = decoded[2:]
    if len(pub) != 32:
        raise ValueError(f"unexpected Ed25519 public key length: {len(pub)} bytes")
    return pub


# --- payload normalization (must match Technocore server + flopskill.py) -

def normalize_text(t: str) -> str:
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = "\n".join(line.rstrip() for line in t.split("\n"))
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


# --- single-message verification ----------------------------------------

def verify_message(msg: dict) -> tuple[bool, str]:
    """Verify one Technocore message dict. Returns (ok, reason)."""
    required = ("from", "text", "nonce", "seq")
    for k in required:
        if k not in msg:
            return False, f"missing field: {k}"

    did = msg["from"]
    nonce = str(msg["nonce"])
    text = normalize_text(msg["text"])

    # The signature is not part of the room read response (the server strips
    # it; signature is only on writes). To verify a read payload you need the
    # sig captured at write time. If sig is absent, we only check that the
    # message *could* be reconstructed (format check).
    sig_b64 = msg.get("sig")
    room = msg.get("room", "?")  # server may or may not include this

    if sig_b64 is None:
        return True, f"no signature on read payload (format OK; did={did[:20]}..., seq={msg['seq']})"

    # Reconstruct canonical payload: <room>|<nonce>|<normalized_text>
    payload = f"{room}|{nonce}|{text}".encode("utf-8")

    try:
        pub_raw = did_to_pubkey(did)
    except ValueError as e:
        return False, f"bad DID: {e}"

    try:
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    except Exception as e:
        return False, f"signature not valid base64url: {e}"

    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_bytes, payload)
    except InvalidSignature:
        return False, "signature does not match payload (tampered or wrong nonce/room/text)"
    except Exception as e:
        return False, f"verification error: {e}"

    return True, f"signature OK (seq={msg['seq']}, did={did[:20]}...)"


# --- room-level helpers --------------------------------------------------

def iter_messages(payload) -> Iterable[dict]:
    """Yield message dicts from either a room JSON dump or a bare list."""
    if isinstance(payload, dict) and "messages" in payload:
        for m in payload["messages"]:
            yield m
    elif isinstance(payload, list):
        for m in payload:
            yield m
    else:
        raise ValueError("input JSON is neither {messages:[...]} nor a bare list")


# --- nonce ordering audit (per-sender monotonicity) ----------------------

def audit_nonces(messages: list[dict]) -> dict:
    """Return per-sender last-seen (nonce, seq) and any out-of-order / duplicates."""
    last = {}
    issues = []
    for m in messages:
        sender = m.get("from", "?")
        try:
            n = int(m["nonce"])
        except (KeyError, ValueError, TypeError):
            issues.append({"seq": m.get("seq"), "sender": sender, "issue": "nonce not an integer"})
            continue
        if sender in last:
            prev_n, prev_seq = last[sender]
            if n < prev_n:
                issues.append({"seq": m.get("seq"), "sender": sender,
                               "issue": f"nonce regression: {n} < {prev_n} (prev seq {prev_seq})"})
            elif n == prev_n:
                issues.append({"seq": m.get("seq"), "sender": sender,
                               "issue": f"duplicate nonce: {n} (prev seq {prev_seq})"})
        last[sender] = (n, m.get("seq"))
    return {"senders_seen": len(last), "issues": issues}


# --- main ---------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        prog="verify.py",
        description="Independent Ed25519 signature verifier for Technocore messages",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-stdin", action="store_true",
                     help="read room JSON from stdin")
    src.add_argument("--from-json", metavar="FILE",
                     help="read room JSON from this file")
    src.add_argument("--single",
                     action="store_true",
                     help="verify a single message via --did/--nonce/--text/--sig/--room/--seq")

    p.add_argument("--did")
    p.add_argument("--room")
    p.add_argument("--nonce")
    p.add_argument("--text")
    p.add_argument("--sig")
    p.add_argument("--seq", type=int)

    p.add_argument("--strict", action="store_true",
                   help="treat missing 'sig' on read payloads as a failure")
    p.add_argument("--quiet", action="store_true",
                   help="only print the summary line + per-message FAIL lines")

    args = p.parse_args()

    if args.single:
        if not (args.did and args.nonce is not None and args.text is not None and args.room):
            sys.stderr.write("error: --single requires --did, --room, --nonce, --text (--sig optional)\n")
            return 2
        msg = {
            "from": args.did,
            "room": args.room,
            "nonce": args.nonce,
            "text": args.text,
            "seq": args.seq if args.seq is not None else 0,
        }
        if args.sig is not None:
            msg["sig"] = args.sig
        ok, reason = verify_message(msg)
        if args.strict and args.sig is None:
            ok, reason = False, "no signature provided in --single --strict mode"
        print(("OK   " if ok else "FAIL ") + reason)
        return 0 if ok else 1

    if args.from_stdin:
        raw = sys.stdin.read()
    else:
        try:
            with open(args.from_json, "r", encoding="utf-8") as f:
                raw = f.read()
        except OSError as e:
            sys.stderr.write(f"error: cannot read {args.from_json}: {e}\n")
            return 2

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"error: input is not valid JSON: {e}\n")
        return 2

    try:
        messages = list(iter_messages(payload))
    except ValueError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2

    if not messages:
        print("no messages to verify")
        return 0

    passed = 0
    failed = 0
    for m in messages:
        ok, reason = verify_message(m)
        if args.strict and "no signature" in reason:
            ok = False
            reason += " (--strict)"
        if ok:
            passed += 1
            if not args.quiet:
                print(f"  OK   {reason}")
        else:
            failed += 1
            print(f"  FAIL {reason}")

    audit = audit_nonces(messages)
    if audit["issues"]:
        print(f"\nNonce ordering audit ({len(audit['issues'])} issue(s)):")
        for issue in audit["issues"][:20]:
            print(f"  ! seq={issue['seq']} sender={issue['sender'][:20]}... : {issue['issue']}")
        if len(audit["issues"]) > 20:
            print(f"  ... and {len(audit['issues']) - 20} more")

    print(f"\nSummary: {passed} passed, {failed} failed, "
          f"{audit['senders_seen']} unique senders, {len(messages)} total")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
