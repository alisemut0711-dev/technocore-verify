#!/usr/bin/env python3
"""
technocore-verify v0.3 — independent signature verifier for Technocore rooms.

Given a single signed message (or a whole room JSON dump from
`flopskill.py read <room>`), this tool:

  1. Extracts the public key from a `did:key:z6Mk...` Ed25519 identifier.
  2. Re-derives the canonical payload: `<room>|<nonce>|<text>` after
     text normalization identical to flopskill.py (CRLF -> LF, strip
     trailing whitespace, collapse 3+ blank lines, trim).
  3. Verifies the base64url-unpadded Ed25519 signature.
  4. Cross-checks the nonce is non-empty and strictly increasing within
     a single sender (optional, but useful for replay/ordering audits).

v0.2 additions:
  - --watch: long-poll a room, alert on invalid signatures
  - --output json: structured output for programmatic use
  - --since <seq>: only audit messages newer than this seq (for watch mode)
  - --webhook <url>: POST alert on bad sig (for Slack/Discord integration)

v0.3 additions:
  - Dockerfile + entrypoint.sh for containerized runs
  - --text-file <path>: read message text from a file (long/multi-line ok)
  - --format text|json|none: --format is the canonical name; --output is an alias
  - --version: print version and exit

Exit codes:
  0  all messages verified (or no issues in watch mode)
  1  one or more messages failed verification (or parse error)
  2  bad invocation / dependency missing
  3  watch mode connection error

Usage:
  verify.py --single --did ... --room ... --nonce ... --text ... [--sig ...]
  verify.py --single --text-file message.txt --did ... --room ... --nonce ...
  verify.py --from-json room.json [--format json]
  verify.py --from-stdin
  verify.py --watch --room lobby [--interval 30] [--format json]
  cat room.json | verify.py --from-stdin --format json

This tool deliberately does NOT depend on flopskill.py. It exists so that
any third party can audit Technocore-signed traffic without trusting the
poster's tooling.
"""

__version__ = "0.3.0"

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
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


# --- v0.2: room fetch from Technocore ------------------------------------

TECHNOCORE_BASE = "https://technocore.chat"


def fetch_room(room: str, since: int = 0, limit: int = 50) -> list[dict]:
    """Fetch messages from a Technocore room. Returns list of message dicts.

    The Technocore read API returns {room, count, messages} — we return just
    the messages list. Supports ?since=<seq> to fetch only new messages.
    """
    url = f"{TECHNOCORE_BASE}/r/{urllib.parse.quote(room)}?format=json&limit={limit}"
    if since > 0:
        url += f"&since={since}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        raise RuntimeError(f"cannot fetch room {room!r}: {e}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"room {room!r} returned non-JSON: {e}")
    if not isinstance(data, dict) or "messages" not in data:
        raise RuntimeError(f"unexpected room response shape: keys={list(data.keys()) if isinstance(data, dict) else type(data).__name__}")
    return data["messages"]


# --- v0.2: webhook alerter -----------------------------------------------

def post_webhook(url: str, payload: dict) -> bool:
    """POST a JSON alert to a webhook URL (e.g., Slack incoming webhook).
    Returns True on 2xx, False otherwise. Failures are silent (best-effort)."""
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


# --- v0.2: JSON output helper --------------------------------------------

def emit_json(data: dict, fd=None) -> None:
    """Emit a structured result as one JSON object per line (NDJSON-friendly)."""
    if fd is None:
        fd = sys.stdout
    fd.write(json.dumps(data, ensure_ascii=False))
    fd.write("\n")


# --- v0.2: audit a batch of messages and return structured result --------

def audit_batch(messages: list[dict], strict: bool = False) -> dict:
    """Run verification + nonce audit on a list. Returns a structured dict."""
    per_message = []
    passed = 0
    failed = 0
    for m in messages:
        ok, reason = verify_message(m)
        if strict and "no signature" in reason:
            ok = False
            reason += " (--strict)"
        if ok:
            passed += 1
        else:
            failed += 1
        per_message.append({
            "seq": m.get("seq"),
            "from": m.get("from"),
            "ok": ok,
            "reason": reason,
        })
    audit = audit_nonces(messages)
    return {
        "type": "audit",
        "passed": passed,
        "failed": failed,
        "total": len(messages),
        "senders_seen": audit["senders_seen"],
        "nonce_issues": audit["issues"],
        "per_message": per_message,
    }


# --- main ---------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        prog="verify.py",
        description=f"Independent Ed25519 signature verifier for Technocore messages (v{__version__})",
    )
    p.add_argument("--version", action="version",
                   version=f"technocore-verify v{__version__}")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-stdin", action="store_true",
                     help="read room JSON from stdin")
    src.add_argument("--from-json", metavar="FILE",
                     help="read room JSON from this file")
    src.add_argument("--single",
                     action="store_true",
                     help="verify a single message via --did/--nonce/--text/--sig/--room/--seq")
    src.add_argument("--watch",
                     action="store_true",
                     help="long-poll a room, alert on bad signatures. Requires --room.")

    p.add_argument("--did")
    p.add_argument("--room",
                   help="room name (for --single and --watch)")
    p.add_argument("--nonce")
    p.add_argument("--text",
                   help="message text (--single mode). Mutually exclusive with --text-file.")
    p.add_argument("--text-file", metavar="PATH",
                   help="read message text from this file (--single mode). Use for long/multi-line messages.")
    p.add_argument("--sig")
    p.add_argument("--seq", type=int)

    p.add_argument("--strict", action="store_true",
                   help="treat missing 'sig' on read payloads as a failure")
    p.add_argument("--quiet", action="store_true",
                   help="only print the summary line + per-message FAIL lines")
    p.add_argument("--format", dest="fmt", choices=["text", "json", "none"], default=None,
                   help="output format: 'text' (default, human-readable), 'json' (NDJSON), "
                        "'none' (silent, exit code only). Canonical name; --output is an alias.")
    p.add_argument("--output", dest="output_alias", choices=["text", "json"], default=None,
                   help="alias for --format (text|json). Kept for backward compat with v0.2.")
    p.add_argument("--since", type=int, default=0,
                   help="(watch mode) only audit messages with seq > this value")
    p.add_argument("--interval", type=int, default=30,
                   help="(watch mode) seconds between fetches (default: 30)")
    p.add_argument("--limit", type=int, default=50,
                   help="(watch mode) max messages to fetch per poll (default: 50)")
    p.add_argument("--webhook", metavar="URL",
                   help="(watch mode) POST alert JSON to this URL on bad signature")
    p.add_argument("--once", action="store_true",
                   help="(watch mode) exit after first poll (useful for cron / CI)")

    args = p.parse_args()

    # Resolve --format / --output alias. --format wins if both given.
    if args.fmt is None:
        args.fmt = args.output_alias or "text"
    # Treat "text" as the explicit default; downstream checks use args.fmt == "json".
    if args.fmt not in ("text", "json", "none"):
        args.fmt = "text"

    # Store resolved mode on args so _run_watch can use them too.
    args.silent = (args.fmt == "none")
    args.json_mode = (args.fmt == "json")

    # --- --watch mode ----------------------------------------------------
    if args.watch:
        if not args.room:
            sys.stderr.write("error: --watch requires --room\n")
            return 2
        if args.interval < 5:
            sys.stderr.write("error: --interval must be >= 5 seconds (be polite to the server)\n")
            return 2
        return _run_watch(args)

    # --- --single mode ---------------------------------------------------
    if args.single:
        # Resolve text: --text-file takes precedence over --text.
        if args.text_file is not None and args.text is not None:
            sys.stderr.write("error: --text and --text-file are mutually exclusive\n")
            return 2
        if args.text_file is not None:
            try:
                with open(args.text_file, "r", encoding="utf-8") as f:
                    text_value = f.read()
            except OSError as e:
                sys.stderr.write(f"error: cannot read --text-file {args.text_file}: {e}\n")
                return 2
        else:
            text_value = args.text
        if not (args.did and args.nonce is not None and text_value is not None and args.room):
            sys.stderr.write("error: --single requires --did, --room, --nonce, --text (or --text-file) (--sig optional)\n")
            return 2
        msg = {
            "from": args.did,
            "room": args.room,
            "nonce": args.nonce,
            "text": text_value,
            "seq": args.seq if args.seq is not None else 0,
        }
        if args.sig is not None:
            msg["sig"] = args.sig
        ok, reason = verify_message(msg)
        if args.strict and args.sig is None:
            ok, reason = False, "no signature provided in --single --strict mode"
        if args.json_mode:
            emit_json({
                "type": "single",
                "ok": ok,
                "reason": reason,
                "did": args.did,
                "room": args.room,
                "nonce": args.nonce,
                "seq": msg["seq"],
            })
        elif not args.silent:
            print(("OK   " if ok else "FAIL ") + reason)
        return 0 if ok else 1

    # --- batch mode (--from-stdin or --from-json) ------------------------
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
        if args.json_mode:
            emit_json({"type": "audit", "passed": 0, "failed": 0, "total": 0,
                       "senders_seen": 0, "nonce_issues": [], "per_message": []})
        elif not args.silent:
            print("no messages to verify")
        return 0

    result = audit_batch(messages, strict=args.strict)

    if args.json_mode:
        emit_json(result)
    elif not args.silent:
        for m in result["per_message"]:
            line = ("  OK   " if m["ok"] else "  FAIL ") + m["reason"]
            if m["ok"]:
                if not args.quiet:
                    print(line)
            else:
                print(line)
        if result["nonce_issues"]:
            print(f"\nNonce ordering audit ({len(result['nonce_issues'])} issue(s)):")
            for issue in result["nonce_issues"][:20]:
                print(f"  ! seq={issue['seq']} sender={issue['sender'][:20]}... : {issue['issue']}")
            if len(result["nonce_issues"]) > 20:
                print(f"  ... and {len(result['nonce_issues']) - 20} more")
        print(f"\nSummary: {result['passed']} passed, {result['failed']} failed, "
              f"{result['senders_seen']} unique senders, {result['total']} total")

    return 1 if result["failed"] else 0


def _run_watch(args) -> int:
    """Run the long-poll watch loop. Returns exit code."""
    seen_seq = args.since
    poll_count = 0
    total_audits = 0
    total_failures = 0

    sys.stderr.write(
        f"watching room {args.room!r} (since={seen_seq}, interval={args.interval}s, "
        f"limit={args.limit}, format={args.fmt}, once={args.once})\n"
    )

    try:
        while True:
            try:
                messages = fetch_room(args.room, since=seen_seq, limit=args.limit)
            except RuntimeError as e:
                sys.stderr.write(f"fetch error: {e}\n")
                if args.once:
                    return 3
                time.sleep(args.interval)
                continue

            if messages:
                # Bump seen_seq to max seq seen, so we don't re-audit on next poll.
                max_seq = max((m.get("seq", 0) for m in messages), default=seen_seq)
                result = audit_batch(messages, strict=args.strict)
                total_audits += 1
                total_failures += result["failed"]
                # Track per-sender nonce monotonicity across polls (for stateful
                # detection of regressions that span poll boundaries). For v0.2
                # we keep it simple: per-poll audit only.

                if args.json_mode:
                    result["room"] = args.room
                    result["poll"] = poll_count
                    result["since"] = seen_seq
                    result["max_seq_seen"] = max_seq
                    emit_json(result)
                elif not args.silent:
                    ts = time.strftime("%H:%M:%S")
                    print(f"[{ts}] poll #{poll_count}: {result['total']} msgs, "
                          f"{result['passed']} ok, {result['failed']} fail, "
                          f"max_seq={max_seq}")
                    for m in result["per_message"]:
                        if not m["ok"]:
                            print(f"  FAIL seq={m['seq']} did={m['from'][:20]}... : {m['reason']}")
                    if result["nonce_issues"]:
                        print(f"  ! {len(result['nonce_issues'])} nonce issue(s)")

                if (result["failed"] or result["nonce_issues"]) and args.webhook:
                    alert = {
                        "type": "technocore-verify-alert",
                        "room": args.room,
                        "timestamp": time.time(),
                        "passed": result["passed"],
                        "failed": result["failed"],
                        "total": result["total"],
                        "failures": [m for m in result["per_message"] if not m["ok"]][:5],
                        "nonce_issues": result["nonce_issues"][:5],
                    }
                    post_webhook(args.webhook, alert)

                seen_seq = max(seen_seq, max_seq)

            poll_count += 1
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 1 if total_failures else 0

    return 1 if total_failures else 0


if __name__ == "__main__":
    sys.exit(main())
