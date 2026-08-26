#!/usr/bin/env python3
"""
technocore-verify — Python API for programmatic verification.

Most users will use the `verify` CLI in verify.py. This module exposes the
same primitives for use from notebooks, agents, or other tools.
"""
# Re-export public surface so `import api; api.did_to_pubkey(...)` works
# without duplicating implementation.
from verify import (  # noqa: F401
    did_to_pubkey,
    normalize_text,
    verify_message,
    iter_messages,
    audit_nonces,
)
