"""
Well-formed post-quantum test addresses.

``to_account_id`` is strict about the ``0xPQ`` form — 64 hex chars, matching what
``PQPublicKey.to_address()`` actually produces — because an address the ledger
cannot key is a bug, and silently bucketing a malformed one would fork state.
Tests therefore need real-shaped addresses rather than short stubs like
``"0xPQalice"``.

``pq("alice")`` gives a deterministic, well-formed PQ address for a label, so
fixtures stay readable without hand-writing 64 hex chars.
"""

from qrdx.crypto.hashing import keccak256

__all__ = ["pq"]


def pq(label: str) -> str:
    """A deterministic, well-formed ``0xPQ`` address for a test label."""
    return "0xPQ" + keccak256(f"qrdx-test-pq:{label}".encode()).hex()
