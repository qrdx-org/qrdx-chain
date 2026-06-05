"""
Whitepaper §3.6 compliance: the consensus state root is BLAKE3, 512-bit.

Pins the quantum-resistant hashing standard so a regression back to blake2b /
sha256 or a wrong output size is caught.
"""

import blake3

from qrdx.crypto.hashing import state_root_hash, state_root_hex, blake3_hash, STATE_ROOT_SIZE
from qrdx.exchange import ExchangeStateManager


def test_state_root_is_blake3_512bit():
    assert STATE_ROOT_SIZE == 64  # 512-bit per Whitepaper §3.6
    assert state_root_hash(b"qrdx") == blake3.blake3(b"qrdx").digest(length=64)
    assert len(state_root_hash(b"qrdx")) == 64
    assert len(state_root_hex(b"qrdx")) == 128


def test_blake3_hash_is_extendable_and_correct():
    assert blake3_hash(b"x", 32) == blake3.blake3(b"x").digest(length=32)
    assert blake3_hash(b"x", 64) == blake3.blake3(b"x").digest(length=64)
    # Distinct from blake2b/sha256 of the same input.
    import hashlib
    assert blake3_hash(b"x", 32) != hashlib.blake2b(b"x", digest_size=32).digest()
    assert blake3_hash(b"x", 32) != hashlib.sha256(b"x").digest()


def test_string_and_bytes_inputs_equivalent():
    assert state_root_hash("qrdx") == state_root_hash(b"qrdx")


def test_exchange_state_root_uses_blake3_512():
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, 1.0)
    root = m.compute_state_root()
    # 128 hex chars = 512-bit BLAKE3 output.
    assert len(root) == 128
    assert all(c in "0123456789abcdef" for c in root)
    # Deterministic for identical state.
    assert root == m.compute_state_root()
