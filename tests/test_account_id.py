"""
The canonical account-identity contract (qrdx/crypto/account_id.py).

``to_account_id`` decides what key an account's state lives under, so its
properties ARE consensus rules: every node must derive the same key from the same
address, forever. These tests pin the ones that would silently fork or merge state
if they ever changed.
"""
import pytest

from qrdx.crypto.account_id import (
    ACCOUNT_ID_LENGTH,
    is_account_id,
    same_account,
    to_account_id,
    to_account_id_bytes,
)
from qrdx.crypto.pq.dilithium import generate_keypair

from pq_addrs import pq


# ── Shape ──────────────────────────────────────────────────────────────

def test_account_id_is_always_a_20_byte_0x_string():
    for addr in (pq("a"), "0x" + "Ab" * 20, "0xPQMS" + "cd" * 19, "Q" + "1" * 44):
        aid = to_account_id(addr)
        assert is_account_id(aid), addr
        assert aid == aid.lower(), "account ids must be canonically lowercase"
        assert len(to_account_id_bytes(addr)) == ACCOUNT_ID_LENGTH


def test_traditional_address_is_its_own_account_id():
    """
    Identity for 20-byte addresses is what keeps QRDX web3-compatible: every
    existing 0x account, contract address, and Ethereum tool keeps working because
    nothing about them is remapped.
    """
    checksummed = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    assert to_account_id(checksummed) == checksummed.lower()


def test_spelling_variants_of_one_address_agree():
    """Checksummed, lowercase, bare-hex and raw-bytes forms are one account."""
    raw = bytes.fromhex("7e5f4552091a69125d5dfcb7b8c2659029395bdf")
    forms = [
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
        "7e5f4552091a69125d5dfcb7b8c2659029395bdf",
        raw,
    ]
    ids = {to_account_id(f) for f in forms}
    assert len(ids) == 1, f"spelling variants split into {ids}"


# ── Determinism & idempotence ──────────────────────────────────────────

def test_derivation_is_deterministic():
    addr = pq("deterministic")
    assert len({to_account_id(addr) for _ in range(50)}) == 1


def test_idempotent_so_it_is_safe_at_every_layer():
    """
    Applied at the RPC, DB and EVM boundaries in turn, so feeding it its own
    output must be a no-op — otherwise layering would re-derive and lose the account.
    """
    for addr in (pq("idem"), "0x" + "11" * 20, "0xPQMS" + "22" * 19):
        once = to_account_id(addr)
        assert to_account_id(once) == once
        assert to_account_id(to_account_id(once)) == once


def test_pq_address_case_does_not_change_the_account():
    addr = pq("mixedcase")
    assert to_account_id(addr.lower()) == to_account_id(addr)
    assert to_account_id(addr.upper().replace("0X", "0x", 1)) == to_account_id(addr)


# ── Injectivity ────────────────────────────────────────────────────────

def test_distinct_addresses_get_distinct_account_ids():
    ids = {to_account_id(pq(f"holder-{i}")) for i in range(200)}
    assert len(ids) == 200, "PQ account ids collided"


def test_address_families_are_domain_separated():
    """
    A PQ address and a multisig address with identical hex payloads must NOT
    collapse into one account — domain separation is what prevents that.
    """
    payload = "cd" * 19
    ms = to_account_id("0xPQMS" + payload)
    legacy = to_account_id("Q" + "1" * 44)
    traditional = to_account_id("0x" + "cd" * 20)
    assert len({ms, legacy, traditional}) == 3


def test_real_dilithium_key_resolves_consistently():
    """A key's account id must agree whether derived via the key or its address."""
    _priv, pub = generate_keypair()
    assert pub.to_account_id() == to_account_id(pub.to_address())


# ── Rejection ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    "",
    "   ",
    "0x",
    "0xnothex0000000000000000000000000000000000",
    "0xdeadbeef",                      # too short
    "0x" + "ab" * 21,                  # too long
    "0xPQ" + "ab" * 16,                # PQ but wrong length (a common stub)
    "0xPQ" + "zz" * 32,                # PQ but not hex
    "definitely not an address",
])
def test_malformed_addresses_are_rejected_not_bucketed(bad):
    """
    Strictness is deliberate. An unkeyable address must raise, never fall back to
    some default bucket — a silent bucket would merge unrelated accounts' funds.
    """
    with pytest.raises(ValueError):
        to_account_id(bad)


def test_raw_bytes_must_be_exactly_20():
    with pytest.raises(ValueError):
        to_account_id(b"\x01" * 32)


def test_same_account_is_false_rather_than_raising_on_garbage():
    assert same_account("0x" + "11" * 20, "0x" + "11" * 20) is True
    assert same_account("garbage", "0x" + "11" * 20) is False
