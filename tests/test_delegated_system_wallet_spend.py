"""
System-wallet spends: a controller may move a system wallet's funds; nobody else may.

A system wallet is spent by its **controller** — a PQ address or an m-of-n multisig — and
holds no key of its own. But a type-0x51 transaction derives its sender from the signing
key, deliberately: there is no sender field on the wire, so nothing can be forged. A
controller therefore could not sign for the wallet, and `--from-system-wallet` had no
working path at all (it built UTXO transactions against an empty UTXO set).

The fix adds an optional `on_behalf_of` field INSIDE the signing hash. The signer still
pays gas and consumes its own nonce; only the value leaves the delegated source. The node
then has to authorise the relationship against the genesis-registered `system_wallets`
table before any value moves.

The property that matters most here is **where** the authorisation runs: at the shared
choke point used by BOTH mempool admission and block import. A check applied only at
submission would let a proposer smuggle an unauthorised delegated spend into a block —
the same hole the PQ signature check sits there to close.
"""
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.contracts.evm_mempool import parse_eth_raw_tx, verify_delegated_spend
from qrdx.crypto.account_id import to_account_id
from qrdx.crypto.pq.dilithium import generate_keypair
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.transactions.pq_tx import InvalidPQTransaction, PQTransaction, decode_pq_tx

from pq_addrs import pq
from qrdx.constants import CHAIN_ID  # the network's chain id (chain spec)

RECIPIENT = bytes.fromhex("cd" * 20)


def _tx(priv, on_behalf_of=None, nonce=0, value=10 ** 18):
    return PQTransaction(
        chain_id=CHAIN_ID, nonce=nonce, gas_price=10 ** 9, gas_limit=500_000,
        to=RECIPIENT, value=value, data=b"", on_behalf_of=on_behalf_of,
    ).sign(priv)


async def _db_with_system_wallet(wallet_addr, controller_addr):
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    await db.connection.execute(
        "INSERT INTO system_wallets (address, name, description, wallet_type, "
        "controller_address, is_burner, category) VALUES (?, 'Treasury', 'test', "
        "'treasury', ?, 0, 'core')",
        (wallet_addr, controller_addr))
    await db.connection.commit()
    return db


async def _close(db):
    path = db.db_path
    await db.close()
    os.remove(path)


# ── The signed envelope ────────────────────────────────────────────────────

def test_the_delegated_source_is_covered_by_the_signature():
    """If it were outside the signing hash, anyone could redirect the spend in flight."""
    priv, _pub = generate_keypair()
    tx = decode_pq_tx(_tx(priv, on_behalf_of=bytes.fromhex("ab" * 20)).encode())
    assert tx.verify()
    tx.on_behalf_of = bytes.fromhex("ee" * 20)
    assert tx.verify() is False, "on_behalf_of is not signed — it can be tampered with"


def test_an_ordinary_transaction_spends_from_its_signer():
    priv, pub = generate_keypair()
    tx = decode_pq_tx(_tx(priv).encode())
    assert tx.is_delegated() is False
    assert tx.spend_from() == tx.sender() == pub.to_account_id()


def test_a_delegated_transaction_separates_signer_from_source():
    priv, pub = generate_keypair()
    source = bytes.fromhex("ab" * 20)
    tx = decode_pq_tx(_tx(priv, on_behalf_of=source).encode())
    assert tx.is_delegated()
    assert tx.sender() == pub.to_account_id()
    assert tx.spend_from() == to_account_id(source) != tx.sender()


def test_a_wrong_sized_delegated_source_is_rejected():
    priv, _pub = generate_keypair()
    import rlp
    from qrdx.transactions.pq_tx import PQ_TX_TYPE
    tx = _tx(priv, on_behalf_of=bytes.fromhex("ab" * 20))
    fields = tx._unsigned_fields()
    fields[7] = b"\x11" * 32
    raw = bytes([PQ_TX_TYPE]) + rlp.encode(fields + [tx.public_key, tx.signature])
    with pytest.raises(InvalidPQTransaction, match="on_behalf_of"):
        decode_pq_tx(raw)


def test_the_parser_reports_the_spend_source():
    priv, _pub = generate_keypair()
    source = bytes.fromhex("ab" * 20)
    parsed = parse_eth_raw_tx("0x" + _tx(priv, on_behalf_of=source).encode().hex())
    assert parsed["spend_from"] == to_account_id(source)
    assert parsed["sender"] != parsed["spend_from"]


def test_a_legacy_transaction_reports_itself_as_its_own_source():
    from eth_account import Account as EthAccount
    from eth_utils import to_checksum_address
    key = "0x" + "e5" * 32
    signed = EthAccount.sign_transaction(
        {"nonce": 0, "gasPrice": 10 ** 9, "gas": 21000,
         "to": to_checksum_address("0x" + "cd" * 20), "value": 1, "data": b"",
         "chainId": CHAIN_ID}, key)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    parsed = parse_eth_raw_tx("0x" + bytes(raw).hex())
    assert parsed["spend_from"] == parsed["sender"]


# ── Authorisation ──────────────────────────────────────────────────────────

async def test_the_controller_may_spend_from_its_system_wallet():
    priv, pub = generate_keypair()
    wallet = pq("treasury-wallet")
    db = await _db_with_system_wallet(wallet, pub.to_address())
    try:
        raw = "0x" + _tx(priv, on_behalf_of=bytes.fromhex(to_account_id(wallet)[2:])).encode().hex()
        ok, why = await verify_delegated_spend(db, raw)
        assert ok, why
    finally:
        await _close(db)


async def test_a_non_controller_may_not():
    """The core authorisation property."""
    _priv_ctrl, pub_ctrl = generate_keypair()
    attacker_priv, _pub_att = generate_keypair()
    wallet = pq("treasury-wallet-2")
    db = await _db_with_system_wallet(wallet, pub_ctrl.to_address())
    try:
        raw = "0x" + _tx(attacker_priv,
                         on_behalf_of=bytes.fromhex(to_account_id(wallet)[2:])).encode().hex()
        ok, why = await verify_delegated_spend(db, raw)
        assert not ok
        assert "not the controller" in why
    finally:
        await _close(db)


async def test_an_ordinary_account_is_not_delegable():
    """Only registered system wallets may be spent on behalf of."""
    priv, _pub = generate_keypair()
    db = await _db_with_system_wallet(pq("some-wallet"), pq("some-controller"))
    try:
        raw = "0x" + _tx(priv, on_behalf_of=bytes.fromhex("99" * 20)).encode().hex()
        ok, why = await verify_delegated_spend(db, raw)
        assert not ok
        assert "not a system wallet" in why
    finally:
        await _close(db)


async def test_authorisation_fails_closed_when_the_registry_is_unreadable():
    """
    A delegated spend is exactly the operation that must never be waved through on a
    check that did not run.
    """
    class Broken:
        class connection:
            @staticmethod
            async def execute(*_a, **_k):
                raise RuntimeError("no such table: system_wallets")

    priv, _pub = generate_keypair()
    raw = "0x" + _tx(priv, on_behalf_of=bytes.fromhex("ab" * 20)).encode().hex()
    ok, why = await verify_delegated_spend(Broken(), raw)
    assert not ok and "unreadable" in why


async def test_non_delegated_transactions_pass_unconditionally():
    """So callers can apply the check to every transaction without branching."""
    priv, _pub = generate_keypair()
    db = await _db_with_system_wallet(pq("w"), pq("c"))
    try:
        assert (await verify_delegated_spend(db, "0x" + _tx(priv).encode().hex()))[0]
        assert (await verify_delegated_spend(db, "0xdeadbeef"))[0]
        assert (await verify_delegated_spend(db, "not-hex"))[0]
    finally:
        await _close(db)


# ── The check runs at BOTH choke points ────────────────────────────────────

def test_block_import_authorises_delegated_spends_too():
    """
    Authorising only at submission would let a proposer smuggle an unauthorised delegated
    spend into a block. Asserted at the source, because reaching this path live needs a
    full node plus a forged block.
    """
    import inspect

    from qrdx.contracts import evm_block_apply

    src = inspect.getsource(evm_block_apply.apply_block_evm_section)
    assert "verify_delegated_spend" in src, (
        "apply_block_evm_section does not authorise delegated spends — a proposer could "
        "include one the mempool would have refused")
    assert src.index("verify_delegated_spend") < src.index("execute_tx("), (
        "the delegated-spend check must run BEFORE any transaction executes")


def test_rpc_admission_authorises_delegated_spends():
    import inspect

    from qrdx.node import main as node_main

    src = inspect.getsource(node_main)
    handler = src[src.index("async def eth_sendRawTransaction_handler"):]
    handler = handler[:handler.index("rpc_server.register_method")]
    assert "verify_delegated_spend" in handler, (
        "eth_sendRawTransaction admits delegated spends without authorising them")
