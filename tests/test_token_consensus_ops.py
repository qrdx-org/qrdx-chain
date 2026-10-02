"""
Phase E (d) inc4 — consensus token ops (TOKEN_DEPLOY / TOKEN_TRANSFER). The rest of the native
token standard (mint, burn, approvals, authorities, freezes) is in test_native_tokens.py.

Token state becomes a consensus object: deploy mints supply to the deployer and
records registry metadata; transfer moves balances; both are recorded as
deterministic per-block deltas the async flush applies to the durable token
ledger (so every node converges by replaying the same section). Pins the op
semantics, the deterministic address derivation, observe/enforce on overspend,
and the flush (registry + balances) against a real DB.
"""

import os
import tempfile
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx.exchange.state_manager import ExchangeStateManager
from qrdx.exchange.block_processor import flush_token_balance_deltas
from qrdx.database_sqlite import DatabaseSQLite

from pq_addrs import pq

ZERO_ROOT = "0" * 128


def _deploy_tx(sender, nonce=0, name="Quantum USD", symbol="qUSD", supply="1000000", decimals=18):
    return SimpleNamespace(sender=sender, nonce=nonce, params={
        "name": name, "symbol": symbol, "total_supply": supply, "decimals": decimals,
    })


def _transfer_tx(sender, token, to, amount, nonce=1):
    return SimpleNamespace(sender=sender, nonce=nonce, params={
        "token_address": token, "to": to, "amount": amount,
    })


def test_address_derivation_deterministic():
    a1 = ExchangeStateManager.derive_token_address(pq("alice"), 0, "qUSD")
    a2 = ExchangeStateManager.derive_token_address(pq("alice"), 0, "qUSD")
    a3 = ExchangeStateManager.derive_token_address(pq("alice"), 1, "qUSD")
    assert a1 == a2 and a1.startswith("0x") and len(a1) == 42
    assert a1 != a3  # nonce changes the address


def test_deploy_credits_deployer_and_records_registry():
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    deployer = pq("11x16")
    res = mgr._op_token_deploy(_deploy_tx(deployer))
    assert res.success
    token = res.data["token_address"]
    # Full supply credited as a positive token delta to the deployer.
    assert mgr.token_balance_deltas()[(deployer, token)] == Decimal("1000000")
    ops = mgr.token_registry_ops()
    assert len(ops) == 1 and ops[0]["symbol"] == "qUSD" and ops[0]["creator"] == deployer


def test_deploy_needs_a_supply_or_a_mint_authority():
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    res = mgr._op_token_deploy(_deploy_tx(pq("z"), supply="0"))
    assert not res.success and "mint authority" in res.error
    res = mgr._op_token_deploy(_deploy_tx(pq("z"), supply="-5"))
    assert not res.success and "non-negative" in res.error
    tx = _deploy_tx(pq("z"), nonce=1, supply="0")
    tx.params["mint_authority"] = pq("z")              # a bridge's token starts at zero
    assert mgr._op_token_deploy(tx).success


def _deployed(mgr, owner, supply="1000"):
    token = mgr._op_token_deploy(_deploy_tx(owner, supply=supply)).data["token_address"]
    return token


def test_transfer_moves_balances():
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    alice = pq("aax16")
    bob = pq("bbx16")
    token = _deployed(mgr, alice)
    mgr._op_token_transfer(_transfer_tx(alice, token, bob, "250"))
    d = mgr.token_balance_deltas()
    assert d[(alice, token)] == Decimal("750")          # 1000 deployed − 250
    assert d[(bob, token)] == Decimal("250")


def test_transfer_of_an_unknown_token_is_refused():
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    res = mgr._op_token_transfer(_transfer_tx(pq("aax16"), "0xTOK", pq("bob"), "1"))
    assert not res.success and "unknown token" in res.error
    assert mgr.token_balance_deltas() == {}


def test_transfer_observe_allows_overspend_warns(caplog):
    import logging
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    alice = pq("aax16")
    token = _deployed(mgr, alice)
    mgr.set_available_token_balance(alice, token, Decimal("100"))
    with caplog.at_level(logging.WARNING):
        res = mgr._op_token_transfer(_transfer_tx(alice, token, pq("bob"), "250"))
    assert res.success  # observe: still executes
    assert any("Phase E observe" in r.message for r in caplog.records)


def test_transfer_enforce_rejects_overspend():
    mgr = ExchangeStateManager()
    mgr.enforce_spot_settlement = True
    mgr.begin_block(1, 0.0)
    alice = pq("aax16")
    token = _deployed(mgr, alice)
    mgr.set_available_token_balance(alice, token, Decimal("100"))
    before = mgr.token_balance_deltas()
    res = mgr._op_token_transfer(_transfer_tx(alice, token, pq("bob"), "250"))
    assert not res.success and "insufficient token balance" in res.error
    assert mgr.token_balance_deltas() == before  # nothing moved


def test_transfer_enforce_refuses_a_balance_that_was_not_loaded():
    """Every debit's balance is preloaded with its block; one that was not (a gap in the
    preload list) is refused, never debited unchecked."""
    mgr = ExchangeStateManager()
    mgr.enforce_spot_settlement = True
    mgr.begin_block(1, 0.0)
    alice = pq("aax16")
    token = _deployed(mgr, alice)
    before = mgr.token_balance_deltas()
    res = mgr._op_token_transfer(_transfer_tx(alice, token, pq("bob"), "1"))
    assert not res.success and "not loaded" in res.error
    assert mgr.token_balance_deltas() == before


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = await DatabaseSQLite.create(path)
    yield database
    await database.connection.close()
    for p in (path, path + "-wal", path + "-shm"):
        try:
            os.remove(p)
        except OSError:
            pass


async def test_flush_applies_registry_and_balances(db):
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    deployer = pq("11x16")
    res = mgr._op_token_deploy(_deploy_tx(deployer))
    token = res.data["token_address"]
    mgr.commit_block()

    await flush_token_balance_deltas(db, mgr)
    await db.connection.commit()

    # Balance landed in the ledger and the registry row exists.
    assert await db.get_token_balance(token, deployer) == Decimal("1000000")
    cur = await db.connection.execute(
        "SELECT symbol, owner_address FROM token_registry WHERE token_address = ?", (token,))
    row = await cur.fetchone()
    assert row[0] == "qUSD" and row[1] == deployer
    # Token root is now non-zero (state exists).
    assert await db.get_token_balances_root() != ZERO_ROOT
