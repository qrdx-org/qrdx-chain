"""
Perps through the exchange manager and real account_state: QRDX is conserved end to end.

tests/test_clearinghouse.py pins the clearinghouse's internal invariants. This file pins what
reaches consensus state: the only real-balance moves perps make are deposits and withdrawals
between a trader and the clearinghouse holder, so the sum of every account_state balance is
unchanged by any perp activity — however the market moves, whoever wins.
"""
import json
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx import constants
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP

D = Decimal
BTC = "BTC-QRDX-PERP"
T0 = 1_700_000_000.0


class Trader:
    def __init__(self):
        self.key = PQPrivateKey.generate()
        self.addr = self.key.public_key.to_address()
        self.nonce = 0

    def tx(self, op, params):
        tx = ExchangeTransaction(op_type=op, sender=self.addr, nonce=self.nonce, params=params,
                                 gas_limit=2_000_000, gas_price=10**9)
        tx.public_key = self.key.public_key.to_bytes()
        tx.signature = self.key.sign(tx.signing_bytes()).to_bytes()
        self.nonce += 1
        return tx


@pytest.fixture
async def env(monkeypatch):
    reporter, alice, bob = Trader(), Trader(), Trader()
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (reporter.addr,))
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    for i, who in enumerate((alice, bob)):
        await db.add_transaction(
            tx_hash=f"alloc-{i}", block_hash=f"{0:064x}",
            tx_hex=json.dumps({"type": "genesis_allocation", "recipient": who.addr,
                               "amount": "100000"}))
    await db.add_block(block_hash=f"{0:064x}", block_height=0, block_content="",
                       validator_address="0xPQ" + "00" * 32, timestamp=int(T0))
    await db.seed_genesis_account_state()
    await db.connection.commit()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.enforce_collateral = True
    yield db, mgr, reporter, alice, bob
    ExchangeStateManager.reset_instance()
    path = db.db_path
    await db.close()
    os.remove(path)


async def _block(db, mgr, height, txs):
    """Apply one block's exchange section the way an importer does."""
    await BP.preload_sender_balances(db, txs, mgr)
    ok, err, _ = BP.process_exchange_transactions(height, T0 + height, txs, mgr)
    assert ok, err
    mgr.commit_block()
    await BP.flush_exchange_balance_deltas(db, mgr, enforce=True)
    await db.connection.commit()
    return mgr._block_results


async def _total_qrdx(db):
    cur = await db.connection.execute("SELECT balance FROM account_state")
    return sum(int(r[0]) for r in await cur.fetchall())


async def test_perps_conserve_real_qrdx_end_to_end(env):
    db, mgr, reporter, alice, bob = env
    total = await _total_qrdx(db)

    await _block(db, mgr, 1, [
        reporter.tx(ExchangeOpType.CREATE_MARKET, {"base_token": "BTC"}),
        reporter.tx(ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:QRDX", "price": "30000"}),
        alice.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "20000"}),
        bob.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "20000"}),
    ])
    holder = ExchangeStateManager.perps_holder_address()
    assert await db.get_address_balance(holder) == D("40000")
    assert await _total_qrdx(db) == total

    results = await _block(db, mgr, 2, [
        bob.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "sell", "size": "1",
                                           "price": "30000"}),
        alice.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "buy", "size": "1",
                                             "price": "30000"}),
    ])
    assert all(r.success for r in results), [r.error for r in results]
    assert await _total_qrdx(db) == total, "a trade must not move real QRDX"

    # BTC rallies 10 %; both close at the new price; both withdraw everything.
    await _block(db, mgr, 3, [
        reporter.tx(ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:QRDX", "price": "33000"}),
        bob.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "buy", "size": "1",
                                           "price": "33000", "reduce_only": True}),
        alice.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "sell", "size": "1",
                                             "price": "33000", "reduce_only": True}),
    ])
    ch = mgr.clearinghouse
    a_out, b_out = ch.withdrawable(alice.addr), ch.withdrawable(bob.addr)
    await _block(db, mgr, 4, [
        alice.tx(ExchangeOpType.PERP_WITHDRAW, {"amount": str(a_out)}),
        bob.tx(ExchangeOpType.PERP_WITHDRAW, {"amount": str(b_out)}),
    ])
    # Alice won exactly what Bob lost; the fees sit in the vault, still inside the holder.
    assert await db.get_address_balance(alice.addr) - D("100000") == a_out - D("20000")
    assert a_out - D("20000") > D("2900") and D("20000") - b_out > D("3000")
    assert await db.get_address_balance(holder) == ch.vault_collateral
    assert await _total_qrdx(db) == total, "QRDX was created or destroyed"
    assert ch.identity_gap() == 0


async def test_an_unaffordable_deposit_is_refused(env):
    db, mgr, reporter, alice, bob = env
    results = await _block(db, mgr, 1, [
        alice.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "100001"})])
    assert not results[0].success and "insufficient balance" in results[0].error
    assert alice.addr not in mgr.clearinghouse.accounts


async def test_a_rejected_block_restores_the_clearinghouse(env):
    db, mgr, reporter, alice, bob = env
    await _block(db, mgr, 1, [
        reporter.tx(ExchangeOpType.CREATE_MARKET, {"base_token": "BTC"}),
        reporter.tx(ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:QRDX", "price": "30000"}),
        alice.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "20000"}),
    ])
    before_root = mgr.compute_state_root()
    before = mgr.clearinghouse.canonical()
    txs = [alice.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "buy", "size": "1",
                                                "price": "30000"})]
    mgr.take_snapshot()
    mgr.begin_block(2, T0 + 2)
    assert mgr.process_transaction(txs[0]).success
    assert mgr.clearinghouse.canonical() != before
    mgr.revert_block()
    assert mgr.clearinghouse.canonical() == before
    assert mgr.compute_state_root() == before_root


async def test_vault_ops_move_no_real_qrdx_and_a_seeder_funds_the_protocol(env, monkeypatch):
    """VAULT_DEPOSIT / VAULT_WITHDRAW move value inside the clearinghouse only; a configured
    treasury seeder's deposit becomes protocol-owned shares."""
    from qrdx.exchange.clearinghouse import PROTOCOL
    db, mgr, reporter, alice, bob = env
    monkeypatch.setattr(constants, "PERP_VAULT_SEEDERS", (bob.addr,))
    monkeypatch.setattr(constants, "PERP_VAULT_LOCKUP_SECONDS", 10)
    total = await _total_qrdx(db)
    await _block(db, mgr, 1, [
        alice.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "5000"}),
        bob.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "5000"}),
    ])
    results = await _block(db, mgr, 2, [
        alice.tx(ExchangeOpType.VAULT_DEPOSIT, {"amount": "1000"}),
        bob.tx(ExchangeOpType.VAULT_DEPOSIT, {"amount": "2000"}),
    ])
    assert [r.data.get("protocol_owned") for r in results] == [False, True]
    ch = mgr.clearinghouse
    assert ch.vault_shares == {alice.addr: D(1000), PROTOCOL: D(2000)}
    assert mgr.balance_deltas() == {}, "vault ops must not touch real balances"
    early = await _block(db, mgr, 3, [
        alice.tx(ExchangeOpType.VAULT_WITHDRAW, {"shares": "1000"})])   # 1 s later: locked
    assert not early[0].success and "locked" in early[0].error
    late = await _block(db, mgr, 20, [
        alice.tx(ExchangeOpType.VAULT_WITHDRAW, {"shares": "1000"})])
    assert late[0].success and D(late[0].data["value"]) == D(1000)
    refused = await _block(db, mgr, 21, [
        bob.tx(ExchangeOpType.VAULT_WITHDRAW, {"shares": "1"})])        # the seed is locked in
    assert not refused[0].success
    assert await _total_qrdx(db) == total
    assert ch.identity_gap() == 0
