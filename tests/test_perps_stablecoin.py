"""
Perps settled in a USD stablecoin token (docs/PERPS_CLEARINGHOUSE.md §2) — Hyperliquid's USDC
model, the project's chosen settlement.

The clearinghouse is unchanged; only the asset that crosses its boundary is: PERP_DEPOSIT and
PERP_WITHDRAW move the configured QRC-20 token between the trader and the clearinghouse holder in
the consensus token ledger, markets are quoted in USD ("BTC-USD-PERP", oracle pair "BTC:USD"),
and native QRDX is untouched by any perp activity.
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
from qrdx.exchange import encode_exchange_txs

D = Decimal
BTC = "BTC-USD-PERP"
T0 = 1_700_000_000


class Key:
    def __init__(self):
        self.key = PQPrivateKey.generate()
        self.addr = self.key.public_key.to_address()
        self.nonce = 0

    def tx(self, op, params):
        t = ExchangeTransaction(op_type=op, sender=self.addr, nonce=self.nonce, params=params,
                                gas_limit=2_000_000, gas_price=D("1"))
        t.public_key = self.key.public_key.to_bytes()
        t.signature = self.key.sign(t.signing_bytes()).to_bytes()
        self.nonce += 1
        return t


@pytest.fixture
async def chain(monkeypatch):
    issuer, rep, alice, bob = Key(), Key(), Key(), Key()
    usd = ExchangeStateManager.derive_token_address(issuer.addr, 0, "qUSD")
    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", usd)
    monkeypatch.setattr(constants, "PERP_QUOTE", "USD")
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (rep.addr,))
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    blocks = []

    async def add(h, txs=(), alloc=()):
        bh = f"{h:064x}"
        await db.add_block(block_hash=bh, block_height=h, block_content="",
                           validator_address="0xPQ" + "00" * 32, timestamp=T0 + 2 * h)
        for i, (r, a) in enumerate(alloc):
            await db.add_transaction(tx_hash=f"a{h}{i}", block_hash=bh, tx_hex=json.dumps(
                {"type": "genesis_allocation", "recipient": r, "amount": a}))
        if txs:
            await db.add_block_exchange_txs(bh, encode_exchange_txs(list(txs)))
        blocks.append((h, list(txs)))

    await add(0, alloc=[(k.addr, "1000") for k in (issuer, rep, alice, bob)])
    await db.seed_genesis_account_state()
    await db.connection.commit()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.enforce_collateral = True
    mgr.enforce_spot_settlement = True

    async def apply(h, txs=()):
        """Store the block and apply it the way every importer does."""
        await add(h, txs)
        if txs:
            await BP.preload_sender_balances(db, txs, mgr)
            await BP.preload_token_balances(db, txs, mgr)
            ok, err, _ = BP.process_exchange_transactions(h, float(T0 + 2 * h), list(txs), mgr)
            assert ok, err
            mgr.commit_block()
            await BP.flush_exchange_balance_deltas(db, mgr, enforce=True)
            await BP.flush_token_balance_deltas(db, mgr)
        else:
            BP.run_exchange_tick(h, float(T0 + 2 * h), mgr)
        await db.connection.commit()
        return mgr._block_results

    yield db, mgr, apply, usd, issuer, rep, alice, bob
    ExchangeStateManager.reset_instance()
    path = db.db_path
    await db.close()
    os.remove(path)


async def _token_total(db, usd):
    cur = await db.connection.execute(
        "SELECT balance FROM token_balances WHERE token_address = ?", (usd,))
    return sum(D(str(r[0])) for r in await cur.fetchall())


async def _qrdx_total(db):
    cur = await db.connection.execute("SELECT balance FROM account_state")
    return sum(int(r[0]) for r in await cur.fetchall())


async def _fund(apply, issuer, rep, alice, bob):
    """The issuer mints 1,000,000 qUSD and pays each trader; the market opens at 30,000."""
    await apply(1, [issuer.tx(ExchangeOpType.TOKEN_DEPLOY, {"name": "Test USD", "symbol": "qUSD",
                                                            "decimals": 18,
                                                            "total_supply": "1000000"})])
    usd = ExchangeStateManager.derive_token_address(issuer.addr, 0, "qUSD")
    await apply(2, [issuer.tx(ExchangeOpType.TOKEN_TRANSFER,
                              {"token_address": usd, "to": who.addr, "amount": "50000"})
                    for who in (alice, bob)])
    results = await apply(3, [
        rep.tx(ExchangeOpType.CREATE_MARKET, {"base_token": "BTC"}),
        rep.tx(ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:USD", "price": "30000"}),
    ])
    assert all(r.success for r in results), [r.error for r in results]
    assert results[0].data["market_id"] == BTC


async def test_perps_settle_in_the_stablecoin_and_conserve_it(chain):
    db, mgr, apply, usd, issuer, rep, alice, bob = chain
    await _fund(apply, issuer, rep, alice, bob)
    supply, qrdx = await _token_total(db, usd), await _qrdx_total(db)
    holder = ExchangeStateManager.perps_holder_address()

    results = await apply(4, [alice.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "20000"}),
                              bob.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "20000"})])
    assert all(r.success for r in results), [r.error for r in results]
    assert await db.get_token_balance(usd, holder) == D(40000)
    assert await db.get_token_balance(usd, alice.addr) == D(30000)
    await apply(5, [bob.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "sell",
                                                       "size": "1", "price": "30000"}),
                    alice.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "buy",
                                                         "size": "1", "price": "30000"})])
    await apply(6, [rep.tx(ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:USD", "price": "33000"}),
                    bob.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "buy",
                                                       "size": "1", "price": "33000",
                                                       "reduce_only": True}),
                    alice.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "sell",
                                                         "size": "1", "price": "33000",
                                                         "reduce_only": True})])
    ch = mgr.clearinghouse
    a_out, b_out = ch.withdrawable(alice.addr), ch.withdrawable(bob.addr)
    results = await apply(7, [alice.tx(ExchangeOpType.PERP_WITHDRAW, {"amount": str(a_out)}),
                              bob.tx(ExchangeOpType.PERP_WITHDRAW, {"amount": str(b_out)})])
    assert all(r.success for r in results), [r.error for r in results]

    # Alice won in USD exactly what Bob lost; the fees stay in the holder (the vault's).
    a_gain = await db.get_token_balance(usd, alice.addr) - D(50000)
    b_loss = D(50000) - await db.get_token_balance(usd, bob.addr)
    assert a_gain > D(2900) and b_loss > D(3000)
    assert b_loss - a_gain == await db.get_token_balance(usd, holder) == ch.vault_collateral
    assert await _token_total(db, usd) == supply, "the stablecoin was created or destroyed"
    assert await _qrdx_total(db) == qrdx, "perps must not touch native QRDX any more"
    assert ch.identity_gap() == 0


async def test_an_unaffordable_stablecoin_deposit_is_refused(chain):
    db, mgr, apply, usd, issuer, rep, alice, bob = chain
    await _fund(apply, issuer, rep, alice, bob)
    results = await apply(4, [alice.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "50001"})])
    assert not results[0].success and "insufficient collateral token" in results[0].error
    assert alice.addr not in mgr.clearinghouse.accounts
    assert await db.get_token_balance(usd, alice.addr) == D(50000)


async def test_a_trader_without_the_stablecoin_cannot_deposit(chain):
    """No token balance at all (and QRDX does not count)."""
    db, mgr, apply, usd, issuer, rep, alice, bob = chain
    await _fund(apply, issuer, rep, alice, bob)
    results = await apply(4, [rep.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "10"})])
    assert not results[0].success
    assert rep.addr not in mgr.clearinghouse.accounts


async def test_no_collateral_configured_means_no_deposits(chain, monkeypatch):
    db, mgr, apply, usd, issuer, rep, alice, bob = chain
    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", "")
    results = await apply(1, [alice.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "10"})])
    assert not results[0].success and "no collateral token" in results[0].error


async def test_forward_and_rebuild_agree_on_stablecoin_perps(chain):
    """The interleaved rebuild re-derives the token ledger and the clearinghouse from the
    chain: same holder balance, same positions, same root."""
    from qrdx.derived_state_rebuild import rebuild_derived_state_interleaved
    db, mgr, apply, usd, issuer, rep, alice, bob = chain
    await _fund(apply, issuer, rep, alice, bob)
    await apply(4, [alice.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "3500"}),
                    bob.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "20000"})])
    await apply(5, [bob.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "sell",
                                                       "size": "1", "price": "30000"}),
                    alice.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "buy",
                                                         "size": "1", "price": "30000"})])
    await apply(6, [rep.tx(ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:USD", "price": "26900"})])
    await apply(7)
    ch = mgr.clearinghouse
    assert BTC not in ch.accounts[alice.addr].positions, "alice should have been liquidated"
    holder = ExchangeStateManager.perps_holder_address()
    forward = (mgr.compute_state_root(), ch.canonical(),
               await db.get_token_balance(usd, holder), await db.get_token_balances_root())

    await rebuild_derived_state_interleaved(db)
    mgr = ExchangeStateManager.get_instance()
    rebuilt = (mgr.compute_state_root(), mgr.clearinghouse.canonical(),
               await db.get_token_balance(usd, holder), await db.get_token_balances_root())
    assert rebuilt == forward
