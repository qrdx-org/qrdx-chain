"""
Funding (docs/PERPS_CLEARINGHOUSE.md, Phase 4) — Hyperliquid's formula, peer to peer.

Every block samples the premium of the book's impact prices over the oracle, weighted by block
time. At each interval boundary of block time, F = average premium + clamp(interest − premium,
±0.05 %) is the 8-hour rate; the interval's share is paid, capped at 4 % per hour. Each position
pays size × oracle × rate — longs to shorts when it is positive — so the payments sum to exactly
zero (rounding dust to the vault). Nothing is minted to pay funding, and nothing is burned.
"""
from decimal import Decimal

import pytest

from qrdx.exchange.clearinghouse import (
    VAULT, Clearinghouse, FUNDING_CAP_PER_HOUR, FUNDING_INTEREST_8H, FUNDING_PREMIUM_CLAMP,
)

D = Decimal
BTC = "BTC-QRDX-PERP"
HOUR = D(3600)
T0 = D(1_700_000_000 // 3600 * 3600)          # on an hour boundary


def _ch(positions=(("alice", "bob", 1),), deposit=D(100_000)):
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D(30000))
    for buyer, seller, size in positions:
        for who in (buyer, seller):
            if who not in ch.accounts:
                ch.deposit(who, deposit)
        ch.place_order(seller, BTC, f"s-{buyer}-{seller}", "sell", D(size), D(30000), 0)
        ch.place_order(buyer, BTC, f"b-{buyer}-{seller}", "buy", D(size), D(30000), 0)
    return ch


def _value(ch):
    """Σ collateral + isolated margins: what funding may move between accounts, never create."""
    return sum((a.collateral + sum((p.isolated_margin for p in a.positions.values()), D(0))
                for a in ch.accounts.values()), D(0))


def _run_hour(ch, step=D(2)):
    """Tick through one funding interval of block time; returns the collateral moves."""
    before = {o: a.collateral for o, a in ch.accounts.items()}
    t = T0
    ch.tick(t)                                          # sets the first boundary
    while t < T0 + HOUR:
        t += step
        ch.tick(t)
    return {o: ch.accounts[o].collateral - before.get(o, D(0)) for o in ch.accounts}


def test_interest_alone_has_longs_pay_shorts_exactly():
    ch = _ch()
    total = _value(ch)
    moves = _run_hour(ch)
    rate = FUNDING_INTEREST_8H / 8                      # no book: premium 0, interest only
    assert ch.markets[BTC].funding_rate == rate
    assert moves["alice"] == -D(30000) * rate and moves["bob"] == D(30000) * rate
    assert _value(ch) == total and ch.identity_gap() == 0


def test_a_book_bid_above_the_oracle_makes_longs_pay_the_premium():
    ch = _ch()
    ch.deposit("mm", D(1_000_000))
    ch.place_order("mm", BTC, "bid", "buy", D(1), D(30300), 0)    # impact bid 1 % over
    _run_hour(ch)
    f8 = D("0.01") - FUNDING_PREMIUM_CLAMP                         # 0.01 + clamp(0.0001 − 0.01)
    assert ch.markets[BTC].funding_rate == f8 / 8
    assert ch.identity_gap() == 0


def test_a_book_ask_below_the_oracle_makes_shorts_pay():
    ch = _ch()
    ch.deposit("mm", D(1_000_000))
    ch.place_order("mm", BTC, "ask", "sell", D(1), D(29700), 0)
    moves = _run_hour(ch)
    assert ch.markets[BTC].funding_rate < 0
    assert moves["bob"] < 0 < moves["alice"]


def test_a_shallow_book_is_no_impact_price():
    """Less than the impact notional resting: that side contributes no premium."""
    ch = _ch()
    ch.deposit("mm", D(1_000_000))
    ch.place_order("mm", BTC, "bid", "buy", D("0.01"), D(36000), 0)   # 360 QRDX < 1,000
    _run_hour(ch)
    assert ch.markets[BTC].funding_rate == FUNDING_INTEREST_8H / 8


def test_the_rate_is_capped_per_hour():
    ch = _ch()
    ch.deposit("mm", D(10_000_000))
    ch.place_order("mm", BTC, "bid", "buy", D(1), D(60000), 0)        # a 100 % premium
    _run_hour(ch)
    assert ch.markets[BTC].funding_rate == FUNDING_CAP_PER_HOUR


def test_nothing_is_paid_before_the_boundary_and_once_at_it():
    ch = _ch()
    a = ch.accounts["alice"]
    start = a.collateral
    ch.tick(T0 + 1)
    ch.tick(T0 + HOUR - 1)
    assert a.collateral == start
    ch.tick(T0 + HOUR)
    paid = start - a.collateral
    assert paid > 0
    ch.tick(T0 + HOUR + 2)
    assert start - a.collateral == paid, "one interval, one payment"
    m = ch.markets[BTC]
    assert m.premium_time == 2 and m.funding_time == T0 + HOUR


def test_isolated_positions_pay_from_their_own_margin():
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D(30000))
    for who in ("alice", "bob"):
        ch.deposit(who, D(100_000))
    ch.set_leverage("alice", BTC, D(10), isolated=True)
    ch.place_order("bob", BTC, "s", "sell", D(1), D(30000), 0)
    ch.place_order("alice", BTC, "b", "buy", D(1), D(30000), 0)
    cross, margin = ch.accounts["alice"].collateral, ch.accounts["alice"].positions[BTC].isolated_margin
    _run_hour(ch)
    rate = FUNDING_INTEREST_8H / 8
    assert ch.accounts["alice"].collateral == cross
    assert ch.accounts["alice"].positions[BTC].isolated_margin == margin - D(30000) * rate


def test_payments_sum_to_exactly_zero_with_rounding_dust_to_the_vault():
    """Sizes and a price that do not divide evenly: each payment rounds to wei, the vault takes
    the few wei left over, and the total is unchanged to the last digit."""
    ch = _ch(positions=(("a", "b", D("0.333333333333333333")), ("c", "b", D("0.7")),
                        ("c", "d", D("1.123456789"))))
    ch.set_oracle_price(BTC, D("29999.999999999999999999"))
    total = _value(ch)
    _run_hour(ch)
    assert _value(ch) == total and ch.identity_gap() == 0
    assert ch.net_size(BTC) == 0
    assert VAULT in ch.accounts


# ── the chain: forward ≡ rebuild across several settlements ──────────────

async def test_forward_and_rebuild_pay_the_same_funding(monkeypatch):
    import json
    import os
    import tempfile
    from qrdx import constants
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.derived_state_rebuild import rebuild_derived_state_interleaved
    from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
    from qrdx.exchange import block_processor as BP
    from qrdx.exchange import encode_exchange_txs

    keys = [PQPrivateKey.generate() for _ in range(3)]
    rep, alice, bob = (k.public_key.to_address() for k in keys)
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (rep,))
    monkeypatch.setattr(constants, "PERP_FUNDING_INTERVAL_SECONDS", 60)
    nonces = {a: 0 for a in (rep, alice, bob)}

    def tx(i, op, params):
        addr = keys[i].public_key.to_address()
        t = ExchangeTransaction(op_type=op, sender=addr, nonce=nonces[addr], params=params,
                                gas_limit=2_000_000, gas_price=10**9)
        nonces[addr] += 1
        t.public_key = keys[i].public_key.to_bytes()
        t.signature = keys[i].sign(t.signing_bytes()).to_bytes()
        return t

    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    try:
        async def add(h, txs=None, alloc=None):
            bh = f"{h:064x}"
            await db.add_block(block_hash=bh, block_height=h, block_content="",
                               validator_address="0xPQ" + "00" * 32, timestamp=int(T0) + 7 * h)
            for i, (r, a) in enumerate(alloc or []):
                await db.add_transaction(tx_hash=f"a{h}{i}", block_hash=bh, tx_hex=json.dumps(
                    {"type": "genesis_allocation", "recipient": r, "amount": a}))
            if txs:
                await db.add_block_exchange_txs(bh, encode_exchange_txs(txs))

        await add(0, alloc=[(alice, "100000"), (bob, "100000"), (rep, "1000")])  # rep pays gas
        await add(1, [tx(0, ExchangeOpType.CREATE_MARKET, {"base_token": "BTC"}),
                      tx(0, ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:QRDX", "price": "30000"}),
                      tx(1, ExchangeOpType.PERP_DEPOSIT, {"amount": "50000"}),
                      tx(2, ExchangeOpType.PERP_DEPOSIT, {"amount": "50000"})])
        await add(2, [tx(2, ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "sell",
                                                        "size": "1", "price": "30000"}),
                      tx(1, ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "buy",
                                                        "size": "1", "price": "30000"}),
                      tx(2, ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "buy",
                                                        "size": "1", "price": "30150"})])
        for h in range(3, 60):                         # ~6.5 minutes: several settlements
            await add(h)
        tip = 59

        await db.seed_genesis_account_state()
        await db.connection.commit()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        mgr.enforce_collateral = True
        mgr.enforce_fees = BP.ENFORCE_EXCHANGE_FEES          # as the rebuild does
        for h in range(1, tip + 1):
            section = await db.get_block_exchange_txs(f"{h:064x}")
            ts = float(int(T0) + 7 * h)
            if section:
                txs = BP.decode_exchange_txs(section)
                await BP.preload_sender_balances(db, txs, mgr)
                ok, err, _ = BP.process_exchange_transactions(h, ts, txs, mgr)
                assert ok, err
                mgr.commit_block()
                await BP.flush_exchange_balance_deltas(db, mgr, enforce=True)
            else:
                BP.run_exchange_tick(h, ts, mgr)
        await db.connection.commit()
        ch = mgr.clearinghouse
        assert ch.markets[BTC].funding_rate > 0, "the premium bid should have made longs pay"
        assert ch.accounts[alice].collateral < D(50000) - D(15)
        forward_root, forward_state = mgr.compute_state_root(), ch.canonical()

        await rebuild_derived_state_interleaved(db)
        mgr = ExchangeStateManager.get_instance()
        assert mgr.clearinghouse.canonical() == forward_state
        assert mgr.compute_state_root() == forward_root
    finally:
        ExchangeStateManager.reset_instance()
        path = db.db_path
        await db.close()
        os.remove(path)
