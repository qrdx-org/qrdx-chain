"""
Liquidations and the backstop vault (docs/PERPS_CLEARINGHOUSE.md, Phase 3).

Hyperliquid's sequence, run in the per-block tick at the new mark prices:
  1. an account below maintenance margin has its orders cancelled and its positions closed on
     the book — never past the bankruptcy price, so a book fill cannot create bad debt;
  2. one still below 2/3 of maintenance is taken over by the backstop vault at mark, with
     whatever margin is left (an isolated position only with its own margin);
  3. one the vault cannot cover is auto-deleveraged against the most profitable, most
     leveraged opposite positions, at a price that returns it to exactly zero.
Everything is a transfer between internal records: the clearinghouse identity stays exact and
every market's net size stays zero, through any crash.
"""
import random
from decimal import Decimal

import pytest

from qrdx.exchange.clearinghouse import (
    PROTOCOL, VAULT, Clearinghouse, ClearinghouseError, MAKER_FEE_RATE, TAKER_FEE_RATE,
)

D = Decimal
BTC = "BTC-QRDX-PERP"
T0 = D(1_700_000_000)
DUST = D("1e-6")


def _ch():
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D(30000))
    return ch


def _open(ch, buyer, seller, size, price, buyer_deposit, seller_deposit=D(10_000_000)):
    """``seller`` rests a sell, ``buyer`` lifts it: buyer long, seller short."""
    for who, amount in ((buyer, buyer_deposit), (seller, seller_deposit)):
        if amount:
            ch.deposit(who, D(amount))
    ch.place_order(seller, BTC, f"s-{buyer}-{seller}", "sell", D(size), D(price), 0)
    ch.place_order(buyer, BTC, f"b-{buyer}-{seller}", "buy", D(size), D(price), 0)


def _equity(ch, owner):
    a = ch.accounts[owner]
    values = [ch.cross_equity(owner)]
    for mid, p in a.positions.items():
        if a.isolated.get(mid, False):
            values.append(ch._iso_equity(a, mid))
    return min(values)


def _sound(ch):
    assert ch.identity_gap() == 0
    for mid in ch.markets:
        assert ch.net_size(mid) == 0
    for owner in ch.accounts:
        assert _equity(ch, owner) >= -DUST, f"{owner} ended negative: {_equity(ch, owner)}"


def _crash(ch, price, now=T0):
    ch.set_oracle_price(BTC, D(price))
    return ch.tick(now)


# ── 1. the book first ──────────────────────────────────────────────────────

def test_book_first_liquidation_leaves_the_remainder_with_the_trader():
    ch = _ch()
    _open(ch, "alice", "bob", 1, 30000, 3500)              # 10x: 3,000 margin, 15 taker fee
    assert ch.accounts["alice"].collateral == D(3485)
    ch.deposit("carol", D(1_000_000))
    ch.place_order("carol", BTC, "c1", "buy", D(1), D(26900), 0)
    events = _crash(ch, 27000)                              # equity 485 < maintenance 675
    assert [(e["owner"], e["stage"], e["filled"]) for e in events] == [("alice", "book", 1)]
    a = ch.accounts["alice"]
    assert BTC not in a.positions
    assert a.collateral == D(3485) - D(3100) - D(26900) * TAKER_FEE_RATE
    assert ch.accounts["carol"].positions[BTC].size == 1
    _sound(ch)


def test_a_partial_book_fill_that_restores_maintenance_stops_there():
    ch = _ch()
    _open(ch, "alice", "bob", 2, 30000, 7000)              # collateral 6,970
    ch.deposit("carol", D(1_000_000))
    ch.place_order("carol", BTC, "c1", "buy", D(1), D(26990), 0)   # room for half
    events = _crash(ch, 27000)                              # equity 970 < maintenance 1,350
    assert [(e["stage"], e["filled"]) for e in events] == [("book", 1)]
    a = ch.accounts["alice"]
    assert a.positions[BTC].size == 1                       # the rest is healthy: kept
    assert ch.cross_equity("alice") >= ch.cross_maintenance("alice")
    _sound(ch)


def test_no_book_fill_is_worse_than_the_bankruptcy_price():
    """The only bid is absurd: filling there would leave the account deeply negative, a loss
    someone else would carry. The liquidation refuses it and the backstop takes over."""
    ch = _ch()
    _open(ch, "alice", "bob", 1, 30000, 3500)
    ch.deposit("carol", D(1_000_000))
    ch.place_order("carol", BTC, "c1", "buy", D(1), D(20000), 0)
    events = _crash(ch, 26900)
    assert [e["stage"] for e in events] == ["backstop"]
    assert "carol" not in ch.markets[BTC].orders.get("c1", type("x", (), {"owner": ""})).owner \
        or ch.markets[BTC].book.get_order("c1").filled == 0
    assert BTC not in ch.accounts["carol"].positions
    _sound(ch)


# ── 2. the backstop vault ──────────────────────────────────────────────────

def test_the_vault_takes_over_at_mark_with_the_remaining_margin():
    ch = _ch()
    _open(ch, "alice", "bob", 1, 30000, 3500)
    fees = D(30000) * (MAKER_FEE_RATE + TAKER_FEE_RATE)    # 21: already the vault's
    assert ch.vault_collateral == fees
    events = _crash(ch, 26900)                              # equity 385 < 2/3 × 672.5
    assert [e["stage"] for e in events] == ["backstop"]
    assert BTC not in ch.accounts["alice"].positions
    assert ch.accounts["alice"].collateral == 0
    vault = ch.accounts[VAULT]
    assert vault.positions[BTC].size == 1 and vault.positions[BTC].entry_price == D(26900)
    assert ch.vault_collateral == fees + D(385)
    _sound(ch)


def test_an_isolated_backstop_takes_only_that_positions_margin():
    ch = _ch()
    ch.deposit("alice", D(10000))
    ch.set_leverage("alice", BTC, D(10), isolated=True)
    _open(ch, "alice", "bob", 1, 30000, 0)
    assert ch.accounts["alice"].collateral == D(10000) - D(3000) - D(15)
    events = _crash(ch, 27400)                              # isolated equity 400 < 2/3 × 685
    assert [(e["mode"], e["stage"]) for e in events] == [("isolated", "backstop")]
    assert ch.accounts["alice"].collateral == D(6985), "cross collateral must be untouched"
    assert BTC not in ch.accounts["alice"].positions
    assert ch.vault_collateral == D(21) + D(400)
    _sound(ch)


# ── 3. auto-deleveraging ───────────────────────────────────────────────────

def test_bad_debt_beyond_the_vault_is_auto_deleveraged_to_exactly_zero():
    ch = _ch()
    _open(ch, "alice", "bob", 1, 30000, 3500)              # vault holds only the 21 of fees
    events = _crash(ch, 26000)                              # equity −515: bankrupt
    assert [e["stage"] for e in events] == ["adl"]
    assert BTC not in ch.accounts["alice"].positions
    assert ch.accounts["alice"].collateral == 0
    # Bob closed at alice's bankruptcy price, 26,515: he gives up 515 of his 4,000 profit.
    assert BTC not in ch.accounts["bob"].positions
    assert ch.accounts["bob"].collateral == D(10_000_000) - D(6) + D(3485)
    assert ch.vault_collateral == D(21), "the vault was not touched"
    _sound(ch)


def test_auto_deleveraging_takes_the_most_profitable_most_leveraged_position_first():
    ch = _ch()
    _open(ch, "carol", "bob", 1, 30000, 1_000_000, 10_000_000)   # bob: short, barely levered
    _open(ch, "alice", "dave", 1, 30000, 3500, 5000)              # dave: short, highly levered
    events = _crash(ch, 26000)
    assert [(e["owner"], e["stage"]) for e in events] == [("alice", "adl")]
    assert BTC not in ch.accounts["dave"].positions
    assert ch.accounts["bob"].positions[BTC].size == -1
    _sound(ch)


def test_orders_are_cancelled_before_the_book_close():
    """Resting orders reserve margin and could reopen exposure; a liquidation cancels them."""
    ch = _ch()
    _open(ch, "alice", "bob", 1, 30000, 3500)
    ch.place_order("alice", BTC, "a-ask", "sell", D(1), D(40000), 0, reduce_only=True)
    ch.place_order("alice", BTC, "a-bid", "buy", D("0.05"), D(20000), 0)
    assert {m.owner for m in ch.markets[BTC].orders.values()} == {"alice"}
    _crash(ch, 26900)
    assert not ch.markets[BTC].orders
    _sound(ch)


# ── the vault's shares ─────────────────────────────────────────────────────

def test_vault_shares_are_priced_at_nav_and_locked():
    ch = _ch()
    _open(ch, "alice", "bob", 1, 30000, 3500)              # 21 of fees, no shares yet
    ch.deposit("eve", D(5000))
    assert ch.vault_deposit("eve", D(1000), T0, D(3600)) == D(1000)
    # The fees that accrued before anyone held a share belong to the protocol, not to eve.
    assert ch.vault_shares[PROTOCOL] == D(21) and ch.vault_nav() == D(1021)
    with pytest.raises(ClearinghouseError, match="locked"):
        ch.vault_withdraw("eve", D(1000), T0 + 3599)
    assert ch.vault_withdraw("eve", D(1000), T0 + 3600) == D(1000)
    assert ch.accounts["eve"].collateral == D(5000) and "eve" not in ch.vault_shares
    _sound(ch)


def test_a_treasury_seed_is_protocol_owned_and_never_withdrawable():
    ch = _ch()
    ch.deposit("seeder", D(10000))
    ch.vault_deposit("seeder", D(10000), T0, D(0), protocol=True)
    assert ch.vault_shares == {PROTOCOL: D(10000)}
    with pytest.raises(ClearinghouseError, match="only 0 vault shares"):
        ch.vault_withdraw("seeder", D(1), T0 + 10**9)
    for op in (lambda: ch.vault_withdraw(PROTOCOL, D(1), T0 + 10**9),
               lambda: ch.deposit(VAULT, D(1)),
               lambda: ch.place_order(VAULT, BTC, "x", "buy", D(1), D(30000), 0)):
        with pytest.raises(ClearinghouseError, match="reserved"):
            op()
    _sound(ch)


def test_a_vault_deposit_needs_free_collateral():
    ch = _ch()
    _open(ch, "alice", "bob", 1, 30000, 3500)              # alice's margin is in use
    with pytest.raises(ClearinghouseError, match="exceeds the withdrawable"):
        ch.vault_deposit("alice", D(3000), T0, D(0))


def test_the_vault_cannot_pay_out_capital_its_positions_need():
    ch = _ch()
    ch.deposit("eve", D(1000))
    ch.vault_deposit("eve", D(1000), T0, D(0))
    _open(ch, "alice", "bob", 1, 30000, 3500)
    _crash(ch, 26900)                                       # the vault now carries alice's long
    assert ch.accounts[VAULT].positions[BTC].size == 1
    with pytest.raises(ClearinghouseError, match="cannot release"):
        ch.vault_withdraw("eve", ch.vault_shares["eve"], T0 + 1)
    _sound(ch)


def test_a_wiped_out_vault_writes_off_its_shares_and_reopens():
    ch = _ch()
    ch.vault_shares, ch.vault_total_shares = {"old": D(5)}, D(5)   # shares, no value left
    ch.deposit("eve", D(100))
    assert ch.vault_deposit("eve", D(100), T0, D(0)) == D(100)
    assert ch.vault_shares == {"eve": D(100)}


# ── randomized: crashes, spikes, thin books ────────────────────────────────

def _random_run(seed, steps=160, vault_capital=20000):
    rng = random.Random(seed)
    ch = _ch()
    traders = [f"t{i}" for i in range(8)]
    for t in traders:
        ch.deposit(t, D(rng.randint(1500, 20000)))
        ch.set_leverage(t, BTC, D(rng.choice([2, 5, 10, 20])), rng.random() < 0.4)
    ch.deposit("mm", D(100_000_000))
    ch.deposit("lp", D(30000))
    if vault_capital:
        ch.vault_deposit("lp", D(vault_capital), T0, D(0))
    oracle, now, n = D(30000), T0, 0
    for _ in range(steps):
        now += 2
        ch.new_block()
        for oid in sorted(o for o, meta in ch.markets[BTC].orders.items() if meta.owner == "mm"):
            ch.cancel_order("mm", BTC, oid)
        if rng.random() < 0.7:                              # a thin, sometimes-absent book
            spread = D(rng.choice(["0.001", "0.005", "0.02"]))
            for side, k in (("buy", 1 - spread), ("sell", 1 + spread)):
                n += 1
                ch.place_order("mm", BTC, f"mm{n}", side, D(rng.randint(1, 20)) / 10,
                               (oracle * k).quantize(D("0.01")), 0)
        for _ in range(rng.randint(0, 4)):
            n += 1
            t = rng.choice(traders)
            side = rng.choice(["buy", "sell"])
            price = (oracle * D(rng.choice(["0.98", "1", "1.02"]))).quantize(D("0.01"))
            try:
                ch.place_order(t, BTC, f"o{n}", side, D(rng.randint(1, 8)) / 10, price, 0,
                               ioc=True)
            except ClearinghouseError:
                pass
        move = rng.choices([D("1"), D("0.995"), D("1.005"), D("0.93"), D("1.07"), D("0.85")],
                           weights=[30, 25, 25, 8, 8, 4])[0]
        oracle = (oracle * move).quantize(D("0.01"))
        ch.set_oracle_price(BTC, oracle)
        ch.tick(now)
        _sound(ch)
    return ch


@pytest.mark.parametrize("seed", range(8))
@pytest.mark.parametrize("vault_capital", [20000, 0], ids=["funded-vault", "empty-vault"])
def test_randomized_crashes_never_leave_an_account_negative(seed, vault_capital):
    """With a funded vault crashes end in backstops; with an empty one, in auto-deleveraging."""
    ch = _random_run(seed, vault_capital=vault_capital)
    assert ch.vault_nav() >= -DUST


def test_liquidations_are_deterministic():
    assert _random_run(3, steps=80).state_hash() == _random_run(3, steps=80).state_hash()


# ── the chain: forward ≡ rebuild, with a liquidation inside a block's tick ────

async def test_forward_and_rebuild_liquidate_identically(monkeypatch):
    """A leveraged long, then an oracle crash in a later block: the liquidation happens in that
    block's tick. The interleaved rebuild must reach the same clearinghouse — the same vault
    position, the same zeroed account — and real QRDX is conserved."""
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
    nonces = {a: 0 for a in (rep, alice, bob)}

    def tx(i, op, params):
        addr = keys[i].public_key.to_address()
        t = ExchangeTransaction(op_type=op, sender=addr, nonce=nonces[addr], params=params,
                                gas_limit=2_000_000, gas_price=D("1"))
        nonces[addr] += 1
        t.public_key = keys[i].public_key.to_bytes()
        t.signature = keys[i].sign(t.signing_bytes()).to_bytes()
        return t

    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    try:
        async def add(h, txs=None, alloc=None):
            bh = f"{h:064x}"
            await db.add_block(block_hash=bh, block_height=h, block_content="",
                               validator_address="0xPQ" + "00" * 32, timestamp=int(T0) + 2 * h)
            for i, (r, a) in enumerate(alloc or []):
                await db.add_transaction(tx_hash=f"a{h}{i}", block_hash=bh, tx_hex=json.dumps(
                    {"type": "genesis_allocation", "recipient": r, "amount": a}))
            if txs:
                await db.add_block_exchange_txs(bh, encode_exchange_txs(txs))

        await add(0, alloc=[(alice, "3500"), (bob, "1000000")])
        await add(1, [tx(0, ExchangeOpType.CREATE_MARKET, {"base_token": "BTC"}),
                      tx(0, ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:QRDX", "price": "30000"}),
                      tx(1, ExchangeOpType.PERP_DEPOSIT, {"amount": "3500"}),
                      tx(2, ExchangeOpType.PERP_DEPOSIT, {"amount": "100000"})])
        await add(2, [tx(2, ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "sell",
                                                        "size": "1", "price": "30000"}),
                      tx(1, ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": "buy",
                                                        "size": "1", "price": "30000"})])
        await add(3)
        await add(4, [tx(0, ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:QRDX", "price": "26900"})])
        await add(5)
        tip = 5

        await db.seed_genesis_account_state()
        await db.connection.commit()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        mgr.enforce_collateral = True
        for h in range(1, tip + 1):
            section = await db.get_block_exchange_txs(f"{h:064x}")
            ts = float(int(T0) + 2 * h)
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
        assert BTC not in ch.accounts[alice].positions, "alice should have been liquidated"
        assert ch.accounts[VAULT].positions[BTC].size == 1
        forward_root, forward_state = mgr.compute_state_root(), ch.canonical()
        cur = await db.connection.execute("SELECT balance FROM account_state")
        forward_total = sum(int(r[0]) for r in await cur.fetchall())

        await rebuild_derived_state_interleaved(db)
        mgr = ExchangeStateManager.get_instance()
        assert mgr.clearinghouse.canonical() == forward_state
        assert mgr.compute_state_root() == forward_root
        cur = await db.connection.execute("SELECT balance FROM account_state")
        assert sum(int(r[0]) for r in await cur.fetchall()) == forward_total
    finally:
        ExchangeStateManager.reset_instance()
        path = db.db_path
        await db.close()
        os.remove(path)
