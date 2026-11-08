"""
The exchange with its spot books held natively (qrdx/exchange/native_book.py) is the exchange with
Python's books, operation for operation (docs/EXCHANGE_ENGINE.md, E3a).

The same random spot traffic runs twice through ``process_transaction`` — once with Python books,
once with native ones — on two pairs (one with pool liquidity: orders and swaps route across the
book and the pool; one without): limit, market and post-only orders, IOC and fill-or-kill,
hidden and iceberg orders, triggers, cancels, modifications, swaps, and each block's tick
(crossed orders filled from the pools, triggers fired). Every block must give the same results
(success, error, gas, data), the same tick events, the same exchange root, the same balance
changes and the same trade history (the fees as settlement charged them); the commitments are
checked against a full recomputation as they go.

A node's checkpoint (and a published snapshot) pickles its books: one taken with native books
loads on a node without them as Python books, and the exchange carries on as before.
"""

import pickle
import random
from decimal import Decimal

import pytest

pytest.importorskip("qrdx_native")

from qrdx.exchange import ExchangeOpType as Op  # noqa: E402
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction, native_book  # noqa: E402
from qrdx.exchange import block_processor as BP  # noqa: E402
from qrdx.exchange.orderbook import OrderBook  # noqa: E402
from qrdx.snapshot import safe_loads  # noqa: E402

D = Decimal
TRADERS = ["0xPQ" + f"{i:064x}" for i in range(1, 7)]
ISSUER = "0xPQ" + "e" * 64
A, B, USD = "0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20
T0 = 1_700_000_000


def _history(m):
    """Each book's display history: the trades as settlement charged them."""
    return sorted(
        (pair, [(t.id, t.maker_order_id, t.taker_order_id, str(t.price), str(t.amount),
                 str(t.maker_fee), str(t.taker_fee), t.buyer, t.seller, t.sequence)
                for t in book.get_recent_trades(100)])
        for pair, book in m._order_books.items())


def _run(native: bool, seed: int, blocks: int, monkeypatch, reload_at=None):
    """``reload_at``: after that block, the state is pickled as a checkpoint and loaded by a node
    with the other kind of books."""
    monkeypatch.setattr(native_book, "available", lambda: native)
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    BP.apply_enforcement(m)
    rng = random.Random(seed)
    nonces = {}
    known = []  # order and trigger ids placed (some resting, some not)
    out = []

    def tx(sender, op, gas_limit=3_000_000, **params):
        n = nonces.get(sender, 0)
        nonces[sender] = n + 1
        return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                                   gas_limit=gas_limit, gas_price=10**9)

    def do(t):
        r = m.process_transaction(t)
        if r.success and isinstance(r.data, dict):
            for key in ("order_id", "trigger_id"):
                if r.data.get(key):
                    known.append((t.sender, r.data[key], t.params.get("pair")))
        return (r.success, r.error, r.gas_used, repr(sorted((r.data or {}).items())))

    m.begin_block(1, float(T0))
    for who in TRADERS + [ISSUER]:
        m.set_available_balance(who, D(10**9))
        for tok in (A, B, USD):
            m.set_available_token_balance(who, tok, D(10**9))
    setup = []
    for t0, t1, price in ((A, USD, "2"), (B, USD, "5")):
        r = m.process_transaction(tx(ISSUER, Op.CREATE_POOL, token0=t0, token1=t1, fee_tier=3000,
                                     pool_type="STANDARD", initial_price=price,
                                     stake_amount="10000"))
        assert r.success, r.error
        pid = r.data["pool_id"]
        for holder in (m.pool_holder_address(pid), m.orderbook_escrow_address(f"{t0}:{t1}")):
            m.set_available_balance(holder, D(0))
            for tok in (t0, t1):
                m.set_available_token_balance(holder, tok, D(0))
        if t0 == A:  # (one pair with liquidity: orders and swaps route across both venues)
            setup.append(do(tx(ISSUER, Op.ADD_LIQUIDITY, pool_id=pid, tick_lower=-60000,
                               tick_upper=60000, amount="100000")))
    out.append(("setup", setup, m.compute_state_root()))
    m.commit_block()
    mids = {f"{A}:{USD}": D(2), f"{B}:{USD}": D(5)}
    for h in range(2, 2 + blocks):
        m.begin_block(h, float(T0 + h))
        results = []
        for _ in range(rng.randint(20, 45)):
            who = rng.choice(TRADERS)
            pair = rng.choice(list(mids))
            mid = mids[pair]
            k = rng.random()
            if k < 0.5:
                side = rng.choice(["buy", "sell"])
                cross = rng.random() < 0.35
                off = D(rng.randint(1, 60)) / D(1000) * mid
                price = (mid + off if side == "buy" else mid - off) if cross else \
                    (mid - off if side == "buy" else mid + off)
                params = dict(pair=pair, side=side, price=str(price.quantize(D("0.0001"))),
                              amount=str(D(rng.randint(1, 400)) / D(10)))
                kind = rng.random()
                if kind < 0.1:
                    params.update(order_type="market")
                    params.pop("price")
                elif kind < 0.17:
                    params.update(order_type=rng.choice(["stop_loss", "take_profit"]),
                                  trigger_price=params["price"])
                else:
                    params.update(order_type="limit",
                                  tif=rng.choice(["gtc", "gtc", "gtc", "ioc", "fok", "alo"]))
                    if rng.random() < 0.08:
                        params["hidden"] = True
                    elif rng.random() < 0.08:
                        params["display_size"] = str(D(params["amount"]) / 4)
                results.append(do(tx(who, Op.PLACE_ORDER, **params)))
            elif k < 0.7 and known:
                owner, oid, p = rng.choice(known)
                caller = owner if rng.random() < 0.9 else who
                results.append(do(tx(caller, Op.CANCEL_ORDER, pair=p or pair, order_id=oid)))
            elif k < 0.8 and known:
                owner, oid, p = rng.choice(known)
                results.append(do(tx(owner, Op.MODIFY_ORDER, pair=p or pair, order_id=oid,
                                     amount=str(D(rng.randint(1, 300)) / D(10)))))
            else:
                base = pair.split(":")[0]
                buy = rng.random() < 0.5
                results.append(do(tx(who, Op.SWAP, token_in=USD if buy else base,
                                     token_out=base if buy else USD,
                                     amount_in=str(D(rng.randint(1, 200)) / D(10)),
                                     min_amount_out="0")))
        now = D(int(m._block_clock()) + 1)
        tick = m.uncross_spot_books(now) + m.fire_spot_triggers(now)
        m.verify_commitments()
        out.append((h, results, repr(tick), m.compute_state_root(),
                    sorted((a, str(v)) for a, v in m.balance_deltas().items()),
                    sorted((repr(k), str(v)) for k, v in m.token_balance_deltas().items()),
                    _history(m)))
        m.commit_block()
        if h == reload_at:
            blob = pickle.dumps(m.capture(), protocol=5)
            ledger = dict(m._available_balances), dict(m._available_token_balances)
            native = not native
            monkeypatch.setattr(native_book, "available", lambda: native)
            ExchangeStateManager.reset_instance()
            m = ExchangeStateManager.get_instance()
            BP.apply_enforcement(m)
            m._restore_snapshot(safe_loads(blob))
            for who, v in ledger[0].items():  # (the balances: a node's database, not the state)
                m.set_available_balance(who, v)
            for (who, tok), v in ledger[1].items():
                m.set_available_token_balance(who, tok, v)
            m.verify_commitments()
            kinds = {type(b) for b in m._order_books.values()}
            assert kinds == {native_book.NativeSpotBook if native else OrderBook}
    traded = sum(b.total_trades for b in m._order_books.values())
    ExchangeStateManager.reset_instance()
    return out, traded


@pytest.mark.parametrize("seed", range(4))
def test_native_books_run_the_exchange_as_python_books_do(seed, monkeypatch):
    python, traded = _run(False, seed, 12, monkeypatch)
    native, traded_native = _run(True, seed, 12, monkeypatch)
    assert traded > 30 and traded == traded_native
    for a, b in zip(python, native):
        assert a == b, f"block {a[0]} differs"
    assert len(python) == len(native)


@pytest.mark.parametrize("seed", range(2))
def test_a_checkpoint_loads_on_a_node_with_the_other_books(seed, monkeypatch):
    python, _ = _run(False, seed, 10, monkeypatch)
    for native in (True, False):  # (native books written, Python ones loaded; and back)
        mixed, _ = _run(native, seed, 10, monkeypatch, reload_at=5)
        assert mixed == python
