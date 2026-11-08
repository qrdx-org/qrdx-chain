"""
Plain spot orders and cancels run natively (qrdx/exchange/order_lane.py,
native/qrdx-native/src/order_lane.rs), held to Python's own path.

Random blocks go through two exchanges side by side, both with native books: one runs the
native lane, the other runs every operation through ``process_transaction``. The traffic is
plain limit orders in every time in force (hidden, iceberg, crossing and resting, too large for
the balance, too small for the book, from an account whose token balance was not loaded) and
cancels (one's own, another's, unknown, already gone), on three pairs — one whose pool has
liquidity (an order that reaches the pool is Python's), two with triggers waiting near the price
(a fill that reaches one is Python's), one quoted in QRDX (on odd seeds the perps' settlement
asset: its fills count toward fee tiers) — among what only Python runs: market and trigger
orders, swaps, modifications, brackets, builder fees. Traders pay their fee tier's rates (one
crosses a tier, another a referral's cap, mid-run), a staking discount, a referee's discount, a
referrer's reward. After every
block everything must be the same: the block's outcome and root, every result (success, gas,
data, error, fee) and transaction field, the nonces, every balance delta and loaded balance (and
the order keys entered their dicts), the block's fees and staker fees, the fee tokens, the
books (levels, orders, owners' nonces, the trade history as settlement charged it); and the
block must still be taken back out by its undo record.
"""

import dataclasses
import random
from decimal import Decimal

import pytest

pytest.importorskip("qrdx_native")

from qrdx.crypto.pq.dilithium import PQPrivateKey  # noqa: E402
from qrdx.exchange import ExchangeOpType as Op  # noqa: E402
from qrdx.exchange import ExchangeTransaction  # noqa: E402
from qrdx.exchange import block_processor as BP  # noqa: E402
from qrdx.exchange import block_undo, native_book, order_lane  # noqa: E402
from qrdx.exchange.clearinghouse import REFERRAL_VOLUME_CAP  # noqa: E402
from qrdx.exchange.fair_ordering import fair_order  # noqa: E402
from qrdx.exchange.state_manager import ExchangeStateManager  # noqa: E402

D = Decimal
KEYS = [PQPrivateKey.generate() for _ in range(7)]
TRADERS = [k.public_key.to_address() for k in KEYS[:6]]
ISSUER = KEYS[6].public_key.to_address()
PK = KEYS[0].public_key.to_bytes()
A, B, C, USD = ("0x" + h * 20 for h in ("11", "22", "44", "33"))
T0 = 1_800_000_000
MIDS = {"A": D(2), "B": D(5), "C": D("0.5")}


def _tx(op, sender, nonce, params, gas_limit=600_000, gas_price=10 ** 9):
    t = ExchangeTransaction(op_type=op, sender=sender, nonce=nonce, params=params,
                            gas_limit=gas_limit, gas_price=gas_price)
    t.public_key, t.signature = PK, b"\x01" * 3309
    return t


def _setup():
    """An exchange with three pairs (A:USD with pool liquidity, B:USD, C:QRDX), funded traders
    (one with no B balance loaded), referrals, fee tiers and a staking discount."""
    m = ExchangeStateManager()
    BP.apply_enforcement(m)
    m.begin_block(1, float(T0 + 1))
    for who in TRADERS + [ISSUER]:
        m.set_available_balance(who, D(10 ** 9))
        for tok in (A, B, C, USD):
            if not (who == TRADERS[5] and tok == B):
                m.set_available_token_balance(who, tok, D(10 ** 7))
    pairs = {}
    nonce = 0
    for label, t0, t1 in (("A", A, USD), ("B", B, USD), ("C", C, "QRDX")):
        r = m.process_transaction(_tx(Op.CREATE_POOL, ISSUER, nonce, dict(
            token0=t0, token1=t1, fee_tier=3000, pool_type="STANDARD",
            initial_price=str(MIDS[label]), stake_amount="10000"), gas_limit=2_000_000))
        nonce += 1
        assert r.success, r.error
        pid = r.data["pool_id"]
        pair = m._canonical_pair(f"{t0}:{t1}")
        pairs[label] = pair
        for holder in (m.pool_holder_address(pid), m.orderbook_escrow_address(pair)):
            m.set_available_balance(holder, D(0))
            for tok in (t0, t1):
                m.set_available_token_balance(holder, tok, D(0))
        if label == "A":
            r = m.process_transaction(_tx(Op.ADD_LIQUIDITY, ISSUER, nonce, dict(
                pool_id=pid, tick_lower=-1200, tick_upper=1200, amount="1000"),
                gas_limit=2_000_000))
            nonce += 1
            assert r.success, r.error
    ch = m.clearinghouse
    ch.register_referral_code(TRADERS[0], "alpha")
    ch.join_referral(TRADERS[1], "alpha")
    ch.join_referral(TRADERS[2], "alpha")
    for who, volume in ((TRADERS[1], REFERRAL_VOLUME_CAP - 8), (TRADERS[2], REFERRAL_VOLUME_CAP)):
        ch.referrals[who] = dataclasses.replace(ch.referrals[who], volume=volume)  # (one crosses)
    day = ch._day()
    for who, volume in ((TRADERS[3], 30_000_000), (TRADERS[4], 2_500_000_000),
                        (TRADERS[5], 8_000_000_000)):
        ch.volumes[who] = ((day, D(volume)),)
    # (just below a tier: fills on a pair quoted in the settlement asset lift it mid-run; and a
    # day past the window, dropped when the volume is next written)
    ch.volumes[TRADERS[0]] = ((day - 30, D(10 ** 9)), (day - 1, D(5_000_000) - D(25)))
    ch.set_stakes({TRADERS[1].lower(): D(150), TRADERS[3].lower(): D(2)})
    m.commit_block()
    return m, pairs, {ISSUER: nonce}


def _block(rng, pairs, nonces, known):
    """A block's operations, fairly ordered, each lane's nonces in sequence."""
    ops = []
    for _ in range(rng.randint(10, 60)):
        who = rng.choice(TRADERS)
        label = rng.choice(list(pairs))
        pair, mid = pairs[label], MIDS[label]
        k = rng.random()
        gas = 600_000
        if k < 0.55:
            side = rng.choice(["buy", "sell"])
            off = D(rng.randint(1, 80)) / D(1000) * mid
            cross = rng.random() < 0.4
            price = (mid + off if side == "buy" else mid - off) if cross else \
                (mid - off if side == "buy" else mid + off)
            amount = rng.choice([str(D(rng.randint(1, 400)) / D(10)), "0.123456789012345678",
                                 str(rng.randint(1, 60)), "0.00001"])
            p = dict(pair=pair, side=rng.choice([side, side.upper()]), order_type="limit",
                     price=str(price.quantize(D("0.0001"))), amount=amount,
                     tif=rng.choice(["gtc", "gtc", "gtc", "ioc", "fok", "alo", "GTC"]))
            r = rng.random()
            if r < 0.06:
                p["hidden"] = True
            elif r < 0.12:
                p["display_size"] = str(D(rng.randint(1, 40)) / D(10))
            elif r < 0.15:
                p["amount"] = "50000000"  # (more than the balance)
            elif r < 0.17:
                p["tif"] = "never"  # (the book refuses it)
            elif r < 0.19:
                p["price"] = "2.123456789123456789123"
            elif r < 0.21:
                gas = 40_000 + rng.randint(0, 3) * 10_000  # (a budget of a few makers)
            elif r < 0.23:
                p["order_type"] = "market"  # (Python's)
                p.pop("price")
            elif r < 0.25:
                p["builder"] = {"b": TRADERS[0], "f": "0.0001"}  # (Python's: refused)
            elif r < 0.27 and side == "buy" and label == "A":
                p["tp"] = {"trigger_price": str(mid * 2)}  # (Python's: a bracket)
            ops.append((Op.PLACE_ORDER, who, p, gas))
        elif k < 0.75 and known:
            owner, oid, p = rng.choice(known)
            caller = owner if rng.random() < 0.85 else who
            params = dict(pair=p, order_id=oid)
            if rng.random() < 0.05:
                params["order_id"] = "f" * 16  # (unknown)
            elif rng.random() < 0.04:
                params.pop("pair")  # (Python's: every book searched)
            ops.append((Op.CANCEL_ORDER, caller, params, gas))
        elif k < 0.82:
            base, quote = pair.split(":", 1)
            buy = rng.random() < 0.5
            ops.append((Op.SWAP, who, dict(token_in=quote if buy else base,
                                            token_out=base if buy else quote,
                                            amount_in=str(D(rng.randint(1, 50)) / D(10)),
                                            min_amount_out="0"), gas))
        elif k < 0.88 and label != "C":
            # (triggers waiting near the price: a fill that reaches one is Python's)
            at = mid * D(rng.randint(930, 1070)) / D(1000)
            ops.append((Op.PLACE_ORDER, who, dict(
                pair=pair, side=rng.choice(["buy", "sell"]),
                order_type=rng.choice(["stop_loss", "take_profit"]),
                trigger_price=str(at.quantize(D("0.0001"))), amount=str(rng.randint(1, 20))), gas))
        elif known:
            owner, oid, p = rng.choice(known)
            ops.append((Op.MODIFY_ORDER, owner, dict(pair=p, order_id=oid,
                                                     amount=str(rng.randint(1, 30))), gas))
    txs = []
    for op, who, params, gas in ops:
        n = nonces.get(who, 0)
        nonces[who] = n + 1
        txs.append(_tx(op, who, n, params, gas_limit=gas))
    return fair_order(txs)


def _books(m):
    out = []
    for pair in sorted(m._order_books):
        b = m._order_books[pair]
        orders = sorted(
            (o.id, o.owner, o.side.value, str(o.price), str(o.amount), str(o.filled),
             o.status.value, o.tif, o.hidden, str(o.display_size), str(o.shown))
            for o in b._orders.values())
        trades = [(t.id, t.maker_order_id, t.taker_order_id, str(t.price), str(t.amount),
                   str(t.maker_fee), str(t.taker_fee), t.buyer, t.seller, t.sequence)
                  for t in b.get_recent_trades(200)]
        out.append((pair, list(b.iter_levels(True)), list(b.iter_levels(False)), orders,
                    list(b._nonces().peek_items()), trades, str(b.total_volume), b.total_trades,
                    b.last_price))
    return out


def _snapshot(m, out):
    results = [(r.success, r.gas_used, r.data, r.error, r.fee) for r in m._block_results]
    fields = [(t.gas_used, t.success, t.result, t.error) for t in m._block_exchange_txs]
    return {
        "out": out,
        "results": results,
        "fields": fields,
        "nonces": list(dict.items(m._nonces)),
        "deltas": [(a, str(v)) for a, v in m._balance_deltas.items()],  # (order counts)
        "token_deltas": [(k, str(v)) for k, v in m._token_balance_deltas.items()],
        "available": sorted((a, str(v)) for a, v in m._available_balances.items()),
        "token_available": sorted((k, str(v)) for k, v in m._available_token_balances.items()),
        "fees": (str(m._block_fees), str(m._block_staker_fees)),
        "fee_tokens": [(t, tuple(map(str, v))) for t, v in m.fee_tokens.peek_items()],
        "orders": m._total_orders,
        "books": _books(m),
        "root": m.compute_state_root(),
    }


def _run_block(m, height, txs, lane, monkeypatch):
    monkeypatch.setattr(order_lane, "enabled", lambda: lane)
    opened = block_undo.open_block(m, height)
    root_before = m.compute_state_root()
    try:
        out = BP.process_exchange_transactions(height, float(T0 + height), txs, m)
        snap = _snapshot(m, out)
    finally:
        block_undo.close_block(opened, applied=True)
    if out[0]:
        m.commit_block()
    return snap, root_before


def _copies(txs):
    out = []
    for t in txs:
        c = ExchangeTransaction.from_dict(t.to_dict())
        c.public_key, c.signature = t.public_key, t.signature
        out.append(c)
    return out


@pytest.mark.parametrize("seed", range(8))
def test_random_blocks_run_as_python_runs_them(seed, monkeypatch):
    from qrdx import constants

    monkeypatch.setattr(native_book, "available", lambda: True)
    # Odd seeds: the perps settle in QRDX (the tests' default), so the QRDX pair's fills count
    # toward fee tiers (Python's); even seeds: in a token no pair trades (all fills native).
    if seed % 2 == 0:
        monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", "0x" + "55" * 20)
    rng = random.Random(seed)
    block_undo.invalidate()
    py, pairs, nonces = _setup()
    nat, _, _ = _setup()
    known = []
    ran = {"native": 0, "fills": 0, "B": 0, "C": 0}
    stretch = order_lane._stretch

    def counted(mgr, fn, txs, prepared, prepaid, payers, start, results):
        n = len(results)
        done = stretch(mgr, fn, txs, prepared, prepaid, payers, start, results)
        ran["native"] += done
        for r in results[n : n + done]:
            for f in r.data.get("fills", ()):
                ran["fills"] += 1
                for label in ("B", "C"):
                    ran[label] += f["market"] == pairs[label]
        return done

    monkeypatch.setattr(order_lane, "_stretch", counted)
    for height in range(2, 26):
        txs = _block(rng, pairs, nonces, known)
        a, _ = _run_block(py, height, txs, False, monkeypatch)
        copies = _copies(txs)
        b, root_before = _run_block(nat, height, copies, True, monkeypatch)
        assert a == b, f"seed {seed} block {height}: {[k for k in a if a[k] != b[k]]}"
        assert a["out"][0], a["out"]
        for t in txs:
            if t.op_type == Op.PLACE_ORDER and t.success and (t.result or {}).get("order_id"):
                known.append((t.sender, t.result["order_id"], t.params["pair"]))
        # every block still undoes: take it back out, compare, run it again
        assert block_undo.take_back(nat, height - 1) == 1
        assert nat.compute_state_root() == root_before
        block_undo.invalidate()
        again, _ = _run_block(nat, height, _copies(txs), True, monkeypatch)
        assert again["root"] == a["root"] and again["deltas"] == a["deltas"]
        assert again["books"] == a["books"]
    # run natively, fills settled — on the pair with triggers waiting, and on the QRDX pair
    # (quoted in the settlement asset on odd seeds: its fills count toward fee tiers)
    assert ran["native"] > 300 and ran["fills"] > 30 and ran["B"] > 5 and ran["C"] > 5, ran
    trades = sum(b.total_trades for b in nat._order_books.values())
    assert trades > 100, trades


def test_what_is_not_a_plain_order_or_cancel_is_left_to_python():
    s = TRADERS[0]
    plain = dict(pair=f"{A}:{USD}", side="buy", order_type="limit", price="2", amount="1")
    assert order_lane.prepare(_tx(Op.PLACE_ORDER, s, 0, plain)) is not None
    assert order_lane.prepare(_tx(Op.CANCEL_ORDER, s, 0, dict(pair="a:b", order_id="x")))
    for change in (dict(order_type="market"), dict(order_type="stop_loss"), dict(price="abc"),
                   dict(amount="NaN"), dict(hidden="yes"), dict(builder={"b": s, "f": "0.1"}),
                   dict(tp={"trigger_price": "3"}), dict(side="long"), dict(pair="AUSD"),
                   dict(stop_price="1")):
        assert order_lane.prepare(_tx(Op.PLACE_ORDER, s, 0, {**plain, **change})) is None, change
    assert order_lane.prepare(_tx(Op.PLACE_ORDER, s, 0, plain, gas_price=0)) is None  # (free)
    assert order_lane.prepare(_tx(Op.PLACE_ORDER, s, 0, plain, gas_limit=39_999)) is None
    agent = _tx(Op.PLACE_ORDER, s, 0, plain)
    agent.signer = TRADERS[1]
    assert order_lane.prepare(agent) is None
    assert order_lane.prepare(_tx(Op.CANCEL_ORDER, s, 0, dict(order_id="x"))) is None
    assert order_lane.prepare(_tx(Op.CANCEL_ORDER, s, 0, dict(pair="a:b", order_id=7))) is None
    assert order_lane.prepare(_tx(Op.SWAP, s, 0, dict(token_in="a"))) is None


@pytest.mark.parametrize("seed", range(6))
def test_sections_are_judged_as_python_judges_them(seed, monkeypatch):
    """Orders and cancels the lane prepares are judged natively (with plain transfers): the same
    refusals as Python's — nonces out of sequence, gas limits too low, payers short of their
    fees — and the same answer for everything else."""
    from qrdx.exchange import transfer_lane

    monkeypatch.setattr(native_book, "available", lambda: True)
    rng = random.Random(seed)
    m, pairs, _ = _setup()
    m.set_available_balance(TRADERS[4], D("0.002"))  # (fees for a few transactions only)
    for _ in range(20):
        txs, nonces = [], {}
        for _ in range(rng.randint(5, 40)):
            who = rng.choice(TRADERS)
            n = nonces.get(who, 0)
            k = rng.random()
            pair = pairs[rng.choice(list(pairs))]
            params = dict(pair=pair, side="buy", order_type="limit", price="1", amount="1")
            op, gas = Op.PLACE_ORDER, 600_000
            if k < 0.3:
                op, params = Op.CANCEL_ORDER, dict(pair=pair, order_id="ab" * 8)
            elif k < 0.35:
                n += 1  # (out of sequence)
            elif k < 0.4:
                gas = 30_000  # (too low)
            elif k < 0.45:
                params["expires_at"] = T0 - 5  # (expired: Python judges it)
            elif k < 0.5:
                op, params = Op.TOKEN_TRANSFER, dict(token_address="QRDX", to=TRADERS[0],
                                                     amount="1")
            nonces[who] = n + 1
            txs.append(_tx(op, who, n, params, gas_limit=gas))
        judged = []
        for lane in (False, True):
            monkeypatch.setattr(order_lane, "enabled", lambda lane=lane: lane)
            monkeypatch.setattr(transfer_lane, "enabled", lambda lane=lane: lane)
            judged.append(m.section_errors(txs, 2, float(T0 + 2)))
        assert judged[0] == judged[1]
