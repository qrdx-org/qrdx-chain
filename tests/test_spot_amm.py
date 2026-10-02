"""
The spot exchange after the audit of 2026-10-02 (docs/KNOWN_ISSUES.md, "Spot exchange: …").

The AMM is now Uniswap V3 mathematics in deterministic Decimal arithmetic: swaps cross ticks,
positions earn fees only inside their range, rounding always favours the pool. Every operation is
all-or-nothing, removing liquidity is owner-only and returns the principal with the fees, the
router settles each venue with its real counterparty, and pool oracles run on block time.
Each test names the defect it pins.
"""
import random
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.amm import (
    MAX_TICK, MIN_TICK, Q96, ConcentratedLiquidityPool, FeeTier, PoolState, PoolType,
    amount0_delta, amount1_delta, sqrt_price_to_tick, tick_to_sqrt_price,
)

D = Decimal
ALICE, BOB, MALLORY, CAROL = ("0xPQ" + c * 64 for c in "abcd")
T0, T1 = "0x" + "11" * 20, "0x" + "22" * 20       # T0 < T1: T0 is token0 / the book's base


def _pool(price_tick=0, tier=FeeTier.MEDIUM):
    return ConcentratedLiquidityPool(PoolState(
        id="p", token0=T0, token1=T1, fee_tier=tier, pool_type=PoolType.STANDARD,
        creator=ALICE, sqrt_price=tick_to_sqrt_price(price_tick),
        tick=price_tick))


# ── tick math ──────────────────────────────────────────────────────────────

def test_tick_math_is_exact_decimal_and_inverts():
    assert tick_to_sqrt_price(0) == Q96
    rng = random.Random(7)
    for t in [MIN_TICK, -887271, -1, 0, 1, 887271] + [rng.randint(MIN_TICK, MAX_TICK - 1)
                                                       for _ in range(200)]:
        assert sqrt_price_to_tick(tick_to_sqrt_price(t)) == t
        # just below a tick's price is the tick below it
        if t > MIN_TICK:
            assert sqrt_price_to_tick(tick_to_sqrt_price(t) * (1 - D("1e-40"))) == t - 1


# ── swaps follow the curve and cross ticks ─────────────────────────────────

def test_a_swap_within_one_range_matches_the_constant_product():
    pool = _pool()
    L = D(1_000_000)
    pool.add_liquidity(ALICE, -6000, 6000, L)
    plan = pool.quote(D(1000), zero_for_one=True)
    # x·y = L² on the virtual reserves: x = L/√P, y = L·√P; after Δx (net of fee) in,
    # y_out = y − L²/(x + Δx).
    s = D(1)
    dx = D(1000) * (1 - FeeTier.MEDIUM.rate)
    expected = L * s - L * L / (L / s + dx)
    assert abs(plan.amount_out - expected) < D("1e-15")
    assert plan.amount_out < expected            # rounded in the pool's favour


def test_a_swap_crosses_into_the_next_range():
    """Two adjacent ranges: the swap exhausts the first and continues in the second, whose
    liquidity it activates at the boundary — the old engine priced the whole move with the
    first range's liquidity and paid out tokens the second range never deposited."""
    pool = _pool()
    pool.add_liquidity(ALICE, -60, 60, D(1_000_000))
    pool.add_liquidity(BOB, -1200, -60, D(5_000_000))
    first_range = amount0_delta(D(tick_to_sqrt_price(-60)) / Q96, D(1), D(1_000_000), True)
    plan = pool.quote(first_range * 3, zero_for_one=True)
    assert plan.crossings and plan.crossings[0][0] == -60
    assert plan.liquidity == D(5_000_000) and plan.tick < -60
    pool.apply(plan)
    assert pool.state.liquidity == D(5_000_000)


def test_fees_are_earned_only_in_range():
    pool = _pool()
    inside = pool.add_liquidity(ALICE, -600, 600, D(1_000_000))
    outside = pool.add_liquidity(BOB, 1200, 2400, D(1_000_000))
    for i in range(10):
        pool.swap(D(100), zero_for_one=(i % 2 == 0))
    a0, a1 = pool.remove_liquidity(inside.id, D(0), owner=ALICE)        # collect only
    b0, b1 = pool.remove_liquidity(outside.id, D(0), owner=BOB)
    assert a0 > 0 and a1 > 0
    assert b0 == 0 and b1 == 0


# ── solvency under random activity ─────────────────────────────────────────

@pytest.mark.parametrize("seed", range(6))
def test_the_pool_always_holds_what_everyone_can_withdraw(seed):
    rng = random.Random(seed)
    pool = _pool(tier=FeeTier.LOW)              # spacing 10
    held = [D(0), D(0)]
    positions = []
    lps = [f"0xPQ{n:064x}" for n in range(5)]
    for step in range(250):
        roll = rng.random()
        if roll < 0.25 or not positions:
            lo = rng.randrange(-200, 200) * 10
            hi = lo + rng.randrange(1, 150) * 10
            L = D(rng.randint(1_000, 5_000_000))
            a0, a1 = pool.amounts_for_liquidity(lo, hi, L, round_up=True)
            pos = pool.add_liquidity(rng.choice(lps), lo, hi, L, now=step)
            held[0] += a0
            held[1] += a1
            positions.append(pos.id)
        elif roll < 0.85:
            zfo = rng.random() < 0.5
            try:
                plan = pool.quote(D(rng.randint(1, 50_000)), zfo)
            except ValueError:
                continue
            pool.apply(plan, now=step)
            i, o = (0, 1) if zfo else (1, 0)
            held[i] += plan.amount_in
            held[o] -= plan.amount_out
        else:
            pid = rng.choice(positions)
            pos = pool.state.positions[pid]
            part = None if rng.random() < 0.5 else (pos.liquidity * D(rng.random())).quantize(D(1))
            out0, out1 = pool.remove_liquidity(pid, part, owner=pos.owner, now=step)
            held[0] -= out0
            held[1] -= out1
            if pid not in pool.state.positions:
                positions.remove(pid)
        assert held[0] >= 0 and held[1] >= 0, f"pool overdrawn at step {step}: {held}"
    # Everyone leaves: what remains is the protocol's fees plus rounding dust in the pool's favour.
    for pid in list(pool.state.positions):
        pos = pool.state.positions[pid]
        out0, out1 = pool.remove_liquidity(pid, owner=pos.owner)
        held[0] -= out0
        held[1] -= out1
    for k, fees in ((0, pool.state.protocol_fees_0), (1, pool.state.protocol_fees_1)):
        dust = held[k] - fees
        assert D(0) <= dust < D("1e-12"), f"token{k}: held {held[k]}, protocol fees {fees}"


# ── the manager: every defect from the audit ───────────────────────────────

_nonces = {}


def _tx(sender, op, params):
    n = _nonces.get(sender, 0)
    _nonces[sender] = n + 1
    return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                               gas_limit=10_000_000, gas_price=D("1"))


@pytest.fixture
def mgr():
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.enforce_spot_settlement = True
    m.enforce_orderbook_settlement = True
    for who in (ALICE, BOB, MALLORY, CAROL):
        m.set_available_balance(who, D(10_000_000))
        for t in (T0, T1):
            m.set_available_token_balance(who, t, D(100_000_000))
    m.begin_block(1, 1_700_000_000.0)
    yield m
    ExchangeStateManager.reset_instance()


def _make_pool(m, price="1", tier=3000, lo=-60000, hi=60000, liquidity="1000000"):
    r = m.process_transaction(_tx(ALICE, ExchangeOpType.CREATE_POOL, {
        "token0": T0, "token1": T1, "fee_tier": tier, "pool_type": "STANDARD",
        "initial_price": price, "stake_amount": "10000"}))
    assert r.success, r.error
    pid = r.data["pool_id"]
    # the holder and the pair's book escrow start empty; the manager tracks them from here
    holder = m.pool_holder_address(pid)
    escrow = m.orderbook_escrow_address(f"{T0}:{T1}")
    for t in (T0, T1):
        m.set_available_token_balance(holder, t, D(0))
        if m.available_token_balance(escrow, t) is None:
            m.set_available_token_balance(escrow, t, D(0))
    add = m.process_transaction(_tx(ALICE, ExchangeOpType.ADD_LIQUIDITY, {
        "pool_id": pid, "tick_lower": lo, "tick_upper": hi, "amount": liquidity}))
    assert add.success, add.error
    return pid, add.data["position_id"], holder


def _net(m, who):
    d = m.token_balance_deltas()
    return d.get((who, T0), D(0)), d.get((who, T1), D(0))


def test_only_the_owner_can_remove_a_position(mgr):
    pid, pos, _ = _make_pool(mgr)
    r = mgr.process_transaction(_tx(MALLORY, ExchangeOpType.REMOVE_LIQUIDITY,
                                    {"pool_id": pid, "position_id": pos}))
    assert not r.success and "owner" in r.error
    assert pos in mgr.pool_manager.get_pool(pid).state.positions
    assert _net(mgr, MALLORY) == (0, 0)


def test_removing_liquidity_returns_the_principal_and_the_fees(mgr):
    pid, pos, holder = _make_pool(mgr)
    deposited = [-x for x in _net(mgr, ALICE)]
    for i in range(6):
        assert mgr.process_transaction(_tx(BOB, ExchangeOpType.SWAP, {
            "token_in": T0 if i % 2 == 0 else T1, "token_out": T1 if i % 2 == 0 else T0,
            "amount_in": "500"})).success
    r = mgr.process_transaction(_tx(ALICE, ExchangeOpType.REMOVE_LIQUIDITY,
                                    {"pool_id": pid, "position_id": pos}))
    assert r.success, r.error
    out = (D(r.data["amount0"]), D(r.data["amount1"]))
    # Back: principal (moved by the trades) plus fees — in total more than was deposited,
    # since the trades were round trips that only paid fees.
    assert out[0] + out[1] > deposited[0] + deposited[1]
    pool = mgr.pool_manager.get_pool(pid)
    held = _net(mgr, holder)
    assert held[0] >= pool.state.protocol_fees_0 and held[1] >= pool.state.protocol_fees_1


def test_a_failed_swap_changes_nothing(mgr):
    """Five swaps that missed their own min_amount_out used to move the pool's price to
    0.25× for free."""
    pid, _, _ = _make_pool(mgr)
    pool = mgr.pool_manager.get_pool(pid)
    before = (pool.state_digest(), mgr.token_balance_deltas())
    for _ in range(5):
        r = mgr.process_transaction(_tx(BOB, ExchangeOpType.SWAP, {
            "token_in": T0, "token_out": T1, "amount_in": "200000",
            "min_amount_out": "999999999"}))
        assert not r.success and "Slippage" in r.error
    assert (pool.state_digest(), mgr.token_balance_deltas()) == before


def test_swaps_work_in_both_directions(mgr):
    """The pair oracle recorded each direction's reciprocal price, so after one swap every
    swap the other way was rejected as an 'outlier' (and still moved the pool)."""
    _make_pool(mgr, price="4")
    for i in range(6):
        a, b = (T0, T1) if i % 2 == 0 else (T1, T0)
        r = mgr.process_transaction(_tx(BOB, ExchangeOpType.SWAP,
                                        {"token_in": a, "token_out": b, "amount_in": "100"}))
        assert r.success, r.error


def test_a_swap_settles_with_the_pool_it_executed_on(mgr):
    """Several fee tiers for one pair: the router used the deepest pool, but settlement
    debited the first pool found."""
    shallow, _, shallow_holder = _make_pool(mgr, tier=500, lo=-60000, hi=60000, liquidity="1000")
    deep, _, deep_holder = _make_pool(mgr, tier=3000, liquidity="10000000")
    before = (_net(mgr, shallow_holder), _net(mgr, deep_holder))
    r = mgr.process_transaction(_tx(BOB, ExchangeOpType.SWAP,
                                    {"token_in": T0, "token_out": T1, "amount_in": "100"}))
    assert r.success and r.data["pool_id"] == deep
    assert _net(mgr, shallow_holder) == before[0]
    d0, d1 = _net(mgr, deep_holder)
    assert d0 - before[1][0] == D(100) and d1 < before[1][1]


def test_an_order_book_route_pays_the_maker(mgr):
    """Swaps the router filled on the order book used to settle against the AMM's reserves
    (or not at all): makers were never paid and their escrow stranded."""
    _make_pool(mgr, liquidity="1000")                               # a thin pool
    pair = f"{T0}:{T1}"
    escrow = mgr.orderbook_escrow_address(pair)
    o = mgr.process_transaction(_tx(CAROL, ExchangeOpType.PLACE_ORDER, {
        "pair": pair, "side": "buy", "order_type": "limit", "price": "0.99", "amount": "50"}))
    assert o.success, o.error                                       # Carol bids 0.99 for T0
    before = (_net(mgr, BOB), _net(mgr, CAROL), _net(mgr, escrow))
    r = mgr.process_transaction(_tx(BOB, ExchangeOpType.SWAP, {
        "token_in": T0, "token_out": T1, "amount_in": "10"}))     # Bob sells 10 T0
    assert r.success and r.data["source"] == "clob", r.data
    bob, carol, esc = _net(mgr, BOB), _net(mgr, CAROL), _net(mgr, escrow)
    assert bob[0] - before[0][0] == -10 and bob[1] - before[0][1] == D("9.9")
    assert carol[0] - before[1][0] == 10                            # Carol got her T0 …
    assert esc[1] - before[2][1] == D("-9.9")                       # … paid from her escrow
    book = mgr._order_books[pair]
    assert sum(o.remaining for o in book._orders.values()) == 40


def test_a_holder_that_cannot_cover_a_payout_refuses_the_operation(mgr):
    """The ledger used to clamp an overdraft at zero while the credit landed — a mint."""
    pid, pos, holder = _make_pool(mgr)
    mgr.set_available_token_balance(holder, T1, D(0))              # as if drained elsewhere
    pool = mgr.pool_manager.get_pool(pid)
    before = (pool.state_digest(), mgr.token_balance_deltas())
    r = mgr.process_transaction(_tx(BOB, ExchangeOpType.SWAP,
                                    {"token_in": T0, "token_out": T1, "amount_in": "100"}))
    assert not r.success and "cannot cover" in r.error
    assert (pool.state_digest(), mgr.token_balance_deltas()) == before


def test_removing_a_pool_pays_out_the_protocol_fees(mgr):
    from qrdx import constants
    pid, pos, holder = _make_pool(mgr)
    for i in range(4):
        mgr.process_transaction(_tx(BOB, ExchangeOpType.SWAP, {
            "token_in": T0 if i % 2 == 0 else T1, "token_out": T1 if i % 2 == 0 else T0,
            "amount_in": "1000"}))
    assert mgr.process_transaction(_tx(ALICE, ExchangeOpType.REMOVE_LIQUIDITY,
                                       {"pool_id": pid, "position_id": pos})).success
    pool = mgr.pool_manager.get_pool(pid)
    fees0 = pool.state.protocol_fees_0
    creator_before = _net(mgr, ALICE)[0]
    r = mgr.process_transaction(_tx(ALICE, ExchangeOpType.REMOVE_POOL, {"pool_id": pid}))
    assert r.success, r.error
    treasury = constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"]
    assert _net(mgr, ALICE)[0] - creator_before == (fees0 / 2).quantize(D("1e-18"))
    assert _net(mgr, treasury)[0] == fees0 - (fees0 / 2).quantize(D("1e-18"))


# ── the pool oracle: block time, replays agree ─────────────────────────────

def test_the_pool_oracle_runs_on_block_time_and_replays_identically(monkeypatch):
    """Router fills used to be stamped with the wall clock and merged per second, so a node
    replaying fast computed a different state root than one that had processed live."""
    import time as _time
    from qrdx.exchange import block_processor as BP

    def run(wall_step):
        _nonces.clear()
        ExchangeStateManager.reset_instance()
        m = ExchangeStateManager.get_instance()
        clock = [1_000_000.0]
        monkeypatch.setattr(_time, "time", lambda: clock[0])
        txs = [_tx(ALICE, ExchangeOpType.CREATE_POOL, {
            "token0": T0, "token1": T1, "fee_tier": 3000, "pool_type": "STANDARD",
            "initial_price": "1", "stake_amount": "10000"})]
        BP.process_exchange_transactions(1, 1000.0, txs, m)
        m.commit_block()
        pid = next(iter(m.pool_manager._pools))
        BP.process_exchange_transactions(2, 1002.0, [_tx(ALICE, ExchangeOpType.ADD_LIQUIDITY, {
            "pool_id": pid, "tick_lower": -6000, "tick_upper": 6000, "amount": "1000000"})], m)
        m.commit_block()
        for h in range(3, 9):
            clock[0] += wall_step
            BP.process_exchange_transactions(h, 1000.0 + 2 * h, [_tx(BOB, ExchangeOpType.SWAP, {
                "token_in": T0, "token_out": T1, "amount_in": "10"})], m)
            m.commit_block()
        pool = m.pool_manager.get_pool(pid)
        return m.compute_state_root(), pool.twap_price(8, 1016), len(pool.state.observations)

    live, replay = run(2.0), run(0.0)
    assert live == replay
    # one observation at the first liquidity, then one per swap block
    assert live[2] == 7 and live[1] is not None and live[1] < 1


# ── the manager under random activity, failures included ───────────────────

@pytest.mark.parametrize("seed", range(4))
def test_random_activity_conserves_tokens_and_failures_change_nothing(seed):
    """Random swaps (routed to the pool or the book), adds, removes, orders and cancels from
    four traders, with deliberately failing operations mixed in — over-minimum swaps, a
    stranger's removal, over-sized deposits. After every operation: each token is conserved
    (moves only), no holder or escrow is overdrawn, and a failed operation changed nothing.
    At the end everyone leaves: the pool's holder keeps exactly its protocol fees (plus dust
    in its favour) and the book's escrow is empty."""
    rng = random.Random(seed)
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    try:
        m.enforce_spot_settlement = m.enforce_orderbook_settlement = True
        users = (ALICE, BOB, MALLORY, CAROL)
        for who in users:
            m.set_available_balance(who, D(10_000_000))
            for t in (T0, T1):
                m.set_available_token_balance(who, t, D(1_000_000))
        m.begin_block(1, 1_700_000_000.0)
        pid, _, holder = _make_pool(m, tier=500, lo=-2000, hi=2000, liquidity="2000000")
        pool = m.pool_manager.get_pool(pid)
        pair = f"{T0}:{T1}"
        escrow = m.orderbook_escrow_address(pair)
        for t in (T0, T1):
            m.set_available_token_balance(escrow, t, D(0))

        def state():
            return (pool.state_digest(), m._order_books[pair].state_digest(),
                    m.token_balance_deltas())

        def check_ledger():
            per_token = {T0: D(0), T1: D(0)}
            for (who, tok), delta in m.token_balance_deltas().items():
                per_token[tok] += delta
            assert per_token == {T0: 0, T1: 0}, per_token
            for who in (holder, escrow) + users:
                for t in (T0, T1):
                    assert m.available_token_balance(who, t) >= 0, (who, t)

        for step in range(250):
            who = rng.choice(users)
            roll = rng.random()
            if roll < 0.15:
                lo = rng.randrange(-300, 300) * 10
                op = (ExchangeOpType.ADD_LIQUIDITY, {
                    "pool_id": pid, "tick_lower": lo, "tick_upper": lo + rng.randrange(1, 80) * 10,
                    # sometimes far more than anyone can pay
                    "amount": str(rng.choice([rng.randint(1_000, 500_000), 10 ** 12]))})
            elif roll < 0.6:
                a, b = (T0, T1) if rng.random() < 0.5 else (T1, T0)
                params = {"token_in": a, "token_out": b, "amount_in": str(rng.randint(1, 6_000))}
                if rng.random() < 0.15:
                    params["min_amount_out"] = "999999999"
                op = (ExchangeOpType.SWAP, params)
            elif roll < 0.75 and pool.state.positions:
                pos = pool.state.positions[rng.choice(sorted(pool.state.positions))]
                remover = pos.owner if rng.random() < 0.8 else rng.choice(users)
                amount = None if rng.random() < 0.5 else str(
                    (pos.liquidity * D(rng.random())).quantize(D(1)))
                params = {"pool_id": pid, "position_id": pos.id}
                if amount is not None:
                    params["amount"] = amount
                who, op = remover, (ExchangeOpType.REMOVE_LIQUIDITY, params)
            elif roll < 0.92:
                op = (ExchangeOpType.PLACE_ORDER, {
                    "pair": pair, "side": rng.choice(["buy", "sell"]), "order_type": "limit",
                    "price": str(D(rng.randint(90, 110)) / 100),
                    "amount": str(rng.randint(1, 5_000))})
            else:
                mine = [o for o in m._order_books[pair]._orders.values() if o.is_active]
                if not mine:
                    continue
                o = rng.choice(sorted(mine, key=lambda o: o.id))
                canceller = o.owner if rng.random() < 0.8 else rng.choice(users)
                who, op = canceller, (ExchangeOpType.CANCEL_ORDER, {"pair": pair,
                                                                     "order_id": o.id})
            before = state()
            r = m.process_transaction(_tx(who, *op))
            if not r.success:
                assert state() == before, (step, op, r.error)
            check_ledger()

        # Everyone leaves.
        for pos_id in sorted(pool.state.positions):
            owner = pool.state.positions[pos_id].owner
            assert m.process_transaction(_tx(owner, ExchangeOpType.REMOVE_LIQUIDITY,
                                             {"pool_id": pid, "position_id": pos_id})).success
        for o in sorted(m._order_books[pair]._orders.values(), key=lambda o: o.id):
            assert m.process_transaction(_tx(o.owner, ExchangeOpType.CANCEL_ORDER,
                                             {"pair": pair, "order_id": o.id})).success
        check_ledger()
        for t, fees in ((T0, pool.state.protocol_fees_0), (T1, pool.state.protocol_fees_1)):
            dust = m.available_token_balance(holder, t) - fees
            assert D(0) <= dust < D("1e-12"), (t, dust)
            assert m.available_token_balance(escrow, t) == 0
    finally:
        ExchangeStateManager.reset_instance()
