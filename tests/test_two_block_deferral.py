"""
Execution deferred a second block (chain-spec feature ``two_block_deferral``; qrdx/post_state.py).

Block N signs the root after block N−2, so a proposer can judge, sign and send its block while its
parent still runs. What must hold:

* the lag: block N is checked against the state after N−2 (from block 2; across an activation the
  state before it is signed twice and none is skipped), and the state after h is vouched for by
  block h + 2;
* those roots are kept by block hash in the database too: a node checks the next block after a
  restart (and a snapshot restore keeps the one its first block needs: tests/test_snapshot*.py);
* the fee floor: within a block, nothing but fees takes a fee-paying account below
  min(FEE_RESERVE_QRDX, its balance as the block began) less the fees the block reserved from it,
  unless its own transaction spends its reserve; protocol holders and system wallets have none;
* so a proposer may judge the next block's fees on the state before its parent and the parent's
  contents alone: random chains built that way — transfers in and out, reserve spends, cancels —
  are every one accepted by importers judging on the state the parent left. Without the floor
  the same chains are not (the test has teeth);
* the native lanes keep the floor as Python does (tests/test_transfer_lane.py and
  tests/test_order_lane.py run their random blocks with it in force).
"""

import os
import random
import tempfile
from decimal import Decimal as D

import pytest

from qrdx import chain_spec as cs
from qrdx import constants, post_state
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP
from qrdx.exchange import transfer_lane
from qrdx.exchange.fair_ordering import fair_order
from qrdx.exchange.handlers.common import _OperationFailed

GWEI = 10 ** 9
GAS = 1_000_000
MAX_FEE = D(GAS * GWEI) / D(10 ** 18)                      # 0.001 QRDX reserved per transaction
ALICE, BOB, CAROL, DAN = ("0xPQ" + h * 64 for h in "abcd")
T0 = 1_700_000_000
Op = ExchangeOpType


@pytest.fixture(autouse=True)
def _one_gwei_floor(monkeypatch):
    monkeypatch.setattr(constants, "EXCHANGE_MIN_GAS_PRICE_WEI", GWEI)


@pytest.fixture
def m():
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    BP.apply_enforcement(mgr)
    mgr.begin_block(1, float(T0))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(op, params=None, sender=ALICE, nonce=0):
    return ExchangeTransaction(op_type=op, sender=sender, nonce=nonce, params=params or {},
                               gas_limit=GAS, gas_price=GWEI)


def _send(to, amount, sender=ALICE, nonce=0, spend=False):
    params = {"token_address": "QRDX", "to": to, "amount": str(amount)}
    if spend:
        params["spend_reserve"] = True
    return _tx(Op.TOKEN_TRANSFER, params, sender=sender, nonce=nonce)


def _block(m, txs, balances, height=2):
    m.clear_available_balances()
    for holder, amount in balances.items():
        m.set_available_balance(holder, D(amount))
    return BP.process_exchange_transactions(height, float(T0 + height), txs, m)


# ── the lag ───────────────────────────────────────────────────────────────────────────────────


def test_the_feature_is_a_genesis_default_and_signs_two_blocks_back():
    assert post_state.TWO_BLOCKS in cs.GENESIS_DEFAULT_FEATURES
    assert post_state.two_blocks(5) and post_state.lag(5) == 2
    assert post_state.lag(1) == 1                           # (block 1 signs the genesis state)
    assert post_state.signer_of(5) == 7 and post_state.newest_signed(9) == 7


def test_without_its_prerequisites_it_does_nothing():
    for dropped in ("exchange_inclusion", "deferred_execution"):
        with cs.use_spec(cs.build_spec(
                "qrdx-test-no-" + dropped.replace("_", "-"), 991243, {}, dev=True,
                features=[f for f in cs.GENESIS_DEFAULT_FEATURES if f != dropped])):
            assert not post_state.two_blocks(5)
            assert post_state.lag(5) == (0 if dropped == "deferred_execution" else 1)
            from qrdx.exchange.state_manager import fee_reserve_at

            assert fee_reserve_at(5) is None


def test_across_an_activation_no_state_goes_unsigned(monkeypatch):
    monkeypatch.setattr(post_state, "two_blocks", lambda h: h is not None and h >= 10)
    assert [post_state.lag(h) for h in (8, 9, 10, 11)] == [1, 1, 2, 2]
    signed = {h - post_state.lag(h) for h in range(2, 20)}
    assert signed == set(range(1, 18))                      # (8 by blocks 9 and 10; none skipped)
    assert [post_state.signer_of(h) for h in (7, 8, 9, 10)] == [8, 9, 11, 12]


class _Blocks:
    def __init__(self, roots):
        self.roots = roots

    async def get_block_by_id(self, h):
        if h not in self.roots:
            return None
        return {"content": str({"state_root": self.roots[h], "slot": h})}


async def test_the_state_after_a_block_is_vouched_for_two_blocks_on():
    db = _Blocks({4: "aa" * 64, 5: "bb" * 64, 6: "cc" * 64})
    assert await post_state.signed_root_of_state(db, 4) == ("cc" * 64, 6)
    assert await post_state.signed_root_of_state(db, 5) == (None, 7)   # (not signed yet)


async def test_a_block_is_checked_against_its_grandparents_state():
    class _Db:
        async def get_block_hashes(self, lo, hi):
            return {lo: f"hash{lo}"}

        async def get_next_block_id(self):
            return 8                                        # (the tip is block 7)

    post_state.forget()
    post_state.remember("hash6", "cc" * 64)
    assert await post_state.check(_Db(), str({"state_root": "cc" * 64}), 8) == (True, "")
    ok, why = await post_state.check(_Db(), str({"state_root": "dd" * 64}), 8)
    assert not ok and "mismatch" in why and "block 6 left" in why
    post_state.forget()                                      # (not kept, and not the state now:)
    ok, why = await post_state.check(_Db(), str({"state_root": "cc" * 64}), 8)
    assert not ok and "not kept here" in why


async def test_the_roots_are_kept_through_a_restart():
    from qrdx.database_sqlite import DatabaseSQLite

    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        await post_state.store(db, 5, "h5", "r5")
        await db.connection.commit()
        post_state.forget()                                  # (a restart: memory is gone)
        assert await post_state.stored(db, "h5") == "r5"
        assert await post_state.root_after(db, 5, "h5") == "r5"
        with pytest.raises(LookupError):
            await post_state.root_after(db, 3, "unknown")    # (and the state now is not it)
        # far below the tip, rows go
        await post_state.store(db, 1024 * 9, "far", "rf")
        post_state.forget()
        assert await post_state.stored(db, "h5") is None and await post_state.stored(db, "far")
    finally:
        post_state.forget()
        await db.connection.close()
        os.remove(path)


# ── the fee floor ─────────────────────────────────────────────────────────────────────────────


def test_nothing_but_fees_takes_an_account_below_its_reserve(m):
    ok, err, _ = _block(m, [_send(BOB, "4.5")], {ALICE: 5, BOB: 0})
    assert ok, err
    (r,) = m._block_results
    assert not r.success and "fee reserve" in r.error and "spend_reserve" in r.error
    assert m.fee_floor(ALICE) == 1 - MAX_FEE                 # (min(R, 5) less its block's fees)

    ok, err, _ = _block(m, [_send(BOB, "3.9", nonce=1)], {ALICE: 5, BOB: 0}, height=3)
    assert ok and m._block_results[0].success                # (5 − 3.9 − fee keeps the floor)


def test_an_account_below_the_reserve_spends_only_by_its_own_say(m):
    ok, _, _ = _block(m, [_send(BOB, "0.2")], {ALICE: "0.5", BOB: 0})
    assert ok and not m._block_results[0].success
    assert m.fee_floor(ALICE) == D("0.5") - MAX_FEE          # (all it held, less its fees)
    ok, _, _ = _block(m, [_send(BOB, "0.2", nonce=1, spend=True)], {ALICE: "0.5", BOB: 0}, 3)
    assert ok and m._block_results[0].success


def test_what_comes_in_during_the_block_may_go_out(m):
    txs = [_send(ALICE, "3", sender=BOB), _send(CAROL, "3.4")]
    ok, err, _ = _block(m, txs, {ALICE: "1.5", BOB: 10, CAROL: 0})
    assert ok, err
    assert [r.success for r in m._block_results] == [True, True]
    assert D("1.5") + m.balance_deltas()[ALICE] >= m.fee_floor(ALICE)


def test_a_reserve_spend_frees_only_its_own_sender(m):
    m.begin_block(2, float(T0 + 2))
    for who in (ALICE, BOB):
        m.set_available_balance(who, D(1))
    m._reserve_spender = ALICE
    try:
        m._record_balance_delta(ALICE, D("-0.9"))              # (its own: may)
        with pytest.raises(_OperationFailed):
            m._record_balance_delta(BOB, D("-0.9"))             # (someone else's: may not)
    finally:
        m._reserve_spender = None


def test_only_accounts_that_pay_fees_have_a_floor(m):
    from qrdx.exchange.handlers.tokens import orderbook_escrow_address
    from qrdx.exchange.trading import subaccount_address

    m.begin_block(2, float(T0 + 2))
    escrow, wallet = orderbook_escrow_address("A:QRDX"), constants.SYSTEM_WALLET_ADDRESSES["AIRDROP"]
    sub, multisig = subaccount_address(ALICE, 1), "0xPQMS" + "ab" * 32
    for holder in (escrow, wallet, sub, multisig):
        m.set_available_balance(holder, D(5))
    assert m.fee_floor(escrow) is None and m.fee_floor(wallet) is None
    assert m.fee_floor(sub) == m.fee_floor(multisig) == D(1)
    m._record_balance_delta(escrow, D(-5))                      # (an escrow pays out all it holds)


# ── the guarantee a pipelined proposer builds on ──────────────────────────────────────────────


def _chain(seed, blocks=25, native=True):
    """A chain built as a proposer that has not run its parent builds: each block judged on the
    state before its parent (its balances) and the parent's contents (each payer's fees in it,
    and whether it spent its reserve) — fees within min(R, balance) less the parent's. Runs it
    as importers do; returns (blocks an importer refused, floor breaches)."""
    rng = random.Random(seed)
    who = [ALICE, BOB, CAROL, DAN]
    reserve = D(constants.FEE_RESERVE_QRDX)
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    BP.apply_enforcement(m)
    m.begin_block(1, float(T0))
    held = {a: D(rng.choice(["0", "0.3", "1", "1.2", "2", "5", "40"])) for a in who}
    nonces = {a: 0 for a in who}
    before = dict(held)                                       # (the state before the parent)
    parent: list = []                                         # (the parent's transactions)
    refused = breaches = 0
    for height in range(2, blocks + 2):
        # Judge the block on the state before its parent and the parent's contents.
        fees = {a: sum((MAX_FEE for t in parent if t.sender == a), D(0)) for a in who}
        spent = {t.sender for t in parent if t.spends_reserve()}
        bound = {a: min(reserve, before[a]) - fees[a] for a in who if a not in spent}
        txs, owed, drained = [], {a: D(0) for a in who}, set()
        for _ in range(rng.randint(0, 10)):
            a = rng.choice(who)
            if a not in bound or a in drained or owed[a] + MAX_FEE > bound[a]:
                continue
            k = rng.random()
            if k < 0.25:
                t = _tx(Op.CANCEL_ALL, sender=a, nonce=nonces[a])
            else:
                amount = rng.choice(["0.05", "0.3", "0.9", "1", "2.5", "7"])
                if k > 0.85 and held[a] - owed[a] - MAX_FEE > 0:
                    # (its last in the block: everything it holds after the block's fees — the
                    # account knows its balance — which would leave its next block's unpaid)
                    amount = str(held[a] - owed[a] - MAX_FEE)
                    drained.add(a)
                t = _send(rng.choice(who), amount, sender=a, nonce=nonces[a],
                          spend=rng.random() < 0.15)
            txs.append(t)
            owed[a] += MAX_FEE
            nonces[a] += 1
        txs = fair_order(txs)
        # An importer judges it on the state its parent left.
        m.clear_available_balances()
        for a in who:
            m.set_available_balance(a, held[a])
        monkey = None if native else transfer_lane._native
        if not native:
            transfer_lane._native = lambda name: None
        try:
            errors = m.section_errors(txs, height, float(T0 + height))
            ok, _err, _ = BP.process_exchange_transactions(height, float(T0 + height), txs, m)
        finally:
            if monkey is not None:
                transfer_lane._native = monkey
        if errors or not ok:
            refused += 1
            break                                             # (an importer would refuse it)
        m.commit_block()
        after = {a: held[a] + m.balance_deltas().get(a, D(0)) for a in who}
        for a in who:
            mine = [t for t in txs if t.sender == a]
            if not any(t.spends_reserve() for t in mine):
                floor = min(reserve, held[a]) - MAX_FEE * len(mine)
                breaches += after[a] < floor
        before, held, parent = held, after, txs
    ExchangeStateManager.reset_instance()
    return refused, breaches


@pytest.mark.parametrize("seed", range(10))
def test_a_block_judged_without_its_parents_run_is_one_importers_accept(seed):
    for native in (True, False):
        assert _chain(seed, native=native) == (0, 0)


def test_without_the_floor_such_blocks_are_refused(monkeypatch):
    """The same chains, with nothing holding the reserve: blocks judged that way are refused
    (a payer spent in the parent what its fees in the block needed)."""
    from qrdx.exchange import state_manager

    monkeypatch.setattr(state_manager, "fee_reserve_at", lambda height: None)
    outcomes = [_chain(seed) for seed in range(10)]
    assert sum(refused for refused, _ in outcomes) >= 3, outcomes
    assert sum(breaches for _, breaches in outcomes) > 0, outcomes
