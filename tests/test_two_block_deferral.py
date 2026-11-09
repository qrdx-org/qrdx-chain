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
    """A chain built as a pipelined proposer builds it (qrdx/validator/pipeline.py): each block
    judged by ``pipeline.judge`` BEFORE its parent runs — on the state before the parent and the
    parent's contents — then the parent run as importers run it, judged on the state its own
    parent left. Transfers in and out (some spending the reserve, some draining an account),
    paid and free cancels. Returns (blocks an importer refused, floor breaches, carried)."""
    from qrdx.validator import pipeline

    rng = random.Random(seed)
    who = [ALICE, BOB, CAROL, DAN]
    reserve = D(constants.FEE_RESERVE_QRDX)
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    BP.apply_enforcement(m)
    m.begin_block(1, float(T0))
    held = {a: D(rng.choice(["0", "0.3", "1", "1.2", "2", "5", "40"])) for a in who}
    nonces = {a: 0 for a in who}  # (each account's next, after what blocks carried)
    parent: list = []  # (judged, not run yet)
    refused = breaches = carried = 0
    saved = transfer_lane._native
    if not native:
        transfer_lane._native = lambda name: None
    try:
        for height in range(2, blocks + 3):
            # 1. The block at ``height``, judged while its parent has not run: the state now is
            #    the one before the parent.
            txs: list = []
            if height <= blocks + 1:
                effects = pipeline.parent_effects(m, parent, [])
                bound = pipeline.bounds(effects, held, reserve)
                start, owed, drained, candidates = dict(nonces), {a: D(0) for a in who}, set(), []
                for _ in range(rng.randint(0, 12)):
                    a = rng.choice(who)
                    if a in drained:
                        continue
                    k = rng.random()
                    if k < 0.3:
                        t = _tx(Op.CANCEL_ALL, sender=a, nonce=nonces[a])
                        if k < 0.1:
                            t.gas_price = 0  # (the free lane)
                    else:
                        amount = rng.choice(["0.05", "0.3", "0.9", "1", "2.5", "7"])
                        rest = held[a] - effects.fees.get(a, D(0)) - owed[a] - MAX_FEE
                        if k > 0.85 and rest > 0:
                            # (its last in the block: all it will hold after the parent's fees
                            # and this block's — which would leave the next block's unpaid)
                            amount = str(rest)
                            drained.add(a)
                        t = _send(rng.choice(who), amount, sender=a, nonce=nonces[a],
                                  spend=rng.random() < 0.15)
                    candidates.append(t)
                    owed[a] += t.max_fee()
                    nonces[a] += 1
                txs = pipeline.judge(m, fair_order(candidates), height, float(T0 + height), None,
                                     effects, bound.get)
                for a in who:
                    kept = [t.nonce for t in txs if t.sender == a]
                    nonces[a] = max(kept) + 1 if kept else start[a]
            # 2. The parent runs, as every importer runs it.
            h = height - 1
            m.clear_available_balances()
            for a in who:
                m.set_available_balance(a, held[a])
            errors = m.section_errors(parent, h, float(T0 + h))
            ok, _err, _ = BP.process_exchange_transactions(h, float(T0 + h), parent, m)
            if errors or not ok:
                refused += 1
                break
            m.commit_block()
            after = {a: held[a] + m.balance_deltas().get(a, D(0)) for a in who}
            for a in who:
                mine = [t for t in parent if t.sender == a]
                if not any(t.spends_reserve() for t in mine):
                    floor = min(reserve, held[a]) - sum((t.max_fee() for t in mine), D(0))
                    breaches += after[a] < floor
            held, parent = after, txs
            carried += len(txs)
    finally:
        transfer_lane._native = saved
        ExchangeStateManager.reset_instance()
    return refused, breaches, carried


@pytest.mark.parametrize("seed", range(10))
def test_a_block_judged_before_its_parent_runs_is_one_importers_accept(seed):
    for native in (True, False):
        refused, breaches, carried = _chain(seed, native=native)
        assert (refused, breaches) == (0, 0) and carried > 40, (refused, breaches, carried)


def test_without_the_floor_such_blocks_are_refused(monkeypatch):
    """The same chains, with nothing holding the reserve: blocks judged that way are refused
    (a payer spent in the parent what its fees in the block needed)."""
    from qrdx.exchange import state_manager

    monkeypatch.setattr(state_manager, "fee_reserve_at", lambda height: None)
    outcomes = [_chain(seed) for seed in range(10)]
    assert sum(refused for refused, _, _ in outcomes) >= 3, outcomes
    assert sum(breaches for _, breaches, _ in outcomes) > 0, outcomes


# ── the pipelined proposer's pieces (qrdx/validator/pipeline.py) ─────────────────────────────


def test_a_parents_effects_come_from_its_contents(m):
    from qrdx.validator import pipeline

    vote = _tx(Op.ORACLE_VOTE, {"prices": {"BTC": "1"}}, sender=DAN, nonce=4)
    free = _tx(Op.CANCEL_ALL, sender=CAROL, nonce=2)
    free.gas_price = 0
    parent = [vote, free, _send(BOB, "1", nonce=0), _send(BOB, "1", nonce=1, spend=True),
              _tx(Op.CANCEL_ALL, sender=BOB, nonce=5)]
    e = pipeline.parent_effects(m, parent, [])
    assert e.unbounded == "" and e.voters == {DAN.lower()} and e.free == {CAROL}
    assert e.lanes == {ALICE: 2, CAROL: 3, BOB: 6} and e.spent == {ALICE}
    assert e.fees == {ALICE: 2 * MAX_FEE, BOB: MAX_FEE}
    b = pipeline.bounds(e, {ALICE: D(9), BOB: D("0.5"), CAROL: D(3)}, D(1))
    assert b == {ALICE: None, BOB: D("0.5") - MAX_FEE, CAROL: D(1)}
    # what changes another block's judgment beyond balances and nonces: run the parent first
    for op, params in ((Op.AGENT_APPROVE, {"agent": BOB}), (Op.STAKE_DEPOSIT, {}),
                       (Op.BATCH, {"actions": [{"op": "AGENT_REVOKE", "params": {}}]})):
        assert pipeline.parent_effects(m, [_tx(op, params)], []).unbounded


def test_an_evm_sender_in_the_parent_has_no_bound(m):
    from qrdx.crypto.account_id import to_account_id
    from qrdx.validator import pipeline

    e = pipeline.ParentEffects(evm_senders={to_account_id(ALICE).lower()})
    assert pipeline.bounds(e, {ALICE: D(5), BOB: D(5)}, D(1)) == {ALICE: None, BOB: D(1)}


def test_the_mempool_selects_after_a_parent_not_run(m):
    from qrdx.exchange import ExchangeMempool
    from qrdx.crypto.pq.dilithium import PQPrivateKey

    keys = [PQPrivateKey.generate() for _ in range(2)]
    pool = ExchangeMempool(nonce_provider=lambda lane: 0)
    for key in keys:
        for n in range(3):
            t = _tx(Op.CANCEL_ALL, sender=key.public_key.to_address(), nonce=n)
            t.public_key = key.public_key.to_bytes()
            t.signature = key.sign(t.signing_bytes()).to_bytes()
            assert pool.admit(t)[0]
    a, b = (k.public_key.to_address() for k in keys)
    picked = pool.select_for_block(after={a: 2}, skip={b})
    assert [(t.sender, t.nonce) for t in picked] == [(a, 2)]


def test_base_fees_come_from_a_parent_not_stored():
    from qrdx import fee_market

    content = {"base_fee": 2 * 10 ** 9, "exchange_base_fee": 3 * 10 ** 8}
    section = [_send(BOB, "1", nonce=n).to_dict() for n in range(3)]
    inputs = fee_market.parent_inputs(content, section, [])
    assert inputs == ((2 * 10 ** 9, 3 * 10 ** 8), 0, 3 * GAS)

    class _NoChain:
        async def get_block_by_id(self, h):
            raise AssertionError("the parent is not read from the chain")

    import asyncio

    fees = asyncio.run(fee_market.base_fees_at(_NoChain(), 5, parent=inputs))
    assert fees[1] == fee_market.next_base_fee(
        3 * 10 ** 8, 3 * GAS, __import__("qrdx.block_limits").block_limits.exchange_gas_limit_at(4),
        fee_market.floors()[1])


def test_the_import_builds_before_running_and_finishes_after():
    """The live import asks the proposer before the block runs, and runs the block it built only
    once its parent's journal and undo scope have closed (never nested in them)."""
    import inspect

    from qrdx.rpc.modules import p2p
    from qrdx.validator import node_integration as NI

    submit = inspect.getsource(p2p.P2PModule.submitBlock)
    assert submit.index("_check_deferred_root(") < submit.index("propose_ahead(")
    assert submit.index("propose_ahead(") < submit.index("_run_pos_block(")
    run = inspect.getsource(p2p.P2PModule._run_pos_block)
    body, tail = run.split("        finally:\n", 1)
    assert "async with await before_block(" in body and "finish_ahead(" in tail
    ahead = inspect.getsource(NI.ValidatorNode.propose_ahead)
    assert ahead.index("parent_effects(") < ahead.index("_select_sections(")
    assert ahead.index("_select_sections(") < ahead.index("_sign_and_send(")
    finish = inspect.getsource(NI.ValidatorNode.finish_ahead)
    assert finish.index("before_block(") < finish.index("_run_and_store(")
