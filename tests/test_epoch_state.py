"""
The validator set as a pure function of the chain (qrdx/validator/epoch_state.py).

``S_E`` — the validators at the start of epoch E — comes from the genesis set and the chain's
blocks alone: executed stake operations, votes carried within the inclusion window, slashing
proofs. Every block is judged against ``S_E`` of its own parent chain, on every path, so a block
judged during a sync or on a branch being adopted is judged against the set it was proposed
under. And a STAKE_DEPOSIT the exchange refused registers nothing (it used to register any stake
its sender named: one holding gas money got ~77 % of the stake).
"""
import hashlib
import inspect
import json
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx import constants
from qrdx.constants import ACTIVATION_DELAY_EPOCHS, SLOTS_PER_EPOCH
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator import epoch_state as ES
from qrdx.validator.epoch_state import EpochInputs, genesis_state, transition
from qrdx.validator.ffg import INCLUSION_EPOCHS

D = Decimal
G = [f"0xPQ{c * 64}" for c in "abc"]          # genesis validators
J = "0xPQ" + "d" * 64                          # a joiner


def _att(validator, target):
    return {"slot": target * SLOTS_PER_EPOCH, "epoch": target, "block_hash": "bh",
            "validator_address": validator, "validator_index": 0, "signature": "",
            "source_epoch": max(0, target - 1), "target_epoch": target,
            "included_in_block": None, "created_at": "2020-01-01T00:00:00"}


class Chain:
    """Blocks stored the way import stores them, and the executed-stake-op logs block
    application writes."""

    def __init__(self, db, tag="a"):
        self.db, self.tag, self.height = db, tag, -1

    async def genesis(self, stakes=(100_000, 100_000, 100_000)):
        await self.db.record_genesis_validators(
            [{"address": a, "public_key": "", "stake": str(s)} for a, s in zip(G, stakes)])
        await self._put(0, 0, {"type": "genesis"})

    async def _put(self, height, slot, extra):
        bh = f"{self.tag}{height:063d}"
        content = {"number": height, "slot": slot, "epoch": slot // SLOTS_PER_EPOCH, **extra}
        await self.db.connection.execute(
            "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
            (bh, height, repr(content)))
        self.height = height
        return bh

    async def block(self, slot, votes=(), deposits=(), exits=(), evidence=()):
        from qrdx.validator.withdrawals import record_validator_exit

        h = self.height + 1
        bh = await self._put(h, slot, {"attestations": [_att(v, t) for v, t in votes],
                                       "slashing_evidence": list(evidence)})
        for address, stake in deposits:
            await self.db.log_validator_deposit(address, "", stake, h, bh)
        for address in exits:
            await record_validator_exit(
                self.db, address, slot // SLOTS_PER_EPOCH + constants.UNBONDING_PERIOD_EPOCHS, h)
        await self.db.connection.commit()
        return h

    async def epoch(self, e, voters=G, target=None, **kw):
        """One block in the middle of epoch ``e`` carrying votes for ``target`` (e − 1)."""
        target = e - 1 if target is None else target
        votes = [(v, target) for v in voters] if target >= 1 else []
        return await self.block(e * SLOTS_PER_EPOCH + 1, votes=votes, **kw)

    async def rollback(self, to_height):
        from qrdx.validator.withdrawals import undo_withdrawal_logs_above

        await self.db.connection.execute("DELETE FROM blocks WHERE block_height > ?", (to_height,))
        await self.db.undo_validator_deposits_above(to_height)
        await undo_withdrawal_logs_above(self.db, to_height)
        await self.db.connection.commit()
        self.height = to_height



def _uncap(monkeypatch):
    """These stakes (100,000) sit at the effective-stake cap (MAX_EFFECTIVE_STAKE, 1 % of the
    genesis supply): lift it, so a reward shows."""
    from qrdx.validator import epoch_processing

    monkeypatch.setattr(epoch_processing, "MAX_EFFECTIVE_BALANCE", D(10_000_000))

@pytest.fixture
async def chain():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(path)
    c = Chain(db)
    await c.genesis()
    yield c
    await db.connection.close()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.remove(p)


def _row(state, address):
    return state.get(address)


# ── the transition ────────────────────────────────────────────────────────

def _inputs(ops=(), attesters=(), offenders=()):
    return EpochInputs(ops=list(ops), attesters=list(attesters), offenders=list(offenders))


def test_a_deposit_is_pending_and_does_not_propose_until_it_activates():
    s = genesis_state([{"address": a, "stake": 100_000} for a in G])
    s = transition(s, 1, _inputs([("deposit", J, "pk", D(200_000))]))
    assert s[J].status == "pending" and s[J].activation_epoch == 1 + ACTIVATION_DELAY_EPOCHS
    assert J not in dict(ES.proposers(s))
    for e in range(2, 1 + ACTIVATION_DELAY_EPOCHS):
        s = transition(s, e, _inputs())
        assert s[J].status == "pending"
    s = transition(s, 1 + ACTIVATION_DELAY_EPOCHS, _inputs())
    assert s[J].status == "active" and dict(ES.proposers(s))[J] == D(200_000)


def test_rewards_wait_for_the_inclusion_window_and_count_only_votes_in_it(monkeypatch):
    _uncap(monkeypatch)
    s = genesis_state([{"address": a, "stake": 100_000} for a in G])
    t = 3
    s = transition(s, t + INCLUSION_EPOCHS, _inputs(attesters=[G[0], G[1]]))
    base = D(100_000) / ES_reward_quotient()
    assert s[G[0]].effective_stake == D(100_000) + base.quantize(D("1e-8"))
    assert s[G[2]].effective_stake == D(100_000) - base.quantize(D("1e-8"))
    # Epochs whose target would be 0 or below have no votes to count: nothing moves.
    s0 = genesis_state([{"address": a, "stake": 100_000} for a in G])
    assert transition(s0, INCLUSION_EPOCHS, _inputs()) == s0


def ES_reward_quotient():
    from qrdx.validator.epoch_rewards import DEFAULT_REWARD_QUOTIENT
    return DEFAULT_REWARD_QUOTIENT


def test_an_exit_keeps_proposing_through_unbonding(monkeypatch):
    monkeypatch.setattr(constants, "UNBONDING_PERIOD_EPOCHS", 3)
    s = genesis_state([{"address": a, "stake": 100_000} for a in G])
    s = transition(s, 1, _inputs([("exit", G[0], None, None)]))
    assert s[G[0]].status == "exiting" and s[G[0]].exit_epoch == 4
    assert G[0] in dict(ES.proposers(s))
    for e in (2, 3):
        s = transition(s, e, _inputs())
    s = transition(s, 4, _inputs())
    assert s[G[0]].status == "exited" and G[0] not in dict(ES.proposers(s))


def test_an_exit_while_pending_never_activates():
    s = genesis_state([{"address": a, "stake": 100_000} for a in G])
    s = transition(s, 1, _inputs([("deposit", J, "pk", D(100_000)), ("exit", J, None, None)]))
    for e in range(2, 3 + ACTIVATION_DELAY_EPOCHS):
        s = transition(s, e, _inputs())
    assert s[J].status == "exited" and J not in dict(ES.proposers(s))


def test_a_top_up_counts_at_once():
    s = genesis_state([{"address": a, "stake": 100_000} for a in G])
    s = transition(s, 1, _inputs([("deposit", G[0], "", D(50_000))]))
    assert s[G[0]].stake == D(150_000) and dict(ES.proposers(s))[G[0]] == D(150_000)


def test_a_slashing_proof_halves_and_ejects_once():
    s = genesis_state([{"address": a, "stake": 100_000} for a in G])
    s = transition(s, 1, _inputs(offenders=[G[1].lower(), G[1]]))
    assert s[G[1]].status == "slashed" and s[G[1]].effective_stake == D(50_000)
    assert G[1] not in dict(ES.proposers(s))
    s = transition(s, 2, _inputs(offenders=[G[1]]))
    assert s[G[1]].effective_stake == D(50_000)            # once


def test_ejection_keeps_the_liveness_backstop():
    four = G + [J]
    s = genesis_state([{"address": a, "stake": 1_000} for a in four])
    s[G[0]].effective_stake = D(400)                       # the floor is 500 (half of 1,000)
    s[G[1]].effective_stake = D(300)
    s = transition(s, 1, _inputs())
    # Two below the floor, but only one may go: three must stay active. The lowest goes.
    assert s[G[1]].status == "exiting" and s[G[0]].status == "active"


# ── on the chain ──────────────────────────────────────────────────────────

async def test_genesis_validators_propose_from_the_start(chain):
    s = await ES.state_at(chain.db, 0)
    assert sorted(dict(ES.proposers(s))) == sorted(G)


async def test_a_refused_deposit_registers_nothing():
    """The exchange refuses a STAKE_DEPOSIT naming more stake than its sender holds; the block
    still carries it (a failed transaction pays its gas). It used to become a validator with
    whatever stake it named."""
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
    from qrdx.exchange import block_processor as BP

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(path)
    try:
        c = Chain(db)
        await c.genesis()
        key = PQPrivateKey.generate()
        addr = key.public_key.to_address()
        await db.add_transaction(tx_hash="alloc", block_hash=f"a{0:063d}", tx_hex=json.dumps(
            {"type": "genesis_allocation", "recipient": addr, "amount": "1"}))
        await db.seed_genesis_account_state()
        tx = ExchangeTransaction(op_type=ExchangeOpType.STAKE_DEPOSIT, sender=addr, nonce=0,
                                 params={"stake_amount": "1000000",
                                         "validator_public_key": key.public_key.to_bytes().hex()},
                                 gas_limit=200_000, gas_price=10**9)
        tx.public_key = key.public_key.to_bytes()
        tx.signature = key.sign(tx.signing_bytes()).to_bytes()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        BP.apply_enforcement(mgr)
        await BP.preload_sender_balances(db, [tx], mgr)
        ok, _err, _root = BP.process_exchange_transactions(1, 1_700_000_001.0, [tx], mgr)
        assert ok and not mgr._block_results[0].success
        h = await c.block(SLOTS_PER_EPOCH + 1)               # the block carrying it
        await db.add_block_exchange_txs(f"a{h:063d}", [tx.to_dict()])
        await BP.flush_validator_lifecycle_deltas(db, mgr, block_epoch=1, block_height=h)
        for e in range(2, 4 + ACTIVATION_DELAY_EPOCHS):
            await c.epoch(e)
        state = await ES.state_at(db, 4 + ACTIVATION_DELAY_EPOCHS)
        assert addr not in state
    finally:
        ExchangeStateManager.reset_instance()
        await db.connection.close()
        os.remove(path)


async def test_a_deposit_on_the_chain_activates_after_the_delay(chain):
    await chain.epoch(1, deposits=[(J, "150000")])
    for e in range(2, 2 + ACTIVATION_DELAY_EPOCHS):        # S_2 .. S_(1+delay): pending
        await chain.epoch(e)
        state = await ES.state_at(chain.db, e)
        assert state[J].status == "pending" and J not in dict(ES.proposers(state))
    state = await ES.state_at(chain.db, 2 + ACTIVATION_DELAY_EPOCHS)
    assert state[J].status == "active" and dict(ES.proposers(state))[J] == D(150_000)


async def test_rewards_follow_the_votes_the_chain_carries(chain, monkeypatch):
    _uncap(monkeypatch)
    await chain.epoch(1)
    await chain.epoch(2, voters=G[:2])                       # G[2] misses its vote for 1
    for e in range(3, 6):
        await chain.epoch(e)
    s = await ES.state_at(chain.db, 1 + INCLUSION_EPOCHS + 1)
    assert s[G[0]].effective_stake > D(100_000) > s[G[2]].effective_stake


async def test_a_late_vote_does_not_count(chain):
    await chain.epoch(1)
    await chain.epoch(2, voters=G[:2])
    await chain.epoch(3)
    await chain.epoch(4)
    await chain.epoch(5, voters=G, target=1)                 # G[2]'s vote for 1: too late
    for e in range(6, 8):
        await chain.epoch(e)
    s = await ES.state_at(chain.db, 7)
    assert s[G[2]].total_slashed > 0                         # penalized for epoch 1


async def test_the_state_is_a_function_of_the_chain_not_of_its_history():
    """Node B first imports a branch carrying a deposit and votes, then reorgs onto A's chain.
    Its states — computed during and after — equal A's, epoch by epoch."""
    dbs, paths = [], []
    for _ in range(2):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        dbs.append(await DatabaseSQLite.create(path))
        paths.append(path)
    try:
        a, b = Chain(dbs[0], "a"), Chain(dbs[1], "a")
        for c in (a, b):
            await c.genesis()
            await c.epoch(1)
            await c.epoch(2)
        b.tag = "x"
        await b.epoch(3, deposits=[(J, "500000")], voters=G[:1])
        await b.epoch(4)
        await ES.state_at(b.db, 5)                           # cached on the orphaned branch
        await b.rollback(2)
        b.tag = "a"
        for c in (a, b):
            for e in range(3, 10):
                await c.epoch(e)
        for e in range(10):
            sa, sb = await ES.state_at(a.db, e), await ES.state_at(b.db, e)
            assert ES.state_hash(sa) == ES.state_hash(sb), e
        assert J not in await ES.state_at(b.db, 9)
    finally:
        for db, path in zip(dbs, paths):
            await db.connection.close()
            os.remove(path)


async def test_a_historical_block_is_judged_against_its_own_epochs_set(chain):
    """Eligibility of a block is decided by the set of its slot's epoch on its parent chain —
    the same answer once the chain has moved on (as during a sync)."""
    from qrdx.validator.block_verification import (
        expected_proposer_for_slot, verify_proposer_eligibility,
    )

    await chain.epoch(1, deposits=[(J, "900000")])
    for e in range(2, 4 + ACTIVATION_DELAY_EPOCHS):
        await chain.epoch(e)
    late = 3 + ACTIVATION_DELAY_EPOCHS        # J proposes from here, with most of the stake
    early_slot, late_slot = 2 * SLOTS_PER_EPOCH + 5, late * SLOTS_PER_EPOCH + 5
    early_set = ES.proposers(await ES.state_at(chain.db, 2, up_to_height=2))
    late_set = ES.proposers(await ES.state_at(chain.db, late))
    assert J not in dict(early_set) and J in dict(late_set)

    def content(slot, number, proposer):
        return repr({"number": number, "slot": slot, "epoch": slot // SLOTS_PER_EPOCH,
                     "proposer_address": proposer})

    # A block of epoch 2 (height 3, on the parent chain ending at height 2), judged now.
    right = expected_proposer_for_slot(early_slot, early_set)
    wrong = next(a for a in G if a != right)
    # (A block's signed ``number`` is its slot; the importer gives its height.)
    assert (await verify_proposer_eligibility(
        chain.db, content(early_slot, early_slot, right), True, height=3))[0]
    assert not (await verify_proposer_eligibility(
        chain.db, content(early_slot, early_slot, wrong), True, height=3))[0]
    # The next block, on today's chain, is judged against today's set.
    tip = chain.height
    expected = expected_proposer_for_slot(late_slot, late_set)
    ok, _ = await verify_proposer_eligibility(
        chain.db, content(late_slot, late_slot, expected), True, height=tip + 1)
    assert ok


def test_every_import_path_enforces_eligibility():
    """Sync and fork-choice adoption used to trust-replay it (``not is_bulk_sync``)."""
    from qrdx.node import main
    src = inspect.getsource(main.process_and_create_block)
    assert "enforce=_ENFORCE_PROPOSER_ELIGIBILITY," in src and "not is_bulk_sync" not in src
    assert main._ENFORCE_PROPOSER_ELIGIBILITY


async def test_finality_weighs_each_target_by_its_own_epochs_state(chain):
    from qrdx.validator import ffg

    await chain.epoch(1, deposits=[(J, "900000")])
    for e in range(2, 5 + ACTIVATION_DELAY_EPOCHS):
        await chain.epoch(e)
    view = ffg.ChainView(chain.db)
    before = await ffg._target_stakes(chain.db, view, 2)
    after = await ffg._target_stakes(chain.db, view, 3 + ACTIVATION_DELAY_EPOCHS)
    assert J not in before and after[J] > sum(v for a, v in after.items() if a != J)
    assert before == ES.voting_stakes(await ES.state_at(chain.db, 2))


async def test_states_are_cached_per_checkpoint_and_a_reorg_never_reuses_one(chain, monkeypatch):
    for e in range(1, 6):
        await chain.epoch(e)
    calls = []
    real = ES.transition
    monkeypatch.setattr(ES, "transition", lambda s, e, i: calls.append(e) or real(s, e, i))
    await ES.state_at(chain.db, 5)
    assert calls == [0, 1, 2, 3, 4]
    calls.clear()
    await ES.state_at(chain.db, 5)
    assert calls == []                                       # computed once
    await chain.rollback(3)                                  # epochs 4, 5 change
    chain.tag = "z"
    await chain.epoch(4, voters=G[:1])
    await chain.epoch(5)
    s = await ES.state_at(chain.db, 6)
    assert calls == [4, 5]                                   # recomputed from S_4
    assert s[G[1]].effective_stake < s[G[0]].effective_stake


async def test_the_display_table_is_the_state_at_the_tip(chain):
    for e in range(1, 4):
        await chain.epoch(e)
    digest = await ES.materialize(chain.db)
    s = await ES.state_at(chain.db, 3)
    assert digest == ES.state_hash(s)
    rows = {r["address"]: r for r in await chain.db.get_validators()}
    assert set(rows) == set(s) and all(D(rows[a]["effective_stake"]) == s[a].effective_stake
                                       for a in s)


# ── stake-floor ejection (ported from the finality-gated sweep's tests) ───

def _with_stakes(stakes, status="active"):
    addrs = [f"0xPQ{i:064x}" for i in range(len(stakes))]
    s = genesis_state([{"address": a, "stake": 1_000} for a in addrs])
    for a, eff in zip(addrs, stakes):
        s[a].effective_stake = D(eff)
    return s, addrs


def test_the_ejection_floor_is_below_the_activation_floor():
    assert constants.VALIDATOR_EJECTION_STAKE == constants.MIN_VALIDATOR_STAKE / 2


@pytest.mark.parametrize("effective, ejected", [
    ("999.99", False), ("500", False), ("499.99", True), ("0", True)])
def test_only_a_stake_below_the_ejection_floor_is_ejected(effective, ejected):
    s, addrs = _with_stakes([effective, 1_000, 1_000, 1_000])
    s = transition(s, 1, _inputs())          # (epoch 1: no reward target to move stakes)
    assert (s[addrs[0]].status == "exiting") == ejected
    if ejected:      # it leaves through unbonding, still proposing meanwhile
        assert s[addrs[0]].exit_epoch == 1 + constants.UNBONDING_PERIOD_EPOCHS
        assert addrs[0] in dict(ES.proposers(s))


def test_only_active_validators_are_swept():
    s, addrs = _with_stakes([1, 100_000, 100_000, 100_000])
    s[addrs[0]].status, s[addrs[0]].activation_epoch = "pending", 100
    assert transition(s, 1, _inputs())[addrs[0]].status == "pending"


def test_ejection_never_drops_below_the_backstop_and_picks_the_same_subset():
    s, addrs = _with_stakes([10, 20, 30, 100_000, 100_000])
    out = transition(s, 1, _inputs())
    assert [out[a].status for a in addrs[:3]] == ["exiting", "exiting", "active"]
    s3, a3 = _with_stakes([10, 20, 30])
    assert all(v.status == "active" for v in transition(s3, 1, _inputs()).values())
    s, addrs = _with_stakes([10, 10, 100_000, 100_000])     # a tie: the lower address goes
    out = transition(s, 1, _inputs())
    assert [out[a].status for a in addrs[:2]] == ["exiting", "active"]


def test_an_ejected_validator_is_not_ejected_again():
    s, addrs = _with_stakes([10, 100_000, 100_000, 100_000, 100_000])
    once = transition(s, 1, _inputs())
    twice = transition(once, 2, _inputs())
    assert twice[addrs[0]].exit_epoch == once[addrs[0]].exit_epoch


# ── the chain: slashing proofs, restarts, cost, genesis top-ups ───────────

async def test_a_slashing_proof_in_a_block_slashes_on_every_node(chain):
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.validator.slashing_block import make_double_sign_evidence
    from test_slashing_evidence import _signed_header

    key = PQPrivateKey.generate()
    offender = key.public_key.to_address()
    await chain.epoch(1, deposits=[(offender, "100000")])
    for e in range(2, 3 + ACTIVATION_DELAY_EPOCHS):
        await chain.epoch(e)
    h1, _ = _signed_header(key, slot=9, state_root="11" * 32)
    h2, _ = _signed_header(key, slot=9, state_root="22" * 32)
    e = 3 + ACTIVATION_DELAY_EPOCHS
    await chain.epoch(e, evidence=[make_double_sign_evidence(h1, h2)])
    before = (await ES.state_at(chain.db, e))[offender]
    assert before.status == "active"
    after = (await ES.state_at(chain.db, e + 1))[offender]
    # Half of what is left after the epoch's own (non-attestation) penalty.
    assert after.status == "slashed" and after.slashed
    assert before.effective_stake / 2 - 10 < after.effective_stake <= before.effective_stake / 2
    assert offender not in dict(ES.proposers(await ES.state_at(chain.db, e + 1)))


async def test_a_restart_reads_the_stored_states(chain, monkeypatch):
    for e in range(1, 6):
        await chain.epoch(e)
    want = ES.state_hash(await ES.state_at(chain.db, 5))
    ES._memo.pop(chain.db, None)                             # a new process: nothing in memory
    calls = []
    real = ES.transition
    monkeypatch.setattr(ES, "transition", lambda s, e, i: calls.append(e) or real(s, e, i))
    assert ES.state_hash(await ES.state_at(chain.db, 5)) == want and calls == []


async def test_the_cost_of_a_new_epoch_does_not_grow_with_the_chain(chain, monkeypatch):
    for e in range(1, 30):
        await chain.epoch(e)
    await ES.state_at(chain.db, 29)
    await chain.epoch(30)
    calls = []
    real = ES.transition
    monkeypatch.setattr(ES, "transition", lambda s, e, i: calls.append(e) or real(s, e, i))
    await ES.state_at(chain.db, 31)
    assert calls == [29, 30]


async def test_a_genesis_validators_top_up_counts_once(chain):
    await chain.epoch(1, deposits=[(G[0], "25000")])
    for e in range(2, 6):
        await chain.epoch(e)
    for e in (2, 5):
        assert (await ES.state_at(chain.db, e))[G[0]].stake == D(125_000)


def test_a_reward_is_capped_and_a_penalty_floored():
    from qrdx.validator.epoch_processing import MAX_EFFECTIVE_BALANCE

    s = genesis_state([{"address": a, "stake": 100_000} for a in G])
    s[G[0]].effective_stake = MAX_EFFECTIVE_BALANCE
    s[G[1]].effective_stake = D("0.000000001")
    out = transition(s, 5, _inputs(attesters=[G[0]]))
    assert out[G[0]].effective_stake == MAX_EFFECTIVE_BALANCE and out[G[0]].total_rewards > 0
    assert out[G[1]].effective_stake >= 0


# ── the batched computation equals the per-epoch definition ──────────────

async def _per_epoch(db, epoch, top):
    """S_epoch the slow, obvious way: each epoch's inputs read on their own, from genesis."""
    s = genesis_state(await ES._genesis_validators(db))
    for e in range(epoch):
        cp = await ES._checkpoint(db, e + 1, top)
        s = transition(s, e, await ES.epoch_inputs(db, e, cp[0]))
    return s


@pytest.mark.parametrize("seed", [1, 2, 3])
async def test_the_batched_computation_equals_the_per_epoch_one(chain, monkeypatch, seed):
    """Deposits, exits, delegations, commission changes, votes carried late (and too late),
    several blocks per epoch, empty epochs and a rollback: the state computed in one pass from a
    stored one is the state computed epoch by epoch from genesis, at every epoch and on every
    prefix of the chain."""
    import random

    monkeypatch.setattr(constants, "UNBONDING_PERIOD_EPOCHS", 3)
    monkeypatch.setattr(constants, "WITHDRAWAL_DELAY_EPOCHS", 2)
    rng = random.Random(seed)
    joiners = [f"0xPQ{c * 64}" for c in "ef"]
    holders = [f"0xPQ{c * 64}" for c in "0123"]
    epoch_of = {0: 0}

    async def build(first, last):
        for e in range(first, last):
            if rng.random() < 0.25:
                continue                                       # an empty epoch
            for k in range(rng.choice([1, 1, 2, 3])):
                votes = [(v, e - lag) for v in G + joiners for lag in (1, 2, 3)
                         if e - lag >= 1 and rng.random() < 0.3]
                deposits = [(j, str(rng.choice([100_000, 150_000]))) for j in joiners
                            if rng.random() < 0.08]
                exits = [v for v in G[2:] + joiners if rng.random() < 0.03]
                h = await chain.block(e * SLOTS_PER_EPOCH + 1 + k, votes=votes,
                                      deposits=deposits, exits=exits)
                epoch_of[h] = e
                for who in holders:
                    r = rng.random()
                    if r < 0.15:
                        await chain.db.log_staking_op(
                            "delegate", who, rng.choice(G + joiners), str(rng.randint(1, 5000)), h)
                    elif r < 0.22:
                        shares = None if rng.random() < 0.5 else str(rng.randint(1, 3000))
                        await chain.db.log_staking_op("undelegate", who, rng.choice(G), shares, h)
                if rng.random() < 0.1:
                    await chain.db.log_staking_op(
                        "commission", rng.choice(G), None, rng.randint(0, 10_000), h)
                await chain.db.connection.commit()

    async def check(epochs, top, fresh=True):
        await ES._ensure(chain.db)
        if fresh:
            await chain.db.connection.execute("DELETE FROM validator_epoch_states")
            ES._memo.pop(chain.db, None)
        for e in epochs:
            want = await _per_epoch(chain.db, e, top)
            assert ES.state_hash(await ES.state_at(chain.db, e, top)) == ES.state_hash(want), (
                seed, e, top)
        return want

    await build(1, 40)
    tip = chain.height
    s = await check([40], tip)                                 # one pass from genesis
    # The chain exercised what it should: joiners, exits, pools, payouts.
    assert set(joiners) & set(s) and {v.status for v in s.values()} & {"exiting", "exited"}
    assert any(p.shares for p in s.pools.values()) and s.payouts
    await check(list(range(0, 42)), tip)                       # each from the previous one
    await check([3, 25, 17, 40], tip)                          # out of order, from stored ones
    await check([30, 41], tip // 2)                            # a prefix of the chain
    await check([40], tip)                                     # (the old branch's states stored)
    await chain.rollback(tip // 2)                             # a reorg …
    chain.tag = "r"
    await build(epoch_of[tip // 2] + 1, 45)                    # … and a different future
    await check([44, 45, 39, 12], chain.height, fresh=False)   # never from a stale state


# ── the validator cap: an activation queue ──────────────────────────────────

def test_no_more_than_max_validators_propose_the_rest_wait_their_turn(monkeypatch):
    """MAX_VALIDATORS was declared and never enforced: any number of validators could join, each
    adding a 3.3 KB vote every epoch that every node verifies and stores. Past the cap a
    deposit waits — in the order it became due — until a validator leaves."""
    monkeypatch.setattr(constants, "MAX_VALIDATORS", 4)
    s = genesis_state([{"address": a, "stake": 100_000} for a in G])          # 3 proposing
    joiners = [f"0xPQ{c * 64}" for c in "123"]
    s = transition(s, 1, _inputs([("deposit", j, "pk", D(100_000)) for j in reversed(joiners)]))
    for e in range(2, 2 + ACTIVATION_DELAY_EPOCHS):
        s = transition(s, e, _inputs())
    statuses = {j: s[j].status for j in joiners}
    assert statuses == {joiners[0]: "active", joiners[1]: "pending", joiners[2]: "pending"}
    assert len(ES.proposers(s)) == 4
    # A validator leaves: the next in line takes its place once its exit completes.
    e = 2 + ACTIVATION_DELAY_EPOCHS
    s = transition(s, e, _inputs([("exit", G[0], None, None)]))
    s = transition(s, s[G[0]].exit_epoch, _inputs())
    assert s[G[0]].status == "exited" and s[joiners[1]].status == "active"
    assert s[joiners[2]].status == "pending" and len(ES.proposers(s)) == 4


def test_a_queued_validator_can_leave_the_queue():
    s = genesis_state([{"address": a, "stake": 100_000} for a in G])
    s = transition(s, 1, _inputs([("deposit", J, "pk", D(100_000))]))
    s = transition(s, 2, _inputs([("exit", J, None, None)]))
    assert s[J].status == "exited"                    # (its principal is paid back as any exit)


def test_the_cap_fits_the_votes_an_epoch_can_carry():
    assert constants.MAX_VALIDATORS <= constants.MAX_ATTESTATIONS_PER_BLOCK * SLOTS_PER_EPOCH
