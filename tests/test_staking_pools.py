"""
Delegation pools and staking rewards (docs/STAKING.md, qrdx/validator/epoch_state.py).

Anyone can stake with a validator without running one: STAKE_DELEGATE locks QRDX in the
validator's pool, which counts towards the validator's weight once warmed up. Each epoch an
attesting validator earns the staking rate on its principal and on its pool; it keeps its own
share and its commission on the pool's, and the rest compounds into the pool — so the pool's
shares grow in value. STAKE_UNDELEGATE redeems shares, paid after the unbonding period;
slashing takes half of the pool and of what is unbonding from it. Every payout is made by the
first block of the epoch it is due, once.
"""
import os
import tempfile
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx import constants
from qrdx.constants import ACTIVATION_DELAY_EPOCHS, SLOTS_PER_EPOCH
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator import epoch_state as ES
from qrdx.validator.epoch_state import EpochInputs, State, genesis_state, transition

D = Decimal
V = [f"0xPQ{c * 64}" for c in "abc"]
A, B = "0xPQ" + "1" * 64, "0xPQ" + "2" * 64           # delegators
RATE = ES.reward_rate_per_epoch()
WEI = D("1e-18")


def _in(ops=(), attesters=V, offenders=(), blocks=True):
    return EpochInputs(ops=list(ops), attesters=list(attesters), offenders=list(offenders),
                       has_blocks=blocks)


def _genesis():
    return genesis_state([{"address": a, "stake": 100_000} for a in V])


def _run(s, start, stop, **kw):
    for e in range(start, stop):
        s = transition(s, e, _in(**kw))
    return s


def _q(x):
    from decimal import ROUND_DOWN
    return x.quantize(WEI, rounding=ROUND_DOWN)


def test_a_delegation_warms_up_then_joins_the_pool_and_the_weight():
    s = transition(_genesis(), 1, _in([("delegate", A, V[0], D(10_000))]))
    pool = s.pools[V[0]]
    assert pool.pending == [(A, D(10_000), 1 + ACTIVATION_DELAY_EPOCHS)] and pool.value == 0
    assert dict(ES.proposers(s))[V[0]] == dict(ES.proposers(s))[V[1]]   # not yet
    s = _run(s, 2, 2 + ACTIVATION_DELAY_EPOCHS, attesters=())        # (no rewards to blur it)
    pool = s.pools[V[0]]
    assert pool.shares == {A: D(10_000)} and pool.value == D(10_000) and not pool.pending
    weights = dict(ES.proposers(s))
    assert weights[V[0]] - weights[V[1]] == D(10_000)
    assert ES.voting_stakes(s)[V[0]] == weights[V[0]]


def test_rewards_pay_the_validator_and_compound_the_pool():
    s = transition(_genesis(), 1, _in([("delegate", A, V[0], D(10_000))], attesters=()))
    s = _run(s, 2, 2 + ACTIVATION_DELAY_EPOCHS, attesters=())
    before = s.pools[V[0]].value
    paid_before = {p.id for p in s.payouts}
    e = 2 + ACTIVATION_DELAY_EPOCHS                               # target ≥ 1: rewards run
    s = transition(s, e, _in())
    pooled = _q(before * RATE)
    commission = _q(pooled * constants.STAKING_DEFAULT_COMMISSION_BPS / 10_000)
    own = _q(D(100_000) * RATE)
    assert s.pools[V[0]].value == before + pooled - commission
    (reward,) = [p for p in s.payouts if p.id not in paid_before and p.address == V[0]]
    assert reward.kind == "reward" and reward.amount == own + commission
    assert reward.due_epoch == e + 1 and s[V[0]].earned == own + commission
    # The other validators earn on their principal only.
    assert [p.amount for p in s.payouts if p.address == V[1] and p.id not in paid_before] == [own]
    # A later delegator buys shares at the grown price: fewer shares per QRDX.
    price = s.pools[V[0]].price()
    assert price > 1
    s = transition(s, e + 1, _in([("delegate", B, V[0], D(10_000))]))
    s = _run(s, e + 2, e + 2 + ACTIVATION_DELAY_EPOCHS)
    assert s.pools[V[0]].shares[B] < s.pools[V[0]].shares[A]


def test_a_validator_that_misses_its_vote_earns_nothing_for_its_pool():
    s = transition(_genesis(), 1, _in([("delegate", A, V[0], D(10_000))], attesters=()))
    s = _run(s, 2, 2 + ACTIVATION_DELAY_EPOCHS, attesters=())
    value = s.pools[V[0]].value
    s = transition(s, 2 + ACTIVATION_DELAY_EPOCHS, _in(attesters=V[1:]))
    assert s.pools[V[0]].value == value
    assert not [p for p in s.payouts if p.address == V[0] and p.kind == "reward"]


def test_undelegating_pays_the_shares_worth_after_unbonding():
    s = transition(_genesis(), 1, _in([("delegate", A, V[0], D(10_000))]))
    s = _run(s, 2, 4 + ACTIVATION_DELAY_EPOCHS)
    pool = s.pools[V[0]]
    worth = _q(pool.shares[A] / 2 * pool.price())
    e = 4 + ACTIVATION_DELAY_EPOCHS
    s = transition(s, e, _in([("undelegate", A, V[0], pool.shares[A] / 2)], attesters=()))
    (out,) = [p for p in s.payouts if p.kind == "undelegation"]
    assert out.address == A and out.amount == worth and out.validator == V[0]
    assert out.due_epoch == e + constants.UNBONDING_PERIOD_EPOCHS + constants.WITHDRAWAL_DELAY_EPOCHS


def test_undelegating_everything_refunds_what_is_still_warming_up():
    s = transition(_genesis(), 1, _in([("delegate", A, V[0], D(500))]))
    s = transition(s, 2, _in([("undelegate", A, V[0], None)]))
    assert [(p.kind, p.amount, p.due_epoch) for p in s.payouts if p.address == A] == [
        ("refund", D(500), 3)]
    assert s.pools[V[0]].pending == []


def test_slashing_takes_half_of_the_pool_and_of_its_unbonding_stake():
    s = transition(_genesis(), 1, _in([("delegate", A, V[0], D(10_000)),
                                        ("delegate", B, V[0], D(10_000))], attesters=()))
    s = _run(s, 2, 2 + ACTIVATION_DELAY_EPOCHS, attesters=())
    e = 2 + ACTIVATION_DELAY_EPOCHS
    s = transition(s, e, _in([("undelegate", B, V[0], None)], attesters=()))
    (unbonding,) = [p for p in s.payouts if p.address == B]
    assert unbonding.amount == D(10_000)
    s = transition(s, e + 1, _in(offenders=[V[0]], attesters=()))
    assert s[V[0]].status == "slashed"
    assert [p.amount for p in s.payouts if p.address == B] == [D(5_000)]
    # The slashed validator's pool is paid out to its delegators, halved, after the delay.
    (out,) = [p for p in s.payouts if p.address == A]
    assert out.amount == D(5_000) and out.due_epoch == e + 1 + constants.WITHDRAWAL_DELAY_EPOCHS
    assert s.pools[V[0]].value == 0 and not s.pools[V[0]].shares


def test_a_validator_that_leaves_pays_its_pool_out(monkeypatch):
    monkeypatch.setattr(constants, "UNBONDING_PERIOD_EPOCHS", 2)
    s = transition(_genesis(), 1, _in([("delegate", A, V[0], D(10_000))], attesters=()))
    s = _run(s, 2, 2 + ACTIVATION_DELAY_EPOCHS, attesters=())
    e = 2 + ACTIVATION_DELAY_EPOCHS
    s = transition(s, e, _in([("exit", V[0], None, None)], attesters=()))
    assert s[V[0]].status == "exiting" and s.pools[V[0]].value == D(10_000)   # still staked
    s = _run(s, e + 1, e + 3, attesters=())
    assert s[V[0]].status == "exited"
    assert [(p.address, p.amount) for p in s.payouts if p.kind == "undelegation"] == [
        (A, D(10_000))]


def test_a_delegation_to_a_non_validator_is_refunded():
    s = transition(_genesis(), 1, _in([("delegate", A, "0xPQ" + "9" * 64, D(700))]))
    assert [(p.address, p.kind, p.amount, p.due_epoch) for p in s.payouts] == [
        (A, "refund", D(700), 2)]


def test_commission_changes_from_the_next_epoch_and_only_for_validators():
    s = transition(_genesis(), 1, _in([("commission", V[0], None, D(2_500)),
                                        ("commission", A, None, D(0))]))
    assert s.pools[V[0]].commission_bps == 2_500 and A not in s.pools


def test_a_payout_is_dropped_once_a_block_of_its_epoch_exists():
    s = transition(_genesis(), 1, _in([("delegate", A, "0xPQ" + "9" * 64, D(700))]))
    assert len(s.payouts) == 1                                   # due 2
    s = transition(s, 2, _in(blocks=False))
    assert len(s.payouts) == 1                                   # no block in epoch 2: unpaid
    s = transition(s, 3, _in(blocks=True))
    assert not [p for p in s.payouts if p.kind == "refund"]      # epoch 3's first block paid it


def test_the_state_round_trips_through_its_stored_form():
    s = transition(_genesis(), 1, _in([("delegate", A, V[0], D(10_000))]))
    s = _run(s, 2, 4 + ACTIVATION_DELAY_EPOCHS)
    back = ES._load(ES._dump(s))
    assert isinstance(back, State) and ES.state_hash(back) == ES.state_hash(s)


# ── on the chain: operations, payouts ─────────────────────────────────────

@pytest.fixture
async def chain():
    from test_epoch_state import Chain

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


async def test_the_exchange_operations_reach_the_pool(chain):
    from qrdx.exchange.block_processor import flush_validator_lifecycle_deltas
    from qrdx.exchange.state_manager import ExchangeStateManager

    from test_epoch_state import G
    mgr = ExchangeStateManager()
    mgr.enforce_validator_stake = True
    mgr.begin_block(1, 0.0)
    mgr.set_available_balance(A, D(5_000))
    ok = mgr._op_stake_delegate(SimpleNamespace(sender=A, nonce=0,
                                                params={"validator": G[0], "amount": "3000"}))
    assert ok.success and mgr.balance_deltas() == {A: D(-3_000)}
    too_much = mgr._op_stake_delegate(SimpleNamespace(
        sender=A, nonce=1, params={"validator": G[0], "amount": "3000"}))
    assert not too_much.success and "insufficient" in too_much.error
    dust = mgr._op_stake_delegate(SimpleNamespace(
        sender=A, nonce=1, params={"validator": G[0], "amount": "0.005"}))
    assert not dust.success and "at least" in dust.error
    assert not mgr._op_stake_set_commission(SimpleNamespace(
        sender=G[0], nonce=0, params={"commission_bps": 10_001})).success
    assert mgr._op_stake_set_commission(SimpleNamespace(
        sender=G[0], nonce=0, params={"commission_bps": 700})).success
    h = await chain.epoch(1)
    await flush_validator_lifecycle_deltas(chain.db, mgr, block_epoch=1, block_height=h)
    await chain.db.connection.commit()
    for e in range(2, 3 + ACTIVATION_DELAY_EPOCHS):
        await chain.epoch(e)
    s = await ES.state_at(chain.db, 2 + ACTIVATION_DELAY_EPOCHS)
    assert s.pools[G[0]].shares == {A: D(3_000)} and s.pools[G[0]].commission_bps == 700


async def test_the_first_block_of_an_epoch_pays_what_is_due_once(chain):
    from qrdx.validator import withdrawals as W

    from test_epoch_state import G
    stranger = "0xPQ" + "9" * 64
    h = await chain.epoch(1)
    await chain.db.log_staking_op("delegate", A, stranger, "700", h)   # refunded, due 2
    await chain.db.connection.commit()
    before = await chain.db.get_address_balance(A)
    first = chain.height + 1
    paid = await W.process_block_withdrawals(chain.db, first, 2)
    await chain.block(2 * SLOTS_PER_EPOCH + 1)
    assert paid >= 1 and await chain.db.get_address_balance(A) == before + 700
    # A second block of epoch 2 pays nothing again.
    assert await W.compute_block_payouts(chain.db, chain.height + 1, 2) == []
    # …and the next epoch's state no longer holds it.
    await chain.block(3 * SLOTS_PER_EPOCH + 1)
    s = await ES.state_at(chain.db, 3)
    assert not [p for p in s.payouts if p.address == A]
    # Rolled back, the payout's ledger row goes; rebuilt, it is re-credited.
    cur = await chain.db.connection.execute("SELECT COUNT(*) FROM staking_payouts WHERE address = ?", (A,))
    assert (await cur.fetchone())[0] == 1
    await W.undo_withdrawal_logs_above(chain.db, first - 1)
    cur = await chain.db.connection.execute("SELECT COUNT(*) FROM staking_payouts")
    assert (await cur.fetchone())[0] == 0


async def test_rewards_are_minted_to_attesting_validators_on_the_chain(chain):
    from qrdx.validator import withdrawals as W

    from test_epoch_state import G
    for e in range(1, 6):
        await chain.epoch(e)
    before = await chain.db.get_address_balance(G[0])
    paid = await W.process_block_withdrawals(chain.db, chain.height + 1, 6)
    assert paid >= 3                                              # every attester earned
    assert await chain.db.get_address_balance(G[0]) - before == _q(D(100_000) * RATE)


@pytest.mark.parametrize("seed", range(6))
def test_delegated_qrdx_is_conserved_through_any_sequence(seed, monkeypatch):
    """With no rewards and no slashing, every delegated wei is always somewhere: in a pool,
    warming up, owed, or paid — whatever the order of delegations, partial and full
    undelegations, warm-ups, validator exits and payouts."""
    import random
    monkeypatch.setattr(constants, "STAKING_REWARD_RATE_BPS", 0)
    monkeypatch.setattr(constants, "UNBONDING_PERIOD_EPOCHS", 3)
    rng = random.Random(seed)
    delegators = [f"0xPQ{i:064x}" for i in range(1, 6)]
    targets = V + ["0xPQ" + "9" * 64]                     # one is not a validator
    s = _genesis()
    delegated, paid, seen = D(0), D(0), set()

    def held(st):
        pools = sum((p.value + sum((a for _w, a, _e in p.pending), D(0)) for p in st.pools.values()),
                    D(0))
        owed = sum((p.amount for p in st.payouts if p.kind != "reward"), D(0))
        return pools + owed

    for e in range(1, 60):
        ops = []
        for _ in range(rng.randint(0, 3)):
            who, to = rng.choice(delegators), rng.choice(targets)
            r = rng.random()
            if r < 0.5:
                amount = D(rng.randint(1, 5_000)) + D(rng.randint(0, 999)) / 1000
                ops.append(("delegate", who, to, amount))
                delegated += amount
            elif r < 0.85:
                pool = s.pools.get(to)
                owned = pool.shares.get(who) if pool else None
                part = None if (owned is None or rng.random() < 0.4) else owned / rng.randint(1, 4)
                ops.append(("undelegate", who, to, part))
            elif r < 0.9 and e > 10:
                ops.append(("exit", rng.choice(V), None, None))
        blocks = rng.random() < 0.8
        # What this epoch's first block pays: everything due by now (if it has a block).
        if blocks:
            for p in s.payouts:
                if p.due_epoch <= e and p.kind != "reward" and p.id not in seen:
                    paid += p.amount
                    seen.add(p.id)
        s = transition(s, e, _in(ops, attesters=(), blocks=blocks))
        assert held(s) + paid == delegated, e
