"""
The validator set as a pure function of the chain (docs/KNOWN_ISSUES.md, "Historical proposer
eligibility").

**The state.** ``S_E`` — every validator's stake, effective stake and status at the start of
epoch ``E`` on a chain — is a deterministic transition over that chain's blocks, from the
genesis set:

    S_0     = the genesis validator set
    S_(e+1) = transition(S_e, the blocks of epoch e):
      1. the epoch's EXECUTED stake operations, in chain order: a STAKE_DEPOSIT registers a
         validator pending activation at e + ACTIVATION_DELAY_EPOCHS (or tops up an existing
         one); a STAKE_EXIT moves an active validator to exiting, leaving at
         e + UNBONDING_PERIOD_EPOCHS, and a pending one out at once;
      2. rewards and penalties for epoch t = e − INCLUSION_EPOCHS: each validator active now is
         rewarded if this chain carries its vote for t (votes may ride up to INCLUSION_EPOCHS
         after their target, so by now every vote for t that will ever count has), penalized
         otherwise;
      3. pending validators whose activation epoch has come become active; exiting ones whose
         exit epoch has come leave;
      4. the slashing proofs the epoch's blocks carry: half the offender's effective stake,
         and out;
      5. stake-floor ejection (with the liveness backstop).

**Fee income** (docs/CONSENSUS_ROADMAP.md 6). The stakers' share of the protocol's QRDX fee
income is held at ``STAKER_FEE_HOLDER`` as it is paid, and each block logs what it took in
(``staker_fee_income``). An epoch's income — with any remainder carried from before — is shared
like the minted rewards for the same target: among the validators whose vote is carried, by
principal and pool, the validator keeping its commission on the pool's part, the rest compounding
into the pool. Fee payouts are paid out of the holder, not minted (validator/withdrawals.py).

Nothing else is read: not finality, not when a node happened to process an epoch, not a table
another code path mutates. Stake operations come from the logs block application writes for
operations that EXECUTED (``validator_deposits`` / ``validator_exits``, reversed on rollback):
the per-block index records every STAKE_DEPOSIT a block carries, including ones the exchange
refused, and replaying those let an account holding gas money register any stake it named.

**Who proposes.** A block of epoch ``E`` is proposed by the validator selected for its slot from
``S_E`` of its own parent chain (active and exiting validators, weighted by effective stake).
Every path — the proposer, live import, sync, fork-choice adoption — applies blocks onto their
parent, so every path can check it: a block judged long after its slot, or on a branch this
node adopts, is judged against the set it was proposed under. Pending validators do not propose
before they activate.

**Finality's weights.** Casper FFG weighs a vote for target ``t`` by ``S_t`` of the chain it is
counted on (``voting_stakes``), so finality too is a function of the chain.

**Cost.** ``S_E`` is cached per (epoch, checkpoint): the checkpoint — the last block before the
epoch's first slot — commits to every block the state depends on, so a reorg can never reuse a
stale state, and a state is computed once per epoch from the previous one.
"""

from __future__ import annotations

import copy
import hashlib
import json
import weakref
from bisect import bisect_left
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from decimal import ROUND_DOWN, Decimal
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..logger import get_logger

logger = get_logger(__name__)

# Statuses selected to propose, and whose stake counts in FFG.
PROPOSING_STATUSES = ("active", "exiting")
ZERO = Decimal(0)
WEI = Decimal("1e-18")  # QRDX amounts are whole wei
SECONDS_PER_YEAR = 31_557_600  # a Julian year
SLASH_FRACTION = Decimal("0.50")  # double sign and surround / double vote alike
MIN_ACTIVE_AFTER_EJECTION = 3  # never eject below this many active validators
# Where the stakers' share of the protocol's fee income waits for its epoch's distribution (a
# synthetic holder: no key signs for it).
STAKER_FEE_HOLDER = "0xFEES" + hashlib.blake2b(b"staking:fee-holder", digest_size=18).hexdigest()

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS validator_epoch_states ("
    " epoch INTEGER NOT NULL,"
    " checkpoint TEXT NOT NULL,"  # hash of the last block before the epoch's first slot
    " state TEXT NOT NULL,"
    " PRIMARY KEY (epoch, checkpoint))"
)


@dataclass
class ValidatorState:
    address: str
    public_key: str
    stake: Decimal  # principal deposited
    effective_stake: Decimal  # its own weight: principal moved by participation
    status: str  # pending | active | exiting | exited | slashed
    activation_epoch: Optional[int] = None
    exit_epoch: Optional[int] = None
    slashed: bool = False
    total_rewards: Decimal = Decimal(0)  # weight gained for attesting
    total_slashed: Decimal = Decimal(0)  # weight lost (missed votes, slashing)
    earned: Decimal = Decimal(0)  # QRDX rewards paid to it (its own share and commission)

    _DECIMALS = ("stake", "effective_stake", "total_rewards", "total_slashed", "earned")

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in self._DECIMALS:
            d[k] = str(d[k])
        return d

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "ValidatorState":
        d = dict(d)
        for k in cls._DECIMALS:
            if k in d:
                d[k] = Decimal(str(d[k]))
        return cls(**d)


@dataclass
class Pool:
    """A validator's delegation pool (docs/STAKING.md): QRDX delegators have locked with it,
    as shares whose value grows with the pool's rewards, net of the validator's commission."""

    validator: str
    commission_bps: int
    value: Decimal = Decimal(0)  # QRDX the shares are worth: delegated and earning
    total_shares: Decimal = Decimal(0)
    shares: Dict[str, Decimal] = field(default_factory=dict)  # delegator → shares
    pending: List[Tuple[str, Decimal, int]] = field(default_factory=list)  # warming up
    next_commission: Optional[int] = None  # takes effect at the end of the epoch

    def price(self) -> Decimal:
        """QRDX per share (1 for an empty pool)."""
        return self.value / self.total_shares if self.total_shares > 0 else Decimal(1)

    def to_json(self) -> Dict[str, Any]:
        return {
            "validator": self.validator,
            "commission_bps": self.commission_bps,
            "value": str(self.value),
            "total_shares": str(self.total_shares),
            "shares": {a: str(v) for a, v in sorted(self.shares.items())},
            "pending": [[a, str(v), int(e)] for a, v, e in self.pending],
            "next_commission": self.next_commission,
        }

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "Pool":
        return cls(
            validator=d["validator"],
            commission_bps=int(d["commission_bps"]),
            value=Decimal(d["value"]),
            total_shares=Decimal(d["total_shares"]),
            shares={a: Decimal(v) for a, v in d["shares"].items()},
            pending=[(a, Decimal(v), int(e)) for a, v, e in d["pending"]],
            next_commission=d.get("next_commission"),
        )


@dataclass
class Payout:
    """QRDX the chain owes an account: a reward, a finished undelegation, a refund. Paid by
    the first block of an epoch ≥ ``due_epoch`` (validator/withdrawals.py)."""

    id: int
    address: str
    amount: Decimal
    due_epoch: int
    kind: str  # reward | undelegation | refund
    validator: str = ""  # the pool it left: slashed with it until paid

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        d["amount"] = str(self.amount)
        return d

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "Payout":
        d = dict(d)
        d["amount"] = Decimal(d["amount"])
        return cls(**d)


class State(dict):
    """address → ValidatorState, plus the delegation pools and the payouts not yet paid."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pools: Dict[str, Pool] = {}
        self.payouts: List[Payout] = []
        self.last_block_epoch: int = -1  # the newest epoch with a block on this chain
        self.next_payout_id: int = 1
        self.fee_carry: Decimal = Decimal(0)  # fee income not yet shared (rounding, no voters)

    def weight(self, address: str) -> Decimal:
        """A validator's stake as selection and finality weigh it: its own effective stake and
        the QRDX delegated to it."""
        pool = self.pools.get(address)
        return self[address].effective_stake + (pool.value if pool else Decimal(0))

    def payout(self, address: str, amount: Decimal, due: int, kind: str, validator: str = ""):
        amount = amount.quantize(WEI, rounding=ROUND_DOWN)
        if amount > 0:
            self.payouts.append(Payout(self.next_payout_id, address, amount, due, kind, validator))
            self.next_payout_id += 1


@dataclass
class EpochInputs:
    """What one epoch's blocks contribute to the transition."""

    # Executed operations, in chain order: ("deposit", address, public_key, stake),
    # ("exit", address, None, None), ("delegate", delegator, validator, amount),
    # ("undelegate", delegator, validator, shares or None for all), ("commission", validator,
    # None, basis points).
    ops: List[Tuple[str, str, Optional[str], Any]]
    attesters: Iterable[str]  # validators whose vote for epoch − INCLUSION_EPOCHS is carried
    offenders: Iterable[str]  # validators a slashing proof in the epoch's blocks convicts
    has_blocks: bool = True  # whether the epoch has a block on this chain
    fees: Decimal = Decimal(0)  # the stakers' fee income the epoch's blocks took in


def genesis_state(genesis_validators: List[Dict[str, Any]]) -> State:
    out = State()
    for v in genesis_validators:
        stake = Decimal(str(v["stake"]))
        out[v["address"]] = ValidatorState(
            address=v["address"],
            public_key=str(v.get("public_key") or ""),
            stake=stake,
            effective_stake=stake,
            status="active",
            activation_epoch=0,
        )
    return out


def reward_rate_per_epoch() -> Decimal:
    """The annual STAKING_REWARD_RATE_BPS, as a fraction per epoch of chain time."""
    from ..constants import SLOT_DURATION_MS, SLOTS_PER_EPOCH, STAKING_REWARD_RATE_BPS

    return (
        Decimal(int(STAKING_REWARD_RATE_BPS))
        * Decimal(int(SLOT_DURATION_MS) * int(SLOTS_PER_EPOCH))
        / Decimal(10_000 * 1_000 * SECONDS_PER_YEAR)
    )


def transition(state: State, epoch: int, inputs: EpochInputs) -> State:
    """``S_(epoch+1)`` from ``S_epoch`` and the epoch's inputs. Pure: the input is not changed."""
    from ..constants import (
        ACTIVATION_DELAY_EPOCHS,
        MAX_VALIDATORS,
        STAKING_DEFAULT_COMMISSION_BPS,
        UNBONDING_PERIOD_EPOCHS,
        VALIDATOR_EJECTION_STAKE,
        WITHDRAWAL_DELAY_EPOCHS,
    )
    from .epoch_processing import MAX_EFFECTIVE_BALANCE
    from .epoch_rewards import compute_epoch_reward_deltas
    from .ffg import INCLUSION_EPOCHS

    s = copy.deepcopy(state)
    s.__dict__.pop("_stakes_memo", None)  # (the copy's stakes are its own, recomputed if asked)
    if not isinstance(s, State):  # a plain mapping (tests, an older cache)
        s = State(s)
    e = int(epoch)

    def pool_of(validator: str) -> Pool:
        if validator not in s.pools:
            s.pools[validator] = Pool(validator, int(STAKING_DEFAULT_COMMISSION_BPS))
        return s.pools[validator]

    # 0. Payouts due by now were paid by the epoch's first block, if it has one.
    if inputs.has_blocks:
        s.last_block_epoch = e
        s.payouts = [p for p in s.payouts if p.due_epoch > e]

    # 1. Executed operations, in chain order.
    for kind, address, other, value in inputs.ops:
        v = s.get(address)
        if kind == "deposit":
            amount = Decimal(str(value))
            if v is None:
                s[address] = ValidatorState(
                    address=address,
                    public_key=str(other or ""),
                    stake=amount,
                    effective_stake=amount,
                    status="pending",
                    activation_epoch=e + ACTIVATION_DELAY_EPOCHS,
                )
            else:  # a top-up
                v.stake += amount
                v.effective_stake += amount
                if other:
                    v.public_key = str(other)
        elif kind == "exit" and v is not None and v.status == "active":
            v.status = "exiting"
            v.exit_epoch = e + UNBONDING_PERIOD_EPOCHS
        elif kind == "exit" and v is not None and v.status == "pending":
            # Never activated: nothing to unbond, and it must not propose as an exiting one.
            v.status, v.exit_epoch = "exited", e
        elif kind == "delegate":
            amount, target = Decimal(str(value)), s.get(str(other))
            if target is None or target.status not in ("pending", "active", "exiting"):
                s.payout(address, amount, e + 1, "refund")  # nothing to delegate to
            else:
                pool_of(target.address).pending.append(
                    (address, amount, e + ACTIVATION_DELAY_EPOCHS)
                )
        elif kind == "undelegate" and other in s.pools:
            pool = s.pools[str(other)]
            if value is None:  # everything, warming-up delegations included
                for who, amount, _at in [p for p in pool.pending if p[0] == address]:
                    s.payout(who, amount, e + 1, "refund")
                pool.pending = [p for p in pool.pending if p[0] != address]
            owned = pool.shares.get(address, Decimal(0))
            burned = owned if value is None else min(owned, Decimal(str(value)))
            if burned > 0:
                amount = (burned * pool.price()).quantize(WEI, rounding=ROUND_DOWN)
                pool.shares[address] = owned - burned
                if pool.shares[address] == 0:
                    del pool.shares[address]
                pool.total_shares -= burned
                pool.value -= amount
                due = e + UNBONDING_PERIOD_EPOCHS + WITHDRAWAL_DELAY_EPOCHS
                s.payout(address, amount, due, "undelegation", pool.validator)
        elif kind == "commission" and v is not None:
            pool_of(address).next_commission = max(0, min(10_000, int(value)))

    # 2. Weight: rewards and penalties for the epoch whose votes have all been included.
    target = e - INCLUSION_EPOCHS
    active = [s[a] for a in sorted(s) if s[a].status == "active"]
    attesters = set(inputs.attesters)
    if target >= 1:  # no vote can target epoch 0
        rewards, penalties = compute_epoch_reward_deltas(
            [{"address": v.address, "effective_stake": v.effective_stake} for v in active],
            attesters,
        )
        for address, amount in rewards.items():
            v = s[address]
            v.effective_stake = min(v.effective_stake + amount, MAX_EFFECTIVE_BALANCE)
            v.total_rewards += amount
        for address, amount in penalties.items():
            v = s[address]
            v.effective_stake = max(v.effective_stake - amount, Decimal(0))
            v.total_slashed += amount

        # 3. QRDX rewards for that epoch: each attesting validator earns the rate on its own
        #    principal and on its pool. It keeps its own share and its commission on the
        #    pool's; the rest compounds into the pool.
        rate = reward_rate_per_epoch()
        for v in active:
            if v.address not in attesters or rate <= 0:
                continue
            earning = s.pools.get(v.address)
            own = (v.stake * rate).quantize(WEI, rounding=ROUND_DOWN)
            pooled = (earning.value * rate).quantize(WEI, rounding=ROUND_DOWN) if earning else ZERO
            commission = ZERO
            if pooled > 0 and earning is not None:
                commission = (pooled * earning.commission_bps / 10_000).quantize(
                    WEI, rounding=ROUND_DOWN
                )
                earning.value += pooled - commission
            if own + commission > 0:
                v.earned += own + commission
                s.payout(v.address, own + commission, e + 1, "reward")

    # 3b. Fee income: the epoch's, and what was carried, shared among the same voters by
    #     principal and pool — paid out of STAKER_FEE_HOLDER, never minted.
    s.fee_carry = getattr(s, "fee_carry", ZERO) + Decimal(str(inputs.fees))
    voters = [v for v in active if v.address in attesters] if target >= 1 else []
    _share_fees(s, voters, e)

    # 4. Scheduled exits, then activations — while fewer than MAX_VALIDATORS propose, in the
    #    order they became due (then by address); the rest wait their turn. Delegations whose
    #    warm-up is over join their pool.
    for address in sorted(s):
        v = s[address]
        if v.status == "exiting" and v.exit_epoch is not None and v.exit_epoch <= e:
            v.status = "exited"
    proposing = sum(1 for v in s.values() if v.status in PROPOSING_STATUSES)
    due = sorted(
        (v.activation_epoch, a)
        for a, v in s.items()
        if v.status == "pending" and v.activation_epoch is not None and v.activation_epoch <= e
    )
    for _due_epoch, address in due:
        if proposing >= MAX_VALIDATORS:
            break
        s[address].status, s[address].activation_epoch = "active", e
        proposing += 1
    for validator in sorted(s.pools):
        pool = s.pools[validator]
        warming = []
        for who, amount, at in pool.pending:
            if at > e:
                warming.append((who, amount, at))
                continue
            shares = amount / pool.price() if pool.total_shares > 0 else amount
            shares = shares.quantize(WEI, rounding=ROUND_DOWN)
            pool.shares[who] = pool.shares.get(who, ZERO) + shares
            pool.total_shares += shares
            pool.value += amount
        pool.pending = warming

    # 5. Slashing proofs carried by the epoch's blocks: half the validator's stake, half its
    #    pool, half what is unbonding from it.
    for address in sorted({str(o) for o in inputs.offenders}):
        v = next((s[a] for a in s if a.lower() == address.lower()), None)
        if v is None or v.slashed:
            continue
        penalty = v.effective_stake * SLASH_FRACTION
        v.effective_stake -= penalty
        v.total_slashed += penalty
        v.slashed, v.status = True, "slashed"
        slashed_pool = s.pools.get(v.address)
        if slashed_pool is not None:
            slashed_pool.value = (slashed_pool.value * (1 - SLASH_FRACTION)).quantize(
                WEI, rounding=ROUND_DOWN
            )
        for p in s.payouts:
            if p.kind == "undelegation" and p.validator == v.address:
                p.amount = (p.amount * (1 - SLASH_FRACTION)).quantize(WEI, rounding=ROUND_DOWN)

    # 6. A validator that has left takes no delegations: its pool is paid out to its
    #    delegators — after the withdrawal delay, the window for evidence of its offences —
    #    and what was still warming up is refunded.
    for validator in sorted(s.pools):
        v = s.get(validator)
        pool = s.pools[validator]
        if v is not None and v.status not in ("exited", "slashed"):
            continue
        price = pool.price()
        amounts = {
            who: (owned * price).quantize(WEI, rounding=ROUND_DOWN)
            for who, owned in sorted(pool.shares.items())
        }
        if amounts:  # the rounding remainder goes to the largest holder: nothing is lost
            top = max(sorted(amounts), key=lambda w: pool.shares[w])
            amounts[top] += pool.value - sum(amounts.values(), ZERO)
        for who, amount in amounts.items():
            s.payout(who, amount, e + WITHDRAWAL_DELAY_EPOCHS, "undelegation", validator)
        for who, amount, _at in pool.pending:
            s.payout(who, amount, e + 1, "refund")
        pool.shares, pool.total_shares, pool.value, pool.pending = {}, ZERO, ZERO, []

    # 7. Stake-floor ejection: an active validator decayed below the floor leaves like a
    #    voluntary exit — but never below the liveness backstop.
    active = [s[a] for a in sorted(s) if s[a].status == "active"]
    below = sorted(
        (v for v in active if v.effective_stake < VALIDATOR_EJECTION_STAKE),
        key=lambda v: (v.effective_stake, v.address),
    )
    room = len(active) - MIN_ACTIVE_AFTER_EJECTION
    for v in below[: max(0, room)]:
        v.status, v.exit_epoch = "exiting", e + UNBONDING_PERIOD_EPOCHS

    # 8. Commission changes take effect from the next epoch's rewards.
    for pool in s.pools.values():
        if pool.next_commission is not None:
            pool.commission_bps, pool.next_commission = pool.next_commission, None
    return s


def _share_fees(s: State, voters: List[ValidatorState], e: int) -> None:
    """Share ``s.fee_carry`` among ``voters`` by principal and pool: a validator's part, and its
    commission on its pool's, is paid to it ("fee"); the rest of its pool's part compounds into
    the pool, leaving the holder too ("fee_pooled"). What rounding leaves stays carried."""
    pot = s.fee_carry
    weights = {
        v.address: v.stake + (s.pools[v.address].value if v.address in s.pools else ZERO)
        for v in voters
    }
    total = sum(weights.values(), ZERO)
    if pot <= 0 or total <= 0:
        return
    shared = ZERO
    for v in voters:
        pool = s.pools.get(v.address)
        own = (pot * v.stake / total).quantize(WEI, rounding=ROUND_DOWN)
        pooled = (pot * pool.value / total).quantize(WEI, rounding=ROUND_DOWN) if pool else ZERO
        commission = ZERO
        if pooled > 0 and pool is not None:
            commission = (pooled * pool.commission_bps / 10_000).quantize(WEI, rounding=ROUND_DOWN)
            pool.value += pooled - commission
            s.payout(STAKER_FEE_HOLDER, pooled - commission, e + 1, "fee_pooled")
        if own + commission > 0:
            v.earned += own + commission
            s.payout(v.address, own + commission, e + 1, "fee")
        shared += own + pooled
    s.fee_carry = pot - shared


def proposers(state: State) -> List[Tuple[str, Decimal]]:
    """(address, weight) of every validator selected from, in address order: its own
    effective stake and the QRDX delegated to it."""
    st = state if isinstance(state, State) else State(state)
    return [(a, st.weight(a)) for a, v in sorted(st.items()) if v.status in PROPOSING_STATUSES]


def voting_stakes(state: State) -> Dict[str, Decimal]:
    st = state if isinstance(state, State) else State(state)
    return {a: st.weight(a) for a, v in st.items() if v.status in PROPOSING_STATUSES}


def _dump(state: State) -> str:
    st = state if isinstance(state, State) else State(state)
    return json.dumps(
        {
            "validators": [st[a].to_json() for a in sorted(st)],
            "pools": [st.pools[a].to_json() for a in sorted(st.pools)],
            "payouts": [p.to_json() for p in st.payouts],
            "last_block_epoch": st.last_block_epoch,
            "next_payout_id": st.next_payout_id,
            # (absent while nothing is carried: earlier states keep their hash)
            **({"fee_carry": str(st.fee_carry)} if getattr(st, "fee_carry", ZERO) else {}),
        },
        sort_keys=True,
    )


def _load(blob: str) -> State:
    data = json.loads(blob)
    if isinstance(data, list):  # validators only (before pools)
        data = {"validators": data}
    st = State({d["address"]: ValidatorState.from_json(d) for d in data["validators"]})
    st.pools = {d["validator"]: Pool.from_json(d) for d in data.get("pools", [])}
    st.payouts = [Payout.from_json(d) for d in data.get("payouts", [])]
    st.last_block_epoch = int(data.get("last_block_epoch", -1))
    st.next_payout_id = int(data.get("next_payout_id", 1))
    st.fee_carry = Decimal(data.get("fee_carry", "0"))
    return st


def state_hash(state: State) -> str:
    import hashlib

    return hashlib.sha256(_dump(state).encode()).hexdigest()


# ── the chain's inputs ───────────────────────────────────────────────────────────────────


async def epoch_inputs(db: Any, epoch: int, up_to_height: int) -> EpochInputs:
    """Epoch ``epoch``'s inputs on the stored chain, read only from blocks at or below
    ``up_to_height`` (the epoch's last block). The definition ``_advance`` batches over a range
    of epochs (tests/test_epoch_state.py holds the two equal)."""
    from .ffg import INCLUSION_EPOCHS

    conn = db.connection
    cur = await conn.execute(
        "SELECT MIN(height), MAX(height) FROM chain_index WHERE epoch = ? AND height <= ?",
        (int(epoch), int(up_to_height)),
    )
    lo, hi = await cur.fetchone()
    ops: List[Tuple[str, str, Optional[str], Any]] = []
    offenders: List[str] = []
    fees = ZERO
    if lo is not None:
        cur = await conn.execute(
            "SELECT block_height, id, address, public_key, stake FROM validator_deposits "
            "WHERE block_height BETWEEN ? AND ? ORDER BY block_height, id",
            (lo, hi),
        )
        deposits = await cur.fetchall()
        cur = await conn.execute(
            "SELECT block_height, id, address FROM validator_exits "
            "WHERE block_height BETWEEN ? AND ? ORDER BY block_height, id",
            (lo, hi),
        )
        exits = await cur.fetchall()
        cur = await conn.execute(
            "SELECT block_height, id, kind, sender, validator, value FROM staking_ops "
            "WHERE block_height BETWEEN ? AND ? ORDER BY block_height, id",
            (lo, hi),
        )
        staking = await cur.fetchall()
        # Per block: deposits, exits, then delegation operations (each log in its own order;
        # how they interleaved within one block is not recoverable across the logs, and any
        # fixed order is deterministic).
        merged: List[Tuple[int, int, int, Tuple[str, str, Optional[str], Any]]] = [
            (h, 0, i, ("deposit", a, pk, Decimal(str(st)))) for h, i, a, pk, st in deposits
        ]
        merged += [(h, 1, i, ("exit", a, None, None)) for h, i, a in exits]
        merged += [
            (h, 2, i, (kind, sender, validator, None if value is None else Decimal(str(value))))
            for h, i, kind, sender, validator, value in staking
        ]
        ops = [op for *_k, op in sorted(merged, key=lambda r: r[:3])]
        cur = await conn.execute(
            "SELECT offender FROM chain_index_offenders WHERE height BETWEEN ? AND ? "
            "ORDER BY height, rowid",
            (lo, hi),
        )
        offenders = [r[0] for r in await cur.fetchall()]
        cur = await conn.execute(
            "SELECT amount FROM staker_fee_income WHERE block_height BETWEEN ? AND ?",
            (lo, hi),
        )
        fees = sum((Decimal(str(a)) for (a,) in await cur.fetchall()), ZERO)
    target = int(epoch) - INCLUSION_EPOCHS
    attesters: List[str] = []
    if target >= 1:
        cur = await conn.execute(
            "SELECT DISTINCT validator FROM chain_index_votes "
            "WHERE target_epoch = ? AND carry_epoch <= ? AND height <= ?",
            (target, int(epoch), int(up_to_height)),
        )
        attesters = [r[0] for r in await cur.fetchall()]
    return EpochInputs(
        ops=ops, attesters=attesters, offenders=offenders, has_blocks=lo is not None, fees=fees
    )


# ── S_E on the stored chain, cached per (epoch, checkpoint) ──────────────────────────────

_MEMO_SIZE = 64
_memo: "weakref.WeakKeyDictionary[Any, OrderedDict]" = weakref.WeakKeyDictionary()
_ready: "weakref.WeakKeyDictionary[Any, bool]" = weakref.WeakKeyDictionary()
_materialized: "weakref.WeakKeyDictionary[Any, str]" = weakref.WeakKeyDictionary()


def _remember(db: Any, key: Tuple[int, str], state: State) -> None:
    memo = _memo.setdefault(db, OrderedDict())
    memo[key] = state
    memo.move_to_end(key)
    while len(memo) > _MEMO_SIZE:
        memo.popitem(last=False)


async def _ensure(db: Any) -> None:
    if not _ready.get(db):
        await db.connection.execute(_SCHEMA)
        _ready[db] = True


async def _checkpoint(
    db: Any, epoch: int, up_to_height: Optional[int]
) -> Optional[Tuple[int, str]]:
    """(height, hash) of the last block before ``epoch``'s first slot, at or below
    ``up_to_height`` (the tip by default)."""
    from .. import chain_index
    from ..constants import SLOTS_PER_EPOCH

    if up_to_height is None:
        return await chain_index.checkpoint(db, int(epoch), SLOTS_PER_EPOCH)
    height = 0
    if epoch > 0:
        height = max(
            0,
            await chain_index.height_before_slot_at_or_below(
                db, int(epoch) * SLOTS_PER_EPOCH, int(up_to_height)
            ),
        )
    root = await chain_index.block_hash_at(db, height)
    return (height, root) if root else None


async def _cached(db: Any, epoch: int, checkpoint: str) -> Optional[State]:
    memo: "OrderedDict[Tuple[int, str], State]" = _memo.get(db) or OrderedDict()
    hit = memo.get((epoch, checkpoint))
    if hit is not None:
        return hit
    cur = await db.connection.execute(
        "SELECT state FROM validator_epoch_states WHERE epoch = ? AND checkpoint = ?",
        (int(epoch), checkpoint),
    )
    row = await cur.fetchone()
    if row is None:
        return None
    state = _load(row[0])
    _remember(db, (epoch, checkpoint), state)
    return state


# States computed on the way to another are stored for the last STORE_EVERY epochs before it
# (where reorgs and FFG targets look) and every STORE_EVERY-th epoch before that: a long gap —
# a chain halt of a day is ~10,800 empty epochs — costs one write per STORE_EVERY epochs.
STORE_EVERY = 16
_CANDIDATE_PAGE = 64  # stored epochs checked per query when looking for the newest valid one


async def state_at(db: Any, epoch: int, up_to_height: Optional[int] = None) -> State:
    """``S_epoch`` on the stored chain — up to ``up_to_height`` (the tip by default), so the
    chain of a block about to be applied on top of it. Computed from the newest stored state
    below it on this chain, reading the blocks between in one pass (a query per input, not per
    epoch: after a long halt the first block computes thousands of epochs)."""
    from .. import chain_index

    await _ensure(db)
    await chain_index.sync(db)
    epoch = max(0, int(epoch))
    if up_to_height is None:
        up_to_height = int(await db.get_next_block_id()) - 1
    top = int(up_to_height)
    if top < 0:
        return State()
    found = await _newest_stored(db, epoch, top)
    if found is None:
        return State()
    start, state = found
    if start < epoch:
        state = await _advance(db, state, start, epoch, top)
    return state


async def _newest_stored(db: Any, epoch: int, top: int) -> Optional[Tuple[int, State]]:
    """(k, S_k) for the newest stored state at or below ``epoch`` on the chain ending at
    ``top`` — or the genesis state."""
    cp = await _checkpoint(db, epoch, top)
    if cp is None:
        return None
    hit = await _cached(db, epoch, cp[1])
    if hit is not None:
        return epoch, hit
    below = epoch
    while below > 0:
        cur = await db.connection.execute(
            "SELECT DISTINCT epoch FROM validator_epoch_states WHERE epoch < ? "
            "ORDER BY epoch DESC LIMIT ?",
            (below, _CANDIDATE_PAGE),
        )
        candidates = [int(e) for (e,) in await cur.fetchall()]
        for e in candidates:
            cp = await _checkpoint(db, e, top)
            hit = await _cached(db, e, cp[1]) if cp else None
            if hit is not None:
                return e, hit
        if len(candidates) < _CANDIDATE_PAGE:
            break
        below = candidates[-1]
    cp0 = await _checkpoint(db, 0, top)
    if cp0 is None:
        return None
    state = genesis_state(await _genesis_validators(db))
    await _store(db, 0, cp0[1], state)
    return 0, state


async def _advance(db: Any, state: State, start: int, epoch: int, top: int) -> State:
    """``S_epoch`` from ``S_start`` on the chain ending at ``top``: every input of the
    transitions start .. epoch−1 read in one query each."""
    from ..constants import SLOTS_PER_EPOCH
    from .ffg import INCLUSION_EPOCHS

    conn = db.connection
    first = max(0, start - INCLUSION_EPOCHS)  # votes for start's reward target ride from here
    base = await _checkpoint(db, first, top)
    cur = await conn.execute(
        "SELECT height, block_hash, slot, epoch FROM chain_index "
        "WHERE height <= ? AND slot IS NOT NULL AND slot >= ? ORDER BY height",
        (top, first * SLOTS_PER_EPOCH),
    )
    rows = [
        (int(h), bh, int(sl), None if ep is None else int(ep))
        for h, bh, sl, ep in await cur.fetchall()
    ]

    slots = [sl for _h, _bh, sl, _ep in rows]

    def checkpoint(e: int) -> Tuple[int, str]:
        """The last block before epoch ``e``'s first slot (rows ascend by height and slot)."""
        i = bisect_left(slots, e * SLOTS_PER_EPOCH)
        if i:
            return rows[i - 1][0], rows[i - 1][1]
        return (base[0], base[1]) if base else (0, "")

    epoch_of = {h: ep for h, _bh, _sl, ep in rows}
    spans: Dict[int, List[int]] = {}
    for h, _bh, _sl, ep in rows:
        if ep is not None and start <= ep < epoch:
            spans.setdefault(ep, []).append(h)
    ops_by_epoch: Dict[int, List[Tuple[int, int, int, Tuple[str, str, Optional[str], Any]]]] = {}
    offenders_by_epoch: Dict[int, List[str]] = {}
    fees_by_epoch: Dict[int, Decimal] = {}
    heights = [h for hs in spans.values() for h in hs]
    if heights:
        lo, hi = min(heights), max(heights)
        cur = await conn.execute(
            "SELECT block_height, id, address, public_key, stake FROM validator_deposits "
            "WHERE block_height BETWEEN ? AND ?",
            (lo, hi),
        )
        for h, i, a, pk, st in await cur.fetchall():
            ep = epoch_of.get(int(h))
            if ep is not None and start <= ep < epoch:
                ops_by_epoch.setdefault(ep, []).append(
                    (int(h), 0, int(i), ("deposit", a, pk, Decimal(str(st))))
                )
        cur = await conn.execute(
            "SELECT block_height, id, address FROM validator_exits "
            "WHERE block_height BETWEEN ? AND ?",
            (lo, hi),
        )
        for h, i, a in await cur.fetchall():
            ep = epoch_of.get(int(h))
            if ep is not None and start <= ep < epoch:
                ops_by_epoch.setdefault(ep, []).append((int(h), 1, int(i), ("exit", a, None, None)))
        cur = await conn.execute(
            "SELECT block_height, id, kind, sender, validator, value FROM staking_ops "
            "WHERE block_height BETWEEN ? AND ?",
            (lo, hi),
        )
        for h, i, kind, sender, validator, value in await cur.fetchall():
            ep = epoch_of.get(int(h))
            if ep is not None and start <= ep < epoch:
                v = None if value is None else Decimal(str(value))
                ops_by_epoch.setdefault(ep, []).append(
                    (int(h), 2, int(i), (kind, sender, validator, v))
                )
        cur = await conn.execute(
            "SELECT height, offender FROM chain_index_offenders WHERE height BETWEEN ? AND ? "
            "ORDER BY height, rowid",
            (lo, hi),
        )
        for h, offender in await cur.fetchall():
            ep = epoch_of.get(int(h))
            if ep is not None and start <= ep < epoch:
                offenders_by_epoch.setdefault(ep, []).append(offender)
        cur = await conn.execute(
            "SELECT block_height, amount FROM staker_fee_income WHERE block_height BETWEEN ? AND ?",
            (lo, hi),
        )
        for h, amount in await cur.fetchall():
            ep = epoch_of.get(int(h))
            if ep is not None and start <= ep < epoch:
                fees_by_epoch[ep] = fees_by_epoch.get(ep, ZERO) + Decimal(str(amount))
    # Votes for the reward targets of these transitions, carried at or below the last one's
    # boundary: (target, validator, carry epoch, height).
    last_boundary = checkpoint(epoch)[0]
    cur = await conn.execute(
        "SELECT target_epoch, validator, carry_epoch, height FROM chain_index_votes "
        "WHERE target_epoch BETWEEN ? AND ? AND height <= ?",
        (start - INCLUSION_EPOCHS, epoch - 1 - INCLUSION_EPOCHS, last_boundary),
    )
    votes: Dict[int, List[Tuple[str, int, int]]] = {}
    for target, validator, carry, h in await cur.fetchall():
        votes.setdefault(int(target), []).append((validator, int(carry), int(h)))

    for e in range(start, epoch):
        boundary = checkpoint(e + 1)
        target = e - INCLUSION_EPOCHS
        attesters = (
            {v for v, carry, h in votes.get(target, ()) if carry <= e and h <= boundary[0]}
            if target >= 1
            else set()
        )
        ops = [op for *_k, op in sorted(ops_by_epoch.get(e, []), key=lambda r: r[:3])]
        inputs = EpochInputs(
            ops=ops,
            attesters=sorted(attesters),
            offenders=offenders_by_epoch.get(e, []),
            has_blocks=e in spans,
            fees=fees_by_epoch.get(e, ZERO),
        )
        state = transition(state, e, inputs)
        if (e + 1) % STORE_EVERY == 0 or epoch - (e + 1) < STORE_EVERY:
            await _store(db, e + 1, boundary[1], state)
    return state


async def _genesis_validators(db: Any) -> List[Dict[str, Any]]:
    """The genesis validator set: the record genesis initialisation writes, or else the
    ``validator_set`` the genesis block itself carries."""
    recorded = await db.get_genesis_validators()
    if recorded:
        return recorded
    try:
        block = await db.get_block_by_id(0)
        content = (block or {}).get("content") or (block or {}).get("block_content")
        data = json.loads(content) if isinstance(content, str) else content
        members = data.get("validator_set") if isinstance(data, dict) else None
    except Exception:
        members = None
    return [
        {"address": m["address"], "public_key": m.get("public_key", ""), "stake": m["stake"]}
        for m in members or []
        if Decimal(str(m.get("stake", 0))) > 0
    ]


def stakes(state: State) -> Dict[str, Decimal]:
    """Each account's QRDX at stake in ``state``: a validator's own principal (active, pending
    or exiting) and every delegator's pool shares at the pool's price — keyed by lower-cased
    address. Memoized on the state (a state is never changed once computed)."""
    memo = getattr(state, "_stakes_memo", None)
    if memo is not None:
        return memo
    out: Dict[str, Decimal] = {}
    for address, v in state.items():
        if v.status in ("active", "pending", "exiting") and v.stake > 0:
            key = address.lower()
            out[key] = out.get(key, ZERO) + v.stake
    for pool in getattr(state, "pools", {}).values():
        price = pool.price()
        for who, shares in pool.shares.items():
            key = who.lower()
            out[key] = out.get(key, ZERO) + (shares * price).quantize(WEI, rounding=ROUND_DOWN)
    try:
        state._stakes_memo = out  # type: ignore[attr-defined]
    except AttributeError:
        pass
    return out


async def stakes_for_block(db: Any, height: int) -> Dict[str, Decimal]:
    """``stakes`` of the validator set in force at block ``height``'s parent (as
    ``committee_for_block``): what the block's staking fee discounts go by."""
    from .. import chain_index
    from ..constants import SLOTS_PER_EPOCH

    parent = int(height) - 1
    if parent < 0:
        return {}
    await chain_index.sync(db)
    slot = await chain_index.slot_at(db, parent)
    epoch = int(slot) // SLOTS_PER_EPOCH if slot is not None else 0
    return stakes(await state_at(db, epoch, parent))


async def committee_for_block(db: Any, height: int) -> Dict[str, Decimal]:
    """The validators whose stake weighs what block ``height`` decides by stake — oracle
    prices, bridge attestations, governance — each by its weight: the set in force at the
    block's parent (active and exiting validators), keyed by lower-cased address."""
    from .. import chain_index
    from ..constants import SLOTS_PER_EPOCH

    parent = int(height) - 1
    if parent < 0:
        return {}
    await chain_index.sync(db)
    slot = await chain_index.slot_at(db, parent)
    epoch = int(slot) // SLOTS_PER_EPOCH if slot is not None else 0
    stakes = voting_stakes(await state_at(db, epoch, parent))
    return {a.lower(): w for a, w in sorted(stakes.items()) if w > 0}


async def _store(db: Any, epoch: int, checkpoint: str, state: State) -> None:
    await db.connection.execute(
        "INSERT OR REPLACE INTO validator_epoch_states (epoch, checkpoint, state) VALUES (?, ?, ?)",
        (int(epoch), checkpoint, _dump(state)),
    )
    _remember(db, (int(epoch), checkpoint), state)


async def proposers_for_slot(
    db: Any, slot: int, parent_height: Optional[int] = None
) -> List[Tuple[str, Decimal]]:
    """Who is selected from for ``slot`` on the chain ending at ``parent_height`` (the tip)."""
    from ..constants import SLOTS_PER_EPOCH

    return proposers(await state_at(db, int(slot) // SLOTS_PER_EPOCH, parent_height))


async def is_validator(db: Any, address: str, block_content: Any, parent_height: int) -> bool:
    """Whether ``address`` is a validator (in any status) of the chain ending at
    ``parent_height``, in the epoch of the block's slot."""
    from ..constants import SLOTS_PER_EPOCH
    from .block_verification import _parse_block_content

    try:
        slot = int(_parse_block_content(block_content)["slot"])
    except Exception:
        return False
    state = await state_at(db, slot // SLOTS_PER_EPOCH, int(parent_height))
    return any(a.lower() == str(address).lower() for a in state)


async def prune(db: Any, below_epoch: int) -> None:
    """Drop cached states of epochs below ``below_epoch`` (below finality, a state is only
    needed to compute the next one), keeping the newest stored one below it to compute from."""
    await _ensure(db)
    await db.connection.execute(
        "DELETE FROM validator_epoch_states WHERE epoch < ? AND epoch < "
        "(SELECT COALESCE(MAX(epoch), 0) FROM validator_epoch_states WHERE epoch <= ?)",
        (int(below_epoch), int(below_epoch)),
    )


async def state_at_tip(db: Any) -> State:
    """The state in force at the tip: ``S`` of the tip's epoch."""
    from .. import chain_index
    from ..constants import SLOTS_PER_EPOCH

    await chain_index.sync(db)
    tip = int(await db.get_next_block_id()) - 1
    if tip < 0:
        return State()
    slot = await chain_index.slot_at(db, tip)
    return await state_at(db, (int(slot) // SLOTS_PER_EPOCH) if slot is not None else 0)


async def materialize(db: Any) -> str:
    """Write the state in force at the tip (``S`` of the tip's epoch) to the ``validators``
    table — what the RPC, the CLI and the explorer show. Nothing in consensus reads that table:
    eligibility and finality read ``state_at``. Returns the state's hash."""
    from .. import chain_index
    from ..constants import SLOTS_PER_EPOCH

    await chain_index.sync(db)
    tip = int(await db.get_next_block_id()) - 1
    if tip < 0:
        return ""
    slot = await chain_index.slot_at(db, tip)
    epoch = (int(slot) // SLOTS_PER_EPOCH) if slot is not None else 0
    state = await state_at(db, epoch)
    digest = state_hash(state)
    if _materialized.get(db) == digest:
        return digest
    conn = db.connection
    await conn.execute("DELETE FROM validators")
    for v in state.values():
        await conn.execute(
            "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
            "activation_epoch, exit_epoch, slashed, total_slashed, total_rewards) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                v.address,
                v.public_key,
                str(v.stake),
                str(v.effective_stake),
                v.status,
                v.activation_epoch,
                v.exit_epoch,
                1 if v.slashed else 0,
                str(v.total_slashed),
                str(v.total_rewards),
            ),
        )
    _materialized[db] = digest
    return digest
