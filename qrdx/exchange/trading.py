"""
Spot trading state beyond the order book (docs/TRADING_FEATURES.md).

**Spot trigger orders.** A stop (``sl``) or take-profit (``tp``) waits off the book for the
pair's last order-book trade price to reach its trigger, then is placed as an ordinary order
of its owner: a limit order at its limit price, or a market order that pays at most
TRIGGER_SLIPPAGE beyond the trigger price (a buy) or takes at least that far below it (a sell).
A buy stop and a sell take-profit fire as the price rises to the trigger, the others as it
falls.

What it may spend is escrowed in the pair's book escrow when it is placed — the amount of base
for a sell, amount × its highest price of quote for a buy — so when it fires, in the block's
tick and outside any transaction, every token it moves is already held by the protocol: the
trades settle out of the escrow, and what it did not use (or the whole escrow, if it cannot be
placed) goes back to its owner. The matching it may do then is paid for when it is placed
(``max_makers``). A block fires no more than SPOT_TRIGGER_FIRES_PER_BLOCK of them, visiting no
more than SPOT_TRIGGER_MAKERS_PER_BLOCK resting orders between them, those the price passed
furthest first, then the first placed; the rest fire in the next blocks.

Consensus state, committed entry by entry, and absent from the exchange root until first used.
The order book's own stop orders (``OrderBook._stop_orders``) trigger inside whichever trade
moves the price and settle nothing; exchange operations no longer place them.
"""

from __future__ import annotations

import bisect
import hashlib
import json
from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import undo
from .commitment import Section, committed, encode_value, tracked

ZERO = Decimal(0)
PRICE_QUANTUM = Decimal("1e-18")

TRIGGER_SLIPPAGE = Decimal("0.10")
SPOT_TRIGGER_DEFAULT_MAKERS = 20
SPOT_TRIGGER_MAX_MAKERS = 100
SPOT_TRIGGERS_PER_ACCOUNT = 50  # in each pair
SPOT_TRIGGER_FIRES_PER_BLOCK = 64
SPOT_TRIGGER_MAKERS_PER_BLOCK = 1000


# TWAP orders: a size worked into the market in equal slices over a duration, each slice an
# immediate-or-cancel within ``max_slippage`` of the price when it runs (perps: the mark; spot:
# a swap's marginal price), what a slice misses spread over the slices left. Each slice's
# matching (``max_makers``) and its own work are paid when the TWAP is placed; a block runs no
# more than TWAP_SLICES_PER_BLOCK slices, visiting no more than TWAP_MAKERS_PER_BLOCK resting
# orders — the rest run in the next blocks.
TWAP_MIN_DURATION = 60  # seconds
TWAP_MAX_DURATION = 24 * 3600
TWAP_MIN_INTERVAL = 30  # seconds between slices, at least
TWAP_MAX_SLICES = 60
TWAP_DEFAULT_SLIPPAGE = Decimal("0.03")
TWAP_MAX_SLIPPAGE = Decimal("0.10")
TWAP_DEFAULT_MAKERS = 5
TWAP_MAX_MAKERS = 20
TWAP_SLICE_GAS = 10_000  # each slice's own work, on top of its matching
TWAPS_PER_ACCOUNT = 10
TWAP_SLICES_PER_BLOCK = 64
TWAP_MAKERS_PER_BLOCK = 640


# Acting for an account: agent keys and sub-accounts.
AGENTS_PER_ACCOUNT = 10
SUBACCOUNTS_PER_ACCOUNT = 20
NAME_MAX = 32


def subaccount_address(master: str, index: int) -> str:
    """A sub-account's address: derived from its master and number, a protocol form no key can
    sign for (``0xSUBA``, qrdx/crypto/account_id.py) — only its master's signature acts for it."""
    body = hashlib.blake2b(f"subaccount:{master}:{int(index)}".encode(), digest_size=18)
    return "0xSUBA" + body.hexdigest()


@dataclass(frozen=True)
class AgentGrant:
    """An agent key an account approved: it may sign trading operations for the account (and
    its sub-accounts) until ``valid_until`` (block time; 0: until revoked)."""

    agent: str
    valid_until: Decimal
    name: str
    # The notional (perps settlement asset) the agent may place a day; 0: no limit
    # (docs/CONSENSUS_ROADMAP.md 7).
    max_notional_per_day: Decimal = Decimal(0)


@dataclass(frozen=True)
class SubAccount:
    master: str
    index: int
    name: str


def _encode_grants(_account: str, grants: tuple) -> Any:
    return [
        [g.agent, str(g.valid_until), g.name]
        + ([str(g.max_notional_per_day)] if g.max_notional_per_day > 0 else [])
        for g in grants
    ]


def _encode_spend(_key: str, spend: Tuple[int, Decimal]) -> Any:
    return [spend[0], str(spend[1])]


def _encode_cancel_at(_account: str, v: Tuple[Decimal, int, int]) -> Any:
    return [str(v[0]), v[1], v[2]]


def _encode_evm_action(_key: str, v: Tuple[str, str, str, int]) -> Any:
    return list(v)


@dataclass(frozen=True)
class Deployer:
    """A market deployer (docs/HYPERLIQUID_PARITY.md): its namespace, the QRDX it has bonded,
    what it is unbonding and the block time that becomes claimable. Kept when emptied: a
    namespace is its deployer's for good (a market named in it stays its, settled or not)."""

    dex: str
    bond: Decimal
    unbonding: Decimal = Decimal(0)
    unlock: Decimal = Decimal(0)


def _encode_deployer(_address: str, d: Deployer) -> Any:
    return [d.dex, str(d.bond), str(d.unbonding), str(d.unlock)]


# Builder codes (Hyperliquid's): a front-end earns up to this fraction of the notional of the fills
# an order it routed takes, when the account approved it (APPROVE_BUILDER_FEE).
BUILDER_FEE_MAX_PERP = Decimal("0.001")
BUILDER_FEE_MAX_SPOT = Decimal("0.01")
# A scheduled cancel (Hyperliquid's dead man's switch, SCHEDULE_CANCEL): at least this far ahead,
# at most this many firing per account per block day, at most this many accounts per block.
CANCEL_MIN_DELAY = Decimal(5)
CANCEL_TRIGGERS_PER_DAY = 10
CANCELS_PER_BLOCK = 50
# Exchange actions EVM contracts sent (qrdx/contracts/exchange_evm.py) run at the start of the next
# block, at most this many a block — more than a block's EVM gas can send — the rest in the next.
EVM_ACTIONS_PER_BLOCK = 256


def _encode_subaccount(_sub: str, sub: SubAccount) -> Any:
    return [sub.master, sub.index, sub.name]


class TradingError(ValueError):
    """A trading operation that cannot execute; nothing has changed."""


@dataclass(frozen=True)
class SpotTrigger:
    """A spot stop or take-profit waiting for its pair's price (replaced, never changed).

    ``kind`` "oco": one-cancels-the-other — a stop leg (``trigger_price``, ``limit_price``) and
    a take-profit leg (``tp_price``, ``tp_limit``) over one escrow; the first leg the price
    reaches fires. ``parent``: the buy order it is attached to (a bracket) — it starts empty and
    each fill of that order puts the base bought into its escrow."""

    owner: str
    pair: str  # the book's canonical "base:quote"
    side: str  # "buy" or "sell"
    kind: str  # "sl", "tp" or "oco"
    trigger_price: Decimal  # the stop's (an oco's stop leg), or the take-profit's
    amount: Decimal  # of base
    limit_price: Decimal  # ZERO: a market order, at most TRIGGER_SLIPPAGE beyond the trigger
    tif: str  # what the order is when it fires: "gtc" or "ioc" (a market trigger: "ioc")
    max_makers: int  # the matching it paid for when placed
    escrowed: Decimal  # what it locked in the book's escrow: quote for a buy, base for a sell
    seq: int  # placement order
    tp_price: Decimal = ZERO  # an oco's take-profit leg
    tp_limit: Decimal = ZERO
    parent: str = ""

    def legs(self) -> List[Tuple[str, Decimal, Decimal]]:
        """(kind, trigger price, limit price) of each leg: the stop's first."""
        if self.kind == "oco":
            return [
                ("sl", self.trigger_price, self.limit_price),
                ("tp", self.tp_price, self.tp_limit),
            ]
        return [(self.kind, self.trigger_price, self.limit_price)]

    def leg_fires_above(self, kind: str) -> bool:
        """A buy stop and a sell take-profit fire as the price rises; the others as it falls."""
        return (self.side == "buy") == (kind == "sl")

    def leg_price(self, trigger: Decimal, limit: Decimal) -> Decimal:
        """A leg's order price when it fires: its limit, or the furthest a market order goes."""
        if limit > 0:
            return limit
        if self.side == "buy":
            return (trigger * (1 + TRIGGER_SLIPPAGE)).quantize(PRICE_QUANTUM, rounding=ROUND_FLOOR)
        return (trigger * (1 - TRIGGER_SLIPPAGE)).quantize(PRICE_QUANTUM, rounding=ROUND_CEILING)

    @property
    def price(self) -> Decimal:
        """The highest price any leg would pay (a buy's escrow covers it), or the first leg's."""
        prices = [self.leg_price(t, lim) for _k, t, lim in self.legs()]
        return max(prices) if self.side == "buy" else prices[0]

    @property
    def fires_above(self) -> bool:
        return self.leg_fires_above(self.kind)

    def crossed_leg(self, price: Decimal) -> Optional[Tuple[str, Decimal, Decimal]]:
        """The first leg the price has reached (None: neither)."""
        for kind, trigger, limit in self.legs():
            if price >= trigger if self.leg_fires_above(kind) else price <= trigger:
                return kind, trigger, limit
        return None

    def crossed(self, price: Decimal) -> bool:
        return self.crossed_leg(price) is not None


def _encode_spot_trigger(_tid: str, t: SpotTrigger) -> Any:
    return [
        t.owner,
        t.pair,
        t.side,
        t.kind,
        str(t.trigger_price),
        str(t.amount),
        str(t.limit_price),
        t.tif,
        t.max_makers,
        str(t.escrowed),
        t.seq,
    ] + ([str(t.tp_price), str(t.tp_limit), t.parent] if t.kind == "oco" or t.parent else [])


@dataclass(frozen=True)
class Twap:
    """A TWAP order in progress (replaced, never changed)."""

    owner: str
    market: str  # a perp market id, or a spot pair "base:quote"
    perp: bool
    side: str  # perps: "buy" or "sell"; spot: the side of the pair token_in sells
    token_in: str  # spot: what it spends ("" for perps)
    token_out: str  # spot: what it buys ("" for perps)
    total: Decimal  # perps: the size; spot: the amount of token_in (escrowed)
    done: Decimal  # perps: the size filled; spot: the token_in spent
    received: Decimal  # spot: the token_out bought; perps: the notional filled
    slices: int
    slices_done: int
    interval: Decimal  # seconds between slices
    next_time: Decimal  # block time of the next slice
    reduce_only: bool
    max_slippage: Decimal
    max_makers: int  # per slice, paid when placed
    seq: int

    @property
    def remaining(self) -> Decimal:
        return self.total - self.done

    def slice_size(self) -> Decimal:
        """This slice's share of what is left: the rest over the slices left (the last takes
        it all), so a slice that missed is made up by the ones after it."""
        left = self.slices - self.slices_done
        if left <= 1:
            return self.remaining
        return (self.remaining / left).quantize(PRICE_QUANTUM, rounding=ROUND_FLOOR)


def _encode_twap(_tid: str, t: Twap) -> Any:
    return [
        t.owner,
        t.market,
        t.perp,
        t.side,
        t.token_in,
        t.token_out,
        str(t.total),
        str(t.done),
        str(t.received),
        t.slices,
        t.slices_done,
        str(t.interval),
        str(t.next_time),
        t.reduce_only,
        str(t.max_slippage),
        t.max_makers,
        t.seq,
    ]


class TradingState:
    """The exchange's trading state outside the order books and the clearinghouse."""

    spot_triggers = committed("tr.spot_triggers", _encode_spot_trigger, mutable=False)
    twaps = committed("tr.twaps", _encode_twap, mutable=False)
    agents = committed("tr.agents", _encode_grants, mutable=False)
    subaccounts = committed("tr.subaccounts", _encode_subaccount, mutable=False)
    subaccount_counts = committed("tr.subaccount_counts", encode_value, mutable=False)
    agent_spend = committed("tr.agent_spend", _encode_spend, mutable=False)
    # account → (block time its orders are all cancelled — 0: none set, block day, fired that day)
    cancel_at = committed("tr.cancel_at", _encode_cancel_at, mutable=False)
    # "account|builder" → the highest fee rate the account lets that builder charge
    builder_approvals = committed("tr.builder_approvals", encode_value, mutable=False)
    # "height:index" → (contract, operation, params JSON, exchange gas limit): exchange actions
    # EVM contracts sent, waiting for the start of the next block
    evm_actions = committed("tr.evm_actions", _encode_evm_action, mutable=False)
    # deployer address → Deployer (DEPLOYER_BOND)
    deployers = committed("tr.deployers", _encode_deployer, mutable=False)
    # "market|validator" → block time of its vote to freeze that deployer market (ORACLE_VOTE)
    freeze_votes = committed("tr.freeze_votes", encode_value, mutable=False)

    def __init__(self) -> None:
        self.spot_triggers = {}  # id → SpotTrigger
        self.twaps = {}  # id → Twap
        self.agents = {}  # account → (AgentGrant, …), at most AGENTS_PER_ACCOUNT
        self.subaccounts = {}  # sub-account address → SubAccount
        self.subaccount_counts = {}  # master → sub-accounts it has created
        self.agent_spend = {}  # "grantor|agent" → (block day, notional placed that day)
        self.cancel_at = {}  # account → (time, day, fired that day): SCHEDULE_CANCEL
        self.builder_approvals = {}  # "account|builder" → max fee rate (APPROVE_BUILDER_FEE)
        self.evm_actions = {}  # queued exchange actions of EVM contracts
        self.deployers = {}  # market deployers and their bonds
        self.freeze_votes = {}  # validators' votes to freeze deployer markets
        self.seq = 0  # trigger and TWAP orders placed so far

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        if "agent_spend" not in state:  # (pickled before agent limits)
            self.agent_spend = {}
        if "cancel_at" not in state:  # (pickled before scheduled cancels)
            self.cancel_at = {}
        if "builder_approvals" not in state:  # (pickled before builder codes)
            self.builder_approvals = {}
        if "evm_actions" not in state:  # (pickled before EVM actions)
            self.evm_actions = {}
        if "deployers" not in state:  # (pickled before deployer markets)
            self.deployers = {}
            self.freeze_votes = {}

    # ── scheduled cancels ───────────────────────────────────────────────

    def due_cancels(self, now: Decimal) -> List[str]:
        """Accounts whose scheduled cancel is due by ``now``, the earliest first (then by
        account) — from a derived index of the armed ones, never committed, kept up to date from
        the entries changed since (as ``twap_index``)."""
        if not len(self.cancel_at):
            return []
        entries = tracked(self.cancel_at)
        index = self.__dict__.get("_cancel_index")
        if index is None or entries.__dict__.get("_index_token") is not index["token"]:
            index = {"token": [], "keys": {}, "armed": []}
            entries.track_changes()
            entries.take_changes()
            entries.__dict__["_index_token"] = index["token"]
            changed: Iterable[str] = list(dict.keys(entries))
            self.__dict__["_cancel_index"] = index
        else:
            changed = entries.take_changes()
        for account in changed:
            old = index["keys"].pop(account, None)
            if old is not None:
                i = bisect.bisect_left(index["armed"], old)
                if i < len(index["armed"]) and index["armed"][i] == old:
                    del index["armed"][i]
            v = entries.peek(account)
            if v is not None and v[0] > 0:
                key = (v[0], account)
                bisect.insort(index["armed"], key)
                index["keys"][account] = key
        armed = index["armed"]
        return [a for _t, a in armed[: bisect.bisect_right(armed, (now, "\U0010ffff"))]]

    # ── acting for an account ───────────────────────────────────────────

    def grant(self, account: str, agent: str) -> Optional[AgentGrant]:
        for g in self.agents.peek(account, ()):
            if g.agent == agent:
                return g
        return None

    def spend(self, grantor: str, grant: AgentGrant, day: int, notional: Decimal) -> Decimal:
        """Count ``notional`` against a limited agent's day; ValueError past its limit. Returns
        what it has placed today."""
        key = f"{grantor}|{grant.agent}"
        prev = self.agent_spend.peek(key) if len(self.agent_spend) else None
        used = prev[1] if prev is not None and prev[0] == day else Decimal(0)
        if used + notional > grant.max_notional_per_day:
            raise ValueError(
                f"the agent {grant.agent[:16]}… may place {grant.max_notional_per_day} a day: "
                f"{used} placed today, this is {notional}"
            )
        self.agent_spend[key] = (day, used + notional)
        return used + notional

    def forget_spend(self, grantor: str, agent: str) -> None:
        key = f"{grantor}|{agent}"
        if len(self.agent_spend) and key in self.agent_spend:
            del self.agent_spend[key]

    def master_of(self, account: str) -> Optional[str]:
        sub = self.subaccounts.peek(account)
        return sub.master if sub is not None else None

    def next_seq(self) -> int:
        undo.keep(self, ("seq",), "trading", shallow=True)
        self.seq += 1
        return self.seq

    def twap_index(self) -> Dict[str, Any]:
        """The TWAPs by owner and by when their next slice is due — derived, never committed;
        kept up to date from the ids marked since. ``due``: sorted (next_time, seq, id)."""
        twaps = tracked(self.twaps)
        index = self.__dict__.get("_twap_index")
        if index is None or twaps.__dict__.get("_index_token") is not index["token"]:
            index = {"token": [], "owned": {}, "keys": {}, "due": []}
            twaps.track_changes()
            twaps.take_changes()
            twaps.__dict__["_index_token"] = index["token"]
            changed: Iterable[str] = list(dict.keys(twaps))
            self.__dict__["_twap_index"] = index
        else:
            changed = twaps.take_changes()
        for tid in changed:
            old = index["keys"].pop(tid, None)
            if old is not None:
                owner, key = old
                i = bisect.bisect_left(index["due"], key)
                if i < len(index["due"]) and index["due"][i] == key:
                    del index["due"][i]
                index["owned"][owner].discard(tid)
            t = twaps.peek(tid)
            if t is not None:
                key = (t.next_time, t.seq, tid)
                bisect.insort(index["due"], key)
                index["keys"][tid] = (t.owner, key)
                index["owned"].setdefault(t.owner, set()).add(tid)
        return index

    def twaps_of(self, owner: str) -> List[str]:
        return sorted(self.twap_index()["owned"].get(owner, ()))

    def due_twaps(self, now: Decimal) -> List[str]:
        """The TWAPs whose next slice is due by ``now``: the longest due first, then the first
        placed."""
        due = self.twap_index()["due"]
        return [tid for _t, _s, tid in due[: bisect.bisect_right(due, (now, 1 << 62, "~"))]]

    # ── spot triggers ───────────────────────────────────────────────────

    def new_spot_trigger(self, **fields: Any) -> SpotTrigger:
        return SpotTrigger(seq=self.next_seq(), **fields)

    def spot_index(self) -> Dict[str, Any]:
        """The spot triggers by owner and pair, and per pair by trigger price — derived, never
        committed; kept up to date from the ids marked since. ``above``/``below``: those that
        fire as the price rises / falls, each sorted by (price, seq, id)."""
        triggers = tracked(self.spot_triggers)
        index = self.__dict__.get("_spot_index")
        if index is None or triggers.__dict__.get("_index_token") is not index["token"]:
            index = {"token": [], "owned": {}, "keys": {}, "above": {}, "below": {}, "parents": {}}
            triggers.track_changes()
            triggers.take_changes()
            triggers.__dict__["_index_token"] = index["token"]
            changed: Iterable[str] = list(dict.keys(triggers))
            self.__dict__["_spot_index"] = index
        else:
            changed = triggers.take_changes()
        for tid in changed:
            old = index["keys"].pop(tid, None)
            if old is not None:
                owner, pair, parent, entries = old
                for above, key in entries:
                    lst = index["above" if above else "below"][pair]
                    i = bisect.bisect_left(lst, key)
                    if i < len(lst) and lst[i] == key:
                        del lst[i]
                index["owned"][(owner, pair)].discard(tid)
                if parent and index["parents"].get(parent) == tid:
                    del index["parents"][parent]
            t = triggers.peek(tid)
            if t is not None:
                entries = []
                for kind, trigger, _limit in t.legs():  # one entry a leg
                    above = t.leg_fires_above(kind)
                    key = (trigger, t.seq, tid)
                    bisect.insort(index["above" if above else "below"].setdefault(t.pair, []), key)
                    entries.append((above, key))
                index["keys"][tid] = (t.owner, t.pair, t.parent, entries)
                index["owned"].setdefault((t.owner, t.pair), set()).add(tid)
                if t.parent:
                    index["parents"][t.parent] = tid
        return index

    def bracket_of(self, order_id: str) -> Optional[str]:
        """The TP/SL attached to a spot order (None if it has none)."""
        return self.spot_index()["parents"].get(order_id)

    def owned(self, owner: str, pair: str) -> List[str]:
        return sorted(self.spot_index()["owned"].get((owner, pair), ()))

    def crossed(self, pair: str, price: Decimal) -> List[str]:
        index = self.spot_index()
        above, below = index["above"].get(pair, []), index["below"].get(pair, [])
        hit = [tid for _p, _s, tid in above[: bisect.bisect_right(above, (price, 1 << 62, "~"))]]
        hit += [tid for _p, _s, tid in below[bisect.bisect_left(below, (price, -1, "")) :]]
        return list(dict.fromkeys(hit))  # (an oco can be listed twice)

    # ── commitment ──────────────────────────────────────────────────────

    @property
    def touched(self) -> bool:
        """In the exchange root at all? From the first entry of any of its collections — every
        one of them: a scheduled cancel, a builder approval or a contract's queued action alone
        used to leave the trading state out of the root."""
        return self.seq > 0 or any(
            len(c)
            for c in (
                self.agents,
                self.subaccounts,
                self.cancel_at,
                self.builder_approvals,
                self.evm_actions,
                self.deployers,
                self.freeze_votes,
            )
        )

    def commitment(self) -> bytes:
        sec = (
            Section("trading")
            .value([self.seq])
            .raw(self.spot_triggers.commitment())
            .raw(self.twaps.commitment())
            .raw(self.agents.commitment())
            .raw(self.subaccounts.commitment())
            .raw(self.subaccount_counts.commitment())
        )
        if len(self.agent_spend):  # (absent until a limited agent first trades)
            sec.raw(self.agent_spend.commitment())
        if len(self.cancel_at):  # (absent until the first scheduled cancel)
            sec.raw(self.cancel_at.commitment())
        if len(self.builder_approvals):  # (absent until the first builder approval)
            sec.raw(self.builder_approvals.commitment())
        if len(self.evm_actions):  # (absent while no contract's action waits)
            sec.raw(self.evm_actions.commitment())
        if len(self.deployers):  # (absent until the first deployer bonds)
            sec.raw(self.deployers.commitment())
        if len(self.freeze_votes):  # (absent while no freeze vote is live)
            sec.raw(self.freeze_votes.commitment())
        return sec.digest()

    def state_hash(self) -> bytes:
        blob = json.dumps(
            {
                "seq": self.seq,
                "spot_triggers": {
                    tid: _encode_spot_trigger(tid, t)
                    for tid, t in sorted(self.spot_triggers.peek_items())
                },
                "twaps": {tid: _encode_twap(tid, t) for tid, t in sorted(self.twaps.peek_items())},
                "agents": {a: _encode_grants(a, g) for a, g in sorted(self.agents.peek_items())},
                "subaccounts": {
                    a: _encode_subaccount(a, sub)
                    for a, sub in sorted(self.subaccounts.peek_items())
                },
                "subaccount_counts": dict(sorted(self.subaccount_counts.peek_items())),
                **(
                    {
                        "agent_spend": {
                            k: _encode_spend(k, v) for k, v in sorted(self.agent_spend.peek_items())
                        }
                    }
                    if len(self.agent_spend)
                    else {}
                ),
                **(
                    {
                        "cancel_at": {
                            k: _encode_cancel_at(k, v)
                            for k, v in sorted(self.cancel_at.peek_items())
                        }
                    }
                    if len(self.cancel_at)
                    else {}
                ),
                **(
                    {
                        "builder_approvals": {
                            k: str(v) for k, v in sorted(self.builder_approvals.peek_items())
                        }
                    }
                    if len(self.builder_approvals)
                    else {}
                ),
                **(
                    {"evm_actions": {k: list(v) for k, v in sorted(self.evm_actions.peek_items())}}
                    if len(self.evm_actions)
                    else {}
                ),
                **(
                    {
                        "deployers": {
                            k: _encode_deployer(k, v)
                            for k, v in sorted(self.deployers.peek_items())
                        }
                    }
                    if len(self.deployers)
                    else {}
                ),
                **(
                    {"freeze_votes": {k: str(v) for k, v in sorted(self.freeze_votes.peek_items())}}
                    if len(self.freeze_votes)
                    else {}
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()

    def verify_commitment(self) -> None:
        self.spot_triggers.verify()
        self.twaps.verify()
        self.agents.verify()
        self.subaccounts.verify()
        self.subaccount_counts.verify()
        self.agent_spend.verify()
        self.cancel_at.verify()
        self.builder_approvals.verify()
        self.evm_actions.verify()
        self.deployers.verify()
        self.freeze_votes.verify()
