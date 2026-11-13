"""
A proposer that builds on a parent it has not run yet (``two_block_deferral``; qrdx/post_state.py,
docs/PERFORMANCE.md 31–32).

Under two blocks a block signs the state its grandparent left, so the proposer of block N can sign
before block N−1 has run here. What it still needs is to judge N's transactions as every importer
will — on the state N−1 leaves — while holding only the state before N−1 and N−1's contents. Here
is that judgment, from those two alone:

* **Nonces.** Every transaction a block carries runs and consumes its nonce
  (``exchange_inclusion``), so each lane's next nonce after N−1 is known from N−1's contents.
* **Fees.** Within N−1 nothing but fees takes a payer below min(R, its balance before N−1) less
  its fees in N−1 (the fee reserve, ``ExchangeStateManager.fee_floor``). That is the balance N's
  fees are judged against. A payer whose own transaction in N−1 spent its reserve, or that sent
  an EVM transaction in N−1, has no such bound: its transactions wait for the next block.
* **The rest of the judgment** reads state no operation in ``PARENT_OPS`` changes for another
  block's judgment — authority (agents, controllers, keys, vaults), the free lane's budgets
  (judged here only for accounts with no free operation in N−1, and on their QRDX holding, never
  their perps equity, which a price move in N−1 can lower), oracle vote sequences (a voter in N−1
  waits). A parent carrying anything else is run first, as under one block.

What is left out waits in the mempool (it is never dropped for that). The importer judges N
exactly as before; a block judged here is one it accepts (tests/test_two_block_deferral.py).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)

# The operations a parent may carry for its child to be built before it runs: what they change
# that another block's judgment reads is balances (bounded by the reserve), nonces (counted) and
# the free lane's budgets (their senders' free operations wait).
_PARENT_OP_NAMES = (
    "TOKEN_TRANSFER",
    "PLACE_ORDER",
    "CANCEL_ORDER",
    "CANCEL_ALL",
    "MODIFY_ORDER",
    "SCHEDULE_CANCEL",
    "SWAP",
    "ADD_LIQUIDITY",
    "REMOVE_LIQUIDITY",
    "PERP_ORDER",
    "PERP_CANCEL",
    "PERP_MODIFY",
    "PERP_TRIGGER",
    "PERP_DEPOSIT",
    "PERP_WITHDRAW",
    "PERP_SET_LEVERAGE",
    "PERP_ISOLATED_MARGIN",
    "TWAP_ORDER",
    "TWAP_CANCEL",
    "ORACLE_VOTE",
    "TOKEN_APPROVE",
)


def _parent_ops() -> Set[Any]:
    from ..exchange.transactions import ExchangeOpType

    return {ExchangeOpType[name] for name in _PARENT_OP_NAMES}


def enabled() -> bool:
    """``QRDX_PIPELINED_PROPOSER=0`` turns it off (the proposer runs its parent first)."""
    return os.environ.get("QRDX_PIPELINED_PROPOSER", "1") != "0"


@dataclass
class ParentEffects:
    """What a parent not run yet does to its child's judgment, from its contents alone."""

    lanes: Dict[str, int] = field(default_factory=dict)  # lane → its next nonce after the parent
    fees: Dict[str, Decimal] = field(default_factory=dict)  # payer → its maximum fees in it
    spent: Set[str] = field(default_factory=set)  # senders that spent their reserve in it
    free: Set[str] = field(default_factory=set)  # accounts with a free operation in it
    voters: Set[str] = field(default_factory=set)  # oracle voters in it (lowercase)
    evm_senders: Set[str] = field(default_factory=set)  # EVM senders in it (lowercase ids)
    unbounded: str = ""  # why its child must wait for it to run ("" if it need not)


def _ops_of(tx: Any) -> List[Any]:
    """A transaction's operation types — a batch's, each of its actions' (None: unreadable)."""
    from ..exchange.transactions import ExchangeOpType, batch_actions

    if tx.op_type != ExchangeOpType.BATCH:
        return [tx.op_type]
    try:
        return [op for op, _params in batch_actions(tx.params or {})]
    except ValueError:
        return [None]


def parent_effects(mgr: Any, exchange_txs: Sequence[Any], evm_raws: Sequence[str]) -> ParentEffects:
    """The parent's effects on its child's judgment (``ParentEffects``)."""
    from ..contracts.evm_mempool import parse_eth_raw_tx

    allowed = _parent_ops()
    out = ParentEffects()
    for tx in exchange_txs:
        for op in _ops_of(tx):
            if op not in allowed:
                out.unbounded = f"its parent carries {getattr(op, 'name', op)}"
                return out
        if tx.op_type.name == "ORACLE_VOTE":
            out.voters.add(tx.sender.lower())
            continue
        lane = tx.nonce_key()
        out.lanes[lane] = max(out.lanes.get(lane, 0), int(tx.nonce) + 1)
        if tx.spends_reserve():
            out.spent.add(tx.sender)
        if tx.free_eligible():
            out.free.add(tx.sender)
        else:
            payer = mgr.fee_payer(tx)
            out.fees[payer] = out.fees.get(payer, Decimal(0)) + tx.max_fee()
    for raw in evm_raws or ():
        try:
            out.evm_senders.add(str(parse_eth_raw_tx(raw)["sender"]).lower())
        except Exception:
            out.unbounded = "its parent carries an unreadable EVM transaction"
            return out
    return out


def bounds(
    effects: ParentEffects, balances: Dict[str, Decimal], reserve: Decimal
) -> Dict[str, Optional[Decimal]]:
    """What each account surely holds once the parent has run: min(R, its balance before the
    parent) less its fees in the parent — None where nothing bounds it (it spent its reserve in
    the parent, or sent EVM transactions there)."""
    from ..crypto.account_id import to_account_id

    out: Dict[str, Optional[Decimal]] = {}
    for account, held in balances.items():
        unbounded = account in effects.spent
        if not unbounded and effects.evm_senders:
            try:
                unbounded = to_account_id(account).lower() in effects.evm_senders
            except Exception:
                unbounded = True
        out[account] = None if unbounded else min(reserve, held) - effects.fees.get(account, 0)
    return out


def judge(
    mgr: Any,
    candidates: Sequence[Any],
    height: int,
    timestamp: float,
    base_fee: Optional[int],
    effects: ParentEffects,
    bound: Callable[[str], Optional[Decimal]],
) -> List[Any]:
    """Of a selection (each lane's run starting after the parent's), what the block may carry,
    judged on the bounds. A transaction left out takes the rest of its lane with it; nothing is
    refused for good (it waits). Read only."""
    from .. import chain_spec, constants
    from ..exchange.fair_ordering import FEATURE, ordering_error

    stopped: Set[str] = set()
    kept = []
    for tx in candidates:
        lane = tx.nonce_key()
        if lane in stopped:
            continue
        payer = mgr.fee_payer(tx)
        held = bound(tx.sender if tx.free_eligible() else payer)
        waits = held is None or (
            tx.free_eligible()
            and (tx.sender in effects.free or held < constants.FREE_ACTION_MIN_QRDX)
        )
        if waits:
            stopped.add(lane)
            continue
        kept.append(tx)
    if not kept:
        return []
    errors = mgr.section_errors(
        kept,
        int(height),
        float(timestamp),
        balance_of=bound,
        base_fee=base_fee,
        nonces_after=effects.lanes,
    )
    if errors:
        stopped = set()
        out = []
        for i, tx in enumerate(kept):
            if i in errors or tx.nonce_key() in stopped:
                stopped.add(tx.nonce_key())
                continue
            out.append(tx)
        kept = out
    if chain_spec.is_active(FEATURE, int(height)) and ordering_error(kept):
        return []  # (cannot happen: a lane is cut whole from where it stops)
    return kept


# ── the node's side ───────────────────────────────────────────────────────────────────────────

# The validator this node proposes as (set when it starts): the live import asks it to build on a
# block before running it (``ValidatorNode.propose_ahead``).
PROPOSER: Any = None


# Blocks being imported now, by height, from the moment they arrive (before they wait for the
# block-processing lock: qrdx/rpc/modules/p2p.py). A proposer whose parent is among them waits for
# it — the import builds the proposer's block on it before running it — instead of giving up after
# the grace and building on the grandparent: a block that competes with its own parent, loses the
# tie-break on half the network and costs those nodes a rollback.
_INCOMING: Dict[int, int] = {}


class incoming_block:
    """``async with incoming_block(height):`` — a block at ``height`` is being imported."""

    def __init__(self, height: Any) -> None:
        try:
            self.height: Optional[int] = int(height)
        except (TypeError, ValueError):
            self.height = None

    async def __aenter__(self) -> "incoming_block":
        if self.height is not None:
            _INCOMING[self.height] = _INCOMING.get(self.height, 0) + 1
        return self

    async def __aexit__(self, *exc: Any) -> None:
        h = self.height
        if h is not None and h in _INCOMING:
            _INCOMING[h] -= 1
            if _INCOMING[h] <= 0:
                del _INCOMING[h]


def incoming(height: int) -> bool:
    """Whether a block at ``height`` is being imported (or held for its parent)."""
    return int(height) in _INCOMING


def note_incoming(height: int, delta: int) -> None:
    """Count (``delta`` 1) or uncount (-1) a block at ``height`` outside ``incoming_block``: one
    held until its parent is imported (qrdx/rpc/modules/p2p.py)."""
    h = int(height)
    n = _INCOMING.get(h, 0) + delta
    if n > 0:
        _INCOMING[h] = n
    else:
        _INCOMING.pop(h, None)


# The highest block a peer sent above this node's tip, with its proposer's signature checked, and
# when (monotonic): a validator two or more blocks behind the network builds only a fork that loses.
_AHEAD: List[Tuple[int, float]] = []
AHEAD_FOR = 1.0  # seconds a sighting counts: the next blocks of a network ahead renew it


def note_ahead(height: int) -> None:
    """A peer sent block ``height``, above this node's tip, signed by its proposer."""
    import time

    if not _AHEAD or height >= _AHEAD[0][0] or time.monotonic() - _AHEAD[0][1] > AHEAD_FOR:
        _AHEAD[:] = [(int(height), time.monotonic())]


def network_ahead() -> Optional[int]:
    """The height of a block the network has above this node's tip, seen in the last
    ``AHEAD_FOR`` seconds (None if none)."""
    import time

    if _AHEAD and time.monotonic() - _AHEAD[0][1] <= AHEAD_FOR:
        return _AHEAD[0][0]
    return None


def parent_carries(content: Dict[str, Any]) -> Tuple[Set[Tuple[str, int]], List[Any]]:
    """The (validator, target epoch) of the votes a parent carries, and its slashing evidence."""
    from .attestation_block import decode_attestations

    votes = {
        (a.validator_address, int(a.target_epoch))
        for a in decode_attestations(content.get("attestations"))
    }
    return votes, list(content.get("slashing_evidence") or [])
