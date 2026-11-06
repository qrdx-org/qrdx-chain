"""
Fair ordering of a block's exchange transactions (chain-spec feature ``fair_ordering``;
docs/CONSENSUS_ROADMAP.md 1).

The proposer orders a block. Without a rule it could put its own taker order ahead of a maker's
cancel it saw in the mempool, and pick off the stale quote. So, as on Hyperliquid, within a block

    1. cancels (and oracle votes),
    2. post-only orders,
    3. everything else

run in that order — a maker can always pull or improve its quotes before any taker in the same
block. One thing outranks the classes: a nonce lane's transactions (``nonce_key``) run in nonce
order. So each transaction's **effective class** is the highest class of it and the lane's
earlier transactions in the block, and a block is valid only if its effective classes never
decrease. The proposer meets that by a stable sort on the effective class (``fair_order``);
every path that applies a block checks it (``ordering_error``).
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from .transactions import ExchangeOpType, batch_actions

CANCEL, POST_ONLY, OTHER = 0, 1, 2
FEATURE = "fair_ordering"

_CANCELS = frozenset(
    {
        ExchangeOpType.CANCEL_ORDER,
        ExchangeOpType.PERP_CANCEL,
        ExchangeOpType.CANCEL_ALL,
        ExchangeOpType.TWAP_CANCEL,
        ExchangeOpType.ORACLE_VOTE,  # (votes only record: applied at the block's end)
    }
)
_ORDERS = frozenset({ExchangeOpType.PLACE_ORDER, ExchangeOpType.PERP_ORDER})


def order_class(op: ExchangeOpType, params: Dict[str, Any]) -> int:
    """An operation's class: a cancel, a post-only order, or anything else."""
    if op in _CANCELS:
        return CANCEL
    if op in _ORDERS:
        return POST_ONLY if str(params.get("tif", "")).lower() == "alo" else OTHER
    if op == ExchangeOpType.BATCH:
        try:
            return max(order_class(o, p) for o, p in batch_actions(params))
        except ValueError:
            return OTHER  # (a malformed batch fails on its own)
    return OTHER


def effective_classes(txs: Sequence[Any]) -> List[int]:
    """Each transaction's class, raised to the highest of its lane's earlier ones."""
    lane_top: Dict[str, int] = {}
    out = []
    for tx in txs:
        lane = tx.nonce_key()
        c = max(order_class(tx.op_type, tx.params or {}), lane_top.get(lane, CANCEL))
        lane_top[lane] = c
        out.append(c)
    return out


def ordering_error(txs: Sequence[Any]) -> str:
    """Why the block's order is not fair ("" if it is)."""
    classes = effective_classes(txs)
    for i in range(1, len(classes)):
        if classes[i] < classes[i - 1]:
            names = ("a cancel", "a post-only order", "another operation")
            return (
                f"exchange transaction {i} ({txs[i].op_type.name}) is {names[classes[i]]}, "
                f"after {names[classes[i - 1]]}: cancels, then post-only orders, then the rest"
            )
    return ""


def fair_order(txs: Sequence[Any]) -> List[Any]:
    """``txs`` in a fair order: by effective class, otherwise as given (so every lane keeps its
    nonce order)."""
    classes = effective_classes(txs)
    order = sorted(range(len(txs)), key=lambda i: (classes[i], i))
    return [txs[i] for i in order]
