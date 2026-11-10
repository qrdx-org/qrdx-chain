"""
The validators' state in the signed root (chain-spec feature ``validator_state_root``;
docs/CHECKPOINT_SYNC.md).

Validator stakes, the delegation pools, the payouts owed and the withdrawals paid are consensus
state: every node derives them identically, and proposer eligibility, finality's weights and
block withdrawals follow them. Before this feature no block's root committed to them, so a node
could not verify them in a snapshot it did not build.

What they are a function of (qrdx/validator/epoch_state.py, qrdx/validator/withdrawals.py):

* ``S_E`` — every validator's stake, effective stake and status, the pools and the payouts not
  yet paid, at the start of epoch ``E``. It has a canonical hash (``epoch_state.state_hash``).
* The logs block application writes, each row keyed to its block and reversed on rollback:
  executed deposits, exits and delegation operations, the stakers' fee income, the
  withdrawals and the payouts paid.

A block at ``height`` in epoch ``E`` commits to both:

    validator_root = BLAKE3-512("qrdx-validators|" · state_hash(S_E on its parent's chain) · "|"
                                · log_root(height))
    log_root(h)    = log_root(h − 1)                                  when block h logged nothing
                   = BLAKE3-256("qrdx-validator-logs" · log_root(h − 1) · h · its rows)  otherwise
    log_root(−1)   = 32 zero bytes

The log root is a hash chain, not a set hash: it binds the order of a block's rows, which the
transition depends on (a delegation and its undelegation in one block). Each table's rows are
taken in the order block application wrote them, by their columns that every node writes
identically: not row ids (a node's AUTOINCREMENT counter), not a block hash or a clock.

``S_E`` is already computed by every path that judges the block's proposer, so the commitment
costs a hash per epoch (memoized on the state) and a few indexed reads of the block's own rows.
``log_root`` of the parent is memoized per (height, block hash), and stored every
``STORE_EVERY`` blocks for restarts; an entry is used only while its hash is still the canonical
block at its height, so a reorganization never reuses a stale one.
"""

from __future__ import annotations

import json
import weakref
from collections import OrderedDict
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Sequence, Tuple

FEATURE = "validator_state_root"
EMPTY = "00" * 32
STORE_EVERY = 256
_MEMO_SIZE = 512
_CANDIDATES = 64

# table → (committed columns, the order block application wrote them in, numeric columns)
LOGS: Tuple[Tuple[str, Tuple[str, ...], str, Tuple[str, ...]], ...] = (
    ("validator_deposits", ("address", "public_key", "stake"), "id", ("stake",)),
    ("validator_exits", ("address", "exit_epoch"), "id", ()),
    ("staking_ops", ("kind", "sender", "validator", "value"), "id", ("value",)),
    ("staker_fee_income", ("amount",), "block_height", ("amount",)),
    (
        "validator_withdrawals",
        ("address", "exit_epoch", "amount"),
        "address, exit_epoch",
        ("amount",),
    ),
    ("staking_payouts", ("payout_id", "address", "amount", "kind"), "payout_id", ("amount",)),
)


_memo: "OrderedDict[int, Tuple[str, str]]" = OrderedDict()  # height → (block hash, log root)
_NEAR = 16  # heights below the asked one checked in the memo before the stored entries


def active(height: int) -> bool:
    from .. import chain_spec

    try:
        return chain_spec.is_active(FEATURE, int(height))
    except Exception:
        return False


def _number(value: Any) -> Optional[str]:
    """One spelling per amount, whichever path wrote it ("1E+3", "1000.0" → "1000")."""
    if value is None:
        return None
    try:
        d = Decimal(str(value))
    except InvalidOperation:
        return str(value)
    return format(d.normalize(), "f") if d else "0"


def _row(values: Sequence[Any], columns: Sequence[str], numeric: Sequence[str]) -> List[Any]:
    out: List[Any] = []
    for name, value in zip(columns, values, strict=True):
        if name in numeric:
            out.append(_number(value))
        elif isinstance(value, bool) or value is None:
            out.append(value)
        elif isinstance(value, int):
            out.append(int(value))
        else:
            out.append(str(value))
    return out


def _rows_of(db: Any, table: str, low: int, high: int) -> List[Any]:
    """``table``'s rows of the blocks ``low`` .. ``high``, by height, then in the order block
    application wrote them (``LOGS``)."""
    t = db.store[table]
    span = {"lo": (int(low),), "hi": (int(high) + 1,)}
    if "by_height" in t.spec.indexes:  # (keyed otherwise: read in height order by its index)
        return t.scan_index("by_height", **span)
    return t.scan(**span)


async def logs_between(db: Any, low: int, high: int) -> Dict[int, List[Any]]:
    """Every logged row of the blocks ``low`` .. ``high``, per height: ``[[table, [row, ...]],
    ...]`` for the tables with rows, in ``LOGS`` order."""
    out: Dict[int, List[Any]] = {}
    if high < low:
        return out
    per: Dict[int, Dict[str, List[Any]]] = {}
    for table, columns, _order, numeric in LOGS:
        for r in _rows_of(db, table, low, high):
            per.setdefault(int(r.block_height), {}).setdefault(table, []).append(
                _row([getattr(r, c) for c in columns], columns, numeric)
            )
    for height, tables in per.items():
        out[height] = [[t, tables[t]] for t, *_rest in LOGS if t in tables]
    return out


def fold(previous: str, height: int, entries: List[Any]) -> str:
    """``log_root`` after a block at ``height`` that logged ``entries`` (none: unchanged)."""
    if not entries:
        return previous
    from ..crypto.hashing import blake3_hash

    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return blake3_hash(
        b"qrdx-validator-logs"
        + bytes.fromhex(previous)
        + int(height).to_bytes(8, "big")
        + encoded.encode(),
        32,
    ).hex()


def _remember(height: int, block_hash: str, root: str) -> None:
    _memo[height] = (block_hash, root)
    _memo.move_to_end(height)
    while len(_memo) > _MEMO_SIZE:
        _memo.popitem(last=False)


_ready: "weakref.WeakKeyDictionary[Any, bool]" = weakref.WeakKeyDictionary()


async def _ensure(db: Any) -> None:
    _ready[db] = True


async def _newest_known(db: Any, height: int) -> Tuple[int, str]:
    """(k, log_root(k)) for the newest k ≤ ``height`` whose root is memoized or stored for the
    block that is canonical at k now — else (−1, EMPTY)."""
    from .. import chain_index

    for k in range(height, max(-1, height - _NEAR), -1):
        hit = _memo.get(k)
        if hit is not None and await chain_index.block_hash_at(db, k) == hit[0]:
            return k, hit[1]
    below = height + 1
    stored = db.store["validator_log_roots"]
    while True:
        rows = [
            (r.height, r.block_hash, r.root)
            for r in stored.scan(lo=(-(2**62),), hi=(below,), reverse=True, limit=_CANDIDATES)
        ]
        for k, block_hash, root in rows:
            if await chain_index.block_hash_at(db, int(k)) == block_hash:
                return int(k), str(root)
        if len(rows) < _CANDIDATES:
            return -1, EMPTY
        below = int(rows[-1][0])


async def log_root(db: Any, height: int) -> str:
    """``log_root`` of the stored chain's block at ``height`` (EMPTY below genesis)."""
    from .. import chain_index

    if height < 0:
        return EMPTY
    await _ensure(db)
    k, root = await _newest_known(db, height)
    if k < height:
        logs = await logs_between(db, k + 1, height)
        for h in sorted(logs):
            root = fold(root, h, logs[h])
        block_hash = await chain_index.block_hash_at(db, height)
        if block_hash is not None:
            _remember(height, block_hash, root)
            if height // STORE_EVERY > k // STORE_EVERY:
                db.store["validator_log_roots"].put(int(height), block_hash, root)
    return root


async def compute(db: Any, height: int, slot: int) -> str:
    """The validator root of the block at ``height`` and ``slot`` being proposed or verified:
    its parent is the stored tip, and its own logs are written (block application ran)."""
    from ..constants import SLOTS_PER_EPOCH
    from ..crypto.hashing import state_root_hex
    from . import epoch_state

    parent = int(height) - 1
    state = await epoch_state.state_at(db, int(slot) // SLOTS_PER_EPOCH, parent)
    own = await logs_between(db, int(height), int(height))
    logs = fold(await log_root(db, parent), int(height), own.get(int(height), []))
    return state_root_hex(f"qrdx-validators|{epoch_state.state_hash(state)}|{logs}".encode())


def clear_memo() -> None:
    _memo.clear()
