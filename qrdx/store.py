"""
The node's store: ordered tables in one MDBX file, kept by the native module (docs/STORAGE.md;
native/qrdx-native/src/store).

It replaces the node's SQLite database table by table. A table here is a sorted map from a key
(a tuple of its key columns) to a value (a tuple of its other columns), each packed so that keys
sort as their tuples do. What SQLite did by triggers, the store does natively as each row
changes, so no write path can forget it:

* **Commitments.** The account, token and UTXO domains' LtHash accumulators
  (qrdx/state_commitment.py) follow every row of the tables that feed them.
* **The undo journal.** While a block's height is set, every row a block changes in a journaled
  table is recorded as it was (qrdx/undo_journal.py), so a reorg takes the block back out.
* **Marks** for the state proof tree (qrdx/state_proofs.py): every changed row of a tracked table.

Writes wait in memory until ``commit`` — the database's ``connection.commit()`` commits the store
first (DatabaseSQLite.create) — and ``rollback`` drops them, so a block's rows reach the file
together or not at all.

Values keep SQLite's column affinities (``_coerce``): a TEXT column stores text, an INTEGER
column an int, so a row reads back as it did from SQLite and commits to the same entry.

The store needs the native module; unlike the paths qrdx/native.py stands in for, there is no
Python implementation (``QRDX_NATIVE=0`` does not turn it off).
"""

from __future__ import annotations

import contextlib
import datetime
import os
from collections import namedtuple
from decimal import Decimal
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

import qrdx_native

pack = qrdx_native.store_pack
unpack = qrdx_native.store_unpack

# Address space reserved for the file (it grows as it fills, up to this), and the steps it grows
# by (a step is written out in full on some file systems: tmpfs).
MAX_GB = float(os.environ.get("QRDX_STORE_MAX_GB", "256"))
GROWTH_MB = float(os.environ.get("QRDX_STORE_GROWTH_MB", "16"))

# The stores this process has open, by their file's real path: MDBX allows one handle a file a
# process, so a second user here (a snapshot of the running node) shares it (``opened``).
_OPEN: Dict[str, "Store"] = {}


def opened(path: str) -> Optional["Store"]:
    """The store this process already has open at ``path``, if any."""
    return _OPEN.get(os.path.realpath(path))


def remove_files(path: str) -> None:
    """Delete a (closed) store's file and its lock file."""
    for name in (path, path + "-lck"):
        if os.path.exists(name):
            os.remove(name)


class Spec:
    """A table: its key columns, its other columns as (name, affinity, default), and its hooks."""

    def __init__(
        self,
        name: str,
        key: Sequence[Tuple[str, str]],
        value: Sequence[Tuple[str, str, Any]],
        *,
        journaled: bool = False,
        tracked: bool = False,
        commitment: Optional[Tuple[str, str, Sequence[str]]] = None,
        raw: bool = False,
        indexes: Optional[Dict[str, Sequence[str]]] = None,
    ) -> None:
        self.name = name
        self.key = tuple(c for c, _a in key)
        self.key_affinity = tuple(a for _c, a in key)
        self.value = tuple(c for c, _a, _d in value)
        self.value_affinity = tuple(a for _c, a, _d in value)
        self.defaults = tuple(d for _c, _a, d in value)
        self.columns = self.key + self.value
        self.journaled = journaled
        self.tracked = tracked
        self.commitment = commitment  # (kind, domain, committed columns)
        # One BLOB column stored as its bytes, not packed: a large value written and read whole.
        self.raw = raw
        if raw and len(self.value) != 1:
            raise ValueError(f"{name}: a raw table has one value column")
        # Secondary indexes, kept natively with every write: name → the columns it is keyed by
        # (its rows, in their order, by ``Table.scan_index``).
        self.indexes: Dict[str, Tuple[str, ...]] = {k: tuple(v) for k, v in (indexes or {}).items()}
        if raw and self.indexes:
            raise ValueError(f"{name}: a raw table has no index")

    def index_table(self, index: str) -> str:
        return f"{self.name}__{index}"

    def affinity(self, column: str) -> str:
        i = self.columns.index(column)
        n = len(self.key)
        return self.key_affinity[i] if i < n else self.value_affinity[i - n]


_T, _I, _B = "TEXT", "INTEGER", "BLOB"

SPECS: Tuple[Spec, ...] = (
    # ── the ledger (qrdx/database_sqlite.py's schema, the same columns) ──
    Spec(
        "account_state",
        [("address", _T)],
        [
            ("balance", _T, "0"),
            ("nonce", _I, 0),
            ("code_hash", _T, None),
            ("storage_root", _T, None),
            ("created_at", _I, 0),
            ("updated_at", _I, 0),
            ("is_contract", _I, 0),
        ],
        journaled=True,
        tracked=True,
        commitment=(
            "account",
            "account",
            ("address", "balance", "nonce", "code_hash", "storage_root"),
        ),
    ),
    Spec(
        "contract_storage",
        [("contract_address", _T), ("storage_key", _T)],
        [("storage_value", _T, None), ("block_number", _I, 0)],
        journaled=True,
        tracked=True,
        commitment=("storage", "account", ("contract_address", "storage_key", "storage_value")),
    ),
    Spec(
        "contract_code",
        [("code_hash", _T)],
        [("bytecode", _B, b""), ("deployed_at", _I, 0), ("deployer", _T, ""), ("size", _I, 0)],
    ),
    Spec(
        "token_balances",
        [("token_address", _T), ("holder_address", _T)],
        [("balance", _T, "0"), ("updated_at", _I, 0)],
        journaled=True,
        tracked=True,
        commitment=("token", "token", ("token_address", "holder_address", "balance")),
    ),
    Spec(
        "token_registry",
        [("token_address", _T)],
        [
            ("name", _T, None),
            ("symbol", _T, None),
            ("decimals", _I, 18),
            ("total_supply", _T, None),
            ("owner_address", _T, None),
            ("is_frozen", _I, 0),
            ("created_at", _I, 0),
            ("updated_at", _I, 0),
        ],
        journaled=True,
    ),
    Spec(
        "evm_balance_sync_registry",
        [("address", _T)],
        [
            ("last_sync_block_height", _I, 0),
            ("last_sync_block_hash", _T, None),
            ("last_sync_timestamp", _T, None),
            ("native_balance_at_sync", _T, None),
            ("evm_balance_at_sync", _T, None),
            ("sync_tx_hash", _T, None),
        ],
        journaled=True,
    ),
    Spec(
        "evm_balance_changes",
        [("change_id", _I)],
        [
            ("address", _T, None),
            ("block_height", _I, 0),
            ("block_hash", _T, None),
            ("tx_hash", _T, None),
            ("balance_before", _T, None),
            ("balance_after", _T, None),
            ("delta", _T, None),
            ("change_reason", _T, None),
            ("changed_at", _T, None),
        ],
        journaled=True,
    ),
    Spec(
        "unspent_outputs",
        [("tx_hash", _T), ("output_index", _I)],
        [("address", _T, None), ("amount", _I, 0)],
        commitment=("utxo", "utxo", ("tx_hash", "output_index", "address", "amount")),
    ),
    # ── the state proof tree (qrdx/state_proofs.py) ──
    Spec("smt_nodes", [("nkey", _T)], [("data", _B, b"")]),
    Spec("smt_stale", [("version", _I), ("nkey", _T)], []),
    Spec("smt_roots", [("height", _I)], [("version", _I, 0), ("root", _B, b"")]),
    Spec("smt_meta", [("id", _I)], [("version", _I, 0), ("root", _B, b"")]),
    Spec(
        "state_root_parts",
        [("height", _I)],
        [
            ("utxo", _T, None),
            ("account", _T, None),
            ("exchange", _T, None),
            ("token", _T, None),
            ("proof", _T, None),
            ("dtree", _T, None),
            ("xtree", _T, None),
            ("validators", _T, None),
        ],
    ),
    # ── the chain: each block's header by height (and by hash), its body apart (zlib text,
    # qrdx/block_codec.py: what most reads skip), the transactions blocks carry (legacy and
    # genesis records, in the order stored), the chain's settings ──
    Spec(
        "blocks",
        [("block_height", _I)],
        [
            ("block_hash", _T, None),
            ("prev_block_hash", _T, None),
            ("merkle_root", _T, None),
            ("timestamp", _I, None),
            ("difficulty", _I, None),
            ("nonce", _I, None),
            ("validator_address", _T, None),
            ("validator_signature", _T, None),
            ("created_at", _T, None),
        ],
        indexes={"by_hash": ("block_hash",)},
    ),
    Spec("block_bodies", [("block_height", _I)], [("content", _B, b"")], raw=True),
    Spec(
        "transactions",
        [("tx_hash", _T)],
        [
            ("tx_hex", _T, None),
            ("block_hash", _T, None),
            ("inputs_addresses", _T, None),
            ("outputs_addresses", _T, None),
            ("outputs_amounts", _T, None),
            ("fees", _I, None),
            ("created_at", _T, None),
            ("seq", _I, 0),
        ],
        indexes={"by_block": ("block_hash", "seq")},
    ),
    Spec("chain_metadata", [("key", _T)], [("value", _T, None)]),
    # ── the chain index (qrdx/chain_index.py): derived from the blocks, re-derived at will ──
    Spec(
        "chain_index",
        [("height", _I)],
        [
            ("block_hash", _T, None),
            ("slot", _I, None),
            ("epoch", _I, None),
            ("randao_mix", _T, None),
        ],
        indexes={"by_slot": ("slot",), "by_epoch": ("epoch",)},
    ),
    Spec(
        "chain_index_votes",
        [("height", _I), ("seq", _I)],
        [("carry_epoch", _I, None), ("target_epoch", _I, None), ("validator", _T, None)],
        indexes={"by_target": ("target_epoch", "validator")},
    ),
    Spec(
        "chain_index_offenders",
        [("height", _I), ("seq", _I)],
        [("offender", _T, None)],
        indexes={"by_offender": ("offender",)},
    ),
    Spec(
        "chain_index_ffg",
        [("height", _I), ("seq", _I)],
        [
            ("validator", _T, None),
            ("source_epoch", _I, None),
            ("source_root", _T, None),
            ("target_epoch", _I, None),
            ("target_root", _T, None),
        ],
        indexes={"by_target": ("target_epoch",)},
    ),
    Spec("chain_index_meta", [("key", _T)], [("value", _T, None)]),
    # ── the validator set's inputs, logged against the blocks that carried them, in the order
    # block application wrote them (qrdx/validator/epoch_state.py, validator_root.py), and its
    # stored states. ``id``: a counter of the table's own (``Store.next_id``), as AUTOINCREMENT
    # was; ``address_lc``: the address lower-cased, which the payouts compare by ──
    Spec(
        "validator_deposits",
        [("block_height", _I), ("id", _I)],
        [
            ("block_hash", _T, None),
            ("address", _T, None),
            ("public_key", _T, None),
            ("stake", _T, None),
            ("created_new", _I, 0),
            ("created_at", _T, None),
            ("address_lc", _T, None),
        ],
        indexes={"by_address": ("address_lc", "block_height")},
    ),
    Spec(
        "validator_exits",
        [("block_height", _I), ("id", _I)],
        [("address", _T, None), ("exit_epoch", _I, None)],
    ),
    Spec(
        "staking_ops",
        [("block_height", _I), ("id", _I)],
        [("kind", _T, None), ("sender", _T, None), ("validator", _T, None), ("value", _T, None)],
    ),
    Spec("staker_fee_income", [("block_height", _I)], [("amount", _T, None)]),
    Spec(
        "validator_withdrawals",
        [("address", _T), ("exit_epoch", _I)],
        [("amount", _T, None), ("block_height", _I, None), ("address_lc", _T, None)],
        indexes={
            "by_address": ("address_lc", "exit_epoch"),
            "by_height": ("block_height", "address"),
        },
    ),
    Spec(
        "staking_payouts",
        [("payout_id", _I)],
        [
            ("address", _T, None),
            ("amount", _T, None),
            ("kind", _T, None),
            ("block_height", _I, None),
        ],
        indexes={"by_height": ("block_height",)},
    ),
    Spec("validator_epoch_states", [("epoch", _I), ("checkpoint", _T)], [("state", _T, None)]),
    Spec("validator_log_roots", [("height", _I), ("block_hash", _T)], [("root", _T, None)]),
    # ── each block's sections, whole, by its hash: the exchange's as a JSON list of its items,
    # the EVM's as a JSON list of raw transactions (they were a row an item) ──
    Spec("exchange_sections", [("block_hash", _T)], [("data", _B, b"")], raw=True),
    Spec("evm_sections", [("block_hash", _T)], [("data", _B, b"")], raw=True),
    # ── the unified root after each block, by its hash (qrdx/post_state.py) ──
    Spec("post_roots", [("block_hash", _T)], [("height", _I, 0), ("root", _T, None)]),
    # ── the store's own settings (the undo journal's floor: qrdx/undo_journal.py) ──
    Spec("store_meta", [("key", _T)], [("value", _T, None)]),
)


def _looks_integral(text: str) -> Optional[int]:
    try:
        return int(text)
    except ValueError:
        pass
    try:
        f = float(text)
    except ValueError:
        return None
    return int(f) if f.is_integer() and abs(f) < 2**63 else None


def _coerce(value: Any, affinity: str) -> Any:
    """``value`` as SQLite stores it in a column of ``affinity``."""
    if value is None:
        return None
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, datetime.datetime):
        value = value.isoformat(" ")  # (sqlite3's adapters)
    elif isinstance(value, datetime.date):
        value = value.isoformat()
    if affinity == _T:
        if isinstance(value, (int, float, Decimal)):
            return str(value)
        if isinstance(value, (bytearray, memoryview)):
            return bytes(value)
        return value
    if affinity == _I:
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value) if value.is_integer() and abs(value) < 2**63 else value
        if isinstance(value, Decimal):
            value = str(value)
        if isinstance(value, str):
            n = _looks_integral(value.strip())
            return n if n is not None else value
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, Decimal):
        return str(value)
    return value


class Table:
    """One table of the store, its rows as named tuples of every column (key columns first)."""

    def __init__(self, store: "Store", spec: Spec) -> None:
        self.store = store
        self.spec = spec
        self.name = spec.name
        self.id = store.native.table_id(spec.name)
        self.Row: Any = namedtuple(spec.name, spec.columns)  # type: ignore[misc]
        self._index_ids = {i: store.native.table_id(spec.index_table(i)) for i in spec.indexes}
        self._n = store.native
        self._nk = len(spec.key)

    # ── keys and rows ──

    def key(self, *key: Any) -> bytes:
        aff = self.spec.key_affinity
        return pack(tuple(_coerce(v, aff[i]) for i, v in enumerate(key)))

    def _value(self, values: Sequence[Any]) -> bytes:
        if self.spec.raw:
            return bytes(values[0])
        aff = self.spec.value_affinity
        return pack(tuple(_coerce(v, aff[i]) for i, v in enumerate(values)))

    def row(self, key: bytes, value: bytes) -> Any:
        k = unpack(key)
        if self.spec.raw:
            return self.Row(*k, value)
        v = unpack(value)
        missing = len(self.spec.value) - len(v)
        if missing > 0:  # (a row written before a column was added)
            v = v + self.spec.defaults[len(v) :]
        return self.Row(*k, *v[: len(self.spec.value)])

    # ── reads ──

    def get(self, *key: Any) -> Any:
        k = self.key(*key)
        v = self._n.get(self.id, k)
        return None if v is None else self.row(k, v)

    def get_many(self, keys: Iterable[Sequence[Any]]) -> List[Any]:
        ks = [self.key(*k) for k in keys]
        return [
            None if v is None else self.row(k, v)
            for k, v in zip(ks, self._n.get_many(self.id, ks), strict=True)
        ]

    def exists(self, *key: Any) -> bool:
        return self._n.get(self.id, self.key(*key)) is not None

    def _range(
        self, prefix: Sequence[Any], lo: Optional[Sequence[Any]], hi: Optional[Sequence[Any]]
    ):
        p = self.key(*prefix) if prefix else b""
        lo_b = self.key(*prefix, *lo) if lo is not None else (p or None)
        hi_b = self.key(*prefix, *hi) if hi is not None else (p + b"\xff" if p else None)
        return lo_b, hi_b

    def scan(
        self,
        *prefix: Any,
        lo: Optional[Sequence[Any]] = None,
        hi: Optional[Sequence[Any]] = None,
        reverse: bool = False,
        limit: Optional[int] = None,
    ) -> List[Any]:
        """The rows whose key starts with ``prefix`` (and, after it, lies in [lo, hi)), in key
        order."""
        lo_b, hi_b = self._range(prefix, lo, hi)
        if self.spec.raw:
            return [self.row(k, v) for k, v in self._n.scan(self.id, lo_b, hi_b, reverse, limit)]
        out = []
        missing_ok = len(self.spec.value)
        for k, v in self._n.scan_rows(self.id, lo_b, hi_b, reverse, limit):
            if len(v) < missing_ok:
                v = v + self.spec.defaults[len(v) :]
            out.append(self.Row(*k, *v[:missing_ok]))
        return out

    def keys(self, *prefix: Any, lo=None, hi=None) -> List[Tuple[Any, ...]]:
        """The keys (as tuples) of the rows ``scan`` would return, without reading a value."""
        lo_b, hi_b = self._range(prefix, lo, hi)
        return [unpack(k) for k in self._n.keys(self.id, lo_b, hi_b)]

    def scan_index(
        self,
        index: str,
        *prefix: Any,
        lo: Optional[Sequence[Any]] = None,
        hi: Optional[Sequence[Any]] = None,
        reverse: bool = False,
        limit: Optional[int] = None,
    ) -> List[Any]:
        """The rows whose ``index`` columns start with ``prefix`` (and, after it, lie in
        [lo, hi)), in the index's order (ties by key)."""
        columns = self.spec.indexes[index]
        aff = [self.spec.affinity(c) for c in columns]

        def packed(values: Sequence[Any]) -> bytes:
            return pack(tuple(_coerce(v, aff[i]) for i, v in enumerate(values)))

        p = packed(prefix) if prefix else b""
        lo_b = packed((*prefix, *lo)) if lo is not None else (p or None)
        hi_b = packed((*prefix, *hi)) if hi is not None else (p + b"\xff" if p else None)
        n = len(self.spec.value)
        out = []
        for k, v in self._n.index_rows(self.id, self._index_ids[index], lo_b, hi_b, reverse, limit):
            if len(v) < n:
                v = v + self.spec.defaults[len(v) :]
            out.append(self.Row(*k, *v[:n]))
        return out

    def count(self, *prefix: Any) -> int:
        if not prefix:
            return self._n.count(self.id)
        lo_b, hi_b = self._range(prefix, None, None)
        return self._n.count(self.id, lo_b, hi_b)

    # ── writes ──

    def put(self, *row: Any, **columns: Any) -> None:
        """Write a whole row: its columns in order, or by name (missing ones take their
        defaults)."""
        if columns:
            spec = self.spec
            values = [columns.get(c, spec.defaults[i]) for i, c in enumerate(spec.value)]
            key = [columns[c] for c in spec.key]
        else:
            key, values = list(row[: self._nk]), list(row[self._nk :])
            if len(values) < len(self.spec.value):
                values += list(self.spec.defaults[len(values) :])
        self._n.put(self.id, self.key(*key), self._value(values))

    def insert(self, **columns: Any) -> bool:
        """``put`` unless the key is taken (INSERT OR IGNORE); whether it was written."""
        k = self.key(*(columns[c] for c in self.spec.key))
        if self._n.get(self.id, k) is not None:
            return False
        spec = self.spec
        self._n.put(
            self.id,
            k,
            self._value([columns.get(c, spec.defaults[i]) for i, c in enumerate(spec.value)]),
        )
        return True

    def update(self, key: Sequence[Any], **changes: Any) -> bool:
        """Change some columns of an existing row; whether there was one."""
        k = self.key(*key)
        v = self._n.get(self.id, k)
        if v is None:
            return False
        row = self.row(k, v)
        values = [changes.get(c, getattr(row, c)) for c in self.spec.value]
        self._n.put(self.id, k, self._value(values))
        return True

    def upsert(self, key: Sequence[Any], insert: Dict[str, Any], update: Iterable[str]) -> None:
        """INSERT … ON CONFLICT DO UPDATE SET (the columns in ``update``, from ``insert``)."""
        k = self.key(*key)
        v = self._n.get(self.id, k)
        spec = self.spec
        if v is None:
            values = [insert.get(c, spec.defaults[i]) for i, c in enumerate(spec.value)]
        else:
            row = self.row(k, v)
            update = set(update)
            values = [insert[c] if c in update else getattr(row, c) for c in spec.value]
        self._n.put(self.id, k, self._value(values))

    def put_raw(self, items: List[Tuple[bytes, bytes]]) -> None:
        """Rows already packed (a hot path that built them itself)."""
        self._n.put_many(self.id, items)

    def delete(self, *key: Any) -> bool:
        return self._n.delete(self.id, self.key(*key))

    def delete_prefix(self, *prefix: Any, lo=None, hi=None) -> int:
        lo_b, hi_b = self._range(prefix, lo, hi)
        return self._n.delete_range(self.id, lo_b, hi_b)

    def clear(self) -> None:
        """Every row gone, without a hook (see the native ``clear``)."""
        self._n.clear(self.id)


class Store:
    """The node's store, opened at ``path`` (a file)."""

    def __init__(self, path: str, specs: Sequence[Spec] = SPECS) -> None:
        self.path = path
        names = [s.name for s in specs]
        names += [s.index_table(i) for s in specs for i in s.indexes]
        self.native = qrdx_native.Store(path, names, MAX_GB, 1.0, GROWTH_MB)
        _OPEN[os.path.realpath(path)] = self
        self.tables: Dict[str, Table] = {}
        from . import state_commitment

        for spec in specs:
            table = self.tables[spec.name] = Table(self, spec)
            if spec.commitment is not None:
                kind, domain, cols = spec.commitment
                at = [spec.columns.index(c) for c in cols]
                encoder = state_commitment.TABLES[kind][1]
                self.native.set_commitment(table.id, kind, domain, at, encoder)
            if spec.journaled:
                self.native.set_journaled(table.id, True)
            if spec.tracked:
                self.native.set_tracked(table.id, True)
            for index, cols in spec.indexes.items():
                at = [spec.columns.index(c) for c in cols]
                self.native.set_index(table.id, table._index_ids[index], at)

    def __getitem__(self, name: str) -> Table:
        return self.tables[name]

    def set_tracking(self, on: bool) -> None:
        """Mark changed rows for the proof tree (only on a network that keeps it)."""
        for t in self.tables.values():
            if t.spec.tracked:
                self.native.set_tracked(t.id, on)

    def table_of(self, table_id: int) -> Table:
        for t in self.tables.values():
            if t.id == table_id:
                return t
        raise KeyError(table_id)

    def next_id(self, table: str) -> int:
        """The next ``id`` of ``table``: one above every id it has given (as AUTOINCREMENT, never
        reused), kept in ``store_meta`` with the rows it numbers."""
        meta = self["store_meta"]
        row = meta.get(f"id:{table}")
        n = (int(row.value) if row is not None else 0) + 1
        meta.put(f"id:{table}", str(n))
        return n

    def commit(self) -> None:
        self.native.commit()

    def rollback(self) -> None:
        self.native.rollback()

    def close(self) -> None:
        if _OPEN.get(os.path.realpath(self.path)) is self:
            del _OPEN[os.path.realpath(self.path)]
        self.native.close()

    def copy_to(self, path: str) -> None:
        """A consistent, compacted copy of what is committed, at ``path`` (a new file)."""
        self.native.copy_to(path)

    # ── commitments ──

    def acc(self, domain: str) -> bytes:
        return self.native.acc(domain)

    def set_acc(self, domain: str, acc: bytes) -> None:
        self.native.set_acc(domain, acc)

    # ── the undo journal ──

    @contextlib.contextmanager
    def recording(self, height: Optional[int]) -> Iterator[None]:
        previous = self.native.height()
        self.native.set_height(None if height is None else int(height))
        try:
            yield
        finally:
            self.native.set_height(previous)

    @contextlib.contextmanager
    def suspended(self) -> Iterator[None]:
        self.native.suspend()
        try:
            yield
        finally:
            self.native.resume()
