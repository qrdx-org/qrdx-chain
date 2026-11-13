"""
Provable state: a sparse Merkle tree over the database state, bound into every block's signed
state root (chain-spec feature ``provable_state``; docs/STATE_PROOFS.md).

The domain roots are LtHash accumulators (qrdx/state_commitment.py): cheap to keep, but they
cannot prove that one entry is in them. This module keeps a sparse Merkle tree
(qrdx/crypto/smt.py) over the same rows, whose root — the **proof root** — is a fifth input of
the unified state root (qrdx/crypto/hashing.py ``unified_state_root``). A balance, a contract
storage slot or a token balance can then be proven against a block's signed header by anyone who
does not execute the chain: a light client, a bridge, or a contract (the EVM precompile,
qrdx/contracts/state_proof_evm.py).

Entries (each a typed, fixed-width payload, so a contract can build one; absent when zero):

* account ``0x01 | id (20) | balance in wei (32) | nonce (32) | code hash (32) | storage root (32)``
* storage ``0x02 | contract id (20) | slot (32) | value (32)``
* token   ``0x03 | holder id (20) | token (20) | balance × 10^18 (32)``

An entry's key is ``key_of(type | identity)``; its leaf commits to ``value_hash(payload)``.

**Keeping it.** The store (qrdx/store.py) marks every changed row of the three tables, in the
writes' own transaction. ``proof_root`` folds the marked rows into the tree when a block's root
is computed — on every path, at the point the other roots are — and records the root for that
height. Everything it writes is in the block's transaction, so a rolled-back block takes its tree
changes with it. The tree is a function of the rows alone (qrdx/crypto/smt.py), so it does not
matter when or how often the marks are folded.

Stored nodes are keyed by an internal version that never repeats in this process (nor across
restarts: it is in ``smt_meta``), so a cached node is never wrong. Nodes a later version replaced
are pruned once no retained height's root reaches them (``STATE_PROOF_RETENTION_BLOCKS``).
"""

from __future__ import annotations

import asyncio
import os
import weakref
from collections import OrderedDict
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .crypto import smt
from .logger import get_logger
from .native import smt_nodes_cache, smt_update_function, smt_update_into_function

logger = get_logger(__name__)

FEATURE = "provable_state"
ACCOUNT, STORAGE, TOKEN = b"\x01", b"\x02", b"\x03"
RETENTION_BLOCKS = int(os.environ.get("QRDX_STATE_PROOF_RETENTION_BLOCKS", "100000"))
PRUNE_EVERY = 1000
_CACHE_SIZE = 200_000

# kind → (table, the identity columns, the payload columns)
TABLES = {
    "account": (
        "account_state",
        ("address",),
        ("address", "balance", "nonce", "code_hash", "storage_root"),
    ),
    "storage": (
        "contract_storage",
        ("contract_address", "storage_key"),
        ("contract_address", "storage_key", "storage_value"),
    ),
    "token": (
        "token_balances",
        ("token_address", "holder_address"),
        ("token_address", "holder_address", "balance"),
    ),
}

# (by store)
_locks: "weakref.WeakKeyDictionary[Any, asyncio.Lock]" = weakref.WeakKeyDictionary()
_versions: "weakref.WeakKeyDictionary[Any, int]" = weakref.WeakKeyDictionary()
# (an OrderedDict, or the native module's SmtNodes: qrdx/native.py ``smt_nodes_cache``)
_caches: "weakref.WeakKeyDictionary[Any, Any]" = weakref.WeakKeyDictionary()

_KIND_OF = {table: kind for kind, (table, _i, _c) in TABLES.items()}


# ── entries ──────────────────────────────────────────────────────────────────────────────


def _id20(address: Any) -> bytes:
    """A 20-byte account id (qrdx/crypto/account_id.py) for any address form."""
    from .crypto.account_id import to_account_id

    return bytes.fromhex(to_account_id(str(address))[2:])


def _addr20(text: Any) -> bytes:
    """A 20-byte address: a 0x… hex address as is, anything else (a symbol) by its hash."""
    s = str(text or "")
    if s.startswith(("0x", "0X")) and len(s) == 42:
        try:
            return bytes.fromhex(s[2:])
        except ValueError:
            pass
    return smt.key_of(b"qrdx/smt/name\x00" + s.encode())[:20]


def _word(value: Any) -> bytes:
    """32 bytes: an integer (big-endian), or a 32-byte hex string, or the hash of other text."""
    if value is None or value == "":
        return bytes(32)
    if isinstance(value, int):
        return max(0, value).to_bytes(32, "big")
    s = str(value)
    h = s[2:] if s.startswith(("0x", "0X")) else s
    if len(h) == 64:
        try:
            return bytes.fromhex(h)
        except ValueError:
            pass
    return smt.key_of(b"qrdx/smt/text\x00" + s.encode())


def _int(value: Any, scale: int = 0) -> int:
    try:
        d = Decimal(str(value or 0))
    except (InvalidOperation, ValueError):
        return 0
    return max(0, int(d.scaleb(scale)))


def account_entry(address, balance, nonce, code_hash, storage_root) -> Optional[bytes]:
    """The account entry's payload — None when the account is all zero (absent)."""
    body = (
        _int(balance).to_bytes(32, "big")
        + _int(nonce).to_bytes(32, "big")
        + _word(code_hash)
        + _word(storage_root)
    )
    if body == bytes(len(body)):
        return None
    return ACCOUNT + _id20(address) + body


def storage_entry(contract, slot, value) -> Optional[bytes]:
    v = _word(value)
    if v == bytes(32):
        return None
    return STORAGE + _id20(contract) + _word(slot) + v


def token_entry(token, holder, balance) -> Optional[bytes]:
    amount = _int(balance, 18)
    if amount == 0:
        return None
    return TOKEN + _id20(holder) + _addr20(token) + amount.to_bytes(32, "big")


_ENTRY: Dict[str, Callable[..., Optional[bytes]]] = {
    "account": account_entry,
    "storage": storage_entry,
    "token": token_entry,
}
_IDENTITY_LENGTH = {ACCOUNT: 20, STORAGE: 52, TOKEN: 40}


def entry_key(payload_or_identity: bytes) -> bytes:
    """An entry's key, from its payload (or its type and identity alone)."""
    kind = payload_or_identity[:1]
    n = _IDENTITY_LENGTH.get(kind)
    if n is None:
        raise ValueError("not a state entry")
    return smt.key_of(payload_or_identity[: 1 + n])


def identity(kind: str, *ident: Any) -> bytes:
    if kind == "account":
        return ACCOUNT + _id20(ident[0])
    if kind == "storage":
        return STORAGE + _id20(ident[0]) + _word(ident[1])
    if kind == "token":
        return TOKEN + _id20(ident[1]) + _addr20(ident[0])
    raise ValueError(f"unknown entry kind {kind!r}")


# ── keeping the tree ─────────────────────────────────────────────────────────────────────


def scheduled() -> bool:
    """Does this network's chain spec switch the feature on at all (genesis or a fork)?"""
    from . import chain_spec

    try:
        return chain_spec.active().is_scheduled(FEATURE, 1 << 62)
    except Exception:
        return False


def install(db: Any) -> None:
    """On a network that schedules the feature: a store that has never kept the tree has every
    row marked, so the first root covers them. Elsewhere the store marks nothing."""
    store = db.store
    if not scheduled():
        store.set_tracking(False)
        return
    if store["smt_meta"].get(1) is None:
        mark_all(db)
        store["smt_meta"].put(1, 0, smt.encode_ref(None))
        store.commit()


def mark_all(db: Any) -> None:
    """Mark every row of the tree's tables (the next root re-derives the tree from them)."""
    for table in _KIND_OF:
        t = db.store[table]
        for row in t.scan():
            db.store.native.mark(t.id, t.key(*row[: len(t.spec.key)]))


def _lock(store: Any) -> asyncio.Lock:
    lock = _locks.get(store)
    if lock is None:
        lock = _locks[store] = asyncio.Lock()
    return lock


def _loader(store: Any):
    cache = _caches.get(store)
    if cache is None:
        native = smt_nodes_cache(_CACHE_SIZE) if smt_update_into_function() else None
        cache = _caches[store] = native if native is not None else OrderedDict()
    nodes = store["smt_nodes"]
    if not isinstance(cache, OrderedDict):  # (held natively)

        async def load_native(nkey: str) -> Optional[bytes]:
            data = cache.get(nkey)
            if data is not None:
                return data  # type: ignore[no-any-return]
            row = nodes.get(nkey)
            if row is None:
                return None
            data = bytes(row.data)
            cache.insert_many([(nkey, data)])
            return data

        return load_native, cache

    async def load(nkey: str) -> Optional[bytes]:
        data = cache.get(nkey)
        if data is not None:
            cache.move_to_end(nkey)
            return data
        row = nodes.get(nkey)
        if row is None:
            return None
        data = bytes(row.data)
        cache[nkey] = data
        if len(cache) > _CACHE_SIZE:
            cache.popitem(last=False)
        return data

    return load, cache


def _load_missing(store: Any, cache: Any, missing: List[str]) -> None:
    """Read the nodes an update named into ``cache`` (KeyError for any the store lacks)."""
    nodes = store["smt_nodes"]
    found = [
        (str(nkey), bytes(row.data))
        for nkey, row in zip(missing, nodes.get_many((k,) for k in missing), strict=True)
        if row is not None
    ]
    if len(found) < len(missing):
        raise KeyError(f"state tree nodes missing (pruned?): {sorted(set(missing))[:3]}")
    if isinstance(cache, OrderedDict):
        cache.update(found)
    else:
        cache.insert_many(found)


def _native_update_into(
    update: Any,
    store: Any,
    cache: Any,
    root_ref: Optional[smt.Ref],
    changes: List[smt.Change],
    version: int,
) -> Optional[smt.Ref]:
    """``_native_update`` over the native node cache, writing the new and stale nodes to the
    store (and the new ones to the cache) itself: the new root."""
    encoded = smt.encode_ref(root_ref)
    tables = (store["smt_nodes"].id, store["smt_stale"].id)
    for _ in range(300):
        out = update(encoded, changes, version, cache, store.native, tables)
        if out[0] == "ok":
            return smt.Ref.decode(out[1])[0]
        _load_missing(store, cache, list(out[1]))
    raise RuntimeError("the state tree update did not settle")


async def _native_update(
    update: Any,
    store: Any,
    cache: Any,
    root_ref: Optional[smt.Ref],
    changes: List[smt.Change],
    version: int,
) -> Tuple[Optional[smt.Ref], List[Tuple[str, bytes]], List[str]]:
    """``smt.Tree(load, version).update(root_ref, changes)``, natively (qrdx/native.py): the same
    writes, stale nodes and root. The nodes it needs that are not cached are named in one pass,
    loaded together, and the update runs again; at most a pass a level of the tree."""
    encoded = smt.encode_ref(root_ref)
    for _ in range(300):
        out = update(encoded, changes, version, cache)
        if out[0] == "ok":
            return smt.Ref.decode(out[1])[0], list(out[2]), list(out[3])
        _load_missing(store, cache, list(out[1]))
    raise RuntimeError("the state tree update did not settle")


def _changes(store: Any, marks: Sequence[Tuple[str, bytes]]) -> List[smt.Change]:
    """The marked rows' entries as they are now: (key, payload or None). Natively where the
    module computes them exactly (``smt_entries``: account ids, plain numerals, 32-byte words),
    else by the functions above."""
    from .native import smt_entries_function
    from .store import unpack

    native_entries = smt_entries_function()
    out: Dict[bytes, Optional[bytes]] = {}
    by_table: Dict[str, List[bytes]] = {}
    for table, key in marks:
        if table in _KIND_OF:
            by_table.setdefault(table, []).append(key)
    for table in sorted(by_table, key=lambda t: _KIND_OF[t]):
        kind = _KIND_OF[table]
        _t, _ident_cols, cols = TABLES[kind]
        t = store[table]
        keys = sorted(set(by_table[table]))  # (packed: in the order of their tuples)
        values = store.native.get_many(t.id, keys)
        at = [t.spec.columns.index(c) for c in cols]
        fast = (
            native_entries(kind, list(zip(keys, values, strict=True)), at)
            if native_entries is not None
            else [None] * len(keys)
        )
        for key, value, got in zip(keys, values, fast, strict=True):
            if got is None:
                ident = unpack(key)
                try:
                    ekey = smt.key_of(identity(kind, *ident))
                except Exception:
                    continue  # an identity no entry can have (malformed row): not committed
                row = t.row(key, value) if value is not None else None
                payload = (
                    _ENTRY[kind](*(getattr(row, c) for c in cols)) if row is not None else None
                )
            else:
                ekey, payload = got
            if ekey not in out or payload is not None:  # (two spellings of one id: the row wins)
                out[ekey] = payload
    return sorted(out.items())


async def proof_root(db: Any, height: int, exchange_root: Optional[bytes] = None) -> Optional[str]:
    """The proof root for the block at ``height`` (hex): the database tree's root — folding in
    every row changed since the last fold — combined with ``exchange_root``, the exchange tree's
    (qrdx/exchange/proofs.py; every caller that binds the root passes it). None if the feature
    is not in force at that height (the tree is still kept on a network that schedules it, so it
    is ready when it is)."""
    from . import chain_spec
    from .store import pack

    if not scheduled():
        return None
    store = db.store
    async with _lock(store):
        meta = store["smt_meta"].get(1)
        if meta is None:
            install(db)
            meta = store["smt_meta"].get(1)
        version, root_ref = int(meta.version), smt.Ref.decode(bytes(meta.root))[0]
        marks = store.native.take_marks()
        if marks:
            version = max(version, _versions.get(store, 0)) + 1
            _versions[store] = version
            load, cache = _loader(store)
            changes = _changes(store, marks)
            update_into = smt_update_into_function()
            if update_into is not None and not isinstance(cache, OrderedDict):
                root_ref = _native_update_into(
                    update_into, store, cache, root_ref, changes, version
                )
            else:
                native_update = smt_update_function()
                if native_update is not None:
                    root_ref, writes, stale = await _native_update(
                        native_update, store, cache, root_ref, changes, version
                    )
                else:
                    tree = smt.Tree(load, version)
                    root_ref = await tree.update(root_ref, changes)
                    writes, stale = list(tree.writes.items()), tree.stale
                store["smt_nodes"].put_raw([(pack((k,)), pack((d,))) for k, d in writes])
                store["smt_stale"].put_raw([(pack((version, k)), pack(())) for k in stale])
                cache.update(writes)
            store["smt_meta"].put(1, version, smt.encode_ref(root_ref))
        store["smt_roots"].put(int(height), version, smt.encode_ref(root_ref))
        if int(height) % PRUNE_EVERY == 0:
            _prune(store, int(height) - RETENTION_BLOCKS)
    if not chain_spec.is_active(FEATURE, int(height)):
        return None
    return smt.combine(smt.root_hash(root_ref), exchange_root or smt.EMPTY).hex()


async def database_root(db: Any, height: int) -> Optional[str]:
    """The database tree's root recorded for ``height`` (hex)."""
    row = db.store["smt_roots"].get(int(height))
    return smt.root_hash(smt.Ref.decode(bytes(row.root))[0]).hex() if row else None


def _prune(store: Any, below_height: int) -> None:
    """Forget heights below ``below_height`` and the nodes only they reached."""
    if below_height <= 0:
        return
    store["smt_roots"].delete_prefix(lo=(-(2**62),), hi=(below_height,))
    store["state_root_parts"].delete_prefix(lo=(-(2**62),), hi=(below_height,))
    # (versions grow with height — a rolled-back height is redone at a newer version — so the
    # lowest retained height's is the oldest)
    lowest = store["smt_roots"].scan(limit=1)
    if not lowest:
        return
    oldest = int(lowest[0].version)  # a node replaced at or before it is reached by no root
    stale = store["smt_stale"].scan(lo=(-(2**62),), hi=(oldest + 1,))
    store.native.delete_many(store["smt_nodes"].id, [store["smt_nodes"].key(r.nkey) for r in stale])
    store["smt_stale"].delete_prefix(lo=(-(2**62),), hi=(oldest + 1,))


async def record_parts(db: Any, height: int, parts: Dict[str, Optional[str]]) -> None:
    """Remember the domain roots block ``height``'s unified root was made of (for proofs)."""
    if not scheduled():
        return
    db.store["state_root_parts"].put(
        int(height),
        parts.get("utxo"),
        parts.get("account"),
        parts.get("exchange"),
        parts.get("token"),
        parts.get("proof"),
        await database_root(db, height),
        parts.get("xtree"),
        parts.get("validators"),
    )


async def recorded(db: Any, height: Optional[int] = None) -> Dict[str, Any]:
    """The roots recorded for ``height`` (default: the newest provable one): the four domain
    roots (and the validator root, once committed), the two trees' and the proof root."""
    roots_t, parts_t = db.store["smt_roots"], db.store["state_root_parts"]
    if height is None:
        newest = parts_t.scan(reverse=True, limit=64)
        height = next((int(p.height) for p in newest if roots_t.exists(p.height)), None)
        if height is None:
            raise ValueError("no provable height recorded yet")
    r, p = roots_t.get(int(height)), parts_t.get(int(height))
    if r is None or p is None:
        raise ValueError(
            f"no proof root recorded for height {height} (pruned, or not computed here)"
        )
    roots = {"utxo": p.utxo, "account": p.account, "exchange": p.exchange, "token": p.token}
    if p.validators:
        roots["validators"] = p.validators
    return {
        "height": int(height),
        "ref": smt.Ref.decode(bytes(r.root))[0],
        "roots": roots,
        "proof_root": p.proof,
        "database_tree_root": p.dtree,
        "exchange_tree_root": p.xtree or smt.EMPTY.hex(),
    }


async def undo_above(db: Any, tip_height: int) -> None:
    """After a rollback to ``tip_height``: the orphaned heights' roots are forgotten. (The tree
    itself needs nothing: the rows the rollback rewrote are marked, and fold in next.)"""
    if not scheduled():
        return
    db.store["smt_roots"].delete_prefix(lo=(int(tip_height) + 1,), hi=(2**62,))
    db.store["state_root_parts"].delete_prefix(lo=(int(tip_height) + 1,), hi=(2**62,))


# ── proofs ───────────────────────────────────────────────────────────────────────────────


async def prove(db: Any, kind: str, *ident: Any, height: Optional[int] = None) -> Dict[str, Any]:
    """A proof of one entry at ``height`` (default: the newest height with a recorded root):
    the entry (or its absence), the tree path, the proof root and the other domain roots — all
    a verifier needs to reach the block's signed state root (``verify_against``)."""
    rec = await recorded(db, height)
    ident_bytes = identity(kind, *ident)
    key = smt.key_of(ident_bytes)
    load, _cache = _loader(db.store)
    siblings, terminal, payload = await smt.Tree(load, 0).prove(rec["ref"], key)
    member = terminal is not None and terminal[0] == key
    return {
        "domain": "database",
        "height": rec["height"],
        "kind": kind,
        "key": key.hex(),
        "identity": ident_bytes.hex(),
        "entry": payload.hex() if member and payload is not None else None,
        "siblings": [s.hex() for s in siblings],
        "terminal": (
            None
            if terminal is None or member
            else {"key": terminal[0].hex(), "value_hash": terminal[1].hex()}
        ),
        "database_tree_root": smt.root_hash(rec["ref"]).hex(),
        "exchange_tree_root": rec["exchange_tree_root"],
        "proof_root": rec["proof_root"],
        "roots": rec["roots"],
    }


async def prove_exchange(
    db: Any, mgr: Any, path: str, key: Any = None, height: Optional[int] = None, part: bool = False
) -> Dict[str, Any]:
    """A proof of one exchange entry (``path``, ``key``) — or of a part (``part``: ``path`` is
    its name) — at ``height`` (default: the newest provable height whose exchange trees this node
    still keeps), with what reaches the signed state root."""
    from .exchange import proofs

    rec = await recorded(db, height)
    out = (
        proofs.prove_part(mgr, rec["height"], path)
        if part
        else proofs.prove(mgr, rec["height"], path, key)
    )
    if out["exchange_tree_root"] != rec["exchange_tree_root"]:
        raise ValueError(f"the exchange trees kept for height {rec['height']} are not its own")
    out.update(
        database_tree_root=rec["database_tree_root"],
        proof_root=rec["proof_root"],
        roots=rec["roots"],
    )
    return out


def verify_against(state_root: str, proof: Dict[str, Any]) -> bool:
    """Does ``proof`` (as ``prove`` or ``prove_exchange`` returns it) hold against a block's
    signed ``state_root``? Folds the entry to its tree's root, combines the two trees' roots into
    the proof root, and checks it with the domain roots against the signed unified root."""
    from .crypto.hashing import unified_state_root

    xroot: Optional[bytes]
    droot: Optional[bytes]
    try:
        if proof.get("domain") in ("exchange", "exchange_part"):
            from .exchange.proofs import exchange_root_of

            xroot = exchange_root_of(proof)
            droot = bytes.fromhex(proof["database_tree_root"])
        else:
            droot = _database_root_of(proof)
            xroot = bytes.fromhex(proof["exchange_tree_root"])
    except (KeyError, ValueError, TypeError):
        return False
    if xroot is None or droot is None:
        return False
    proof_root = smt.combine(droot, xroot).hex()
    if proof.get("proof_root") not in (None, proof_root):
        return False
    r = proof["roots"]
    unified = unified_state_root(
        r["utxo"] or "0" * 64,
        r["account"],
        r["exchange"],
        r["token"],
        proof_root,
        r.get("validators"),
    )
    return unified == state_root


def _database_root_of(proof: Dict[str, Any]) -> Optional[bytes]:
    """The database tree root a database proof folds to (None if it is malformed)."""
    key = bytes.fromhex(proof["key"])
    entry = bytes.fromhex(proof["entry"]) if proof.get("entry") else None
    if entry is not None and entry_key(entry) != key:
        return None
    if entry is None and smt.key_of(bytes.fromhex(proof["identity"])) != key:
        return None
    t = proof.get("terminal")
    terminal = (
        None
        if entry is not None
        else (bytes.fromhex(t["key"]), bytes.fromhex(t["value_hash"])) if t else None
    )
    return smt.fold(
        key,
        smt.value_hash(entry) if entry is not None else None,
        [bytes.fromhex(s) for s in proof["siblings"]],
        terminal,
    )


def decode_entry(payload: bytes) -> Dict[str, Any]:
    """An entry's fields, for display."""
    kind = payload[:1]
    if kind == ACCOUNT:
        return {
            "type": "account",
            "id": "0x" + payload[1:21].hex(),
            "balance_wei": str(int.from_bytes(payload[21:53], "big")),
            "nonce": int.from_bytes(payload[53:85], "big"),
            "code_hash": payload[85:117].hex(),
            "storage_root": payload[117:149].hex(),
        }
    if kind == STORAGE:
        return {
            "type": "storage",
            "contract": "0x" + payload[1:21].hex(),
            "slot": payload[21:53].hex(),
            "value": payload[53:85].hex(),
        }
    if kind == TOKEN:
        return {
            "type": "token",
            "holder": "0x" + payload[1:21].hex(),
            "token": "0x" + payload[21:41].hex(),
            "balance_e18": str(int.from_bytes(payload[41:73], "big")),
        }
    raise ValueError("not a state entry")
