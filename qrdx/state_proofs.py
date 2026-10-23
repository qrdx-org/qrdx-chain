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

**Keeping it.** TEMP triggers (on the node's own connection, like the accumulators') mark every
changed row in ``smt_dirty``, in the writing statement's transaction. ``proof_root`` folds the
marked rows into the tree when a block's root is computed — on every path, at the point the
other roots are — and records the root for that height. Everything it writes is in the block's
transaction, so a rolled-back block takes its tree changes with it. The tree is a function of the
rows alone (qrdx/crypto/smt.py), so it does not matter when or how often the marks are folded.

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

logger = get_logger(__name__)

FEATURE = "provable_state"
ACCOUNT, STORAGE, TOKEN = b"\x01", b"\x02", b"\x03"
RETENTION_BLOCKS = int(os.environ.get("QRDX_STATE_PROOF_RETENTION_BLOCKS", "100000"))
PRUNE_EVERY = 1000
_CACHE_SIZE = 200_000

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS smt_nodes (nkey TEXT PRIMARY KEY, data BLOB NOT NULL)",
    # (No unique key: a trigger's conflict clause yields to its outer statement's — an upsert
    # would abort on a repeated mark. Marks are de-duplicated when read.)
    "CREATE TABLE IF NOT EXISTS smt_dirty (kind TEXT NOT NULL, ident TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_smt_dirty ON smt_dirty(kind, ident)",
    "CREATE TABLE IF NOT EXISTS smt_meta (id INTEGER PRIMARY KEY CHECK (id = 1),"
    " version INTEGER NOT NULL, root BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS smt_roots (height INTEGER PRIMARY KEY, version INTEGER NOT NULL,"
    " root BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS smt_stale (version INTEGER NOT NULL, nkey TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_smt_stale_version ON smt_stale(version)",
    # The domain roots each height's unified root was computed from (node-local: what a proof
    # needs to reach the signed root; written where the root is computed or checked).
    # (dtree / xtree: the database tree's and the exchange tree's roots; proof combines them)
    "CREATE TABLE IF NOT EXISTS state_root_parts (height INTEGER PRIMARY KEY, utxo TEXT,"
    " account TEXT, exchange TEXT, token TEXT, proof TEXT, dtree TEXT, xtree TEXT)",
)

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

_locks: "weakref.WeakKeyDictionary[Any, asyncio.Lock]" = weakref.WeakKeyDictionary()
_versions: "weakref.WeakKeyDictionary[Any, int]" = weakref.WeakKeyDictionary()
_caches: "weakref.WeakKeyDictionary[Any, OrderedDict]" = weakref.WeakKeyDictionary()


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


def _trigger_sql(kind: str) -> List[str]:
    table, ident_cols, payload_cols = TABLES[kind]

    def ident(prefix: str) -> str:
        return " || '|' || ".join(f"{prefix}.{c}" for c in ident_cols)

    mark = (
        "INSERT INTO smt_dirty (kind, ident) SELECT '{k}', {i} WHERE NOT EXISTS "
        "(SELECT 1 FROM smt_dirty WHERE kind = '{k}' AND ident = {i});"
    )
    changed = " OR ".join(f"OLD.{c} IS NOT NEW.{c}" for c in payload_cols)
    return [
        f"CREATE TEMP TRIGGER IF NOT EXISTS qrdx_smt_{kind}_ins AFTER INSERT ON main.{table} "
        f"BEGIN {mark.format(k=kind, i=ident('NEW'))} END",
        f"CREATE TEMP TRIGGER IF NOT EXISTS qrdx_smt_{kind}_upd AFTER UPDATE ON main.{table} "
        f"WHEN {changed} BEGIN {mark.format(k=kind, i=ident('OLD'))} "
        f"{mark.format(k=kind, i=ident('NEW'))} END",
        f"CREATE TEMP TRIGGER IF NOT EXISTS qrdx_smt_{kind}_del AFTER DELETE ON main.{table} "
        f"BEGIN {mark.format(k=kind, i=ident('OLD'))} END",
    ]


def scheduled() -> bool:
    """Does this network's chain spec switch the feature on at all (genesis or a fork)?"""
    from . import chain_spec

    try:
        return chain_spec.active().is_scheduled(FEATURE, 1 << 62)
    except Exception:
        return False


async def install(conn: Any) -> None:
    """Create the tables and the triggers on this connection — on a network that schedules
    the feature. A database that has never kept the tree has all its rows marked, so the first
    root covers them."""
    if not scheduled():
        return
    for sql in SCHEMA:
        await conn.execute(sql)
    for kind in TABLES:
        for sql in _trigger_sql(kind):
            await conn.execute(sql)
    cur = await conn.execute("SELECT 1 FROM smt_meta WHERE id = 1")
    fresh = await cur.fetchone() is None
    repaired = getattr(conn, "qrdx_lt_repaired", None) or {}
    if fresh or repaired.get("account") or repaired.get("token"):
        # Every row marked: a database that never kept the tree, or one whose rows were written
        # where the triggers do not run (the accumulators caught it at startup: they cover
        # every column the tree does). The next root re-derives the tree from the rows.
        if not fresh:
            # Rebuilt from empty: a row deleted without the triggers leaves nothing to mark.
            # (This node's proofs of earlier heights go with the old tree.)
            logger.warning("state proof tree: rows were written without its triggers; rebuilt")
            for table in ("smt_nodes", "smt_stale", "smt_roots"):
                await conn.execute(f"DELETE FROM {table}")
            await conn.execute("UPDATE smt_meta SET root = ? WHERE id = 1", (smt.encode_ref(None),))
            _caches.pop(conn, None)
        await conn.execute("DELETE FROM smt_dirty")
        for kind, (table, ident_cols, _cols) in TABLES.items():
            ident = " || '|' || ".join(ident_cols)
            try:
                await conn.execute(
                    f"INSERT INTO smt_dirty (kind, ident) SELECT DISTINCT '{kind}', {ident} "
                    f"FROM {table}"
                )
            except Exception:
                pass  # (a table not created yet: nothing to mark)
        if fresh:
            await conn.execute(
                "INSERT INTO smt_meta (id, version, root) VALUES (1, 0, ?)",
                (smt.encode_ref(None),),
            )
        await conn.commit()


def _lock(conn: Any) -> asyncio.Lock:
    lock = _locks.get(conn)
    if lock is None:
        lock = _locks[conn] = asyncio.Lock()
    return lock


def _loader(conn: Any):
    cache = _caches.get(conn)
    if cache is None:
        cache = _caches[conn] = OrderedDict()

    async def load(nkey: str) -> Optional[bytes]:
        data = cache.get(nkey)
        if data is not None:
            cache.move_to_end(nkey)
            return data
        cur = await conn.execute("SELECT data FROM smt_nodes WHERE nkey = ?", (nkey,))
        row = await cur.fetchone()
        if row is None:
            return None
        data = bytes(row[0])
        cache[nkey] = data
        if len(cache) > _CACHE_SIZE:
            cache.popitem(last=False)
        return data

    return load, cache


async def _changes(conn: Any, dirty: Sequence[Tuple[str, str]]) -> List[smt.Change]:
    """The marked rows' entries as they are now: (key, payload or None)."""
    out: Dict[bytes, Optional[bytes]] = {}
    by_kind: Dict[str, List[str]] = {}
    for kind, ident in dirty:
        by_kind.setdefault(kind, []).append(ident)
    for kind in sorted(by_kind):
        table, ident_cols, cols = TABLES[kind]
        idents = sorted(set(by_kind[kind]))
        found: Dict[str, Tuple[Any, ...]] = {}
        expr = " || '|' || ".join(ident_cols)
        for i in range(0, len(idents), 500):
            chunk = idents[i : i + 500]
            marks = ",".join("?" * len(chunk))
            cur = await conn.execute(
                f"SELECT {expr}, {', '.join(cols)} FROM {table} WHERE {expr} IN ({marks})",
                chunk,
            )
            for row in await cur.fetchall():
                found[str(row[0])] = tuple(row[1:])
        for ident in idents:
            parts = ident.split("|")
            try:
                key = smt.key_of(identity(kind, *parts))
            except Exception:
                continue  # an identity no entry can have (malformed row): not committed
            row = found.get(ident)
            payload = _ENTRY[kind](*row) if row is not None else None
            if key not in out or payload is not None:  # (two spellings of one id: the row wins)
                out[key] = payload
    return sorted(out.items())


async def proof_root(db: Any, height: int, exchange_root: Optional[bytes] = None) -> Optional[str]:
    """The proof root for the block at ``height`` (hex): the database tree's root — folding in
    every row changed since the last fold — combined with ``exchange_root``, the exchange tree's
    (qrdx/exchange/proofs.py; every caller that binds the root passes it). None if the feature
    is not in force at that height (the tree is still kept on a network that schedules it, so it
    is ready when it is)."""
    from . import chain_spec

    if not scheduled():
        return None
    conn = db.connection
    async with _lock(conn):
        cur = await conn.execute("SELECT version, root FROM smt_meta WHERE id = 1")
        meta = await cur.fetchone()
        if meta is None:
            await install(conn)
            cur = await conn.execute("SELECT version, root FROM smt_meta WHERE id = 1")
            meta = await cur.fetchone()
        version, root_ref = int(meta[0]), smt.Ref.decode(bytes(meta[1]))[0]
        cur = await conn.execute("SELECT DISTINCT kind, ident FROM smt_dirty ORDER BY kind, ident")
        dirty = [(str(k), str(i)) for k, i in await cur.fetchall()]
        if dirty:
            version = max(version, _versions.get(conn, 0)) + 1
            _versions[conn] = version
            load, cache = _loader(conn)
            tree = smt.Tree(load, version)
            root_ref = await tree.update(root_ref, await _changes(conn, dirty))
            await conn.executemany(
                "INSERT OR REPLACE INTO smt_nodes (nkey, data) VALUES (?, ?)",
                list(tree.writes.items()),
            )
            await conn.executemany(
                "INSERT INTO smt_stale (version, nkey) VALUES (?, ?)",
                [(version, k) for k in tree.stale],
            )
            cache.update(tree.writes)
            await conn.execute(
                "UPDATE smt_meta SET version = ?, root = ? WHERE id = 1",
                (version, smt.encode_ref(root_ref)),
            )
            await conn.execute("DELETE FROM smt_dirty")
        await conn.execute(
            "INSERT OR REPLACE INTO smt_roots (height, version, root) VALUES (?, ?, ?)",
            (int(height), version, smt.encode_ref(root_ref)),
        )
        if int(height) % PRUNE_EVERY == 0:
            await _prune(conn, int(height) - RETENTION_BLOCKS)
    if not chain_spec.is_active(FEATURE, int(height)):
        return None
    return smt.combine(smt.root_hash(root_ref), exchange_root or smt.EMPTY).hex()


async def database_root(db: Any, height: int) -> Optional[str]:
    """The database tree's root recorded for ``height`` (hex)."""
    cur = await db.connection.execute("SELECT root FROM smt_roots WHERE height = ?", (int(height),))
    row = await cur.fetchone()
    return smt.root_hash(smt.Ref.decode(bytes(row[0]))[0]).hex() if row else None


async def _prune(conn: Any, below_height: int) -> None:
    """Forget heights below ``below_height`` and the nodes only they reached."""
    if below_height <= 0:
        return
    await conn.execute("DELETE FROM smt_roots WHERE height < ?", (below_height,))
    await conn.execute("DELETE FROM state_root_parts WHERE height < ?", (below_height,))
    cur = await conn.execute("SELECT MIN(version) FROM smt_roots")
    row = await cur.fetchone()
    if row is None or row[0] is None:
        return
    oldest = int(row[0])  # a node replaced at or before it is reached by no retained root
    await conn.execute(
        "DELETE FROM smt_nodes WHERE nkey IN (SELECT nkey FROM smt_stale WHERE version <= ?)",
        (oldest,),
    )
    await conn.execute("DELETE FROM smt_stale WHERE version <= ?", (oldest,))


async def record_parts(db: Any, height: int, parts: Dict[str, Optional[str]]) -> None:
    """Remember the domain roots block ``height``'s unified root was made of (for proofs)."""
    if not scheduled():
        return
    await db.connection.execute(
        "INSERT OR REPLACE INTO state_root_parts "
        "(height, utxo, account, exchange, token, proof, dtree, xtree) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            int(height),
            parts.get("utxo"),
            parts.get("account"),
            parts.get("exchange"),
            parts.get("token"),
            parts.get("proof"),
            await database_root(db, height),
            parts.get("xtree"),
        ),
    )


async def recorded(db: Any, height: Optional[int] = None) -> Dict[str, Any]:
    """The roots recorded for ``height`` (default: the newest provable one): the four domain
    roots, the two trees' and the proof root."""
    conn = db.connection
    if height is None:
        cur = await conn.execute(
            "SELECT MAX(r.height) FROM smt_roots r JOIN state_root_parts p USING (height)"
        )
        row = await cur.fetchone()
        if row is None or row[0] is None:
            raise ValueError("no provable height recorded yet")
        height = int(row[0])
    cur = await conn.execute(
        "SELECT r.root, p.utxo, p.account, p.exchange, p.token, p.proof, p.dtree, p.xtree "
        "FROM smt_roots r JOIN state_root_parts p USING (height) WHERE height = ?",
        (int(height),),
    )
    row = await cur.fetchone()
    if row is None:
        raise ValueError(
            f"no proof root recorded for height {height} (pruned, or not computed here)"
        )
    return {
        "height": int(height),
        "ref": smt.Ref.decode(bytes(row[0]))[0],
        "roots": {"utxo": row[1], "account": row[2], "exchange": row[3], "token": row[4]},
        "proof_root": row[5],
        "database_tree_root": row[6],
        "exchange_tree_root": row[7] or smt.EMPTY.hex(),
    }


async def undo_above(db: Any, tip_height: int) -> None:
    """After a rollback to ``tip_height``: the orphaned heights' roots are forgotten. (The tree
    itself needs nothing: the rows the rollback rewrote are marked, and fold in next.)"""
    if not scheduled():
        return
    conn = db.connection
    await conn.execute("DELETE FROM smt_roots WHERE height > ?", (int(tip_height),))
    await conn.execute("DELETE FROM state_root_parts WHERE height > ?", (int(tip_height),))


# ── proofs ───────────────────────────────────────────────────────────────────────────────


async def prove(db: Any, kind: str, *ident: Any, height: Optional[int] = None) -> Dict[str, Any]:
    """A proof of one entry at ``height`` (default: the newest height with a recorded root):
    the entry (or its absence), the tree path, the proof root and the other domain roots — all
    a verifier needs to reach the block's signed state root (``verify_against``)."""
    conn = db.connection
    rec = await recorded(db, height)
    ident_bytes = identity(kind, *ident)
    key = smt.key_of(ident_bytes)
    load, _cache = _loader(conn)
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
        r["utxo"] or "0" * 64, r["account"], r["exchange"], r["token"], proof_root
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
