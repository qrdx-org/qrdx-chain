"""
Checkpoint sync: join the network from a snapshot of another node's database, verified, instead
of replaying from genesis (docs/CHECKPOINT_SYNC.md).

A snapshot server is anyone. Nothing in a snapshot is believed until it is checked against what
the restoring node already trusts — its chain spec and genesis file, and a trusted checkpoint
(weak subjectivity: qrdx/checkpoints.py, or one the operator gives):

1. **Genesis.** The node builds its network's genesis itself, in a scratch database, from its
   genesis file. The snapshot's block 0 must be that block, and the tables genesis writes
   (the system wallets, the genesis validator record) are taken from the scratch database.
2. **History.** Every block from genesis to the trusted checkpoint must hash to its signed
   header (``reconstruct_signing_root``) and link to its parent; the trusted checkpoint's hash
   then vouches for each of them. Hashing only: nothing is executed. Each block's body must
   hash to the ``body_root`` its header signs — except a block the snapshotting node pruned
   (qrdx/history_pruning.py), allowed only below the last few epochs before the exchange
   checkpoint, whose votes the next validator-set transitions read.
3. **State.** The snapshot holds the database at its tip T and the exchange's checkpoint at a
   finalized height C ≤ the trusted checkpoint (the node persists one every 1,024 finalized
   blocks). The database is stepped back to C through its undo journal, and every root is
   recomputed from the rows — the LtHash accumulators, the state-proof tree, the exchange's
   commitments from scratch, the validators' state — and combined. The result must be the
   unified state root block C signs. Every cache a root could be read from (accumulators,
   trees, digests, stored log roots) is discarded first, so a server cannot make the rows and
   their commitments disagree. The validator states the snapshot stored may serve as the base
   ``S_E`` is computed from — its hash is checked all the same — and only the verified one is
   kept.
4. **The rest.** Blocks above C are removed (the node syncs them from peers, verifying them as
   any import). The tables that are a function of history (the chain index: slots, RANDAO
   mixes, votes, offenders) are rebuilt from the verified blocks; node-local ones (peers,
   pending transactions, the undo journal, transaction and trading history) start empty.

**The exchange checkpoint is not unpickled.** The node persists it with pickle, which runs code
named in the data. A snapshot's copy is read by an unpickler that resolves only the classes and
encoder functions an exchange state is made of (``SAFE_GLOBALS``) and refuses anything else, and
the state it yields is then checked against the signed root like the rest.

What a snapshot cannot prove, it cannot change: a field the root does not commit to (a display
counter, a cache) that a server altered either makes the restored node compute different roots
for the next blocks — it stops following the chain, it is not deceived — or is rebuilt here.
"""

from __future__ import annotations

import json
import os
import pickle
import shutil
import sqlite3
import zlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from .logger import get_logger

logger = get_logger(__name__)

MANIFEST = "manifest.json"
DATABASE = "qrdx.db"
FORMAT = 1


class SnapshotError(Exception):
    """A snapshot that cannot be created, or that does not verify. Nothing was restored."""


# ── reading the exchange checkpoint without running code ─────────────────────────────────

# Exactly what an exchange state is pickled from: its classes and the encoder functions its
# committed collections hold by reference. A pickle can call any callable it names, so each
# entry is a plain data class or a pure function. tests/test_snapshot.py checks a populated
# state needs nothing else; a global outside this set refuses the snapshot.
SAFE_GLOBALS: frozenset = frozenset(
    {
        ("builtins", "set"),
        ("builtins", "frozenset"),
        ("builtins", "bytearray"),
        ("collections", "OrderedDict"),
        ("collections", "defaultdict"),
        ("collections", "deque"),
        ("decimal", "Decimal"),
        ("copyreg", "_reconstructor"),
        ("builtins", "object"),
        ("builtins", "dict"),
        ("builtins", "list"),
    }
)
# Modules whose own classes, and own ``_encode_*`` / ``_rebuild_*`` / ``encode_*`` functions,
# an exchange state is made of. Resolved only as attributes defined in that very module, never
# a dotted path (``Class.method``) or an imported name.
SAFE_MODULES: frozenset = frozenset(
    {
        "qrdx.exchange.amm",
        "qrdx.exchange.authority",
        "qrdx.exchange.bridge",
        "qrdx.exchange.clearinghouse",
        "qrdx.exchange.commitment",
        "qrdx.exchange.governance",
        "qrdx.exchange.handlers.common",
        "qrdx.exchange.nfts",
        "qrdx.exchange.oracle",
        "qrdx.exchange.orderbook",
        "qrdx.exchange.qns",
        "qrdx.exchange.router",
        "qrdx.exchange.state_manager",
        "qrdx.exchange.tokens",
        "qrdx.exchange.trading",
        "qrdx.exchange.transactions",
    }
)
_SAFE_FUNCTION_PREFIXES = ("_encode_", "_rebuild_", "encode_")
# Classes in those modules whose construction does more than hold data.
_UNSAFE_CLASSES = frozenset({"ExchangeStateManager"})


def _safe_global(module: str, name: str) -> Any:
    import importlib
    import inspect

    if (module, name) in SAFE_GLOBALS:
        return getattr(importlib.import_module(module), name)
    if module not in SAFE_MODULES or "." in name or name in _UNSAFE_CLASSES:
        raise SnapshotError(f"the exchange checkpoint names {module}.{name}: refused")
    try:
        obj = getattr(importlib.import_module(module), name)
    except (ImportError, AttributeError):
        raise SnapshotError(f"the exchange checkpoint names {module}.{name}: unknown") from None
    # An imported name must be defined in a safe module too. (state_manager.py re-exports the
    # helpers of handlers/common.py, where they moved: a checkpoint made before names them there.)
    if getattr(obj, "__module__", None) not in SAFE_MODULES:
        raise SnapshotError(f"the exchange checkpoint names {module}.{name}: refused")
    if inspect.isclass(obj):
        return obj
    if inspect.isfunction(obj) and name.startswith(_SAFE_FUNCTION_PREFIXES):
        return obj
    raise SnapshotError(f"the exchange checkpoint names {module}.{name}: refused")


class _Unpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> Any:
        return _safe_global(module, name)


def safe_loads(blob: bytes) -> Any:
    """Unpickle data a stranger wrote, resolving only ``_safe_global`` names."""
    import io

    try:
        return _Unpickler(io.BytesIO(blob)).load()
    except SnapshotError:
        raise
    except Exception as e:
        raise SnapshotError(f"the exchange checkpoint does not decode: {e}") from e


def pickled_globals(blob: bytes) -> Set[Tuple[str, str]]:
    """Every global a pickle THIS NODE wrote resolves (tooling and tests: it loads the data
    normally, so never call it on a stranger's)."""
    import io

    seen: Set[Tuple[str, str]] = set()

    class Recorder(pickle.Unpickler):
        def find_class(self, module: str, name: str) -> Any:
            seen.add((module, name))
            return super().find_class(module, name)

    Recorder(io.BytesIO(blob)).load()
    return seen


# ── creating ─────────────────────────────────────────────────────────────────────────────


def _backup(source: str, dest: str) -> None:
    """A consistent copy of a (possibly running) node's database: SQLite's online backup."""
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    try:
        out = sqlite3.connect(dest)
        try:
            src.backup(out)
        finally:
            out.close()
    finally:
        src.close()


def _exchange_checkpoint(conn: sqlite3.Connection) -> Tuple[int, str, bytes]:
    try:
        row = conn.execute(
            "SELECT height, block_hash, state FROM exchange_checkpoint WHERE id = 1"
        ).fetchone()
    except sqlite3.Error:
        row = None
    if row is None:
        raise SnapshotError(
            "the database holds no exchange checkpoint yet (one is persisted every 1,024 "
            "finalized blocks)"
        )
    return int(row[0]), str(row[1]), bytes(row[2])


def _sha256(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, out_dir: str, progress: Callable[[str], None] = print) -> Dict[str, Any]:
    """Download a snapshot directory that any HTTP server publishes (``manifest.json`` and
    ``qrdx.db`` under ``url``), resuming a partial download. The manifest's checksum catches a
    broken transfer early; it vouches for nothing — ``restore`` verifies the snapshot itself."""
    import urllib.request

    base = url.rstrip("/") + "/"
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(base + MANIFEST, timeout=60) as r:
        manifest = json.loads(r.read(1 << 20))
    total = int(manifest["bytes"])
    part = out / (DATABASE + ".part")
    have = part.stat().st_size if part.exists() else 0
    while have < total:
        request = urllib.request.Request(base + DATABASE, headers={"Range": f"bytes={have}-"})
        with urllib.request.urlopen(request, timeout=60) as r, open(part, "ab") as f:
            if have and r.status != 206:  # (the server ignored the range: start over)
                f.truncate(0)
                have = 0
            for chunk in iter(lambda: r.read(1 << 20), b""):
                f.write(chunk)
                have += len(chunk)
                if have % (64 << 20) < len(chunk):
                    progress(f"{have >> 20} / {total >> 20} MB")
    if have != total or _sha256(str(part)) != manifest.get("sha256"):
        part.unlink()
        raise SnapshotError("the download does not match the manifest: fetch it again")
    part.rename(out / DATABASE)
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def discover(peers: Sequence[str], timeout: float = 10.0) -> Tuple[str, Dict[str, Any]]:
    """The newest snapshot the given nodes publish (``/snapshot/``, qrdx/snapshot_publisher.py):
    (its URL, its manifest), by exchange checkpoint height. Nodes that publish none, or do not
    answer, are skipped. Where it comes from does not matter: ``restore`` verifies it."""
    import urllib.request

    best: Optional[Tuple[str, Dict[str, Any]]] = None
    for peer in peers:
        url = peer.rstrip("/") + "/snapshot/"
        try:
            with urllib.request.urlopen(url + MANIFEST, timeout=timeout) as r:
                manifest = json.loads(r.read(1 << 20))
            height = int(manifest["checkpoint"]["height"])
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if best is None or height > int(best[1]["checkpoint"]["height"]):
            best = (url, manifest)
    if best is None:
        raise SnapshotError("none of these nodes publishes a snapshot")
    return best


def create(source_db: str, out_dir: str, public: bool = False) -> Dict[str, Any]:
    """Write a snapshot of ``source_db`` (a node's database, running or not) to ``out_dir``:
    the database and a manifest. Nothing in the manifest is trusted by a restore; it says what
    the snapshot claims, for the operator choosing one.

    ``public``: for publishing. Leave out every table a restore discards (``_discarded``) — the
    node's own (its peers, pending transactions, indexes and display copies) and what a restore
    recomputes or rebuilds — overwritten, not only unlinked, and compact the file."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=False)
    db_path = str(out / DATABASE)
    _backup(source_db, db_path)
    conn = sqlite3.connect(db_path)
    try:
        if public:
            conn.execute("PRAGMA journal_mode = DELETE")
            conn.execute("PRAGMA secure_delete = ON")
            for table in _discarded(_tables(conn)):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()
            conn.execute("VACUUM")
        height, block_hash, _state = _exchange_checkpoint(conn)
        tip = conn.execute("SELECT MAX(block_height) FROM blocks").fetchone()[0]
        genesis = conn.execute("SELECT block_hash FROM blocks WHERE block_height = 0").fetchone()
    finally:
        conn.close()
    manifest = {
        "format": FORMAT,
        "tip": int(tip),
        "checkpoint": {"height": height, "block_hash": block_hash},
        "genesis_hash": genesis[0] if genesis else None,
        "bytes": os.path.getsize(db_path),
        "sha256": _sha256(db_path),
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


# ── restoring ────────────────────────────────────────────────────────────────────────────

# Recomputed from the rows here, never read from a snapshot.
_RECOMPUTED = (
    "state_commitment",
    "smt_meta",
    "smt_nodes",
    "smt_stale",
    "smt_roots",
    "smt_dirty",
    "state_root_parts",
    "validator_log_roots",
)
# Rebuilt from the verified blocks.
_REBUILT = (
    "chain_index",
    "chain_index_votes",
    "chain_index_offenders",
    "chain_index_ffg",
    "chain_index_meta",
)
# This node's own, not the server's.
_LOCAL = (
    "peers",
    "pending_transactions",
    "pending_spent_outputs",
    "pending_exchange_transactions",
    "signed_blocks",
    "signed_votes",
    "watermarks",
    "attestation_votes",
    "slashing_events",
    "epochs",
    "validators",
    "contract_logs",
    "contract_transactions",
)


def _tables(conn: sqlite3.Connection) -> Set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _discarded(present: Set[str]) -> List[str]:
    """The tables of ``present`` a restore empties: recomputed, rebuilt, or the node's own
    (its transaction index and trading history included)."""
    named = [t for t in _RECOMPUTED + _REBUILT + _LOCAL if t in present]
    return named + sorted(
        t for t in present if t.startswith(("tx_index", "tx_participants", "hist_"))
    )


def _wipe(path: str) -> None:
    conn = sqlite3.connect(path)
    try:
        for table in _discarded(_tables(conn)):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    finally:
        conn.close()


async def _genesis(db: Any, genesis_file: Optional[str], scratch: str) -> str:
    """Build the network's genesis in a scratch database; the snapshot's block 0 must be it.
    Takes what genesis writes (the system wallets, the chain metadata) from the scratch
    database. Returns the genesis hash."""
    from . import chain_spec
    from .database_sqlite import DatabaseSQLite
    from .validator.genesis_init import initialize_genesis_if_needed

    spec = chain_spec.active()
    if genesis_file is None and not spec.dev:
        raise SnapshotError(f"{spec.network} needs its genesis file to verify a snapshot")
    ref = await DatabaseSQLite.create(scratch)
    try:
        await initialize_genesis_if_needed(ref, genesis_file=genesis_file, chain_spec=spec)
        want = await ref.get_block_by_id(0)
        cur = await ref.connection.execute("SELECT key, value FROM chain_metadata")
        metadata = [tuple(r) for r in await cur.fetchall()]
        cur = await ref.connection.execute("SELECT * FROM system_wallets ORDER BY address")
        wallets = [tuple(r) for r in await cur.fetchall()]
        cols = [d[0] for d in cur.description] if cur.description else []
        # Block 0's records (the allocations, system wallets and predeployed contracts) are what
        # every rebuild seeds the state from: this network's, never the server's.
        cur = await ref.connection.execute(
            "SELECT * FROM transactions WHERE block_hash = ? ORDER BY tx_hash", (want["hash"],)
        )
        records = [tuple(r) for r in await cur.fetchall()]
        record_cols = [d[0] for d in cur.description] if cur.description else []
    finally:
        await ref.connection.close()
    have = await db.get_block_by_id(0)
    if not have or not want or have["hash"] != want["hash"]:
        raise SnapshotError(
            f"the snapshot's genesis ({(have or {}).get('hash', '?')[:16]}…) is not this "
            f"network's ({(want or {}).get('hash', '?')[:16]}…)"
        )
    # The chain's metadata is this node's own: what genesis records (the scratch database's),
    # nothing the server recorded (its finality, its passed forks). Its journal floor stays for
    # the step back to the checkpoint (were it false, the step back would be inexact, and the
    # roots would not match); the restore then sets its own.
    conn = db.connection
    await conn.execute("DELETE FROM chain_metadata WHERE key != 'undo_floor'")
    await conn.executemany(
        "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES (?, ?)",
        [(k, v) for k, v in metadata if k != "undo_floor"],
    )
    await conn.execute("DELETE FROM system_wallets")
    if wallets:
        marks = ", ".join("?" * len(cols))
        await conn.executemany(
            f"INSERT INTO system_wallets ({', '.join(cols)}) VALUES ({marks})", wallets
        )
    await conn.execute("DELETE FROM transactions WHERE block_hash = ?", (want["hash"],))
    if records:
        marks = ", ".join("?" * len(record_cols))
        await conn.executemany(
            f"INSERT INTO transactions ({', '.join(record_cols)}) VALUES ({marks})", records
        )
    return str(want["hash"])


async def _verify_code(db: Any) -> None:
    """Every contract's code is the code its hash names. The root commits to each account's
    code hash, not to the code table, which is keyed by that hash: a server could have put other
    code under a contract's hash, which this node would then run and answer calls with."""
    from eth_utils import keccak

    cur = await db.connection.execute("SELECT code_hash, bytecode FROM contract_code")
    for code_hash, bytecode in await cur.fetchall():
        code = (
            bytes(bytecode)
            if isinstance(bytecode, (bytes, memoryview))
            else bytes.fromhex(str(bytecode).removeprefix("0x"))
        )
        if keccak(code).hex() != str(code_hash).lower().removeprefix("0x"):
            raise SnapshotError(
                f"contract code stored under {str(code_hash)[:16]}… is not that code"
            )


async def _verify_history(
    db: Any, genesis_hash: str, top: int, bodies_from: int, progress: Callable[[str], None]
) -> None:
    """Every block 1..``top`` is the block its hash names, and the chain links to genesis. From
    ``bodies_from`` on, each must also carry the body its header signs: a block below it may be
    pruned (qrdx/history_pruning.py) — its header still hashes, its votes and sections are not
    vouched for, and nothing verified here depends on them."""
    from .validator.block_verification import (
        _parse_block_content,
        block_integrity_error,
        reconstruct_signing_root,
    )

    parent = genesis_hash
    for height in range(1, top + 1):
        block = await db.get_block_by_id(height)
        if block is None:
            raise SnapshotError(f"the snapshot has no block at height {height}")
        try:
            bc = _parse_block_content(block.get("content"))
        except Exception as e:
            raise SnapshotError(f"block {height} does not decode: {e}") from e
        if bc.get("pruned"):
            if height >= bodies_from:
                raise SnapshotError(
                    f"block {height} is pruned, but the restore needs bodies from block "
                    f"{bodies_from} (snapshot a node that keeps a longer history window)"
                )
            try:
                ok = reconstruct_signing_root(bc).hex() == str(block["hash"]).lower()
            except Exception:
                ok = False
            if not ok:
                raise SnapshotError(f"block {height}: its header does not hash to its hash")
        else:
            exchange = await db.get_block_exchange_txs(block["hash"])
            evm = await db.get_block_evm_txs(block["hash"])
            why = block_integrity_error(bc, exchange or [], evm or [], block_hash=block["hash"])
            if why:
                raise SnapshotError(f"block {height}: {why}")
        if str(bc.get("parent_hash", "")).lower() != str(parent).lower():
            raise SnapshotError(f"block {height} does not link to block {height - 1}")
        parent = block["hash"]
        if height % 10_000 == 0:
            progress(f"history verified to block {height}")


async def restore(
    snapshot_dir: str,
    target_db: str,
    *,
    genesis_file: Optional[str],
    trusted: Dict[int, str],
    progress: Callable[[str], None] = lambda message: logger.info(message),
) -> Dict[str, Any]:
    """Verify the snapshot in ``snapshot_dir`` and, only if it holds, write the database a node
    starts from at ``target_db`` (which must not exist). ``trusted``: {height: block hash} of
    trusted checkpoints; one at or above the snapshot's exchange checkpoint must be on its chain.
    Returns what was restored."""
    from . import chain_index, state_proofs, undo_journal
    from .crypto.hashing import unified_state_root
    from .database_sqlite import DatabaseSQLite
    from .derived_state_rebuild import CHECKPOINTS, persist_checkpoint
    from .exchange.journal import ExchangeJournal
    from .exchange.state_manager import ExchangeStateManager
    from .validator import validator_root
    from .validator.block_verification import _parse_block_content
    from .validator.withdrawals import undo_withdrawal_logs_above

    source = str(Path(snapshot_dir) / DATABASE)
    if not os.path.exists(source):
        raise SnapshotError(f"no {DATABASE} in {snapshot_dir}")
    if os.path.exists(target_db):
        raise SnapshotError(f"{target_db} exists: restore into a new path")
    work = target_db + ".partial"
    scratch = target_db + ".genesis"
    for leftover in (work, scratch):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(leftover + suffix):
                os.remove(leftover + suffix)
    _backup(source, work)
    raw = sqlite3.connect(work)
    try:
        height, checkpoint_hash, state_blob = _exchange_checkpoint(raw)
    finally:
        raw.close()
    _wipe(work)

    db = await DatabaseSQLite.create(work)
    ok = False
    try:
        progress("genesis: building this network's own")
        genesis_hash = await _genesis(db, genesis_file, scratch)

        # The block whose signed root binds the state after block ``height``: the next one under
        # deferred execution (qrdx/post_state.py), which the trusted history must then reach.
        from . import post_state

        signer = height + 1 if post_state.active(height + 1) else height
        anchor = None
        for h in sorted(h for h in trusted if h >= signer):
            if (await db.get_block_hashes(h, h)).get(h, "").lower() == trusted[h].lower():
                anchor = h
                break
        if anchor is None:
            raise SnapshotError(
                f"no trusted checkpoint at or above the snapshot's exchange checkpoint "
                f"(block {height}) is on its chain: pass one (height:hash) from a source you trust"
            )
        from .constants import SLOTS_PER_EPOCH
        from .validator.ffg import INCLUSION_EPOCHS

        # The votes the next validator-set transitions read ride in the blocks of the last few
        # epochs below the checkpoint: those blocks must come with their signed bodies.
        bodies_from = max(1, height - (INCLUSION_EPOCHS + 2) * SLOTS_PER_EPOCH)
        progress(f"history: blocks 1..{anchor}, against trusted checkpoint {anchor}")
        await _verify_history(db, genesis_hash, anchor, bodies_from, progress)
        if (await db.get_block_hashes(height, height)).get(height) != checkpoint_hash:
            raise SnapshotError(f"the exchange checkpoint is not block {height} of this chain")
        signing = await db.get_block_by_id(signer)
        if not signing:
            raise SnapshotError(f"the snapshot lacks block {signer}, which signs its state")
        signed_root = _parse_block_content(signing["content"]).get("state_root")

        progress(f"state: stepping back to block {height}")
        if await undo_journal.rollback_to(db, height) is None:
            raise SnapshotError(
                f"the snapshot's undo journal does not reach back to block {height}"
            )
        await db.remove_blocks(height + 1)
        await db.undo_validator_deposits_above(height)
        await undo_withdrawal_logs_above(db, height)
        await state_proofs.undo_above(db, height)
        await chain_index.sync(db)

        block = await db.get_block_by_id(height)
        bc = _parse_block_content(block["content"])
        state = safe_loads(zlib.decompress(state_blob))
        if not isinstance(state, dict) or int(state.get("block_height", -1)) != height:
            raise SnapshotError(f"the exchange checkpoint is not the state after block {height}")
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        mgr._restore_snapshot(state)
        try:
            mgr.verify_commitments()  # every incremental commitment, from its entries
        except Exception as e:
            raise SnapshotError(
                f"the exchange state does not match its own commitments: {e}"
            ) from e

        progress(f"state: recomputing every root of block {height}")
        utxo = await db.get_unspent_outputs_hash(height)
        account = await db.get_account_state_root(height)
        token = await db.get_token_balances_root(height)
        exchange = mgr.compute_state_root()
        validators = None
        if validator_root.active(height):
            validator_root.clear_memo()
            validators = await validator_root.compute(db, height, int(bc["slot"]))
        proof = None
        if state_proofs.scheduled():
            xroot = mgr.exchange_proof_root(height)
            proof = await state_proofs.proof_root(db, height, xroot)
        computed = unified_state_root(utxo or "0" * 64, account, exchange, token, proof, validators)
        if computed != signed_root:
            raise SnapshotError(
                f"the snapshot's state is not the state block {signer} signs: computed "
                f"{computed[:16]}…, signed {str(signed_root)[:16]}…"
            )

        await _verify_code(db)

        progress("verified; preparing the node's database")
        # Of the validator states the snapshot stored, only the one just verified is kept (the
        # others were at most a base it was computed from, or unverified).
        from .validator import epoch_state

        set_epoch = int(bc["slot"]) // SLOTS_PER_EPOCH
        cp = await epoch_state._checkpoint(db, set_epoch, height - 1)
        await db.connection.execute(
            "DELETE FROM validator_epoch_states WHERE NOT (epoch = ? AND checkpoint = ?)",
            (set_epoch, cp[1] if cp else ""),
        )
        epoch_state._memo.pop(db, None)
        await undo_journal.reset(db)
        await undo_journal.set_floor(db, height)
        CHECKPOINTS.clear()
        CHECKPOINTS[height] = (checkpoint_hash, mgr.capture())
        mgr.journal = ExchangeJournal()
        await persist_checkpoint(db, height)
        await db.connection.execute(
            "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES (?, ?)",
            (
                "restored_from_snapshot",
                json.dumps({"height": height, "block_hash": checkpoint_hash, "anchor": anchor}),
            ),
        )
        await db.connection.commit()
        ok = True
        return {
            "height": height,
            "block_hash": checkpoint_hash,
            "state_root": computed,
            "trusted_checkpoint": anchor,
        }
    finally:
        await db.connection.close()
        CHECKPOINTS.clear()
        ExchangeStateManager.reset_instance()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(scratch + suffix):
                os.remove(scratch + suffix)
        if ok:
            shutil.move(work, target_db)
            for suffix in ("-wal", "-shm"):
                if os.path.exists(work + suffix):
                    os.remove(work + suffix)
        else:
            for suffix in ("", "-wal", "-shm"):
                if os.path.exists(work + suffix):
                    os.remove(work + suffix)
