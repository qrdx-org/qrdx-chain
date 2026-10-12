"""
Chain index — a compact, reorg-safe summary of every canonical block, so that no consensus
helper ever has to re-read the chain from genesis.

Several consensus helpers need a few facts about every historical block: its slot and epoch,
the running RANDAO mix, the stake operations and attestation votes it carries, and the
offenders its slashing evidence proves. They used to fetch and parse every block body from
genesis on each call — ``ast.literal_eval`` of a ~60 KB body per block, on the event loop — so
the cost of a call grew with the chain, and with it the time a validator needed per slot. On a
testnet that had produced 75,000 blocks the block time had drifted from 2 s to 14.5 s.

The index stores those facts once per block and is extended lazily: ``sync`` indexes only the
blocks added since its last call. It never trusts itself across a reorg. A block's hash commits
to its whole ancestry, so the index is valid exactly up to the highest height whose recorded
hash still matches the ``blocks`` table; ``sync`` finds that height (one comparison in the
common case, a binary search after a reorg), drops everything above it, and re-derives.

Index writes join the connection's current transaction (no commit of their own): a block that
is rolled back takes its index rows with it, and a block deleted by a rollback is caught by the
hash check on the next ``sync``.

Every derived value is what the original per-call walk computed (tests/test_chain_index.py
checks each against it, across reorgs).
"""

from __future__ import annotations

import asyncio
import weakref
from typing import Any, Dict, List, Optional, Tuple

from .logger import get_logger

logger = get_logger(__name__)

_SCHEMA = [
    "CREATE TABLE IF NOT EXISTS chain_index ("
    " height INTEGER PRIMARY KEY,"
    " block_hash TEXT NOT NULL,"
    " slot INTEGER,"
    " epoch INTEGER,"
    " randao_mix TEXT NOT NULL)",  # hex: the mix after folding this block's reveal
    "CREATE INDEX IF NOT EXISTS idx_chain_index_slot ON chain_index(slot)",
    "CREATE TABLE IF NOT EXISTS chain_index_votes ("
    " height INTEGER NOT NULL,"
    " carry_epoch INTEGER NOT NULL,"  # the epoch of the block carrying the vote
    " target_epoch INTEGER NOT NULL,"
    " validator TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_chain_index_votes_target"
    " ON chain_index_votes(target_epoch, validator, carry_epoch)",
    "CREATE INDEX IF NOT EXISTS idx_chain_index_votes_carry ON chain_index_votes(carry_epoch)",
    "CREATE INDEX IF NOT EXISTS idx_chain_index_votes_height ON chain_index_votes(height)",
    "CREATE TABLE IF NOT EXISTS chain_index_offenders ("
    " height INTEGER NOT NULL,"
    " offender TEXT NOT NULL)",  # lower-cased address a verified proof convicts
    "CREATE INDEX IF NOT EXISTS idx_chain_index_offenders ON chain_index_offenders(offender, height)",
    # The Casper FFG votes canonical blocks carry (qrdx/validator/ffg.py) — every field the
    # finality computation and the proposer's inclusion check need, so neither re-parses a body.
    "CREATE TABLE IF NOT EXISTS chain_index_ffg ("
    " height INTEGER NOT NULL,"
    " validator TEXT NOT NULL,"
    " source_epoch INTEGER NOT NULL,"
    " source_root TEXT NOT NULL,"
    " target_epoch INTEGER NOT NULL,"
    " target_root TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_chain_index_ffg_target"
    " ON chain_index_ffg(target_epoch, validator, height)",
    "CREATE INDEX IF NOT EXISTS idx_chain_index_ffg_height ON chain_index_ffg(height)",
    "CREATE TABLE IF NOT EXISTS chain_index_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
]

_TABLES = (
    "chain_index",
    "chain_index_votes",
    "chain_index_offenders",
    "chain_index_ffg",
)
# Bumped whenever what is derived per block changes: an index written by an older version is
# dropped and re-derived (it is derived data; the chain is the source).
_VERSION = "3"  # 3: no stake-op index (it could not tell an executed deposit from a refused one)
_BATCH = 256  # blocks read per query while catching up

_locks: "weakref.WeakKeyDictionary[Any, asyncio.Lock]" = weakref.WeakKeyDictionary()
_ready: "weakref.WeakKeyDictionary[Any, bool]" = weakref.WeakKeyDictionary()


def _lock_for(db: Any) -> asyncio.Lock:
    lock = _locks.get(db)
    if lock is None:
        lock = _locks[db] = asyncio.Lock()
    return lock


async def _ensure(db: Any) -> None:
    if _ready.get(db):
        return
    # One statement at a time: executescript() would COMMIT whatever the shared connection
    # has pending — another task's half-applied block, say.
    for sql in _SCHEMA:
        await db.connection.execute(sql)
    cur = await db.connection.execute("SELECT value FROM chain_index_meta WHERE key = 'version'")
    row = await cur.fetchone()
    if row is None or row[0] != _VERSION:
        for table in _TABLES:
            await db.connection.execute(f"DELETE FROM {table}")
        await db.connection.execute("DROP TABLE IF EXISTS chain_index_ops")  # retired in v3
        await db.connection.execute(
            "INSERT OR REPLACE INTO chain_index_meta (key, value) VALUES ('version', ?)",
            (_VERSION,),
        )
        if row is not None:
            logger.info("chain index: format changed (v%s → v%s) — re-deriving", row[0], _VERSION)
    _ready[db] = True


# ── deriving one block's facts ───────────────────────────────────────────────────────────


def _parse(content: Any) -> Optional[Dict[str, Any]]:
    from .validator.block_verification import _parse_block_content

    try:
        parsed = _parse_block_content(content)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _reveal(bc: Optional[Dict[str, Any]]) -> Optional[bytes]:
    """The proposer's RANDAO reveal, exactly as randao._extract_reveal reads it."""
    if bc is None:
        return None
    hexrev = bc.get("randao_reveal")
    if not hexrev:
        return None
    try:
        raw = bytes.fromhex(hexrev)
    except (ValueError, TypeError):
        return None
    return raw or None


def _votes(bc: Optional[Dict[str, Any]], carry_epoch: Optional[int]) -> List[Tuple[int, str]]:
    """(target_epoch, validator) for each attestation the block carries — the reward input of
    the validator set (validator/epoch_state.py)."""
    if bc is None or carry_epoch is None:
        return []
    from .validator.attestation_block import extract_attestations_from_dict

    try:
        return [
            (int(a.target_epoch), a.validator_address) for a in extract_attestations_from_dict(bc)
        ]
    except Exception:
        return []


def _ffg(bc: Optional[Dict[str, Any]]) -> List[Tuple[str, int, str, int, str]]:
    """(validator, source epoch, source root, target epoch, target root) for each FFG vote the
    block carries. (Import accepts a block only if every carried vote is valid for its chain —
    validator/ffg.py verify_block_votes — so these are trusted here.)"""
    if bc is None:
        return []
    from .validator.attestation_block import extract_attestations_from_dict

    try:
        return [
            (
                a.validator_address,
                int(a.source_epoch),
                a.source_root,
                int(a.target_epoch),
                a.target_root,
            )
            for a in extract_attestations_from_dict(bc)
            if a.target_root
        ]
    except Exception:
        return []


def _offenders(bc: Optional[Dict[str, Any]]) -> List[str]:
    """Validators a verified slashing proof in the block convicts (lower-cased)."""
    if bc is None or not bc.get("slashing_evidence"):
        return []
    from .validator.slashing_block import extract_slashing_evidence_from_dict, verified_offender

    found = []
    try:
        for ev in extract_slashing_evidence_from_dict(bc):
            offender = verified_offender(ev)
            if offender:
                found.append(offender.lower())
    except Exception:
        return found
    return found


async def _index_block(db: Any, height: int, block_hash: str, content: Any, mix: bytes) -> bytes:
    """Index one block on top of ``mix`` (the mix after its predecessor); returns its mix."""
    from .validator.block_verification import epoch_from_block
    from .validator.randao import _mix_in

    bc = _parse(content)
    slot: Optional[int] = None
    epoch: Optional[int] = None
    if bc is not None:
        try:
            slot = int(bc["slot"]) if bc.get("slot") is not None else None
        except (TypeError, ValueError):
            slot = None
        epoch = epoch_from_block(bc)
    reveal = _reveal(bc)
    if reveal is not None:
        mix = _mix_in(mix, reveal)
    conn = db.connection
    await conn.execute(
        "INSERT OR REPLACE INTO chain_index (height, block_hash, slot, epoch, randao_mix) "
        "VALUES (?, ?, ?, ?, ?)",
        (height, block_hash, slot, epoch, mix.hex()),
    )
    votes = _votes(bc, epoch)
    if votes:
        await conn.executemany(
            "INSERT INTO chain_index_votes (height, carry_epoch, target_epoch, validator) "
            "VALUES (?, ?, ?, ?)",
            [(height, epoch, te, v) for te, v in votes],
        )
    for offender in _offenders(bc):
        await conn.execute(
            "INSERT INTO chain_index_offenders (height, offender) VALUES (?, ?)", (height, offender)
        )
    ffg = _ffg(bc)
    if ffg:
        await conn.executemany(
            "INSERT INTO chain_index_ffg (height, validator, source_epoch, source_root, "
            "target_epoch, target_root) VALUES (?, ?, ?, ?, ?, ?)",
            [(height, *v) for v in ffg],
        )
    return mix


# ── keeping it in step with the chain ────────────────────────────────────────────────────


async def _chain_hash(db: Any, height: int) -> Optional[str]:
    cur = await db.connection.execute(
        "SELECT block_hash FROM blocks WHERE block_height = ?", (int(height),)
    )
    row = await cur.fetchone()
    return row[0] if row else None


async def _indexed_at_or_below(db: Any, height: int) -> Optional[Tuple[int, str, str]]:
    cur = await db.connection.execute(
        "SELECT height, block_hash, randao_mix FROM chain_index WHERE height <= ? "
        "ORDER BY height DESC LIMIT 1",
        (int(height),),
    )
    row = await cur.fetchone()
    return (int(row[0]), row[1], row[2]) if row else None


async def _valid_top(db: Any) -> int:
    """The highest indexed height still on the chain (-1 if none), dropping every row above
    it. Matching hashes form a prefix — a block's hash commits to its ancestry — so one
    comparison settles the usual case and a binary search finds the fork point after a
    reorg."""
    cur = await db.connection.execute("SELECT MAX(height) FROM chain_index")
    row = await cur.fetchone()
    top = row[0] if row else None
    if top is None:
        return -1
    entry = await _indexed_at_or_below(db, top)
    if entry and await _chain_hash(db, entry[0]) == entry[1]:
        return entry[0]
    lo, hi, good = 0, int(top) - 1, -1
    while lo <= hi:
        mid = (lo + hi) // 2
        entry = await _indexed_at_or_below(db, mid)
        if entry is None:
            break
        if await _chain_hash(db, entry[0]) == entry[1]:
            good = entry[0]
            lo = mid + 1
        else:
            hi = entry[0] - 1
    for table in _TABLES:
        await db.connection.execute(f"DELETE FROM {table} WHERE height > ?", (good,))
    logger.info("chain index: chain changed below the indexed tip — re-deriving above %d", good)
    return good


async def sync(db: Any, up_to: Optional[int] = None) -> int:
    """Index every block up to ``up_to`` (default: the tip). Returns the highest height the
    index now covers (-1 for an empty chain). Cheap when nothing is new."""
    async with _lock_for(db):
        await _ensure(db)
        tip = int(await db.get_next_block_id()) - 1
        target = tip if up_to is None else min(int(up_to), tip)
        top = await _valid_top(db)
        if top >= target:
            return top
        from .validator.randao import RANDAO_SEED

        below = await _indexed_at_or_below(db, top) if top >= 0 else None
        mix = bytes.fromhex(below[2]) if below else RANDAO_SEED
        start = top + 1
        while start <= target:
            end = min(target, start + _BATCH - 1)
            cur = await db.connection.execute(
                "SELECT block_height, block_hash, content FROM blocks "
                "WHERE block_height BETWEEN ? AND ? ORDER BY block_height",
                (start, end),
            )
            for height, block_hash, content in await cur.fetchall():
                mix = await _index_block(db, int(height), block_hash, content, mix)
            start = end + 1
            await asyncio.sleep(0)  # let the node run between batches while catching up
        return target


# ── what consumers ask ───────────────────────────────────────────────────────────────────


async def randao_mix(db: Any, up_to_height: int) -> bytes:
    """The RANDAO mix after folding every canonical block's reveal up to ``up_to_height``."""
    from .validator.randao import RANDAO_SEED

    if up_to_height < 0:
        return RANDAO_SEED
    await sync(db, up_to_height)
    entry = await _indexed_at_or_below(db, up_to_height)
    return bytes.fromhex(entry[2]) if entry else RANDAO_SEED


async def highest_height_before_slot(db: Any, slot: int) -> int:
    """The highest block height whose slot is < ``slot`` (-1 if none)."""
    await sync(db)
    cur = await db.connection.execute(
        "SELECT MAX(height) FROM chain_index WHERE slot IS NOT NULL AND slot < ?", (int(slot),)
    )
    row = await cur.fetchone()
    return int(row[0]) if row and row[0] is not None else -1


async def slashed_before(db: Any, address: str, before_height: int) -> bool:
    """True if a canonical block below ``before_height`` carries a verified slashing proof
    against ``address``."""
    await sync(db, int(before_height) - 1)
    cur = await db.connection.execute(
        "SELECT 1 FROM chain_index_offenders WHERE offender = ? AND height < ? LIMIT 1",
        (address.lower(), int(before_height)),
    )
    return (await cur.fetchone()) is not None


async def offenders_before(db: Any, before_height: int) -> List[str]:
    """Every address a canonical block below ``before_height`` convicts (lower-cased, sorted)."""
    await sync(db, int(before_height) - 1)
    cur = await db.connection.execute(
        "SELECT DISTINCT offender FROM chain_index_offenders WHERE height < ? ORDER BY offender",
        (int(before_height),),
    )
    return [r[0] for r in await cur.fetchall()]


# ── Casper FFG (validator/ffg.py) ────────────────────────────────────────────────────────


async def block_hash_at(db: Any, height: int) -> Optional[str]:
    await sync(db, height)
    cur = await db.connection.execute(
        "SELECT block_hash FROM chain_index WHERE height = ?", (int(height),)
    )
    row = await cur.fetchone()
    return row[0] if row else None


async def checkpoint(db: Any, epoch: int, slots_per_epoch: int) -> Optional[Tuple[int, str]]:
    """(height, hash) of epoch ``epoch``'s checkpoint on the canonical chain: the last block
    before the epoch's first slot — known by the time anyone votes in the epoch. Genesis for
    epoch 0 (and for any epoch before the first block). None while the chain is empty."""
    height = 0
    if epoch > 0:
        height = max(0, await highest_height_before_slot(db, int(epoch) * int(slots_per_epoch)))
    root = await block_hash_at(db, height)
    return (height, root) if root else None


async def ffg_votes(
    db: Any, from_target_epoch: int, up_to_height: Optional[int] = None
) -> List[Tuple[int, str, int, str, int, str]]:
    """Canonical FFG votes with target epoch ≥ ``from_target_epoch`` (carried at or below
    ``up_to_height``, default the tip), in chain order: (height, validator, source epoch,
    source root, target epoch, target root)."""
    await sync(db, up_to_height)
    sql = (
        "SELECT height, validator, source_epoch, source_root, target_epoch, target_root "
        "FROM chain_index_ffg WHERE target_epoch >= ?"
    )
    args: List[Any] = [int(from_target_epoch)]
    if up_to_height is not None:
        sql += " AND height <= ?"
        args.append(int(up_to_height))
    cur = await db.connection.execute(sql + " ORDER BY height, rowid", args)
    return [tuple(r) for r in await cur.fetchall()]  # type: ignore[misc]


async def height_before_slot_at_or_below(db: Any, slot: int, max_height: int) -> int:
    """The highest canonical height ≤ ``max_height`` whose slot is < ``slot`` (-1 if none)."""
    await sync(db, max_height)
    cur = await db.connection.execute(
        "SELECT MAX(height) FROM chain_index WHERE slot IS NOT NULL AND slot < ? AND height <= ?",
        (int(slot), int(max_height)),
    )
    row = await cur.fetchone()
    return int(row[0]) if row and row[0] is not None else -1


async def voted_targets(
    db: Any, from_target_epoch: int, up_to_height: Optional[int] = None
) -> Dict[Tuple[str, int], Tuple[int, str, int, str]]:
    """{(validator, target epoch): its first canonical FFG vote} for targets ≥
    ``from_target_epoch`` carried at or below ``up_to_height`` (default: the tip)."""
    await sync(db, up_to_height)
    sql = (
        "SELECT validator, target_epoch, source_epoch, source_root, target_root FROM "
        "chain_index_ffg WHERE target_epoch >= ?"
    )
    args: List[Any] = [int(from_target_epoch)]
    if up_to_height is not None:
        sql += " AND height <= ?"
        args.append(int(up_to_height))
    cur = await db.connection.execute(sql + " ORDER BY height, rowid", args)
    out: Dict[Tuple[str, int], Tuple[int, str, int, str]] = {}
    for validator, te, se, sr, tr in await cur.fetchall():
        out.setdefault((validator, int(te)), (int(se), sr, int(te), tr))
    return out


async def validator_public_key(db: Any, address: str, before_height: int) -> Optional[bytes]:
    """The public key of ``address`` as the canonical chain records it below ``before_height``:
    the genesis validator set, or an executed STAKE_DEPOSIT by the address (the
    ``validator_deposits`` log block application writes) — only a key that derives to the
    address counts (a deposit does not otherwise prove the key is the sender's). The same
    answer on every node holding the same chain."""
    from .crypto.pq.dilithium import PQPublicKey

    def owns(key_hex: Any) -> Optional[bytes]:
        try:
            raw = bytes.fromhex(str(key_hex))
            return raw if PQPublicKey.from_bytes(raw).to_address() == address else None
        except Exception:
            return None

    try:
        for v in await db.get_genesis_validators():
            if v.get("address") == address:
                key = owns(v.get("public_key"))
                if key:
                    return key
    except Exception:
        pass
    try:
        cur = await db.connection.execute(
            "SELECT public_key FROM validator_deposits WHERE address = ? AND block_height < ? "
            "ORDER BY block_height, id",
            (address, int(before_height)),
        )
        rows = await cur.fetchall()
    except Exception:
        return None  # no deposit log (a database without validators)
    for (key_hex,) in rows:
        key = owns(key_hex)
        if key:
            return key
    return None


async def slot_at(db: Any, height: int) -> Optional[int]:
    """The slot of the canonical block at ``height`` (None if unknown)."""
    await sync(db, height)
    cur = await db.connection.execute(
        "SELECT slot FROM chain_index WHERE height = ?", (int(height),)
    )
    row = await cur.fetchone()
    return int(row[0]) if row and row[0] is not None else None
