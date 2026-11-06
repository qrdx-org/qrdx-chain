"""
Slashing protection: a validator never signs two different blocks for one slot, nor two
conflicting FFG votes (two different attestations for one target epoch, or one whose source and
target surround another's). Not across restarts, not after its chain database is resynced, and
not after it moves to another machine with its record.

The record is an SQLite file of its own (``QRDX_SLASHING_PROTECTION_DB``; by default next to the
chain database, never inside it). Each signature is recorded before it exists, in the same
transaction that checks it, and that transaction is durable before the signing starts. A crash
between the two loses a slot, never protection. One process holds the record at a time, through
an exclusive lock on ``<record>.lock``.

The record moves between machines with the key, in EIP-3076's interchange format (with QRDX
addresses in the ``pubkey`` field): ``scripts/validator/slashing_protection.py``. Like EIP-3076,
an import raises low watermarks. Nothing at or below an imported slot or target epoch is signed
again, and no vote whose source is below an imported source, so a partial history cannot hide an
older signature. Pruning old rows raises the same watermarks.

Rows are kept per network (the network's block signing domain, which binds the chain id and the
genesis). Signatures carry their network's domain, so what a key signed on another network is not
slashable here.

What a record cannot stop is the same key signing on two machines that each keep their own. The
doppelganger check covers that (qrdx/validator/node_integration.py): after starting, a validator
listens before it signs, and stops if the chain shows its key signing something its record does
not hold.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..logger import get_logger
from .keystore import ValidatorKeyError

logger = get_logger(__name__)

PATH_ENV = "QRDX_SLASHING_PROTECTION_DB"
INTERCHANGE_VERSION = "5"
# Rows older than this (in slots / epochs) behind the newest are pruned into the watermarks.
KEEP_SLOTS = 1 << 20
KEEP_EPOCHS = 1 << 14
_PRUNE_EVERY = 4096

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS signed_blocks ("
    " network TEXT NOT NULL, validator TEXT NOT NULL, slot INTEGER NOT NULL,"
    " signing_root TEXT NOT NULL, PRIMARY KEY (network, validator, slot))",
    "CREATE TABLE IF NOT EXISTS signed_votes ("
    " network TEXT NOT NULL, validator TEXT NOT NULL, source_epoch INTEGER NOT NULL,"
    " target_epoch INTEGER NOT NULL, signing_root TEXT NOT NULL,"
    " PRIMARY KEY (network, validator, target_epoch))",
    "CREATE INDEX IF NOT EXISTS idx_signed_votes_source"
    " ON signed_votes (network, validator, source_epoch)",
    # Nothing at or below these is signed again (imports and pruning raise them). -1: none.
    "CREATE TABLE IF NOT EXISTS watermarks ("
    " network TEXT NOT NULL, validator TEXT NOT NULL,"
    " block_slot INTEGER NOT NULL DEFAULT -1, source_epoch INTEGER NOT NULL DEFAULT -1,"
    " target_epoch INTEGER NOT NULL DEFAULT -1, PRIMARY KEY (network, validator))",
)


class ProtectionStoreError(ValidatorKeyError):
    """The record cannot be used safely; the validator must not sign."""


def network_key(spec: Any = None) -> str:
    """The network a record's rows belong to: its block signing domain (chain id + genesis)."""
    from .. import constants  # noqa: F401  (installs this process's chain spec)
    from ..chain_spec import signing_domain

    return signing_domain("block", spec).hex()


def default_path() -> str:
    """``QRDX_SLASHING_PROTECTION_DB``, else ``<chain database>.slashing-protection.sqlite``."""
    explicit = os.environ.get(PATH_ENV)
    if explicit:
        return explicit
    from ..constants import DENARO_DATABASE_PATH

    base = str(DENARO_DATABASE_PATH) if DENARO_DATABASE_PATH else "data/qrdx.db"
    return os.path.splitext(base)[0] + ".slashing-protection.sqlite"


def _root(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    text = str(value or "").lower()
    return text[2:] if text.startswith("0x") else text


class SlashingProtection:
    """The validator's signing record (see the module docstring). Open with :meth:`open`."""

    def __init__(self, path: str, network: str) -> None:
        self.path = path
        self.network = network
        self._conn: Any = None
        self._lock_file: Any = None
        self._mutex = asyncio.Lock()
        self._writes = 0

    # ── lifecycle ─────────────────────────────────────────────────────────────

    @classmethod
    async def open(cls, path: str, network: str) -> "SlashingProtection":
        import aiosqlite

        self = cls(path, network)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        lock_path = path + ".lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise ProtectionStoreError(
                f"another process holds the slashing-protection record {path}: two processes "
                "signing with one key get it slashed"
            ) from exc
        self._lock_file = fd
        try:
            self._conn = await aiosqlite.connect(path, isolation_level=None)
            await self._conn.execute("PRAGMA journal_mode=WAL")
            await self._conn.execute("PRAGMA synchronous=FULL")
            for statement in _SCHEMA:
                await self._conn.execute(statement)
            os.chmod(path, 0o600)
        except Exception:
            await self.close()
            raise
        return self

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
        if self._lock_file is not None:
            try:
                fcntl.flock(self._lock_file, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_file)
                self._lock_file = None

    # ── queries ───────────────────────────────────────────────────────────────

    async def _one(self, sql: str, args: Tuple[Any, ...]) -> Optional[Tuple[Any, ...]]:
        cur = await self._conn.execute(sql, args)
        return await cur.fetchone()

    async def _watermarks(self, validator: str) -> Tuple[int, int, int]:
        row = await self._one(
            "SELECT block_slot, source_epoch, target_epoch FROM watermarks"
            " WHERE network = ? AND validator = ?",
            (self.network, validator),
        )
        return (int(row[0]), int(row[1]), int(row[2])) if row else (-1, -1, -1)

    async def _block_refusal(self, validator: str, slot: int, root: Optional[str]) -> Optional[str]:
        row = await self._one(
            "SELECT signing_root FROM signed_blocks WHERE network = ? AND validator = ? AND slot = ?",
            (self.network, validator, slot),
        )
        if row is not None:
            if root is not None and row[0] == root:
                return None  # the same block again
            return f"already signed a block at slot {slot}"
        floor, _s, _t = await self._watermarks(validator)
        if slot <= floor:
            return f"slot {slot} is at or below the record's watermark {floor}"
        return None

    async def _vote_refusal(
        self, validator: str, source: int, target: int, root: Optional[str]
    ) -> Optional[str]:
        if source > target:
            return f"source epoch {source} is after target epoch {target}"
        row = await self._one(
            "SELECT signing_root FROM signed_votes"
            " WHERE network = ? AND validator = ? AND target_epoch = ?",
            (self.network, validator, target),
        )
        if row is not None:
            if root is not None and row[0] == root:
                return None  # the same attestation again
            return f"already voted for target epoch {target}"
        surround = await self._one(
            "SELECT source_epoch, target_epoch FROM signed_votes WHERE network = ? AND validator = ?"
            " AND ((source_epoch < ? AND target_epoch > ?) OR (source_epoch > ? AND target_epoch < ?))"
            " LIMIT 1",
            (self.network, validator, source, target, source, target),
        )
        if surround is not None:
            return f"{source}->{target} and the recorded {surround[0]}->{surround[1]} surround"
        _b, floor_source, floor_target = await self._watermarks(validator)
        if source < floor_source or target <= floor_target:
            return (
                f"{source}->{target} is below the record's watermarks "
                f"(source {floor_source}, target {floor_target})"
            )
        return None

    async def may_sign_block(self, validator: str, slot: int) -> bool:
        """Whether a block at ``slot`` could be signed (a cheap check before building one)."""
        async with self._mutex:
            return await self._block_refusal(validator, int(slot), None) is None

    async def may_vote(self, validator: str, source: int, target: int) -> bool:
        """Whether some vote ``source -> target`` could be signed."""
        async with self._mutex:
            return await self._vote_refusal(validator, int(source), int(target), None) is None

    # ── check and record, before signing ─────────────────────────────────────

    async def _write(self, check, insert: Tuple[str, Tuple[Any, ...]]) -> Optional[str]:
        async with self._mutex:
            await self._conn.execute("BEGIN IMMEDIATE")
            try:
                refusal = await check()
                if refusal is None:
                    await self._conn.execute(*insert)
                await self._conn.execute("COMMIT")
            except BaseException:
                await self._conn.execute("ROLLBACK")
                raise
            self._writes += 1
        if refusal is None and self._writes % _PRUNE_EVERY == 0:
            await self.prune()
        return refusal

    async def record_block(self, validator: str, slot: int, signing_root: Any) -> bool:
        """Record a block about to be signed. False (and nothing recorded) if signing it could
        be slashable; the caller must then not sign."""
        root, slot = _root(signing_root), int(slot)
        refusal = await self._write(
            lambda: self._block_refusal(validator, slot, root),
            (
                "INSERT OR IGNORE INTO signed_blocks VALUES (?, ?, ?, ?)",
                (self.network, validator, slot, root),
            ),
        )
        if refusal:
            logger.warning(
                "slashing protection: not signing a block for %s: %s", validator, refusal
            )
        return refusal is None

    async def record_vote(
        self, validator: str, source: int, target: int, signing_root: Any
    ) -> bool:
        """Record an attestation about to be signed. False (and nothing recorded) if signing it
        could be slashable; the caller must then not sign."""
        root, source, target = _root(signing_root), int(source), int(target)
        refusal = await self._write(
            lambda: self._vote_refusal(validator, source, target, root),
            (
                "INSERT OR IGNORE INTO signed_votes VALUES (?, ?, ?, ?, ?)",
                (self.network, validator, source, target, root),
            ),
        )
        if refusal:
            logger.warning("slashing protection: not voting for %s: %s", validator, refusal)
        return refusal is None

    # ── what the record holds (the doppelganger check) ───────────────────────

    async def signed_block_roots(self, validator: str, from_slot: int) -> Dict[int, str]:
        cur = await self._conn.execute(
            "SELECT slot, signing_root FROM signed_blocks"
            " WHERE network = ? AND validator = ? AND slot >= ?",
            (self.network, validator, int(from_slot)),
        )
        return {int(s): r for s, r in await cur.fetchall()}

    async def signed_vote_roots(self, validator: str, from_target: int) -> Dict[int, str]:
        cur = await self._conn.execute(
            "SELECT target_epoch, signing_root FROM signed_votes"
            " WHERE network = ? AND validator = ? AND target_epoch >= ?",
            (self.network, validator, int(from_target)),
        )
        return {int(t): r for t, r in await cur.fetchall()}

    async def latest(self, validator: str) -> Tuple[int, int]:
        """The highest slot and target epoch this validator has signed (-1 if none): for
        monitoring that it keeps signing."""
        blocks = await self._one(
            "SELECT MAX(slot) FROM signed_blocks WHERE network = ? AND validator = ?",
            (self.network, validator),
        )
        votes = await self._one(
            "SELECT MAX(target_epoch) FROM signed_votes WHERE network = ? AND validator = ?",
            (self.network, validator),
        )
        b, _s, t = await self._watermarks(validator)
        slot = blocks[0] if blocks and blocks[0] is not None else b
        epoch = votes[0] if votes and votes[0] is not None else t
        return int(slot), int(epoch)

    # ── watermarks, pruning, interchange ─────────────────────────────────────

    async def _raise_watermarks(
        self, validator: str, block_slot: int, source_epoch: int, target_epoch: int
    ) -> None:
        b, s, t = await self._watermarks(validator)
        await self._conn.execute(
            "INSERT OR REPLACE INTO watermarks VALUES (?, ?, ?, ?, ?)",
            (
                self.network,
                validator,
                max(b, block_slot),
                max(s, source_epoch),
                max(t, target_epoch),
            ),
        )

    async def prune(self) -> None:
        """Fold rows far behind the newest into the watermarks."""
        async with self._mutex:
            await self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = await self._conn.execute(
                    "SELECT validator, MAX(slot) FROM signed_blocks WHERE network = ?"
                    " GROUP BY validator",
                    (self.network,),
                )
                for validator, top in await cur.fetchall():
                    cut = int(top) - KEEP_SLOTS
                    if cut > 0:
                        await self._raise_watermarks(validator, cut, -1, -1)
                        await self._conn.execute(
                            "DELETE FROM signed_blocks WHERE network = ? AND validator = ?"
                            " AND slot <= ?",
                            (self.network, validator, cut),
                        )
                cur = await self._conn.execute(
                    "SELECT validator, MAX(target_epoch) FROM signed_votes WHERE network = ?"
                    " GROUP BY validator",
                    (self.network,),
                )
                for validator, top in await cur.fetchall():
                    cut = int(top) - KEEP_EPOCHS
                    if cut > 0:
                        row = await self._one(
                            "SELECT MAX(source_epoch) FROM signed_votes WHERE network = ?"
                            " AND validator = ? AND target_epoch <= ?",
                            (self.network, validator, cut),
                        )
                        source = int(row[0]) if row and row[0] is not None else -1
                        await self._raise_watermarks(validator, -1, source, cut)
                        await self._conn.execute(
                            "DELETE FROM signed_votes WHERE network = ? AND validator = ?"
                            " AND target_epoch <= ?",
                            (self.network, validator, cut),
                        )
                await self._conn.execute("COMMIT")
            except BaseException:
                await self._conn.execute("ROLLBACK")
                raise

    async def export(self, validators: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        """The record in the interchange format (EIP-3076, addresses as ``pubkey``)."""
        wanted: Optional[Set[str]] = set(validators) if validators is not None else None
        cur = await self._conn.execute(
            "SELECT validator FROM signed_blocks WHERE network = ? UNION"
            " SELECT validator FROM signed_votes WHERE network = ? UNION"
            " SELECT validator FROM watermarks WHERE network = ?",
            (self.network, self.network, self.network),
        )
        data: List[Dict[str, Any]] = []
        for (validator,) in sorted(await cur.fetchall()):
            if wanted is not None and validator not in wanted:
                continue
            blocks = await self._conn.execute(
                "SELECT slot, signing_root FROM signed_blocks WHERE network = ? AND validator = ?"
                " ORDER BY slot",
                (self.network, validator),
            )
            votes = await self._conn.execute(
                "SELECT source_epoch, target_epoch, signing_root FROM signed_votes"
                " WHERE network = ? AND validator = ? ORDER BY target_epoch",
                (self.network, validator),
            )
            b, s, t = await self._watermarks(validator)
            signed_blocks = [
                {"slot": str(slot), "signing_root": "0x" + root}
                for slot, root in await blocks.fetchall()
            ]
            signed_votes = [
                {"source_epoch": str(se), "target_epoch": str(te), "signing_root": "0x" + root}
                for se, te, root in await votes.fetchall()
            ]
            # Watermarks travel as root-less entries: the importer refuses at or below them.
            if b >= 0:
                signed_blocks.insert(0, {"slot": str(b)})
            if t >= 0:
                signed_votes.insert(0, {"source_epoch": str(max(s, 0)), "target_epoch": str(t)})
            data.append(
                {
                    "pubkey": validator,
                    "signed_blocks": signed_blocks,
                    "signed_attestations": signed_votes,
                }
            )
        return {
            "metadata": {
                "interchange_format_version": INTERCHANGE_VERSION,
                "genesis_validators_root": "0x" + self.network,
            },
            "data": data,
        }

    async def import_interchange(self, doc: Dict[str, Any]) -> int:
        """Merge an interchange document: its rows join the record and raise its watermarks to
        the highest slot, source and target it names. Refuses another network's record.
        Returns the number of validators imported."""
        meta = doc.get("metadata") or {}
        if str(meta.get("interchange_format_version")) != INTERCHANGE_VERSION:
            raise ProtectionStoreError(
                f"interchange format {meta.get('interchange_format_version')!r} is not "
                f"{INTERCHANGE_VERSION}"
            )
        if _root(meta.get("genesis_validators_root")) != self.network:
            raise ProtectionStoreError("the interchange file belongs to another network")
        entries = doc.get("data") or []
        async with self._mutex:
            await self._conn.execute("BEGIN IMMEDIATE")
            try:
                for entry in entries:
                    validator = str(entry["pubkey"])
                    top_slot = top_source = top_target = -1
                    for blk in entry.get("signed_blocks") or []:
                        slot = int(blk["slot"])
                        top_slot = max(top_slot, slot)
                        if blk.get("signing_root"):
                            await self._conn.execute(
                                "INSERT OR IGNORE INTO signed_blocks VALUES (?, ?, ?, ?)",
                                (self.network, validator, slot, _root(blk["signing_root"])),
                            )
                    for att in entry.get("signed_attestations") or []:
                        source, target = int(att["source_epoch"]), int(att["target_epoch"])
                        if source > target:
                            raise ProtectionStoreError(
                                f"{validator}: a vote {source}->{target} runs backwards"
                            )
                        top_source, top_target = max(top_source, source), max(top_target, target)
                        if att.get("signing_root"):
                            await self._conn.execute(
                                "INSERT OR IGNORE INTO signed_votes VALUES (?, ?, ?, ?, ?)",
                                (
                                    self.network,
                                    validator,
                                    source,
                                    target,
                                    _root(att["signing_root"]),
                                ),
                            )
                    await self._raise_watermarks(validator, top_slot, top_source, top_target)
                await self._conn.execute("COMMIT")
            except BaseException:
                await self._conn.execute("ROLLBACK")
                raise
        return len(entries)

    async def import_legacy_votes(self, db: Any) -> int:
        """Fold the chain database's older vote record (``ffg_signing_record``) in as
        watermarks: it kept only each vote's epochs, so no vote at or below them is signed."""
        try:
            cur = await db.connection.execute(
                "SELECT validator, MAX(source_epoch), MAX(target_epoch) FROM ffg_signing_record"
                " GROUP BY validator"
            )
            rows = await cur.fetchall()
        except Exception:
            return 0  # no such table: nothing was ever recorded there
        if not rows:
            return 0
        doc = {
            "metadata": {
                "interchange_format_version": INTERCHANGE_VERSION,
                "genesis_validators_root": self.network,
            },
            "data": [
                {
                    "pubkey": v,
                    "signed_blocks": [],
                    "signed_attestations": [{"source_epoch": int(s), "target_epoch": int(t)}],
                }
                for v, s, t in rows
            ],
        }
        return await self.import_interchange(doc)


def load_interchange(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
