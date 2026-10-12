"""
Casper FFG finality (docs/KNOWN_ISSUES.md, "Finality was not bound to a branch").

Finality used to justify an epoch when 2/3 of the stake had cast *any* vote for it, and
validators voted every slot for whatever head they saw. A validator that switched forks
therefore voted for both — legitimately — and when a fork outlived the finality lag both
branches finalized different blocks at the same height. The reorg guard then made the split
permanent: each side refused the other's chain.

This is the FFG rule set, with every input taken from the canonical chain so every node holding
the same chain computes the same finality:

* **Checkpoints.** Epoch *e*'s checkpoint is the last block before *e*'s first slot (genesis for
  epoch 0). It is fixed by the time anyone votes in *e*.
* **Votes.** An attestation casts one FFG vote: a source checkpoint (the voter's latest
  justified checkpoint) and a target checkpoint (the current epoch's), each by epoch and block
  hash, both signed. An honest validator casts one per epoch (``vote_slot``), and never two
  different ones for the same target or one that surrounds another — both are slashable
  (``slashing_block.attestation_equivocation``), and ``SigningRecord`` keeps a validator from
  doing either by accident, across restarts.
* **What counts.** Only votes carried by canonical blocks, each validated on import
  (``verify_block_votes``): a known key, a valid signature, and a target that is this chain's
  checkpoint. A vote's source must be a checkpoint already justified on this chain.
* **Justified.** Checkpoint *t* is justified when validators holding ≥ ATTESTATION_THRESHOLD of
  the stake voted for it from justified sources.
* **Finalized.** Justified checkpoint *t−1* is finalized when that threshold voted the link
  *t−1 → t* exactly.

Two branches can then finalize conflicting checkpoints only if a third of the stake signed a
double or surround vote. Finalized checkpoints are never reorged (the guard refuses), so the
computation resumes from the last one instead of genesis.
"""

from __future__ import annotations

import json
import weakref
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

from ..constants import ATTESTATION_THRESHOLD, SLOTS_PER_EPOCH
from ..logger import get_logger

logger = get_logger(__name__)

# How far into each epoch a validator casts its vote, in slots: late enough that the previous
# epoch's last block (this epoch's checkpoint) has reached it, and the previous epoch's votes
# have been included, so its source is usually the previous epoch and the link finalizes it.
VOTE_OFFSET_SLOTS = max(1, SLOTS_PER_EPOCH // 4) if SLOTS_PER_EPOCH > 1 else 0
# A vote may be included this many epochs after its target, then no longer.
INCLUSION_EPOCHS = 2
# Epochs of each node's vote history (attestation_votes, with every vote's 3.3 KB signature) kept
# below the finalized epoch. The slashing detector compares a new vote with a validator's 128
# latest; older rows were never read again and grew the database by ~0.5 KB a block.
VOTE_HISTORY_EPOCHS = 256

Checkpoint = Tuple[int, str]  # (epoch, block hash)


def vote_slot(epoch: int) -> int:
    """The slot in which validators cast their vote for ``epoch``."""
    return int(epoch) * SLOTS_PER_EPOCH + VOTE_OFFSET_SLOTS


def _hex_root(value: Any) -> bool:
    try:
        return isinstance(value, str) and len(bytes.fromhex(value)) == 32
    except ValueError:
        return False


async def checkpoint(db: Any, epoch: int) -> Optional[Tuple[int, str]]:
    """(height, hash) of ``epoch``'s checkpoint on the canonical chain."""
    from .. import chain_index

    return await chain_index.checkpoint(db, int(epoch), SLOTS_PER_EPOCH)


# ── validator keys (deterministic, from the chain) ───────────────────────────────────────

_keys: "weakref.WeakKeyDictionary[Any, Dict[str, Tuple[int, bytes]]]" = weakref.WeakKeyDictionary()


async def validator_key(db: Any, address: str, height: int) -> Optional[bytes]:
    """The key ``address`` votes with in a block at ``height`` (chain_index.validator_public_key,
    cached: a key, once on the chain, never changes)."""
    cache = _keys.setdefault(db, {})
    hit = cache.get(address)
    if hit is not None and hit[0] < height:
        return hit[1]
    from .. import chain_index

    key = await chain_index.validator_public_key(db, address, height)
    if key is not None:
        cache[address] = (-1, key)  # valid from the start: a key derives to its address
    return key


# ── block validity ───────────────────────────────────────────────────────────────────────


async def verify_block_votes(
    db: Any, block: Dict[str, Any], height: int, block_epoch: Optional[int]
) -> Tuple[bool, str]:
    """Every attestation a block carries must be a valid FFG vote for this chain: a target
    epoch ≥ 1 and ≤ the block's, a source epoch below it, both roots 32-byte hashes, the target
    root this chain's checkpoint for that epoch, the voter's key on the chain and its signature
    valid. Checked by every import path before a block is stored, so the chain index — and
    the finality, rewards and validator set computed from it — counts only real votes.
    ``(True, "")`` or ``(False, reason)``."""
    from .attestation_block import extract_attestations_from_dict

    try:
        attestations = extract_attestations_from_dict(block)
    except Exception as e:
        return False, f"malformed attestations: {e}"
    if not attestations:
        return True, ""
    epoch = int(block_epoch) if block_epoch is not None else None
    checkpoints: Dict[int, Optional[Tuple[int, str]]] = {}
    seen = set()
    for a in attestations:
        who = f"attestation by {str(a.validator_address)[:20]}… for epoch {a.target_epoch}"
        if not (_hex_root(a.source_root) and _hex_root(a.target_root)):
            return False, f"{who}: missing or malformed checkpoint roots"
        if a.target_epoch < 1 or (epoch is not None and a.target_epoch > epoch):
            return False, f"{who}: target epoch outside 1..{epoch}"
        if not 0 <= a.source_epoch < a.target_epoch:
            return False, f"{who}: source epoch {a.source_epoch} not below the target"
        if (a.validator_address, a.target_epoch) in seen:
            return False, f"{who}: two votes by one validator for one target in one block"
        seen.add((a.validator_address, a.target_epoch))
        if a.target_epoch not in checkpoints:
            checkpoints[a.target_epoch] = await checkpoint(db, a.target_epoch)
        cp = checkpoints[a.target_epoch]
        if cp is None or cp[1] != a.target_root:
            return False, f"{who}: target is not this chain's checkpoint"
        key = await validator_key(db, a.validator_address, height)
        if key is None:
            return False, f"{who}: no key for the validator on this chain"
        if not a.verify(key):
            return False, f"{who}: bad signature"
    return True, ""


# ── finality ─────────────────────────────────────────────────────────────────────────────


@dataclass
class Finality:
    justified: Dict[int, str] = field(default_factory=dict)  # epoch → checkpoint root
    finalized: Checkpoint = (0, "")
    finalized_height: int = 0

    @property
    def latest_justified(self) -> Checkpoint:
        e = max(self.justified)
        return e, self.justified[e]


async def _target_stakes(db: Any, view: "ChainView", target: int) -> Dict[str, Decimal]:
    """The stake a vote for ``target`` weighs: each active or exiting validator's effective
    stake in ``S_target`` of the chain the vote is counted on (validator/epoch_state.py) — so
    finality is a function of the chain, not of this node's live table. For a branch view,
    an epoch past the common prefix is weighed by the newest state the prefix determines: its
    own would need the branch's blocks applied (their stake operations executed)."""
    from .epoch_state import state_at, voting_stakes

    if view.ancestor is None:
        return voting_stakes(await state_at(db, target))
    first = view.branch[0][2] // SLOTS_PER_EPOCH if view.branch else target
    return voting_stakes(await state_at(db, min(target, first), view.ancestor))


async def _stored_finalized(db: Any) -> Optional[Tuple[int, str, int]]:
    try:
        cur = await db.connection.execute(
            "SELECT value FROM chain_metadata WHERE key = 'ffg_finalized'"
        )
        row = await cur.fetchone()
    except Exception:
        return None
    if not row:
        return None
    v = json.loads(row[0])
    return int(v["epoch"]), str(v["root"]), int(v["height"])


class ChainView:
    """The chain finality is computed over: the canonical chain, or — to score a competing
    branch before adopting it (fork choice) — the canonical chain up to ``ancestor`` followed by
    ``branch``: [(height, hash, slot, attestations)] in height order."""

    def __init__(
        self,
        db: Any,
        ancestor: Optional[int] = None,
        branch: Optional[List[Tuple[int, str, int, List[Any]]]] = None,
    ) -> None:
        self.db = db
        self.ancestor = ancestor if branch is not None else None
        self.branch = branch or []

    async def block_hash(self, height: int) -> Optional[str]:
        from .. import chain_index

        if self.ancestor is not None and height > self.ancestor:
            for h, bh, _slot, _atts in self.branch:
                if h == height:
                    return bh
            return None
        return await chain_index.block_hash_at(self.db, height)

    async def checkpoint(self, epoch: int) -> Optional[Tuple[int, str]]:
        from .. import chain_index

        if self.ancestor is None:
            return await checkpoint(self.db, epoch)
        start = int(epoch) * SLOTS_PER_EPOCH
        if epoch > 0:
            for h, bh, slot, _atts in reversed(self.branch):
                if slot < start:
                    return h, bh
        height = 0
        if epoch > 0:
            height = max(
                0, await chain_index.height_before_slot_at_or_below(self.db, start, self.ancestor)
            )
        root = await chain_index.block_hash_at(self.db, height)
        return (height, root) if root else None

    async def votes(self, from_target_epoch: int) -> List[Tuple[str, int, str, int, str]]:
        """(validator, source epoch, source root, target epoch, target root), in chain order."""
        from .. import chain_index

        out = [
            (v, int(se), sr, int(te), tr)
            for _h, v, se, sr, te, tr in await chain_index.ffg_votes(
                self.db, from_target_epoch, self.ancestor
            )
        ]
        for _h, _bh, _slot, atts in self.branch:
            for a in atts:
                if a.target_epoch >= from_target_epoch and a.target_root:
                    out.append(
                        (
                            a.validator_address,
                            a.source_epoch,
                            a.source_root,
                            a.target_epoch,
                            a.target_root,
                        )
                    )
        return out


async def compute(db: Any, view: Optional[ChainView] = None) -> Optional[Finality]:
    """Justified and finalized checkpoints of the canonical chain — or of ``view`` — (None while
    it has no blocks). Resumes from the stored finalized checkpoint while it is on the chain."""
    view = view or ChainView(db)
    genesis = await view.block_hash(0)
    if genesis is None:
        return None
    state = Finality(justified={0: genesis}, finalized=(0, genesis), finalized_height=0)
    stored = await _stored_finalized(db)
    if stored is not None and await view.block_hash(stored[2]) == stored[1]:
        state.justified = {stored[0]: stored[1]}
        state.finalized, state.finalized_height = (stored[0], stored[1]), stored[2]
    # First vote per (validator, target), in chain order. A validator's second, different vote
    # for one target is a double vote: slashable, never counted.
    votes: Dict[int, Dict[str, Tuple[int, str, str]]] = {}
    for validator, se, sr, te, tr in await view.votes(state.finalized[0] + 1):
        votes.setdefault(int(te), {}).setdefault(validator, (int(se), sr, tr))

    for t in sorted(votes):
        cp = await view.checkpoint(t)
        if cp is None:
            break
        stakes = await _target_stakes(db, view, t)
        total = sum(stakes.values(), Decimal(0))
        if total <= 0:
            continue
        support = link = Decimal(0)
        for validator, (se, sr, tr) in votes[t].items():
            if tr != cp[1] or se >= t or state.justified.get(se) != sr:
                continue
            weight = stakes.get(validator, Decimal(0))
            support += weight
            if se == t - 1:
                link += weight
        if support / total < ATTESTATION_THRESHOLD:
            continue
        state.justified[t] = cp[1]
        if t - 1 in state.justified and link / total >= ATTESTATION_THRESHOLD:
            prev = await view.checkpoint(t - 1)
            if prev is not None and t - 1 > state.finalized[0]:
                state.finalized, state.finalized_height = (t - 1, prev[1]), prev[0]
    return state


class Score(NamedTuple):
    """A chain as fork choice compares it (``prefer``)."""

    justified: int  # latest justified epoch on this chain
    height: int
    tip: str
    justified_height: int  # height of that justified checkpoint's block


async def _score(view: "ChainView", state: Optional[Finality], height: int, tip: str) -> Score:
    justified = max(state.justified) if state else 0
    cp = await view.checkpoint(justified) if justified else None
    return Score(justified, height, tip, cp[0] if cp else 0)


async def branch_score(
    db: Any, ancestor: int, branch: List[Tuple[int, str, int, List[Any]]]
) -> Score:
    """Fork-choice score of the chain that is ours up to ``ancestor`` and then ``branch``.
    See ``prefer``."""
    view = ChainView(db, ancestor, branch)
    state = await compute(db, view)
    if not branch:
        return await _score(view, state, ancestor, await ChainView(db).block_hash(ancestor) or "")
    return await _score(view, state, branch[-1][0], branch[-1][1])


async def local_score(db: Any) -> Score:
    """This node's chain as ``branch_score`` scores a branch."""
    from .. import chain_index

    state = await compute(db)
    tip = int(await db.get_next_block_id()) - 1
    return await _score(ChainView(db), state, tip, (await chain_index.block_hash_at(db, tip)) or "")


def prefer(
    candidate: Sequence[Any], current: Sequence[Any], ancestor: Optional[int] = None
) -> bool:
    """Fork choice between two chains that share every block up to ``ancestor``: Casper FFG's
    rule, then the longest chain. A chain holding the newest justified checkpoint is never left
    for one that does not hold it. When that checkpoint lies at or below ``ancestor`` both
    chains hold it, and the taller chain wins, then the lower tip hash (every node breaks a tie
    the same way).

    A checkpoint's justification belongs to the checkpoint, not to the branch whose blocks carry
    the votes. Comparing each branch's justified epoch regardless let a branch that happened to
    carry one more vote for a shared checkpoint beat a far taller one: on the 250 ms testnet a
    single validator's branch kept "justified 14" against the network's "justified 9" and never
    rejoined it, and finality stopped. Scores without a justified height (or no ``ancestor``)
    compare justification first, as before."""
    cj, ch, ct = candidate[0], candidate[1], candidate[2]
    oj, oh, ot = current[0], current[1], current[2]
    if cj != oj:
        newer = candidate if cj > oj else current
        newer_height = newer[3] if len(newer) > 3 else None
        if ancestor is None or newer_height is None or newer_height > ancestor:
            return cj > oj
    if ch != oh:
        return ch > oh
    return bool(ct) and ct < ot


_cache: "weakref.WeakKeyDictionary[Any, Tuple[int, str]]" = weakref.WeakKeyDictionary()


async def update(db: Any) -> Dict[str, int]:
    """Recompute and persist: the epochs table's justified/finalized flags (what the epoch
    loop, reconstruction and the RPC read) and the finalized checkpoint (what the reorg guard
    reads). Returns ``{"justified_epoch", "finalized_epoch"}`` (-1 for none)."""
    state = await compute(db)
    if state is None:
        return {"justified_epoch": -1, "finalized_epoch": -1}
    prev = await _stored_finalized(db)
    fin_epoch, fin_root = state.finalized
    if prev is None or fin_epoch > prev[0]:
        await db.connection.execute(
            "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES ('ffg_finalized', ?)",
            (json.dumps({"epoch": fin_epoch, "root": fin_root, "height": state.finalized_height}),),
        )
        try:
            from ..derived_state_rebuild import prune_reorg_state

            await prune_reorg_state(db, state.finalized_height)
        except Exception as e:
            logger.debug("reorg-state prune skipped: %s", e)
        if hasattr(db, "prune_attestation_votes"):
            try:
                await db.prune_attestation_votes(fin_epoch - VOTE_HISTORY_EPOCHS)
            except Exception as e:
                logger.debug("vote-history prune skipped: %s", e)
        if prev is not None and fin_epoch > prev[0]:
            logger.info(
                "[finality] finalized epoch %d (block %d, %s…), justified %d",
                fin_epoch,
                state.finalized_height,
                fin_root[:16],
                max(state.justified),
            )
    # The epochs table: every epoch up to the finalized one is irreversible (marked finalized,
    # including any skipped since the last update); justification above it is recomputed, since
    # a reorg can change it.
    low = prev[0] if prev is not None else 0
    cur = await db.connection.execute(
        "SELECT epoch, justified, finalized FROM epochs WHERE epoch >= ?", (low,)
    )
    stored = {int(r[0]): (bool(r[1]), bool(r[2])) for r in await cur.fetchall()}
    top = max([fin_epoch, *state.justified, *stored])
    for ep in range(low, top + 1):
        was = stored.get(ep, (False, False))
        finalized = ep <= fin_epoch or was[1]
        justified = ep in state.justified or (finalized and was[0])
        if (justified, finalized) != was:
            await db.set_epoch_finality(
                ep,
                ep * SLOTS_PER_EPOCH,
                (ep + 1) * SLOTS_PER_EPOCH - 1,
                justified=justified,
                finalized=finalized,
            )
    _cache[db] = (state.finalized_height, fin_root)
    return {"justified_epoch": max(state.justified), "finalized_epoch": fin_epoch}


async def finalized_height(db: Any) -> int:
    """Height of the finalized checkpoint's block (0 — genesis — before any)."""
    hit = _cache.get(db)
    if hit is not None:
        return hit[0]
    stored = await _stored_finalized(db)
    return stored[2] if stored is not None else 0


# ── the honest validator ─────────────────────────────────────────────────────────────────


async def vote_for(db: Any, epoch: int) -> Optional[Tuple[int, str, int, str]]:
    """The FFG vote an honest validator casts in ``epoch``: from its latest justified checkpoint
    (below the epoch) to the epoch's checkpoint. None when there is nothing to vote for."""
    if epoch < 1:
        return None
    cp = await checkpoint(db, epoch)
    state = await compute(db)
    if cp is None or state is None:
        return None
    sources = [e for e in state.justified if e < epoch]
    if not sources:
        return None
    se = max(sources)
    return se, state.justified[se], int(epoch), cp[1]


class SigningRecord:
    """What a validator has signed (``ffg_signing_record`` in the node's database), so it never
    signs a double vote (two different votes for one target epoch) or a surround vote — not
    even across a restart, when it no longer remembers voting. Slashing protection."""

    _SCHEMA = (
        "CREATE TABLE IF NOT EXISTS ffg_signing_record ("
        " validator TEXT NOT NULL,"
        " target_epoch INTEGER NOT NULL,"
        " source_epoch INTEGER NOT NULL,"
        " vote TEXT NOT NULL,"
        " PRIMARY KEY (validator, target_epoch))"
    )

    def __init__(self, db: Any) -> None:
        self.db = db
        self._ready = False

    async def _ensure(self) -> None:
        if not self._ready:
            await self.db.connection.execute(self._SCHEMA)
            self._ready = True

    async def may_sign(self, validator: str, vote: Tuple[int, str, int, str]) -> bool:
        """True if signing ``vote`` is safe: no different vote for its target, no surround."""
        await self._ensure()
        se, _sr, te, _tr = vote
        cur = await self.db.connection.execute(
            "SELECT target_epoch, source_epoch, vote FROM ffg_signing_record WHERE validator = ?",
            (validator,),
        )
        for t, s, recorded in await cur.fetchall():
            if int(t) == te:
                return json.loads(recorded) == list(vote)  # the same vote again is harmless
            if (s < se and te < t) or (se < s and t < te):
                return False
        return True

    async def record(self, validator: str, vote: Tuple[int, str, int, str]) -> None:
        """Record ``vote`` as signed. Committed before the vote leaves the node."""
        await self._ensure()
        await self.db.connection.execute(
            "INSERT OR IGNORE INTO ffg_signing_record (validator, target_epoch, source_epoch, "
            "vote) VALUES (?, ?, ?, ?)",
            (validator, vote[2], vote[0], json.dumps(list(vote))),
        )
        await self.db.connection.commit()


# ── inclusion ────────────────────────────────────────────────────────────────────────────


async def votes_to_include(
    db: Any, candidates: List[Any], block_epoch: int, limit: int
) -> List[Any]:
    """The pool attestations a proposer may put in its next block: valid for its chain (the
    target is this chain's checkpoint), within the inclusion window, and not already carried by
    the chain — judged against the chain itself, so a vote that rode an orphaned block is
    included again. One per (validator, target), oldest target first."""
    from .. import chain_index

    low = max(1, int(block_epoch) - INCLUSION_EPOCHS)
    carried = await chain_index.voted_targets(db, low)
    height = int(await db.get_next_block_id())
    checkpoints: Dict[int, Optional[Tuple[int, str]]] = {}
    chosen: Dict[Tuple[str, int], Any] = {}
    for a in sorted(candidates, key=lambda x: (x.target_epoch, x.validator_address, x.slot)):
        key = (a.validator_address, a.target_epoch)
        if key in chosen or key in carried or not low <= a.target_epoch <= block_epoch:
            continue
        if not (_hex_root(a.source_root) and _hex_root(a.target_root)):
            continue
        if a.target_epoch not in checkpoints:
            checkpoints[a.target_epoch] = await checkpoint(db, a.target_epoch)
        cp = checkpoints[a.target_epoch]
        if cp is None or cp[1] != a.target_root or not 0 <= a.source_epoch < a.target_epoch:
            continue
        # The exact checks importers apply (verify_block_votes): one bad vote would cost the
        # proposer its block.
        vkey = await validator_key(db, a.validator_address, height)
        if vkey is None or not a.verify(vkey):
            continue
        chosen[key] = a
        if len(chosen) >= limit:
            break
    return list(chosen.values())
