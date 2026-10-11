"""
Validators reorg-reconstruction — the 5th reorg-reconstructed consensus domain (item 3).

The consensus ``validators`` DYNAMIC state (deposit stake + activation/exit schedule + epoch
rewards) was applied INCREMENTALLY on the live import path and never reset+replayed on reorg —
unlike the token ledger / account / exchange state, each of which has a ``rebuild_*_from_chain``.
So a DEPOSITED validator's state depended on a node's reorg history (an orphaned STAKE_DEPOSIT
froze its schedule; a live re-flush topped up its stake) rather than purely on the canonical chain
→ cross-node divergence (see tests/test_validator_reorg_reconstruction.py).

``reconstruct_validators_state`` rebuilds it as a PURE FUNCTION of the canonical chain, so it is
identical on every node regardless of import history:

  1. RESET to the genesis base (``db.seed_genesis_validators``) — drop deposited validators, reset
     genesis validators' dynamic state.
  2. Walk epochs 0..finalized_epoch IN ORDER, and at each epoch e:
       a. apply the STAKE ops carried in blocks OF epoch e — a STAKE_DEPOSIT registers a PENDING
          validator scheduled to activate at e+ACTIVATION_DELAY_EPOCHS; a STAKE_EXIT moves an
          active validator to 'exiting' at e+UNBONDING_PERIOD_EPOCHS. Deduped by tx-id so a genuine
          multi-deposit accumulates but a reorg replay never double-counts, and processed in strict
          (epoch, tx_id) order so the interleave with (b) is deterministic — an EXIT finds its
          validator already active because activation ran in an earlier epoch's step (b).
       b. run the finalized-epoch update: activate pending whose activation_epoch ≤ e, exit exiting
          whose exit_epoch ≤ e, and apply the reward/penalty deltas — ``compute_epoch_reward_deltas``
          over the (now canonical) active set + that epoch's attesters. Because the schedule is
          canonical, the active set at each epoch is canonical, so the rewards converge too.

Inputs are INJECTED (genesis set, canonical ops, per-epoch attesters) so the core is unit-testable
without a block/P2P harness; the live caller (follow-up) supplies db-backed enumerators. This
module is not yet wired into the live reorg path — it is validated first by an equivalence +
convergence test (tests/test_validator_reconstruction_equivalence.py), exactly as the exchange /
EVM rebuilds were before being trusted live.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Mapping, Optional

from ..constants import ACTIVATION_DELAY_EPOCHS, UNBONDING_PERIOD_EPOCHS
from .epoch_processing import MAX_EFFECTIVE_BALANCE
from .epoch_rewards import compute_epoch_reward_deltas


async def reconstruct_validators_state(
    db,
    *,
    genesis_validators: List[Dict[str, Any]],
    canonical_ops: Iterable[Dict[str, Any]],
    attesters_by_epoch: Mapping[int, Iterable[str]],
    finalized_epoch: int,
    commit: bool = True,
) -> None:
    """Deterministically rebuild the ``validators`` dynamic state from canonical-chain inputs.

    ``genesis_validators``  : [{address, public_key, stake}] — the genesis base to reset to.
    ``canonical_ops``       : [{epoch, tx_id, type('deposit'|'exit'), address, public_key, stake}]
                              — the STAKE ops from the CANONICAL chain only (orphans excluded);
                              deduped here by tx_id as a safety net.
    ``attesters_by_epoch``  : {epoch: [validator_address, ...]} — who attested each epoch (chain
                              data; the live caller reads it from ``db.get_epoch_attesters``).
    ``finalized_epoch``     : rebuild through this epoch (inclusive).

    Writes the rebuilt table (``enforce=True`` on the per-epoch update); commits once at the end
    unless ``commit=False``. Idempotent — re-running yields the identical table."""
    # apply_epoch_slashings is imported lazily (epoch_loop pulls finality/rewards) to avoid a
    # module-load cycle. The reset below un-slashes everyone; re-applying the recorded slashing
    # events during the walk restores the penalty — slashing is itself a pure function of the
    # chain's slashing_events (evidence-in-blocks), so this keeps the rebuild fully canonical.
    await db.seed_genesis_validators(genesis_validators)
    # The reset dropped/rebased every validator, so any previously-applied slashing must be
    # re-applied. Clear the processed flag ≤ finalized so the walk re-slashes each offence at the
    # first epoch ≥ its offence epoch (exactly where the forward loop applied it — the penalty is a
    # fraction of the effective_stake at that point, which the deterministic walk reproduces).
    try:
        await db.connection.execute(
            "UPDATE slashing_events SET processed = 0 WHERE epoch <= ?", (int(finalized_epoch),)
        )
    except Exception:
        pass  # no slashing_events table / column — nothing to re-apply

    # Group canonical ops by carrying epoch, deduped by tx-id (first occurrence wins — canonical
    # enumeration already excludes orphans, so this only guards accidental double-inclusion).
    ops_by_epoch: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    seen_tx: set = set()
    for op in canonical_ops:
        txid = op.get("tx_id")
        if txid is not None:
            if txid in seen_tx:
                continue
            seen_tx.add(txid)
        ops_by_epoch[int(op["epoch"])].append(op)

    for epoch in range(int(finalized_epoch) + 1):
        await _apply_epoch(
            db, epoch, ops_by_epoch.get(epoch, []), attesters_by_epoch.get(epoch, [])
        )

    if commit:
        await db.connection.commit()


async def _apply_epoch(
    db, epoch: int, ops: Iterable[Dict[str, Any]], attesters: Iterable[str]
) -> None:
    """One epoch of the reconstruction walk: (a) its STAKE ops in deterministic tx_id order,
    (b) the finalized-epoch update — scheduled activations/exits and the reward/penalty deltas
    over the active set and that epoch's attesters — (c) the slashing offences finalized by
    it, (d) stake-floor ejection. Shared by the full rebuild and the incremental path, so the
    two cannot drift apart."""
    from .epoch_loop import (
        _ENFORCE_STAKE_FLOOR_EJECTION,
        _eject_validators_below_stake_floor,
        apply_epoch_slashings,
    )

    # (a) apply this epoch's STAKE ops, deterministic (epoch, tx_id) order.
    for op in sorted(ops, key=lambda o: str(o.get("tx_id", ""))):
        if op["type"] == "deposit":
            await db.register_pending_validator(
                op["address"],
                op["public_key"],
                op["stake"],
                activation_epoch=epoch + ACTIVATION_DELAY_EPOCHS,
            )
        elif op["type"] == "exit":
            await db.mark_validator_exiting(
                op["address"], exit_epoch=epoch + UNBONDING_PERIOD_EPOCHS
            )

    # (b) finalized-epoch update: schedule-driven activation/exit + reward/penalty deltas.
    activated = await db.get_validators_to_activate(epoch)
    exited = await db.get_validators_to_exit(epoch)
    active = await db.get_validators(status="active")
    rewards, penalties = compute_epoch_reward_deltas(active, list(attesters or []))
    await db.apply_epoch_validator_updates(
        rewards,
        penalties,
        activated=activated,
        exited=exited,
        activation_epoch=epoch,
        max_effective_balance=MAX_EFFECTIVE_BALANCE,
        enforce=True,
    )
    # (c) Re-apply slashing offences finalized by this epoch (slashes + ejects; marks processed
    # so a later epoch's call is a no-op) — same call the forward epoch loop makes.
    await apply_epoch_slashings(db, epoch, enforce=True)
    # (d) Stake-floor ejection, per epoch, AFTER that epoch's rewards/penalties/slashing so it
    # reads settled stake. It must live HERE: with reconstruction on (the live configuration)
    # the epoch loop never reaches the incremental path, so ejection placed only there never
    # ran. It reads and writes only the validators table, so it is a deterministic function of
    # the chain like everything else in this walk. log=False: replays re-announce nothing.
    if _ENFORCE_STAKE_FLOOR_EJECTION:
        await _eject_validators_below_stake_floor(db, epoch, log=False)


async def enumerate_canonical_validator_ops(db) -> List[Dict[str, Any]]:
    """Every canonical STAKE op — read from the chain index on the node's database (each block
    is decoded once, ever), by walking the chain otherwise. See
    ``enumerate_canonical_validator_ops_by_walk``."""
    if getattr(db, "connection", None) is not None:
        from ..chain_index import stake_ops

        return await stake_ops(db)
    return await enumerate_canonical_validator_ops_by_walk(db)


async def enumerate_canonical_validator_ops_by_walk(db) -> List[Dict[str, Any]]:
    """Walk the CANONICAL chain (height 0..tip) and pull every STAKE_DEPOSIT / STAKE_EXIT op with
    its carrying epoch — the ``canonical_ops`` for reconstruction. Enumerating stored canonical
    blocks in height order is inherently orphan-free (a reorg rollback already removed the orphan
    blocks), so a genuine multi-deposit accumulates while no orphan effect is ever replayed. Each
    op carries a stable ``tx_id`` (block_hash:index) as a dedup safety net."""
    from ..exchange.block_processor import decode_exchange_txs
    from ..exchange.transactions import ExchangeOpType
    from .block_verification import epoch_from_block

    ops: List[Dict[str, Any]] = []
    try:
        tip = (await db.get_next_block_id()) - 1
    except Exception:
        return ops
    for height in range(0, int(tip) + 1):
        try:
            block = await db.get_block_by_id(height)
        except Exception:
            block = None
        if not block:
            continue
        bh = block.get("hash") or block.get("block_hash")
        if not bh:
            continue
        # Stored blocks expose their content as ``content`` (str(block.to_dict())); epoch_from_block
        # reads it via the block_content key.
        epoch = epoch_from_block({"block_content": block.get("content"), **block})
        if epoch is None:
            continue  # cannot determine the carrying epoch → cannot schedule deterministically
        try:
            section = await db.get_block_exchange_txs(bh)
        except Exception:
            section = None
        if not section:
            continue
        try:
            txs = decode_exchange_txs(section)
        except Exception:
            continue
        for i, tx in enumerate(txs):
            if tx.op_type == ExchangeOpType.STAKE_DEPOSIT:
                ops.append(
                    {
                        "epoch": int(epoch),
                        "tx_id": f"{bh}:{i}",
                        "type": "deposit",
                        "address": tx.sender,
                        "public_key": str(tx.params.get("validator_public_key", "")),
                        "stake": str(tx.params.get("stake_amount")),
                    }
                )
            elif tx.op_type == ExchangeOpType.STAKE_EXIT:
                ops.append(
                    {
                        "epoch": int(epoch),
                        "tx_id": f"{bh}:{i}",
                        "type": "exit",
                        "address": tx.sender,
                    }
                )
    return ops


async def enumerate_canonical_epoch_attesters(db, finalized_epoch: int) -> Dict[int, list]:
    """Per-epoch attester sets from finalized canonical blocks — read from the chain index on
    the node's database, by walking the chain otherwise. See
    ``enumerate_canonical_epoch_attesters_by_walk``."""
    if getattr(db, "connection", None) is not None:
        from ..chain_index import epoch_attesters

        return await epoch_attesters(db, int(finalized_epoch))
    return await enumerate_canonical_epoch_attesters_by_walk(db, finalized_epoch)


async def enumerate_canonical_epoch_attesters_by_walk(db, finalized_epoch: int) -> Dict[int, list]:
    """Per-epoch attester sets computed from attestations carried in FINALIZED CANONICAL BLOCKS —
    the DETERMINISTIC reward input (replacing db.get_epoch_attesters → the accumulated
    `attestation_votes` table, which is NOT reorg-clean: a node can hold an extra/orphan vote,
    diverging rewards → effective_stake, even though the schedule converges).

    A vote counts for epoch e's reward iff a validator's attestation with target_epoch=e is carried
    in a canonical block whose OWN epoch ≤ finalized_epoch (i.e. the carrying block is finalized) —
    so every node, reading the identical finalized canonical blocks, derives the identical sets.
    Deduped by (target_epoch, validator) — one honest vote per target; re-inclusion is idempotent.
    (compute_epoch_reward_deltas only rewards attesters that are ACTIVE, so a spurious attester that
    is not in the active set is harmless — no signature re-verification needed here.)"""
    import ast

    from .attestation_block import extract_attestations_from_dict
    from .block_verification import epoch_from_block

    sets: Dict[int, set] = {e: set() for e in range(int(finalized_epoch) + 1)}
    try:
        tip = (await db.get_next_block_id()) - 1
    except Exception:
        return {e: [] for e in sets}
    for height in range(0, int(tip) + 1):
        try:
            block = await db.get_block_by_id(height)
        except Exception:
            block = None
        if not block:
            continue
        content = block.get("content")
        try:
            bc = ast.literal_eval(content) if isinstance(content, str) else content
        except Exception:
            continue
        if not isinstance(bc, dict):
            continue
        carry_epoch = epoch_from_block(bc)
        if carry_epoch is None or carry_epoch > finalized_epoch:
            continue  # only attestations carried in FINALIZED blocks are deterministic across nodes
        for att in extract_attestations_from_dict(bc):
            te = int(att.target_epoch)
            if 0 <= te <= finalized_epoch:
                sets[te].add(att.validator_address)
    return {e: list(s) for e, s in sets.items()}


async def reconstruct_validators_live(db, finalized_epoch: int, *, commit: bool = True) -> None:
    """Live entrypoint: bring the ``validators`` dynamic state to what a full rebuild through
    ``finalized_epoch`` from the canonical chain yields (``reconstruct_validators_full``).

    Incrementally, from the most recent per-epoch snapshot that is still exact: the latest
    one normally, an earlier one when the newly finalized blocks carry a vote that adds an
    attester to an already-processed epoch, when slashing evidence for such an epoch was
    recorded since, or when the chain below a snapshot changed. Falls back to the full
    rebuild when no snapshot reaches back far enough. The result is the full rebuild's,
    exactly (tests/test_validator_reconstruction_incremental.py); the cost is the new epochs,
    not the chain's history."""
    if getattr(db, "connection", None) is None:
        await reconstruct_validators_full(db, finalized_epoch, commit=commit)
        return
    await _reconstruct_incremental(db, int(finalized_epoch))
    if commit:
        await db.connection.commit()


async def reconstruct_validators_full(db, finalized_epoch: int, *, commit: bool = True) -> None:
    """The definition: gather the reconstruction inputs (genesis set, canonical STAKE ops,
    per-epoch attesters from FINALIZED CANONICAL BLOCKS — not db.get_epoch_attesters, whose
    attestation_votes table is not reorg-clean) and rebuild from genesis through
    ``finalized_epoch``."""
    genesis = await db.get_genesis_validators()
    ops = await enumerate_canonical_validator_ops(db)
    attesters_by_epoch = await enumerate_canonical_epoch_attesters(db, int(finalized_epoch))
    await reconstruct_validators_state(
        db,
        genesis_validators=genesis,
        canonical_ops=ops,
        attesters_by_epoch=attesters_by_epoch,
        finalized_epoch=int(finalized_epoch),
        commit=commit,
    )


# ── incremental reconstruction ───────────────────────────────────────────────────────────

# How many recent finalized epochs keep a snapshot to restart from. A vote or a slashing
# record that reaches further back than this forces a full rebuild (correct, just slow).
SNAPSHOT_EPOCHS = 64

_SNAPSHOT_TABLE = (
    "CREATE TABLE IF NOT EXISTS validator_reconstruction_snapshots ("
    "epoch INTEGER PRIMARY KEY, "
    "boundary_hash TEXT, "  # hash of the last block of this epoch: the chain the state is of
    "validators TEXT NOT NULL, "  # every validators row (JSON)
    "slashing TEXT NOT NULL)"  # every slashing_events key of an epoch <= this one + processed
)


async def _rows(db, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    cur = await db.connection.execute(sql, params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in await cur.fetchall()]


async def _boundary_hash(db, epoch: int) -> str:
    """Hash of the last canonical block of an epoch <= ``epoch`` ('' before any)."""
    cur = await db.connection.execute(
        "SELECT block_hash FROM chain_index WHERE epoch IS NOT NULL AND epoch <= ? "
        "ORDER BY height DESC LIMIT 1",
        (int(epoch),),
    )
    row = await cur.fetchone()
    return row[0] if row else ""


async def _slashing_keys(db, up_to_epoch: int) -> List[List[Any]]:
    try:
        rows = await _rows(
            db,
            "SELECT validator_address, slot, condition, epoch, processed FROM slashing_events "
            "WHERE epoch <= ? ORDER BY validator_address, slot, condition",
            (int(up_to_epoch),),
        )
    except Exception:
        return []  # no slashing_events table
    return [
        [r["validator_address"], r["slot"], r["condition"], r["epoch"], r["processed"]]
        for r in rows
    ]


async def _take_snapshot(db, epoch: int) -> None:
    validators = await _rows(db, "SELECT * FROM validators ORDER BY address")
    await db.connection.execute(
        "INSERT OR REPLACE INTO validator_reconstruction_snapshots "
        "(epoch, boundary_hash, validators, slashing) VALUES (?, ?, ?, ?)",
        (
            int(epoch),
            await _boundary_hash(db, epoch),
            json.dumps(validators, default=str),
            json.dumps(await _slashing_keys(db, epoch), default=str),
        ),
    )


async def _restore_snapshot(db, epoch: int) -> None:
    cur = await db.connection.execute(
        "SELECT validators, slashing FROM validator_reconstruction_snapshots WHERE epoch = ?",
        (int(epoch),),
    )
    validators_json, slashing_json = await cur.fetchone()
    await db.connection.execute("DELETE FROM validators")
    for row in json.loads(validators_json):
        cols = list(row)
        await db.connection.execute(
            f"INSERT INTO validators ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            [row[c] for c in cols],
        )
    try:
        # Evidence of a later epoch is re-applied by the walk; earlier evidence is exactly as
        # the walk left it when this snapshot was taken.
        await db.connection.execute(
            "UPDATE slashing_events SET processed = 0 WHERE epoch > ?", (int(epoch),)
        )
        for address, slot, condition, _ep, processed in json.loads(slashing_json):
            await db.connection.execute(
                "UPDATE slashing_events SET processed = ? "
                "WHERE validator_address = ? AND slot = ? AND condition = ?",
                (processed, address, slot, condition),
            )
    except Exception:
        pass  # no slashing_events table


async def _earliest_slashing_change(db, snapshot_epoch: int) -> Optional[int]:
    """Epoch of the earliest slashing record (≤ ``snapshot_epoch``) added or removed since that
    snapshot was taken."""
    cur = await db.connection.execute(
        "SELECT slashing FROM validator_reconstruction_snapshots WHERE epoch = ?",
        (int(snapshot_epoch),),
    )
    row = await cur.fetchone()
    then = {tuple(k[:4]) for k in json.loads(row[0])} if row else set()
    now = {tuple(k[:4]) for k in await _slashing_keys(db, snapshot_epoch)}
    changed = then ^ now
    return min(int(k[3]) for k in changed) if changed else None


async def _reconstruct_incremental(db, finalized_epoch: int) -> None:
    from .. import chain_index

    await chain_index.sync(db)
    await db.connection.execute(_SNAPSHOT_TABLE)
    cur = await db.connection.execute("SELECT MAX(epoch) FROM validator_reconstruction_snapshots")
    row = await cur.fetchone()
    latest = row[0] if row else None

    restart: Optional[int] = None
    if latest is not None and latest <= finalized_epoch:
        restart = int(latest)
        for earlier in (
            await chain_index.earliest_new_vote_epoch(db, restart, finalized_epoch),
            await _earliest_slashing_change(db, restart),
        ):
            if earlier is not None:
                restart = min(restart, earlier - 1)
        # The newest snapshot at or below `restart` whose chain is still the canonical one.
        cur = await db.connection.execute(
            "SELECT epoch, boundary_hash FROM validator_reconstruction_snapshots "
            "WHERE epoch <= ? ORDER BY epoch DESC",
            (restart,),
        )
        restart = None
        for epoch, boundary in await cur.fetchall():
            if await _boundary_hash(db, epoch) == boundary:
                restart = int(epoch)
                break

    if restart is None:
        await reconstruct_validators_full(db, finalized_epoch, commit=False)
        await db.connection.execute("DELETE FROM validator_reconstruction_snapshots")
        if finalized_epoch >= 0:
            await _take_snapshot(db, finalized_epoch)  # later epochs add theirs as they go
        return

    await _restore_snapshot(db, restart)
    await db.connection.execute(
        "DELETE FROM validator_reconstruction_snapshots WHERE epoch > ?", (restart,)
    )
    for epoch in range(restart + 1, finalized_epoch + 1):
        ops = await chain_index.stake_ops_for_epoch(db, epoch)
        attesters = await chain_index.attesters_of_epoch(db, epoch, finalized_epoch)
        await _apply_epoch(db, epoch, ops, attesters)
        await _take_snapshot(db, epoch)
    await db.connection.execute(
        "DELETE FROM validator_reconstruction_snapshots WHERE epoch <= ?",
        (finalized_epoch - SNAPSHOT_EPOCHS,),
    )
