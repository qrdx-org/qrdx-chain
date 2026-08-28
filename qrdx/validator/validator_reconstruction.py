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
    from .epoch_loop import apply_epoch_slashings

    await db.seed_genesis_validators(genesis_validators)
    # The reset dropped/rebased every validator, so any previously-applied slashing must be
    # re-applied. Clear the processed flag ≤ finalized so the walk re-slashes each offence at the
    # first epoch ≥ its offence epoch (exactly where the forward loop applied it — the penalty is a
    # fraction of the effective_stake at that point, which the deterministic walk reproduces).
    try:
        await db.connection.execute(
            "UPDATE slashing_events SET processed = 0 WHERE epoch <= ?", (int(finalized_epoch),))
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
        # (a) apply this epoch's STAKE ops, deterministic (epoch, tx_id) order.
        for op in sorted(ops_by_epoch.get(epoch, []), key=lambda o: str(o.get("tx_id", ""))):
            if op["type"] == "deposit":
                await db.register_pending_validator(
                    op["address"], op["public_key"], op["stake"],
                    activation_epoch=epoch + ACTIVATION_DELAY_EPOCHS)
            elif op["type"] == "exit":
                await db.mark_validator_exiting(
                    op["address"], exit_epoch=epoch + UNBONDING_PERIOD_EPOCHS)

        # (b) finalized-epoch update: schedule-driven activation/exit + reward/penalty deltas.
        activated = await db.get_validators_to_activate(epoch)
        exited = await db.get_validators_to_exit(epoch)
        active = await db.get_validators(status="active")
        attesters = list(attesters_by_epoch.get(epoch, []) or [])
        rewards, penalties = compute_epoch_reward_deltas(active, attesters)
        await db.apply_epoch_validator_updates(
            rewards, penalties, activated=activated, exited=exited,
            activation_epoch=epoch, max_effective_balance=MAX_EFFECTIVE_BALANCE, enforce=True)
        # Re-apply slashing offences finalized by this epoch (slashes + ejects; marks processed
        # so a later epoch's call is a no-op) — same call the forward epoch loop makes.
        await apply_epoch_slashings(db, epoch, enforce=True)

    if commit:
        await db.connection.commit()


async def enumerate_canonical_validator_ops(db) -> List[Dict[str, Any]]:
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
                ops.append({
                    "epoch": int(epoch), "tx_id": f"{bh}:{i}", "type": "deposit",
                    "address": tx.sender,
                    "public_key": str(tx.params.get("validator_public_key", "")),
                    "stake": str(tx.params.get("stake_amount")),
                })
            elif tx.op_type == ExchangeOpType.STAKE_EXIT:
                ops.append({
                    "epoch": int(epoch), "tx_id": f"{bh}:{i}", "type": "exit",
                    "address": tx.sender,
                })
    return ops


async def reconstruct_validators_live(db, finalized_epoch: int, *, commit: bool = True) -> None:
    """Live entrypoint: gather the reconstruction inputs from the DB (genesis set, canonical STAKE
    ops, per-epoch attesters) and rebuild the ``validators`` dynamic state through ``finalized_epoch``
    as a pure function of the canonical chain. Called from the reorg rollback path (gated) so the
    deposited-validator dynamic state converges across nodes regardless of import history."""
    genesis = await db.get_genesis_validators()
    ops = await enumerate_canonical_validator_ops(db)
    attesters_by_epoch = {e: await db.get_epoch_attesters(e) for e in range(int(finalized_epoch) + 1)}
    await reconstruct_validators_state(
        db, genesis_validators=genesis, canonical_ops=ops,
        attesters_by_epoch=attesters_by_epoch, finalized_epoch=int(finalized_epoch), commit=commit)
