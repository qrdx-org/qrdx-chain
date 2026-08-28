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
    await db.seed_genesis_validators(genesis_validators)

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

    if commit:
        await db.connection.commit()
