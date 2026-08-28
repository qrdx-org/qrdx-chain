"""
Validators reorg-reconstruction — equivalence + convergence proof (item 3), the de-risking step
before wiring reconstruct_validators_state into the live reorg path (mirrors how the exchange / EVM
rebuilds were validated by a rebuild-vs-forward equivalence test first).

Proves three things on the SAME canonical chain (genesis G1/G2; a STAKE_DEPOSIT for V canonically
carried in a block of epoch 3 → activates at 3+ACTIVATION_DELAY):
  1. EQUIVALENCE   — reconstruction == the clean (no-reorg) forward result.
  2. BUG           — a forward node that saw V's deposit first on an ORPHAN block (epoch 1) then
                     canonically (epoch 3) DIVERGES from the clean node (frozen early activation +
                     topped-up double stake) — the exact item-3 divergence.
  3. CONVERGENCE   — running the reconstruction on that divergent node HEALS it back to the
                     canonical result. So the rebuilt state is a pure function of the chain,
                     import-history-independent.
"""
import os
import tempfile

import pytest

from qrdx.constants import ACTIVATION_DELAY_EPOCHS
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.epoch_processing import MAX_EFFECTIVE_BALANCE
from qrdx.validator.epoch_rewards import compute_epoch_reward_deltas
from qrdx.validator.validator_reconstruction import reconstruct_validators_state

G1 = "0xPQgenesis000000000000000000000000000000000000000000000000000000G1"
G2 = "0xPQgenesis000000000000000000000000000000000000000000000000000000G2"
V = "0xPQdepositor00000000000000000000000000000000000000000000000000000V"
GENESIS = [{"address": G1, "public_key": "a1", "stake": "100000"},
           {"address": G2, "public_key": "a2", "stake": "100000"}]
FINALIZED = 10
DEP_TX = "dep-V"
CANON_DEP_EPOCH = 3
CANON_ACT = CANON_DEP_EPOCH + ACTIVATION_DELAY_EPOCHS  # 7

# Canonical attester participation: G1/G2 every epoch; V from its canonical activation (epoch 7).
ATTESTERS = {e: [G1, G2] + ([V] if e >= CANON_ACT else []) for e in range(FINALIZED + 1)}


async def _new_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return await DatabaseSQLite.create(path), path


async def _snapshot(db):
    """Full validators table as {address: row} for a byte-level cross-node comparison."""
    c = await db.connection.execute(
        "SELECT address, status, activation_epoch, exit_epoch, stake, effective_stake, "
        "total_rewards, total_slashed FROM validators ORDER BY address")
    return {r[0]: tuple(r[1:]) for r in await c.fetchall()}


async def _run_epoch(db, e):
    """One finalized-epoch forward update (the epoch_loop body, enforce)."""
    activated = await db.get_validators_to_activate(e)
    exited = await db.get_validators_to_exit(e)
    active = await db.get_validators(status="active")
    rewards, penalties = compute_epoch_reward_deltas(active, ATTESTERS.get(e, []))
    await db.apply_epoch_validator_updates(
        rewards, penalties, activated=activated, exited=exited,
        activation_epoch=e, max_effective_balance=MAX_EFFECTIVE_BALANCE, enforce=True)


async def _forward(db, deposit_imports):
    """Simulate a node's forward path: seed genesis, apply the given deposit imports (each at its
    own block epoch, via the live register), then drain the finalized epoch loop 0..FINALIZED."""
    await db.seed_genesis_validators(GENESIS)
    for imp in deposit_imports:  # (block_epoch, stake)
        await db.register_pending_validator(
            V, "vv", imp[1], activation_epoch=imp[0] + ACTIVATION_DELAY_EPOCHS)
    await db.connection.commit()
    for e in range(FINALIZED + 1):
        await _run_epoch(db, e)
    await db.connection.commit()


@pytest.mark.asyncio
async def test_reconstruction_equals_clean_forward_and_heals_orphan_divergence():
    canonical_ops = [{"epoch": CANON_DEP_EPOCH, "tx_id": DEP_TX, "type": "deposit",
                      "address": V, "public_key": "vv", "stake": "50000"}]

    # (1) Clean forward node — V's deposit only ever seen canonically at epoch 3.
    clean, p_clean = await _new_db()
    # Orphan forward node — saw V at epoch 1 (orphan) then epoch 3 (reflush → top-up).
    orphan, p_orphan = await _new_db()
    # Reconstruction target DB.
    rebuilt, p_rebuilt = await _new_db()
    try:
        await _forward(clean, [(CANON_DEP_EPOCH, "50000")])
        await _forward(orphan, [(1, "50000"), (CANON_DEP_EPOCH, "50000")])

        clean_snap = await _snapshot(clean)
        orphan_snap = await _snapshot(orphan)

        # BUG: the orphan history diverges (frozen early activation + double-counted stake).
        assert orphan_snap != clean_snap
        assert orphan_snap[V][1] != clean_snap[V][1]        # activation_epoch differs (5 vs 7)
        assert orphan_snap[V][3] != clean_snap[V][3]        # stake differs (100000 vs 50000)
        assert clean_snap[V][1] == CANON_ACT and clean_snap[V][3] == "50000"

        # EQUIVALENCE: reconstruction from canonical ops == the clean forward result.
        await reconstruct_validators_state(
            rebuilt, genesis_validators=GENESIS, canonical_ops=canonical_ops,
            attesters_by_epoch=ATTESTERS, finalized_epoch=FINALIZED)
        assert await _snapshot(rebuilt) == clean_snap

        # CONVERGENCE: reconstructing ON the divergent orphan DB heals it to the canonical result.
        await reconstruct_validators_state(
            orphan, genesis_validators=GENESIS, canonical_ops=canonical_ops,
            attesters_by_epoch=ATTESTERS, finalized_epoch=FINALIZED)
        assert await _snapshot(orphan) == clean_snap

        # IDEMPOTENT: a second reconstruction is a no-op.
        await reconstruct_validators_state(
            orphan, genesis_validators=GENESIS, canonical_ops=canonical_ops,
            attesters_by_epoch=ATTESTERS, finalized_epoch=FINALIZED)
        assert await _snapshot(orphan) == clean_snap
    finally:
        for db, p in ((clean, p_clean), (orphan, p_orphan), (rebuilt, p_rebuilt)):
            await db.connection.close()
            os.remove(p)


@pytest.mark.asyncio
async def test_reconstruction_dedups_reorg_replayed_deposit():
    """A canonical-ops list that accidentally carries the SAME deposit tx twice (e.g. a reorg
    re-enumeration) must NOT double-count — dedup by tx_id keeps stake single."""
    rebuilt, p = await _new_db()
    dup_ops = [
        {"epoch": CANON_DEP_EPOCH, "tx_id": DEP_TX, "type": "deposit",
         "address": V, "public_key": "vv", "stake": "50000"},
        {"epoch": 1, "tx_id": DEP_TX, "type": "deposit",  # same tx, orphan epoch — must be ignored
         "address": V, "public_key": "vv", "stake": "50000"},
    ]
    try:
        await reconstruct_validators_state(
            rebuilt, genesis_validators=GENESIS, canonical_ops=dup_ops,
            attesters_by_epoch=ATTESTERS, finalized_epoch=FINALIZED)
        snap = await _snapshot(rebuilt)
        assert snap[V][3] == "50000"          # stake single, not doubled
        assert snap[V][1] == CANON_ACT        # canonical activation (first occurrence, epoch 3)
    finally:
        await rebuilt.connection.close()
        os.remove(p)
