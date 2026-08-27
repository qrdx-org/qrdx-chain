"""
Item 3 — the consensus `validators` DYNAMIC state is not reorg-reconstructed, so a DEPOSITED
validator diverges across nodes with different reorg histories.

Every OTHER consensus-bound domain is reset + replayed from the canonical chain on reorg — the
token ledger, account state, and exchange state each have a `rebuild_*_from_chain`. The
`validators` table does NOT: `flush_validator_lifecycle_deltas` (register_pending_validator /
mark_validator_exiting) runs only on the LIVE import path, and `rebuild_exchange_state_from_chain`
never re-derives it. So the table simply RETAINS whatever a node's actual import history applied —
a STAKE_DEPOSIT first seen on an ORPHANED block (one epoch) then canonically included at a DIFFERENT
epoch leaves the orphan's activation schedule frozen, and a live re-flush on reorg TOPS UP the stake
(register_pending_validator adds to an existing row) → double count. Final state depends on reorg
history, not purely the canonical chain.

The control test proves genesis validators converge (the harness distinguishes the bug from noise).
The divergence test is xfail(strict) until the fix lands: a reorg-reconstructed validators domain
(reset to the genesis base + replay canonical STAKE_DEPOSIT/EXIT deduped by tx-id + re-run finalized
epoch processing), the same shape as rebuild_exchange_state_from_chain / rebuild_account_state_from_chain.
"""
import os
import tempfile

import pytest

from qrdx.constants import ACTIVATION_DELAY_EPOCHS
from qrdx.database_sqlite import DatabaseSQLite

D = ACTIVATION_DELAY_EPOCHS
V_ADDR = "0xPQdepositor00000000000000000000000000000000000000000000000000000001"
V_PK = "de" * 32
STAKE = "50000"


async def _new_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(path)
    # Genesis validator, seeded identically on every node (active, activation_epoch=0).
    await db.connection.execute(
        "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
        "activation_epoch) VALUES ('0xPQgenesis0001', 'aa', '100000', '100000', 'active', 0)")
    await db.connection.commit()
    return db, path


async def _row(db, addr):
    c = await db.connection.execute(
        "SELECT status, activation_epoch, exit_epoch, stake, effective_stake "
        "FROM validators WHERE address = ?", (addr,))
    return await c.fetchone()


async def _close(db, path):
    await db.connection.close()
    os.remove(path)


@pytest.mark.asyncio
async def test_genesis_validator_converges_across_histories():
    """CONTROL: the genesis validator's state is import-history-independent (seeded identically),
    so two nodes agree on it regardless of reorgs. Proves the comparison harness is sound."""
    a, pa = await _new_db()
    b, pb = await _new_db()
    try:
        assert await _row(a, "0xPQgenesis0001") == await _row(b, "0xPQgenesis0001")
    finally:
        await _close(a, pa)
        await _close(b, pb)


@pytest.mark.xfail(strict=True, reason="item 3: validators dynamic state is not reorg-reconstructed")
@pytest.mark.asyncio
async def test_deposited_validator_converges_across_histories():
    """A STAKE_DEPOSIT for V is canonically included at epoch 8. Two nodes with different reorg
    histories of the SAME canonical chain MUST end with identical V state — but today they don't.

    Node A saw V's deposit first on an ORPHAN block at epoch 7 (register act=7+D), then the chain
    reorged and the canonical epoch-8 inclusion was re-flushed live (register again → TOP-UP: stake
    doubles, activation_epoch stays frozen at 7+D). Node B only ever saw the canonical epoch-8
    inclusion (register act=8+D, stake once). With no reorg reconstruction the two diverge; the fix
    must make them converge to the canonical result (epoch-8 schedule, single stake)."""
    a, pa = await _new_db()
    b, pb = await _new_db()
    try:
        # Node A: orphan (epoch 7) then canonical re-flush (epoch 8) → top-up.
        await a.register_pending_validator(V_ADDR, V_PK, STAKE, activation_epoch=7 + D)
        await a.register_pending_validator(V_ADDR, V_PK, STAKE, activation_epoch=8 + D)
        await a.connection.commit()
        # Node B: canonical only (epoch 8).
        await b.register_pending_validator(V_ADDR, V_PK, STAKE, activation_epoch=8 + D)
        await b.connection.commit()

        assert await _row(a, V_ADDR) == await _row(b, V_ADDR)
    finally:
        await _close(a, pa)
        await _close(b, pb)
