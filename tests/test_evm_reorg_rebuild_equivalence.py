"""
Reorg-safety (EVM/account path): the account-state REBUILD must reproduce the SAME state as
incremental forward application, byte-for-byte — the EVM analog of
tests/test_reorg_rebuild_equivalence.py (which caught the exchange rebuild's missing
enforce_spot_settlement flag).

A node that never reorgs builds account_state by INCREMENTAL forward application: seed the
genesis allocations once, then apply_block_evm_section per block. A node that reorgs instead
CLEARS account_state and runs rebuild_account_state_from_chain — clear + reseed genesis +
produce_block_evm_section for every canonical block. For the SAME canonical chain the two must
yield the identical account_state root, or a reorged node diverges from the network at equal tip.

This drives BOTH paths over one deterministic chain (no network, no reorg timing) and asserts
the roots match. It covers the two things a rebuild can get wrong that the per-block
produce↔apply round-trip test does NOT: (a) the genesis reseed — a genesis-only account, never
touched by any EVM tx, must survive the clear+rebuild; (b) full-chain replay ordering.
  * FAIL → a real determinism bug in the account rebuild (root cause, right here).
  * PASS → the account rebuild is equivalent to forward apply (closes the reorg-safety class).
"""
import json
import os
import tempfile

from eth_account import Account as EthAccount
from eth_utils import to_checksum_address

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.contracts.state import ContractStateManager
from qrdx.contracts.evm_block_apply import (
    apply_block_evm_section, produce_block_evm_section, rebuild_account_state_from_chain,
)


def _raw(i, nonce=0, value=1):
    """A validly-signed legacy EVM tx from key i (parse_eth_raw_tx accepts it)."""
    key = "0x" + f"{i:064x}"
    acct = EthAccount.from_key(key)
    tx = {"nonce": nonce, "gasPrice": 10 ** 9, "gas": 21000,
          "to": acct.address, "value": value, "data": b"", "chainId": 1}
    signed = EthAccount.sign_transaction(tx, key)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    return "0x" + bytes(raw).hex(), to_checksum_address(acct.address)


def _executor(sm, credit):
    """Deterministic fake executor (defer_commit semantics): sets the sender's cached balance
    to `credit`. Identical on both the forward and rebuild paths, so any root divergence is
    the rebuild ORCHESTRATION (genesis reseed / replay), not execution."""
    async def execute_tx(raw_tx_hex, block_height, block_hash, block_timestamp):
        from qrdx.contracts.evm_mempool import parse_eth_raw_tx
        p = parse_eth_raw_tx(raw_tx_hex)
        sender = to_checksum_address(p["sender"])
        acc = await sm.get_account(sender)
        acc.balance = credit
        acc.nonce = int(p["nonce"]) + 1
        await sm.set_account(acc)
        return {"success": True, "tx_hash": p["tx_hash"], "sender": sender,
                "nonce": p["nonce"], "created_address": None}
    return execute_tx


async def _add_block(db, height, evm_section=None, genesis_alloc=None):
    bh = f"{height:064x}"
    await db.add_block(block_hash=bh, block_height=height, block_content="",
                       validator_address="0xPQ" + "00" * 32, timestamp=1_700_000_000 + height)
    if genesis_alloc:
        for i, (recipient, amount) in enumerate(genesis_alloc):
            await db.add_transaction(
                tx_hash=f"alloc-{i}-{recipient[:10]}",
                tx_hex=json.dumps({"type": "genesis_allocation", "recipient": recipient,
                                   "amount": str(amount)}),
                block_hash=bh)
    if evm_section:
        await db.add_block_evm_txs(bh, evm_section)
    return bh


async def test_evm_account_rebuild_equals_forward_apply():
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        # Actors: A, B are touched by EVM txs; C is a GENESIS-ONLY account (must survive rebuild).
        raw_a1, addr_a = _raw(101, nonce=0)
        raw_b1, addr_b = _raw(102, nonce=0)
        raw_a2, _ = _raw(101, nonce=1)
        _, addr_c = _raw(103)  # never sends a tx — genesis allocation only

        # Genesis (block 0) funds A, B, C; blocks 1-3 carry EVM sections.
        await _add_block(db, 0, genesis_alloc=[(addr_a, "500000"), (addr_b, "500000"),
                                               (addr_c, "777")])
        await _add_block(db, 1, evm_section=[raw_a1])
        await _add_block(db, 2, evm_section=[raw_b1, raw_a2])
        await _add_block(db, 3, evm_section=[])  # empty section (no-op) in the middle

        CREDIT = 4242

        # ── Forward path: seed genesis once, then build each block incrementally (no clear).
        # A non-reorg node builds account_state this way (produce↔apply agree per block —
        # test_proposer_produce_then_importer_apply_agree — so produce here stands for both). ──
        await db.seed_genesis_account_state()
        await db.connection.commit()
        sm_f = ContractStateManager(db)
        for h in range(0, 4):
            section = await db.get_block_evm_txs(f"{h:064x}")
            if not section:
                continue
            await produce_block_evm_section(h, f"{h:064x}", 0, section, db, sm_f, _executor(sm_f, CREDIT))
        await db.connection.commit()
        fwd_root = await db.get_account_state_root()

        # ── Rebuild path: clear + reseed genesis + produce every canonical block. The executor
        # MUST mutate the SAME manager the rebuild flushes (the real caller passes one shared
        # EVM_STATE_MANAGER — the deferred executor closes over it). ──
        sm_r = ContractStateManager(db)
        rebuild_root = await rebuild_account_state_from_chain(db, sm_r, _executor(sm_r, CREDIT))

        assert rebuild_root == fwd_root, (
            f"account rebuild diverges from forward apply: forward={fwd_root[:16]} "
            f"rebuild={rebuild_root[:16]}")

        # And the genesis-only account C survived the clear+rebuild with its exact balance.
        cur = await db.connection.execute(
            "SELECT balance FROM account_state WHERE LOWER(address) = LOWER(?)", (addr_c,))
        row = await cur.fetchone()
        assert row is not None, "genesis-only account was dropped by the rebuild"
        assert int(row[0]) == 777 * 10 ** 18, "genesis-only balance wrong after rebuild"
    finally:
        await db.close()
        os.remove(path)
