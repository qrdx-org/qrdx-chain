"""
Atomic EVM block-section apply / validate (E-D3b).

The account/EVM analog of ``qrdx.exchange.block_processor.apply_block_exchange_section``.
This is the consensus enforcement an importing node runs before accepting a
block's EVM section, and the same routine the proposer uses to execute the
section it is about to declare a root for. It is the linchpin that makes the
EVM "execute-on-mine" flip safe: a block whose ``account_state_root`` does not
match the deterministic replay is REJECTED with local state left untouched.

Why this is safe without coordinating every scattered ``conn.commit()``:

  * ``account_state`` (and ``contract_storage``) has a **single writer**:
    ``ContractStateManager.commit()``. The mid-execution ``conn.commit()`` calls
    on the shared connection (balance-sync registry, balance-change audit,
    content-addressed contract_code) never write the consensus tables, so they
    cannot persist a rejected block's account changes.
  * Execution runs with ``defer_commit=True`` so successful txs accumulate only
    in the EVM cache.
  * The block boundary is a single flush-read-decide on one connection:
      1. ``commit(block_height, flush_only=True)`` writes the dirty rows but does
         NOT ``conn.commit()`` and keeps the dirty sets / snapshots.
      2. ``db.get_account_state_root()`` reads those same-connection,
         not-yet-committed rows and computes the canonical BLAKE3-512 root.
      3. match  → ``conn.commit()`` (persist) and clear the cache bookkeeping.
         mismatch → ``conn.rollback()`` (discard the flushed rows) + cache
         ``revert`` to the block-start snapshot (which also removes accounts
         *created* during the rejected block).

The executor is injected (``execute_tx``) rather than imported, because EVM
execution needs the live py-evm executor + state manager wired in the node; the
exchange equivalent could call its pure state manager directly. Injection also
keeps this module unit-testable with a lightweight fake executor.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, List, Optional, Tuple

from .evm_mempool import parse_eth_raw_tx
from .state import ContractStateManager

# execute_tx(raw_tx_hex, block_height, block_hash, block_timestamp) -> result dict
#   The callable MUST execute the tx with deferred commit (changes stay in the
#   ContractStateManager cache, not flushed to the DB).
ExecuteTx = Callable[[str, int, str, int], Awaitable[Optional[dict]]]


async def produce_block_evm_section(
    block_height: int,
    block_hash: str,
    block_timestamp: int,
    raw_txs: Optional[List[str]],
    db: Any,
    state_manager: ContractStateManager,
    execute_tx: ExecuteTx,
) -> Tuple[Optional[str], List[str]]:
    """
    Proposer-side execution of a block's EVM section (E-D3b).

    The symmetric counterpart of ``apply_block_evm_section``: the proposer
    executes the selected txs to obtain the ``account_state_root`` it will declare
    in the block. So the proposer ships exactly what an importer would accept, the
    flush-read-**commit** here is byte-identical to the importer's
    flush-read-**decide**, just without a pre-declared root to compare against.

    On ANY tx that cannot execute, the whole section is reverted and dropped
    (returns ``(None, [])``) so the proposer ships a block *without* an EVM section
    rather than one importers would reject — mirroring the exchange proposer's
    "drop the section rather than ship a bad block" policy.

    Returns ``(account_state_root, included_raw_txs)``. When no section is
    produced, returns ``(None, [])`` and local state is untouched.
    """
    if not raw_txs:
        return None, []

    block_snap = await state_manager.snapshot()
    try:
        for i, raw in enumerate(raw_txs):
            res = await execute_tx(raw, block_height, block_hash, block_timestamp)
            if res is None or res.get("tx_hash") is None:
                await state_manager.revert(block_snap)
                return None, []
    except Exception:
        await state_manager.revert(block_snap)
        return None, []

    await state_manager.commit(block_height, flush_only=True)
    root = await db.get_account_state_root()
    await db.connection.commit()
    state_manager._dirty_accounts.clear()
    state_manager._dirty_storage.clear()
    state_manager._snapshots.clear()
    return root, list(raw_txs)


async def apply_block_evm_section(
    block_height: int,
    block_hash: str,
    block_timestamp: int,
    raw_txs: Optional[List[str]],
    declared_state_root: Optional[str],
    db: Any,
    state_manager: ContractStateManager,
    execute_tx: ExecuteTx,
) -> Tuple[bool, str]:
    """
    Securely validate and apply a block's EVM section on import (E-D3b).

    Steps (mirrors the exchange D3 enforcement):
      1. **Authenticate first** — recover the sender of every tx via
         ``parse_eth_raw_tx`` BEFORE touching state; a forged/typed/malformed tx
         rejects the whole block so a proposer cannot smuggle unverifiable txs.
      2. **Require a declared root** — a section with no ``account_state_root`` is
         unverifiable and rejected.
      3. **Execute deterministically** under a block-start cache snapshot, with
         each tx deferring its commit.
      4. **Flush-read-decide** — flush the cache, read the canonical root, and on
         any mismatch ``rollback`` the DB + ``revert`` the cache so a rejected
         block leaves local state untouched.
      5. **Commit on success.**

    An empty/absent section is a no-op success.

    Returns ``(ok, error)``. On ``False`` the block MUST be rejected and local
    EVM/account state is unchanged.
    """
    if not raw_txs:
        return True, ""

    if not declared_state_root:
        return False, "evm section present but block declares no account_state_root"

    # 1. Authenticate every tx before mutating any state.
    for i, raw in enumerate(raw_txs):
        try:
            parse_eth_raw_tx(raw)
        except Exception as e:  # ValueError on malformed/forged/typed tx
            return False, f"evm tx {i} in block {block_height} failed verification: {e}"

    # 2. Block-start snapshot (revert point for reject-on-mismatch).
    block_snap = await state_manager.snapshot()

    # 3. Replay deterministically, deferring per-tx commits.
    try:
        for i, raw in enumerate(raw_txs):
            res = await execute_tx(raw, block_height, block_hash, block_timestamp)
            # A tx that *reverts* (out of gas / EVM revert) is still validly
            # included and still mutates state (nonce/gas); the root comparison
            # below — not per-tx success — is the authoritative gate. Only a hard
            # inability to run the tx (None / no tx_hash) indicates a node that
            # cannot validate the block, so we conservatively reject.
            if res is None or res.get("tx_hash") is None:
                await state_manager.revert(block_snap)
                err = res.get("error") if isinstance(res, dict) else "no result"
                return False, f"evm tx {i} in block {block_height} could not execute: {err}"
    except Exception as e:
        await state_manager.revert(block_snap)
        return False, f"evm execution raised in block {block_height}: {e}"

    # 4. Flush-read-decide on a single connection (no competing commit here).
    await state_manager.commit(block_height, flush_only=True)
    computed_root = await db.get_account_state_root()
    if computed_root != declared_state_root:
        await db.connection.rollback()      # discard the flushed (uncommitted) rows
        await state_manager.revert(block_snap)  # discard cache + created accounts
        return False, (
            f"account_state_root mismatch at block {block_height}: "
            f"declared {declared_state_root[:16]}..., computed {computed_root[:16]}..."
        )

    # 5. Accept: persist atomically and discard the revert bookkeeping.
    await db.connection.commit()
    state_manager._dirty_accounts.clear()
    state_manager._dirty_storage.clear()
    state_manager._snapshots.clear()
    return True, ""
