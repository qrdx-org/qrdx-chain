"""
Fork choice: rolling back, reorganizing, resolving a fork against a peer's chain, and
the periodic reconciliation pass.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import asyncio
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from qrdx.logger import get_logger
from qrdx.node import (
    block_import as _import,
    chain_identity as _identity,
    derived_state as _derived,
    main as _node,
    sync as _sync,
)
from qrdx.node.nodes_manager import NodeInterface, NodesManager
from qrdx.node.observability import METRICS
from qrdx.transactions import CoinbaseTransaction

logger = get_logger(__name__)

# Finality reorg guard (link 5): refuse reorgs that would roll back below the
# irreversibly finalized block height. Enabled after observe-mode showed
# legitimate reorgs never cross finality (0 crossings; deterministic boundary).
_ENFORCE_FINALITY_REORG_GUARD = True

# Fork-choice mechanism-2 (equal-height tie-break). When a competing block arrives
# at the just-filled tip (same parent, different hash) and WINS the lowest-hash
# canonical rule, the p2p path rolls back the losing tip + rebuilds derived state
# (via _tiebreak_rollback) then re-accepts the winner — converging block history to
# one canonical block per height (the RANDAO-selection gate). Observe-first: with
# this False the p2p path only logs the comparison and keeps the stored block.
#
# KEPT OBSERVE — enforce soak (6 runs) showed reactive local replacement DOES NOT
# converge block history: 4/6 runs still ended with 2 RANDAO mixes (incl. runs where
# 3-4 replacements fired but the fork persisted, one that raised broken links to 2),
# and one run failed a scenario. ROOT CAUSE (design limitation, not a bug): on-receipt
# rollback+replace only converges nodes that actually RECEIVE the winning block — a
# node that only ever saw the losing fork never triggers the tie-break, so the fork
# persists network-wide. Global convergence needs ACTIVE reconciliation (gossip the
# canonical per-height choice, or a periodic fork-choice pass that pulls + adopts the
# lowest-hash block at contested heights), not passive replacement. The gated
# implementation stays for that future approach. See FORK_CHOICE_CONVERGENCE.md.
_ENFORCE_EQUAL_HEIGHT_TIEBREAK = False

# Fork-choice mechanism-2 via ACTIVE reconciliation (the redirect from the failed
# passive soak above). A periodic, all-nodes pass that PULLS peers' block hash at each
# recent unfinalized height, computes the deterministic canonical choice (lowest hash),
# and — where the local block is not the canonical one — reorgs onto the peer holding
# the winning chain (reusing the longest-chain reorg machinery). Unlike passive
# replacement this converges every node, because every node actively queries regardless
# of what it received. Observe-first: with this False the pass only MEASURES divergence
# + logs the would-be canonical choice and a RANDAO-mix convergence probe; it never
# rolls back. Never reconciles below the finalized height (the reorg guard). See the
# active-reconciliation redirect in FORK_CHOICE_CONVERGENCE.md.
#
# ENABLED (2026-09-28) with the enforce path now wired. Root cause confirmed from
# preserved soak databases: competing blocks at one height share a PARENT but come from
# ADJACENT SLOTS — e.g. h=66 held slot 72's block on one node and slot 73's on another,
# each signed by its own slot's legitimately-eligible proposer. Both are valid, so
# eligibility cannot reject either, and with a 2s slot the next proposer routinely builds
# before the previous block propagates. Nothing broke the tie, so the fork was permanent
# (19 differing block hashes between two nodes in a 20-reorg soak, with the token ledger
# splitting three ways). See "Block history did not converge" in docs/KNOWN_ISSUES.md.
# The enforce path was a stub ("intentionally not wired yet"), so flipping this flag did
# nothing. Once implemented, it was first kept OBSERVE because no soak with it alone was
# clean:
#
#   soak                      reorgs  worst block divergence  derived state  scenarios
#   baseline (observe)          20            19              3-way split      FAIL
#   rollback only               29            12              node1 wrecked    pass
#   via _sync_blockchain        10            22              converged        pass
#   rollback + fetch            25             7              converged        FAIL
#
# Divergence improves (19 → 7) and derived state converges, but reorg counts swing 10-29
# between runs, so the scenario failures cannot be separated from churn. More runs at a
# controlled churn level are needed before this can be judged.
#
# ENABLED (2026-09-29). Alone it did not converge (the A/Bs above), because nodes kept
# appending blocks onto parents they did not hold — the p2p path never enforced parent
# continuity (it called the checker without `enforce`). With continuity now enforced on
# every path, the two together drove worst pairwise block divergence to 0 in all three
# fault-injecting soaks (vs 4-5 observe), and this path logged real convergences (2-6 per
# run) where every earlier version logged none. See _ENFORCE_PARENT_CONTINUITY above and
# docs/KNOWN_ISSUES.md. Env-overridable (=0) for A/B testing only.
_ENFORCE_FORK_CHOICE_RECONCILE = os.getenv(
    "QRDX_ENFORCE_FORK_CHOICE_RECONCILE", "1"
).lower() not in ("0", "false", "no")
# How many recent heights (down from the tip) the active pass inspects per cycle. Forks
# are tip-local (block-time ≈ propagation-time), so a bounded window catches them while
# keeping the per-cycle peer-query cost small. Clamped to the finalized boundary.
_FORK_CHOICE_WINDOW = 24


async def _tiebreak_rollback(block_no: int) -> None:
    """Fork-choice mechanism-2: roll back the losing block at the contested tip
    (height ``block_no``) and rebuild derived state to ``block_no - 1``, so the
    p2p path can then re-accept the lowest-hash-winning competing block at that
    height via its normal validated flow. Holds the block-processing lock at the
    call site (p2p.submitBlock)."""
    await _node.db.remove_blocks(block_no)
    await _derived._rebuild_derived_state_after_rollback()
    logger.warning(
        "[fork-choice ENFORCE] rolled back contested tip h=%d for equal-height replacement",
        block_no,
    )


async def handle_reorganization(
    node_interface: NodeInterface, local_height: int, search_from: Optional[int] = None
):
    """Handles blockchain reorganization with proper validation.

    ``local_height`` is the local tip: everything above the common ancestor up to it is
    rolled back and its transactions re-queued. ``search_from`` is where the common-ancestor
    search starts (default: the local tip). Fork-choice reconciliation passes the divergence
    height, because the peer holding the canonical block can be SHORTER than the local
    chain — searching from the local tip asked it for a block it did not have, and the
    reorg aborted ("Could not get remote block"). That was 18 of the 24 failed
    reconciliations across three soaks."""
    METRICS.inc("qrdx_reorgs_total")
    logger.warning(
        f"[REORG] Fork detected! Starting reorganization process from local height {local_height}."
    )

    last_common_block_id = -1
    check_height = local_height if search_from is None else min(local_height, int(search_from))

    # Find the last common block
    while check_height >= 0:
        local_block = await _node.db.get_block_by_id(check_height)
        if not local_block:
            logger.error(
                f"[REORG] Error: Could not retrieve local block at height {check_height}. Halting search."
            )
            break

        try:
            remote_block_info = await node_interface.get_block(str(check_height))
            if remote_block_info and remote_block_info.get("ok"):
                remote_hash = remote_block_info["result"]["block"]["hash"]
                if remote_hash == local_block["hash"]:
                    last_common_block_id = check_height
                    logger.info(
                        f"[REORG] Found common ancestor at block height: {last_common_block_id}"
                    )
                    break
            else:
                logger.warning(
                    f"[REORG] Could not get remote block at height {check_height}. Aborting search."
                )
                return None

        except httpx.RequestError:
            logger.warning(
                "[REORG] Peer became unreachable during common ancestor search. Aborting."
            )
            # Let the caller handle the peer removal.
            return None

        except Exception as e:
            logger.error(
                f"[REORG] Network error while finding common ancestor at height {check_height}: {e}"
            )
            return None

        if (local_height - check_height) > 200:
            logger.warning("[REORG] Reorganization depth exceeds 200 blocks. Aborting for safety.")
            return None

        check_height -= 1

    if last_common_block_id == -1:
        logger.warning(
            "[REORG] Could not find a common ancestor. Local chain appears invalid. Will perform a full rollback."
        )
    return await _rollback_to(last_common_block_id, local_height)


@asynccontextmanager
async def _block_lock(held: bool):
    """block_processing_lock, unless the caller already holds it (asyncio locks don't nest)."""
    if held:
        yield
    else:
        async with _node.block_processing_lock:
            yield


async def _rollback_to(
    last_common_block_id: int, local_height: int, *, lock_held: bool = False
) -> Optional[int]:
    """Roll the chain back to ``last_common_block_id``: re-queue the orphaned blocks'
    transactions, refuse if that would cross the finalized checkpoint, remove the blocks and
    rebuild derived state under the block-processing lock (``lock_held``: the caller holds it).
    Returns the new tip, or None when the finality guard refuses."""
    logger.info(
        f"[REORG] Collecting transactions from orphaned blocks between {last_common_block_id + 1} and {local_height}."
    )
    orphaned_txs = []
    orphaned_exchange_sections = []
    orphaned_evm_sections = []
    for height in range(last_common_block_id + 1, local_height + 1):
        block = await _node.db.get_block_by_id(height)
        if block:
            block_txs = await _node.db.get_block_transactions(block["hash"], hex_only=False)
            orphaned_txs.extend([tx for tx in block_txs if not isinstance(tx, CoinbaseTransaction)])
            # Capture orphaned exchange sections so their txs can be re-queued.
            try:
                section = await _node.db.get_block_exchange_txs(block["hash"])
                if section:
                    orphaned_exchange_sections.append(section)
            except Exception:
                pass
            # Capture orphaned EVM sections so their txs can be re-queued (E-D3b).
            try:
                evm_sec = await _node.db.get_block_evm_txs(block["hash"])
                if evm_sec:
                    orphaned_evm_sections.append(evm_sec)
            except Exception:
                pass

    # Finality guard (link 5 — ENFORCED): a reorg must never roll back below an
    # irreversibly finalized block (≥2/3 stake attested at least that deep).
    # Refusing such a reorg bounds reorg depth to the finality lag and rejects any
    # peer chain that conflicts with finality. Enabled after observe-mode soak
    # showed legitimate reorgs never cross finality (0 crossings, deterministic
    # boundary across nodes). Gated for revertibility.
    if _ENFORCE_FINALITY_REORG_GUARD:
        try:  # finality, or a trusted checkpoint above it (qrdx/checkpoints.py)
            from ..checkpoints import reorg_floor

            _final_h = await reorg_floor(_node.db)
        except Exception as e:
            logger.debug(f"[REORG] finality guard check skipped: {e}")
            _final_h = -1
        if _final_h >= 0 and last_common_block_id < _final_h:
            logger.error(
                f"[REORG][finality] REFUSING reorg: would roll back to "
                f"{last_common_block_id}, below finalized height {_final_h}. The "
                f"peer chain conflicts with finality (>1/3 stake would have "
                f"equivocated) — keeping our finalized chain."
            )
            return None  # caller aborts the sync cycle; local finalized chain kept

    logger.info(f"[REORG] Rolling back local chain to block {last_common_block_id}.")
    # Serialize the rollback + derived-state rebuild under the block-processing lock
    # (the same one the forward-sync apply loop and every import/propose path hold), so
    # the multi-step reseed→reflush is atomic w.r.t. a concurrent block on a busy node.
    # The ancestor search above stays OUTSIDE the lock (it does network I/O).
    async with _block_lock(lock_held):
        await _node.db.remove_blocks(last_common_block_id + 1)
        # E-D3b + Phase E reorg safety: rebuild all derived state (account/EVM, token
        # ledger, exchange) from the canonical blocks up to the rolled-back tip. Shared
        # with the equal-height tie-break path.
        await _derived._rebuild_derived_state_after_rollback()

    logger.info(f"[REORG] Re-adding {len(orphaned_txs)} orphaned transactions to the pending pool.")
    for tx in orphaned_txs:
        try:
            await _node.security.transaction_pool.add_transaction(tx.hash(), tx, _node.db)
        except Exception as e:
            logger.error(f"[REORG] Could not re-add orphaned transaction {tx.hash()}: {e}")

    # Re-queue orphaned exchange txs to the exchange mempool (re-verified on admit)
    # so they can be re-included on the new canonical chain.
    if orphaned_exchange_sections:
        try:
            from ..exchange.block_processor import decode_exchange_txs

            mp = _node._get_exchange_mempool()
            requeued = 0
            for section in orphaned_exchange_sections:
                for tx in decode_exchange_txs(section):
                    ok, _err = mp.admit(tx)
                    if ok:
                        requeued += 1
            logger.info(f"[REORG] Re-queued {requeued} orphaned exchange tx(s)")
        except Exception as e:
            logger.error(f"[REORG] Could not re-queue orphaned exchange txs: {e}")

    # Re-queue orphaned EVM txs to the EVM mempool (re-verified on admit) so they
    # can be re-included on the new canonical chain (E-D3b).
    if orphaned_evm_sections:
        try:
            from ..contracts.evm_block import decode_evm_txs

            mp = _node._get_evm_mempool()
            requeued = 0
            for section in orphaned_evm_sections:
                for raw in decode_evm_txs(section):
                    ok, _err, _h = mp.admit(raw)
                    if ok:
                        requeued += 1
            logger.info(f"[REORG] Re-queued {requeued} orphaned EVM tx(s)")
        except Exception as e:
            logger.error(f"[REORG] Could not re-queue orphaned EVM txs: {e}")

    return last_common_block_id


# Fork resolution (resolve_fork_with_peer): how far back a competing branch is looked for, and
# how many of its blocks are fetched. Deeper forks are below finality or are a stale node,
# which ordinary sync handles.
_FORK_SEARCH_DEPTH = 256
_FORK_FETCH_LIMIT = 1024
_fork_resolution_lock = asyncio.Lock()
_fork_resolutions_pending: Set[str] = set()


def _transfer_parent(block_info: dict) -> Optional[str]:
    """The parent hash a block declares, as peers transfer it (None if unreadable)."""
    from ..validator.block_verification import _parse_block_content

    try:
        b = block_info["block"]
        return _parse_block_content(b.get("content") or b.get("block_content")).get("parent_hash")
    except Exception:
        return None


def _parse_transfer_block(block_info: dict) -> Optional[Tuple[int, str, int, list]]:
    """(height, hash, slot, attestations) of a block as peers transfer it (fork-choice
    scoring), or None if it cannot be read — or if the hash it was sent under is not its
    header's (a branch is scored by its hashes; the import verifies everything else)."""
    from ..validator.attestation_block import extract_attestations_from_dict
    from ..validator.block_verification import _parse_block_content, reconstruct_signing_root

    try:
        b = block_info["block"]
        bc = _parse_block_content(b.get("content") or b.get("block_content"))
        claimed = str(b.get("hash") or b.get("block_hash") or "")
        if claimed.lower().removeprefix("0x") != reconstruct_signing_root(bc).hex():
            return None
        return (
            int(b.get("id", b.get("block_height"))),
            claimed,
            int(bc["slot"]),
            extract_attestations_from_dict(bc),
        )
    except Exception:
        return None


async def resolve_fork_with_peer(peer_id: str, reason: str = "") -> bool:
    """Fork choice against one peer, applied at once (qrdx/validator/ffg.py ``prefer``: the
    newest justified checkpoint, then height, then the lower tip hash).

    1. Find the common ancestor from one exchange of block hashes (never below the finalized
       checkpoint, never deeper than _FORK_SEARCH_DEPTH).
    2. Fetch the peer's branch above it and score it from its own blocks — the justification
       its votes give it — never from what the peer claims.
    3. Only if it wins: roll back to the ancestor and apply it, block by block, under the import
       rules. If one of its blocks is refused, roll back again and restore our own branch.

    It used to happen only in a pass every ~8 s, by rules that disagreed (sync took the longer
    chain, the reconcile pass the lower hash at the first divergent height). At sub-second slots
    a node spent dozens of slots on a losing branch. Returns True if this node moved."""
    if _fork_resolution_lock.locked() or _node.security.sync_state_manager.is_syncing:
        return False
    peer = NodesManager.get_peer(peer_id)
    if not peer or not peer.get("url"):
        return False
    from ..validator import ffg

    async with _fork_resolution_lock:
        iface = NodeInterface(peer["url"], client=_node.http_client, db=_node.db)
        status = await iface.get_status()
        if not (status and status.get("ok")):
            return False
        remote = status["result"]
        if not await _identity._drop_if_incompatible(peer_id, remote.get("network"), "fork choice"):
            return False
        remote_height = int(remote.get("height", -1))
        local_height = int(await _node.db.get_next_block_id()) - 1
        local_tip = (await _node.db.get_block_hashes(local_height, local_height)).get(local_height)
        if remote_height < 0 or remote.get("last_block_hash") == local_tip:
            return False

        # 1. The common ancestor — never below finality or a trusted checkpoint.
        from ..checkpoints import reorg_floor

        final_h = await reorg_floor(_node.db)
        hi = min(local_height, remote_height)
        lo = max(0, final_h, hi - _FORK_SEARCH_DEPTH)
        resp = await iface.get_block_hashes(lo, hi)
        if not (resp and resp.get("ok")):
            return False
        theirs = {int(h): bh for h, bh in resp["result"].items()}
        ours = await _node.db.get_block_hashes(lo, hi)
        ancestor = next((h for h in range(hi, lo - 1, -1) if theirs.get(h) == ours.get(h)), None)
        if ancestor is None:
            logger.warning(
                "[fork-choice] %s diverges from us below height %d (the finalized checkpoint or "
                "the search depth) — not following it",
                peer_id[:16],
                lo,
            )
            return False
        if ancestor == local_height and remote_height > local_height:
            # Not a fork: the peer is simply ahead on our chain.
            asyncio.create_task(_sync._sync_blockchain(node_id=peer_id))
            return False

        # 2. Their branch, scored from its own blocks.
        branch: List[dict] = []
        start = ancestor + 1
        while start <= remote_height and len(branch) < _FORK_FETCH_LIMIT:
            resp = await iface.get_blocks(start, min(512, remote_height - start + 1))
            batch = resp.get("result") if resp and resp.get("ok") else None
            if not batch:
                break
            branch.extend(batch)
            start += len(batch)
        parsed = [_parse_transfer_block(b) for b in branch]
        if not branch or any(p is None for p in parsed):
            return False
        heights = [p[0] for p in parsed]  # type: ignore[index]
        if heights != list(range(ancestor + 1, ancestor + 1 + len(branch))):
            return False
        candidate = await ffg.branch_score(_node.db, ancestor, parsed)  # type: ignore[arg-type]
        current = await ffg.local_score(_node.db)
        if not ffg.prefer(candidate, current, ancestor):
            return False

        # 3. Adopt it.
        logger.warning(
            "[fork-choice] switching to %s's branch at %d (justified %d, height %d, tip %s…) "
            "from ours (justified %d, height %d, tip %s…)%s",
            peer_id[:16],
            ancestor,
            candidate[0],
            candidate[1],
            candidate[2][:16],
            current[0],
            current[1],
            current[2][:16],
            f" — {reason}" if reason else "",
        )
        from ..rpc.modules.p2p import blocks_for_transfer

        # The switch holds the block-processing lock throughout: another path (a block pushed
        # over p2p, a sync, our own proposer) must not add a block between the rollback and the
        # branch, or the branch no longer fits on top and our own cannot be restored either.
        async with _sync._adopting_peer_chain(), _node.block_processing_lock:
            now = int(await _node.db.get_next_block_id()) - 1
            if (await _node.db.get_block_hashes(now, now)).get(now) != local_tip:
                return False  # the chain moved while the branch was scored; the next block retries
            ours_saved = await blocks_for_transfer(_node.db, ancestor + 1, local_height - ancestor)
            if (
                ancestor < local_height
                and await _rollback_to(ancestor, local_height, lock_held=True) is None
            ):
                return False
            if await _apply_branch(branch, lock_held=True):
                METRICS.inc("qrdx_fork_choice_reconciles_total")
                return True
            logger.warning(
                "[fork-choice] %s's branch had a block we refuse — restoring our own", peer_id[:16]
            )
            await _node.security.reputation_manager.record_violation(
                peer_id, "invalid_fork_branch", severity=8
            )
            now = int(await _node.db.get_next_block_id()) - 1
            if now > ancestor:
                await _rollback_to(ancestor, now, lock_held=True)
            if not await _apply_branch(ours_saved, lock_held=True):
                logger.error("[fork-choice] could not restore our own branch above %d", ancestor)
            return False


async def _apply_branch(blocks: List[dict], *, lock_held: bool = False) -> bool:
    """Apply consecutive blocks on top of the tip under the sync import rules: proposer
    signatures, slot eligibility (against each block's own parent chain), parent continuity,
    slot progression and FFG votes are all enforced; E-D4 below the tip is trust-replayed."""
    async with _block_lock(lock_held):
        for block_data in blocks:
            if not await _import.process_and_create_block(block_data, is_bulk_sync=True):
                return False
            await asyncio.sleep(0)
    return True


def schedule_fork_resolution(peer_id: Optional[str], reason: str) -> None:
    """Resolve a fork with ``peer_id`` now, in the background (once per peer at a time) — called
    when a peer sends a block that does not extend our tip."""
    if not peer_id or peer_id in _fork_resolutions_pending:
        return
    _fork_resolutions_pending.add(peer_id)

    async def run() -> None:
        try:
            await resolve_fork_with_peer(peer_id, reason)
        except Exception as e:
            logger.debug(f"fork resolution with {peer_id[:16]} failed: {e}")
        finally:
            _fork_resolutions_pending.discard(peer_id)

    asyncio.create_task(run())


async def fork_choice_reconcile_pass(enforce: bool = False) -> dict:
    """
    Fork-choice mechanism-2 via ACTIVE reconciliation (Option A, pull-based).

    For each recent UNFINALIZED height (a bounded window down from the tip, never below
    the finalized boundary), PULL every peer's block hash at that height, union them
    with the local hash, and compute the deterministic canonical choice — the LOWEST
    hash (unbiasable, slot-independent, a pure function of the blocks, so every node
    agrees). At the lowest height where the local block is NOT that canonical choice the
    block history has forked; under ``enforce`` the node would reorg onto the peer
    holding the winning chain (reusing the longest-chain reorg machinery).

    Observe-first: with ``enforce=False`` this only MEASURES and logs the would-be
    canonical choice + a RANDAO-mix probe (the sharpest convergence signal — it folds
    every block's reveal, so it agrees network-wide only when block history is identical
    at every height). It never mutates state. Returns a small summary dict for the
    caller/probe. See the active-reconciliation redirect in FORK_CHOICE_CONVERGENCE.md.
    """
    summary: Dict[str, Any] = {
        "window": None,
        "diverged_at": None,
        "randao_mix": None,
        "reconciled": None,
    }
    try:
        if _node.security.sync_state_manager.is_syncing:
            return summary
        last = await _node.db.get_last_block()
        if not last:
            return summary
        tip = int(last["id"])
        try:
            from ..validator.finality import finalized_block_height

            fin = await finalized_block_height(_node.db)
        except Exception:
            fin = -1
        low = max(0, fin + 1, tip - _FORK_CHOICE_WINDOW)
        if low > tip:
            return summary
        summary["window"] = (low, tip)

        peers = [p for p in NodesManager.get_all_peers() if p.get("url")]
        # RANDAO-mix convergence probe — a chain-index lookup (qrdx/chain_index.py).
        try:
            from ..validator.randao import compute_randao_mix

            mix = await compute_randao_mix(_node.db, tip)
            mix_hex = mix.hex()[:16] if isinstance(mix, (bytes, bytearray)) else str(mix)[:16]
        except Exception:
            mix_hex = "?"
        summary["randao_mix"] = mix_hex

        if not peers:
            return summary

        # Fork choice with every peer (qrdx/validator/ffg.py prefer). Cheap when chains agree:
        # one status call per peer. The same resolver runs at once when a peer sends a block
        # that does not extend our tip (schedule_fork_resolution); this pass is the backstop.
        if not enforce:
            return summary
        for peer in peers:
            if await resolve_fork_with_peer(peer.get("node_id", ""), "fork-choice pass"):
                summary["reconciled"] = True
                summary["diverged_at"] = tip
                break
        return summary
    except Exception as e:
        logger.debug(f"fork-choice pass skipped: {e}")
        return summary
