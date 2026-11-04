"""
Chain sync: pulling blocks from peers, pushing ours to peers that are behind, the
initial-sync gate a validator waits on, and the periodic update fetcher.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import asyncio
import random
import time
import traceback
from contextlib import asynccontextmanager
from typing import Any, List, Optional

import httpx
from fastapi import HTTPException

from qrdx.constants import MAX_BATCH_BYTES, MAX_REORG_DEPTH, MAX_TX_FETCH_LIMIT, SLOT_DURATION
from qrdx.database_sqlite import DatabaseSQLite as Database
from qrdx.logger import get_logger
from qrdx.node import (
    block_import as _import,
    chain_identity as _identity,
    fork_choice as _forks,
    main as _node,
    peers as _peers,
)
from qrdx.node.nodes_manager import NodeInterface, NodesManager
from qrdx.transactions import Transaction

logger = get_logger(__name__)


async def _push_sync_to_peer(
    peer_info: dict, start_block: int, db_conn: Database, trigger_data: dict
):
    """Push missing blocks to a lagging peer with proper resource management."""
    peer_id = peer_info.get("node_id", "Unknown")
    peer_url = peer_info.get("url")
    sync_successful = False
    try:
        target_block_id = trigger_data.get("id")
        if target_block_id is None:
            logger.warning(
                f"[PUSH-SYNC] Aborted for {peer_id}: No target block ID in trigger data."
            )
            return

        logger.info(
            f"[PUSH-SYNC] Starting for {peer_id}. They need blocks from {start_block} up to (but not including) {target_block_id}."
        )

        # Pass the db object to the interface
        node_interface = NodeInterface(peer_info["url"], client=_node.http_client, db=db_conn)
        current_block_to_send = start_block

        while current_block_to_send < target_block_id:
            remaining_blocks = target_block_id - current_block_to_send
            batch_size_limit = min(MAX_REORG_DEPTH, remaining_blocks)

            structured_blocks_to_send = await db_conn.get_blocks(
                current_block_to_send, batch_size_limit
            )
            if not structured_blocks_to_send:
                logger.warning(
                    f"[PUSH-SYNC] to {peer_id} halted. Local DB has no more blocks in the required range."
                )
                sync_successful = False
                break

            payload_batch: List[Any] = []
            current_batch_bytes = 0

            for raw_block in structured_blocks_to_send:
                # db.get_blocks() returns raw row dicts — normalise into
                # the {block, transactions} structure the rest of the code expects.
                if isinstance(raw_block, dict) and "block" in raw_block:
                    block_record = raw_block["block"]
                    tx_list = raw_block.get("transactions", [])
                else:
                    block_record = raw_block
                    block_hash = block_record.get("hash") or block_record.get("block_hash")
                    try:
                        tx_list = (
                            await db_conn.get_block_transactions(block_hash, hex_only=True)
                            if block_hash
                            else []
                        )
                    except Exception:
                        tx_list = []
                block_size_estimate = len(block_record.get("content", "")) + sum(
                    len(str(tx)) for tx in tx_list
                )

                if payload_batch and current_batch_bytes + block_size_estimate > MAX_BATCH_BYTES:
                    break

                # The hash and proposer are what route a block to the PoS import path; without
                # them p2p_submitBlocks handed every pushed block to the PoW parser, which
                # failed on it, so a push-sync of a PoS chain never delivered a block.
                payload_item = {
                    "id": block_record["id"],
                    "block_content": block_record["content"],
                    "block_hash": block_record.get("hash") or block_record.get("block_hash"),
                    "validator_address": block_record.get("address")
                    or block_record.get("validator_address"),
                    "timestamp": block_record.get("timestamp"),
                    "txs": tx_list,
                }
                # Attach protocol sections so the syncing peer reconstructs
                # exchange + EVM/account state (E-D3b). Trust-replayed there.
                _bh = block_record.get("hash") or block_record.get("block_hash")
                if _bh:
                    try:
                        _ex = await db_conn.get_block_exchange_txs(_bh)
                        if _ex:
                            payload_item["exchange_transactions"] = _ex
                    except Exception:
                        pass
                    try:
                        _evm = await db_conn.get_block_evm_txs(_bh)
                        if _evm:
                            payload_item["evm_transactions"] = _evm
                    except Exception:
                        pass
                payload_batch.append(payload_item)
                current_batch_bytes += block_size_estimate

            if not payload_batch:
                logger.warning(
                    f"[PUSH-SYNC] Could not form a batch for {peer_id} without exceeding size limits. Halting."
                )
                return

            response = await node_interface.submit_blocks(payload_batch)

            if not response or not response.get("ok"):
                error_msg = response.get("error", "")
                if (
                    "Block sequence out of order" in error_msg
                    or "sequence desynchronized" in error_msg
                ):
                    logger.info(
                        f"[PUSH-SYNC] to {peer_id} ceded. Peer's state changed, another node is likely already syncing them."
                    )
                else:
                    # Not a violation: a peer may refuse blocks we offered it (its view of the
                    # chain differs, or it is still starting). Penalising it here banned a
                    # catching-up node after four refused pushes, and a banned node's handshake
                    # is refused, which stranded it with no peer to pull from.
                    logger.warning(
                        f"[PUSH-SYNC] to {peer_id} failed. Peer responded with an unexpected error: {response}"
                    )
                return

            batch_len = len(payload_batch)
            logger.debug(f"[PUSH-SYNC] Peer {peer_id} accepted batch of {batch_len} blocks.")
            current_block_to_send += len(payload_batch)
            await asyncio.sleep(0.1)

        if current_block_to_send >= target_block_id:
            logger.info(
                f"[PUSH-SYNC] to {peer_id} complete. Sent all blocks up to {target_block_id - 1}."
            )
            sync_successful = True

    except httpx.RequestError:
        await _peers.handle_unreachable_peer(peer_id, peer_url, "push-sync")

    except Exception as e:
        logger.error(f"Error during BULK push-sync to {peer_id}: {e}")
        traceback.print_exc()

    finally:
        await _node.security.peer_sync_tracker.remove_peer(peer_id)

        # Only attempt to resubmit if the trigger_data was a full block payload,
        # which we can check by looking for 'block_content'.
        if sync_successful and trigger_data and "block_content" in trigger_data:
            logger.info(
                f"[PUSH-SYNC] Sync for {peer_id} complete. Retrying submission of triggering block {trigger_data.get('id')}..."
            )
            try:
                # Recreate the interface to be safe within the finally block
                final_interface = NodeInterface(
                    peer_info["url"], client=_node.http_client, db=db_conn
                )
                final_response = await final_interface.submit_block(trigger_data)
                logger.debug(
                    f"[PUSH-SYNC] Final submission response for block {trigger_data.get('id')} from {peer_id}: {final_response}"
                )

            except httpx.RequestError:
                await _peers.handle_unreachable_peer(
                    peer_id, peer_url, "push-sync final submission"
                )

            except Exception as e:
                logger.error(f"[PUSH-SYNC] Error during final submission for {peer_id}: {e}")

        logger.debug(f"Push-sync task for peer {peer_id} has finished.")


async def _follow_up_sync(sender_node_id: str):
    """
    Immediately after accepting a block, check whether the sending peer has
    even more blocks we haven't seen yet.  This eliminates the up-to-60-second
    gap between poll cycles and keeps non-validator nodes tightly in sync.
    """
    if _node.security.sync_state_manager.is_syncing:
        return  # Don't pile on if a full sync is already running

    peer_info = NodesManager.get_peer(sender_node_id)
    if not peer_info or not peer_info.get("url"):
        return

    try:
        interface = NodeInterface(peer_info["url"], client=_node.http_client, db=_node.db)
        remote_status = await interface.get_status()
        if not (remote_status and remote_status.get("ok")):
            return
        if not await _identity._drop_if_incompatible(
            sender_node_id, remote_status["result"].get("network"), "follow-up sync"
        ):
            return

        remote_height = remote_status["result"]["height"]
        local_height = await _node.db.get_next_block_id() - 1

        if remote_height > local_height:
            logger.info(
                f"[FOLLOW-UP] Still behind peer {sender_node_id} "
                f"(local={local_height}, remote={remote_height}). Triggering immediate sync."
            )
            await _sync_blockchain(node_id=sender_node_id)
    except Exception as e:
        logger.debug(f"[FOLLOW-UP] Check failed for {sender_node_id}: {e}")


async def check_peer_and_sync(peer_info: dict):
    """
    Checks a given peer's chain status and triggers a sync if their chain is longer.
    This is a core component of the trustless sync mechanism.
    """
    if _node.security.sync_state_manager.is_syncing:
        # Don't start a new sync if one is already in progress to avoid race conditions.
        return

    peer_id = peer_info.get("node_id", "Unknown")
    peer_url = peer_info.get("url")

    try:
        # Ensure the peer is connectable
        if not peer_info.get("url"):
            return

        interface = NodeInterface(peer_info["url"], client=_node.http_client, db=_node.db)
        remote_status_resp = await interface.get_status()

        if not (remote_status_resp and remote_status_resp.get("ok")):
            logger.warning(f"Could not get status from peer {peer_id} during check.")
            await _node.security.reputation_manager.record_violation(
                peer_id, "status_unavailable", severity=1
            )
            return
        if not await _identity._drop_if_incompatible(
            peer_id, remote_status_resp["result"].get("network"), "status check"
        ):
            return

        remote_height = remote_status_resp["result"]["height"]
        local_height = await _node.db.get_next_block_id() - 1

        if remote_height > local_height:
            logger.info(
                f"Discovered longer chain on peer {peer_id} (Remote: {remote_height} > Local: {local_height}). Initiating sync."
            )
            # Trigger the main sync logic, targeting this specific peer
            await _sync_blockchain(node_id=peer_id)
        # If their chain is not longer, there's nothing to do.

    except httpx.RequestError:
        await _peers.handle_unreachable_peer(peer_id, peer_url, "periodic status check")

    except Exception as e:
        logger.error(f"Error during status check with peer {peer_id}: {e}")


# How far behind a peer a starting validator may be and still begin: about a second of blocks
# (a sync always ends behind by what the network produced while it ran).
_CAUGHT_UP_BLOCKS = max(2, round(1 / SLOT_DURATION))


async def _catch_up_before_validating() -> None:
    """Sync until no connectable peer is more than _CAUGHT_UP_BLOCKS ahead (or the initial-sync
    deadline passes). At 250 ms slots a restarted validator came out of its first sync six
    blocks short of the network, and proposed on that."""
    while time.monotonic() < _initial_sync_deadline:
        peers = [p for p in NodesManager.get_all_peers() if p.get("url")][:3]
        if not peers:
            return
        while (
            _node.security.sync_state_manager.is_syncing
            and time.monotonic() < _initial_sync_deadline
        ):
            await asyncio.sleep(0.25)
        local_height = int(await _node.db.get_next_block_id()) - 1
        ahead = None
        for peer_info in peers:
            try:
                resp = await NodeInterface(
                    peer_info["url"], client=_node.http_client, db=_node.db
                ).get_status()
                height = int(resp["result"]["height"]) if resp and resp.get("ok") else -1
            except Exception:
                continue
            if height > local_height + _CAUGHT_UP_BLOCKS:
                ahead = peer_info
                break
        if ahead is None:
            return
        await check_peer_and_sync(ahead)
        await asyncio.sleep(0.25)


async def periodic_update_fetcher():
    """
    A background task that runs for ALL nodes to discover new blocks and transactions.
    It periodically polls random peers to ensure the node is on the heaviest chain
    and to learn about new unconfirmed transactions.
    """
    await asyncio.sleep(5)  # Fast start — begin polling almost immediately

    logger.info("Starting periodic update fetcher for this node...")
    while True:
        await asyncio.sleep(8)  # Poll every 8s for fast chain convergence

        # 1. CHECK FOR LONGER CHAINS (BLOCK SYNC)
        if not _node.security.sync_state_manager.is_syncing:
            all_peers = NodesManager.get_all_peers()
            connectable_peers = [p for p in all_peers if p.get("url")]

            if connectable_peers:
                # Probe up to 2 random peers to find a potentially longer chain
                peers_to_probe = random.sample(connectable_peers, k=min(len(connectable_peers), 2))
                logger.debug(f"Probing {len(peers_to_probe)} peer(s) for a longer chain")
                for peer_info in peers_to_probe:
                    await check_peer_and_sync(peer_info)
                    await asyncio.sleep(1)  # Small delay between probes

        # 1b. FORK-CHOICE ACTIVE RECONCILIATION (mechanism-2). After the longest-chain
        #     check, actively reconcile equal-height block-history forks (which the
        #     longest-chain sync cannot see). Observe-first via _ENFORCE_FORK_CHOICE_RECONCILE.
        if not _node.security.sync_state_manager.is_syncing:
            try:
                await _forks.fork_choice_reconcile_pass(
                    enforce=_forks._ENFORCE_FORK_CHOICE_RECONCILE
                )
            except Exception as e:
                logger.debug(f"fork-choice reconcile pass skipped: {e}")

        # 2. CHECK FOR NEW TRANSACTIONS (MEMPOOL SYNC)
        all_peers = NodesManager.get_all_peers()
        connectable_peers = [p for p in all_peers if p.get("url")]

        if not connectable_peers:
            continue

        # Ask one random peer for their mempool
        peer_to_ask = random.choice(connectable_peers)
        interface = NodeInterface(peer_to_ask["url"], client=_node.http_client, db=_node.db)
        peer_id = peer_to_ask["node_id"]
        peer_url = peer_to_ask["url"]

        logger.debug(f"Polling peer {peer_id} for new transactions")
        try:
            mempool_hashes_resp = await interface.get_mempool_hashes()

            if mempool_hashes_resp is None or not mempool_hashes_resp.get("ok"):
                logger.warning(
                    f"Could not get mempool hashes from {peer_id}. Skipping transaction sync."
                )
                continue

            remote_hashes = set(mempool_hashes_resp["result"])
            local_hashes = set(await _node.db.get_all_pending_transaction_hashes())
            needed_hashes = list(remote_hashes - local_hashes)

            if needed_hashes:
                logger.debug(
                    f"Discovered {len(needed_hashes)} new transaction(s) from {peer_id}. Fetching..."
                )

                for i in range(0, len(needed_hashes), MAX_TX_FETCH_LIMIT):
                    batch = needed_hashes[i : i + MAX_TX_FETCH_LIMIT]
                    fetched_txs_resp = await interface.get_transactions_by_hash(batch)

                    if fetched_txs_resp and fetched_txs_resp.get("ok"):
                        transactions_to_propagate = []
                        for tx_hex in fetched_txs_resp["result"]:
                            try:
                                is_valid, error_msg = (
                                    _node.security.input_validator.validate_transaction_data(tx_hex)
                                )
                                if not is_valid:
                                    logger.warning(
                                        f"Skipping invalid transaction from peer: {error_msg}"
                                    )
                                    continue

                                tx = await Transaction.from_hex(tx_hex)
                                if await _node.security.transaction_pool.add_transaction(
                                    tx.hash(), tx, _node.db
                                ):
                                    logger.debug(
                                        f"  -> Accepted new pending transaction {tx.hash()[:10]}"
                                    )
                                    transactions_to_propagate.append(tx_hex)
                            except Exception as e:
                                logger.error(f"Error processing fetched transaction: {e}")

                        if transactions_to_propagate:
                            logger.debug(
                                f"Propagating {len(transactions_to_propagate)} newly learned transactions..."
                            )
                            for tx_hex in transactions_to_propagate:
                                asyncio.create_task(
                                    _peers.propagate(
                                        "push_tx",
                                        {"tx_hex": tx_hex},
                                        ignore_node_id=peer_to_ask["node_id"],
                                    )
                                )
                    else:
                        logger.warning("Failed to fetch full transaction data for batch.")

        except httpx.RequestError:
            await _peers.handle_unreachable_peer(peer_id, peer_url, "periodic mempool fetch")

        except Exception as e:
            logger.error(f"An unexpected error occurred during periodic fetch from {peer_id}: {e}")
            traceback.print_exc()


async def _sync_blockchain(node_id: Optional[str] = None):
    """Synchronizes the local blockchain with proper state management"""
    # Bail out early if a sync is already running — don't raise an exception.
    if _node.security.sync_state_manager.is_syncing:
        logger.debug("[SYNC] Skipping: another sync operation is already in progress.")
        return

    try:
        async with _node.security.sync_state_manager.acquire_sync():
            logger.info("[SYNC] Starting blockchain synchronization process...")

            peer_to_sync_from = None
            if node_id:
                peer_to_sync_from = NodesManager.get_peer(node_id)
                if peer_to_sync_from:
                    peer_to_sync_from["node_id"] = node_id
            else:
                active_peers = NodesManager.get_propagate_peers(limit=1)
                if active_peers:
                    peer_to_sync_from = active_peers[0]

            if not peer_to_sync_from:
                logger.warning("[SYNC] Aborting: No known (or specified) peer to sync from.")
                return

            peer_url = peer_to_sync_from["url"]
            peer_id = peer_to_sync_from["node_id"]
            logger.info(f"[SYNC] Attempting to sync with peer {peer_id} at {peer_url}")

            node_interface = NodeInterface(peer_url, client=_node.http_client, db=_node.db)

            last_local_block = await _node.db.get_last_block()
            local_height = last_local_block["id"] if last_local_block else -1

            remote_status_resp = await node_interface.get_status()

            if not (remote_status_resp and remote_status_resp.get("ok")):
                logger.warning(f"[SYNC] Failed to get chain status from {peer_url}. Aborting.")
                return

            remote_status = remote_status_resp["result"]
            if not await _identity._drop_if_incompatible(
                peer_id, remote_status.get("network"), "sync"
            ):
                return
            remote_height = remote_status["height"]

            logger.info(f"[SYNC] Local height: {local_height}, Remote height: {remote_height}")

            if remote_height <= local_height:
                logger.debug("[SYNC] Local chain is at or ahead of remote. No sync needed.")
                return

            logger.info("[SYNC] Remote chain is longer.")

            fork_detected = False
            if local_height > -1:
                local_last_hash = last_local_block["hash"]
                remote_block_resp = await node_interface.get_block(str(local_height))

                if not (remote_block_resp and remote_block_resp.get("ok")):
                    logger.warning(
                        "[SYNC] Could not fetch remote block for integrity check. Aborting."
                    )
                    return

                remote_block_at_our_height = remote_block_resp["result"]
                if remote_block_at_our_height["block"]["hash"] != local_last_hash:
                    logger.warning("[SYNC] Fork detected. Our tip is on a shorter fork.")
                    fork_detected = True
            else:
                logger.info("[SYNC] Local chain is empty. Beginning initial block download.")

            # Everything from here to the end of the fetch loop adopts the peer's chain: the
            # local proposer must not build on the tip meanwhile (_adopting_peer_chain).
            if fork_detected:
                # A fork, not just a longer chain: fork choice decides whether to follow it
                # (justification first — a longer branch does not win by length alone).
                _forks.schedule_fork_resolution(peer_id, "sync found a fork")
                return

            async with _adopting_peer_chain():

                logger.info("[SYNC] Starting block fetching process.")
                while True:
                    start_block_id = await _node.db.get_next_block_id()

                    if start_block_id > remote_height:
                        logger.info(
                            "[SYNC] Local height now meets or exceeds remote height. Sync appears complete."
                        )
                        break

                    logger.debug(
                        f"[SYNC] Fetching {MAX_REORG_DEPTH} blocks starting from block {start_block_id}..."
                    )

                    blocks_resp = await node_interface.get_blocks(start_block_id, MAX_REORG_DEPTH)

                    if not (blocks_resp and blocks_resp.get("ok")):
                        logger.warning(
                            "[SYNC] Failed to fetch a batch of blocks from peer. Aborting sync cycle."
                        )
                        break

                    blocks_batch = blocks_resp["result"]
                    if not blocks_batch:
                        logger.info(
                            "[SYNC] No more blocks returned by peer. Sync presumed complete."
                        )
                        break

                    # Serialize block APPLICATION under the same lock every other block-
                    # mutation path holds (p2p import, REST, proposer). The forward-sync loop
                    # was the ONE unlocked state-mutating path, so its process_and_create_block
                    # raced a concurrent proposer/import on a busy node — a block landing mid-
                    # apply could leave derived account_state at a reseeded-genesis value with
                    # the activity (perp margin / EVM transfer) re-applied to the wrong base.
                    # The network FETCH above stays outside the lock (I/O); only the local
                    # per-batch apply is serialized. See phase_e_invariants reorg divergence.
                    async with _node.block_processing_lock:
                        for block_data in blocks_batch:
                            # Blocks pushed to us while the batch was in flight are already
                            # here: skip them. At 250 ms slots that race is routine; it used to
                            # abort the sync as a fatal error and penalize the honest peer. A
                            # different block at a height we have is a fork: fork choice decides.
                            parsed = _forks._parse_transfer_block(block_data)
                            next_id = await _node.db.get_next_block_id()
                            if parsed is not None and parsed[0] < next_id:
                                have = await _node.db.get_block_hashes(parsed[0], parsed[0])
                                if have.get(parsed[0]) == parsed[1]:
                                    continue
                                _forks.schedule_fork_resolution(
                                    peer_to_sync_from["node_id"], "sync batch left our chain"
                                )
                                return
                            # The peer can reorg between the check above and this batch: a block
                            # whose parent is not our tip is on a fork, not an invalid block.
                            if parsed is not None and parsed[0] == next_id:
                                parent = _forks._transfer_parent(block_data)
                                tip = (
                                    await _node.db.get_block_hashes(next_id - 1, next_id - 1)
                                ).get(next_id - 1)
                                if parent and tip and parent != tip:
                                    _forks.schedule_fork_resolution(
                                        peer_to_sync_from["node_id"], "sync batch left our chain"
                                    )
                                    return
                            if not await _import.process_and_create_block(
                                block_data, is_bulk_sync=True
                            ):
                                logger.error(
                                    "[SYNC] FATAL ERROR: Failed to create blocks during sync. Aborting."
                                )
                                await _node.security.reputation_manager.record_violation(
                                    peer_to_sync_from["node_id"], "invalid_sync_block", severity=8
                                )
                                return
                            await asyncio.sleep(0)

                    NodesManager.update_peer_last_seen(peer_to_sync_from["node_id"])

    except httpx.RequestError:
        if peer_to_sync_from:
            await _peers.handle_unreachable_peer(
                peer_to_sync_from.get("node_id", "unknown"),
                peer_to_sync_from.get("url"),
                "blockchain sync",
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SYNC] An unexpected error occurred during the sync process: {e}")
        import traceback

        traceback.print_exc()
    finally:
        logger.info("[SYNC] Synchronization process finished.")


# Peer-chain adoptions in flight (rollback → fetch → apply). The rollback and each applied batch
# hold block_processing_lock, but the network fetches between them cannot, and the local
# proposer used to slip into that gap: it built a fresh block on the just-rolled-back tip, the
# adoption's next block then failed ("height N != expected N+1"), and the fork it was resolving
# was re-created by the resolver itself — seen in soaks, including after the proposer started
# taking the lock. While this is non-zero the proposer skips its slot (checked under the lock).
_PEER_CHAIN_ADOPTIONS = 0


@asynccontextmanager
async def _adopting_peer_chain():
    global _PEER_CHAIN_ADOPTIONS
    _PEER_CHAIN_ADOPTIONS += 1
    try:
        yield
    finally:
        _PEER_CHAIN_ADOPTIONS -= 1


def _peer_chain_adoption_in_progress() -> bool:
    """True while this node is adopting a peer chain."""
    return _PEER_CHAIN_ADOPTIONS > 0


# A validator that starts behind the network must neither propose nor vote before its first
# sync with peers. At 250 ms slots, a validator that joined late built seconds of blocks on its
# stale tip, which forked the network until fork choice undid them, and spent its one FFG vote
# of the epoch on a checkpoint of that stale chain. Cleared once the post-bootstrap sync check
# has run (periodic_peer_discovery; with no reachable peer there is nothing to wait for).
# _INITIAL_SYNC_WAIT_S bounds the wait, so an isolated node still produces.
_INITIAL_SYNC_WAIT_S = 120.0
_initial_sync_pending = True
_initial_sync_deadline = time.monotonic() + _INITIAL_SYNC_WAIT_S


def _validator_wait_reason() -> Optional[str]:
    """The validator node's guard: why it must not propose or vote in this slot, or None."""
    if _peer_chain_adoption_in_progress():
        return "adopting a peer's chain"
    if _initial_sync_pending and time.monotonic() < _initial_sync_deadline:
        return "waiting for the first sync with peers"
    return None
