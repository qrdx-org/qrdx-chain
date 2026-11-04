"""
Blocks pushed by peers and by validators (/push_block, /submit_block,
/submit_blocks), and the peer list and sync triggers.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

from typing import Optional

from fastapi import Body, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.background import BackgroundTasks
from starlette.requests import Request

from qrdx.constants import MAX_BLOCK_CONTENT_SIZE, MAX_BLOCKS_PER_SUBMISSION, VALID_HEX_PATTERN
from qrdx.helpers import sha256
from qrdx.logger import get_logger
from qrdx.manager import create_block
from qrdx.node import (
    block_import as _import,
    derived_state as _derived,
    evm_runtime as _evm,
    main as _node,
    peers as _peers,
    sync as _sync,
)
from qrdx.node.api import verified_sender
from qrdx.node.main import app, limiter
from qrdx.node.nodes_manager import NodesManager
from qrdx.transactions import Transaction
from qrdx.validator.block_verification import verify_block_proposer, verify_proposer_eligibility

logger = get_logger(__name__)


@app.post("/push_block")
@limiter.limit("12/minute")
async def push_block(request: Request):
    """The inherited miners' endpoint. QRDX is proof of stake: a mined block is refused here
    (and by ``manager.create_block`` on every other path). It used to be judged by the
    proof-of-work rules alone and appended at the tip (docs/KNOWN_ISSUES.md)."""
    return JSONResponse(
        status_code=status.HTTP_410_GONE,
        content={
            "ok": False,
            "error": "proof-of-work blocks are not accepted: QRDX is proof of stake",
        },
    )


@app.post("/submit_block")
@limiter.limit("2/second")
async def submit_block(
    request: Request,
    background_tasks: BackgroundTasks,
    body: dict = Body(...),
    verified_sender: str = Depends(verified_sender),
):
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    block_content = body.get("block_content")
    if not block_content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing block_content.")

    # Validate block content size
    if len(block_content) > MAX_BLOCK_CONTENT_SIZE:
        await _node.security.reputation_manager.record_violation(
            verified_sender, "oversized_block", severity=3
        )
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Block content too large.")

    block_identifier = sha256(block_content.encode())

    # Use time-based cache
    if await _node.security.block_cache.contains(block_identifier):
        return {"ok": False, "error": "Block recently seen"}

    # Check sync state
    if _node.security.sync_state_manager.is_syncing:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"ok": False, "error": "Node is busy synchronizing, please try again later."},
        )

    async with _node.block_processing_lock:
        block_no = body.get("id") or body.get("block_no")
        if block_no is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing block ID.")

        # Validate block height
        if not await _node.security.input_validator.validate_block_height(block_no, _node.db):
            await _node.security.reputation_manager.record_violation(
                verified_sender, "invalid_block_height", severity=4
            )
            return {"ok": False, "error": "Invalid block height"}

        next_block_id = await _node.db.get_next_block_id()
        if next_block_id > block_no:
            return {"ok": False, "error": "Too old block"}

        if next_block_id < block_no:
            # Check if peer is already syncing
            if await _node.security.peer_sync_tracker.is_syncing(verified_sender):
                return {"ok": False, "error": "Already syncing to this peer"}

            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    "ok": False,
                    "error": "sync_required",
                    "result": {"next_block_expected": next_block_id},
                },
            )

        await _node.security.block_cache.put(block_identifier, True)

        # --- PoS fast-path: if the body includes a validator_address & block_hash,
        # this is a PoS block produced by a validator.  Store it directly. ---
        block_hash = body.get("block_hash")
        validator_address = body.get("validator_address")
        if block_hash and validator_address:
            # Security: validate block_hash is well-formed hex
            if not _node.security.input_validator.validate_hex(
                block_hash, min_length=16, max_length=128
            ):
                await _node.security.reputation_manager.record_violation(
                    verified_sender, "malformed_block_hash", severity=5
                )
                return {"ok": False, "error": "Invalid block hash format"}

            # Security: block_no must be exactly the next expected height
            if block_no != next_block_id:
                return {"ok": False, "error": "Block height does not match expected next block"}

            # Security: the claimed proposer must be a validator on this chain (the set its
            # slot is selected from: validator/epoch_state.py).
            from qrdx.validator.epoch_state import is_validator

            if not await is_validator(_node.db, validator_address, block_content, block_no - 1):
                await _node.security.reputation_manager.record_violation(
                    verified_sender, "unknown_validator", severity=6
                )
                return {"ok": False, "error": "Validator address not registered"}

            # Security: authenticate the proposer (pubkey↔address binding +
            # Dilithium signature over the signed header). Registration alone does
            # not prove the block was produced by that validator.
            ok_prop, prop_err = await verify_block_proposer(
                _node.db, block_content, validator_address, block_no
            )
            if not ok_prop:
                await _node.security.reputation_manager.record_violation(
                    verified_sender, "invalid_proposer_signature", severity=8
                )
                return {"ok": False, "error": f"Proposer authentication failed: {prop_err}"}

            # Security: proposer must be eligible for the block's slot. Observe-first.
            ok_elig, elig_err = await verify_proposer_eligibility(
                _node.db,
                block_content,
                enforce=_import._ENFORCE_PROPOSER_ELIGIBILITY,
                height=int(block_no),
            )
            if not ok_elig:
                await _node.security.reputation_manager.record_violation(
                    verified_sender, "ineligible_proposer", severity=8
                )
                return {"ok": False, "error": f"Proposer ineligible: {elig_err}"}

            # Parent-hash continuity (observe-first): also instrument the REST
            # submit_block path — a fork block entering here (which has no parent
            # check beyond height) is a candidate entry point for the genesis-era
            # broken-linkage divergence seen with no reorg. Observe = log only.
            ok_par, par_err = await _import._check_parent_continuity(
                block_no,
                block_content,
                enforce=_import._ENFORCE_PARENT_CONTINUITY,
            )
            if not ok_par:
                return {"ok": False, "error": f"Parent discontinuity: {par_err}"}

            ok_votes, votes_err = await _import._verify_chain_rules(
                block_content,
                block_no,
                body.get("exchange_transactions"),
                body.get("evm_transactions"),
                block_hash,
            )
            if not ok_votes:
                return {"ok": False, "error": f"Chain rules: {votes_err}"}

            # Everything the block changes from here is recorded in the undo journal under its
            # height (a checkpoint first if it opens an epoch) — what makes a later reorg cheap.
            from qrdx.derived_state_rebuild import before_block
            from qrdx.validator.block_verification import epoch_from_block as _block_epoch

            async with await before_block(_node.db, block_no, _block_epoch(body)):
                # D3: if the block carries an exchange section, securely validate +
                # replay it (verify signatures, re-execute, match declared root)
                # BEFORE storing. Reject the block on any mismatch — local exchange
                # state is left untouched by a rejected block.
                ex_section = body.get("exchange_transactions")
                if ex_section:
                    try:
                        # Phase E: route through the importer hook so the collateral
                        # flush (margin debit → account_state) runs on this REST
                        # live-broadcast path too, deterministically with proposer/sync.
                        from qrdx.validator.block_verification import epoch_from_block

                        ok, verr = await _import._apply_exchange_section_on_import(
                            block_no,
                            float(body.get("timestamp", 0) or 0),
                            ex_section,
                            body.get("exchange_state_root"),
                            block_epoch=epoch_from_block(body),
                        )
                    except Exception as e:
                        ok, verr = False, f"exchange validation error: {e}"
                    if not ok:
                        await _node.security.reputation_manager.record_violation(
                            verified_sender, "invalid_exchange_section", severity=6
                        )
                        return {"ok": False, "error": f"Invalid exchange section: {verr}"}
                else:
                    # No exchange transactions — the exchange still ticks (mark prices, ...).
                    await _import._exchange_tick_on_import(block_no, body.get("timestamp", 0) or 0)

                # E-D3b: validate + replay the EVM section (execute-on-mine) before
                # storing; reject on account_state_root mismatch.
                evm_section = body.get("evm_transactions")
                if evm_section:
                    ok_evm, verr_evm = await _evm._apply_evm_section_on_import(
                        block_no,
                        block_hash,
                        int(body.get("timestamp", 0) or 0),
                        evm_section,
                        body.get("account_state_root"),
                    )
                    if not ok_evm:
                        await _node.security.reputation_manager.record_violation(
                            verified_sender, "invalid_evm_section", severity=6
                        )
                        await _derived._restore_after_rejected_block(
                            block_no, f"EVM section: {verr_evm}"
                        )
                        return {"ok": False, "error": f"Invalid EVM section: {verr_evm}"}

                # Stake withdrawals — same point as the proposer: after EVM, before E-D4.
                from qrdx.validator.block_verification import epoch_from_block as _efb

                await _import._apply_block_withdrawals_on_import(block_no, _efb(body))

                # E-D4: verify the recomputed unified state root against the signed root.
                ok_root, root_err = await _import._verify_unified_state_root(
                    block_content, height=block_no
                )
                if not ok_root:
                    await _node.security.reputation_manager.record_violation(
                        verified_sender, "invalid_state_root", severity=8
                    )
                    await _derived._restore_after_rejected_block(block_no, f"E-D4: {root_err}")
                    return {"ok": False, "error": f"Invalid state root: {root_err}"}

                try:
                    await _node.db.add_block(
                        block_hash=block_hash,
                        block_height=block_no,
                        block_content=block_content or "",
                        validator_address=validator_address,
                        timestamp=body.get("timestamp", 0),
                    )
                    # D2.2b: persist the (now-validated) exchange section for durability.
                    if ex_section:
                        try:
                            await _node.db.add_block_exchange_txs(block_hash, ex_section)
                        except Exception as e:
                            logger.warning(
                                f"Failed to store exchange section for block {block_no}: {e}"
                            )
                    # E-D3b: persist the (now-validated) EVM section for durability/rebuild.
                    if evm_section:
                        try:
                            await _node.db.add_block_evm_txs(block_hash, evm_section)
                        except Exception as e:
                            logger.warning(f"Failed to store EVM section for block {block_no}: {e}")
                    # Finality (observe): record attestation votes + recompute.
                    try:
                        from qrdx.validator.finality import record_finality_from_block

                        await record_finality_from_block(_node.db, block_content)
                    except Exception as e:
                        logger.debug(f"finality record skipped for block {block_no}: {e}")
                    await _node.security.reputation_manager.record_good_behavior(
                        verified_sender, points=5
                    )
                    logger.info(
                        f"Accepted PoS block {block_no} from {verified_sender}. Propagating..."
                    )
                    background_tasks.add_task(
                        _peers.propagate,
                        "submit_block",
                        body,
                        ignore_node_id=verified_sender,
                        db=_node.db,
                    )
                    # Immediate follow-up: check if we're still behind and need more blocks
                    background_tasks.add_task(_sync._follow_up_sync, verified_sender)
                    return {"ok": True, "result": f"Block {block_no} accepted."}
                except Exception as e:
                    logger.error(f"Failed to store PoS block {block_no}: {e}")
                    return {"ok": False, "error": "Failed to store block"}

        # --- Legacy PoW path ---
        # Process transactions with validation
        txs_data = body.get("txs", [])
        final_transactions = []
        tx_hashes_to_find = []

        if isinstance(txs_data, str):
            txs_data = txs_data.split(",") if txs_data else []

        for tx_hex in txs_data:
            if isinstance(tx_hex, str) and len(tx_hex) == 64 and VALID_HEX_PATTERN.match(tx_hex):
                tx_hashes_to_find.append(tx_hex)
            else:
                is_valid, error_msg = _node.security.input_validator.validate_transaction_data(
                    tx_hex
                )
                if not is_valid:
                    await _node.security.reputation_manager.record_violation(
                        verified_sender, "invalid_block_transaction", severity=5
                    )
                    return {"ok": False, "error": f"Invalid transaction in block: {error_msg}"}

                final_transactions.append(await Transaction.from_hex(tx_hex))

        if tx_hashes_to_find:
            db_results = await _node.db.get_pending_transactions_by_hash(tx_hashes_to_find)
            if len(db_results) < len(tx_hashes_to_find):
                return {"ok": False, "error": "Transaction hash not found."}

            tx_map = {tx.hash(): tx for tx in db_results}
            ordered_txs = [tx_map.get(tx_hash) for tx_hash in tx_hashes_to_find]
            final_transactions.extend(ordered_txs)

        if not await create_block(block_content, final_transactions):
            await _node.security.reputation_manager.record_violation(
                verified_sender, "invalid_block", severity=7
            )
            return {"ok": False, "error": "Block failed validation."}

        # Record successful block
        await _node.security.reputation_manager.record_good_behavior(verified_sender, points=5)

        logger.info(f"Accepted block {block_no} from {verified_sender}. Propagating to network...")
        background_tasks.add_task(
            _peers.propagate, "submit_block", body, ignore_node_id=verified_sender, db=_node.db
        )
        # Immediate follow-up: check if we're still behind and need more blocks
        background_tasks.add_task(_sync._follow_up_sync, verified_sender)
        return {"ok": True, "result": f"Block {block_no} accepted."}


@app.post("/submit_blocks")
@limiter.limit("30/minute")
async def submit_blocks(
    request: Request, body: list = Body(...), verified_sender: str = Depends(verified_sender)
):
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    if not isinstance(body, list) or not body:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Request body must be a non-empty list.")

    if len(body) > MAX_BLOCKS_PER_SUBMISSION:
        await _node.security.reputation_manager.record_violation(
            verified_sender, "too_many_blocks", severity=3
        )
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Request limit exceeded. You can only submit up to {MAX_BLOCKS_PER_SUBMISSION} blocks at a time.",
        )

    try:
        async with _node.security.sync_state_manager.acquire_sync():
            async with _node.block_processing_lock:
                blocks_to_process = sorted(body, key=lambda x: x["id"])

                # Verify continuity
                for i in range(1, len(blocks_to_process)):
                    if blocks_to_process[i]["id"] != blocks_to_process[i - 1]["id"] + 1:
                        await _node.security.reputation_manager.record_violation(
                            verified_sender, "non_continuous_blocks", severity=4
                        )
                        return {"ok": False, "error": "Block sequence must be continuous"}

                next_block_id = await _node.db.get_next_block_id()
                if blocks_to_process[0]["id"] != next_block_id:
                    return {
                        "ok": False,
                        "error": f'Block sequence out of order. Expected {next_block_id}, got {blocks_to_process[0]["id"]}.',
                    }

                for block_payload in blocks_to_process:
                    block_no = block_payload.get("id")

                    current_expected_id = await _node.db.get_next_block_id()
                    if current_expected_id != block_no:
                        return {
                            "ok": False,
                            "error": f"Block sequence desynchronized during batch. Expected {current_expected_id}, got {block_no}.",
                        }

                    block_content = block_payload.get("block_content")
                    txs_data = block_payload.get("txs", [])

                    if not block_content:
                        return {
                            "ok": False,
                            "error": f"Invalid block data for block {block_no}: missing content.",
                        }

                    # Validate block content size
                    if len(block_content) > MAX_BLOCK_CONTENT_SIZE:
                        await _node.security.reputation_manager.record_violation(
                            verified_sender, "oversized_bulk_block", severity=3
                        )
                        return {"ok": False, "error": f"Block {block_no} content too large."}

                    block_identifier = sha256(block_content.encode())
                    if await _node.security.block_cache.contains(block_identifier):
                        continue

                    final_transactions = []
                    for tx_hex in txs_data:
                        is_valid, error_msg = (
                            _node.security.input_validator.validate_transaction_data(tx_hex)
                        )
                        if not is_valid:
                            await _node.security.reputation_manager.record_violation(
                                verified_sender, "invalid_bulk_transaction", severity=5
                            )
                            return {
                                "ok": False,
                                "error": f"Block {block_no} contains an invalid transaction: {error_msg}",
                            }
                        final_transactions.append(await Transaction.from_hex(tx_hex))

                    if not await create_block(block_content, final_transactions):
                        await _node.security.reputation_manager.record_violation(
                            verified_sender, "invalid_bulk_block", severity=7
                        )
                        return {
                            "ok": False,
                            "error": f"Block {block_no} failed validation. Halting.",
                        }

                    await _node.security.block_cache.put(block_identifier, True)
                    logger.info(f"Accepted block {block_no} from {verified_sender} via bulk sync.")

                # Reward successful bulk submission
                await _node.security.reputation_manager.record_good_behavior(
                    verified_sender, points=len(blocks_to_process) * 2
                )

                return {
                    "ok": True,
                    "result": f"Successfully processed {len(blocks_to_process)} blocks.",
                }

    except HTTPException:
        raise
    except Exception as e:
        await _node.security.security_monitor.log_event(
            "bulk_sync_error", {"peer_id": verified_sender, "error": str(e)}
        )
        raise


@app.post("/get_peers")
async def get_peers(verified_sender: str = Depends(verified_sender)):
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    peers_list = [
        {"node_id": peer_id, **peer_data}
        for peer_id, peer_data in NodesManager.peers.items()
        # Only share peers that haven't been banned
        if not await _node.security.reputation_manager.is_banned(peer_id)
    ]
    return {"ok": True, "result": {"peers": peers_list}}


# The handshake is JSON-RPC only (p2p_handshakeChallenge / p2p_handshakeResponse): mutual,
# with signed calls and a signed identity proof. The REST pair it replaced took a peer's
# identity on its word, and is gone rather than left as a weaker second way in.


@app.get("/sync_blockchain")
@limiter.limit("10/minute")
async def sync(request: Request, node_id: Optional[str] = None):
    """Initiates a blockchain synchronization process"""
    if _node.security.sync_state_manager.is_syncing:
        return {"ok": False, "error": "Node is already syncing"}

    background_tasks = BackgroundTasks()
    background_tasks.add_task(_sync._sync_blockchain, node_id=node_id)

    return JSONResponse(
        content={"ok": True, "result": "Synchronization process has been initiated."},
        background=background_tasks,
    )
