"""
Read-only REST views of the chain: blocks, status, validators, attestations, nodes,
the mempool and state roots.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import ipaddress
import json
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set

import httpx
from fastapi import Body, Depends, HTTPException, Query, status
from fastapi.responses import Response
from slowapi.util import get_remote_address
from starlette.background import BackgroundTasks
from starlette.requests import Request

from qrdx.constants import (
    MAX_MEMPOOL_SIZE,
    MAX_MINING_CANDIDATES,
    MAX_TX_DATA_SIZE,
    MAX_TX_FETCH_LIMIT,
    NODE_VERSION,
)
from qrdx.helpers import timestamp
from qrdx.logger import get_logger
from qrdx.manager import (
    Manager,
    clear_pending_transactions,
    get_difficulty,
    get_transactions_merkle_tree,
)
from qrdx.node import main as _node
from qrdx.node.api import CustomJSONEncoder, verified_sender
from qrdx.node.main import app, limiter
from qrdx.node.nodes_manager import NodesManager

logger = get_logger(__name__)

LAST_PENDING_TRANSACTIONS_CLEAN = [0]


@app.get("/")
async def root():
    return {
        "node_version": NODE_VERSION,
        "unspent_outputs_hash": await _node.db.get_unspent_outputs_hash(),
    }


@app.get("/get_unified_state_root")
async def get_unified_state_root():
    """
    Return the unified block state root (Whitepaper §3.6): a BLAKE3-512 commitment
    over all state domains — UTXO set, account/EVM state, exchange state, and the
    QRC-20 token ledger.

    Phase D4 primitive. NOTE: this is computed/observable but not yet *enforced*
    in consensus. Enforcing it requires every committed domain to be
    deterministically re-executed on import; the exchange domain is (D3), but the
    account/EVM domain still applies via gossip rather than consensus replay, so
    its root can differ across nodes until the EVM domain receives the same D1–D3
    treatment. See docs/EXCHANGE_PRODUCTION_READINESS.md.
    """
    try:
        from qrdx.crypto.hashing import unified_state_root
        from qrdx.exchange import ExchangeStateManager

        # The tip's state, under the rule of the tip's height.
        tip = max(0, (await _node.db.get_next_block_id()) - 1)
        utxo_root = await _node.db.get_unspent_outputs_hash(tip)
        account_root = await _node.db.get_account_state_root(tip)
        exchange_root = ExchangeStateManager.get_instance().compute_state_root()
        token_root = await _node.db.get_token_balances_root(tip)
        from qrdx import state_proofs

        row = _node.db.store["state_root_parts"].get(tip) if state_proofs.scheduled() else None
        proof_root = row.proof if row is not None else None
        validators = row.validators if row is not None else None
        root = unified_state_root(
            utxo_root, account_root, exchange_root, token_root, proof_root, validators
        )
        return {
            "ok": True,
            "result": {
                "unified_state_root": root,
                "utxo_root": utxo_root,
                "account_root": account_root,
                "exchange_root": exchange_root,
                "token_root": token_root,
                "proof_root": proof_root,
                "validator_root": validators,
                "token_root_bound": True,
                "enforced": False,
            },
        }
    except Exception as e:
        logger.error(f"get_unified_state_root error: {e}")
        return {"ok": False, "error": str(e)}


@app.get("/get_randao_mix")
async def get_randao_mix():
    """
    The accumulated RANDAO mix (observe-first) — a deterministic fold of every
    canonical block's proposer reveal (see qrdx.validator.randao). All honest nodes
    on the same chain MUST report an identical mix; this endpoint is how that
    cross-node convergence is confirmed before the mix drives proposer selection.

    NOTE: proposer selection still uses the constant zero mix today, so this is
    observational — it does not yet affect consensus.
    """
    try:
        from qrdx.validator.randao import compute_randao_mix

        tip = (await _node.db.get_next_block_id()) - 1
        mix = await compute_randao_mix(_node.db, tip)
        return {
            "ok": True,
            "result": {
                "randao_mix": mix.hex(),
                "height": tip,
                "drives_selection": False,
            },
        }
    except Exception as e:
        logger.error(f"get_randao_mix error: {e}")
        return {"ok": False, "error": str(e)}


@app.get("/get_mining_info")
@limiter.limit("15/minute")
async def get_mining_info(
    request: Request,
    background_tasks: BackgroundTasks,
    pretty: bool = False,
    debug: bool = False,
):
    """
    Build a block template from the full mempool:
      - Load ALL pending transaction hashes from the DB (no hidden filters).
      - Deserialize those transactions.
      - Topologically select valid, non-conflicting txs (parents first), so
        multiple independent txs and parent+child chains can be included in
        the same block.
      - Return selected tx hexes and hashes, merkle root, and optional debug.
    """

    # Recompute difficulty/tip
    Manager.difficulty = None
    difficulty, last_block = await get_difficulty()

    next_block_height = (last_block["id"] + 1) if last_block else 0

    # Guard mempool size (same as before)
    pending_count = await _node.db.get_pending_transaction_count()
    if pending_count > MAX_MEMPOOL_SIZE:
        logger.warning(
            f"Mempool size ({pending_count}) exceeds limit of ({MAX_MEMPOOL_SIZE}). Triggering cleanup."
        )
        await clear_pending_transactions([])

    # === Load ALL mempool transactions by hash, then hydrate ===
    # This avoids whatever filtering/ordering get_pending_transactions_limit() was doing.
    try:
        all_hashes = await _node.db.get_all_pending_transaction_hashes()  # returns List[str]
    except Exception as e:
        logger.error(f"Error fetching mempool hashes: {e}")
        all_hashes = []

    # Optionally cap to something huge to avoid pathological mempools
    if len(all_hashes) > MAX_MINING_CANDIDATES:
        all_hashes = all_hashes[:MAX_MINING_CANDIDATES]

    # Preserve DB-provided order (whatever it is), and create a stable index
    order_index = {h: i for i, h in enumerate(all_hashes)}

    # Fetch full tx objects for these hashes
    # This DB API exists in your code (used in /submit_block, etc.)
    pending_tx_objects = await _node.db.get_pending_transactions_by_hash(all_hashes)

    # Build a hash -> Transaction map and drop unknowns (shouldn't happen, but be safe)
    tx_by_hash = {}
    for tx in pending_tx_objects:
        try:
            tx_by_hash[tx.hash()] = tx
        except Exception:
            # If a deserialization glitch happens, skip the tx
            continue

    # Only keep hashes we could hydrate
    candidate_hashes = [h for h in all_hashes if h in tx_by_hash]
    logger.debug(f"Building block template from full mempool. Candidates: {len(candidate_hashes)}")

    # Fast-path: nothing pending
    if not candidate_hashes:
        merkle_root = get_transactions_merkle_tree([], next_block_height)
        result = {
            "ok": True,
            "result": {
                "difficulty": difficulty,
                "last_block": last_block,
                "pending_transactions": [],
                "pending_transactions_hashes": [],
                "merkle_root": merkle_root,
            },
        }
        return (
            Response(
                content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
                media_type="application/json",
            )
            if pretty
            else result
        )

    # Debug info per tx
    debug_rows = {}  # h -> dict

    # Memoize chain prev-tx lookups
    chain_tx_cache: Dict[str, Any] = {}

    async def chain_tx(prev_hash: str):
        if prev_hash in chain_tx_cache:
            return chain_tx_cache[prev_hash]
        data = await _node.db.get_nice_transaction(prev_hash)
        chain_tx_cache[prev_hash] = data
        return data

    # Dependency graph
    deps: Dict[str, Set[str]] = {h: set() for h in candidate_hashes}  # child -> parents in mempool
    children = defaultdict(set)  # parent -> set(children)
    prevouts = {}  # h -> set("txhash:index")
    invalid = set()  # bad references / failed verify

    # First pass: validate inputs, build deps, record prevouts
    for h in candidate_hashes:
        tx = tx_by_hash[h]
        info = {
            "hash": h,
            "selected": False,
            "reason": None,
            "deps": [],
            "prevouts": [],
            "indegree_initial": None,
            "indegree_final": None,
            "parents_not_selected": [],
        }

        # Record prevouts for in-block double-spend checks
        my_prevouts = {f"{inp.tx_hash}:{inp.index}" for inp in tx.inputs}
        prevouts[h] = my_prevouts
        info["prevouts"] = list(my_prevouts)

        try:
            ok = True
            for inp in tx.inputs:
                p = inp.tx_hash

                # If the parent is also pending, register dependency
                if p in tx_by_hash:
                    deps[h].add(p)
                    continue

                # Otherwise the parent must exist on-chain and index be valid
                src = await chain_tx(p)
                if src is None:
                    logger.debug(f"Tx {h[:10]} references unknown prev tx {p[:10]}")
                    info["reason"] = f"invalid_input_unknown_parent:{p}"
                    ok = False
                    break

                if "outputs" in src and inp.index >= len(src["outputs"]):
                    logger.debug(
                        f"Tx {h[:10]} references out-of-range output {inp.index} in {p[:10]}"
                    )
                    info["reason"] = f"invalid_input_out_of_range:{p}:{inp.index}"
                    ok = False
                    break

            if not ok:
                invalid.add(h)
                debug_rows[h] = info
                continue

            # Full signature/script verification
            if not await tx.verify():
                logger.debug(f"Tx {h[:10]} failed verification")
                info["reason"] = "verify_failed"
                invalid.add(h)
                debug_rows[h] = info
                continue

        except Exception as e:
            logger.debug(f"Tx {h[:10]} verification error: {e}")
            info["reason"] = f"verify_exception:{e}"
            invalid.add(h)
            debug_rows[h] = info
            continue

        info["deps"] = list(deps[h])
        debug_rows[h] = info

    # Build children edges (ignore invalid parents)
    for child_h, parents in deps.items():
        if child_h in invalid:
            continue
        for parent_h in parents:
            if parent_h not in invalid:
                children[parent_h].add(child_h)

    # Compute indegrees
    indegree = {}
    for h in candidate_hashes:
        if h in invalid:
            continue
        indegree[h] = sum(1 for p in deps[h] if p not in invalid)
        debug_rows[h]["indegree_initial"] = indegree[h]

    # Queue of zero-dep txs in stable order (DB order)
    zero_dep = [h for h, d in indegree.items() if d == 0]
    zero_dep.sort(key=lambda k: order_index.get(k, 1_000_000))
    queue = deque(zero_dep)

    # Selection loop
    selected = []
    selected_hashes = set()
    spent_prevouts: Set[str] = set()
    total_size = 0
    size_hard_stop = False

    while queue:
        h = queue.popleft()
        if h in selected_hashes or h in invalid:
            continue

        tx = tx_by_hash[h]
        tx_hex = tx.hex()

        # Ensure we don't exceed size target
        if total_size + len(tx_hex) > MAX_TX_DATA_SIZE:
            logger.debug("Reached MAX_TX_DATA_SIZE while assembling block template.")
            size_hard_stop = True
            break

        # In-block double-spend check
        if not prevouts[h].isdisjoint(spent_prevouts):
            if debug:
                debug_rows[h]["reason"] = "double_spend_conflict_in_block"
            continue

        # Accept tx
        selected.append(tx)
        selected_hashes.add(h)
        spent_prevouts.update(prevouts[h])
        total_size += len(tx_hex)
        debug_rows[h]["selected"] = True

        # Relax children indegrees
        for c in children.get(h, ()):
            if c in indegree:
                indegree[c] -= 1
                if indegree[c] == 0:
                    queue.append(c)

    # Annotate non-selected reasons
    for h, d in indegree.items():
        debug_rows[h]["indegree_final"] = d
        if not debug_rows[h]["selected"] and h not in invalid and debug_rows[h]["reason"] is None:
            if d > 0:
                blocked_by = [p for p in deps[h] if p not in invalid and p not in selected_hashes]
                debug_rows[h]["reason"] = "blocked_by_unselected_parents"
                debug_rows[h]["parents_not_selected"] = blocked_by
            else:
                if size_hard_stop:
                    debug_rows[h]["reason"] = "size_limit_reached"
                else:
                    debug_rows[h]["reason"] = "skipped_for_conflict_or_unknown"

    # Purge invalids
    if invalid:
        logger.info(f"Removing {len(invalid)} invalid tx(s) from mempool")
        for h in invalid:
            try:
                await _node.db.remove_pending_transaction(h)
                await _node.security.transaction_pool.remove_transactions([h])
            except Exception as e:
                logger.error(f"Error removing invalid tx {h[:10]}: {e}")

    # Compose response
    selected_hex = [tx.hex() for tx in selected]
    selected_hashes_list = [tx.hash() for tx in selected]
    merkle_root = get_transactions_merkle_tree(selected_hashes_list, next_block_height)

    # Periodic cleanup (unchanged)
    if LAST_PENDING_TRANSACTIONS_CLEAN[0] < timestamp() - 600:
        logger.debug("Clearing old pending transactions")
        LAST_PENDING_TRANSACTIONS_CLEAN[0] = timestamp()
        # Feed the cleaner the full set we loaded (not just selected)
        try:
            # If you want to pass hex, hydrate:
            all_loaded_hex = [tx_by_hash[h].hex() for h in candidate_hashes]
            background_tasks.add_task(clear_pending_transactions, all_loaded_hex)
        except Exception:
            pass

    payload = {
        "ok": True,
        "result": {
            "difficulty": difficulty,
            "last_block": last_block,
            "pending_transactions": selected_hex,
            "pending_transactions_hashes": selected_hashes_list,
            "merkle_root": merkle_root,
        },
    }

    if debug:
        dbg = []
        for h, row in debug_rows.items():
            dbg.append(
                {
                    "hash": h,
                    "selected": row["selected"],
                    "reason": row["reason"],
                    "deps": row["deps"],
                    "prevouts": row["prevouts"],
                    "indegree_initial": row["indegree_initial"],
                    "indegree_final": row["indegree_final"],
                    "parents_not_selected": row["parents_not_selected"],
                }
            )
        payload["debug"] = dbg

    return (
        Response(
            content=json.dumps(payload, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
        if pretty
        else payload
    )


@app.get("/get_nodes")
async def get_nodes(pretty: bool = False):
    # Return all active, non-banned peers (both public and private)
    # Redact private peer URLs unless QRDX_SELF_URL is also private
    all_peers = []
    for p in NodesManager.get_recent_nodes()[:100]:
        if await _node.security.reputation_manager.is_banned(p["node_id"]):
            continue
        all_peers.append(
            {
                "node_id": p["node_id"],
                "is_public": p.get("is_public", False),
                "url": p.get("url", ""),
                "reputation_score": await _node.security.reputation_manager.get_score(p["node_id"]),
            }
        )
    result = {"ok": True, "result": all_peers}
    return (
        Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
        if pretty
        else result
    )


@app.get("/get_pending_transactions")
async def get_pending_transactions(pretty: bool = False):
    result = {
        "ok": True,
        "result": [tx.hex() for tx in await _node.db.get_pending_transactions_limit(1024)],
    }
    return (
        Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
        if pretty
        else result
    )


@app.get("/get_slashing_events")
async def get_slashing_events(validator: Optional[str] = None):
    """The offences this node recorded (the double-sign and surround proofs blocks carried), by
    slot, optionally for one validator. The proofs are on chain: nothing here is private."""
    return {"ok": True, "result": await _node.db.get_slashing_events(validator)}


@app.get("/get_validators")
async def get_validators(status: Optional[str] = None, pretty: bool = False):
    """
    Return the PoS validator set from the validators table.

    Validators are populated at genesis and updated through the staking
    lifecycle. The ``validators`` key is included alongside the standard
    ``{ok, result}`` envelope for client compatibility.
    """
    try:
        validators = await _node.db.get_validators(status=status)
    except Exception as e:
        logger.error(f"get_validators error: {e}")
        validators = []
    result = {"ok": True, "result": validators, "validators": validators}
    return (
        Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
        if pretty
        else result
    )


@app.get("/get_recent_blocks")
@limiter.limit("10/minute")
async def get_recent_blocks(
    request: Request,
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    include_validator_info: bool = Query(default=True),
    pretty: bool = False,
):
    """
    Get most recent blocks with validator information
    """
    try:
        if hasattr(_node.db, "pool"):
            # PostgreSQL implementation
            async with _node.db.pool.acquire() as conn:
                # Get recent blocks with validator information
                blocks_query = """
                SELECT
                    b.id,
                    b.hash,
                    b.address,
                    b.slot,
                    b.epoch,
                    b.proposer_address,
                    b.attestations_included,
                    b.reward,
                    b.timestamp,
                    (SELECT COUNT(*) FROM transactions WHERE block_hash = b.hash) as tx_count
                FROM blocks b
                ORDER BY b.id DESC
                LIMIT $1 OFFSET $2
            """

            recent_blocks = await conn.fetch(blocks_query, limit, offset)

            result_blocks = []
            for block in recent_blocks:
                block_data = {
                    "block_number": block["id"],
                    "block_hash": block["hash"],
                    "timestamp": block["timestamp"].isoformat() if block["timestamp"] else None,
                    "reward": "{:f}".format(block["reward"]) if block["reward"] else "0",
                    "tx_count": block["tx_count"],
                }

                # Add PoS-specific data if available
                if block["slot"] is not None:
                    block_data.update(
                        {
                            "slot": block["slot"],
                            "epoch": block["epoch"],
                            "proposer": block["proposer_address"],
                            "attestations": block["attestations_included"],
                        }
                    )

                    # Get validator info if requested
                    if include_validator_info and block["proposer_address"]:
                        validator = await conn.fetchrow(
                            """
                            SELECT address, stake, effective_stake, status
                            FROM validators
                            WHERE address = $1
                        """,
                            block["proposer_address"],
                        )

                        if validator:
                            block_data["validator"] = {
                                "address": validator["address"],
                                "stake": str(validator["stake"]),
                                "effective_stake": str(validator["effective_stake"]),
                                "status": validator["status"],
                            }
                else:
                    # Legacy PoW block
                    block_data["miner"] = block["address"]

                result_blocks.append(block_data)
        else:
            # SQLite implementation
            recent_blocks = await _node.db.get_recent_blocks_with_validators(limit, offset)
            result_blocks = []

            for block in recent_blocks:
                block_data = {
                    "block_number": block.get("block_height", 0),
                    "block_hash": block.get("block_hash", ""),
                    "timestamp": block.get("timestamp", ""),
                    "tx_count": block.get("tx_count", 0),
                }

                if include_validator_info:
                    validator_info = await _node.db.get_validator_info(block.get("validator"))
                    if validator_info:
                        block_data["validator"] = {
                            "address": validator_info["address"],
                            "stake": str(validator_info.get("stake", 0)),
                            "status": validator_info.get("status", "unknown"),
                        }
                else:
                    block_data["validator"] = block.get("validator")

                result_blocks.append(block_data)

            result = {"ok": True, "result": {"blocks": result_blocks, "count": len(result_blocks)}}

    except Exception as e:
        logger.error(f"Error fetching recent blocks: {e}")
        result = {"ok": False, "error": "Error fetching recent blocks"}

    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
    return result


@app.get("/get_attestations")
@limiter.limit("10/minute")
async def get_attestations(
    request: Request,
    slot: int = Query(default=None),
    epoch: int = Query(default=None),
    validator_address: str = Query(default=None),
    block_hash: str = Query(default=None),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    pretty: bool = False,
):
    """
    Get attestations by slot, epoch, validator, or block
    """
    # Validate inputs if provided
    if validator_address and not _node.security.input_validator.validate_address(validator_address):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid validator address format")

    if block_hash and not _node.security.input_validator.validate_hex(
        block_hash, min_length=64, max_length=64
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid block hash format")

    try:
        if hasattr(_node.db, "pool"):
            # PostgreSQL implementation
            # Build query based on provided filters
            filters = []
            params: List[Any] = []
            param_count = 0

            if slot is not None:
                param_count += 1
                filters.append(f"slot = ${param_count}")
                params.append(slot)

            if epoch is not None:
                param_count += 1
                filters.append(f"epoch = ${param_count}")
                params.append(epoch)

            if validator_address:
                param_count += 1
                filters.append(f"validator_address = ${param_count}")
                params.append(validator_address)

            if block_hash:
                param_count += 1
                filters.append(f"block_hash = ${param_count}")
                params.append(block_hash)

            async with _node.db.pool.acquire() as conn:
                where_clause = " AND ".join(filters) if filters else "1=1"

                attestations_query = f"""
                    SELECT
                        a.id,
                        a.slot,
                        a.epoch,
                        a.block_hash,
                        a.validator_address,
                        a.validator_index,
                        a.source_epoch,
                        a.target_epoch,
                        a.included_in_block,
                        a.inclusion_slot,
                        a.created_at,
                        v.stake,
                        v.effective_stake,
                        v.status as validator_status
                    FROM attestations a
                    LEFT JOIN validators v ON a.validator_address = v.address
                    WHERE {where_clause}
                    ORDER BY a.slot DESC, a.validator_index ASC
                    LIMIT ${param_count + 1} OFFSET ${param_count + 2}
                """

                params.extend([limit, offset])
                attestations = await conn.fetch(attestations_query, *params)

                result_attestations = []
                for att in attestations:
                    result_attestations.append(
                        {
                            "id": att["id"],
                            "slot": att["slot"],
                            "epoch": att["epoch"],
                            "block_hash": att["block_hash"],
                            "validator": {
                                "address": att["validator_address"],
                                "index": att["validator_index"],
                                "stake": str(att["stake"]) if att["stake"] else None,
                                "effective_stake": (
                                    str(att["effective_stake"]) if att["effective_stake"] else None
                                ),
                                "status": att["validator_status"],
                            },
                            "checkpoint": {
                                "source_epoch": att["source_epoch"],
                                "target_epoch": att["target_epoch"],
                            },
                            "inclusion": (
                                {
                                    "block_hash": att["included_in_block"],
                                    "slot": att["inclusion_slot"],
                                }
                                if att["included_in_block"]
                                else None
                            ),
                            "created_at": (
                                att["created_at"].isoformat() if att["created_at"] else None
                            ),
                        }
                    )
        else:
            # SQLite implementation
            sqlite_filters = {
                "slot": slot,
                "epoch": epoch,
                "validator_address": validator_address,
                "block_hash": block_hash,
            }
            attestations = await _node.db.get_attestations_filtered(sqlite_filters, limit, offset)

            result_attestations = []
            for att in attestations:
                result_attestations.append(
                    {
                        "id": att.get("id"),
                        "slot": att.get("slot"),
                        "epoch": att.get("epoch"),
                        "block_hash": att.get("block_hash"),
                        "validator": {
                            "address": att.get("validator_address"),
                            "index": att.get("validator_index"),
                            "stake": str(att.get("stake", 0)),
                            "status": att.get("validator_status"),
                        },
                        "checkpoint": {
                            "source_epoch": att.get("source_epoch"),
                            "target_epoch": att.get("target_epoch"),
                        },
                        "inclusion": (
                            {
                                "block_hash": att.get("included_in_block"),
                                "slot": att.get("inclusion_slot"),
                            }
                            if att.get("included_in_block")
                            else None
                        ),
                    }
                )

            result = {
                "ok": True,
                "result": {
                    "attestations": result_attestations,
                    "count": len(result_attestations),
                    "filters": {
                        "slot": slot,
                        "epoch": epoch,
                        "validator": validator_address,
                        "block_hash": block_hash,
                    },
                },
            }

    except Exception as e:
        logger.error(f"Error fetching attestations: {e}")
        result = {"ok": False, "error": "Error fetching attestations"}

    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
    return result


@app.get("/get_block")
@limiter.limit("8/second")
async def get_block(
    request: Request, block: str, full_transactions: bool = False, pretty: bool = False
):
    # Validate block parameter
    block_info = None
    block_hash = ""

    # Validate block parameter
    if block.isdecimal():
        block_id = int(block)
        if not await _node.security.input_validator.validate_block_height(
            block_id, _node.db, max_ahead=0
        ):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid block height")

        block_info = await _node.db.get_block_by_id(block_id)
        if block_info:
            block_hash = block_info["hash"]

    else:
        if not _node.security.input_validator.validate_hex(block, min_length=64, max_length=64):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid block hash format")

        block_hash = block
        block_info = await _node.db.get_block(block_hash)

    if block_info:
        result = {
            "ok": True,
            "result": {
                "block": block_info,
                "transactions": (
                    await _node.db.get_block_transactions(block_hash, hex_only=True)
                    if not full_transactions
                    else None
                ),
                "full_transactions": (
                    await _node.db.get_block_nice_transactions(block_hash)
                    if full_transactions
                    else None
                ),
            },
        }
    else:
        result = {"ok": False, "error": "Not found"}

    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
    return result


@app.get("/get_blocks")
@limiter.limit("4/second")
async def get_blocks(
    request: Request,
    offset: int = Query(default=..., ge=0),
    limit: int = Query(default=..., le=512),
    pretty: bool = False,
):
    # Use QueryCostCalculator to prevent abuse of pagination
    client_ip = get_remote_address(request)
    await _node.security.query_calculator.check_and_update_cost(client_ip, offset, limit)

    from qrdx.history_pruning import HistoryPruned, require_history

    try:  # (a full node does not hold the bodies below its pruning point)
        await require_history(_node.db, offset, "serving these blocks")
    except HistoryPruned as e:
        return {"ok": False, "error": str(e)}
    blocks = await _node.db.get_blocks(offset, limit)

    # Return structured block data including transactions so that
    # syncing peers can reconstruct the chain.
    structured_blocks = []
    for block in blocks:
        block_hash = block.get("hash") or block.get("block_hash")
        txs = await _node.db.get_block_transactions(block_hash, hex_only=True) if block_hash else []
        # Attach protocol sections so a syncing node reconstructs exchange + EVM/
        # account state (E-D3b); trust-replayed on the consume side.
        if block_hash:
            try:
                ex_section = await _node.db.get_block_exchange_txs(block_hash)
                if ex_section:
                    block["exchange_transactions"] = ex_section
            except Exception:
                pass
            try:
                evm_section = await _node.db.get_block_evm_txs(block_hash)
                if evm_section:
                    block["evm_transactions"] = evm_section
            except Exception:
                pass
        structured_blocks.append({"block": block, "transactions": txs or []})

    result = {"ok": True, "result": structured_blocks}

    if pretty:
        return Response(
            content=json.dumps(result, indent=4, cls=CustomJSONEncoder),
            media_type="application/json",
        )
    return result


@app.api_route("/get_status", methods=["GET", "HEAD"])
async def get_status():
    """
    Returns the current block height, last block hash, and the node's ID.
    """
    try:
        height = await _node.db.get_next_block_id() - 1

        # Create a base response object that always includes the node's ID.
        response_data = {
            "height": height,
            "last_block_hash": None,
            "node_id": _node.self_node_id,  # This is the key addition
        }

        if height >= 0:
            last_block = await _node.db.get_block_by_id(height)
            if last_block:
                # If a block exists, add its hash to the response.
                response_data["last_block_hash"] = last_block["hash"]
            else:
                # This handles a rare edge case where the DB might be inconsistent.
                # We report height as -1 to signal a non-ready state.
                response_data["height"] = -1

        return {"ok": True, "result": response_data}

    except Exception as e:
        logger.error(f"Error in /get_status: {e}")
        await _node.security.security_monitor.log_event("get_status_error", {"error": str(e)})
        return {"ok": False, "error": "Internal server error"}


@app.post("/check_reachability")
@limiter.limit("2/minute")
async def check_reachability(
    request: Request, body: dict = Body(...), verified_sender: str = Depends(verified_sender)
):
    """
    A SECURED endpoint for a peer to ask us to check if they are reachable at a given URL.
    This endpoint is secured against SSRF, anonymous abuse, and DoS amplification.
    """
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    url_to_check = body.get("url_to_check")
    if not url_to_check:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Body must contain 'url_to_check'.")

    cached_result = await _node.security.reachability_cache.get(url_to_check)
    if cached_result is not None:
        logger.debug(f"Returning cached reachability for {url_to_check} for peer {verified_sender}")
        return {"ok": True, "result": {"reachable": cached_result, "cached": True}}

    is_valid, resolved_ip = await _node.security.dns_client.validate_and_resolve(url_to_check)
    if not is_valid:
        return {"ok": False, "error": "Invalid or unresolvable URL"}

    ip_obj = ipaddress.ip_address(resolved_ip)
    if not ip_obj.is_global:
        return {"ok": False, "error": "IP address is not globally routable and cannot be checked."}

    is_reachable = False
    try:
        # Use the single, shared, and persistent http_client
        response = await _node.http_client.get(url_to_check)
        if response.status_code > 0:
            is_reachable = True
    except httpx.RequestError as e:
        logger.warning(f"Reachability check failed for {url_to_check}: {e}")
        is_reachable = False

    await _node.security.reachability_cache.put(url_to_check, is_reachable)
    return {"ok": True, "result": {"reachable": is_reachable, "cached": False}}


@app.post("/get_mempool_hashes")
async def get_mempool_hashes(verified_sender: str = Depends(verified_sender)):
    """
    Returns a list of all transaction hashes currently in the pending pool.
    """
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    hashes = await _node.db.get_all_pending_transaction_hashes()
    return {"ok": True, "result": hashes}


@app.post("/get_transactions_by_hash")
@limiter.limit("20/minute")
async def get_transactions_by_hash(
    request: Request, body: dict = Body(...), verified_sender: str = Depends(verified_sender)
):
    """
    Accepts a list of transaction hashes and returns the full transaction data.
    """
    if not verified_sender:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Signed request required.")

    hashes_to_find = body.get("hashes")
    if not isinstance(hashes_to_find, list):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Body must contain a 'hashes' list.")

    if len(hashes_to_find) > MAX_TX_FETCH_LIMIT:
        await _node.security.reputation_manager.record_violation(
            verified_sender, "tx_fetch_limit_exceeded", severity=2
        )
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Request limit exceeded. Maximum {MAX_TX_FETCH_LIMIT} transactions per request.",
        )

    # Validate all hashes using the secure validator
    for hash_str in hashes_to_find:
        if not _node.security.input_validator.validate_hex(hash_str, min_length=64, max_length=64):
            await _node.security.reputation_manager.record_violation(
                verified_sender, "invalid_tx_hash_format", severity=3
            )
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, f"Invalid transaction hash format for hash: {hash_str}"
            )

    found_txs = await _node.db.get_pending_transactions_by_hash(hashes_to_find)
    tx_hex_list = [tx.hex() for tx in found_txs]

    return {"ok": True, "result": tx_hex_list}
