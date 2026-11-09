"""
QRDX p2p_* RPC Methods

Inter-node P2P communication via JSON-RPC 2.0.

These methods replace the legacy REST API endpoints for node-to-node
block/transaction propagation.  They are always registered (not gated
by QRDX_RPC_ENABLED) because they are essential for consensus.

Methods:
    p2p_submitBlock          – Accept a propagated block from a peer
    p2p_submitBlocks         – Accept a batch of blocks (push-sync)
    p2p_getStatus            – Return chain height & tip hash
    p2p_getBlock             – Return a single block + its transactions
    p2p_getBlocks            – Return a range of blocks for sync
    p2p_pushTx               – Accept a new transaction from a peer
    p2p_getMempoolHashes     – Return pending transaction hashes
    p2p_getTransactionsByHash – Return full transactions by hash list
    p2p_getPeers             – Return known peer list
    p2p_handshakeChallenge   – Issue a handshake challenge
    p2p_handshakeResponse    – Verify a handshake response
"""

import asyncio
import json
import time
from typing import Any, Dict, List, Optional

from ...constants import SLOTS_PER_EPOCH
from ...logger import get_logger
from ...node.observability import Phases
from ..server import (
    RPCError,
    RPCErrorCode,
    RPCModule,
    peer_only,
    rpc_caller,
    rpc_caller_meta,
    rpc_method,
)

logger = get_logger(__name__)

# Best-effort p2p metrics into the shared observability registry (no-op fallback so propagation
# never depends on it importing).
try:
    from ...node.observability import record as _metric
except Exception:  # pragma: no cover

    def _metric(name: str, amount: float = 1.0, labels: Optional[Dict[str, Any]] = None) -> None:
        return None


def handshake_proof_message(client_nonce: str, challenge_result: Dict[str, Any]) -> bytes:
    """What a node signs to prove, in a handshake, that it holds the key it presents: the
    caller's fresh nonce, the challenge, and every identity claim it makes — on this network
    (the signing domain), so a proof made elsewhere is worthless here."""
    from ... import chain_spec
    from ...node.identity import get_canonical_json_bytes

    claims = {
        k: challenge_result.get(k) for k in ("challenge", "node_id", "pubkey", "url", "network")
    }
    return chain_spec.signing_domain("p2p-handshake") + get_canonical_json_bytes(
        {"client_nonce": client_nonce, **claims}
    )


def validator_peer_message(node_id: str) -> bytes:
    """What a validator signs, with its validator key, to vouch that the node ``node_id`` is its
    own: a peer that proves it runs a validator holds a place in the peer table no newcomer
    takes (NodesManager.admit_peer). Bound to this network and to the node, so it serves no
    other node and no other chain."""
    from ... import chain_spec

    return chain_spec.signing_domain("peer-validator") + str(node_id).encode()


def verify_handshake_proof(client_nonce: str, challenge_result: Dict[str, Any]) -> Optional[str]:
    """Why the challenge answer does not prove the peer's identity, or None when it does: the
    node id must be the presented key's, and the proof that key's signature over the caller's
    nonce and the peer's claims."""
    from ...node.identity import node_id_for_public_key, verify_signature

    pubkey = challenge_result.get("pubkey") or ""
    if node_id_for_public_key(pubkey) != challenge_result.get("node_id"):
        return "node id is not the presented key's"
    proof = challenge_result.get("proof")
    if not proof or not verify_signature(
        pubkey, proof, handshake_proof_message(client_nonce, challenge_result)
    ):
        return "identity proof does not verify"
    return None


async def blocks_for_transfer(db: Any, offset: int, limit: int) -> List[Dict[str, Any]]:
    """Blocks ``offset``.. (at most ``limit``) as peers exchange them: each block row with its
    transactions and its protocol sections, so a node applying it reconstructs the exchange and
    EVM/account state exactly as forward application did (E-D3b). Used to serve sync and,
    locally, to keep a node's own branch while it tries a competing one (fork choice). Raises
    HistoryPruned for blocks below this node's pruning point (qrdx/history_pruning.py)."""
    from ...history_pruning import require_history

    await require_history(db, offset, "serving these blocks")
    structured = []
    for block in await db.get_blocks(offset, limit):
        block_hash = block.get("hash") or block.get("block_hash")
        txs = await db.get_block_transactions(block_hash, hex_only=True) if block_hash else []
        if block_hash:
            try:
                ex_section = await db.get_block_exchange_txs(block_hash)
                if ex_section:
                    block["exchange_transactions"] = ex_section
            except Exception:
                pass
            try:
                evm_section = await db.get_block_evm_txs(block_hash)
                if evm_section:
                    block["evm_transactions"] = evm_section
            except Exception:
                pass
        structured.append({"block": block, "transactions": txs or []})
    return structured


class P2PModule(RPCModule):
    """
    Inter-node P2P RPC methods (p2p_* namespace).

    Wired at startup via ``set_node_context()`` with references to the
    live database, security components, and propagation function.
    """

    namespace = "p2p"

    def __init__(self, context: Any = None):
        super().__init__(context)
        self._block_relay: Any = None  # compact blocks (qrdx/node/block_relay.py)
        self._rebuilding: set = set()  # (block hashes being rebuilt from a compact block now)
        self._db: Any = None
        self._security: Any = None
        self._propagate_fn: Any = None
        self._process_and_create_block: Any = None
        self._create_block: Any = None
        self._block_processing_lock: Any = None
        self._nodes_manager: Any = None
        self._self_node_id: Any = None
        self._handshake_manager: Any = None  # same object as security.handshake_manager
        self._sync_blockchain: Any = None
        self._follow_up_sync: Any = None
        self._evm_apply_section: Any = (
            None  # E-D3b importer hook (main._apply_evm_section_on_import)
        )
        self._exchange_apply_section: Any = (
            None  # D3/Phase E importer hook (main._apply_exchange_section_on_import)
        )
        self._verify_unified_root: Any = (
            None  # E-D4 importer hook (main._verify_unified_state_root)
        )
        self._check_parent_continuity: Any = (
            None  # parent-continuity hook (main._check_parent_continuity)
        )
        # deferred execution: async (content, height) -> (ok, err), the signed root against the
        # state the parent left, before the block runs (block_import._check_deferred_root)
        self._check_deferred_root: Any = None
        self._restore_after_rejected_block: Any = None  # undo a rejected block's effects (main)
        self._tiebreak_rollback: Any = None  # mechanism-2 rollback hook (main._tiebreak_rollback)
        self._enforce_equal_height_tiebreak = False  # mechanism-2 enforce gate (observe-first)
        self._enforce_proposer_eligibility = False  # slot-eligibility gate (observe-first)
        self._add_remote_attestation: Any = (
            None  # attestation-gossip receive hook (main._add_remote_attestation)
        )
        self._network_identity: Any = None  # async () -> this node's network identity (main)
        self._check_peer_identity: Any = None  # async (remote) -> (ok, reason) (main)
        # async (content, height, exchange section, evm section, hash) -> (ok, err) (main)
        self._verify_chain_rules: Any = None
        self._on_fork: Any = None  # (peer id, reason) -> None: resolve a fork now (main)
        # async (node id, request meta, validator proof) -> None: admit a handshaken caller
        self._admit_peer: Any = None

    # ---- wiring (called once at startup from main.py) --------------------

    def set_node_context(
        self,
        *,
        db,
        security,
        propagate_fn,
        process_and_create_block,
        create_block,
        block_processing_lock,
        nodes_manager,
        self_node_id: str,
        sync_blockchain,
        follow_up_sync=None,
        evm_apply_section=None,
        exchange_apply_section=None,
        verify_unified_root=None,
        check_parent_continuity=None,
        restore_after_rejected_block=None,
        tiebreak_rollback=None,
        enforce_equal_height_tiebreak=False,
        enforce_proposer_eligibility=False,
        add_remote_attestation=None,
        network_identity=None,
        check_peer_identity=None,
        verify_chain_rules=None,
        on_fork=None,
        admit_peer=None,
        block_relay=None,
        check_deferred_root=None,
    ):
        self._db = db
        self._security = security
        self._propagate_fn = propagate_fn
        self._process_and_create_block = process_and_create_block
        self._create_block = create_block
        self._block_processing_lock = block_processing_lock
        self._nodes_manager = nodes_manager
        self._self_node_id = self_node_id
        self._sync_blockchain = sync_blockchain
        self._follow_up_sync = follow_up_sync
        self._evm_apply_section = evm_apply_section
        self._exchange_apply_section = exchange_apply_section
        self._verify_unified_root = verify_unified_root
        self._check_parent_continuity = check_parent_continuity
        self._check_deferred_root = check_deferred_root
        self._restore_after_rejected_block = restore_after_rejected_block
        self._tiebreak_rollback = tiebreak_rollback
        self._enforce_equal_height_tiebreak = enforce_equal_height_tiebreak
        self._enforce_proposer_eligibility = enforce_proposer_eligibility
        self._add_remote_attestation = add_remote_attestation
        self._network_identity = network_identity
        self._check_peer_identity = check_peer_identity
        self._verify_chain_rules = verify_chain_rules
        self._on_fork = on_fork
        self._admit_peer = admit_peer
        self._block_relay = block_relay

    def _signal_fork(self, block_no: Any, block_data: Dict, reason: str) -> None:
        """A peer sent a block that does not extend our tip: let fork choice compare its chain
        with ours now (main.schedule_fork_resolution), rather than at the next periodic pass."""
        sender = rpc_caller.get()
        if self._on_fork is None or not sender:
            return
        try:
            self._on_fork(sender, f"{reason} (height {block_no})")
        except Exception as e:
            logger.debug(f"fork signal dropped: {e}")

    def _require_db(self):
        if self._db is None:
            raise RPCError(RPCErrorCode.RESOURCE_UNAVAILABLE, "Node not ready")

    # =====================================================================
    # BLOCK ENDPOINTS
    # =====================================================================

    async def _restore_after_rejection(self, block_no, reason: str) -> None:
        """Undo a rejected block's already-applied effects (see main._restore_after_rejected_block).

        The sections run before the final checks and do not all roll back on their own, so a
        block rejected at the EVM root check or at E-D4 would otherwise leave its effects in
        this node's derived state. The caller holds the block-processing lock."""
        if self._restore_after_rejected_block is None:
            return
        try:
            await self._restore_after_rejected_block(block_no, reason)
        except Exception as e:
            logger.error("restore after rejected block %s failed: %s", block_no, e)

    async def _equal_height_incoming_wins(self, block_no, block_data, block_content) -> bool:
        """Fork-choice convergence (mechanism-2). Compare an incoming block at an
        already-filled height to the one we stored: if they share a parent but
        differ (an equal-height fork), decide whether the incoming WINS the
        lowest-hash canonical rule. Logs the comparison and returns True iff the
        incoming should replace the stored block. Pure read; never mutates state."""
        from ...validator.block_verification import (
            _parse_block_content,
            reconstruct_signing_root,
        )

        stored = await self._db.get_block_by_id(block_no)
        if not stored:
            return False
        stored_hash = stored.get("hash") or stored.get("block_hash")
        incoming_hash = block_data.get("block_hash")
        if not stored_hash or not incoming_hash or stored_hash == incoming_hash:
            return False  # same block (a re-broadcast) — not a fork
        try:  # the hash it was sent under must be its header's: a sender cannot choose it
            if (
                str(incoming_hash).lower().removeprefix("0x")
                != reconstruct_signing_root(_parse_block_content(block_content)).hex()
            ):
                return False
        except Exception:
            return False
        try:
            inc_parent = _parse_block_content(block_content).get("parent_hash")
            stored_parent = _parse_block_content(
                stored.get("content") or stored.get("block_content")
            ).get("parent_hash")
        except Exception:
            inc_parent = stored_parent = None
        if inc_parent and stored_parent and inc_parent != stored_parent:
            return False  # different parent → not an equal-height equivalent fork
        incoming_wins = str(incoming_hash) < str(stored_hash)  # lowest-hash rule
        logger.warning(
            "[fork-choice %s] equal-height fork at h=%d: stored=%s incoming=%s "
            "-> %s wins (lowest-hash); %s",
            "ENFORCE" if self._enforce_equal_height_tiebreak else "observe",
            block_no,
            str(stored_hash)[:12],
            str(incoming_hash)[:12],
            "incoming" if incoming_wins else "stored",
            (
                ("REPLACING" if incoming_wins else "keeping stored")
                if self._enforce_equal_height_tiebreak
                else ("would REPLACE" if incoming_wins else "would keep stored")
            ),
        )
        # Slashing detection (observe): an equal-height fork whose two blocks share the
        # SAME proposer + slot is a DOUBLE_SIGN (the eligible proposer signed two blocks
        # for its slot) — distinct from the benign distinct-proposer race. Record durable
        # evidence; the deterministic stake penalty is a follow-up.
        try:
            await self._detect_and_record_double_sign(
                block_no, block_content, stored.get("content") or stored.get("block_content")
            )
        except Exception as e:
            logger.debug("double-sign detection skipped at h=%d: %s", block_no, e)
        return incoming_wins

    async def _detect_and_record_double_sign(
        self, block_no, incoming_content, stored_content
    ) -> bool:
        """If the two competing blocks at ``block_no`` are a same-proposer/same-slot
        DOUBLE_SIGN, persist slashing evidence (idempotent). Observe-only — records
        evidence, applies no penalty. Returns True if evidence was newly recorded."""
        from ...validator.block_verification import _parse_block_content, is_double_sign
        from ...validator.slashing_block import (
            make_double_sign_evidence,
            verify_double_sign_evidence,
        )

        if not is_double_sign(incoming_content, stored_content):
            return False
        c = _parse_block_content(incoming_content)
        proposer = c.get("proposer_address")
        slot = int(c.get("slot") or 0)
        stated_epoch = c.get("epoch")
        epoch = int(stated_epoch) if stated_epoch is not None else slot // SLOTS_PER_EPOCH
        # Build the SELF-VALIDATING proof (both signed headers, and the proposer's key, which
        # blocks no longer carry) so the evidence can ride the canonical chain (block body) and
        # every importer can verify it with no external state.
        from ...validator.ffg import validator_key

        key = await validator_key(self._db, str(proposer), int(block_no))
        evidence = make_double_sign_evidence(
            c, _parse_block_content(stored_content), key.hex() if key else None
        )
        ok_ev, ev_err = verify_double_sign_evidence(evidence)
        if not ok_ev:
            # is_double_sign matched proposer+slot+hash but a header isn't validly signed —
            # do NOT record an unslashable proof (a real double-sign has two valid signatures).
            logger.debug("double-sign at h=%d not a verifiable proof: %s", block_no, ev_err)
            return False
        new = await self._db.record_slashing_event(
            proposer, "double_sign", slot, epoch, json.dumps(evidence)
        )
        logger.warning(
            "[slashing observe] DOUBLE_SIGN by %s at slot %d (h=%d) — evidence %s",
            str(proposer)[:20],
            slot,
            block_no,
            "recorded" if new else "already known",
        )
        return new

    @rpc_method
    @peer_only
    async def submitBlock(self, block_data: Dict) -> Dict:
        """
        Accept a single propagated block from a peer.

        Mirrors the old ``POST /submit_block`` REST endpoint but without
        the Dilithium-signed-request requirement—the RPC transport layer
        handles authentication at a higher level (or not, for open P2P).

        Args:
            block_data: dict with keys block_content, id/block_no,
                        and optionally block_hash + validator_address (PoS).

        Returns:
            ``{"ok": True, "result": "..."}`` on success.
        """
        self._require_db()
        _metric("qrdx_p2p_blocks_received_total")
        _received = time.perf_counter()
        phases = Phases()

        block_content = block_data.get("block_content")
        if not block_content:
            return {"ok": False, "error": "Missing block_content"}

        block_no = block_data.get("id") or block_data.get("block_no")
        if block_no is None:
            return {"ok": False, "error": "Missing block ID"}

        # ---- Idempotency: skip blocks we already have ----
        from hashlib import sha256

        block_identifier = sha256(block_content.encode()).hexdigest()
        if await self._security.block_cache.contains(block_identifier):
            return {"ok": False, "error": "Block recently seen"}

        # ---- Sync guard ----
        if self._security.sync_state_manager.is_syncing:
            return {"ok": False, "error": "Node is synchronizing"}

        async with self._block_processing_lock:
            phases.mark("lock")
            next_block_id = await self._db.get_next_block_id()

            if next_block_id > block_no:
                # Fork-choice mechanism-2: a block at an already-filled height is
                # normally dropped as "too old". When it is a COMPETING block at the
                # just-filled tip (same parent, different hash) that WINS the
                # lowest-hash canonical rule, adopt it: roll back the losing tip +
                # rebuild derived state (injected hook), then FALL THROUGH so the
                # normal acceptance flow below validates + stores the winner at the
                # now-reopened height. Observe (flag off): just log, still drop.
                # See docs/FORK_CHOICE_CONVERGENCE.md.
                if block_no == next_block_id - 1:
                    try:
                        incoming_wins = await self._equal_height_incoming_wins(
                            block_no, block_data, block_content
                        )
                    except Exception:
                        incoming_wins = False
                    if (
                        incoming_wins
                        and self._enforce_equal_height_tiebreak
                        and self._tiebreak_rollback is not None
                    ):
                        try:
                            await self._tiebreak_rollback(block_no)
                            next_block_id = await self._db.get_next_block_id()
                        except Exception as e:
                            logger.error(
                                "[fork-choice ENFORCE] tie-break rollback failed at h=%d: %s",
                                block_no,
                                e,
                            )
                            return {"ok": False, "error": "Too old block"}
                        # rollback succeeded → next_block_id should now == block_no;
                        # fall through to normal acceptance only if so.
                        if next_block_id != block_no:
                            return {"ok": False, "error": "Too old block"}
                    else:
                        self._signal_fork(block_no, block_data, "a competing block at our tip")
                        return {"ok": False, "error": "Too old block"}
                else:
                    return {"ok": False, "error": "Too old block"}

            if next_block_id < block_no:
                # Peer is ahead—request sync (and check whether it is on another branch).
                self._signal_fork(block_no, block_data, "a block above our tip")
                return {
                    "ok": False,
                    "error": "sync_required",
                    "result": {"next_block_expected": next_block_id},
                }

            await self._security.block_cache.put(block_identifier, True)

            # --- PoS fast-path ---
            block_hash = block_data.get("block_hash")
            validator_address = block_data.get("validator_address")
            if block_hash and validator_address:
                if not self._security.input_validator.validate_hex(
                    block_hash, min_length=16, max_length=128
                ):
                    return {"ok": False, "error": "Invalid block hash format"}

                if block_no != next_block_id:
                    return {"ok": False, "error": "Block height mismatch"}

                from ...validator.epoch_state import is_validator

                if not await is_validator(self._db, validator_address, block_content, block_no - 1):
                    return {"ok": False, "error": "Validator not registered"}

                # Security: authenticate the proposer (pubkey↔address binding +
                # Dilithium signature over the signed header). Registration alone
                # does not prove the block was produced by that validator.
                from ...validator.block_verification import (
                    verify_block_proposer,
                    verify_proposer_eligibility,
                )

                ok_prop, prop_err = await verify_block_proposer(
                    self._db, block_content, validator_address, block_no
                )
                if not ok_prop:
                    return {"ok": False, "error": f"Proposer authentication failed: {prop_err}"}
                phases.mark("proposer")

                # Proposer must be eligible for the block's slot. Observe-first
                # (the _enforce_proposer_eligibility flag is injected from main.py).
                ok_elig, elig_err = await verify_proposer_eligibility(
                    self._db,
                    block_content,
                    enforce=bool(self._enforce_proposer_eligibility),
                    height=int(block_no),
                )
                if not ok_elig:
                    return {"ok": False, "error": f"Proposer ineligible: {elig_err}"}
                phases.mark("eligibility")

                # Parent-hash continuity (observe-first): the block's parent_hash
                # must match the local tip, else it is on a fork. Injected hook
                # (main._check_parent_continuity); observe-only for now.
                if self._check_parent_continuity is not None:
                    try:
                        ok_par, par_err = await self._check_parent_continuity(
                            block_no, block_content
                        )
                    except Exception as e:
                        ok_par, par_err = True, f"parent-continuity check error: {e}"
                    if not ok_par:
                        self._signal_fork(block_no, block_data, "a block on another branch")
                        return {"ok": False, "error": f"Parent discontinuity: {par_err}"}
                    phases.mark("parent")

                # Block limits, slot progression and FFG votes (main._verify_chain_rules).
                if self._verify_chain_rules is not None:
                    try:
                        ok_votes, votes_err = await self._verify_chain_rules(
                            block_content,
                            block_no,
                            block_data.get("exchange_transactions"),
                            block_data.get("evm_transactions"),
                            block_hash,
                        )
                    except Exception as e:
                        ok_votes, votes_err = False, f"vote verification error: {e}"
                    if not ok_votes:
                        return {"ok": False, "error": f"Chain rules: {votes_err}"}

                # Deferred execution (qrdx/post_state.py): the signed root is the state the parent
                # left, the state this node holds; checked before the block runs.
                if self._check_deferred_root is not None:
                    ok_root, root_err = await self._check_deferred_root(
                        block_content, int(block_no)
                    )
                    if not ok_root:
                        return {"ok": False, "error": f"Refused before running: {root_err}"}

                # Two blocks (qrdx/validator/pipeline.py): when this node proposes the next slot
                # and this block would not have run by then, it builds and sends the next block
                # first — judged on the state now and this block's contents — then runs this one.
                from ...validator import pipeline

                phases.mark("rules")
                ahead = None
                if pipeline.PROPOSER is not None:
                    try:
                        ahead = await pipeline.PROPOSER.propose_ahead(block_data, int(block_no))
                    except Exception as e:
                        logger.warning(f"Building on block {block_no} before it ran failed: {e}")
                    if ahead is not None:
                        phases.mark("ahead")
                try:
                    return await self._run_pos_block(
                        block_data, block_no, block_hash, block_content, validator_address,
                        phases, _received, ahead,
                    )  # fmt: skip
                finally:
                    if ahead is not None and not ahead.finished:
                        logger.warning(
                            f"Block #{ahead.height}, sent before its parent ran, is dropped: "
                            f"its parent {block_no} was refused"
                        )

            # --- Legacy PoW path ---

            from ...transactions import Transaction

            txs_data = block_data.get("txs", [])
            final_transactions = []

            if isinstance(txs_data, str):
                txs_data = txs_data.split(",") if txs_data else []

            tx_hashes_to_find = []
            for tx_hex in txs_data:
                if isinstance(tx_hex, str) and len(tx_hex) == 64:
                    tx_hashes_to_find.append(tx_hex)
                else:
                    final_transactions.append(await Transaction.from_hex(tx_hex))

            if tx_hashes_to_find:
                db_results = await self._db.get_pending_transactions_by_hash(tx_hashes_to_find)
                if len(db_results) < len(tx_hashes_to_find):
                    return {"ok": False, "error": "Transaction hash not found"}
                tx_map = {tx.hash(): tx for tx in db_results}
                final_transactions.extend([tx_map.get(h) for h in tx_hashes_to_find])

            if not await self._create_block(block_content, final_transactions):
                return {"ok": False, "error": "Block failed validation"}

            logger.info(f"Accepted PoW block {block_no} via RPC. Propagating...")
            asyncio.create_task(
                self._propagate_fn("submit_block", block_data, ignore_node_id=None, db=self._db)
            )
            return {"ok": True, "result": f"Block {block_no} accepted."}

    async def _slot_timing(self, block_content: Any, received: float) -> str:
        """When a block arrived and was done, in ms into its own slot (", slot +A→+D ms"): what
        shows a block running late — its proposer's start, its trip, or its import."""
        try:
            from ...constants import SLOT_DURATION_MS
            from ...validator.block_verification import _parse_block_content, genesis_time

            origin = await genesis_time(self._db)
            slot = int(_parse_block_content(block_content)["slot"])
            start = float(origin) + slot * int(SLOT_DURATION_MS) / 1000  # type: ignore[arg-type]
            now = time.time()
            arrived = now - (time.perf_counter() - received)
            return f", slot +{1000 * (arrived - start):.0f}→+{1000 * (now - start):.0f} ms"
        except Exception:
            return ""

    async def _run_pos_block(
        self,
        block_data: Dict,
        block_no: Any,
        block_hash: str,
        block_content: Any,
        validator_address: str,
        phases: Phases,
        _received: float,
        ahead: Any,
    ) -> Dict:
        """Run a verified PoS block's sections, check its root, store it and relay it — then run
        and store the block this node built on it before it ran (``ahead``), if any."""
        # Everything the block changes from here is recorded in the undo journal under its
        # height (a checkpoint first if it opens an epoch) — what makes a later reorg cheap.
        from ...derived_state_rebuild import before_block
        from ...validator.block_verification import epoch_from_block as _block_epoch

        stored = False
        try:
            async with await before_block(self._db, block_no, _block_epoch(block_data)):
                phases.mark("journal")
                # D3: securely validate + replay the exchange section (verify
                # signatures, re-execute, match the declared exchange_state_root)
                # BEFORE storing. Reject the block on any mismatch — local
                # exchange state is left untouched.
                ex_section = block_data.get("exchange_transactions")
                if ex_section:
                    try:
                        if self._exchange_apply_section is not None:
                            # Phase E: route through the importer hook so the
                            # collateral flush (margin debit → account_state) runs
                            # on this live-broadcast path too — otherwise only the
                            # proposer/sync paths debit and account_state diverges.
                            from ...validator.block_verification import epoch_from_block

                            ok_ex, verr = await self._exchange_apply_section(
                                block_no,
                                float(block_data.get("timestamp", 0) or 0),
                                # (a compact block's: the mempool's own, already checked)
                                block_data.get("_exchange_objects") or ex_section,
                                block_data.get("exchange_state_root"),
                                epoch_from_block(block_data),
                            )
                        else:
                            from ...exchange.block_processor import apply_block_exchange_section

                            ok_ex, verr = apply_block_exchange_section(
                                block_no,
                                float(block_data.get("timestamp", 0) or 0),
                                ex_section,
                                block_data.get("exchange_state_root"),
                            )
                    except Exception as e:
                        ok_ex, verr = False, f"exchange validation error: {e}"
                    if not ok_ex:
                        # Half-applied (there is no per-block revert point): back to the tip.
                        await self._restore_after_rejection(block_no, f"exchange section: {verr}")
                        return {"ok": False, "error": f"Invalid exchange section: {verr}"}
                    phases.mark("exchange")
                elif block_no and int(block_no) >= 1:
                    # No exchange transactions — the exchange still ticks every block (mark
                    # prices; liquidations and funding next), exactly as the other paths do.
                    try:
                        from ...exchange.block_processor import (
                            ensure_oracle_committee,
                            tick_and_flush,
                        )
                        from ...exchange.state_manager import ExchangeStateManager

                        await ensure_oracle_committee(
                            self._db, ExchangeStateManager.get_instance(), int(block_no)
                        )
                        await tick_and_flush(
                            self._db, int(block_no), float(block_data.get("timestamp", 0) or 0)
                        )
                    except Exception as e:
                        logger.error(f"exchange tick failed at block {block_no}: {e}")
                    phases.mark("tick")

                # E-D3b: validate + replay the EVM section (execute-on-mine) before
                # storing; reject on account_state_root mismatch. The apply hook is
                # injected from main.py (shares the live executor + state manager).
                evm_section = block_data.get("evm_transactions")
                if evm_section and self._evm_apply_section is not None:
                    try:
                        ok_evm, verr_evm = await self._evm_apply_section(
                            block_no,
                            block_hash,
                            int(block_data.get("timestamp", 0) or 0),
                            evm_section,
                            block_data.get("account_state_root"),
                        )
                    except Exception as e:
                        ok_evm, verr_evm = False, f"evm validation error: {e}"
                    if not ok_evm:
                        await self._restore_after_rejection(block_no, f"EVM section: {verr_evm}")
                        return {"ok": False, "error": f"Invalid EVM section: {verr_evm}"}
                    phases.mark("evm")

                # Stake withdrawals — same point as the proposer and the other import
                # paths: after the EVM section, before the unified-root check.
                try:
                    from ...validator.block_verification import epoch_from_block
                    from ...validator.withdrawals import process_block_withdrawals

                    _wd_epoch = epoch_from_block(block_data)
                    if _wd_epoch is not None:
                        await process_block_withdrawals(self._db, int(block_no), int(_wd_epoch))
                except Exception as e:
                    logger.error(
                        "withdrawal processing failed on p2p import of block %s: %s",
                        block_no,
                        e,
                    )
                phases.mark("withdrawals")

                # E-D4: verify the recomputed unified state root against the signed
                # root (after section replay, before storing).
                if self._verify_unified_root is not None:
                    try:
                        ok_root, root_err = await self._verify_unified_root(
                            block_content, height=int(block_no), block_hash=block_hash
                        )
                    except Exception as e:
                        ok_root, root_err = True, f"unified root check error: {e}"
                    if not ok_root:
                        await self._restore_after_rejection(block_no, f"E-D4: {root_err}")
                        return {"ok": False, "error": f"Invalid state root: {root_err}"}
                phases.mark("root")

                try:
                    await self._db.add_block(
                        block_hash=block_hash,
                        block_height=block_no,
                        block_content=block_content or "",
                        validator_address=validator_address,
                        timestamp=block_data.get("timestamp", 0),
                    )
                    # Persist the (validated) exchange section for durability.
                    if ex_section:
                        try:
                            await self._db.add_block_exchange_txs(
                                block_hash, ex_section, block_data.get("_exchange_objects")
                            )
                        except Exception as e:
                            logger.warning(
                                f"Failed to store exchange section for block {block_no}: {e}"
                            )
                    # Persist the (validated) EVM section for durability/rebuild.
                    if evm_section:
                        try:
                            await self._db.add_block_evm_txs(block_hash, evm_section)
                        except Exception as e:
                            logger.warning(f"Failed to store EVM section for block {block_no}: {e}")
                    phases.mark("store")
                    if self._block_relay is not None:
                        try:
                            self._block_relay.settle(block_data)
                        except Exception as e:  # (hygiene: never fails an import)
                            logger.debug(f"mempool settle after block {block_no}: {e}")
                    # Finality (observe): record attestation votes + recompute.
                    try:
                        from ...validator.finality import record_finality_from_block

                        await record_finality_from_block(self._db, block_content)
                    except Exception as e:
                        logger.debug(f"finality record skipped for block {block_no}: {e}")
                    phases.mark("finality")
                    logger.info(
                        f"Accepted PoS block {block_no} via RPC "
                        f"({1000 * (time.perf_counter() - _received):.0f} ms: {phases}"
                        f"{await self._slot_timing(block_content, _received)}). Propagating..."
                    )
                    asyncio.create_task(
                        self._propagate_fn(
                            "submit_block", block_data, ignore_node_id=None, db=self._db
                        )
                    )
                    # Immediate follow-up sync check — with the node that verifiably sent the
                    # block (its signed request), never one a sender merely names.
                    sender = rpc_caller.get()
                    if self._follow_up_sync and sender:
                        asyncio.create_task(self._follow_up_sync(sender))
                    stored = True
                    return {"ok": True, "result": f"Block {block_no} accepted."}
                except Exception as e:
                    logger.error(f"Failed to store PoS block {block_no}: {e}")
                    return {"ok": False, "error": "Storage failure"}
        finally:
            if stored:
                from ...validator import pipeline

                if ahead is not None:
                    # (after this block's journal and undo scope closed: the next block's own)
                    ahead.finished = True
                    try:
                        await pipeline.PROPOSER.finish_ahead(ahead)
                    except Exception as e:
                        logger.error(f"Block #{ahead.height}, built on {block_no}: {e}")

    @rpc_method
    @peer_only
    async def submitBlocks(self, blocks: List[Dict]) -> Dict:
        """
        Accept a batch of blocks during push-sync.

        Args:
            blocks: list of block dicts (each with id, block_content, txs).

        Returns:
            ``{"ok": True, "result": "..."}`` on success.
        """
        self._require_db()

        if not blocks:
            return {"ok": False, "error": "Empty batch"}

        # Sync guard
        if self._security.sync_state_manager.is_syncing:
            return {"ok": False, "error": "Node is synchronizing"}

        async with self._block_processing_lock:
            next_expected = await self._db.get_next_block_id()
            first_in_batch = blocks[0].get("id")

            if first_in_batch is None:
                return {"ok": False, "error": "Missing block ID in batch"}

            if first_in_batch != next_expected:
                return {
                    "ok": False,
                    "error": f"Block sequence out of order. Expected {next_expected}, got {first_in_batch}.",
                }

            accepted = 0
            for block_data in blocks:
                block_id = block_data.get("id")
                current_expected = await self._db.get_next_block_id()

                if block_id != current_expected:
                    return {
                        "ok": False,
                        "error": (
                            f"Block sequence desynchronized at block {block_id}. "
                            f"Expected {current_expected}."
                        ),
                    }

                block_info = {
                    "block": {
                        "id": block_id,
                        "content": block_data.get("block_content", ""),
                        "hash": block_data.get("block_hash", ""),
                        "address": block_data.get("validator_address", ""),
                        "timestamp": block_data.get("timestamp", 0),
                    },
                    "transactions": block_data.get("txs", []),
                }
                # Carry the protocol sections (+ any declared roots) through to the
                # consumer so a push-synced node reconstructs exchange + EVM state.
                for _k in (
                    "exchange_transactions",
                    "exchange_state_root",
                    "evm_transactions",
                    "account_state_root",
                ):
                    if block_data.get(_k):
                        block_info["block"][_k] = block_data[_k]

                if not await self._process_and_create_block(block_info):
                    return {
                        "ok": False,
                        "error": f"Failed to process block {block_id}",
                    }
                accepted += 1

        return {"ok": True, "result": f"{accepted} blocks accepted."}

    # =====================================================================
    # CHAIN QUERY ENDPOINTS
    # =====================================================================

    @rpc_method
    async def getStatus(self) -> Dict:
        """Return current chain height and tip hash."""
        self._require_db()

        height = await self._db.get_next_block_id() - 1
        response = {
            "height": height,
            "last_block_hash": None,
            "node_id": self._self_node_id,
        }
        if self._network_identity is not None:
            # Network, genesis and fork id (docs/PROTOCOL_UPGRADES.md): what a peer checks
            # before following this node, and how an operator sees who is ready for a fork.
            response["network"] = await self._network_identity()

        if height >= 0:
            read = getattr(self._db, "get_block_header", None) or self._db.get_block_by_id
            last_block = await read(height)
            if last_block:
                response["last_block_hash"] = last_block["hash"]
            else:
                response["height"] = -1
        try:
            # Informational (fork choice never trusts it: it scores a peer's branch from the
            # branch's own blocks — qrdx/validator/ffg.py).
            from ...validator.ffg import compute

            state = await compute(self._db)
            if state is not None:
                response["justified_epoch"] = max(state.justified)
                response["finalized_epoch"] = state.finalized[0]
        except Exception:
            pass
        # The snapshot this node publishes for checkpoint sync, if any (QRDX_SNAPSHOT_DIR):
        # its manifest and where it is served. Never trusted by the node that fetches it.
        from ...snapshot_publisher import advertised

        snapshot = advertised()
        if snapshot is not None:
            response["snapshot"] = snapshot

        return response

    @rpc_method
    async def getBlockHashes(self, start: int, end: int) -> Dict:
        """{height: hash} of this node's chain for ``start``..``end`` (at most 1024 heights):
        how a peer finds the common ancestor of two chains in one call."""
        self._require_db()
        start, end = int(start), int(end)
        if end < start:
            return {"ok": True, "result": {}}
        end = min(end, start + 1023)
        hashes = await self._db.get_block_hashes(start, end)
        return {"ok": True, "result": {str(h): bh for h, bh in hashes.items()}}

    @rpc_method
    async def getBlock(self, block: str) -> Dict:
        """
        Return a single block and its transactions.

        Args:
            block: Block height (decimal string) or block hash (hex).

        Returns:
            ``{"ok": True, "result": {"block": {...}, "transactions": [...]}}``
        """
        self._require_db()

        block_info = None
        block_hash = None

        if block.isdecimal():
            block_id = int(block)
            block_info = await self._db.get_block_by_id(block_id)
            if block_info:
                block_hash = block_info["hash"]
        else:
            block_hash = block
            block_info = await self._db.get_block(block_hash)

        if block_info:
            txs = (
                await self._db.get_block_transactions(block_hash, hex_only=True)
                if block_hash
                else []
            )
            return {
                "ok": True,
                "result": {"block": block_info, "transactions": txs or []},
            }
        return {"ok": False, "error": "Not found"}

    @rpc_method
    async def getBlocks(self, offset: int, limit: int) -> Dict:
        """
        Return a range of blocks for chain sync.

        Args:
            offset: Start block height.
            limit:  Maximum number of blocks.

        Returns:
            ``{"ok": True, "result": [{block, transactions}, ...]}``
        """
        from ...history_pruning import HistoryPruned

        self._require_db()
        try:
            blocks = await blocks_for_transfer(self._db, offset, min(limit, 512))
        except HistoryPruned as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "result": blocks}

    # =====================================================================
    # TRANSACTION ENDPOINTS
    # =====================================================================

    @rpc_method
    @peer_only
    async def submitCompactBlock(self, block_data: Dict) -> Dict:
        """A block whose exchange operations are named by hash (qrdx/node/block_relay.py): rebuilt
        from this node's mempool and what the sender sends of the rest, then accepted exactly as
        ``submitBlock`` accepts a whole one. A rebuilt body that is not the signed one is
        fetched whole and tried once more."""
        if self._block_relay is None:
            raise RPCError(RPCErrorCode.METHOD_NOT_FOUND, "compact blocks are not relayed here")
        if not isinstance(block_data, dict):
            return {"ok": False, "error": "a block is an object"}
        # A block this node has: its own, echoed back by each peer that relays it, or one it
        # already took from another peer. Its operations have left the mempool, so rebuilding it
        # fetched every one of them from the sender, for submitBlock to drop it as seen.
        self._require_db()
        content = block_data.get("block_content")
        if isinstance(content, str):
            from hashlib import sha256

            if await self._security.block_cache.contains(sha256(content.encode()).hexdigest()):
                return {"ok": False, "error": "Block recently seen"}
        known = block_data.get("block_hash")
        if isinstance(known, str) and await self._db.get_block(known) is not None:
            return {"ok": False, "error": "Block recently seen"}
        # The same block from several relays at once: rebuilt once (each copy fetched its
        # missing operations again before the first was stored).
        if isinstance(known, str):
            if known in self._rebuilding:
                return {"ok": False, "error": "Block recently seen"}
            self._rebuilding.add(known)
        try:
            sender_url = self._sender_url()
            full, why = await self._block_relay.rebuild(
                block_data, sender_url, sender_node=rpc_caller.get()
            )
            if full is None:
                return {"ok": False, "error": why}
            reply = await self.submitBlock(full)
            if not reply.get("ok") and "body_root" in str(reply.get("error", "")):
                full, why = await self._block_relay.rebuild(block_data, sender_url, whole=True)
                if full is None:
                    return {"ok": False, "error": why}
                reply = await self.submitBlock(full)
            return reply
        finally:
            if isinstance(known, str):
                self._rebuilding.discard(known)

    @rpc_method
    @peer_only
    async def getBlockTxs(self, block_hash: str, indexes: List[int]) -> Dict:
        """The exchange operations at ``indexes`` of a block this node relayed lately, for a peer
        rebuilding it from a compact block."""
        if self._block_relay is None or not isinstance(indexes, list):
            return {"ok": False, "error": "unavailable"}
        txs = self._block_relay.body_txs(str(block_hash), indexes)
        if txs is None:
            return {"ok": False, "error": "unknown block or positions"}
        return {"ok": True, "result": txs}

    def _sender_url(self) -> Optional[str]:
        """Where the verified caller is reached: its peer entry, else the URL it signed."""
        caller = rpc_caller.get()
        if caller and self._nodes_manager is not None:
            peer = self._nodes_manager.get_peer(caller)
            if peer and peer.get("url"):
                return peer["url"]
        meta = rpc_caller_meta.get() or {}
        return meta.get("url")

    @rpc_method
    @peer_only
    async def pushTx(self, tx_hex: str) -> Dict:
        """
        Accept a new transaction from a peer.

        Args:
            tx_hex: Hex-encoded transaction.
        """
        self._require_db()

        from ...transactions import Transaction

        try:
            tx = await Transaction.from_hex(tx_hex)
        except Exception:
            return {"ok": False, "error": "Invalid transaction"}

        try:
            await self._db.add_pending_transaction(tx)
        except Exception:
            return {"ok": False, "error": "Transaction rejected"}

        # Propagate to other peers (fire-and-forget)
        asyncio.create_task(self._propagate_fn("push_tx", {"tx_hex": tx_hex}, db=self._db))
        return {"ok": True, "result": "Transaction accepted"}

    @rpc_method
    @peer_only
    async def pushAttestation(self, attestation: Dict) -> Dict:
        """
        Accept a gossiped validator attestation from a peer (finality-gossip). The
        injected hook verifies the signature against the attester's registered pubkey,
        adds it to this node's attestation pool (so a proposer includes it in its next
        block → it reaches every node's attestation_votes → finality coverage), and
        re-gossips it once. Idempotent + best-effort; an unknown/invalid/duplicate
        attestation is simply not re-propagated.
        """
        if self._add_remote_attestation is None:
            return {"ok": True, "result": "ignored (no handler)"}
        try:
            sender = (
                attestation.pop("_sender_node_id", None) if isinstance(attestation, dict) else None
            )
            accepted = await self._add_remote_attestation(attestation, sender)
            return {"ok": True, "result": "accepted" if accepted else "duplicate/ignored"}
        except Exception as e:
            return {"ok": False, "error": f"attestation rejected: {e}"}

    @rpc_method
    async def getMempoolHashes(self) -> Dict:
        """Return hashes of all pending transactions."""
        self._require_db()

        try:
            hashes = await self._db.get_all_pending_transaction_hashes()
        except Exception:
            hashes = []
        return {"ok": True, "result": {"hashes": hashes or []}}

    @rpc_method
    async def getTransactionsByHash(self, hashes: List[str]) -> Dict:
        """
        Return full transactions by hash list.

        Args:
            hashes: list of 64-char hex transaction hashes.
        """
        self._require_db()

        results = await self._db.get_pending_transactions_by_hash(hashes)
        return {
            "ok": True,
            "result": {"transactions": [tx.hex() for tx in results]},
        }

    # =====================================================================
    # PEER / HANDSHAKE ENDPOINTS
    # =====================================================================

    @rpc_method
    async def getPeers(self) -> Dict:
        """Return known peer list for peer exchange.

        Returns ALL peers that have a reachable URL, regardless of
        public/private status.  Peer exchange is how the network
        forms its mesh — filtering to public-only breaks gossip in
        any deployment where nodes use private IPs (testnet, LAN,
        Docker, etc.).
        """
        if self._nodes_manager is None:
            return {"ok": False, "error": "Not ready"}

        peers_list = []
        for nid, pdata in self._nodes_manager.peers.items():
            if pdata.get("url"):
                peers_list.append(
                    {
                        "node_id": nid,
                        "url": pdata["url"],
                        "is_public": pdata.get("is_public", False),
                    }
                )
        return {"ok": True, "result": {"peers": peers_list}}

    @rpc_method
    @peer_only
    async def handshakeChallenge(self, client_nonce: Optional[str] = None) -> Dict:
        """
        Issue a handshake challenge.  The caller must respond with
        ``p2p_handshakeResponse`` to complete the handshake.

        Mutual: the caller is a verified node (signed request), and the challenge can be
        answered only by it; this node in turn proves its identity by signing the caller's
        fresh ``client_nonce`` with the challenge and what it claims (``handshake_proof``) —
        so the caller adds this node as a peer on proof, not on its word.
        """
        self._require_db()

        from ...constants import DENARO_SELF_URL
        from ...node.identity import get_public_key_hex, sign_message

        if not client_nonce or len(client_nonce) < 32 or len(client_nonce) > 128:
            return {"ok": False, "error": "client_nonce (32–128 hex chars) is required"}
        caller = rpc_caller.get()
        challenge = await self._security.handshake_manager.create_challenge(issued_to=caller)
        height = await self._db.get_next_block_id() - 1

        result = {
            "challenge": challenge,
            "node_id": self._self_node_id,
            "pubkey": get_public_key_hex(),
            "is_public": self._nodes_manager.self_is_public if self._nodes_manager else False,
            "url": DENARO_SELF_URL or None,
            "height": height,
        }
        if self._network_identity is not None:
            # The caller checks this BEFORE it adds us as a peer (main.do_handshake_with_peer).
            result["network"] = await self._network_identity()
        result["proof"] = sign_message(handshake_proof_message(client_nonce, result))
        return {"ok": True, "result": result}

    @rpc_method
    @peer_only
    async def handshakeResponse(
        self,
        challenge: str,
        peer_height: int = -1,
        peer_hash: Optional[str] = None,
        network: Optional[Dict] = None,
        validator_proof: Optional[Dict] = None,
    ) -> Dict:
        """
        Verify a handshake response and negotiate sync direction.

        Args:
            challenge:   The challenge string from ``handshakeChallenge``.
            peer_height: The caller's chain height.
            peer_hash:   The caller's tip block hash (optional).
            network:     The caller's network identity (chain_spec.network_identity). A caller
                         on another network, or with an incompatible fork history, is refused
                         before any sync is negotiated.
            validator_proof: ``{address, signature}``, the caller's validator key over
                         ``validator_peer_message``: the caller runs that validator.

        A caller that completes the handshake is admitted as a peer, under the peer table's
        rules (NodesManager.admit_peer) — the only way an unknown node becomes one.
        """
        self._require_db()

        if not challenge:
            return {"ok": False, "error": "Missing challenge"}

        if not await self._security.handshake_manager.verify_and_consume_challenge(
            challenge, rpc_caller.get()
        ):
            return {"ok": False, "error": "Invalid or expired challenge"}

        if self._check_peer_identity is not None:
            ok, reason = await self._check_peer_identity(network)
            if not ok:
                return {"ok": False, "error": "network_mismatch", "detail": reason}
        if self._admit_peer is not None:
            try:
                await self._admit_peer(rpc_caller.get(), rpc_caller_meta.get(), validator_proof)
            except Exception as e:  # noqa: BLE001 — admission never fails the handshake
                logger.debug("peer admission after handshake failed: %s", e)

        local_height = await self._db.get_next_block_id() - 1

        if peer_height > local_height:
            return {
                "ok": True,
                "result": "sync_requested",
                "detail": {
                    "start_block": local_height + 1,
                    "target_block": peer_height + 1,
                },
            }

        if local_height > peer_height:
            return {
                "ok": False,
                "error": "sync_required",
                "result": {"next_block_expected": peer_height + 1},
            }

        return {"ok": True, "result": "Handshake successful."}
