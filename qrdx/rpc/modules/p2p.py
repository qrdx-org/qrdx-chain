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

from typing import Any, Dict, List, Optional
import asyncio

from ..server import RPCModule, rpc_method, RPCError, RPCErrorCode
from ...logger import get_logger

logger = get_logger(__name__)


class P2PModule(RPCModule):
    """
    Inter-node P2P RPC methods (p2p_* namespace).

    Wired at startup via ``set_node_context()`` with references to the
    live database, security components, and propagation function.
    """

    namespace = "p2p"

    def __init__(self, context: Any = None):
        super().__init__(context)
        self._db = None
        self._security = None
        self._propagate_fn = None
        self._process_and_create_block = None
        self._create_block = None
        self._block_processing_lock = None
        self._nodes_manager = None
        self._self_node_id = None
        self._handshake_manager = None        # same object as security.handshake_manager
        self._sync_blockchain = None
        self._follow_up_sync = None

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

    def _require_db(self):
        if self._db is None:
            raise RPCError(RPCErrorCode.RESOURCE_UNAVAILABLE, "Node not ready")

    # =====================================================================
    # BLOCK ENDPOINTS
    # =====================================================================

    @rpc_method
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

        block_content = block_data.get('block_content')
        if not block_content:
            return {'ok': False, 'error': 'Missing block_content'}

        block_no = block_data.get('id') or block_data.get('block_no')
        if block_no is None:
            return {'ok': False, 'error': 'Missing block ID'}

        # ---- Idempotency: skip blocks we already have ----
        from hashlib import sha256
        block_identifier = sha256(block_content.encode()).hexdigest()
        if await self._security.block_cache.contains(block_identifier):
            return {'ok': False, 'error': 'Block recently seen'}

        # ---- Sync guard ----
        if self._security.sync_state_manager.is_syncing:
            return {'ok': False, 'error': 'Node is synchronizing'}

        async with self._block_processing_lock:
            next_block_id = await self._db.get_next_block_id()

            if next_block_id > block_no:
                return {'ok': False, 'error': 'Too old block'}

            if next_block_id < block_no:
                # Peer is ahead—request sync
                return {
                    'ok': False,
                    'error': 'sync_required',
                    'result': {'next_block_expected': next_block_id},
                }

            await self._security.block_cache.put(block_identifier, True)

            # --- PoS fast-path ---
            block_hash = block_data.get('block_hash')
            validator_address = block_data.get('validator_address')
            if block_hash and validator_address:
                if not self._security.input_validator.validate_hex(
                    block_hash, min_length=16, max_length=128
                ):
                    return {'ok': False, 'error': 'Invalid block hash format'}

                if block_no != next_block_id:
                    return {'ok': False, 'error': 'Block height mismatch'}

                validator_info = await self._db.get_validator_info(validator_address)
                if not validator_info:
                    return {'ok': False, 'error': 'Validator not registered'}

                try:
                    await self._db.add_block(
                        block_hash=block_hash,
                        block_height=block_no,
                        block_content=block_content or '',
                        validator_address=validator_address,
                        timestamp=block_data.get('timestamp', 0),
                    )
                    logger.info(f"Accepted PoS block {block_no} via RPC. Propagating...")
                    asyncio.create_task(
                        self._propagate_fn(
                            'submit_block', block_data, ignore_node_id=None, db=self._db
                        )
                    )
                    # Immediate follow-up sync check
                    if self._follow_up_sync and block_data.get('_sender_node_id'):
                        asyncio.create_task(
                            self._follow_up_sync(block_data['_sender_node_id'])
                        )
                    return {'ok': True, 'result': f'Block {block_no} accepted.'}
                except Exception as e:
                    logger.error(f"Failed to store PoS block {block_no}: {e}")
                    return {'ok': False, 'error': 'Storage failure'}

            # --- Legacy PoW path ---
            from ...transactions import Transaction
            txs_data = block_data.get('txs', [])
            final_transactions = []

            if isinstance(txs_data, str):
                txs_data = txs_data.split(',') if txs_data else []

            tx_hashes_to_find = []
            for tx_hex in txs_data:
                if isinstance(tx_hex, str) and len(tx_hex) == 64:
                    tx_hashes_to_find.append(tx_hex)
                else:
                    final_transactions.append(await Transaction.from_hex(tx_hex))

            if tx_hashes_to_find:
                db_results = await self._db.get_pending_transactions_by_hash(tx_hashes_to_find)
                if len(db_results) < len(tx_hashes_to_find):
                    return {'ok': False, 'error': 'Transaction hash not found'}
                tx_map = {tx.hash(): tx for tx in db_results}
                final_transactions.extend(
                    [tx_map.get(h) for h in tx_hashes_to_find]
                )

            if not await self._create_block(block_content, final_transactions):
                return {'ok': False, 'error': 'Block failed validation'}

            logger.info(f"Accepted PoW block {block_no} via RPC. Propagating...")
            asyncio.create_task(
                self._propagate_fn(
                    'submit_block', block_data, ignore_node_id=None, db=self._db
                )
            )
            return {'ok': True, 'result': f'Block {block_no} accepted.'}

    @rpc_method
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
            return {'ok': False, 'error': 'Empty batch'}

        # Sync guard
        if self._security.sync_state_manager.is_syncing:
            return {'ok': False, 'error': 'Node is synchronizing'}

        async with self._block_processing_lock:
            next_expected = await self._db.get_next_block_id()
            first_in_batch = blocks[0].get('id')

            if first_in_batch is None:
                return {'ok': False, 'error': 'Missing block ID in batch'}

            if first_in_batch != next_expected:
                return {
                    'ok': False,
                    'error': f'Block sequence out of order. Expected {next_expected}, got {first_in_batch}.',
                }

            accepted = 0
            for block_data in blocks:
                block_id = block_data.get('id')
                current_expected = await self._db.get_next_block_id()

                if block_id != current_expected:
                    return {
                        'ok': False,
                        'error': (
                            f'Block sequence desynchronized at block {block_id}. '
                            f'Expected {current_expected}.'
                        ),
                    }

                block_info = {
                    'block': {
                        'id': block_id,
                        'content': block_data.get('block_content', ''),
                        'hash': block_data.get('block_hash', ''),
                        'address': block_data.get('validator_address', ''),
                        'timestamp': block_data.get('timestamp', 0),
                    },
                    'transactions': block_data.get('txs', []),
                }

                if not await self._process_and_create_block(block_info):
                    return {
                        'ok': False,
                        'error': f'Failed to process block {block_id}',
                    }
                accepted += 1

        return {'ok': True, 'result': f'{accepted} blocks accepted.'}

    # =====================================================================
    # CHAIN QUERY ENDPOINTS
    # =====================================================================

    @rpc_method
    async def getStatus(self) -> Dict:
        """Return current chain height and tip hash."""
        self._require_db()

        height = await self._db.get_next_block_id() - 1
        response = {
            'height': height,
            'last_block_hash': None,
            'node_id': self._self_node_id,
        }

        if height >= 0:
            last_block = await self._db.get_block_by_id(height)
            if last_block:
                response['last_block_hash'] = last_block['hash']
            else:
                response['height'] = -1

        return response

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
                block_hash = block_info['hash']
        else:
            block_hash = block
            block_info = await self._db.get_block(block_hash)

        if block_info:
            txs = await self._db.get_block_transactions(block_hash, hex_only=True) if block_hash else []
            return {
                'ok': True,
                'result': {'block': block_info, 'transactions': txs or []},
            }
        return {'ok': False, 'error': 'Not found'}

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
        self._require_db()

        limit = min(limit, 512)
        blocks = await self._db.get_blocks(offset, limit)

        structured = []
        for block in blocks:
            block_hash = block.get('hash') or block.get('block_hash')
            txs = (
                await self._db.get_block_transactions(block_hash, hex_only=True)
                if block_hash
                else []
            )
            structured.append({'block': block, 'transactions': txs or []})

        return {'ok': True, 'result': structured}

    # =====================================================================
    # TRANSACTION ENDPOINTS
    # =====================================================================

    @rpc_method
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
            return {'ok': False, 'error': 'Invalid transaction'}

        try:
            await self._db.add_pending_transaction(tx)
        except Exception:
            return {'ok': False, 'error': 'Transaction rejected'}

        # Propagate to other peers (fire-and-forget)
        asyncio.create_task(
            self._propagate_fn('push_tx', {'tx_hex': tx_hex}, db=self._db)
        )
        return {'ok': True, 'result': 'Transaction accepted'}

    @rpc_method
    async def getMempoolHashes(self) -> Dict:
        """Return hashes of all pending transactions."""
        self._require_db()

        pending = await self._db.get_pending_transactions()
        hashes = [tx.hash() for tx in (pending or [])]
        return {'ok': True, 'result': {'hashes': hashes}}

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
            'ok': True,
            'result': {'transactions': [tx.hex() for tx in results]},
        }

    # =====================================================================
    # PEER / HANDSHAKE ENDPOINTS
    # =====================================================================

    @rpc_method
    async def getPeers(self) -> Dict:
        """Return known peer list."""
        if self._nodes_manager is None:
            return {'ok': False, 'error': 'Not ready'}

        peers_list = []
        for nid, pdata in self._nodes_manager.peers.items():
            if pdata.get('is_public') and pdata.get('url'):
                peers_list.append({
                    'node_id': nid,
                    'url': pdata['url'],
                })
        return {'ok': True, 'result': {'peers': peers_list}}

    @rpc_method
    async def handshakeChallenge(self) -> Dict:
        """
        Issue a handshake challenge.  The caller must respond with
        ``p2p_handshakeResponse`` to complete the handshake.
        """
        self._require_db()

        from ...node.identity import get_public_key_hex

        challenge = await self._security.handshake_manager.create_challenge()
        height = await self._db.get_next_block_id() - 1

        return {
            'ok': True,
            'result': {
                'challenge': challenge,
                'node_id': self._self_node_id,
                'pubkey': get_public_key_hex(),
                'is_public': self._nodes_manager.self_is_public if self._nodes_manager else False,
                'url': None,  # filled by caller from env
                'height': height,
            },
        }

    @rpc_method
    async def handshakeResponse(self, challenge: str, peer_height: int = -1, peer_hash: Optional[str] = None) -> Dict:
        """
        Verify a handshake response and negotiate sync direction.

        Args:
            challenge:   The challenge string from ``handshakeChallenge``.
            peer_height: The caller's chain height.
            peer_hash:   The caller's tip block hash (optional).
        """
        self._require_db()

        if not challenge:
            return {'ok': False, 'error': 'Missing challenge'}

        if not await self._security.handshake_manager.verify_and_consume_challenge(challenge):
            return {'ok': False, 'error': 'Invalid or expired challenge'}

        local_height = await self._db.get_next_block_id() - 1

        if peer_height > local_height:
            return {
                'ok': True,
                'result': 'sync_requested',
                'detail': {
                    'start_block': local_height + 1,
                    'target_block': peer_height + 1,
                },
            }

        if local_height > peer_height:
            return {
                'ok': False,
                'error': 'sync_required',
                'result': {'next_block_expected': peer_height + 1},
            }

        return {'ok': True, 'result': 'Handshake successful.'}
