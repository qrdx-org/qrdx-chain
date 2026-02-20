"""
QRDX qrdx_* RPC Methods

Chain-specific JSON-RPC methods.
"""

from typing import Any, Dict, List, Optional
from decimal import Decimal
from ..server import RPCModule, rpc_method, rpc_admin_method, RPCError, RPCErrorCode


class QRDXModule(RPCModule):
    """
    QRDX-specific RPC methods (qrdx_* namespace).
    
    These methods provide chain-specific functionality not covered
    by the standard eth_* namespace.
    """
    
    namespace = "qrdx"
    
    @rpc_method
    async def getMiningInfo(self) -> Dict:
        """
        Returns mining information for creating a new block.
        
        This is the main endpoint for miners.
        
        Returns:
            Mining info including difficulty, block template, etc.
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")
        
        # Get current block info
        last_block = await self.context.db.get_last_block()
        next_block_id = (last_block["id"] + 1) if last_block else 0
        
        # Get pending transactions
        pending_txs = await self.context.db.get_pending_transactions()
        
        # Calculate difficulty
        from ...manager import calculate_difficulty
        difficulty, _ = await calculate_difficulty()
        
        return {
            "height": next_block_id,
            "previousHash": last_block["hash"] if last_block else "0" * 64,
            "difficulty": str(difficulty),
            "timestamp": int(self.context.helpers.timestamp()) if self.context else 0,
            "pendingTransactions": len(pending_txs) if pending_txs else 0,
            "reward": str(self._calculate_reward(next_block_id)),
        }
    
    @rpc_method
    async def submitBlock(
        self,
        block_hash: str,
        block_content: str,
        address: str
    ) -> Dict:
        """
        Submit a mined block.
        
        Args:
            block_hash: The block's hash
            block_content: Block content in hex
            address: Miner's address for reward
            
        Returns:
            Submission result with 'success' and optional 'error'
        """
        if not self.context:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Context not available")
        if not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")

        try:
            import hashlib

            # 1. Decode block content
            try:
                block_bytes = bytes.fromhex(block_content)
            except ValueError:
                return {"success": False, "error": "Invalid hex block content"}

            # 2. Verify block hash matches content
            computed_hash = hashlib.sha256(block_bytes).hexdigest()
            if computed_hash != block_hash:
                return {"success": False, "error": "Block hash does not match content"}

            # 3. Validate via the node's block-processing pipeline
            # The pipeline checks PoW/PoS, parent hash, difficulty, timestamps, etc.
            if hasattr(self.context, 'node') and hasattr(self.context.node, 'process_block'):
                accepted = await self.context.node.process_block(
                    block_hash=block_hash,
                    block_content=block_bytes,
                    miner_address=address,
                )
                if not accepted:
                    return {"success": False, "error": "Block rejected by consensus rules"}
            elif hasattr(self.context, 'add_block'):
                accepted = await self.context.add_block(
                    block_hash=block_hash,
                    block_content=block_bytes,
                    miner_address=address,
                )
                if not accepted:
                    return {"success": False, "error": "Block rejected by chain"}
            else:
                # Legacy path: store directly via DB (used in simple miner setups)
                from ...manager import check_block_is_valid
                try:
                    await check_block_is_valid(block_bytes)
                except Exception as validation_error:
                    return {"success": False, "error": f"Validation failed: {validation_error}"}

            return {
                "success": True,
                "hash": block_hash,
            }
        except RPCError:
            raise
        except Exception as e:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, str(e))
    
    @rpc_method
    async def getAddressInfo(self, address: str) -> Dict:
        """
        Returns detailed information about an address.
        
        Args:
            address: The address to query
            
        Returns:
            Address info including balance, transaction count, etc.
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")
        
        balance = await self.context.db.get_address_balance(address)
        pending_balance = await self.context.db.get_address_balance(address, True)
        
        return {
            "address": address,
            "balance": str(balance or Decimal(0)),
            "pendingBalance": str(pending_balance or Decimal(0)),
            "pendingDelta": str((pending_balance or Decimal(0)) - (balance or Decimal(0))),
        }
    
    @rpc_method
    async def getPendingTransactions(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> Dict:
        """
        Returns pending transactions from the mempool.
        
        Args:
            limit: Maximum transactions to return
            offset: Offset for pagination
            
        Returns:
            List of pending transactions
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")
        
        pending = await self.context.db.get_pending_transactions(limit, offset)
        
        return {
            "transactions": [self._format_pending_tx(tx) for tx in (pending or [])],
            "count": len(pending) if pending else 0,
        }
    
    @rpc_method
    async def getNetworkInfo(self) -> Dict:
        """
        Returns network statistics.
        
        Returns:
            Network info
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")
        
        last_block = await self.context.db.get_last_block()
        
        return {
            "version": self._get_version(),
            "chainId": self.context.config.chain_id if self.context else 1,
            "blockHeight": last_block["id"] if last_block else 0,
            "difficulty": str(last_block["difficulty"]) if last_block else "6.0",
            "peerCount": await self._get_peer_count(),
            "syncing": False,  # Could check sync status from context if available
        }
    
    @rpc_method
    async def getPeers(self) -> List[Dict]:
        """
        Returns list of connected peers.
        
        Returns:
            List of peer info
        """
        if not self.context:
            return []
        
        # Get peers from P2P manager if available
        if hasattr(self.context, 'p2p') and self.context.p2p:
            try:
                if hasattr(self.context.p2p, 'peers'):
                    return [
                        {
                            "address": str(peer),
                            "connected": True
                        }
                        for peer in self.context.p2p.peers
                    ]
            except Exception:
                pass
        
        return []
    
    @rpc_admin_method
    async def addPeer(self, uri: str) -> bool:
        """
        Manually add a peer.  Requires admin_token authentication.
        
        Args:
            uri: Peer URI (qnode:// format)
            
        Returns:
            True if added successfully
        """
        if not self.context:
            return False
        
        # Add peer to P2P manager if available
        if hasattr(self.context, 'p2p') and self.context.p2p:
            try:
                if hasattr(self.context.p2p, 'add_peer'):
                    await self.context.p2p.add_peer(uri)
                    return True
            except Exception:
                pass
        
        return False
    
    @rpc_admin_method
    async def removePeer(self, node_id: str) -> bool:
        """
        Remove a peer.  Requires admin_token authentication.
        
        Args:
            node_id: Node ID to remove
            
        Returns:
            True if removed successfully
        """
        if not self.context:
            return False
        
        # Remove peer from P2P manager if available
        if hasattr(self.context, 'p2p') and self.context.p2p:
            try:
                if hasattr(self.context.p2p, 'remove_peer'):
                    await self.context.p2p.remove_peer(node_id)
                    return True
            except Exception:
                pass
        
        return False
    
    @rpc_method
    async def getDifficulty(self) -> Dict:
        """
        Returns current mining difficulty.
        
        Returns:
            Difficulty info
        """
        from ...manager import calculate_difficulty
        difficulty, last_block = await calculate_difficulty()
        
        return {
            "difficulty": str(difficulty),
            "blockHeight": last_block.get("id", 0) if last_block else 0,
        }
    
    @rpc_method
    async def getBlockReward(self, block_height: Optional[int] = None) -> Dict:
        """
        Returns block reward for a given height.
        
        Args:
            block_height: Block height (uses latest if None)
            
        Returns:
            Reward info
        """
        if block_height is None:
            if self.context and self.context.db:
                last_block = await self.context.db.get_last_block()
                block_height = last_block["id"] + 1 if last_block else 0
            else:
                block_height = 0
        
        reward = self._calculate_reward(block_height)
        
        return {
            "blockHeight": block_height,
            "reward": str(reward),
        }
    
    # Helper methods
    
    def _calculate_reward(self, block_height: int) -> Decimal:
        """Calculate block reward for height."""
        from ...constants import INITIAL_REWARD, HALVING_INTERVAL
        
        halvings = block_height // HALVING_INTERVAL
        reward = INITIAL_REWARD / (2 ** halvings)
        return reward
    
    def _get_version(self) -> str:
        """Get node version."""
        from ...constants import NODE_VERSION
        return NODE_VERSION
    
    async def _get_peer_count(self) -> int:
        """Get peer count."""
        if self.context and hasattr(self.context, 'p2p'):
            return len(self.context.p2p.peers)
        return 0
    
    def _format_pending_tx(self, tx: Dict) -> Dict:
        """Format pending transaction."""
        return {
            "hash": tx.get("tx_hash"),
            "hex": tx.get("tx_hex"),
            "fees": str(tx.get("fees", Decimal(0))),
            "timestamp": tx.get("time_received"),
        }
