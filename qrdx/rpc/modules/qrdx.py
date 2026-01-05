"""
QRDX qrdx_* RPC Methods

Chain-specific JSON-RPC methods.
"""

from typing import Any, Dict, List, Optional
from decimal import Decimal
from ..server import RPCModule, rpc_method, RPCError, RPCErrorCode


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
            Submission result
        """
        if not self.context:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Context not available")
        
        # TODO: Implement block submission
        raise RPCError(
            RPCErrorCode.METHOD_NOT_SUPPORTED,
            "submitBlock not yet implemented in new RPC"
        )
    
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
            "syncing": False,  # TODO: Check sync status
        }
    
    @rpc_method
    async def getPeers(self) -> List[Dict]:
        """
        Returns list of connected peers.
        
        Returns:
            List of peer info
        """
        # TODO: Get from P2P manager
        return []
    
    @rpc_method
    async def addPeer(self, uri: str) -> bool:
        """
        Manually add a peer.
        
        Args:
            uri: Peer URI (qnode:// format)
            
        Returns:
            True if added successfully
        """
        # TODO: Implement peer addition
        raise RPCError(
            RPCErrorCode.METHOD_NOT_SUPPORTED,
            "addPeer not yet implemented"
        )
    
    @rpc_method
    async def removePeer(self, node_id: str) -> bool:
        """
        Remove a peer.
        
        Args:
            node_id: Node ID to remove
            
        Returns:
            True if removed successfully
        """
        # TODO: Implement peer removal
        raise RPCError(
            RPCErrorCode.METHOD_NOT_SUPPORTED,
            "removePeer not yet implemented"
        )
    
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
