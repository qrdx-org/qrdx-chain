"""
QRDX eth_* RPC Methods

Web3-compatible Ethereum JSON-RPC methods.
"""

from typing import Any, Dict, List, Optional, Union
from ..server import RPCModule, rpc_method, RPCError, RPCErrorCode


class EthModule(RPCModule):
    """
    Ethereum-compatible RPC methods (eth_* namespace).
    
    Implements standard Web3 methods for compatibility with
    existing Ethereum tooling (web3.py, ethers.js, etc.).
    """
    
    namespace = "eth"
    
    @rpc_method
    async def chainId(self) -> str:
        """
        Returns the chain ID.
        
        Returns:
            Hex string of chain ID
        """
        # TODO: Get from config
        chain_id = self.context.config.chain_id if self.context else 1
        return hex(chain_id)
    
    @rpc_method
    async def blockNumber(self) -> str:
        """
        Returns the current block number.
        
        Returns:
            Hex string of block number
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")
        
        block_number = await self.context.db.get_next_block_id() - 1
        return hex(max(0, block_number))
    
    @rpc_method
    async def getBlockByNumber(
        self,
        block_number: str,
        include_transactions: bool = False
    ) -> Optional[Dict]:
        """
        Returns block by number.
        
        Args:
            block_number: Block number (hex) or "latest", "earliest", "pending"
            include_transactions: Include full transactions if True
            
        Returns:
            Block object or None
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")
        
        # Parse block number
        if block_number == "latest":
            block_id = await self.context.db.get_next_block_id() - 1
        elif block_number == "earliest":
            block_id = 0
        elif block_number == "pending":
            # Return latest for pending
            block_id = await self.context.db.get_next_block_id() - 1
        else:
            block_id = int(block_number, 16)
        
        if block_id < 0:
            return None
        
        block = await self.context.db.get_block_by_id(block_id)
        if not block:
            return None
        
        return await self._format_block(block, include_transactions)
    
    @rpc_method
    async def getBlockByHash(
        self,
        block_hash: str,
        include_transactions: bool = False
    ) -> Optional[Dict]:
        """
        Returns block by hash.
        
        Args:
            block_hash: Block hash (0x prefixed)
            include_transactions: Include full transactions if True
            
        Returns:
            Block object or None
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")
        
        # Remove 0x prefix if present
        if block_hash.startswith("0x"):
            block_hash = block_hash[2:]
        
        block = await self.context.db.get_block_by_hash(block_hash)
        if not block:
            return None
        
        return await self._format_block(block, include_transactions)
    
    @rpc_method
    async def getTransactionByHash(self, tx_hash: str) -> Optional[Dict]:
        """
        Returns transaction by hash.
        
        Args:
            tx_hash: Transaction hash (0x prefixed)
            
        Returns:
            Transaction object or None
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")
        
        if tx_hash.startswith("0x"):
            tx_hash = tx_hash[2:]
        
        tx = await self.context.db.get_transaction(tx_hash)
        if not tx:
            return None
        
        return self._format_transaction(tx)
    
    @rpc_method
    async def getTransactionReceipt(self, tx_hash: str) -> Optional[Dict]:
        """
        Returns transaction receipt by hash.
        
        Args:
            tx_hash: Transaction hash (0x prefixed)
            
        Returns:
            Transaction receipt or None
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")
        
        if tx_hash.startswith("0x"):
            tx_hash = tx_hash[2:]
        
        tx = await self.context.db.get_transaction(tx_hash)
        if not tx:
            return None
        
        # Build receipt
        return {
            "transactionHash": "0x" + tx_hash,
            "transactionIndex": hex(0),  # TODO: Get actual index
            "blockHash": "0x" + tx.get("block_hash", "0" * 64),
            "blockNumber": hex(tx.get("block_id", 0)),
            "from": tx.get("from_address", "0x" + "0" * 40),
            "to": tx.get("to_address"),
            "cumulativeGasUsed": hex(0),
            "gasUsed": hex(0),
            "contractAddress": None,
            "logs": [],
            "logsBloom": "0x" + "00" * 256,
            "status": "0x1",  # Success
            "type": "0x0",
        }
    
    @rpc_method
    async def getBalance(
        self,
        address: str,
        block_number: str = "latest"
    ) -> str:
        """
        Returns the balance of an address.
        
        Args:
            address: Address to query
            block_number: Block number (hex) or tag
            
        Returns:
            Balance in wei (hex)
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")
        
        # Note: QRDX uses different address format
        # This needs migration mapping
        balance = await self.context.db.get_address_balance(address)
        
        # Convert from QRDX smallest unit to wei-like representation
        # QRDX uses 6 decimals (SMALLEST = 1000000)
        # Ethereum uses 18 decimals
        # We'll return in QRDX's native units for now
        balance_int = int(balance * 1000000) if balance else 0
        return hex(balance_int)
    
    @rpc_method
    async def getTransactionCount(
        self,
        address: str,
        block_number: str = "latest"
    ) -> str:
        """
        Returns the transaction count (nonce) of an address.
        
        Args:
            address: Address to query
            block_number: Block number or tag
            
        Returns:
            Transaction count (hex)
        """
        # QRDX doesn't have account nonces in the same way
        # Return 0 for now
        return "0x0"
    
    @rpc_method
    async def sendRawTransaction(self, raw_tx: str) -> str:
        """
        Submits a signed transaction.
        
        Args:
            raw_tx: Signed transaction hex
            
        Returns:
            Transaction hash
        """
        if not self.context:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Context not available")
        
        # TODO: Implement transaction parsing and submission
        raise RPCError(
            RPCErrorCode.METHOD_NOT_SUPPORTED,
            "sendRawTransaction not yet implemented"
        )
    
    @rpc_method
    async def call(
        self,
        transaction: Dict,
        block_number: str = "latest"
    ) -> str:
        """
        Executes a call without creating a transaction.
        
        QRDX doesn't have smart contracts, so this always returns empty.
        
        Returns:
            Empty hex string
        """
        return "0x"
    
    @rpc_method
    async def estimateGas(self, transaction: Dict) -> str:
        """
        Estimates gas for a transaction.
        
        QRDX doesn't use gas, returns 0.
        
        Returns:
            Gas estimate (hex)
        """
        return "0x0"
    
    @rpc_method
    async def gasPrice(self) -> str:
        """
        Returns current gas price.
        
        QRDX doesn't use gas, returns 0.
        
        Returns:
            Gas price (hex)
        """
        return "0x0"
    
    @rpc_method
    async def syncing(self) -> Union[bool, Dict]:
        """
        Returns sync status.
        
        Returns:
            False if not syncing, or sync status object
        """
        if not self.context:
            return False
        
        # TODO: Implement actual sync status
        return False
    
    @rpc_method
    async def mining(self) -> bool:
        """
        Returns whether the node is mining.
        
        Returns:
            True if mining
        """
        return False  # TODO: Check mining status
    
    @rpc_method
    async def hashrate(self) -> str:
        """
        Returns the node's hashrate.
        
        Returns:
            Hashrate (hex)
        """
        return "0x0"  # TODO: Get actual hashrate
    
    @rpc_method
    async def accounts(self) -> List[str]:
        """
        Returns list of accounts owned by the node.
        
        QRDX nodes don't manage accounts.
        
        Returns:
            Empty list
        """
        return []
    
    @rpc_method
    async def getCode(
        self,
        address: str,
        block_number: str = "latest"
    ) -> str:
        """
        Returns code at address.
        
        QRDX doesn't have smart contracts.
        
        Returns:
            Empty hex string
        """
        return "0x"
    
    @rpc_method
    async def getLogs(self, filter_params: Dict) -> List[Dict]:
        """
        Returns logs matching filter.
        
        QRDX doesn't have logs/events.
        
        Returns:
            Empty list
        """
        return []
    
    # Helper methods
    
    async def _format_block(self, block: Dict, include_txs: bool) -> Dict:
        """Format block for RPC response."""
        # Convert to Web3-compatible format
        return {
            "number": hex(block.get("id", 0)),
            "hash": "0x" + block.get("hash", "0" * 64),
            "parentHash": "0x" + block.get("previous_hash", "0" * 64),
            "nonce": "0x" + "0" * 16,  # QRDX doesn't have block nonce
            "sha3Uncles": "0x" + "0" * 64,
            "logsBloom": "0x" + "00" * 256,
            "transactionsRoot": "0x" + block.get("merkle_tree", "0" * 64),
            "stateRoot": "0x" + "0" * 64,
            "receiptsRoot": "0x" + "0" * 64,
            "miner": "0x" + "0" * 40,  # TODO: Convert address
            "difficulty": hex(int(float(block.get("difficulty", 0)) * 1000)),
            "totalDifficulty": hex(int(float(block.get("difficulty", 0)) * 1000)),
            "extraData": "0x",
            "size": hex(len(block.get("content", "")) // 2),
            "gasLimit": "0x0",
            "gasUsed": "0x0",
            "timestamp": hex(block.get("timestamp", 0)),
            "transactions": [],  # TODO: Include transactions if requested
            "uncles": [],
            "baseFeePerGas": "0x0",
        }
    
    def _format_transaction(self, tx: Dict) -> Dict:
        """Format transaction for RPC response."""
        return {
            "hash": "0x" + tx.get("tx_hash", "0" * 64),
            "blockHash": "0x" + tx.get("block_hash", "0" * 64),
            "blockNumber": hex(tx.get("block_id", 0)),
            "transactionIndex": hex(0),
            "from": tx.get("from_address", "0x" + "0" * 40),
            "to": tx.get("to_address"),
            "value": hex(int(float(tx.get("amount", 0)) * 1000000)),
            "gas": "0x0",
            "gasPrice": "0x0",
            "input": "0x",
            "nonce": "0x0",
            "v": "0x0",
            "r": "0x0",
            "s": "0x0",
            "type": "0x0",
        }
