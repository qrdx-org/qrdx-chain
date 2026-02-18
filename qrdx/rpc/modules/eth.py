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
        # QRDX uses chain ID 88888 for mainnet (configurable via context)
        chain_id = self.context.config.chain_id if (self.context and hasattr(self.context, 'config') and hasattr(self.context.config, 'chain_id')) else 88888
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
        # Get transaction index from block if available
        tx_index = 0
        if "transaction_index" in tx:
            tx_index = tx["transaction_index"]
        elif "tx_index" in tx:
            tx_index = tx["tx_index"]
        
        return {
            "transactionHash": "0x" + tx_hash,
            "transactionIndex": hex(tx_index),
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
        if not self.context:
            return "0x0"
        
        # Try to get nonce from contract state manager if available
        if hasattr(self.context, 'state_manager') and self.context.state_manager:
            try:
                nonce = await self.context.state_manager.get_nonce(address)
                return hex(nonce)
            except:
                pass
        
        # For non-contract addresses in QRDX, check transaction count
        if hasattr(self.context, 'db') and self.context.db:
            try:
                # Count transactions from this address
                tx_count = await self.context.db.get_transaction_count_by_address(address)
                return hex(tx_count if tx_count else 0)
            except:
                pass
        
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
        
        # The actual implementation is registered separately in node/main.py
        # as eth_sendRawTransaction_handler to handle contract transactions
        # This method serves as the RPC interface definition
        raise RPCError(
            RPCErrorCode.INTERNAL_ERROR,
            "sendRawTransaction should be handled by registered handler"
        )
    
    @rpc_method
    async def call(
        self,
        transaction: Dict,
        block_number: str = "latest"
    ) -> str:
        """
        Executes a call without creating a transaction.
        
        Args:
            transaction: Transaction object
            block_number: Block number or tag
        
        Returns:
            Call result (hex)
        """
        # Delegate to contract handler if available
        if hasattr(self.context, 'evm_executor') and self.context.evm_executor:
            # Handler registered in node/main.py handles actual execution
            raise RPCError(
                RPCErrorCode.INTERNAL_ERROR,
                "eth_call should be handled by registered handler"
            )
        return "0x"
    
    @rpc_method
    async def estimateGas(self, transaction: Dict) -> str:
        """
        Estimates gas for a transaction.
        
        Args:
            transaction: Transaction object
        
        Returns:
            Gas estimate (hex)
        """
        # For contract transactions, return realistic gas estimate
        if hasattr(self.context, 'evm_executor') and self.context.evm_executor:
            # Default gas limit for contract operations
            return hex(10000000)  # 10M gas
        # For simple QRDX transactions, minimal gas
        return hex(21000)  # Standard ETH transfer gas
    
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
        if not self.context or not self.context.db:
            return False
        
        # Check if node is syncing
        try:
            current_block = await self.context.db.get_next_block_id() - 1
            # In QRDX, we consider syncing if we're significantly behind
            # This would need to check against known network height
            # For now, return False as we don't have a way to determine network height
            # A production implementation would compare against known peers
            return False
        except:
            return False
    
    @rpc_method
    async def mining(self) -> bool:
        """
        Returns whether the node is mining.
        
        Returns:
            True if mining
        """
        # Check if there's a miner configured and running
        if self.context and hasattr(self.context, 'miner'):
            return bool(self.context.miner)
        return False
    
    @rpc_method
    async def hashrate(self) -> str:
        """
        Returns the node's hashrate.
        
        Returns:
            Hashrate (hex)
        """
        # Get hashrate from miner if available
        if self.context and hasattr(self.context, 'miner') and self.context.miner:
            if hasattr(self.context.miner, 'hashrate'):
                return hex(int(self.context.miner.hashrate))
        return "0x0"
    
    @rpc_method
    async def accounts(self) -> List[str]:
        """
        Returns list of accounts owned by the node.
        
        Returns:
            List of account addresses
        """
        accounts = []
        
        # Check for validator wallet
        if self.context and hasattr(self.context, 'validator_manager'):
            if hasattr(self.context.validator_manager, 'wallet'):
                wallet = self.context.validator_manager.wallet
                if hasattr(wallet, 'address'):
                    accounts.append(wallet.address)
        
        # Check for node wallet
        if self.context and hasattr(self.context, 'wallet'):
            if hasattr(self.context.wallet, 'address'):
                addr = self.context.wallet.address
                if addr not in accounts:
                    accounts.append(addr)
        
        return accounts
    
    @rpc_method
    async def getCode(
        self,
        address: str,
        block_number: str = "latest"
    ) -> str:
        """
        Returns code at address.
        
        Args:
            address: Contract address
            block_number: Block number or tag
        
        Returns:
            Contract bytecode (hex)
        """
        # Try to get code from contract state manager
        if self.context and hasattr(self.context, 'state_manager') and self.context.state_manager:
            try:
                code = await self.context.state_manager.get_code(address)
                if code:
                    return "0x" + code.hex()
            except:
                pass
        return "0x"
    
    @rpc_method
    async def getLogs(self, filter_params: Dict) -> List[Dict]:
        """
        Returns logs matching filter.
        
        Args:
            filter_params: Filter parameters (fromBlock, toBlock, address, topics)
        
        Returns:
            List of log objects
        """
        # Try to get logs from database if contract system is enabled
        if not self.context or not self.context.db:
            return []
        
        try:
            # Check if contract_logs table exists
            logs = []
            # This would query the contract_logs table
            # For now return empty as the full implementation is in contracts.py module
            return logs
        except:
            return []
    
    @rpc_method
    async def getStorageAt(
        self,
        address: str,
        position: str,
        block_number: str = "latest"
    ) -> str:
        """
        Returns storage value at position.
        
        Args:
            address: Contract address
            position: Storage position (hex)
            block_number: Block number or tag
        
        Returns:
            Storage value (hex, 32 bytes)
        """
        if self.context and hasattr(self.context, 'state_manager') and self.context.state_manager:
            try:
                # Convert position to bytes
                pos_int = int(position, 16) if position.startswith('0x') else int(position, 16)
                key = pos_int.to_bytes(32, 'big')
                
                # Get storage value
                value = await self.context.state_manager.get_storage(address, key)
                return '0x' + value.hex() if value else '0x' + ('0' * 64)
            except:
                pass
        return '0x' + ('0' * 64)
    
    @rpc_method
    async def getBlockTransactionCountByHash(self, block_hash: str) -> str:
        """
        Returns number of transactions in a block by hash.
        
        Args:
            block_hash: Block hash (0x prefixed)
        
        Returns:
            Transaction count (hex)
        """
        if not self.context or not self.context.db:
            return "0x0"
        
        if block_hash.startswith("0x"):
            block_hash = block_hash[2:]
        
        block = await self.context.db.get_block_by_hash(block_hash)
        if not block:
            return None
        
        # Get transaction count from block
        tx_count = block.get("transaction_count", 0)
        return hex(tx_count)
    
    @rpc_method
    async def getBlockTransactionCountByNumber(self, block_number: str) -> str:
        """
        Returns number of transactions in a block by number.
        
        Args:
            block_number: Block number (hex) or tag
        
        Returns:
            Transaction count (hex)
        """
        if not self.context or not self.context.db:
            return "0x0"
        
        # Parse block number
        if block_number == "latest":
            block_id = await self.context.db.get_next_block_id() - 1
        elif block_number == "earliest":
            block_id = 0
        elif block_number == "pending":
            block_id = await self.context.db.get_next_block_id() - 1
        else:
            block_id = int(block_number, 16)
        
        if block_id < 0:
            return None
        
        block = await self.context.db.get_block_by_id(block_id)
        if not block:
            return None
        
        tx_count = block.get("transaction_count", 0)
        return hex(tx_count)
    
    @rpc_method
    async def getUncleCountByBlockHash(self, block_hash: str) -> str:
        """
        Returns number of uncles in a block by hash.
        
        QRDX doesn't have uncles (Proof of Stake).
        
        Args:
            block_hash: Block hash
        
        Returns:
            "0x0" (no uncles)
        """
        return "0x0"
    
    @rpc_method
    async def getUncleCountByBlockNumber(self, block_number: str) -> str:
        """
        Returns number of uncles in a block by number.
        
        QRDX doesn't have uncles (Proof of Stake).
        
        Args:
            block_number: Block number or tag
        
        Returns:
            "0x0" (no uncles)
        """
        return "0x0"
    
    @rpc_method
    async def getTransactionByBlockHashAndIndex(
        self,
        block_hash: str,
        index: str
    ) -> Optional[Dict]:
        """
        Returns transaction by block hash and index.
        
        Args:
            block_hash: Block hash (0x prefixed)
            index: Transaction index (hex)
        
        Returns:
            Transaction object or None
        """
        if not self.context or not self.context.db:
            return None
        
        if block_hash.startswith("0x"):
            block_hash = block_hash[2:]
        
        tx_index = int(index, 16)
        
        # Get transactions in block
        block = await self.context.db.get_block_by_hash(block_hash)
        if not block:
            return None
        
        # This would need database support for getting tx by index
        # For now, return None
        return None
    
    @rpc_method
    async def getTransactionByBlockNumberAndIndex(
        self,
        block_number: str,
        index: str
    ) -> Optional[Dict]:
        """
        Returns transaction by block number and index.
        
        Args:
            block_number: Block number (hex) or tag
            index: Transaction index (hex)
        
        Returns:
            Transaction object or None
        """
        if not self.context or not self.context.db:
            return None
        
        # Parse block number
        if block_number == "latest":
            block_id = await self.context.db.get_next_block_id() - 1
        elif block_number == "earliest":
            block_id = 0
        elif block_number == "pending":
            block_id = await self.context.db.get_next_block_id() - 1
        else:
            block_id = int(block_number, 16)
        
        if block_id < 0:
            return None
        
        tx_index = int(index, 16)
        
        # This would need database support for getting tx by block and index
        # For now, return None
        return None
    
    @rpc_method
    async def protocolVersion(self) -> str:
        """
        Returns the current ethereum protocol version.
        
        Returns:
            Protocol version (hex)
        """
        # Return a version number compatible with Ethereum
        return hex(65)  # ETH protocol version 65 (common post-merge)
    
    # Helper methods
    
    async def _format_block(self, block: Dict, include_txs: bool) -> Dict:
        """Format block for RPC response."""
        # Get transactions if requested
        transactions = []
        if include_txs and self.context and self.context.db:
            try:
                # Get full transaction objects
                block_txs = await self.context.db.get_transactions_by_block_id(block.get("id", 0))
                transactions = [self._format_transaction(tx) for tx in block_txs]
            except:
                # If can't get full transactions, just return hashes
                transactions = []
        
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
            "miner": block.get("miner", "0x" + "0" * 40) if isinstance(block.get("miner"), str) else "0x" + "0" * 40,
            "difficulty": hex(int(float(block.get("difficulty", 0)) * 1000)),
            "totalDifficulty": hex(int(float(block.get("difficulty", 0)) * 1000)),
            "extraData": "0x",
            "size": hex(len(block.get("content", "")) // 2),
            "gasLimit": "0x0",
            "gasUsed": "0x0",
            "timestamp": hex(block.get("timestamp", 0)),
            "transactions": transactions,
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
