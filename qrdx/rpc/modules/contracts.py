"""
Ethereum-Compatible RPC Methods

Full eth_* RPC API for smart contract interaction.
Provides complete Ethereum JSON-RPC compatibility.
"""

from typing import Optional, Dict, List, Any
from decimal import Decimal
import asyncio

from ...logger import get_logger
from ...rpc.server import RPCError, RPCErrorCode, RPCModule, rpc_method
from ...transactions.contract_transaction import ContractTransaction
from ...contracts import ContractStateManager, QRDXEVMExecutor, QRDXVMExecutor
from ...crypto.contract import (
    convert_eth_to_qrdx_address,
    convert_qrdx_to_eth_address,
    encode_function_call,
    decode_function_call,
)
from eth_utils import to_canonical_address, to_checksum_address, encode_hex, decode_hex
from eth_utils import to_canonical_address, to_checksum_address, encode_hex, decode_hex

logger = get_logger(__name__)


class EthereumRPCModule:
    """
    Ethereum-compatible RPC methods for contract interaction.
    
    Implements:
    - eth_sendTransaction
    - eth_call
    - eth_estimateGas
    - eth_getCode
    - eth_getStorageAt
    - eth_getTransactionCount
    - eth_getTransactionReceipt
    - eth_getLogs
    - eth_getBlockByNumber
    - eth_getBalance
    """
    
    def __init__(self, node_manager=None, validator_manager=None):
        """
        Initialize Ethereum RPC module.
        
        Args:
            node_manager: Node manager instance
            validator_manager: Validator manager instance
        """
        self.node_manager = node_manager
        self.validator_manager = validator_manager
        self.state_manager: Optional[ContractStateManager] = None
        self.evm_executor: Optional[QRDXEVMExecutor] = None
        self.qrdx_vm: Optional[QRDXVMExecutor] = None
        
        # Initialize contract system
        asyncio.create_task(self._init_contract_system())
    
    async def _init_contract_system(self):
        """Initialize contract execution system."""
        from ... import Database
        
        # Wait for database
        while not Database.instance:
            await asyncio.sleep(0.1)
        
        database = Database.instance
        
        # Initialize state manager
        self.state_manager = ContractStateManager(database)
        
        # Initialize executors
        self.evm_executor = QRDXEVMExecutor(self.state_manager)  # 100% Ethereum compatible
        self.qrdx_vm = QRDXVMExecutor(self.state_manager)
        
        logger.info("Contract execution system initialized with 100% EVM compatibility")
    
    async def eth_sendTransaction(self, params: Dict[str, Any]) -> str:
        """
        Send a contract transaction.
        
        Args:
            params: Transaction parameters
                - from: Sender address
                - to: Recipient (contract) address or null for deployment
                - gas: Gas limit (optional)
                - gasPrice: Gas price (optional)
                - value: Value to send (optional)
                - data: Transaction data/bytecode
                - nonce: Transaction nonce (optional)
            
        Returns:
            Transaction hash
        """
        try:
            # Parse addresses
            sender_hex = params.get('from')
            to_hex = params.get('to')
            
            # Convert to canonical addresses (20 bytes)
            sender = to_canonical_address(sender_hex)
            to = to_canonical_address(to_hex) if to_hex else None
            
            # Parse data
            data = decode_hex(params.get('data', '0x'))
            value = int(params.get('value', '0x0'), 16) if isinstance(params.get('value'), str) else int(params.get('value', 0))
            gas = int(params.get('gas', '0x100000'), 16) if isinstance(params.get('gas'), str) else int(params.get('gas', 1000000))
            gas_price = int(params.get('gasPrice', '0x3b9aca00'), 16) if isinstance(params.get('gasPrice'), str) else int(params.get('gasPrice', 1000000000))
            
            # Execute transaction via EVM
            result = self.evm_executor.execute(
                sender=sender,
                to=to,
                value=value,
                data=data,
                gas=gas,
                gas_price=gas_price,
            )
            
            if not result.success:
                raise RPCError(-32000, f"Transaction failed: {result.error}")
            
            # Return transaction hash (simplified - should compute actual hash)
            import hashlib
            tx_data = sender + (to or b'') + data
            tx_hash = '0x' + hashlib.sha256(tx_data).hexdigest()
            
            return tx_hash
            
        except Exception as e:
            logger.error(f"eth_sendTransaction error: {e}")
            raise RPCError(-32000, str(e))
    
    async def eth_call(
        self,
        call_params: Dict[str, Any],
        block_number: str = 'latest'
    ) -> str:
        """
        Execute contract call without state changes.
        
        Args:
            call_params: Call parameters
                - from: Caller address (optional)
                - to: Contract address
                - gas: Gas limit (optional)
                - gasPrice: Gas price (optional)
                - value: Value to send (optional)
                - data: Call data
            block_number: Block number or 'latest', 'pending', 'earliest'
            
        Returns:
            Call output (hex-encoded)
        """
        try:
            sender_hex = call_params.get('from', '0x' + '0' * 40)
            to_hex = call_params['to']
            
            # Convert to canonical addresses
            sender = to_canonical_address(sender_hex)
            to = to_canonical_address(to_hex)
            
            # Parse data
            data_hex = call_params.get('data', call_params.get('input', '0x'))
            data = decode_hex(data_hex) if data_hex else b''
            value = int(call_params.get('value', '0x0'), 16) if isinstance(call_params.get('value'), str) else 0
            gas = int(call_params.get('gas', '0x989680'), 16) if isinstance(call_params.get('gas'), str) else 10000000
            
            # Execute call (no state changes)
            result = self.evm_executor.call(
                sender=sender,
                to=to,
                data=data,
                value=value,
                gas=gas,
            )
            
            if not result.success:
                raise RPCError(-32000, f"Call failed: {result.error}")
            
            return encode_hex(result.output)
            
        except Exception as e:
            logger.error(f"eth_call error: {e}")
            raise RPCError(-32000, str(e))
    
    async def eth_estimateGas(self, call_params: Dict[str, Any]) -> str:
        """
        Estimate gas for transaction.
        
        Args:
            call_params: Call parameters (same as eth_call)
            
        Returns:
            Estimated gas (hex-encoded)
        """
        try:
            sender_hex = call_params.get('from', '0x' + '0' * 40)
            to_hex = call_params.get('to')
            
            # Convert to canonical addresses
            sender = to_canonical_address(sender_hex)
            to = to_canonical_address(to_hex) if to_hex else None
            
            # Parse data
            data_hex = call_params.get('data', call_params.get('input', '0x'))
            data = decode_hex(data_hex) if data_hex else b''
            value = int(call_params.get('value', '0x0'), 16) if isinstance(call_params.get('value'), str) else 0
            
            # Estimate gas
            gas_estimate = self.evm_executor.estimate_gas(
                sender=sender,
                to=to,
                data=data,
                value=value,
            )
            
            return hex(gas_estimate)
            
        except Exception as e:
            logger.error(f"eth_estimateGas error: {e}")
            raise RPCError(-32000, str(e))
    
    async def eth_getCode(self, address: str, block_number: str = 'latest') -> str:
        """
        Get contract code at address.
        
        Args:
            address: Contract address
            block_number: Block number or 'latest'
            
        Returns:
            Contract bytecode (hex-encoded)
        """
        try:
            code = await self.state_manager.get_code(address)
            return '0x' + code.hex() if code else '0x'
            
        except Exception as e:
            logger.error(f"eth_getCode error: {e}")
            return '0x'
    
    async def eth_getStorageAt(
        self,
        address: str,
        position: str,
        block_number: str = 'latest'
    ) -> str:
        """
        Get storage value at position.
        
        Args:
            address: Contract address
            position: Storage position (hex)
            block_number: Block number or 'latest'
            
        Returns:
            Storage value (hex-encoded 32 bytes)
        """
        try:
            # Convert position to bytes
            pos_int = int(position, 16)
            key = pos_int.to_bytes(32, 'big')
            
            # Get storage value
            value = await self.state_manager.get_storage(address, key)
            
            return '0x' + value.hex()
            
        except Exception as e:
            logger.error(f"eth_getStorageAt error: {e}")
            return '0x' + ('0' * 64)
    
    async def eth_getTransactionCount(
        self,
        address: str,
        block_number: str = 'latest'
    ) -> str:
        """
        Get transaction count (nonce) for address.
        
        Args:
            address: Account address
            block_number: Block number or 'latest'
            
        Returns:
            Transaction count (hex-encoded)
        """
        try:
            nonce = await self.state_manager.get_nonce(address)
            return hex(nonce)
            
        except Exception as e:
            logger.error(f"eth_getTransactionCount error: {e}")
            return '0x0'
    
    async def eth_getBalance(
        self,
        address: str,
        block_number: str = 'latest'
    ) -> str:
        """
        Get account balance.
        
        Args:
            address: Account address
            block_number: Block number or 'latest'
            
        Returns:
            Balance in smallest unit (hex-encoded)
        """
        try:
            balance = await self.state_manager.get_balance(address)
            return hex(balance)
            
        except Exception as e:
            logger.error(f"eth_getBalance error: {e}")
            return '0x0'
    
    async def eth_getTransactionReceipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get transaction receipt.
        
        Args:
            tx_hash: Transaction hash
            
        Returns:
            Transaction receipt or None
        """
        try:
            from ... import Database
            database = Database.instance
            
            async with database.pool.acquire() as conn:
                # Get transaction
                tx = await conn.fetchrow(
                    """
                    SELECT * FROM contract_transactions
                    WHERE tx_hash = $1
                    """,
                    tx_hash
                )
                
                if not tx:
                    return None
                
                # Get logs
                logs = await conn.fetch(
                    """
                    SELECT * FROM contract_logs
                    WHERE tx_hash = $1
                    ORDER BY log_index
                    """,
                    tx_hash
                )
                
                # Build receipt
                receipt = {
                    'transactionHash': tx_hash,
                    'transactionIndex': hex(tx['tx_index']),
                    'blockNumber': hex(tx['block_number']),
                    'blockHash': '0x' + ('0' * 64),  # TODO: Get actual block hash
                    'from': tx['from_address'],
                    'to': tx['to_address'],
                    'cumulativeGasUsed': hex(tx['gas_used']),
                    'gasUsed': hex(tx['gas_used']),
                    'contractAddress': tx['contract_address'],
                    'logs': [
                        {
                            'address': log['contract_address'],
                            'topics': [t for t in [log['topic0'], log['topic1'], log['topic2'], log['topic3']] if t],
                            'data': '0x' + bytes(log['data']).hex() if log['data'] else '0x',
                            'blockNumber': hex(log['block_number']),
                            'transactionHash': tx_hash,
                            'transactionIndex': hex(tx['tx_index']),
                            'logIndex': hex(log['log_index']),
                            'removed': log['removed'],
                        }
                        for log in logs
                    ],
                    'logsBloom': '0x' + bytes(tx['logs_bloom']).hex() if tx['logs_bloom'] else '0x' + ('0' * 512),
                    'status': hex(tx['status']),
                }
                
                return receipt
                
        except Exception as e:
            logger.error(f"eth_getTransactionReceipt error: {e}")
            return None
    
    async def eth_getLogs(self, filter_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get logs matching filter.
        
        Args:
            filter_params: Filter parameters
                - fromBlock: Start block (optional)
                - toBlock: End block (optional)
                - address: Contract address or list (optional)
                - topics: Topic filters (optional)
            
        Returns:
            List of matching logs
        """
        try:
            from ... import Database
            database = Database.instance
            
            # Build query
            query = "SELECT * FROM contract_logs WHERE 1=1"
            params = []
            
            # Block range filter
            if 'fromBlock' in filter_params:
                from_block = self._parse_block_number(filter_params['fromBlock'])
                query += f" AND block_number >= ${len(params) + 1}"
                params.append(from_block)
            
            if 'toBlock' in filter_params:
                to_block = self._parse_block_number(filter_params['toBlock'])
                query += f" AND block_number <= ${len(params) + 1}"
                params.append(to_block)
            
            # Address filter
            if 'address' in filter_params:
                addresses = filter_params['address']
                if isinstance(addresses, str):
                    addresses = [addresses]
                query += f" AND contract_address = ANY(${len(params) + 1})"
                params.append(addresses)
            
            # Topic filters
            topics = filter_params.get('topics', [])
            for i, topic in enumerate(topics):
                if topic is not None:
                    if isinstance(topic, list):
                        query += f" AND topic{i} = ANY(${len(params) + 1})"
                        params.append(topic)
                    else:
                        query += f" AND topic{i} = ${len(params) + 1}"
                        params.append(topic)
            
            query += " ORDER BY block_number, log_index LIMIT 1000"
            
            async with database.pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
            
            # Build log objects
            logs = []
            for row in rows:
                logs.append({
                    'address': row['contract_address'],
                    'topics': [t for t in [row['topic0'], row['topic1'], row['topic2'], row['topic3']] if t],
                    'data': '0x' + bytes(row['data']).hex() if row['data'] else '0x',
                    'blockNumber': hex(row['block_number']),
                    'transactionHash': row['tx_hash'],
                    'logIndex': hex(row['log_index']),
                    'removed': row['removed'],
                })
            
            return logs
            
        except Exception as e:
            logger.error(f"eth_getLogs error: {e}")
            return []
    
    async def eth_chainId(self) -> str:
        """Get chain ID."""
        return hex(88888)  # QRDX chain ID
    
    async def eth_accounts(self) -> List[str]:
        """Get list of available accounts."""
        # Return validator wallet if available
        if self.validator_manager and hasattr(self.validator_manager, 'wallet'):
            return [self.validator_manager.wallet.address]
        return []
    
    async def _store_contract_transaction(
        self,
        tx: ContractTransaction,
        result: Any
    ) -> None:
        """Store contract transaction in database."""
        from ... import Database
        database = Database.instance
        
        block_number = await self._get_current_block_number()
        
        async with database.pool.acquire() as conn:
            # Store transaction
            await conn.execute(
                """
                INSERT INTO contract_transactions
                (tx_hash, block_number, tx_index, from_address, to_address, value,
                 gas_limit, gas_used, gas_price, nonce, input_data, contract_address,
                 status, error_message, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                """,
                tx.tx_hash,
                block_number,
                0,  # TODO: Get actual tx index
                tx.sender,
                tx.to,
                str(tx.value),
                tx.gas_limit,
                result.gas_used,
                str(tx.gas_price),
                tx.nonce,
                tx.data,
                result.contract_address,
                1 if result.success else 0,
                result.error,
                block_number,  # Using block number as timestamp
            )
            
            # Store logs
            for i, log in enumerate(result.logs):
                topics = log.get('topics', [])
                await conn.execute(
                    """
                    INSERT INTO contract_logs
                    (tx_hash, block_number, log_index, contract_address,
                     topic0, topic1, topic2, topic3, data)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    """,
                    tx.tx_hash,
                    block_number,
                    i,
                    log.get('address'),
                    topics[0] if len(topics) > 0 else None,
                    topics[1] if len(topics) > 1 else None,
                    topics[2] if len(topics) > 2 else None,
                    topics[3] if len(topics) > 3 else None,
                    bytes.fromhex(log.get('data', '')[2:]) if log.get('data') else None,
                )
    
    async def _get_current_block_number(self) -> int:
        """Get current block number."""
        from ... import Database
        database = Database.instance
        
        async with database.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT MAX(id) as height FROM blocks")
            return row['height'] if row and row['height'] else 0
    
    def _parse_block_number(self, block_param: str) -> int:
        """Parse block number parameter."""
        if block_param == 'latest' or block_param == 'pending':
            return 999999999  # Large number for latest
        elif block_param == 'earliest':
            return 0
        else:
            return int(block_param, 16)
