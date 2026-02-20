"""
QRDX eth_* RPC Methods

Web3-compatible Ethereum JSON-RPC methods.
"""

from decimal import Decimal
from typing import Any, Dict, List, Optional, Union

from ...logger import get_logger
from ..server import RPCModule, rpc_method, RPCError, RPCErrorCode

logger = get_logger(__name__)


class EthModule(RPCModule):
    """
    Ethereum-compatible RPC methods (eth_* namespace).

    Implements standard Web3 methods for compatibility with
    existing Ethereum tooling (web3.py, ethers.js, etc.).
    """

    namespace = "eth"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _resolve_block_id(self, block_number: str) -> int:
        """Convert a block parameter ('latest', 'earliest', 'pending', hex)
        to a concrete integer block id."""
        if block_number in ("latest", "pending"):
            return await self.context.db.get_next_block_id() - 1
        elif block_number == "earliest":
            return 0
        else:
            return int(block_number, 16)

    async def _get_contract_tx(self, tx_hash: str) -> Optional[Dict]:
        """Look up a contract transaction from the contract_transactions table.
        Returns a dict row, or None."""
        try:
            db = self.context.db
            async with db.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM contract_transactions WHERE tx_hash = $1",
                    tx_hash,
                )
                return dict(row) if row else None
        except Exception:
            return None

    async def _get_contract_logs_for_tx(self, tx_hash: str) -> List[Dict]:
        """Get event logs for a specific contract transaction."""
        try:
            db = self.context.db
            async with db.pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM contract_logs WHERE tx_hash = $1 ORDER BY log_index",
                    tx_hash,
                )
                return [dict(r) for r in rows]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # eth_chainId
    # ------------------------------------------------------------------

    @rpc_method
    async def chainId(self) -> str:
        """
        Returns the chain ID.

        Returns:
            Hex string of chain ID
        """
        chain_id = (
            self.context.config.chain_id
            if (self.context and hasattr(self.context, 'config')
                and hasattr(self.context.config, 'chain_id'))
            else 88888
        )
        return hex(chain_id)

    # ------------------------------------------------------------------
    # eth_blockNumber
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # eth_getBlockByNumber
    # ------------------------------------------------------------------

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

        block_id = await self._resolve_block_id(block_number)
        if block_id < 0:
            return None

        block = await self.context.db.get_block_by_id(block_id)
        if not block:
            return None

        return await self._format_block(block, include_transactions)

    # ------------------------------------------------------------------
    # eth_getBlockByHash
    # ------------------------------------------------------------------

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

        if block_hash.startswith("0x"):
            block_hash = block_hash[2:]

        block = await self.context.db.get_block(block_hash)
        if not block:
            return None

        return await self._format_block(block, include_transactions)

    # ------------------------------------------------------------------
    # eth_getTransactionByHash
    # ------------------------------------------------------------------

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

        raw_hash = tx_hash[2:] if tx_hash.startswith("0x") else tx_hash

        # Try contract transaction first (richer data)
        ctx = await self._get_contract_tx(raw_hash)
        if ctx:
            return self._format_contract_transaction(ctx)

        # Fall back to native UTXO transaction
        tx_info = await self.context.db.get_transaction_info(raw_hash)
        if not tx_info:
            return None

        return self._format_native_transaction(tx_info)

    # ------------------------------------------------------------------
    # eth_getTransactionReceipt
    # ------------------------------------------------------------------

    @rpc_method
    async def getTransactionReceipt(self, tx_hash: str) -> Optional[Dict]:
        """
        Returns transaction receipt by hash.

        Queries the contract_transactions and contract_logs tables for
        real gas usage, status, logs and contract addresses.  Falls back
        to a lightweight receipt for native UTXO transactions.

        Args:
            tx_hash: Transaction hash (0x prefixed)

        Returns:
            Transaction receipt or None
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")

        raw_hash = tx_hash[2:] if tx_hash.startswith("0x") else tx_hash

        # --- contract transaction (rich receipt) --------------------------
        ctx = await self._get_contract_tx(raw_hash)
        if ctx:
            logs_rows = await self._get_contract_logs_for_tx(raw_hash)
            logs = []
            for log in logs_rows:
                topics = [
                    t for t in [
                        log.get('topic0'), log.get('topic1'),
                        log.get('topic2'), log.get('topic3'),
                    ] if t
                ]
                data_field = log.get('data')
                if isinstance(data_field, (bytes, memoryview)):
                    data_hex = '0x' + bytes(data_field).hex()
                elif isinstance(data_field, str):
                    data_hex = data_field if data_field.startswith('0x') else '0x' + data_field
                else:
                    data_hex = '0x'

                logs.append({
                    "address": log.get('contract_address', ''),
                    "topics": topics,
                    "data": data_hex,
                    "blockNumber": hex(log.get('block_number', 0)),
                    "transactionHash": "0x" + raw_hash,
                    "transactionIndex": hex(ctx.get('tx_index', 0)),
                    "logIndex": hex(log.get('log_index', 0)),
                    "removed": bool(log.get('removed', False)),
                })

            bloom = ctx.get('logs_bloom')
            if isinstance(bloom, (bytes, memoryview)):
                bloom_hex = '0x' + bytes(bloom).hex()
            else:
                bloom_hex = '0x' + '00' * 256

            block_hash_raw = ctx.get('block_hash', '0' * 64)
            if not isinstance(block_hash_raw, str):
                block_hash_raw = '0' * 64

            return {
                "transactionHash": "0x" + raw_hash,
                "transactionIndex": hex(ctx.get('tx_index', 0)),
                "blockHash": "0x" + block_hash_raw,
                "blockNumber": hex(ctx.get('block_number', 0)),
                "from": ctx.get('from_address', '0x' + '0' * 40),
                "to": ctx.get('to_address'),
                "cumulativeGasUsed": hex(ctx.get('gas_used', 0)),
                "gasUsed": hex(ctx.get('gas_used', 0)),
                "contractAddress": ctx.get('contract_address'),
                "logs": logs,
                "logsBloom": bloom_hex,
                "status": hex(ctx.get('status', 1)),
                "type": "0x0",
            }

        # --- native UTXO transaction (lightweight receipt) ----------------
        tx_info = await self.context.db.get_transaction_info(raw_hash)
        if not tx_info:
            return None

        block_hash = tx_info.get("block_hash", "0" * 64) or "0" * 64

        # Resolve block number from block hash
        block_id = 0
        try:
            blk = await self.context.db.get_block(block_hash)
            if blk:
                block_id = blk.get("id", 0)
        except Exception:
            pass

        return {
            "transactionHash": "0x" + raw_hash,
            "transactionIndex": "0x0",
            "blockHash": "0x" + block_hash,
            "blockNumber": hex(block_id),
            "from": (tx_info.get("inputs_addresses") or ["0x" + "0" * 40])[0],
            "to": (tx_info.get("outputs_addresses") or [None])[0],
            "cumulativeGasUsed": "0x0",
            "gasUsed": "0x0",
            "contractAddress": None,
            "logs": [],
            "logsBloom": "0x" + "00" * 256,
            "status": "0x1",
            "type": "0x0",
        }

    # ------------------------------------------------------------------
    # eth_getBalance
    # ------------------------------------------------------------------

    @rpc_method
    async def getBalance(
        self,
        address: str,
        block_number: str = "latest"
    ) -> str:
        """
        Returns the balance of an address.

        Checks the EVM state manager first (for contract accounts),
        then falls back to native UTXO balance.

        Args:
            address: Address to query
            block_number: Block number (hex) or tag

        Returns:
            Balance in the smallest native unit (hex).
            QRDX uses 6 decimals; Ethereum tooling expects 18.
            The value is scaled to 18-decimal wei for Web3 compatibility.
        """
        if not self.context or not self.context.db:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Database not available")

        # Try EVM state manager first (contract/EVM accounts)
        if hasattr(self.context, 'state_manager') and self.context.state_manager:
            try:
                balance = await self.context.state_manager.get_balance(address)
                if balance and balance > 0:
                    return hex(balance)
            except Exception:
                pass

        # Native UTXO balance (Decimal in QRDX units)
        balance = await self.context.db.get_address_balance(address)

        # QRDX uses 6 decimals (SMALLEST = 1_000_000).
        # Ethereum uses 18 decimals.  Scale up by 10^12 so Web3 tools work.
        balance_int = int(balance * 10**18) if balance else 0
        return hex(balance_int)

    # ------------------------------------------------------------------
    # eth_getTransactionCount
    # ------------------------------------------------------------------

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

        # Contract/EVM nonce from state manager
        if hasattr(self.context, 'state_manager') and self.context.state_manager:
            try:
                nonce = await self.context.state_manager.get_nonce(address)
                return hex(nonce)
            except Exception:
                pass

        # Native tx count via direct DB query
        if hasattr(self.context, 'db') and self.context.db:
            try:
                async with self.context.db.pool.acquire() as conn:
                    count = await conn.fetchval(
                        "SELECT COUNT(*) FROM transactions WHERE inputs_addresses @> ARRAY[$1]::text[]",
                        address,
                    )
                    return hex(count if count else 0)
            except Exception:
                pass

        return "0x0"

    # ------------------------------------------------------------------
    # eth_sendRawTransaction  (delegated to node/main.py handler)
    # ------------------------------------------------------------------

    @rpc_method
    async def sendRawTransaction(self, raw_tx: str) -> str:
        """
        Submits a signed transaction.

        The real implementation is registered via ``register_method`` in
        ``node/main.py`` which overrides this module method at startup.
        If execution reaches this body it means the override was not
        registered (e.g. EVM subsystem disabled).

        Args:
            raw_tx: Signed transaction hex

        Returns:
            Transaction hash
        """
        if not self.context:
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, "Context not available")

        raise RPCError(
            RPCErrorCode.METHOD_NOT_SUPPORTED,
            "eth_sendRawTransaction requires the EVM subsystem to be enabled "
            "(set QRDX_RPC_ENABLED=true)"
        )

    # ------------------------------------------------------------------
    # eth_call  (delegated to node/main.py handler when EVM is up)
    # ------------------------------------------------------------------

    @rpc_method
    async def call(
        self,
        transaction: Dict,
        block_number: str = "latest"
    ) -> str:
        """
        Executes a call without creating a transaction.

        When the EVM executor is available the real handler is registered
        as an override in ``node/main.py``.  This fallback attempts a
        direct call through the executor on the context.

        Args:
            transaction: Transaction object
            block_number: Block number or tag

        Returns:
            Call result (hex)
        """
        if self.context and hasattr(self.context, 'evm_executor') and self.context.evm_executor:
            try:
                from eth_utils import to_canonical_address, encode_hex, decode_hex

                sender_hex = transaction.get('from', '0x' + '0' * 40)
                to_hex = transaction.get('to')
                if not to_hex:
                    return "0x"
                data_hex = transaction.get('data', transaction.get('input', '0x'))
                value = (
                    int(transaction.get('value', '0x0'), 16)
                    if isinstance(transaction.get('value'), str)
                    else int(transaction.get('value', 0))
                )
                gas = (
                    int(transaction.get('gas', '0x989680'), 16)
                    if isinstance(transaction.get('gas'), str)
                    else int(transaction.get('gas', 10_000_000))
                )

                sender = to_canonical_address(sender_hex)
                to = to_canonical_address(to_hex)
                data = decode_hex(data_hex) if data_hex else b''

                result = self.context.evm_executor.call(
                    sender=sender, to=to, data=data,
                    value=value, gas=gas,
                )
                if not result.success:
                    raise RPCError(RPCErrorCode.EXECUTION_ERROR, f"Call reverted: {result.error}")
                return encode_hex(result.output)
            except RPCError:
                raise
            except Exception as e:
                raise RPCError(RPCErrorCode.INTERNAL_ERROR, str(e))

        return "0x"

    # ------------------------------------------------------------------
    # eth_estimateGas
    # ------------------------------------------------------------------

    @rpc_method
    async def estimateGas(self, transaction: Dict) -> str:
        """
        Estimates gas for a transaction.

        Runs the transaction through the EVM executor in estimation mode
        when available; otherwise returns the standard transfer gas.

        Args:
            transaction: Transaction object

        Returns:
            Gas estimate (hex)
        """
        if self.context and hasattr(self.context, 'evm_executor') and self.context.evm_executor:
            try:
                from eth_utils import to_canonical_address, decode_hex

                sender_hex = transaction.get('from', '0x' + '0' * 40)
                to_hex = transaction.get('to')
                data_hex = transaction.get('data', transaction.get('input', '0x'))
                value = (
                    int(transaction.get('value', '0x0'), 16)
                    if isinstance(transaction.get('value'), str)
                    else int(transaction.get('value', 0))
                )

                sender = to_canonical_address(sender_hex)
                to = to_canonical_address(to_hex) if to_hex else None
                data = decode_hex(data_hex) if data_hex else b''

                gas_estimate = self.context.evm_executor.estimate_gas(
                    sender=sender, to=to, data=data, value=value,
                )
                return hex(gas_estimate)
            except Exception as e:
                logger.debug(f"estimateGas EVM fallback: {e}")
                return hex(10_000_000)

        # Simple QRDX transfer
        return hex(21000)

    # ------------------------------------------------------------------
    # eth_gasPrice
    # ------------------------------------------------------------------

    @rpc_method
    async def gasPrice(self) -> str:
        """
        Returns current gas price.

        QRDX doesn't use gas, returns 0.

        Returns:
            Gas price (hex)
        """
        return "0x0"

    # ------------------------------------------------------------------
    # eth_syncing
    # ------------------------------------------------------------------

    @rpc_method
    async def syncing(self) -> Union[bool, Dict]:
        """
        Returns sync status.

        Checks the ``SyncStateManager`` and ``NodesManager`` to compare
        local block height against the highest height reported by peers.

        Returns:
            False if not syncing, or sync status dict
        """
        if not self.context or not self.context.db:
            return False

        try:
            current_block = await self.context.db.get_next_block_id() - 1

            # Check SyncStateManager flag (set by the sync subsystem)
            if hasattr(self.context, 'sync_state_manager') and self.context.sync_state_manager:
                if self.context.sync_state_manager.is_syncing:
                    highest = current_block
                    if hasattr(self.context, 'nodes_manager'):
                        nm = self.context.nodes_manager
                        peers = getattr(nm, 'peers', {}) or {}
                        for peer_data in peers.values():
                            ph = peer_data.get('height', 0)
                            if isinstance(ph, int) and ph > highest:
                                highest = ph
                    return {
                        "startingBlock": hex(max(0, current_block)),
                        "currentBlock": hex(max(0, current_block)),
                        "highestBlock": hex(max(0, highest)),
                    }

            # Also try the module-level NodesManager
            try:
                from ...node.nodes_manager import NodesManager
                peers = getattr(NodesManager, 'peers', {}) or {}
                highest = current_block
                for peer_data in peers.values():
                    ph = peer_data.get('height', 0)
                    if isinstance(ph, int) and ph > highest:
                        highest = ph
                # If we are more than 5 blocks behind best-known peer
                if highest > current_block + 5:
                    return {
                        "startingBlock": hex(max(0, current_block)),
                        "currentBlock": hex(max(0, current_block)),
                        "highestBlock": hex(highest),
                    }
            except Exception:
                pass

            return False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # eth_mining
    # ------------------------------------------------------------------

    @rpc_method
    async def mining(self) -> bool:
        """
        Returns whether the node is mining.

        Returns:
            True if mining
        """
        if self.context and hasattr(self.context, 'miner'):
            return bool(self.context.miner)
        return False

    # ------------------------------------------------------------------
    # eth_hashrate
    # ------------------------------------------------------------------

    @rpc_method
    async def hashrate(self) -> str:
        """
        Returns the node's hashrate.

        Returns:
            Hashrate (hex)
        """
        if self.context and hasattr(self.context, 'miner') and self.context.miner:
            if hasattr(self.context.miner, 'hashrate'):
                return hex(int(self.context.miner.hashrate))
        return "0x0"

    # ------------------------------------------------------------------
    # eth_accounts
    # ------------------------------------------------------------------

    @rpc_method
    async def accounts(self) -> List[str]:
        """
        Returns list of accounts owned by the node.

        Returns:
            List of account addresses
        """
        accts: List[str] = []

        if self.context and hasattr(self.context, 'validator_manager'):
            vm = self.context.validator_manager
            if hasattr(vm, 'wallet') and hasattr(vm.wallet, 'address'):
                accts.append(vm.wallet.address)

        if self.context and hasattr(self.context, 'wallet'):
            w = self.context.wallet
            if hasattr(w, 'address') and w.address not in accts:
                accts.append(w.address)

        return accts

    # ------------------------------------------------------------------
    # eth_getCode
    # ------------------------------------------------------------------

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
        if self.context and hasattr(self.context, 'state_manager') and self.context.state_manager:
            try:
                code = await self.context.state_manager.get_code(address)
                if code:
                    return "0x" + code.hex()
            except Exception:
                pass
        return "0x"

    # ------------------------------------------------------------------
    # eth_getLogs
    # ------------------------------------------------------------------

    @rpc_method
    async def getLogs(self, filter_params: Dict) -> List[Dict]:
        """
        Returns logs matching filter.

        Queries the ``contract_logs`` table with the supplied filter
        parameters (fromBlock, toBlock, address, topics).

        Args:
            filter_params: Filter parameters

        Returns:
            List of log objects
        """
        if not self.context or not self.context.db:
            return []

        try:
            db = self.context.db
            query = "SELECT * FROM contract_logs WHERE 1=1"
            params: list = []

            # Block range
            if 'fromBlock' in filter_params:
                fb = filter_params['fromBlock']
                from_block = await self._resolve_block_id(fb) if isinstance(fb, str) else int(fb)
                params.append(from_block)
                query += f" AND block_number >= ${len(params)}"

            if 'toBlock' in filter_params:
                tb = filter_params['toBlock']
                to_block = await self._resolve_block_id(tb) if isinstance(tb, str) else int(tb)
                params.append(to_block)
                query += f" AND block_number <= ${len(params)}"

            # Address filter
            if 'address' in filter_params:
                addresses = filter_params['address']
                if isinstance(addresses, str):
                    addresses = [addresses]
                params.append(addresses)
                query += f" AND contract_address = ANY(${len(params)})"

            # Topic filters
            for i, topic in enumerate(filter_params.get('topics', [])):
                if topic is None:
                    continue
                col = f"topic{i}"
                if isinstance(topic, list):
                    params.append(topic)
                    query += f" AND {col} = ANY(${len(params)})"
                else:
                    params.append(topic)
                    query += f" AND {col} = ${len(params)}"

            query += " ORDER BY block_number, log_index LIMIT 10000"

            async with db.pool.acquire() as conn:
                rows = await conn.fetch(query, *params)

            result = []
            for row in rows:
                topics = [
                    t for t in [row.get('topic0'), row.get('topic1'),
                                row.get('topic2'), row.get('topic3')]
                    if t
                ]
                data_field = row.get('data')
                if isinstance(data_field, (bytes, memoryview)):
                    data_hex = '0x' + bytes(data_field).hex()
                elif isinstance(data_field, str):
                    data_hex = data_field if data_field.startswith('0x') else '0x' + data_field
                else:
                    data_hex = '0x'

                result.append({
                    "address": row.get('contract_address', ''),
                    "topics": topics,
                    "data": data_hex,
                    "blockNumber": hex(row.get('block_number', 0)),
                    "transactionHash": row.get('tx_hash', ''),
                    "logIndex": hex(row.get('log_index', 0)),
                    "removed": bool(row.get('removed', False)),
                })

            return result
        except Exception as e:
            logger.debug(f"getLogs error (table may not exist yet): {e}")
            return []

    # ------------------------------------------------------------------
    # eth_getStorageAt
    # ------------------------------------------------------------------

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
                pos_int = int(position, 16) if position.startswith('0x') else int(position, 16)
                key = pos_int.to_bytes(32, 'big')
                value = await self.context.state_manager.get_storage(address, key)
                return '0x' + value.hex() if value else '0x' + ('0' * 64)
            except Exception:
                pass
        return '0x' + ('0' * 64)

    # ------------------------------------------------------------------
    # eth_getBlockTransactionCountByHash
    # ------------------------------------------------------------------

    @rpc_method
    async def getBlockTransactionCountByHash(self, block_hash: str) -> Optional[str]:
        """
        Returns number of transactions in a block by hash.
        """
        if not self.context or not self.context.db:
            return "0x0"

        if block_hash.startswith("0x"):
            block_hash = block_hash[2:]

        block = await self.context.db.get_block(block_hash)
        if not block:
            return None

        try:
            tx_hashes = await self.context.db.get_block_transaction_hashes(block_hash)
            return hex(len(tx_hashes))
        except Exception:
            return hex(block.get("transaction_count", 0))

    # ------------------------------------------------------------------
    # eth_getBlockTransactionCountByNumber
    # ------------------------------------------------------------------

    @rpc_method
    async def getBlockTransactionCountByNumber(self, block_number: str) -> Optional[str]:
        """
        Returns number of transactions in a block by number.
        """
        if not self.context or not self.context.db:
            return "0x0"

        block_id = await self._resolve_block_id(block_number)
        if block_id < 0:
            return None

        block = await self.context.db.get_block_by_id(block_id)
        if not block:
            return None

        block_hash = block.get("hash", "")
        try:
            tx_hashes = await self.context.db.get_block_transaction_hashes(block_hash)
            return hex(len(tx_hashes))
        except Exception:
            return hex(block.get("transaction_count", 0))

    # ------------------------------------------------------------------
    # eth_getUncleCountByBlockHash / ByBlockNumber
    # ------------------------------------------------------------------

    @rpc_method
    async def getUncleCountByBlockHash(self, block_hash: str) -> str:
        """QRDX doesn't have uncles (Proof of Stake)."""
        return "0x0"

    @rpc_method
    async def getUncleCountByBlockNumber(self, block_number: str) -> str:
        """QRDX doesn't have uncles (Proof of Stake)."""
        return "0x0"

    # ------------------------------------------------------------------
    # eth_getTransactionByBlockHashAndIndex
    # ------------------------------------------------------------------

    @rpc_method
    async def getTransactionByBlockHashAndIndex(
        self,
        block_hash: str,
        index: str
    ) -> Optional[Dict]:
        """
        Returns transaction by block hash and index.
        """
        if not self.context or not self.context.db:
            return None

        if block_hash.startswith("0x"):
            block_hash = block_hash[2:]

        tx_index = int(index, 16)

        block = await self.context.db.get_block(block_hash)
        if not block:
            return None

        try:
            tx_hashes = await self.context.db.get_block_transaction_hashes(block_hash)
            if tx_index < 0 or tx_index >= len(tx_hashes):
                return None
            target_hash = tx_hashes[tx_index]

            ctx = await self._get_contract_tx(target_hash)
            if ctx:
                return self._format_contract_transaction(ctx)

            tx_info = await self.context.db.get_transaction_info(target_hash)
            if tx_info:
                formatted = self._format_native_transaction(tx_info)
                formatted["transactionIndex"] = hex(tx_index)
                return formatted
        except Exception as e:
            logger.debug(f"getTransactionByBlockHashAndIndex error: {e}")

        return None

    # ------------------------------------------------------------------
    # eth_getTransactionByBlockNumberAndIndex
    # ------------------------------------------------------------------

    @rpc_method
    async def getTransactionByBlockNumberAndIndex(
        self,
        block_number: str,
        index: str
    ) -> Optional[Dict]:
        """
        Returns transaction by block number and index.
        """
        if not self.context or not self.context.db:
            return None

        block_id = await self._resolve_block_id(block_number)
        if block_id < 0:
            return None

        block = await self.context.db.get_block_by_id(block_id)
        if not block:
            return None

        block_hash = block.get("hash", "")
        tx_index = int(index, 16)

        try:
            tx_hashes = await self.context.db.get_block_transaction_hashes(block_hash)
            if tx_index < 0 or tx_index >= len(tx_hashes):
                return None
            target_hash = tx_hashes[tx_index]

            ctx = await self._get_contract_tx(target_hash)
            if ctx:
                return self._format_contract_transaction(ctx)

            tx_info = await self.context.db.get_transaction_info(target_hash)
            if tx_info:
                formatted = self._format_native_transaction(tx_info)
                formatted["transactionIndex"] = hex(tx_index)
                return formatted
        except Exception as e:
            logger.debug(f"getTransactionByBlockNumberAndIndex error: {e}")

        return None

    # ------------------------------------------------------------------
    # eth_protocolVersion
    # ------------------------------------------------------------------

    @rpc_method
    async def protocolVersion(self) -> str:
        """
        Returns the current ethereum protocol version.

        Returns:
            Protocol version (hex)
        """
        return hex(65)

    # ===================================================================
    # Formatting helpers
    # ===================================================================

    async def _format_block(self, block: Dict, include_txs: bool) -> Dict:
        """Format a block dict from the DB into a Web3-compatible response."""

        block_hash = block.get("hash", "0" * 64)
        block_id = block.get("id", 0)

        # Resolve transactions
        transactions: list = []
        if include_txs and self.context and self.context.db:
            try:
                tx_hashes = await self.context.db.get_block_transaction_hashes(block_hash)
                for i, th in enumerate(tx_hashes):
                    ctx = await self._get_contract_tx(th)
                    if ctx:
                        formatted = self._format_contract_transaction(ctx)
                    else:
                        tx_info = await self.context.db.get_transaction_info(th)
                        if tx_info:
                            formatted = self._format_native_transaction(tx_info)
                        else:
                            formatted = {"hash": "0x" + th}
                    formatted["transactionIndex"] = hex(i)
                    transactions.append(formatted)
            except Exception:
                transactions = []
        elif not include_txs and self.context and self.context.db:
            try:
                tx_hashes = await self.context.db.get_block_transaction_hashes(block_hash)
                transactions = ["0x" + h for h in tx_hashes]
            except Exception:
                transactions = []

        # Aggregate gas from contract transactions in this block
        gas_used = 0
        try:
            db = self.context.db
            async with db.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT COALESCE(SUM(gas_used), 0) AS total_gas "
                    "FROM contract_transactions WHERE block_number = $1",
                    block_id,
                )
                if row:
                    gas_used = int(row['total_gas'])
        except Exception:
            pass

        # State root from EVM state manager (if available)
        state_root = "0x" + "0" * 64
        if hasattr(self.context, 'state_manager') and self.context.state_manager:
            try:
                sr = await self.context.state_manager.get_state_root()
                if sr:
                    state_root = "0x" + (sr.hex() if isinstance(sr, bytes) else str(sr))
            except Exception:
                pass

        miner = block.get("address", "") or block.get("miner", "")
        if not miner:
            miner = "0x" + "0" * 40

        return {
            "number": hex(block_id),
            "hash": "0x" + block_hash,
            "parentHash": "0x" + block.get("previous_hash", "0" * 64),
            "nonce": "0x" + "0" * 16,
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "logsBloom": "0x" + "00" * 256,
            "transactionsRoot": "0x" + block.get("merkle_tree", "0" * 64),
            "stateRoot": state_root,
            "receiptsRoot": "0x" + "0" * 64,
            "miner": miner,
            "difficulty": hex(int(float(block.get("difficulty", 0)) * 1000)),
            "totalDifficulty": hex(int(float(block.get("difficulty", 0)) * 1000)),
            "extraData": "0x",
            "size": hex(max(1, len(block.get("content", "") or "") // 2)),
            "gasLimit": hex(30_000_000),
            "gasUsed": hex(gas_used),
            "timestamp": hex(block.get("timestamp", 0)),
            "transactions": transactions,
            "uncles": [],
            "baseFeePerGas": "0x0",
        }

    def _format_contract_transaction(self, ctx: Dict) -> Dict:
        """Format a contract_transactions row into a Web3 tx object."""
        input_data = ctx.get('input_data')
        if isinstance(input_data, (bytes, memoryview)):
            input_hex = '0x' + bytes(input_data).hex()
        elif isinstance(input_data, str):
            input_hex = input_data if input_data.startswith('0x') else '0x' + input_data
        else:
            input_hex = '0x'

        block_hash = ctx.get('block_hash', '0' * 64)
        if not isinstance(block_hash, str):
            block_hash = '0' * 64

        return {
            "hash": "0x" + (ctx.get('tx_hash', '0' * 64) or '0' * 64),
            "blockHash": "0x" + block_hash,
            "blockNumber": hex(ctx.get('block_number', 0)),
            "transactionIndex": hex(ctx.get('tx_index', 0)),
            "from": ctx.get('from_address', '0x' + '0' * 40),
            "to": ctx.get('to_address'),
            "value": hex(int(ctx.get('value', 0))),
            "gas": hex(ctx.get('gas_limit', 0)),
            "gasPrice": hex(int(ctx.get('gas_price', 0))),
            "input": input_hex,
            "nonce": hex(ctx.get('nonce', 0)),
            "v": "0x0",
            "r": "0x0",
            "s": "0x0",
            "type": "0x0",
        }

    def _format_native_transaction(self, tx_info: Dict) -> Dict:
        """Format a native UTXO transaction row into a Web3-like tx object."""
        tx_hash = tx_info.get("tx_hash", "0" * 64)
        block_hash = tx_info.get("block_hash", "0" * 64) or "0" * 64

        # Sender = first input address
        inputs_addrs = tx_info.get("inputs_addresses") or []
        from_addr = inputs_addrs[0] if inputs_addrs else "0x" + "0" * 40

        # Recipient = first output address
        outputs_addrs = tx_info.get("outputs_addresses") or []
        to_addr = outputs_addrs[0] if outputs_addrs else None

        # Value = sum of output amounts (in smallest unit)
        outputs_amounts = tx_info.get("outputs_amounts") or []
        total_value = sum(int(a) for a in outputs_amounts) if outputs_amounts else 0

        return {
            "hash": "0x" + tx_hash,
            "blockHash": "0x" + block_hash,
            "blockNumber": "0x0",
            "transactionIndex": "0x0",
            "from": from_addr,
            "to": to_addr,
            "value": hex(total_value),
            "gas": "0x5208",
            "gasPrice": "0x0",
            "input": "0x",
            "nonce": "0x0",
            "v": "0x0",
            "r": "0x0",
            "s": "0x0",
            "type": "0x0",
        }
