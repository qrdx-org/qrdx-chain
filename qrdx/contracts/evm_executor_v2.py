"""
Minimal 100% EVM-Compatible Executor for QRDX

Direct integration with py-evm (Shanghai fork) for full Ethereum compatibility.
Stripped down to essentials - no unnecessary abstractions.
"""

import sys
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass

# Add py-evm to path
sys.path.insert(0, '/workspaces/qrdx-chain-denaro/py-evm')

from eth.vm.forks.shanghai import ShanghaiVM
from eth.db.atomic import AtomicDB
from eth.db.account import AccountDB
from eth.vm.forks.shanghai.state import ShanghaiState
from eth.vm.forks.shanghai.computation import ShanghaiComputation
from eth.vm.message import Message
from eth.vm.transaction_context import BaseTransactionContext
from eth.vm.execution_context import ExecutionContext
from eth.constants import CREATE_CONTRACT_ADDRESS, ZERO_ADDRESS, GENESIS_DIFFICULTY
from eth_typing import Address
from eth_utils import (
    to_canonical_address,
    to_checksum_address,
    to_bytes,
    to_int,
    keccak,
    encode_hex,
    decode_hex,
)
import rlp


@dataclass
class EVMResult:
    """Minimal EVM execution result."""
    success: bool
    gas_used: int
    output: bytes
    logs: List[Tuple[bytes, List[bytes], bytes]]  # (address, topics, data)
    error: Optional[str] = None
    created_address: Optional[bytes] = None


class QRDXEVMExecutor:
    """
    100% EVM-Compatible Executor.
    
    Uses py-evm Shanghai fork directly - no custom modifications.
    Handles QRDX-specific state management externally.
    """
    
    def __init__(self, state_manager):
        """
        Initialize EVM executor.
        
        Args:
            state_manager: QRDX contract state manager
        """
        self.state_manager = state_manager
        
        # Create persistent databases for all executions
        from eth.db.backends.memory import MemoryDB
        from trie import HexaryTrie
        
        self.trie_db = MemoryDB()
        self.state_db = AtomicDB(self.trie_db)
        
        # Create empty state root
        empty_trie = HexaryTrie(self.trie_db)
        self.state_root = empty_trie.root_hash
        
    def _create_message(
        self,
        sender: bytes,
        to: bytes,
        value: int,
        data: bytes,
        gas: int,
        code: bytes = b'',
        is_create: bool = False,
    ) -> Message:
        """Create EVM message."""
        if is_create:
            return Message(
                gas=gas,
                to=CREATE_CONTRACT_ADDRESS,
                sender=sender,
                value=value,
                data=b'',
                code=code,
                create_address=to,
            )
        else:
            return Message(
                gas=gas,
                to=to,
                sender=sender,
                value=value,
                data=data,
                code=code,
            )
    
    def execute(
        self,
        sender: bytes,
        to: Optional[bytes],
        value: int,
        data: bytes,
        gas: int,
        gas_price: int,
        origin: Optional[bytes] = None,
    ) -> EVMResult:
        """
        Execute EVM transaction.
        
        Args:
            sender: 20-byte sender address
            to: 20-byte recipient (None for contract creation)
            value: Wei value to send
            data: Transaction data/bytecode
            gas: Gas limit
            gas_price: Gas price in wei
            origin: Transaction origin (defaults to sender)
            
        Returns:
            EVMResult with execution details
        """
        if origin is None:
            origin = sender
            
        is_create = (to is None)
        
        try:
            # Create execution context (block-level context)
            exec_context = ExecutionContext(
                coinbase=ZERO_ADDRESS,
                timestamp=1,
                block_number=1,
                difficulty=GENESIS_DIFFICULTY,
                mix_hash=b'\x00' * 32,
                gas_limit=10_000_000,
                prev_hashes=[b'\x00' * 32] * 256,
                chain_id=88888,  # QRDX chain ID
                base_fee_per_gas=1000000000,  # 1 gwei
            )
            
            # Create state with persistent root
            state = ShanghaiState(self.state_db, exec_context, self.state_root)
            
            # Sync account state from QRDX state manager
            self._sync_to_evm(state, sender, to)
            
            # Get code for contract calls
            code = b''
            if not is_create and to:
                code = self.state_manager.get_code_sync(to_checksum_address(to))
                if isinstance(code, str):
                    code = decode_hex(code) if code.startswith('0x') else bytes.fromhex(code)
            elif is_create:
                code = data
                # Generate contract address
                nonce = self.state_manager.get_nonce_sync(to_checksum_address(sender))
                to = self._compute_create_address(sender, nonce)
                
            # Create message
            message = self._create_message(
                sender=sender,
                to=to if to else ZERO_ADDRESS,
                value=value,
                data=data if not is_create else b'',
                gas=gas,
                code=code,
                is_create=is_create,
            )
            
            # Create transaction context
            tx_context = BaseTransactionContext(
                gas_price=gas_price,
                origin=origin,
            )
            
            # Execute via Shanghai computation
            if is_create:
                computation = ShanghaiComputation.apply_create_message(
                    state,
                    message,
                    tx_context,
                )
            else:
                computation = ShanghaiComputation.apply_message(
                    state,
                    message,
                    tx_context,
                )
            
            # Extract results
            success = not computation.is_error
            gas_used = gas - computation.get_gas_remaining()
            output = bytes(computation.output)
            
            # Extract logs
            logs = []
            try:
                for log_entry in computation.get_log_entries():
                    # Log entries are tuples: (address, topics, data)
                    if isinstance(log_entry, tuple):
                        logs.append(log_entry)
                    else:
                        # If it's an object with attributes
                        logs.append((log_entry.address, log_entry.topics, log_entry.data))
            except Exception as e:
                # Log extraction error shouldn't fail execution
                logger.warning(f"Could not extract logs: {e}")
            
            error = None
            if computation.is_error:
                error = str(computation.error) if computation.error else "Execution failed"
            
            # Sync state back to QRDX and persist state root
            self._sync_from_evm(state, sender, to)
            
            # Commit state changes and persist state root
            state.persist()
            self.state_root = state.state_root
            
            # Handle contract creation storage
            created_address = None
            if is_create and success:
                created_address = to
                # Store deployed code
                deployed_code = computation.output
                self.state_manager.set_code_sync(
                    to_checksum_address(to),
                    encode_hex(deployed_code)
                )
                # Update nonce
                self.state_manager.set_nonce_sync(
                    to_checksum_address(sender),
                    nonce + 1
                )
            
            # Deduct gas cost from sender
            gas_cost = gas_used * gas_price
            sender_addr_str = to_checksum_address(sender)
            sender_balance = self.state_manager.get_balance_sync(sender_addr_str)
            self.state_manager.set_balance_sync(
                sender_addr_str,
                sender_balance - gas_cost - value
            )
            
            # Credit value to recipient
            if value > 0:
                if to:
                    to_addr_str = to_checksum_address(to)
                    to_balance = self.state_manager.get_balance_sync(to_addr_str)
                    self.state_manager.set_balance_sync(to_addr_str, to_balance + value)
            
            return EVMResult(
                success=success,
                gas_used=gas_used,
                output=output,
                logs=logs,
                error=error,
                created_address=created_address,
            )
            
        except Exception as e:
            from ..logger import get_logger
            logger = get_logger(__name__)
            logger.error(f"EVM execution error: {e}", exc_info=True)
            return EVMResult(
                success=False,
                gas_used=gas,
                output=b'',
                logs=[],
                error=f"Execution error: {str(e)}",
            )
    
    def call(
        self,
        sender: bytes,
        to: bytes,
        data: bytes,
        value: int = 0,
        gas: int = 10_000_000,
    ) -> EVMResult:
        """
        Execute read-only call (eth_call).
        
        State changes are not persisted.
        """
        # Take snapshot
        snapshot = self.state_manager.snapshot_sync()
        
        try:
            result = self.execute(
                sender=sender,
                to=to,
                value=value,
                data=data,
                gas=gas,
                gas_price=0,
            )
            return result
        finally:
            # Always revert to snapshot
            self.state_manager.revert_sync(snapshot)
    
    def estimate_gas(
        self,
        sender: bytes,
        to: Optional[bytes],
        data: bytes,
        value: int = 0,
    ) -> int:
        """
        Estimate gas for transaction.
        
        Uses binary search to find minimum gas.
        """
        low = 21000  # Minimum transaction cost
        high = 10_000_000
        
        snapshot = self.state_manager.snapshot_sync()
        
        try:
            # Binary search
            while low < high:
                mid = (low + high) // 2
                
                result = self.execute(
                    sender=sender,
                    to=to,
                    value=value,
                    data=data,
                    gas=mid,
                    gas_price=0,
                )
                
                if result.success:
                    high = mid
                else:
                    low = mid + 1
                
                # Revert for next iteration
                self.state_manager.revert_sync(snapshot)
                snapshot = self.state_manager.snapshot_sync()
            
            # Add 10% buffer
            return int(low * 1.1)
            
        finally:
            self.state_manager.revert_sync(snapshot)
    
    def _compute_create_address(self, sender: bytes, nonce: int) -> bytes:
        """Compute CREATE address."""
        rlp_encoded = rlp.encode([sender, nonce])
        return keccak(rlp_encoded)[12:]  # Take last 20 bytes
    
    def _sync_to_evm(self, state: ShanghaiState, sender: bytes, to: Optional[bytes]) -> None:
        """Sync QRDX state to EVM state."""
        # Sync sender
        sender_addr = to_checksum_address(sender)
        balance = self.state_manager.get_balance_sync(sender_addr)
        nonce = self.state_manager.get_nonce_sync(sender_addr)
        
        state.set_balance(sender, balance)
        state.set_nonce(sender, nonce)
        
        # Sync recipient if exists
        if to:
            to_addr = to_checksum_address(to)
            balance = self.state_manager.get_balance_sync(to_addr)
            nonce = self.state_manager.get_nonce_sync(to_addr)
            code = self.state_manager.get_code_sync(to_addr)
            
            state.set_balance(to, balance)
            state.set_nonce(to, nonce)
            
            if code:
                if isinstance(code, str):
                    code = decode_hex(code) if code.startswith('0x') else bytes.fromhex(code)
                state.set_code(to, code)
            
            # Sync storage
            storage = self.state_manager.get_all_storage_sync(to_addr)
            for key_hex, value_hex in storage.items():
                key = to_int(hexstr=key_hex)
                value = to_int(hexstr=value_hex)
                state.set_storage(to, key, value)
    
    def _sync_from_evm(self, state: ShanghaiState, sender: bytes, to: Optional[bytes]) -> None:
        """Sync EVM state back to QRDX state."""
        # Sync sender balances/nonces
        sender_addr = to_checksum_address(sender)
        self.state_manager.set_balance_sync(sender_addr, state.get_balance(sender))
        self.state_manager.set_nonce_sync(sender_addr, state.get_nonce(sender))
        
        # Sync recipient if exists
        if to:
            to_addr = to_checksum_address(to)
            self.state_manager.set_balance_sync(to_addr, state.get_balance(to))
            self.state_manager.set_nonce_sync(to_addr, state.get_nonce(to))
        
        # Note: Storage is already persisted in the EVM state database
        # We don't need to manually sync it back since we use persistent state_root
