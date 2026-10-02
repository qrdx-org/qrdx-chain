"""
QRDX EVM Executor (Production)

Direct integration with py-evm QRDX fork for full Ethereum + PQ compatibility.
Uses QRDXVM (extends ShanghaiVM) with quantum-resistant precompiles at
0x09-0x0c.  Stripped down to essentials — no unnecessary abstractions.
"""

import logging
import sys
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass

from importlib import util as importlib_util

# Prefer an installed `eth` package (the container installs the py-evm QRDX fork
# as a wheel). Fall back to the in-repo checkout for local development, resolved
# relative to this file rather than a hardcoded absolute path.
import os

if importlib_util.find_spec("eth") is None:
    _vendored_py_evm = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "py-evm",
    )
    if os.path.isdir(_vendored_py_evm) and _vendored_py_evm not in sys.path:
        sys.path.insert(0, _vendored_py_evm)

from eth.vm.forks.qrdx import QRDXVM
from eth.db.atomic import AtomicDB
from eth.db.account import AccountDB
from eth.vm.forks.qrdx.state import QRDXState
from eth.vm.forks.qrdx.computation import QRDXComputation
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

logger = logging.getLogger(__name__)


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
    
    Uses py-evm QRDX fork (extends Shanghai) with PQ precompiles.
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
        intrinsic_gas: int = 0,
        block_number: int = 1,
        timestamp: int = 1,
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
            intrinsic_gas: Transaction-level gas floor (21000 + calldata for a
                legacy tx; substantially more for a type-0x51 PQ tx, which must
                pay for its ~5.3KB authentication envelope). ``apply_message``
                charges NO transaction-level gas, so without this a plain transfer
                costs nothing at all. Callers that are not executing a real
                transaction (``eth_call``, gas estimation) leave it at 0.
            
        Returns:
            EVMResult with execution details. ``gas_used`` is the amount actually
            charged, i.e. the floor when execution consumed less than it.
        """
        if origin is None:
            origin = sender
            
        is_create = (to is None)
        
        try:
            # Create execution context (block-level context)
            # block.number / block.timestamp are the block being executed — every consensus
            # path passes them (proposer, importers, rebuild), so contracts with timelocks or
            # vesting see the chain advance, identically on every node. They used to be the
            # constant 1. The defaults serve callers with no block (standalone use).
            exec_context = ExecutionContext(
                coinbase=ZERO_ADDRESS,
                timestamp=max(1, int(timestamp)),
                block_number=max(1, int(block_number)),
                difficulty=GENESIS_DIFFICULTY,
                mix_hash=b'\x00' * 32,
                gas_limit=10_000_000,
                prev_hashes=[b'\x00' * 32] * 256,
                chain_id=88888,  # QRDX chain ID
                base_fee_per_gas=1000000000,  # 1 gwei
            )
            
            # Create state with persistent root
            state = QRDXState(self.state_db, exec_context, self.state_root)
            
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
            
            # Execute via QRDX computation (includes PQ precompiles)
            if is_create:
                computation = QRDXComputation.apply_create_message(
                    state,
                    message,
                    tx_context,
                )
            else:
                computation = QRDXComputation.apply_message(
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
            created_address = None
            if is_create and success:
                created_address = to
                # Store deployed code
                deployed_code = computation.output
                self.state_manager.set_code_sync(
                    to_checksum_address(to),
                    encode_hex(deployed_code)
                )

            # Increment the sender's nonce on ANY successful transaction, not just a
            # contract creation.
            #
            # ``apply_message`` / ``apply_create_message`` do not touch the sender
            # nonce (that is ``apply_transaction``'s job, which this executor does
            # not use), so before this a plain value transfer left the account nonce
            # at 0 forever. ``eth_getTransactionCount`` reads that nonce, so it
            # under-reported, and every web3 client broke on its SECOND transaction:
            # it would sign nonce 0 again and the mempool would reject it as
            # "nonce too low" against its own correctly-advanced pending counter.
            if success:
                sender_addr = to_checksum_address(sender)
                self.state_manager.set_nonce_sync(
                    sender_addr,
                    self.state_manager.get_nonce_sync(sender_addr) + 1,
                )

            
            # Charge tx-level gas ONLY.
            #
            # The value transfer is performed by the EVM itself inside
            # apply_message / apply_create_message, and ``_sync_from_evm`` above has
            # already written the VM's post-execution balances back — so the
            # sender's debit and the recipient's credit are recorded at that point.
            # Re-applying ``value`` here as well double-counted every native
            # transfer: the recipient received 2x and the sender paid 2x. (It also
            # meant a reverted call still moved funds, since the VM rolls its own
            # transfer back but this manual credit did not.)
            #
            # Gas is different and must stay: py-evm's apply_message does NOT do
            # tx-level gas accounting (that lives in apply_transaction, which this
            # executor does not use), so nothing else charges it.
            # Charge at least the transaction's intrinsic floor, never more than the
            # gas limit the sender authorised.
            gas_used = min(gas, max(gas_used, intrinsic_gas))
            gas_cost = gas_used * gas_price
            sender_addr_str = to_checksum_address(sender)
            sender_balance = self.state_manager.get_balance_sync(sender_addr_str)
            self.state_manager.set_balance_sync(
                sender_addr_str,
                sender_balance - gas_cost,
            )

            return EVMResult(
                success=success,
                gas_used=gas_used,
                output=output,
                logs=logs,
                error=error,
                created_address=created_address,
            )
            
        except Exception as e:
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
        block_number: int = 1,
        timestamp: int = 1,
    ) -> EVMResult:
        """
        Execute read-only call (eth_call), in the context of ``block_number``/``timestamp``
        (the caller passes the latest block's).
        
        State changes are not persisted.
        """
        # Take snapshot
        snapshot = self.state_manager.snapshot_sync()
        
        try:
            result = self.execute(
                sender=sender,
                to=to,
                value=value,
                block_number=block_number,
                timestamp=timestamp,
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
    
    def _sync_to_evm(self, state: QRDXState, sender: bytes, to: Optional[bytes]) -> None:
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
    
    def _sync_from_evm(self, state: QRDXState, sender: bytes, to: Optional[bytes]) -> None:
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
