"""
EVM Executor using py-evm

Ethereum Virtual Machine execution engine for QRDX blockchain.
Uses py-evm library for full Ethereum compatibility.
"""

from typing import Optional, Dict, List, Tuple, Any
from decimal import Decimal
from dataclasses import dataclass
import sys
sys.path.insert(0, '/workspaces/qrdx-chain-denaro/py-evm')

from eth.vm.forks.qrdx import QRDXVM
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth_typing import Address
from eth_utils import to_canonical_address, to_checksum_address, keccak
from eth.vm.message import Message
from eth.vm.transaction_context import BaseTransactionContext
from eth.constants import CREATE_CONTRACT_ADDRESS

from .state import ContractStateManager


@dataclass
class ExecutionResult:
    """Result of contract execution."""
    success: bool
    gas_used: int
    gas_remaining: int
    output: bytes
    logs: List[Dict[str, Any]]
    error: Optional[str] = None
    contract_address: Optional[str] = None
    state_root: Optional[bytes] = None


class EVMExecutor:
    """
    Execute smart contracts using py-evm.
    
    Provides full Ethereum compatibility with:
    - All EVM opcodes and precompiles
    - Transaction execution
    - State management
    - Gas accounting
    """
    
    def __init__(self, state_manager: ContractStateManager, block_number: int = 0):
        """
        Initialize EVM executor.
        
        Args:
            state_manager: Contract state manager
            block_number: Current block number
        """
        self.state_manager = state_manager
        self.block_number = block_number
        
        # Initialize py-evm database
        self.db = AtomicDB()
        
        # Create VM instance
        self.vm = None
        self._init_vm()
    
    def _init_vm(self):
        """Initialize QRDX VM instance."""
        from eth.chains.base import Chain
        from eth.chains.mainnet import MAINNET_CHAIN_ID
        from eth.vm.forks.qrdx import QRDXVM
        from eth import constants
        from eth_typing import BlockNumber, Hash32
        
        # Create minimal chain context
        class QRDXChain(Chain):
            vm_configuration = (
                (BlockNumber(0), QRDXVM),
            )
            chain_id = 88888  # QRDX chain ID
        
        # Initialize chain with in-memory database
        self.chain = QRDXChain.configure(
            __name__='QRDXChain',
            vm_configuration=((BlockNumber(0), QRDXVM),)
        )(self.db, None)
    
    async def execute_transaction(
        self,
        sender: str,
        to: Optional[str],
        value: int,
        data: bytes,
        gas_limit: int,
        gas_price: int,
        nonce: int,
    ) -> ExecutionResult:
        """
        Execute a contract transaction.
        
        Args:
            sender: Sender address
            to: Recipient address (None for contract creation)
            value: Value to send (in smallest unit)
            data: Transaction data/bytecode
            gas_limit: Gas limit
            gas_price: Gas price per unit
            nonce: Sender nonce
            
        Returns:
            ExecutionResult with execution details
        """
        try:
            # Convert addresses
            sender_addr = to_canonical_address(sender)
            to_addr = to_canonical_address(to) if to else CREATE_CONTRACT_ADDRESS
            
            # Check sender balance
            sender_balance = await self.state_manager.get_balance(sender)
            total_cost = value + (gas_limit * gas_price)
            
            if sender_balance < total_cost:
                return ExecutionResult(
                    success=False,
                    gas_used=0,
                    gas_remaining=gas_limit,
                    output=b'',
                    logs=[],
                    error=f"Insufficient balance: {sender_balance} < {total_cost}"
                )
            
            # Create execution message
            is_create = (to is None or to == '' or to_addr == CREATE_CONTRACT_ADDRESS)
            
            if is_create:
                # Contract creation
                contract_address = self._compute_contract_address(sender, nonce)
                message = Message(
                    gas=gas_limit,
                    to=CREATE_CONTRACT_ADDRESS,
                    sender=sender_addr,
                    value=value,
                    data=b'',
                    code=data,  # Bytecode goes in code field for creation
                    create_address=to_canonical_address(contract_address),
                )
            else:
                # Contract call
                code = await self.state_manager.get_code(to)
                message = Message(
                    gas=gas_limit,
                    to=to_addr,
                    sender=sender_addr,
                    value=value,
                    data=data,
                    code=code,
                )
            
            # Create transaction context
            tx_context = BaseTransactionContext(
                gas_price=gas_price,
                origin=sender_addr,
            )
            
            # Get VM state
            vm = self.chain.get_vm()
            state = vm.state
            
            # Sync state from our state manager
            await self._sync_state_to_vm(state)
            
            # Execute computation
            if is_create:
                computation = state.computation_class.apply_create_message(
                    state,
                    message,
                    tx_context,
                )
            else:
                computation = state.computation_class.apply_message(
                    state,
                    message,
                    tx_context,
                )
            
            # Extract results
            success = not computation.is_error
            gas_used = gas_limit - computation.get_gas_remaining()
            
            # Extract logs
            logs = []
            for log_entry in computation.get_log_entries():
                logs.append({
                    'address': to_checksum_address(log_entry.address),
                    'topics': [topic.hex() for topic in log_entry.topics],
                    'data': log_entry.data.hex(),
                })
            
            # Sync state back from VM
            await self._sync_state_from_vm(state)
            
            # Deduct gas cost
            gas_cost = gas_used * gas_price
            new_balance = sender_balance - gas_cost - value
            await self.state_manager.set_balance(sender, new_balance)
            
            # If contract creation, store code
            if is_create and success:
                deployed_code = computation.output
                await self.state_manager.set_code(
                    contract_address,
                    deployed_code,
                    self.block_number,
                    sender
                )
                
                # Credit contract with sent value
                if value > 0:
                    await self.state_manager.set_balance(contract_address, value)
            
            # If contract call, update recipient balance
            elif to and value > 0:
                to_balance = await self.state_manager.get_balance(to)
                await self.state_manager.set_balance(to, to_balance + value)
            
            return ExecutionResult(
                success=success,
                gas_used=gas_used,
                gas_remaining=computation.get_gas_remaining(),
                output=bytes(computation.output),
                logs=logs,
                error=str(computation.error) if computation.is_error else None,
                contract_address=contract_address if is_create else None,
                state_root=state.state_root,
            )
            
        except Exception as e:
            return ExecutionResult(
                success=False,
                gas_used=gas_limit,  # Consume all gas on error
                gas_remaining=0,
                output=b'',
                logs=[],
                error=str(e),
            )
    
    async def call_contract(
        self,
        sender: str,
        to: str,
        data: bytes,
        value: int = 0,
        gas_limit: int = 10_000_000,
    ) -> ExecutionResult:
        """
        Call contract without state changes (eth_call).
        
        Args:
            sender: Caller address
            to: Contract address
            data: Call data
            value: Value to send
            gas_limit: Gas limit
            
        Returns:
            ExecutionResult
        """
        # Take snapshot
        snapshot_id = await self.state_manager.snapshot()
        
        try:
            # Execute call
            result = await self.execute_transaction(
                sender=sender,
                to=to,
                value=value,
                data=data,
                gas_limit=gas_limit,
                gas_price=0,  # No gas cost for eth_call
                nonce=0,
            )
            
            return result
        finally:
            # Always revert state changes
            await self.state_manager.revert(snapshot_id)
    
    async def estimate_gas(
        self,
        sender: str,
        to: Optional[str],
        data: bytes,
        value: int = 0,
    ) -> int:
        """
        Estimate gas for transaction.
        
        Args:
            sender: Sender address
            to: Recipient address
            data: Transaction data
            value: Value to send
            
        Returns:
            Estimated gas amount
        """
        # Binary search for gas limit
        low = 21000  # Minimum transaction gas
        high = 10_000_000  # Maximum reasonable gas
        
        snapshot_id = await self.state_manager.snapshot()
        
        try:
            while low < high:
                mid = (low + high) // 2
                
                result = await self.execute_transaction(
                    sender=sender,
                    to=to,
                    value=value,
                    data=data,
                    gas_limit=mid,
                    gas_price=0,
                    nonce=0,
                )
                
                if result.success:
                    high = mid
                else:
                    low = mid + 1
                
                # Revert for next iteration
                await self.state_manager.revert(snapshot_id)
                snapshot_id = await self.state_manager.snapshot()
            
            # Add 10% buffer
            return int(low * 1.1)
        finally:
            await self.state_manager.revert(snapshot_id)
    
    def _compute_contract_address(self, sender: str, nonce: int) -> str:
        """Compute contract address for CREATE."""
        from ..crypto.contract import generate_contract_address
        return generate_contract_address(sender, nonce)
    
    async def _sync_state_to_vm(self, vm_state) -> None:
        """Sync state manager to VM state."""
        # Sync account balances and nonces
        for address, account in self.state_manager._accounts_cache.items():
            canonical_addr = to_canonical_address(address)
            vm_state.set_balance(canonical_addr, account.balance)
            vm_state.set_nonce(canonical_addr, account.nonce)
            
            # Sync code if contract
            if account.code_hash:
                code = await self.state_manager.get_code(address)
                vm_state.set_code(canonical_addr, code)
        
        # Sync storage
        for (address, key), value in self.state_manager._storage_cache.items():
            canonical_addr = to_canonical_address(address)
            slot = int.from_bytes(key, 'big')
            value_int = int.from_bytes(value, 'big')
            vm_state.set_storage(canonical_addr, slot, value_int)
    
    async def _sync_state_from_vm(self, vm_state) -> None:
        """Sync VM state back to state manager.

        After EVM execution the VM state contains all storage writes,
        internal balance transfers, nonce increments, and self-destructs.
        We iterate every account that existed in our pre-execution cache
        *plus* any addresses observed in execution logs and write the
        final values back to the ``ContractStateManager``.
        """
        # Collect addresses that may have been modified
        touched: set = set()

        # 1. All accounts we synced TO the VM before execution
        for addr_str in list(self.state_manager._accounts_cache.keys()):
            touched.add(addr_str)

        # 2. All addresses referenced in storage cache
        for (addr_str, _key) in list(self.state_manager._storage_cache.keys()):
            touched.add(addr_str)

        # Sync each touched account
        for addr_str in touched:
            try:
                canonical = to_canonical_address(addr_str)

                # Balance – internal CALLs / SELFDESTRUCTs may have moved funds
                vm_balance = vm_state.get_balance(canonical)
                await self.state_manager.set_balance(addr_str, vm_balance)

                # Nonce
                vm_nonce = vm_state.get_nonce(canonical)
                await self.state_manager.set_nonce(addr_str, vm_nonce)

                # Code (may be set by CREATE / CREATE2)
                vm_code = vm_state.get_code(canonical)
                if vm_code:
                    existing_code = await self.state_manager.get_code(addr_str)
                    if existing_code != vm_code:
                        await self.state_manager.set_code(
                            addr_str, vm_code, self.block_number, addr_str,
                        )

                # Storage – replay cached slots through the VM's final state
                for (cached_addr, cached_key), _old_val in list(
                    self.state_manager._storage_cache.items()
                ):
                    if cached_addr != addr_str:
                        continue
                    slot = int.from_bytes(cached_key, 'big')
                    vm_val = vm_state.get_storage(canonical, slot)
                    new_val = vm_val.to_bytes(32, 'big')
                    await self.state_manager.set_storage(addr_str, cached_key, new_val)
            except Exception:
                # Account may not exist in VM state (e.g. self-destructed)
                continue
