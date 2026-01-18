"""
Smart Contract Support for QRDX

Ethereum-compatible smart contract execution with dual VM support:
- py-evm: Full Ethereum Virtual Machine with all forks (100% compatible)
- QRDX VM: Modern, lightweight VM with quantum-resistant features
"""

from .state import ContractStateManager, Account
from .evm_executor_v2 import QRDXEVMExecutor  # New 100% compatible executor
from .vm_executor import QRDXVMExecutor

# Legacy alias for backward compatibility
EVMExecutor = QRDXEVMExecutor

__all__ = [
    'ContractStateManager',
    'Account',
    'QRDXEVMExecutor',  # Primary EVM executor
    'EVMExecutor',      # Legacy alias
    'QRDXVMExecutor',   # Alternative VM
]
