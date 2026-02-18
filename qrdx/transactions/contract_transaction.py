"""
Contract Transaction Types

Ethereum-compatible contract creation and contract call transactions.
Supports both traditional (ECDSA) and post-quantum (Dilithium) signatures.
"""

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Optional, List, Dict, Any
from enum import IntEnum
import hashlib

from ..crypto.hashing import keccak256
from ..crypto.signing import verify_signature


class InvalidTransactionError(Exception):
    """Raised when transaction validation fails."""
    pass


def sha256d(data: bytes) -> bytes:
    """Double SHA256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class ContractTransactionType(IntEnum):
    """Transaction types for contracts (EIP-2718 compatible)."""
    LEGACY = 0  # Legacy contract transaction
    EIP2930 = 1  # Access list transaction
    EIP1559 = 2  # Dynamic fee transaction
    CONTRACT_CREATE = 3  # QRDX contract creation
    CONTRACT_CALL = 4  # QRDX contract call


@dataclass
class ContractTransaction:
    """
    Base contract transaction.
    
    Ethereum-compatible transaction format for contract deployment and execution.
    Supports both ECDSA and Dilithium signatures for quantum resistance.
    """
    
    # Core transaction fields
    nonce: int
    sender: str  # Address (QRDX or Ethereum format)
    value: Decimal  # Amount of QRDX to send (in QRDX, not wei)
    gas_limit: int
    gas_price: Decimal  # In QRDX per gas unit
    
    # Contract-specific fields
    data: bytes  # Contract bytecode or calldata
    to: Optional[str] = None  # None for contract creation, address for calls
    
    # Signature fields
    signature: bytes = b''
    public_key: bytes = b''
    signature_type: str = 'ecdsa'  # 'ecdsa' or 'dilithium'
    
    # EIP-2930 access list
    access_list: List[tuple[str, List[int]]] = field(default_factory=list)
    
    # EIP-1559 dynamic fees
    max_priority_fee_per_gas: Optional[Decimal] = None
    max_fee_per_gas: Optional[Decimal] = None
    
    # Transaction hash
    tx_hash: Optional[str] = None
    
    def __post_init__(self):
        """Validate and compute transaction hash."""
        if self.to is None and not self.data:
            raise InvalidTransactionError("Contract creation requires bytecode in data field")
        
        if self.value < 0:
            raise InvalidTransactionError("Value cannot be negative")
        
        if self.gas_limit <= 0:
            raise InvalidTransactionError("Gas limit must be positive")
        
        if not self.tx_hash:
            self.tx_hash = self.compute_hash()
    
    @property
    def is_contract_creation(self) -> bool:
        """Check if this is a contract creation transaction."""
        return self.to is None or self.to == ''
    
    @property
    def transaction_type(self) -> ContractTransactionType:
        """Determine transaction type based on fields."""
        if self.max_fee_per_gas is not None:
            return ContractTransactionType.EIP1559
        elif self.access_list:
            return ContractTransactionType.EIP2930
        elif self.is_contract_creation:
            return ContractTransactionType.CONTRACT_CREATE
        else:
            return ContractTransactionType.CONTRACT_CALL
    
    def compute_hash(self) -> str:
        """
        Compute transaction hash (Ethereum-compatible).
        
        Returns:
            Hex-encoded transaction hash
        """
        # Build transaction data for hashing
        data = (
            self.nonce.to_bytes(8, 'little') +
            self.sender.encode('utf-8') +
            (self.to.encode('utf-8') if self.to else b'') +
            str(self.value).encode('utf-8') +
            self.gas_limit.to_bytes(8, 'little') +
            str(self.gas_price).encode('utf-8') +
            self.data
        )
        
        # Add EIP-1559 fields if present
        if self.max_fee_per_gas is not None:
            data += str(self.max_fee_per_gas).encode('utf-8')
            data += str(self.max_priority_fee_per_gas or 0).encode('utf-8')
        
        # Add access list if present
        if self.access_list:
            for address, slots in self.access_list:
                data += address.encode('utf-8')
                for slot in slots:
                    data += slot.to_bytes(32, 'big')
        
        # Double SHA256 (Bitcoin/QRDX style) or single Keccak256 (Ethereum style)
        # Using SHA256d for consistency with QRDX
        return sha256d(data).hex()
    
    def sign(self, private_key: bytes, signature_type: str = 'ecdsa') -> None:
        """
        Sign the transaction.
        
        Args:
            private_key: Private key (ECDSA or Dilithium)
            signature_type: 'ecdsa' or 'dilithium'
        """
        from ..crypto.signing import sign_message
        
        self.signature_type = signature_type
        message = bytes.fromhex(self.compute_hash())
        
        self.signature, self.public_key = sign_message(message, private_key, signature_type)
        self.tx_hash = self.compute_hash()
    
    def verify_signature(self) -> bool:
        """
        Verify transaction signature.
        
        Returns:
            True if signature is valid
        """
        # First check system wallet constraints
        from .validation import validate_transaction
        is_valid, error = validate_transaction(self)
        if not is_valid:
            raise InvalidTransactionError(f"System wallet validation failed: {error}")
        
        if not self.signature or not self.public_key:
            return False
        
        message = bytes.fromhex(self.compute_hash())
        return verify_signature(message, self.signature, self.public_key, self.signature_type)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary (Ethereum RPC compatible).
        
        Returns:
            Transaction dictionary
        """
        result = {
            'hash': self.tx_hash,
            'nonce': hex(self.nonce),
            'from': self.sender,
            'to': self.to if self.to else None,
            'value': hex(int(self.value * 1_000_000)),  # Convert to smallest unit
            'gas': hex(self.gas_limit),
            'gasPrice': hex(int(self.gas_price * 1_000_000)),
            'input': '0x' + self.data.hex(),
            'type': hex(self.transaction_type),
        }
        
        # Add EIP-1559 fields if present
        if self.max_fee_per_gas is not None:
            result['maxFeePerGas'] = hex(int(self.max_fee_per_gas * 1_000_000))
            result['maxPriorityFeePerGas'] = hex(int((self.max_priority_fee_per_gas or 0) * 1_000_000))
        
        # Add access list if present
        if self.access_list:
            result['accessList'] = [
                {
                    'address': addr,
                    'storageKeys': [hex(slot) for slot in slots]
                }
                for addr, slots in self.access_list
            ]
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContractTransaction':
        """
        Create transaction from dictionary (Ethereum RPC compatible).
        
        Args:
            data: Transaction dictionary
            
        Returns:
            ContractTransaction instance
        """
        # Parse hex values
        nonce = int(data.get('nonce', '0x0'), 16)
        value = Decimal(int(data.get('value', '0x0'), 16)) / 1_000_000
        gas_limit = int(data.get('gas', '0x5208'), 16)  # 21000 default
        gas_price = Decimal(int(data.get('gasPrice', '0x0'), 16)) / 1_000_000
        
        # Parse data/input field
        input_data = data.get('input', data.get('data', '0x'))
        if input_data.startswith('0x'):
            input_data = input_data[2:]
        data_bytes = bytes.fromhex(input_data)
        
        # Parse EIP-1559 fields
        max_fee = None
        max_priority_fee = None
        if 'maxFeePerGas' in data:
            max_fee = Decimal(int(data['maxFeePerGas'], 16)) / 1_000_000
            max_priority_fee = Decimal(int(data.get('maxPriorityFeePerGas', '0x0'), 16)) / 1_000_000
        
        # Parse access list
        access_list = []
        if 'accessList' in data:
            for item in data['accessList']:
                address = item['address']
                slots = [int(slot, 16) for slot in item.get('storageKeys', [])]
                access_list.append((address, slots))
        
        return cls(
            nonce=nonce,
            sender=data['from'],
            to=data.get('to'),
            value=value,
            gas_limit=gas_limit,
            gas_price=gas_price,
            data=data_bytes,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=max_priority_fee,
            access_list=access_list,
        )
    
    def get_gas_cost(self) -> int:
        """
        Calculate intrinsic gas cost.
        
        Returns:
            Gas cost in units
        """
        # Base transaction cost
        if self.is_contract_creation:
            gas_cost = 53000  # Contract creation base
        else:
            gas_cost = 21000  # Transaction base
        
        # Add calldata cost
        for byte in self.data:
            if byte == 0:
                gas_cost += 4  # Zero byte
            else:
                gas_cost += 16  # Non-zero byte
        
        # Add access list cost (EIP-2930)
        if self.access_list:
            for address, slots in self.access_list:
                gas_cost += 2400  # Address cost
                gas_cost += len(slots) * 1900  # Storage slot cost
        
        return gas_cost
    
    def get_total_cost(self) -> Decimal:
        """
        Calculate total transaction cost (value + gas fees).
        
        Returns:
            Total cost in QRDX
        """
        gas_cost = self.get_gas_cost()
        gas_fee = Decimal(gas_cost) * self.gas_price
        return self.value + gas_fee


@dataclass
class ContractDeployment(ContractTransaction):
    """
    Contract deployment transaction.
    
    Specialized transaction for deploying smart contracts.
    """
    
    # Contract metadata
    contract_name: Optional[str] = None
    compiler_version: Optional[str] = None
    source_code: Optional[str] = None
    abi: Optional[List[Dict[str, Any]]] = None
    
    def __post_init__(self):
        """Validate contract deployment."""
        if self.to is not None and self.to != '':
            raise InvalidTransactionError("Contract deployment must have empty 'to' field")
        
        if not self.data:
            raise InvalidTransactionError("Contract deployment requires bytecode")
        
        super().__post_init__()
    
    def compute_contract_address(self) -> str:
        """
        Compute the address where contract will be deployed.
        
        Uses CREATE2 opcode logic: keccak256(0xff + sender + salt + keccak256(bytecode))
        Or CREATE opcode logic: keccak256(rlp([sender, nonce]))
        
        Returns:
            Contract address (hex string)
        """
        # Simple nonce-based address generation (Ethereum CREATE)
        from ..crypto.address import generate_contract_address
        
        return generate_contract_address(self.sender, self.nonce)


@dataclass
class ContractCall(ContractTransaction):
    """
    Contract call transaction.
    
    Transaction for calling existing smart contract functions.
    """
    
    # Function selector and arguments
    function_selector: Optional[bytes] = None
    function_args: Optional[bytes] = None
    
    def __post_init__(self):
        """Validate contract call."""
        if not self.to:
            raise InvalidTransactionError("Contract call must have target address")
        
        # Parse function selector from data if present
        if self.data and len(self.data) >= 4:
            self.function_selector = self.data[:4]
            self.function_args = self.data[4:]
        
        super().__post_init__()
    
    def get_function_signature(self) -> Optional[str]:
        """
        Get function signature hash (first 4 bytes of keccak256(function_sig)).
        
        Returns:
            Function selector as hex string
        """
        if self.function_selector:
            return '0x' + self.function_selector.hex()
        return None
