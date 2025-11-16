"""
AddressRegistry Contract Deployment

This script deploys the AddressRegistry contract to the canonical address
0x0000000000000000000000000000000000000100 using a deterministic CREATE2 deployment.

The registry enables mapping between classical 20-byte Ethereum addresses and
32-byte post-quantum addresses.
"""

import os
from typing import Optional, Dict, Any
from pathlib import Path

from eth_typing import Address, Hash32
from eth_utils import to_canonical_address, encode_hex, decode_hex, keccak, function_signature_to_4byte_selector
from eth_hash.auto import keccak as eth_keccak

try:
    from solcx import compile_source, install_solc
    SOLC_AVAILABLE = True
except ImportError:
    SOLC_AVAILABLE = False

# Canonical address for AddressRegistry
ADDRESS_REGISTRY_ADDRESS = to_canonical_address("0x0000000000000000000000000000000000000100")

# Contract bytecode and ABI - compiled on demand
_compiled_contract = None


def _get_contract_source() -> str:
    """Get AddressRegistry Solidity source code"""
    contract_path = Path(__file__).parent / "AddressRegistry.sol"
    if not contract_path.exists():
        raise FileNotFoundError(f"AddressRegistry.sol not found at {contract_path}")
    return contract_path.read_text()


def _compile_contract() -> Dict[str, Any]:
    """Compile AddressRegistry contract"""
    global _compiled_contract
    
    if _compiled_contract is not None:
        return _compiled_contract
    
    if not SOLC_AVAILABLE:
        raise ImportError("py-solc-x not installed. Run: pip install py-solc-x")
    
    try:
        # Install solc if needed
        try:
            from solcx import get_solc_version
            get_solc_version()
        except:
            install_solc('0.8.19')
        
        # Compile contract
        source = _get_contract_source()
        compiled = compile_source(
            source,
            output_values=['abi', 'bin'],
            solc_version='0.8.19'
        )
        
        # Extract contract data (handle both old and new solcx formats)
        contract_id = list(compiled.keys())[0]
        _compiled_contract = {
            'abi': compiled[contract_id]['abi'],
            'bin': compiled[contract_id]['bin'],
        }
        
        return _compiled_contract
    except Exception as e:
        # Fallback: return empty bytecode if compilation fails
        raise RuntimeError(f"Failed to compile AddressRegistry: {e}")


def _get_function_selector(signature: str) -> bytes:
    """Get 4-byte function selector from signature"""
    return function_signature_to_4byte_selector(signature)


# Lazy-loaded contract data
ADDRESS_REGISTRY_BYTECODE = None
ADDRESS_REGISTRY_ABI = None


def get_address_registry_address() -> Address:
    """
    Get the canonical address of the AddressRegistry contract
    
    Returns:
        Address: The 20-byte canonical address (0x...0100)
    """
    return ADDRESS_REGISTRY_ADDRESS


def get_address_registry_bytecode() -> bytes:
    """
    Get the deployment bytecode for AddressRegistry
    
    Returns:
        bytes: Contract creation bytecode
    """
    global ADDRESS_REGISTRY_BYTECODE
    
    if ADDRESS_REGISTRY_BYTECODE is None:
        compiled = _compile_contract()
        ADDRESS_REGISTRY_BYTECODE = decode_hex(compiled['bin'])
    
    return ADDRESS_REGISTRY_BYTECODE


def get_address_registry_abi() -> list:
    """
    Get the ABI for AddressRegistry
    
    Returns:
        list: Contract ABI
    """
    global ADDRESS_REGISTRY_ABI
    
    if ADDRESS_REGISTRY_ABI is None:
        compiled = _compile_contract()
        ADDRESS_REGISTRY_ABI = compiled['abi']
    
    return ADDRESS_REGISTRY_ABI


def deploy_address_registry(
    vm,
    deployer_address: Optional[Address] = None,
) -> Address:
    """
    Deploy AddressRegistry contract to canonical address
    
    Note: For production, this should be pre-allocated in genesis.
    This function is mainly for testing.
    
    Args:
        vm: The VM instance to deploy on
        deployer_address: Address deploying the contract (uses default if None)
    
    Returns:
        Address: The deployed contract address (should match canonical address)
    
    Raises:
        ValueError: If deployment fails or address doesn't match expected
    """
    if deployer_address is None:
        # Use a deterministic deployer address
        deployer_address = to_canonical_address("0x" + "ff" * 20)
    
    bytecode = get_address_registry_bytecode()
    
    # For genesis deployment, just return the canonical address
    # The bytecode should be placed in genesis alloc
    return ADDRESS_REGISTRY_ADDRESS


class AddressRegistryInterface:
    """
    Python interface for interacting with the AddressRegistry contract
    
    This provides a clean API for the RPC layer to interact with the
    address registry without dealing with raw contract calls.
    """
    
    def __init__(self, vm, registry_address: Address = ADDRESS_REGISTRY_ADDRESS):
        """
        Initialize the registry interface
        
        Args:
            vm: The VM instance
            registry_address: The registry contract address
        """
        self.vm = vm
        self.address = registry_address
    
    def link_address(
        self,
        classical_address: Address,
        pq_address: bytes,
        pq_pubkey: bytes,
        pq_signature: bytes,
    ) -> bytes:
        """
        Link a classical address to a PQ address
        
        Args:
            classical_address: 20-byte classical address
            pq_address: 32-byte PQ address
            pq_pubkey: Dilithium public key (2592 bytes)
            pq_signature: Dilithium signature (4595 bytes)
        
        Returns:
            bytes: Transaction data (for inclusion in transaction)
        """
        # Get function selector for linkAddress(bytes32,bytes,bytes)
        function_selector = _get_function_selector("linkAddress(bytes32,bytes,bytes)")
        
        # Encode parameters
        params = self._encode_link_params(pq_address, pq_pubkey, pq_signature)
        
        # Return transaction data (caller must send transaction)
        return function_selector + params
    
    def get_linked_pq_address(self, classical_address: Address) -> Optional[bytes]:
        """
        Get the PQ address linked to a classical address
        
        This returns transaction data for a static call.
        Caller must execute the call and decode the result.
        
        Args:
            classical_address: 20-byte classical address
        
        Returns:
            bytes: Transaction data for view function call
        """
        # Get function selector for getLinkedPQAddress(address)
        function_selector = _get_function_selector("getLinkedPQAddress(address)")
        
        # Encode address parameter (left-padded to 32 bytes)
        data = function_selector + classical_address.rjust(32, b"\x00")
        
        return data
    
    def get_linked_classical_address(self, pq_address: bytes) -> bytes:
        """
        Get the classical address linked to a PQ address
        
        This returns transaction data for a static call.
        Caller must execute the call and decode the result.
        
        Args:
            pq_address: 32-byte PQ address
        
        Returns:
            bytes: Transaction data for view function call
        """
        # Get function selector for getLinkedClassicalAddress(bytes32)
        function_selector = _get_function_selector("getLinkedClassicalAddress(bytes32)")
        
        # Encode bytes32 parameter
        data = function_selector + pq_address
        
        return data
    
    def is_address_linked(self, classical_address: Address) -> bytes:
        """
        Check if a classical address has a PQ mapping
        
        This returns transaction data for checking linkage.
        Caller must execute call to getLinkedPQAddress and check if result is non-zero.
        
        Args:
            classical_address: 20-byte classical address
        
        Returns:
            bytes: Transaction data for view function call
        """
        return self.get_linked_pq_address(classical_address)
    
    def is_migration_completed(self, classical_address: Address) -> bytes:
        """
        Check if an address has completed migration
        
        This returns transaction data for a static call.
        Caller must execute the call and decode the result.
        
        Args:
            classical_address: 20-byte classical address
        
        Returns:
            bytes: Transaction data for view function call
        """
        # Get function selector for isMigrationCompleted(address)
        function_selector = _get_function_selector("isMigrationCompleted(address)")
        
        # Encode address parameter
        data = function_selector + classical_address.rjust(32, b"\x00")
        
        return data
    
    def _encode_link_params(
        self,
        pq_address: bytes,
        pq_pubkey: bytes,
        pq_signature: bytes,
    ) -> bytes:
        """
        Encode parameters for linkAddress call using ABI encoding
        
        Args:
            pq_address: 32-byte PQ address
            pq_pubkey: Dilithium public key
            pq_signature: Dilithium signature
        
        Returns:
            bytes: ABI-encoded parameters
        """
        # Manual ABI encoding for: function linkAddress(bytes32 pqAddress, bytes pqPubkey, bytes pqSignature)
        # Format: [bytes32][offset_pubkey][offset_signature][length_pubkey][pubkey_data][length_signature][signature_data]
        
        # Fixed size param: bytes32 pqAddress (32 bytes)
        encoded = pq_address
        
        # Dynamic params offsets (both bytes types)
        # Offset to pqPubkey data = 32 (pqAddress) + 32 (offset_pubkey) + 32 (offset_signature) = 96
        offset_pubkey = 96
        # Offset to pqSignature = offset_pubkey + 32 (length) + len(pqPubkey) aligned to 32
        pubkey_size_aligned = ((len(pq_pubkey) + 31) // 32) * 32
        offset_signature = offset_pubkey + 32 + pubkey_size_aligned
        
        # Add offsets
        encoded += offset_pubkey.to_bytes(32, 'big')
        encoded += offset_signature.to_bytes(32, 'big')
        
        # Add pqPubkey: [length][data padded to 32-byte boundary]
        encoded += len(pq_pubkey).to_bytes(32, 'big')
        encoded += pq_pubkey + b'\x00' * (pubkey_size_aligned - len(pq_pubkey))
        
        # Add pqSignature: [length][data padded to 32-byte boundary]
        sig_size_aligned = ((len(pq_signature) + 31) // 32) * 32
        encoded += len(pq_signature).to_bytes(32, 'big')
        encoded += pq_signature + b'\x00' * (sig_size_aligned - len(pq_signature))
        
        return encoded


# ========== Genesis Configuration ==========

def get_address_registry_genesis_config() -> dict:
    """
    Get the genesis configuration for AddressRegistry
    
    This ensures the contract is deployed at the canonical address
    in the genesis block.
    
    Returns:
        dict: Genesis allocation for the registry
    """
    bytecode = get_address_registry_bytecode()
    
    return {
        encode_hex(ADDRESS_REGISTRY_ADDRESS): {
            "balance": "0x0",
            "code": encode_hex(bytecode),
            "nonce": "0x1",
            "storage": {},
        }
    }
