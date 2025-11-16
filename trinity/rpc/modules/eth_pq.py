"""
Post-Quantum RPC API Extensions

This module extends the Eth RPC API with post-quantum specific methods:
- eth_sendPQTransaction: Send Type 4 pure PQ transaction
- eth_sendHybridTransaction: Send Type 5 hybrid transaction
- eth_generatePQAddress: Generate PQ address (testing/development only)
- eth_migrateAccount: Link classical address to PQ address
- eth_getAddressMapping: Query address registry for mappings
"""

from typing import Any, Dict, Optional

from eth_typing import Address, Hash32
from eth_utils import (
    decode_hex,
    encode_hex,
    to_canonical_address,
    ValidationError,
)
from lahja import EndpointAPI

from trinity.chains.base import AsyncChainAPI
from trinity.config import TrinityConfig
from trinity.rpc.format import format_params, to_int_if_hex
from trinity.rpc.modules import Eth1ChainRPCModule
from trinity.sync.common.events import SendLocalTransaction

# Import PQ transaction builders
try:
    from eth.vm.forks.qrdx.transactions import (
        QRDXTransactionBuilder,
        PURE_PQ_TRANSACTION_TYPE,
        HYBRID_TRANSACTION_TYPE,
    )
    from eth.vm.forks.qrdx.constants import (
        PQ_SIGNATURE_VERIFICATION_GAS,
        HYBRID_SIGNATURE_VERIFICATION_GAS,
    )
    PQ_AVAILABLE = True
except ImportError:
    PQ_AVAILABLE = False

# Import PQ crypto
try:
    from trinity.crypto.pq import (
        DilithiumPrivateKey,
        generate_pq_address,
    )
    from trinity.contracts.address_registry import (
        AddressRegistryInterface,
        ADDRESS_REGISTRY_ADDRESS,
    )
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def identity(value: Any) -> Any:
    """Identity function for format_params decorator"""
    return value


class EthPQ(Eth1ChainRPCModule):
    """
    Post-quantum extensions to the Eth RPC API
    
    All methods are prefixed with "eth_" to maintain compatibility
    with the Ethereum JSON-RPC specification.
    """
    
    def __init__(
        self,
        chain: AsyncChainAPI,
        event_bus: EndpointAPI,
        trinity_config: TrinityConfig
    ) -> None:
        self.trinity_config = trinity_config
        super().__init__(chain, event_bus)
        
        # Initialize address registry interface
        if CRYPTO_AVAILABLE:
            self.address_registry = AddressRegistryInterface(
                None,  # Will be set to VM when needed
                ADDRESS_REGISTRY_ADDRESS
            )
        else:
            self.address_registry = None
    
    @format_params(identity)
    async def sendPQTransaction(self, transaction: Dict[str, Any]) -> str:
        """
        Send a Type 4 pure post-quantum transaction
        
        Parameters:
        -----------
        transaction : dict
            {
                "from": "0x..." (optional, for nonce calculation),
                "to": "0x...",
                "value": "0x...",
                "data": "0x...",
                "gas": "0x...",
                "gasPrice": "0x...",
                "nonce": "0x...",
                "chainId": "0x...",
                "pqPubkey": "0x..." (hex-encoded 2592 bytes),
                "pqSignature": "0x..." (hex-encoded 4595 bytes)
            }
        
        Returns:
        --------
        str : Transaction hash (hex)
        
        Raises:
        -------
        ValidationError: If transaction parameters are invalid
        """
        if not PQ_AVAILABLE:
            raise ValidationError("PQ transactions not available in this build")
        
        # Validate required fields
        required_fields = ["to", "pqPubkey", "pqSignature"]
        for field in required_fields:
            if field not in transaction:
                raise ValidationError(f"Missing required field: {field}")
        
        # Parse transaction parameters
        chain_id = int(transaction.get("chainId", hex(self.chain.chain_id)), 16)
        
        # Get nonce from parameter or calculate from state
        if "nonce" in transaction:
            nonce = int(transaction["nonce"], 16)
        elif "from" in transaction:
            # Calculate nonce from state for the PQ address
            from_addr = decode_hex(transaction["from"])
            # For PQ addresses, we'd need to query the state
            # For now, require explicit nonce
            raise ValidationError("nonce is required for PQ transactions")
        else:
            raise ValidationError("Either 'nonce' or 'from' must be provided")
        
        gas_price = int(transaction.get("gasPrice", "0x3b9aca00"), 16)  # 1 gwei default
        gas = int(transaction.get("gas", hex(21000 + PQ_SIGNATURE_VERIFICATION_GAS)), 16)
        to = to_canonical_address(transaction["to"])
        value = int(transaction.get("value", "0x0"), 16)
        data = decode_hex(transaction.get("data", "0x"))
        pq_pubkey = decode_hex(transaction["pqPubkey"])
        pq_signature = decode_hex(transaction["pqSignature"])
        
        # Validate PQ parameters
        if len(pq_pubkey) != 2592:
            raise ValidationError(f"PQ pubkey must be 2592 bytes, got {len(pq_pubkey)}")
        if len(pq_signature) not in (4595, 4627):
            raise ValidationError(f"PQ signature must be 4595 or 4627 bytes, got {len(pq_signature)}")
        
        # Build Type 4 transaction
        typed_tx = QRDXTransactionBuilder.new_pure_pq_transaction(
            chain_id=chain_id,
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to,
            value=value,
            data=data,
            pq_pubkey=pq_pubkey,
            pq_signature=pq_signature,
        )
        
        # Validate signature
        try:
            typed_tx.validate()
        except Exception as e:
            raise ValidationError(f"Transaction validation failed: {e}")
        
        # Broadcast transaction to network via event bus
        from trinity.sync.common.events import SendLocalTransaction
        await self.event_bus.broadcast(SendLocalTransaction(typed_tx))
        
        return encode_hex(typed_tx.hash)
    
    @format_params(identity)
    async def sendHybridTransaction(self, transaction: Dict[str, Any]) -> str:
        """
        Send a Type 5 hybrid (ECDSA + PQ) transaction
        
        Parameters:
        -----------
        transaction : dict
            {
                "from": "0x...",
                "to": "0x...",
                "value": "0x...",
                "data": "0x...",
                "gas": "0x...",
                "gasPrice": "0x...",
                "nonce": "0x...",
                "chainId": "0x...",
                "pqPubkey": "0x..." (2592 bytes),
                "v": "0x...",
                "r": "0x...",
                "s": "0x...",
                "pqSignature": "0x..." (4595 bytes)
            }
        
        Returns:
        --------
        str : Transaction hash (hex)
        """
        if not PQ_AVAILABLE:
            raise ValidationError("PQ transactions not available in this build")
        
        # Validate required fields
        required_fields = ["from", "to", "pqPubkey", "v", "r", "s", "pqSignature"]
        for field in required_fields:
            if field not in transaction:
                raise ValidationError(f"Missing required field: {field}")
        
        # Parse transaction parameters
        chain_id = int(transaction.get("chainId", hex(self.chain.chain_id)), 16)
        nonce = int(transaction.get("nonce", "0x0"), 16)
        gas_price = int(transaction.get("gasPrice", "0x3b9aca00"), 16)
        gas = int(transaction.get("gas", hex(21000 + HYBRID_SIGNATURE_VERIFICATION_GAS)), 16)
        to = to_canonical_address(transaction["to"])
        value = int(transaction.get("value", "0x0"), 16)
        data = decode_hex(transaction.get("data", "0x"))
        pq_pubkey = decode_hex(transaction["pqPubkey"])
        
        # ECDSA signature components
        v = int(transaction["v"], 16)
        r = int(transaction["r"], 16)
        s = int(transaction["s"], 16)
        
        # PQ signature
        pq_signature = decode_hex(transaction["pqSignature"])
        
        # Build Type 5 transaction
        typed_tx = QRDXTransactionBuilder.new_hybrid_transaction(
            chain_id=chain_id,
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to,
            value=value,
            data=data,
            pq_pubkey=pq_pubkey,
            v=v,
            r=r,
            s=s,
            pq_signature=pq_signature,
        )
        
        # Validate both signatures
        try:
            typed_tx.validate()
        except Exception as e:
            raise ValidationError(f"Transaction validation failed: {e}")
        
        # Broadcast transaction to network via event bus
        from trinity.sync.common.events import SendLocalTransaction
        await self.event_bus.broadcast(SendLocalTransaction(typed_tx))
        
        return encode_hex(typed_tx.hash)
    
    async def generatePQAddress(self) -> Dict[str, str]:
        """
        Generate a new PQ address and keypair
        
        **WARNING:** This is for testing/development only!
        Never use this in production - it returns the private key in the response.
        
        Returns:
        --------
        dict : {
            "address": "qrdx1..." (bech32m-encoded),
            "addressHex": "0x..." (32-byte hex),
            "publicKey": "0x..." (2592-byte Dilithium pubkey),
            "privateKey": "0x..." (4896-byte Dilithium privkey) - INSECURE!
        }
        """
        if not CRYPTO_AVAILABLE:
            raise ValidationError("PQ crypto not available in this build")
        
        # Generate Dilithium keypair
        privkey = DilithiumPrivateKey.generate()
        pubkey = privkey.public_key()
        
        # Generate PQ address
        pq_address = generate_pq_address(pubkey)
        
        # Encode address in bech32m format
        from trinity.crypto.pq.addresses import encode_pq_address
        address_bech32 = encode_pq_address(pq_address)
        
        return {
            "address": address_bech32,
            "addressHex": encode_hex(pq_address),
            "publicKey": encode_hex(pubkey.to_bytes()),
            "privateKey": encode_hex(privkey.to_bytes()),  # INSECURE - testing only!
        }
    
    @format_params(identity)
    async def migrateAccount(self, params: Dict[str, str]) -> str:
        """
        Link a classical address to a PQ address via AddressRegistry
        
        Parameters:
        -----------
        params : dict
            {
                "classicalAddress": "0x..." (20 bytes),
                "pqAddress": "0x..." (32 bytes),
                "pqPubkey": "0x..." (2592 bytes),
                "pqSignature": "0x..." (4595 bytes, proving ownership)
            }
        
        Returns:
        --------
        str : Transaction hash of the registry call
        """
        if not CRYPTO_AVAILABLE:
            raise ValidationError("Address registry not available")
        
        # Validate parameters
        required = ["classicalAddress", "pqAddress", "pqPubkey", "pqSignature"]
        for field in required:
            if field not in params:
                raise ValidationError(f"Missing required field: {field}")
        
        classical_address = to_canonical_address(params["classicalAddress"])
        pq_address = decode_hex(params["pqAddress"])
        pq_pubkey = decode_hex(params["pqPubkey"])
        pq_signature = decode_hex(params["pqSignature"])
        
        # Validate sizes
        if len(pq_address) != 32:
            raise ValidationError(f"PQ address must be 32 bytes, got {len(pq_address)}")
        if len(pq_pubkey) != 2592:
            raise ValidationError(f"PQ pubkey must be 2592 bytes, got {len(pq_pubkey)}")
        if len(pq_signature) not in (4595, 4627):
            raise ValidationError(f"PQ signature must be 4595 or 4627 bytes")
        
        # Build transaction data for AddressRegistry.linkAddress()
        tx_data = self.address_registry.link_address(
            classical_address,
            pq_address,
            pq_pubkey,
            pq_signature,
        )
        
        # Build unsigned transaction to AddressRegistry contract
        # This returns the call data that needs to be included in a transaction
        # The transaction must be signed by the classical address owner
        
        # Return information about how to complete the migration
        # In a full implementation, this would create and broadcast a transaction
        # For now, provide the data needed for manual transaction creation
        return {
            "status": "pending",
            "message": "Migration requires transaction signing",
            "to": encode_hex(ADDRESS_REGISTRY_ADDRESS),
            "from": encode_hex(classical_address),
            "data": encode_hex(tx_data),
            "gas": "0x249F0",  # 150000 gas
            "note": "Send this transaction using your classical address private key"
        }
    
    @format_params(decode_hex)
    async def getAddressMapping(self, address: Address) -> Optional[Dict[str, str]]:
        """
        Query the AddressRegistry for address mappings
        
        Parameters:
        -----------
        address : Address
            Classical address (20 bytes) or PQ address (32 bytes as hex)
        
        Returns:
        --------
        dict or None : {
            "classicalAddress": "0x..." (20 bytes),
            "pqAddress": "0x..." (32 bytes),
            "migrationCompleted": bool
        }
        Returns None if no mapping exists.
        """
        if not CRYPTO_AVAILABLE:
            raise ValidationError("Address registry not available")
        
        # Get call data for contract queries
        # Note: These return call data, not results
        # In production, we'd need to execute static calls against chain state
        
        # For now, return a placeholder indicating the feature requires full VM integration
        # This would need to:
        # 1. Get current block/state
        # 2. Execute static call to AddressRegistry contract
        # 3. Decode ABI result
        # 4. Return formatted response
        
        if len(address) == 20:
            call_data = self.address_registry.get_linked_pq_address(address)
        elif len(address) == 32:
            call_data = self.address_registry.get_linked_classical_address(address)
        else:
            raise ValidationError(f"Address must be 20 or 32 bytes, got {len(address)}")
        
        # Return error indicating VM integration needed
        raise ValidationError(
            "getAddressMapping requires VM state access. "
            "This feature needs full Trinity chain integration. "
            f"Contract call data would be: {encode_hex(call_data)}"
        )
    
    async def getPQTransactionStats(self) -> Dict[str, Any]:
        """
        Get statistics about PQ transaction usage
        
        This would require scanning the blockchain for PQ transaction types.
        For now, returns structure showing what would be tracked.
        
        Returns:
        --------
        dict : {
            "totalPQTransactions": int,
            "totalHybridTransactions": int,
            "totalLinkedAddresses": int,
            "pqTransactionTypes": {
                "4": int,  # Pure PQ count
                "5": int   # Hybrid count
            }
        }
        """
        # This requires:
        # 1. Scan blockchain for Type 4 and Type 5 transactions
        # 2. Query AddressRegistry events for linked addresses
        # 3. Track statistics in database
        
        # For now, return structure indicating implementation needed
        return {
            "totalPQTransactions": 0,
            "totalHybridTransactions": 0,
            "totalLinkedAddresses": 0,
            "pqTransactionTypes": {
                "4": 0,  # Would count Type 4 transactions
                "5": 0,  # Would count Type 5 transactions
            },
            "note": "Statistics tracking requires blockchain scanning - not yet implemented"
        }

def identity(value: Any) -> Any:
    """Identity function for format_params decorator"""
    return value
