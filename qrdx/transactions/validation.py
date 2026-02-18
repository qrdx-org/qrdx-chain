"""
Transaction Validation Hooks

Provides validation hooks for special transaction types including
system wallet transactions.
"""

from decimal import Decimal
from typing import Optional, Tuple, Any
from ..logger import get_logger

logger = get_logger(__name__)


class TransactionValidator:
    """
    Validates transactions with special rules.
    
    Handles:
    - System wallet transaction validation
    - Reserved address checks
    - Controller wallet authorization
    """
    
    def __init__(self, system_wallet_manager=None):
        """
        Initialize transaction validator.
        
        Args:
            system_wallet_manager: Optional SystemWalletManager instance
        """
        self._system_wallet_manager = system_wallet_manager
        self._enabled = system_wallet_manager is not None
    
    def set_system_wallet_manager(self, manager):
        """Set or update the system wallet manager."""
        self._system_wallet_manager = manager
        self._enabled = manager is not None
        logger.info("System wallet validation enabled")
    
    def validate_transaction(
        self,
        tx: Any,
    ) -> Tuple[bool, str]:
        """
        Validate a transaction.
        
        Args:
            tx: Transaction object (regular or contract transaction)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # If system wallet validation is disabled, allow everything
        if not self._enabled:
            return True, "OK"
        
        # Extract sender/from address
        from_address = self._extract_sender(tx)
        if not from_address:
            return True, "OK"  # No sender (e.g., coinbase), allow
        
        # Extract signer address (who signed the transaction)
        signer_address = self._extract_signer(tx)
        if not signer_address:
            # If we can't determine signer, fall back to from_address
            signer_address = from_address
        
        # Validate system wallet transaction
        return self._validate_system_wallet_transaction(from_address, signer_address)
    
    def _extract_sender(self, tx: Any) -> Optional[str]:
        """Extract sender address from transaction."""
        # Try different transaction types
        if hasattr(tx, 'sender'):
            return tx.sender
        if hasattr(tx, 'from_address'):
            return tx.from_address
        if hasattr(tx, 'address'):
            return tx.address
        
        # For regular transactions with inputs
        if hasattr(tx, 'inputs') and tx.inputs:
            # Get first input's address
            first_input = tx.inputs[0]
            if hasattr(first_input, 'address'):
                return first_input.address
            if hasattr(first_input, 'transaction_info'):
                tx_info = first_input.transaction_info
                if tx_info and 'outputs_addresses' in tx_info:
                    outputs = tx_info['outputs_addresses']
                    if outputs and first_input.index < len(outputs):
                        return outputs[first_input.index]
        
        return None
    
    def _extract_signer(self, tx: Any) -> Optional[str]:
        """Extract signer address from transaction signature."""
        # For contract transactions
        if hasattr(tx, 'public_key') and tx.public_key:
            try:
                from ..crypto.address import public_key_to_address, AddressType
                from ..crypto.keys import PublicKey
                from ..crypto.pq.dilithium import PQPublicKey
                
                # Determine signature type
                sig_type = getattr(tx, 'signature_type', 'ecdsa')
                
                if sig_type == 'dilithium':
                    # Post-quantum signature
                    pq_pubkey = PQPublicKey.from_bytes(tx.public_key)
                    return pq_pubkey.to_address()
                else:
                    # Traditional ECDSA signature
                    pubkey = PublicKey.from_bytes(tx.public_key)
                    return pubkey.to_address()
            except Exception as e:
                logger.debug(f"Could not extract signer from public key: {e}")
                return None
        
        # For regular transactions with inputs
        if hasattr(tx, 'inputs') and tx.inputs:
            # Check first input for public key
            first_input = tx.inputs[0]
            if hasattr(first_input, 'public_key') and first_input.public_key:
                try:
                    from ..crypto.address import public_key_to_address
                    return public_key_to_address(first_input.public_key)
                except Exception as e:
                    logger.debug(f"Could not extract signer from input: {e}")
        
        return None
    
    def _validate_system_wallet_transaction(
        self,
        from_address: str,
        signer_address: str,
    ) -> Tuple[bool, str]:
        """
        Validate transaction involving system wallet.
        
        Args:
            from_address: Address sending funds
            signer_address: Address that signed the transaction
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self._system_wallet_manager:
            return True, "OK"
        
        # Use system wallet manager's validation
        return self._system_wallet_manager.validate_system_transaction(
            from_address,
            signer_address,
        )
    
    def is_system_wallet(self, address: str) -> bool:
        """Check if address is a system wallet."""
        if not self._system_wallet_manager:
            return False
        return self._system_wallet_manager.is_system_wallet(address)
    
    def is_burner_wallet(self, address: str) -> bool:
        """Check if address is a burner wallet."""
        if not self._system_wallet_manager:
            return False
        return self._system_wallet_manager.is_burner_wallet(address)


# Global transaction validator instance
_global_validator: Optional[TransactionValidator] = None


def get_transaction_validator() -> TransactionValidator:
    """Get the global transaction validator instance."""
    global _global_validator
    if _global_validator is None:
        _global_validator = TransactionValidator()
    return _global_validator


def initialize_transaction_validator(system_wallet_manager):
    """Initialize the global transaction validator with system wallet manager."""
    global _global_validator
    validator = get_transaction_validator()
    validator.set_system_wallet_manager(system_wallet_manager)
    logger.info("Global transaction validator initialized")
    return validator


def validate_transaction(tx: Any) -> Tuple[bool, str]:
    """
    Validate a transaction using the global validator.
    
    Args:
        tx: Transaction to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    validator = get_transaction_validator()
    return validator.validate_transaction(tx)
