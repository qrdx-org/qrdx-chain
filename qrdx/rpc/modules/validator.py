"""
QRDX Validator RPC Module

Provides RPC endpoints for validator operations in the QR-PoS consensus.

Endpoints:
- validator_getStatus: Get validator status and info
- validator_getStake: Get stake information
- validator_getDuties: Get proposal/attestation duties
- validator_register: Register as a validator
- validator_exit: Request validator exit
- validator_getAttestations: Get pending attestations
- validator_submitAttestation: Submit an attestation
- validator_getSlashings: Get slashing events

CRITICAL: All validator operations require a Post-Quantum (PQ) wallet.
"""

from decimal import Decimal
from typing import Any, Dict, List, Optional

from ...logger import get_logger
from ...validator import (
    ValidatorManager,
    ValidatorConfig,
    ValidatorStatus,
    ValidatorError,
    NotPQWalletError,
    InsufficientStakeError,
)
from ...consensus import is_pos_active, get_pos_rules

logger = get_logger(__name__)


class ValidatorModule:
    """
    Validator RPC methods for QR-PoS consensus.
    
    All methods require PoS to be active and a validator manager instance.
    """
    
    def __init__(self, validator_manager: Optional[ValidatorManager] = None):
        """
        Initialize the validator RPC module.
        
        Args:
            validator_manager: Optional validator manager (None if validation disabled)
        """
        self.manager = validator_manager
    
    def set_manager(self, manager: ValidatorManager):
        """Set the validator manager instance."""
        self.manager = manager
    
    # =========================================================================
    # STATUS AND INFO
    # =========================================================================
    
    async def validator_getStatus(self) -> Dict[str, Any]:
        """
        Get the status of the local validator.
        
        Returns:
            Dictionary with validator status information
        """
        if not self.manager:
            return {
                'enabled': False,
                'error': 'Validator mode not enabled on this node',
            }
        
        try:
            return await self.manager.get_status()
        except Exception as e:
            logger.error(f"validator_getStatus error: {e}")
            return {'error': str(e)}
    
    async def validator_getValidatorInfo(
        self,
        address: str,
    ) -> Dict[str, Any]:
        """
        Get information about a specific validator.
        
        Args:
            address: Validator's PQ address
            
        Returns:
            Validator information dictionary
        """
        from ... import Database
        
        database = Database.instance
        if not database:
            return {'error': 'Database not initialized'}
        
        try:
            async with database.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM validators WHERE address = $1",
                    address,
                )
                
                if not row:
                    return {'error': f'Validator not found: {address}'}
                
                return {
                    'address': row['address'],
                    'public_key': row['public_key'],
                    'stake': str(row['stake']),
                    'effective_stake': str(row['effective_stake']),
                    'status': row['status'],
                    'activation_epoch': row.get('activation_epoch'),
                    'exit_epoch': row.get('exit_epoch'),
                    'slashed': row.get('slashed', False),
                    'blocks_proposed': row.get('blocks_proposed', 0),
                    'blocks_missed': row.get('blocks_missed', 0),
                    'attestations_made': row.get('attestations_made', 0),
                    'total_rewards': str(row.get('total_rewards', 0)),
                }
        except Exception as e:
            logger.error(f"validator_getValidatorInfo error: {e}")
            return {'error': str(e)}
    
    async def validator_getValidatorSet(
        self,
        epoch: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Get the active validator set for an epoch.
        
        Args:
            epoch: Epoch number (current if not specified)
            
        Returns:
            Dictionary with validator set information
        """
        from ... import Database
        from ...constants import SLOTS_PER_EPOCH
        
        database = Database.instance
        if not database:
            return {'error': 'Database not initialized'}
        
        try:
            async with database.pool.acquire() as conn:
                # Get active validators
                rows = await conn.fetch("""
                    SELECT address, stake, effective_stake, status
                    FROM validators 
                    WHERE status = 'active'
                    ORDER BY effective_stake DESC
                """)
                
                validators = []
                total_stake = Decimal('0')
                
                for row in rows:
                    validators.append({
                        'address': row['address'],
                        'stake': str(row['stake']),
                        'effective_stake': str(row['effective_stake']),
                    })
                    total_stake += Decimal(str(row['effective_stake']))
                
                return {
                    'epoch': epoch,
                    'validator_count': len(validators),
                    'total_stake': str(total_stake),
                    'validators': validators,
                }
        except Exception as e:
            logger.error(f"validator_getValidatorSet error: {e}")
            return {'error': str(e)}
    
    # =========================================================================
    # STAKING
    # =========================================================================
    
    async def validator_getStake(
        self,
        address: str,
    ) -> Dict[str, Any]:
        """
        Get stake information for an address.
        
        Args:
            address: Validator's PQ address
            
        Returns:
            Stake information dictionary
        """
        from ... import Database
        
        database = Database.instance
        if not database:
            return {'error': 'Database not initialized'}
        
        try:
            async with database.pool.acquire() as conn:
                # Get validator stake
                validator = await conn.fetchrow(
                    "SELECT stake, effective_stake, status FROM validators WHERE address = $1",
                    address,
                )
                
                if not validator:
                    return {
                        'address': address,
                        'stake': '0',
                        'effective_stake': '0',
                        'status': 'not_registered',
                    }
                
                # Get pending withdrawals
                withdrawals = await conn.fetch("""
                    SELECT amount, withdrawable_at 
                    FROM stakes 
                    WHERE validator_address = $1 
                    AND withdrawal_requested_epoch IS NOT NULL
                    AND withdrawal_completed_epoch IS NULL
                """, address)
                
                pending_withdrawals = [
                    {
                        'amount': str(w['amount']),
                        'withdrawable_at': w['withdrawable_at'].isoformat() if w['withdrawable_at'] else None,
                    }
                    for w in withdrawals
                ]
                
                return {
                    'address': address,
                    'stake': str(validator['stake']),
                    'effective_stake': str(validator['effective_stake']),
                    'status': validator['status'],
                    'pending_withdrawals': pending_withdrawals,
                }
        except Exception as e:
            logger.error(f"validator_getStake error: {e}")
            return {'error': str(e)}
    
    async def validator_register(
        self,
        initial_stake: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Register as a validator (requires running validator node).
        
        Args:
            initial_stake: Initial stake amount (uses minimum if not specified)
            
        Returns:
            Registration result
        """
        if not self.manager:
            return {'error': 'Validator mode not enabled on this node'}
        
        try:
            stake = Decimal(initial_stake) if initial_stake else None
            success = await self.manager.register_validator(stake)
            
            return {
                'success': success,
                'address': self.manager.wallet.address,
                'stake': str(stake) if stake else 'minimum',
            }
        except NotPQWalletError:
            return {'error': 'Validators must use Post-Quantum (PQ) wallets only'}
        except InsufficientStakeError as e:
            return {'error': f'Insufficient stake: required {e.required}, have {e.actual}'}
        except Exception as e:
            logger.error(f"validator_register error: {e}")
            return {'error': str(e)}
    
    async def validator_requestExit(self) -> Dict[str, Any]:
        """
        Request to exit the validator set.
        
        Starts the unbonding process.
        
        Returns:
            Exit request result
        """
        if not self.manager:
            return {'error': 'Validator mode not enabled on this node'}
        
        try:
            success = await self.manager.request_exit()
            
            return {
                'success': success,
                'address': self.manager.wallet.address,
                'message': 'Exit requested. Stake will be withdrawable after unbonding period.',
            }
        except Exception as e:
            logger.error(f"validator_requestExit error: {e}")
            return {'error': str(e)}
    
    # =========================================================================
    # DUTIES
    # =========================================================================
    
    async def validator_getDuties(
        self,
        epoch: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Get validator duties for an epoch.
        
        Args:
            epoch: Epoch number (current if not specified)
            
        Returns:
            Dictionary with proposal and attestation duties
        """
        if not self.manager:
            return {'error': 'Validator mode not enabled on this node'}
        
        try:
            return await self.manager.get_duties(epoch)
        except Exception as e:
            logger.error(f"validator_getDuties error: {e}")
            return {'error': str(e)}
    
    async def validator_getProposerDuties(
        self,
        epoch: int,
    ) -> Dict[str, Any]:
        """
        Get block proposer duties for all validators in an epoch.
        
        Args:
            epoch: Epoch number
            
        Returns:
            List of (slot, proposer_address) tuples
        """
        from ... import Database
        
        database = Database.instance
        if not database:
            return {'error': 'Database not initialized'}
        
        try:
            async with database.pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT slot, validator_address, proposed, missed
                    FROM proposer_duties 
                    WHERE epoch = $1
                    ORDER BY slot
                """, epoch)
                
                duties = [
                    {
                        'slot': row['slot'],
                        'validator': row['validator_address'],
                        'proposed': row['proposed'],
                        'missed': row['missed'],
                    }
                    for row in rows
                ]
                
                return {
                    'epoch': epoch,
                    'duties': duties,
                }
        except Exception as e:
            logger.error(f"validator_getProposerDuties error: {e}")
            return {'error': str(e)}
    
    # =========================================================================
    # ATTESTATIONS
    # =========================================================================
    
    async def validator_getAttestations(
        self,
        slot: Optional[int] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Get attestations for a slot.
        
        Args:
            slot: Slot number (all pending if not specified)
            limit: Maximum number to return
            
        Returns:
            List of attestations
        """
        from ... import Database
        
        database = Database.instance
        if not database:
            return {'error': 'Database not initialized'}
        
        try:
            async with database.pool.acquire() as conn:
                if slot is not None:
                    rows = await conn.fetch("""
                        SELECT * FROM attestations 
                        WHERE slot = $1
                        ORDER BY validator_index
                        LIMIT $2
                    """, slot, limit)
                else:
                    # Get pending (not included) attestations
                    rows = await conn.fetch("""
                        SELECT * FROM attestations 
                        WHERE included_in_block IS NULL
                        ORDER BY slot DESC
                        LIMIT $1
                    """, limit)
                
                attestations = [
                    {
                        'slot': row['slot'],
                        'epoch': row['epoch'],
                        'block_hash': row['block_hash'],
                        'validator_address': row['validator_address'],
                        'validator_index': row['validator_index'],
                        'source_epoch': row['source_epoch'],
                        'target_epoch': row['target_epoch'],
                        'included': row['included_in_block'] is not None,
                    }
                    for row in rows
                ]
                
                return {
                    'slot': slot,
                    'count': len(attestations),
                    'attestations': attestations,
                }
        except Exception as e:
            logger.error(f"validator_getAttestations error: {e}")
            return {'error': str(e)}
    
    # =========================================================================
    # SLASHING
    # =========================================================================
    
    async def validator_getSlashings(
        self,
        epoch: Optional[int] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Get slashing events.
        
        Args:
            epoch: Filter by epoch (all if not specified)
            limit: Maximum number to return
            
        Returns:
            List of slashing events
        """
        from ... import Database
        
        database = Database.instance
        if not database:
            return {'error': 'Database not initialized'}
        
        try:
            async with database.pool.acquire() as conn:
                if epoch is not None:
                    rows = await conn.fetch("""
                        SELECT * FROM slashing_events 
                        WHERE epoch = $1
                        ORDER BY created_at DESC
                        LIMIT $2
                    """, epoch, limit)
                else:
                    rows = await conn.fetch("""
                        SELECT * FROM slashing_events 
                        ORDER BY created_at DESC
                        LIMIT $1
                    """, limit)
                
                events = [
                    {
                        'validator_address': row['validator_address'],
                        'condition': row['condition'],
                        'slot': row['slot'],
                        'epoch': row['epoch'],
                        'penalty_amount': str(row['penalty_amount']),
                        'penalty_percentage': str(row['penalty_percentage']),
                        'reporter_address': row.get('reporter_address'),
                        'executed': row['executed'],
                        'created_at': row['created_at'].isoformat(),
                    }
                    for row in rows
                ]
                
                return {
                    'epoch': epoch,
                    'count': len(events),
                    'events': events,
                }
        except Exception as e:
            logger.error(f"validator_getSlashings error: {e}")
            return {'error': str(e)}
    
    # =========================================================================
    # CONSENSUS INFO
    # =========================================================================
    
    async def validator_getChainHead(self) -> Dict[str, Any]:
        """
        Get the current chain head for PoS.
        
        Returns:
            Chain head information including slot, epoch, and finality
        """
        from ...manager import get_pos_chain_head
        
        try:
            return await get_pos_chain_head()
        except Exception as e:
            logger.error(f"validator_getChainHead error: {e}")
            return {'error': str(e)}
    
    async def validator_getEpochInfo(
        self,
        epoch: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Get epoch information.
        
        Args:
            epoch: Epoch number (current if not specified)
            
        Returns:
            Epoch information including finality status
        """
        from ... import Database
        
        database = Database.instance
        if not database:
            return {'error': 'Database not initialized'}
        
        try:
            async with database.pool.acquire() as conn:
                if epoch is not None:
                    row = await conn.fetchrow(
                        "SELECT * FROM epochs WHERE epoch = $1",
                        epoch,
                    )
                else:
                    row = await conn.fetchrow(
                        "SELECT * FROM epochs ORDER BY epoch DESC LIMIT 1"
                    )
                
                if not row:
                    return {'error': f'Epoch not found'}
                
                return {
                    'epoch': row['epoch'],
                    'start_slot': row['start_slot'],
                    'end_slot': row['end_slot'],
                    'active_validators': row['active_validators'],
                    'total_stake': str(row['total_stake']),
                    'justified': row['justified'],
                    'finalized': row['finalized'],
                    'finality_root': row.get('finality_root'),
                    'total_rewards': str(row['total_rewards']),
                    'total_penalties': str(row['total_penalties']),
                }
        except Exception as e:
            logger.error(f"validator_getEpochInfo error: {e}")
            return {'error': str(e)}
    
    async def validator_getConsensusParams(self) -> Dict[str, Any]:
        """
        Get PoS consensus parameters.
        
        Returns:
            Dictionary of consensus constants
        """
        from ...constants import (
            SLOT_DURATION,
            SLOTS_PER_EPOCH,
            MIN_VALIDATORS,
            MAX_VALIDATORS,
            MIN_VALIDATOR_STAKE,
            MAX_EFFECTIVE_STAKE,
            UNBONDING_PERIOD_EPOCHS,
            ATTESTATION_THRESHOLD,
            SLASHING_DOUBLE_SIGN,
            SLASHING_INVALID_ATTESTATION,
            SLASHING_DOWNTIME,
        )
        
        return {
            'consensus_type': 'proof_of_stake',
            'timing': {
                'slot_duration': SLOT_DURATION,
                'slots_per_epoch': SLOTS_PER_EPOCH,
                'epoch_duration': SLOT_DURATION * SLOTS_PER_EPOCH,
            },
            'validators': {
                'min_validators': MIN_VALIDATORS,
                'max_validators': MAX_VALIDATORS,
                'min_stake': str(MIN_VALIDATOR_STAKE),
                'max_effective_stake': str(MAX_EFFECTIVE_STAKE),
            },
            'staking': {
                'unbonding_epochs': UNBONDING_PERIOD_EPOCHS,
                'unbonding_days': (UNBONDING_PERIOD_EPOCHS * SLOT_DURATION * SLOTS_PER_EPOCH) / 86400,
            },
            'finality': {
                'attestation_threshold': str(ATTESTATION_THRESHOLD),
            },
            'slashing': {
                'double_sign_penalty': str(SLASHING_DOUBLE_SIGN),
                'invalid_attestation_penalty': str(SLASHING_INVALID_ATTESTATION),
                'downtime_penalty': str(SLASHING_DOWNTIME),
            },
        }


# Module instance for RPC server
validator_module = ValidatorModule()


def get_validator_methods() -> Dict[str, Any]:
    """
    Get all validator RPC methods.
    
    Returns:
        Dictionary mapping method names to functions
    """
    return {
        'validator_getStatus': validator_module.validator_getStatus,
        'validator_getValidatorInfo': validator_module.validator_getValidatorInfo,
        'validator_getValidatorSet': validator_module.validator_getValidatorSet,
        'validator_getStake': validator_module.validator_getStake,
        'validator_register': validator_module.validator_register,
        'validator_requestExit': validator_module.validator_requestExit,
        'validator_getDuties': validator_module.validator_getDuties,
        'validator_getProposerDuties': validator_module.validator_getProposerDuties,
        'validator_getAttestations': validator_module.validator_getAttestations,
        'validator_getSlashings': validator_module.validator_getSlashings,
        'validator_getChainHead': validator_module.validator_getChainHead,
        'validator_getEpochInfo': validator_module.validator_getEpochInfo,
        'validator_getConsensusParams': validator_module.validator_getConsensusParams,
    }
