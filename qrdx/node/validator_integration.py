"""
QRDX Validator Node Integration

Provides toggleable validator functionality for QRDX nodes.

This module integrates the validator system with the node's lifecycle,
enabling nodes to participate in PoS consensus as validators when configured.

CRITICAL: Validators MUST use Post-Quantum (PQ) wallets with Dilithium3 signatures.

Usage:
    # In node startup:
    from qrdx.node.validator_integration import ValidatorNode
    
    validator = ValidatorNode(config)
    if validator.is_enabled:
        await validator.start()
"""

import asyncio
import os
from pathlib import Path
from typing import Optional, Dict, Any
from decimal import Decimal

from ..logger import get_logger
from ..wallet_v2 import PQWallet, WalletType
from ..validator import (
    ValidatorManager,
    ValidatorConfig,
    StakingConfig,
    SlashingProtectionConfig,
    ValidatorError,
    NotPQWalletError,
    InsufficientStakeError,
)
from ..consensus import is_pos_active
from ..constants import (
    MIN_VALIDATOR_STAKE,
    MAX_EFFECTIVE_STAKE,
    UNBONDING_PERIOD_EPOCHS,
    SLOT_DURATION,
    SLOTS_PER_EPOCH,
)

logger = get_logger(__name__)


class ValidatorNode:
    """
    Validator node integration for QR-PoS consensus.
    
    Provides a toggleable validator component that can be enabled/disabled
    at runtime. When enabled, the node participates in block proposal and
    attestation duties.
    
    CRITICAL: Requires a Post-Quantum (PQ) wallet for all operations.
    """
    
    def __init__(self, config: dict = None):
        """
        Initialize validator node.
        
        Args:
            config: Configuration dictionary from config.toml
        """
        self.config = config or {}
        self._manager: Optional[ValidatorManager] = None
        self._wallet: Optional[PQWallet] = None
        self._running = False
        self._slot_task: Optional[asyncio.Task] = None
        
        # Parse configuration
        self._parse_config()
    
    def _parse_config(self):
        """Parse validator configuration from config dict."""
        validator_config = self.config.get('validator', {})
        
        self.enabled = validator_config.get('enabled', False)
        self.wallet_path = validator_config.get('pq_wallet_path', './data/validator_wallet.json')
        self.wallet_password = (
            validator_config.get('pq_wallet_password') or
            os.environ.get('QRDX_VALIDATOR_PASSWORD', '')
        )
        self.graffiti = validator_config.get('graffiti', '')[:32]
        
        # Staking config
        staking = validator_config.get('staking', {})
        self.min_stake = Decimal(str(staking.get('min_stake', MIN_VALIDATOR_STAKE)))
        self.max_effective = Decimal(str(staking.get('max_effective_stake', MAX_EFFECTIVE_STAKE)))
        self.unbonding_epochs = staking.get('unbonding_epochs', UNBONDING_PERIOD_EPOCHS)
        
        # Attestation config
        attestation = validator_config.get('attestation', {})
        self.max_attestations = attestation.get('max_attestations_per_block', 128)
        self.max_inclusion_dist = attestation.get('max_inclusion_distance', 32)
        self.aggregation_delay = attestation.get('aggregation_delay', 1.0)
        
        # Slashing protection
        slashing = validator_config.get('slashing_protection', {})
        self.slashing_protection_enabled = slashing.get('enabled', True)
        self.slashing_protection_db = slashing.get('db_path', './data/slashing_protection.db')
        
        # Rewards config
        rewards = validator_config.get('rewards', {})
        self.fee_recipient = rewards.get('fee_recipient', '')
        self.auto_compound = rewards.get('auto_compound', False)
        self.compound_threshold = Decimal(str(rewards.get('compound_threshold', 100)))
    
    @property
    def is_enabled(self) -> bool:
        """Check if validator mode is enabled in config."""
        return self.enabled
    
    @property
    def is_running(self) -> bool:
        """Check if validator is currently running."""
        return self._running
    
    @property
    def address(self) -> Optional[str]:
        """Get validator's PQ address."""
        return self._wallet.address if self._wallet else None
    
    @property
    def manager(self) -> Optional[ValidatorManager]:
        """Get the validator manager instance."""
        return self._manager
    
    async def initialize(self) -> bool:
        """
        Initialize the validator (load wallet, create manager).
        
        Returns:
            True if initialization successful
        """
        if not self.enabled:
            logger.info("Validator mode is disabled")
            return False
        
        if not is_pos_active():
            logger.warning("PoS consensus not active, validator cannot start")
            return False
        
        try:
            # Load PQ wallet
            logger.info(f"Loading PQ wallet from: {self.wallet_path}")
            
            wallet_path = Path(self.wallet_path)
            if not wallet_path.exists():
                logger.error(f"PQ wallet file not found: {wallet_path}")
                logger.error("Create a PQ wallet first using: qrdx wallet create --type pq")
                return False
            
            self._wallet = PQWallet.load(wallet_path, self.wallet_password)
            
            # Verify wallet type
            if self._wallet.wallet_type != WalletType.POST_QUANTUM:
                logger.error("Validator wallets MUST be Post-Quantum (PQ) type!")
                logger.error("Create a PQ wallet using: qrdx wallet create --type pq")
                raise NotPQWalletError()
            
            logger.info(f"PQ wallet loaded: {self._wallet.address}")
            
            # Build validator config
            validator_config = ValidatorConfig(
                enabled=True,
                pq_wallet_path=str(wallet_path),
                pq_wallet_password=self.wallet_password,
                graffiti=self.graffiti,
                staking=StakingConfig(
                    min_validator_stake=self.min_stake,
                    max_effective_stake=self.max_effective,
                    unbonding_epochs=self.unbonding_epochs,
                ),
                slashing_protection=SlashingProtectionConfig(
                    enabled=self.slashing_protection_enabled,
                    db_path=self.slashing_protection_db,
                ),
            )
            
            # Create validator manager
            self._manager = ValidatorManager(
                wallet=self._wallet,
                config=validator_config,
            )
            
            # Initialize slashing protection
            if self.slashing_protection_enabled:
                from ..validator.slashing import SlashingProtectionDB
                self._manager.slashing_protection = SlashingProtectionDB(
                    self.slashing_protection_db
                )
                await self._manager.slashing_protection.initialize()
            
            logger.info("Validator initialized successfully")
            return True
            
        except NotPQWalletError:
            logger.error("CRITICAL: Validators must use PQ wallets only!")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize validator: {e}")
            return False
    
    async def start(self) -> bool:
        """
        Start validator operations.
        
        Begins participating in block proposal and attestation duties.
        
        Returns:
            True if started successfully
        """
        if self._running:
            logger.warning("Validator already running")
            return True
        
        if not self._manager:
            if not await self.initialize():
                return False
        
        try:
            # Check stake requirement
            from .. import Database
            database = Database.instance
            
            if database:
                async with database.pool.acquire() as conn:
                    validator = await conn.fetchrow(
                        "SELECT stake FROM validators WHERE address = $1",
                        self._wallet.address,
                    )
                    
                    if not validator:
                        logger.warning(
                            f"Validator not registered. "
                            f"Register first with minimum {self.min_stake} QRDX stake."
                        )
                        return False
                    
                    stake = Decimal(str(validator['stake']))
                    if stake < self.min_stake:
                        logger.error(
                            f"Insufficient stake: {stake} QRDX "
                            f"(minimum: {self.min_stake} QRDX)"
                        )
                        return False
            
            # Start the manager
            await self._manager.start()
            self._running = True
            
            # Start slot processing loop
            self._slot_task = asyncio.create_task(self._slot_loop())
            
            logger.info(
                f"Validator started: {self._wallet.address} "
                f"(graffiti: {self.graffiti or 'none'})"
            )
            
            return True
            
        except InsufficientStakeError as e:
            logger.error(f"Insufficient stake: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to start validator: {e}")
            return False
    
    async def stop(self):
        """Stop validator operations."""
        if not self._running:
            return
        
        logger.info("Stopping validator...")
        
        self._running = False
        
        if self._slot_task:
            self._slot_task.cancel()
            try:
                await self._slot_task
            except asyncio.CancelledError:
                pass
        
        if self._manager:
            await self._manager.stop()
        
        logger.info("Validator stopped")
    
    async def _slot_loop(self):
        """Main loop for processing slots."""
        from ..manager import get_pos_chain_head, create_pos_block, commit_pos_block
        from .. import Database
        
        while self._running:
            try:
                # Get current chain head
                head = await get_pos_chain_head()
                current_slot = head['slot']
                
                # Check if we should propose
                duties = await self._manager.get_duties()
                
                if current_slot + 1 in duties.get('proposal_slots', []):
                    logger.info(f"Proposing block for slot {current_slot + 1}")
                    await self._propose_block(current_slot + 1, head['block_hash'])
                
                # Check if we should attest
                if current_slot in duties.get('attestation_slots', []):
                    await self._create_attestation(current_slot, head['block_hash'])
                
                # Wait for next slot
                await asyncio.sleep(SLOT_DURATION)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in slot loop: {e}")
                await asyncio.sleep(1)
    
    async def _propose_block(self, slot: int, parent_hash: str):
        """Propose a block for the given slot."""
        from .. import Database
        from ..manager import create_pos_block, commit_pos_block
        from ..transactions import Transaction
        
        try:
            database = Database.instance
            
            # Get pending transactions
            pending_txs = await database.get_pending_transactions_limit(limit=500)
            transactions = []
            
            for tx_hex in pending_txs:
                try:
                    tx = await Transaction.from_hex(tx_hex, check_signatures=True)
                    if await tx.verify():
                        transactions.append(tx)
                except Exception:
                    continue
            
            # Create block
            block_data = await create_pos_block(
                slot=slot,
                parent_hash=parent_hash,
                transactions=transactions,
                proposer_address=self._wallet.address,
                proposer_public_key=self._wallet.public_key,
                sign_func=self._wallet.sign,
                graffiti=self.graffiti,
            )
            
            if not block_data:
                logger.warning(f"Failed to create block for slot {slot}")
                return
            
            # Commit block
            success = await commit_pos_block(block_data, transactions)
            
            if success:
                logger.info(
                    f"Block proposed: slot={slot}, hash={block_data['hash'][:16]}..."
                )
                
                # Propagate to peers
                await self._propagate_block(block_data)
            else:
                logger.error(f"Failed to commit block for slot {slot}")
                
        except Exception as e:
            logger.error(f"Error proposing block: {e}")
    
    async def _create_attestation(self, slot: int, block_hash: str):
        """Create and submit an attestation."""
        try:
            attestation = await self._manager.create_attestation(
                slot=slot,
                block_hash=block_hash,
            )
            
            if attestation:
                await self._manager.submit_attestation(attestation)
                logger.debug(f"Attestation submitted for slot {slot}")
                
                # Propagate to peers
                await self._propagate_attestation(attestation)
                
        except Exception as e:
            logger.error(f"Error creating attestation: {e}")
    
    async def _propagate_block(self, block_data: dict):
        """Propagate a proposed block to peers."""
        # This would be integrated with the node's P2P layer
        pass
    
    async def _propagate_attestation(self, attestation):
        """Propagate an attestation to peers."""
        # This would be integrated with the node's P2P layer
        pass
    
    async def get_status(self) -> Dict[str, Any]:
        """Get validator status information."""
        if not self._manager:
            return {
                'enabled': self.enabled,
                'running': False,
                'address': None,
                'message': 'Validator not initialized',
            }
        
        return await self._manager.get_status()
    
    async def register(self, initial_stake: Decimal = None) -> bool:
        """
        Register as a validator.
        
        Args:
            initial_stake: Initial stake amount (uses min if not specified)
            
        Returns:
            True if registration successful
        """
        if not self._manager:
            if not await self.initialize():
                return False
        
        return await self._manager.register_validator(initial_stake)
    
    async def request_exit(self) -> bool:
        """
        Request to exit the validator set.
        
        Returns:
            True if exit request successful
        """
        if not self._manager:
            logger.error("Validator not initialized")
            return False
        
        return await self._manager.request_exit()


# Global validator instance (set during node startup)
_validator_node: Optional[ValidatorNode] = None


def get_validator_node() -> Optional[ValidatorNode]:
    """Get the global validator node instance."""
    return _validator_node


def set_validator_node(node: ValidatorNode):
    """Set the global validator node instance."""
    global _validator_node
    _validator_node = node


async def initialize_validator(config: dict) -> Optional[ValidatorNode]:
    """
    Initialize the validator node from configuration.
    
    Args:
        config: Full node configuration dictionary
        
    Returns:
        ValidatorNode instance if enabled, None otherwise
    """
    validator = ValidatorNode(config)
    
    if validator.is_enabled:
        if await validator.initialize():
            set_validator_node(validator)
            return validator
        else:
            logger.error("Failed to initialize validator")
            return None
    else:
        logger.info("Validator mode disabled in configuration")
        return None
