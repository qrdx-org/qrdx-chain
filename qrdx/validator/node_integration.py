"""
QRDX Validator Node Integration

This module integrates the PoS consensus validator into the node lifecycle.
It handles validator initialization, block production, attestation, and epoch processing.
"""
import asyncio
import json
import os
from typing import Optional
from datetime import datetime, timezone, timedelta

from ..logger import get_logger
from ..constants import SLOTS_PER_EPOCH, SLOT_DURATION
from .config import ValidatorConfig
from .manager import ValidatorManager
from .types import Validator, ValidatorSet, ValidatorStatus
from ..wallet_v2.pq_wallet import PQWallet
from ..crypto.pq.dilithium import PQPrivateKey as PrivateKey, PQPublicKey as PublicKey

logger = get_logger(__name__)

# Slot duration in seconds (from SLOT_DURATION constant which is in int format)
SLOT_DURATION_SECONDS = SLOT_DURATION if isinstance(SLOT_DURATION, int) else 12


class ValidatorNode:
    """
    Integrates PoS validator consensus into the node.
    
    Responsibilities:
    - Load and validate PQ wallet
    - Initialize ValidatorManager
    - Run block proposal duties
    - Run attestation duties
    - Process epoch boundaries
    - Handle slashing detection
    """
    
    def __init__(self, db, validator_wallet_path: str, password: str = "", broadcast_callback=None):
        """
        Initialize validator node.
        
        Args:
            db: Database instance
            validator_wallet_path: Path to PQ wallet JSON file
            password: Wallet password (optional for testnet)
            broadcast_callback: Async function to broadcast blocks to peers
        """
        self.db = db
        self.wallet_path = validator_wallet_path
        self.password = password
        self.broadcast_callback = broadcast_callback
        
        self.wallet: Optional[PQWallet] = None
        self.config: Optional[ValidatorConfig] = None
        self.manager: Optional[ValidatorManager] = None
        
        self._running = False
        self._block_production_task: Optional[asyncio.Task] = None
        self._attestation_task: Optional[asyncio.Task] = None
        self._epoch_processing_task: Optional[asyncio.Task] = None
        
        logger.info(f"ValidatorNode initialized for wallet: {validator_wallet_path}")
    
    async def initialize(self) -> bool:
        """
        Load wallet and initialize validator manager.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # Load wallet from JSON
            logger.info(f"Loading PQ wallet from {self.wallet_path}")
            with open(self.wallet_path, 'r') as f:
                wallet_data = json.load(f)
            
            # Extract keys and address
            address = wallet_data['address']
            private_key_hex = wallet_data['private_key']
            
            # Load PQ wallet from hex private key
            private_key = PrivateKey.from_hex(private_key_hex)
            self.wallet = PQWallet(private_key=private_key)
            logger.info(f"Wallet loaded: {address}")
            
            # Create validator configuration (use defaults)
            self.config = ValidatorConfig(enabled=True)
            
            # Initialize ValidatorManager with database
            logger.info("Initializing ValidatorManager...")
            self.manager = ValidatorManager(
                wallet=self.wallet,
                config=self.config,
                database=self.db  # Pass database for stake persistence
            )
            
            # Load existing stakes from database
            await self.manager.stake_manager.load_from_database()
            
            # Register initial stake (using deposit mechanism)
            from decimal import Decimal
            current_stake = await self.manager.stake_manager.get_stake(self.wallet.address)
            
            # Only deposit if we don't have enough stake
            min_stake = self.config.staking.min_validator_stake
            if current_stake < min_stake:
                stake_needed = min_stake  # Deposit full minimum if no stake exists
                logger.info(f"Depositing {stake_needed} QRDX stake (current: {current_stake})")
                await self.manager.stake_manager.deposit(
                    validator_address=self.wallet.address,
                    amount=stake_needed,
                    tx_hash=f"genesis_{self.wallet.address[:16]}",
                    block_number=0,
                    epoch=0
                )
            else:
                logger.info(f"Validator already has sufficient stake: {current_stake} QRDX")
            
            # Initialize validator state (for now, set to ACTIVE immediately)
            # In production, validators would go through activation queue
            actual_stake = await self.manager.stake_manager.get_stake(self.wallet.address)
            effective_stake = await self.manager.stake_manager.get_effective_stake(self.wallet.address)
            
            # Verify meets minimum stake before creating validator
            if effective_stake < min_stake:
                raise Exception(f"Insufficient stake: {effective_stake} < {min_stake} QRDX required")
            
            # Create and activate validator (bypass activation queue for testnet)
            self.manager._validator = Validator(
                address=self.wallet.address,
                public_key=self.wallet.public_key,
                stake=actual_stake,
                effective_stake=effective_stake,
                status=ValidatorStatus.ACTIVE,
                activation_epoch=0,
                slashed=False,
                uptime_score=1.0,
                index=0
            )
            
            # Create validator set with ALL active validators from database
            # This enables proper proposer selection across multiple validators
            all_validators = [self.manager._validator]
            
            # Load other validators from database
            try:
                cursor = await self.db.connection.execute(
                    "SELECT validator_address, stake FROM validator_stakes WHERE status = 'PENDING' OR status = 'ACTIVE'"
                )
                rows = await cursor.fetchall()
                
                logger.info(f"Found {len(rows)} validators in database")
                
                for row in rows:
                    other_address = row[0]
                    if other_address != self.wallet.address:
                        # Create validator object for other validators
                        from decimal import Decimal
                        other_stake = Decimal(str(row[1])) / Decimal("100000000")
                        other_validator = Validator(
                            address=other_address,
                            public_key=b'',  # Unknown for remote validators
                            stake=other_stake,
                            effective_stake=other_stake,
                            status=ValidatorStatus.ACTIVE,
                            activation_epoch=0,
                            slashed=False,
                            uptime_score=1.0,
                            index=len(all_validators)
                        )
                        all_validators.append(other_validator)
                        logger.info(f"Added validator to set: {other_address[:30]}... (stake: {other_stake} QRDX)")
            except Exception as e:
                logger.warning(f"Could not load other validators: {e}")
            
            # Calculate total stake
            total_stake = sum(v.stake for v in all_validators)
            
            self.manager._validator_set = ValidatorSet(
                epoch=0,
                validators=all_validators,
                total_stake=total_stake
            )
            
            logger.info(f"Validator set created with {len(all_validators)} validators (total stake: {total_stake} QRDX)")
            
            logger.info(f"Validator stake: {actual_stake} QRDX (effective: {effective_stake} QRDX)")
            
            logger.info(f"✅ Validator registered and activated: {self.wallet.address}")
            logger.info("✅ Validator initialization complete")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize validator: {e}", exc_info=True)
            return False
    
    async def start(self):
        """Start validator consensus duties."""
        if not self.manager:
            logger.error("Cannot start validator - not initialized")
            return
        
        self._running = True
        logger.info("🚀 Starting validator consensus duties...")
        
        # Start validator tasks
        self._block_production_task = asyncio.create_task(self._block_production_loop())
        self._attestation_task = asyncio.create_task(self._attestation_loop())
        self._epoch_processing_task = asyncio.create_task(self._epoch_processing_loop())
        
        logger.info("✅ Validator tasks started")
    
    async def stop(self):
        """Stop validator consensus duties."""
        self._running = False
        logger.info("Stopping validator consensus duties...")
        
        # Cancel tasks
        if self._block_production_task:
            self._block_production_task.cancel()
        if self._attestation_task:
            self._attestation_task.cancel()
        if self._epoch_processing_task:
            self._epoch_processing_task.cancel()
        
        logger.info("Validator stopped")
    
    async def _block_production_loop(self):
        """
        Main block production loop.
        Checks if this validator is the proposer for the current slot and produces blocks.
        """
        logger.info("Block production loop started")
        
        while self._running:
            try:
                # Get current slot and epoch
                current_slot = await self._get_current_slot()
                current_epoch = current_slot // SLOTS_PER_EPOCH
                
                logger.info(f"📍 Checking slot {current_slot} (epoch {current_epoch}) for block proposal...")
                
                # Get latest block from database for parent hash and next height
                next_block_id = await self.db.get_next_block_id()
                latest_block = await self.db.get_block_by_id(next_block_id - 1)
                parent_hash = latest_block.get('hash') or latest_block.get('block_hash') if latest_block else '0' * 64
                next_height = next_block_id  # Sequential: 0 (genesis), 1, 2, 3...
                
                # Get pending transactions
                pending_txs = await self.db.get_need_propagate_transactions() or []
                
                # Attempt to propose block (ValidatorManager checks if we're the proposer)
                block = await self.manager.propose_block(
                    slot=current_slot,
                    parent_hash=parent_hash,
                    transactions=pending_txs[:100],  # Limit to 100 txs per block
                    state_root=None  # Will compute if needed
                )
                
                if block:
                    logger.info(f"📦 Proposed block #{next_height} at slot {current_slot}: {block.hash[:16]}...")
                    
                    # Add block to database with sequential height
                    await self.db.add_block(
                        block_hash=block.hash,
                        block_height=next_height,
                        block_content=str(block.to_dict()),
                        validator_address=block.proposer_address,
                        timestamp=block.timestamp
                    )
                    
                    # Broadcast block to network peers
                    if self.broadcast_callback:
                        try:
                            block_data = {
                                'id': next_height,
                                'block_content': str(block.to_dict()),
                                'block_hash': block.hash,
                                'validator_address': block.proposer_address
                            }
                            await self.broadcast_callback('submit_block', block_data, ignore_node_id=None, db=self.db)
                            logger.info(f"📡 Broadcast block #{next_height} to peers")
                        except Exception as e:
                            logger.warning(f"Failed to broadcast block: {e}")
                    
                    logger.info(f"✅ Block {block.hash[:16]}... added to chain")
                
                # Wait for next slot
                await asyncio.sleep(SLOT_DURATION_SECONDS)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in block production loop: {e}", exc_info=True)
                await asyncio.sleep(SLOT_DURATION_SECONDS)
        
        logger.info("Block production loop stopped")
    
    async def _attestation_loop(self):
        """
        Main attestation loop.
        Creates and broadcasts attestations for proposed blocks.
        """
        logger.info("Attestation loop started")
        
        while self._running:
            try:
                current_slot = await self._get_current_slot()
                current_epoch = current_slot // SLOTS_PER_EPOCH
                
                # Wait briefly for block proposals to arrive
                await asyncio.sleep(SLOT_DURATION_SECONDS / 3)
                
                # Get latest block to attest to
                latest_block = await self.db.get_block_by_id(await self.db.get_next_block_id() - 1)
                if latest_block:
                    block_hash = latest_block.get('hash') or latest_block.get('block_hash')
                    
                    # Create attestation (ValidatorManager checks if we can attest)
                    attestation = await self.manager.create_attestation(
                        slot=current_slot,
                        block_hash=block_hash,
                        source_epoch=max(0, current_epoch - 1),
                        target_epoch=current_epoch
                    )
                    
                    if attestation:
                        # Submit to pool
                        submitted = await self.manager.submit_attestation(attestation)
                        if submitted:
                            logger.info(f"✅ Attested to block {block_hash[:16]}... at slot {current_slot}")
                            logger.debug(f"Attestation broadcast: epoch {current_epoch}, source {attestation.source_epoch}, target {attestation.target_epoch}")
                
                # Wait for rest of slot
                await asyncio.sleep(2 * SLOT_DURATION_SECONDS / 3)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in attestation loop: {e}", exc_info=True)
                await asyncio.sleep(SLOT_DURATION_SECONDS)
        
        logger.info("Attestation loop stopped")
    
    async def _epoch_processing_loop(self):
        """
        Epoch boundary processing loop.
        Handles rewards, penalties, validator rotation, finalization.
        """
        logger.info("Epoch processing loop started")
        
        while self._running:
            try:
                current_slot = await self._get_current_slot()
                current_epoch = current_slot // SLOTS_PER_EPOCH
                
                # Check if we're at epoch boundary
                if current_slot % SLOTS_PER_EPOCH == 0:
                    logger.info(f"🔄 Processing epoch {current_epoch} boundary")
                    
                    # Process epoch transition using ValidatorManager
                    try:
                        # TODO: Implement epoch processing (rewards, finality, validator rotation)
                        # await self.manager.process_epoch(current_epoch)
                        logger.info(f"✅ Epoch {current_epoch} boundary detected")
                    except Exception as e:
                        logger.error(f"Failed to process epoch {current_epoch}: {e}", exc_info=True)
                
                await asyncio.sleep(SLOT_DURATION_SECONDS)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in epoch processing loop: {e}", exc_info=True)
                await asyncio.sleep(SLOT_DURATION_SECONDS)
        
        logger.info("Epoch processing loop stopped")
    
    async def _get_current_slot(self) -> int:
        """
        Calculate current slot based on genesis time and slot duration.
        
        Returns:
            Current slot number
        """
        # Get genesis time from database or use a default
        now = datetime.now(timezone.utc)
        
        # Try to get genesis block timestamp
        try:
            genesis_block = await self.db.get_block_by_id(0)
            if genesis_block and 'timestamp' in genesis_block:
                genesis_time = datetime.fromtimestamp(genesis_block['timestamp'], tz=timezone.utc)
            else:
                # Fallback: genesis is NOW (start of chain)
                genesis_time = now
        except:
            # Fallback: genesis is NOW
            genesis_time = now
        
        elapsed = (now - genesis_time).total_seconds()
        current_slot = int(elapsed // SLOT_DURATION_SECONDS)
        # Ensure slot is at least 0
        return max(0, current_slot)


async def initialize_validator_node(db, wallet_path: str, password: str = "", broadcast_callback=None) -> Optional[ValidatorNode]:
    """
    Initialize and start a validator node.
    
    Args:
        db: Database instance
        wallet_path: Path to PQ wallet JSON
        password: Wallet password
        broadcast_callback: Async function to broadcast blocks to peers
    
    Returns:
        ValidatorNode instance if successful, None otherwise
    """
    validator = ValidatorNode(db, wallet_path, password, broadcast_callback)
    
    if await validator.initialize():
        await validator.start()
        return validator
    
    return None
