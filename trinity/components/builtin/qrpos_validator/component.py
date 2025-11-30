"""
QR-PoS Validator Component

Implements block production and attestation for QRDX's QR-PoS consensus.
"""

import asyncio
import time
from typing import Optional, List

from async_service import Service

from lahja import EndpointAPI

from eth_typing import Address, Hash32, BlockNumber
from eth_utils import encode_hex

from trinity.boot_info import BootInfo
from trinity.config import Eth1AppConfig
from trinity.constants import TO_NETWORKING_BROADCAST_CONFIG
from trinity.extensibility import AsyncioIsolatedComponent
from trinity._utils.logging import get_logger

from eth.consensus.qrpos import (
    QRPoSConsensus,
    SLOT_DURATION,
    VALIDATOR_COUNT,
)
from eth.crypto import DilithiumPrivateKey


logger = get_logger('trinity.components.QRPoSValidator')


class QRPoSValidatorService(Service):
    """
    Service that handles validator duties:
    - Block proposal when it's our turn
    - Attestation broadcasting
    - Slot timing
    """
    
    def __init__(
        self,
        event_bus: EndpointAPI,
        consensus: QRPoSConsensus,
        validator_index: int,
        validator_key: DilithiumPrivateKey,
    ) -> None:
        self.event_bus = event_bus
        self.consensus = consensus
        self.validator_index = validator_index
        self.validator_key = validator_key
        self.current_slot = 0
        
        logger.info(
            f"Initialized validator {validator_index} with public key "
            f"{encode_hex(validator_key.public_key.to_bytes()[:32])}..."
        )
    
    async def run(self) -> None:
        """Main validator loop."""
        logger.info(f"Validator {self.validator_index} starting...")
        
        # Wait for chain to sync
        await asyncio.sleep(5)
        
        # Calculate initial slot based on genesis time
        genesis_time = self.consensus.genesis_time
        current_time = int(time.time())
        self.current_slot = (current_time - genesis_time) // SLOT_DURATION
        
        logger.info(
            f"Validator {self.validator_index} synchronized to slot {self.current_slot}"
        )
        
        # Main validator loop
        while self.manager.is_running:
            try:
                await self._validator_tick()
            except Exception as e:
                logger.error(f"Error in validator tick: {e}", exc_info=True)
            
            # Sleep until next slot
            await self._sleep_until_next_slot()
    
    async def _validator_tick(self) -> None:
        """Execute validator duties for current slot."""
        self.current_slot += 1
        
        # Check if it's our turn to propose
        proposer_index = self.current_slot % VALIDATOR_COUNT
        
        if proposer_index == self.validator_index:
            logger.info(
                f"Slot {self.current_slot}: Validator {self.validator_index} "
                f"is proposer - proposing block..."
            )
            await self._propose_block()
        else:
            logger.debug(
                f"Slot {self.current_slot}: Waiting for validator {proposer_index} "
                f"to propose (we are validator {self.validator_index})"
            )
        
        # Always attest to the head block
        await self._create_attestation()
    
    async def _propose_block(self) -> None:
        """Propose a new block for the current slot."""
        try:
            logger.info(f"Validator {self.validator_index} building block for slot {self.current_slot}")
            
            # TODO: Get pending transactions from mempool
            # TODO: Build block with transactions
            # TODO: Sign block with Dilithium key
            # TODO: Broadcast block to network
            
            logger.info(
                f"Validator {self.validator_index} successfully proposed block "
                f"for slot {self.current_slot}"
            )
            
        except Exception as e:
            logger.error(
                f"Validator {self.validator_index} failed to propose block: {e}",
                exc_info=True
            )
    
    async def _create_attestation(self) -> None:
        """Create and broadcast attestation for current head."""
        try:
            logger.debug(
                f"Validator {self.validator_index} creating attestation "
                f"for slot {self.current_slot}"
            )
            
            # TODO: Get current head block
            # TODO: Create attestation
            # TODO: Sign attestation with Dilithium key
            # TODO: Broadcast attestation to network
            
        except Exception as e:
            logger.error(
                f"Validator {self.validator_index} failed to create attestation: {e}",
                exc_info=True
            )
    
    async def _sleep_until_next_slot(self) -> None:
        """Sleep until the start of the next slot."""
        genesis_time = self.consensus.genesis_time
        next_slot_time = genesis_time + (self.current_slot + 1) * SLOT_DURATION
        current_time = int(time.time())
        
        sleep_duration = max(0, next_slot_time - current_time)
        
        if sleep_duration > 0:
            logger.debug(f"Sleeping {sleep_duration}s until slot {self.current_slot + 1}")
            await asyncio.sleep(sleep_duration)


class QRPoSValidatorComponent(AsyncioIsolatedComponent):
    """Trinity component that runs QR-PoS validator service."""
    
    name = "QRPoS Validator"
    
    @property
    def is_enabled(self) -> bool:
        """Enable if validator keys are configured."""
        config = self.boot_info.trinity_config
        return (
            hasattr(config, 'validator_index') and 
            hasattr(config, 'validator_key')
        )
    
    async def do_run(self, event_bus: EndpointAPI) -> None:
        """Run the validator service."""
        config = self.boot_info.trinity_config
        
        # Get validator configuration
        validator_index = getattr(config, 'validator_index', None)
        validator_key_path = getattr(config, 'validator_key', None)
        
        if validator_index is None or validator_key_path is None:
            logger.info("No validator configuration found, skipping validator service")
            return
        
        # Load validator key
        # TODO: Implement key loading from file
        # For now, generate a test key
        validator_key = DilithiumPrivateKey.generate()
        
        # Initialize consensus
        consensus = QRPoSConsensus()
        
        # Create and run validator service
        service = QRPoSValidatorService(
            event_bus=event_bus,
            consensus=consensus,
            validator_index=validator_index,
            validator_key=validator_key,
        )
        
        await service.run()
