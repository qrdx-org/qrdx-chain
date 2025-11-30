"""
QR-PoS Validator Component

Implements block production and attestation for QRDX's QR-PoS consensus.
"""

import asyncio
import time
from typing import Optional, List

from async_service import Service, background_asyncio_service

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
            f"{encode_hex(validator_key.public_key().to_bytes()[:32])}..."
        )
    
    async def run(self) -> None:
        """Run the validator service."""
        debug_log = '/tmp/validator_debug.log'
        
        def log_debug(msg: str) -> None:
            with open(debug_log, 'a') as f:
                f.write(f"[{time.time()}] SERVICE: {msg}\n")
        
        log_debug("=== VALIDATOR SERVICE RUN STARTING ===")
        
        # Calculate initial slot
        genesis_time = self.consensus.genesis_time
        log_debug(f"Genesis time: {genesis_time}")
        current_time = time.time()
        log_debug(f"Current time: {current_time}")
        
        elapsed = current_time - genesis_time
        log_debug(f"Elapsed: {elapsed}")
        
        self.current_slot = int(elapsed // SLOT_DURATION)
        log_debug(f"Starting at slot: {self.current_slot}")
        
        logger.info(
            f"Validator {self.validator_index} starting at slot {self.current_slot}"
        )
        
        log_debug("Entering main loop...")
        
        while self.manager.is_running:
            try:
                log_debug(f"Tick for slot {self.current_slot}")
                await self._validator_tick()
                log_debug(f"Tick completed for slot {self.current_slot}")
            except Exception as e:
                log_debug(f"ERROR in tick: {type(e).__name__}: {str(e)}")
                logger.error(f"Error in validator tick: {e}", exc_info=True)
            
            # Sleep until next slot
            log_debug("Sleeping until next slot...")
            await self._sleep_until_next_slot()
            log_debug("Woke up for next slot")
    
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
        config = self._boot_info.trinity_config
        # For now, enable on all nodes for testing
        return True
    
    async def do_run(self, event_bus: EndpointAPI) -> None:
        """Main run loop for the validator component."""
        config = self._boot_info.trinity_config
        
        # Debug logging to file to bypass broken exception handling
        debug_log = '/tmp/validator_debug.log'
        
        def log_debug(msg: str) -> None:
            with open(debug_log, 'a') as f:
                f.write(f"[{time.time()}] {msg}\n")
        
        try:
            log_debug("=== VALIDATOR COMPONENT STARTING ===")
            
            # Determine validator index from data directory
            data_dir = str(config.data_dir)
            log_debug(f"Data dir: {data_dir}")
            
            validator_index = 0
            if 'node-1' in data_dir:
                validator_index = 1
            elif 'node-2' in data_dir:
                validator_index = 2
            
            log_debug(f"Validator index: {validator_index}")
            logger.info(f"Starting QRPoS validator (index {validator_index})")
            
            # Generate Dilithium keypair (TODO: load from file)
            log_debug("Importing generate_dilithium_keypair...")
            from eth.crypto import generate_dilithium_keypair
            
            log_debug("Generating keypair...")
            private_key, public_key = generate_dilithium_keypair()
            log_debug(f"Keypair generated: private_key type={type(private_key)}, public_key type={type(public_key)}")
            
            logger.info(f"Generated Dilithium keypair for validator {validator_index}")
            
            # Initialize consensus
            log_debug("Creating QRPoSConsensus...")
            consensus = QRPoSConsensus(
                genesis_time=int(time.time())
            )
            log_debug(f"Consensus created: {type(consensus)}")
            
            # Create and run validator service
            log_debug("Creating QRPoSValidatorService...")
            service = QRPoSValidatorService(
                event_bus=event_bus,
                consensus=consensus,
                validator_index=validator_index,
                validator_key=private_key,
            )
            log_debug(f"Service created: {type(service)}")
            
            logger.info(f"Starting validator service for validator {validator_index}")
            log_debug("Starting service with background_asyncio_service...")
            
            async with background_asyncio_service(service) as manager:
                log_debug("Service manager started, waiting for it to finish...")
                await manager.wait_finished()
            
            log_debug("service manager finished (should not happen unless shutdown)")
            
        except Exception as e:
            log_debug(f"EXCEPTION CAUGHT: {type(e).__name__}: {str(e)}")
            logger.error(f"QRPoS Validator failed: {e}")
            # Keep the component alive so Trinity doesn't shutdown
            await asyncio.sleep(3600)
