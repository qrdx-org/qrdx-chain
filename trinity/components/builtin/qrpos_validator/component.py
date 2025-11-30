"""
QR-PoS Validator Component

Implements block production and attestation for QRDX's QR-PoS consensus.
"""

import asyncio
import time
from typing import Optional, List, cast

from async_service import Service, background_asyncio_service

from lahja import EndpointAPI

from eth_typing import Hash32, BlockNumber
from eth_utils import encode_hex, to_canonical_address

# Import Address from eth_typing
try:
    from eth_typing import Address
except ImportError:
    # Fallback if Address not in eth_typing
    Address = bytes

from trinity.boot_info import BootInfo
from trinity.config import Eth1AppConfig
from trinity.constants import FIRE_AND_FORGET_BROADCASTING
from trinity.extensibility import AsyncioIsolatedComponent
from trinity._utils.logging import get_logger
from trinity.protocol.eth.events import QRPoSNewBlockEvent

from eth.consensus.qrpos import (
    QRPoSConsensus,
    SLOT_DURATION,
    VALIDATOR_COUNT,
)
from eth.crypto import DilithiumPrivateKey
from eth.rlp.headers import BlockHeader
from eth.rlp.blocks import BaseBlock
from eth.abc import BlockAPI, BaseTransactionAPI
from eth.constants import EMPTY_UNCLE_HASH, GENESIS_PARENT_HASH
from eth_typing import Hash32
import rlp


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
        boot_info: 'BootInfo',
    ) -> None:
        self.event_bus = event_bus
        self.consensus = consensus
        self.validator_index = validator_index
        self.validator_key = validator_key
        self.boot_info = boot_info
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
        
        # Debug log to file
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] TICK: slot={self.current_slot}, validator={self.validator_index}\n")
        
        # Check if it's our turn to propose
        proposer_index = self.current_slot % VALIDATOR_COUNT
        
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] TICK: proposer_index={proposer_index}, is_proposer={proposer_index == self.validator_index}\n")
        
        if proposer_index == self.validator_index:
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] TICK: *** WE ARE PROPOSER! Calling _propose_block() ***\n")
            
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
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Starting block proposal for slot {self.current_slot}\n")
            
            logger.info(f"Validator {self.validator_index} building block for slot {self.current_slot}")
            
            # Get current chain head
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Getting chain head...\n")
            parent_header = await self._get_chain_head()
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Got parent header #{parent_header.block_number}\n")
            
            # Get pending transactions (empty for now)
            transactions = await self._get_pending_transactions()
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Got {len(transactions)} transactions\n")
            
            # Build block header
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Building block header...\n")
            header = await self._build_block_header(parent_header, transactions)
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Built block header #{header.block_number}\n")
            
            # Sign block with Dilithium key
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: About to call _sign_block()...\n")
            signature = self._sign_block(header)
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: _sign_block() returned, signature size={len(signature)}\n")
            
            # For now, just work with header since we don't have transactions
            # TODO: Create proper block with transactions when mempool is integrated
            
            # Import block locally
            await self._import_block_locally(header, signature)
            
            # Broadcast to peers
            await self._broadcast_block(header, signature)
            
            logger.info(
                f"Validator {self.validator_index} successfully proposed block "
                f"#{header.block_number} (hash={encode_hex(header.hash[:8])}...) "
                f"for slot {self.current_slot}"
            )
            
        except Exception as e:
            with open('/tmp/validator_debug.log', 'a') as f:
                import traceback
                f.write(f"[{time.time()}] PROPOSE ERROR: {type(e).__name__}: {e}\n")
                f.write(f"[{time.time()}] PROPOSE TRACEBACK: {traceback.format_exc()}\n")
            
            logger.error(
                f"Validator {self.validator_index} failed to propose block: {e}",
                exc_info=True
            )
    
    async def _get_chain_head(self) -> BlockHeader:
        """Get current chain head header from the actual chain database."""
        # Import here to avoid circular imports
        from trinity._utils.connect import get_eth1_chain_with_remote_db
        
        # Get chain head from database
        with get_eth1_chain_with_remote_db(self.boot_info, self.event_bus) as chain:
            head = chain.get_canonical_head()
            return head
    
    async def _get_pending_transactions(self) -> List[BaseTransactionAPI]:
        """Get pending transactions from mempool."""
        # TODO: Query transaction pool via event bus
        return []  # No transactions for now
    
    async def _build_block_header(self, parent: BlockHeader, transactions: List[BaseTransactionAPI]) -> BlockHeader:
        """Build new block header for QR-PoS."""
        # Calculate block number
        block_number = parent.block_number + 1
        
        # Timestamp is current time
        timestamp = int(time.time())
        
        # Encode QR-PoS data in extra_data
        # Format: [slot(8 bytes)][validator_index(8 bytes)][pubkey_prefix(16 bytes)]
        proposer_pubkey = self.validator_key.public_key().to_bytes()
        extra_data = (
            self.current_slot.to_bytes(8, 'big') +
            self.validator_index.to_bytes(8, 'big') +
            proposer_pubkey[:16]  # First 16 bytes of public key as identifier
        )
        
        # Build header (simplified - no state execution yet)
        header = BlockHeader(
            difficulty=0,  # QR-PoS has no PoW difficulty
            block_number=block_number,
            gas_limit=parent.gas_limit,
            timestamp=timestamp,
            coinbase=Address(proposer_pubkey[:20]),  # Use pubkey as coinbase
            parent_hash=parent.hash,
            uncles_hash=EMPTY_UNCLE_HASH,
            state_root=parent.state_root,  # TODO: Compute after executing txs
            transaction_root=Hash32(b'\x00' * 32),  # TODO: Compute from transactions
            receipt_root=Hash32(b'\x00' * 32),  # TODO: Compute from receipts
            bloom=0,  # TODO: Compute from receipts
            gas_used=0,  # TODO: Sum from receipts
            extra_data=extra_data,
            mix_hash=Hash32(b'\x00' * 32),  # Not used in QR-PoS
            nonce=b'\x00' * 8,  # Not used in QR-PoS
        )
        
        return header
    
    def _sign_block(self, header: BlockHeader) -> bytes:
        """Sign block header with Dilithium key."""
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] SIGN: Signing block #{header.block_number}...\n")
        
        # Serialize header for signing
        header_bytes = rlp.encode(header)
        
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] SIGN: Serialized header to {len(header_bytes)} bytes\n")
        
        # Sign with Dilithium key (produces 3,309 byte signature)
        signature = self.validator_key.sign(header_bytes)
        
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] SIGN: Generated signature ({len(signature)} bytes)\n")
        
        logger.debug(
            f"Signed block #{header.block_number} with Dilithium "
            f"(signature size: {len(signature)} bytes)"
        )
        
        return signature
    
    async def _import_block_locally(self, header: BlockHeader, signature: bytes) -> None:
        """Import proposed block to local chain."""
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] IMPORT: Importing block #{header.block_number}...\n")
        # TODO: Validate and import block to chain database
        # For now, just log it
        logger.info(
            f"Importing block #{header.block_number} locally "
            f"(hash={encode_hex(header.hash[:8])}..., sig_size={len(signature)} bytes)"
        )
    
    async def _broadcast_block(self, header: BlockHeader, signature: bytes) -> None:
        """Broadcast proposed block to peers via event bus."""
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] BROADCAST: Broadcasting block #{header.block_number} via event bus...\n")
            f.write(f"[{time.time()}] BROADCAST: Event type: {QRPoSNewBlockEvent.__name__}\n")
            f.write(f"[{time.time()}] BROADCAST: Header hash: {encode_hex(header.hash)}\n")
            f.write(f"[{time.time()}] BROADCAST: Validator index: {self.validator_index}\n")
            f.write(f"[{time.time()}] BROADCAST: Slot: {self.current_slot}\n")
        
        try:
            # Create QR-PoS block event
            event = QRPoSNewBlockEvent(
                header_rlp=rlp.encode(header),  # Encode header as RLP bytes for IPC
                signature=signature,
                validator_index=self.validator_index,
                slot=self.current_slot,
            )
            
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] BROADCAST: Event created successfully\n")
                f.write(f"[{time.time()}] BROADCAST: Broadcasting with FIRE_AND_FORGET_BROADCASTING...\n")
            
            # Broadcast to all components (not just networking)
            await self.event_bus.broadcast(
                event,
                FIRE_AND_FORGET_BROADCASTING
            )
            
            logger.info(
                f"Broadcast block #{header.block_number} to peers "
                f"(hash={encode_hex(header.hash[:8])}..., sig_size={len(signature)} bytes)"
            )
            
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] BROADCAST: Event broadcast complete\n")
                
        except Exception as e:
            logger.error(f"Failed to broadcast block: {e}", exc_info=True)
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] BROADCAST ERROR: {e}\n")
    
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
                boot_info=self._boot_info,
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
