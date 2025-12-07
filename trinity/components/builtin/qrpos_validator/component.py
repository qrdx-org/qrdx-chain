"""
QR-PoS Validator Component

Implements block production and attestation for QRDX's QR-PoS consensus.
"""

import asyncio
import time
from typing import Optional, List, cast, Tuple

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
        
        # Calculate current slot based on genesis time and current time
        current_slot = self.consensus.get_current_slot()
        self.current_slot = current_slot
        
        log_debug(f"Starting at slot: {self.current_slot} (calculated from genesis time {self.consensus.genesis_time})")
        
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
        # Recalculate current slot based on actual time (not just increment)
        # This ensures we stay synchronized with wall clock time
        self.current_slot = self.consensus.get_current_slot()
        
        # Debug log to file
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] TICK: slot={self.current_slot}, validator={self.validator_index}\n")
            f.write(f"[{time.time()}] TICK: About to call get_proposer_for_slot\n")
            f.write(f"[{time.time()}] TICK: self.consensus = {self.consensus}\n")
            f.write(f"[{time.time()}] TICK: self.current_slot = {self.current_slot}\n")
        
        # Get the proposer for this slot from consensus
        # This handles the full validator set properly for production
        # Determine if we are the proposer for this slot
        try:
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] TICK: Calling consensus.get_proposer_for_slot({self.current_slot})\n")
            proposer_index = self.consensus.get_proposer_for_slot(self.current_slot)
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] TICK: Got proposer_index={proposer_index}\n")
        except Exception as e:
            import traceback
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] TICK: Error getting proposer: {str(e)}\n")
                f.write(f"[{time.time()}] TICK: Error type: {type(e)}\n")
                f.write(f"[{time.time()}] TICK: Traceback:\n{traceback.format_exc()}\n")
            return
        
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
            
            # Get pending transactions
            transactions = await self._get_pending_transactions()
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Got {len(transactions)} transactions\n")
            
            # Get attestations from pool
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Getting attestations from pool...\n")
            attestations = await self._get_attestations_for_block()
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Got {len(attestations)} attestations\n")
            
            logger.info(
                f"Including {len(attestations)} attestations in block "
                f"#{parent_header.block_number + 1}"
            )
            
            # Build block header and execute transactions
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Building and executing block...\n")
            header, receipts, computations = await self._build_and_execute_block(
                parent_header,
                transactions
            )
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: Built block header #{header.block_number} with correct roots\n")
            
            # Sign block with Dilithium key
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: About to call _sign_block()...\n")
            signature = self._sign_block(header)
            with open('/tmp/validator_debug.log', 'a') as f:
                f.write(f"[{time.time()}] PROPOSE: _sign_block() returned, signature size={len(signature)}\n")
            
            # Import block locally (with attestations, transactions, and receipts)
            await self._import_block_locally(header, signature, attestations, transactions, receipts)
            
            # Broadcast to peers
            await self._broadcast_block(header, signature, transactions)
            
            logger.info(
                f"Validator {self.validator_index} successfully proposed block "
                f"#{header.block_number} (hash={encode_hex(header.hash[:8])}...) "
                f"for slot {self.current_slot} with {len(attestations)} attestations"
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
        """
        Get pending transactions from mempool.
        
        Returns empty list for now. Transaction pool integration is a separate phase.
        For production, this should query the transaction pool component via IPC.
        """
        return []  # Empty blocks until transaction pool integrated
    
    async def _get_attestations_for_block(self) -> List:
        """Get attestations from pool for inclusion in new block."""
        from eth.consensus.qrpos import Attestation
        
        try:
            # Get attestations directly from the consensus engine's attestation pool
            # No need to access chain.consensus - we have self.consensus
            attestations = self.consensus.attestation_pool.get_attestations_for_inclusion(
                current_slot=self.current_slot,
                max_attestations=128,
            )
            
            logger.debug(
                f"Retrieved {len(attestations)} attestations for block "
                f"(slot {self.current_slot})"
            )
            
            return attestations
        except Exception as e:
            logger.warning(f"Failed to get attestations for block: {e}")
            return []
    
    async def _build_and_execute_block(
        self,
        parent: BlockHeader,
        transactions: List[BaseTransactionAPI],
    ) -> Tuple[BlockHeader, tuple, tuple]:
        """
        Build block header and execute all transactions.
        
        This method:
        1. Creates a base header with QR-PoS metadata
        2. Executes all transactions using the VM
        3. Computes correct state/transaction/receipt roots
        4. Computes bloom filter and gas used
        5. Persists state to database
        
        Returns:
            Tuple of (complete_header, receipts, computations)
            The header has all correct merkle roots and is ready to sign.
        """
        from trinity._utils.connect import get_eth1_chain_with_remote_db
        from eth.rlp.receipts import Receipt
        from eth.abc import ComputationAPI, ReceiptAPI
        
        # Calculate block number
        block_number = parent.block_number + 1
        
        # Timestamp must be greater than parent for Byzantium validation
        # Even though QR-PoS doesn't use PoW difficulty, the header validation still checks this
        timestamp = max(int(time.time()), parent.timestamp + 1)
        
        # Encode QR-PoS data in extra_data
        # Format: [slot(8 bytes)][validator_index(8 bytes)][pubkey_prefix(16 bytes)]
        proposer_pubkey = self.validator_key.public_key().to_bytes()
        extra_data = (
            self.current_slot.to_bytes(8, 'big') +
            self.validator_index.to_bytes(8, 'big') +
            proposer_pubkey[:16]  # First 16 bytes of public key as identifier
        )
        
        # Create base header (will be updated with correct roots by VM)
        base_header = parent.copy(
            difficulty=0,  # QR-PoS has no PoW difficulty
            block_number=block_number,
            gas_limit=parent.gas_limit,
            timestamp=timestamp,
            coinbase=Address(proposer_pubkey[:20]),  # Use pubkey as coinbase
            parent_hash=parent.hash,
            uncles_hash=EMPTY_UNCLE_HASH,
            extra_data=extra_data,
            mix_hash=Hash32(b'\x00' * 32),  # Not used in QR-PoS
            nonce=b'\x00' * 8,  # Not used in QR-PoS
        )
        
        # Execute transactions using VM to compute correct roots
        with get_eth1_chain_with_remote_db(self.boot_info, self.event_bus) as chain:
            # Get VM for this header
            vm = chain.get_vm(base_header)
            
            # Execute all transactions - this computes state/tx/receipt roots correctly
            result_header, receipts, computations = vm.apply_all_transactions(
                transactions,
                base_header
            )
            
            # Persist state to database (CRITICAL for correct state root)
            vm.state.persist()
            
            # Update header with persisted state root
            final_header = result_header.copy(
                state_root=vm.state.state_root
            )
            
            logger.info(
                f"Executed {len(transactions)} transactions: "
                f"state_root={encode_hex(final_header.state_root[:8])}..., "
                f"gas_used={final_header.gas_used}"
            )
        
        return final_header, receipts, computations
    
    def _sign_block(self, header: BlockHeader) -> bytes:
        """Sign block header with Dilithium key."""
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] SIGN: Signing block #{header.block_number}...\n")
            f.write(f"[{time.time()}] SIGN: Validator pubkey: {self.validator_key.public_key().to_bytes().hex()[:64]}...\n")
        
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
    
    async def _import_block_locally(
        self,
        header: BlockHeader,
        signature: bytes,
        attestations: List,
        transactions: List[BaseTransactionAPI],
        receipts: tuple,
    ) -> None:
        """
        Import proposed block to local chain with attestations.
        
        Args:
            header: Block header with correct state/tx/receipt roots
            signature: Dilithium signature of the header
            attestations: List of Attestation objects for this block
            transactions: List of transactions included in block
            receipts: Tuple of receipts from transaction execution
        """
        from trinity._utils.connect import get_eth1_chain_with_remote_db
        
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] IMPORT: Importing block #{header.block_number}...\n")
        
        try:
            with get_eth1_chain_with_remote_db(self.boot_info, self.event_bus) as chain:
                # Create block from header and transactions
                vm = chain.get_vm()
                block_class = vm.get_block_class()
                block = block_class(header=header, transactions=transactions, uncles=[])
                
                # Import the block
                chain.import_block(block, perform_validation=False)
                
                # Store Dilithium signature
                chain.chaindb.persist_qrpos_signature(header.hash, signature)
                
                # Store attestations with the block
                chain.chaindb.persist_qrpos_attestations(header.hash, attestations)
                
                # Calculate and store block weight for fork choice
                if attestations:
                    epoch = self.current_slot // 32  # SLOTS_PER_EPOCH = 32
                    weight = self.consensus.calculate_block_weight(
                        header.hash,
                        attestations,
                        epoch
                    )
                    chain.chaindb.persist_qrpos_block_weight(header.hash, weight)
                    logger.debug(
                        f"Block #{header.block_number} weight: {weight} "
                        f"({len(attestations)} attestations)"
                    )
                
                # Process attestations for finality
                if attestations:
                    finality_gadget = self.consensus.finality_gadget
                    is_justified, is_finalized = finality_gadget.process_attestations(
                        self.current_slot,
                        header.hash,
                        attestations,
                        self.consensus.validator_set,
                    )
                    
                    # Update justified checkpoint
                    if is_justified:
                        chain.chaindb.persist_qrpos_justified_checkpoint(
                            finality_gadget.justified_slot,
                            finality_gadget.justified_hash
                        )
                        logger.info(
                            f"✓ Block #{header.block_number} JUSTIFIED "
                            f"(slot={finality_gadget.justified_slot}, "
                            f"hash={encode_hex(finality_gadget.justified_hash[:8])}...)"
                        )
                    
                    # Update finalized checkpoint
                    if is_finalized:
                        chain.chaindb.persist_qrpos_finalized_checkpoint(
                            finality_gadget.finalized_slot,
                            finality_gadget.finalized_hash
                        )
                        logger.info(
                            f"🔒 Block #{header.block_number} FINALIZED "
                            f"(slot={finality_gadget.finalized_slot}, "
                            f"hash={encode_hex(finality_gadget.finalized_hash[:8])}...)"
                        )
                
                logger.info(
                    f"Imported block #{header.block_number} locally "
                    f"(hash={encode_hex(header.hash[:8])}..., "
                    f"{len(transactions)} txs, {len(attestations)} attestations, "
                    f"gas_used={header.gas_used})"
                )
        except Exception as e:
            logger.error(f"Failed to import block locally: {e}", exc_info=True)
    
    async def _broadcast_block(
        self,
        header: BlockHeader,
        signature: bytes,
        transactions: List[BaseTransactionAPI],
    ) -> None:
        """
        Broadcast proposed block to peers via event bus.
        
        Args:
            header: Block header with correct state/tx/receipt roots
            signature: Dilithium signature of the header
            transactions: List of transactions included in block
        """
        with open('/tmp/validator_debug.log', 'a') as f:
            f.write(f"[{time.time()}] BROADCAST: Broadcasting block #{header.block_number} via event bus...\n")
            f.write(f"[{time.time()}] BROADCAST: Event type: {QRPoSNewBlockEvent.__name__}\n")
            f.write(f"[{time.time()}] BROADCAST: Header hash: {encode_hex(header.hash)}\n")
            f.write(f"[{time.time()}] BROADCAST: Validator index: {self.validator_index}\n")
            f.write(f"[{time.time()}] BROADCAST: Slot: {self.current_slot}\n")
            f.write(f"[{time.time()}] BROADCAST: Transactions: {len(transactions)}\n")
        
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
                f"(hash={encode_hex(header.hash[:8])}..., "
                f"sig_size={len(signature)} bytes, "
                f"{len(transactions)} txs, "
                f"gas_used={header.gas_used})"
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
            
            # Get current chain head
            from trinity._utils.connect import get_eth1_chain_with_remote_db
            from eth.consensus.qrpos import Attestation
            from eth.crypto import blake3_hash_bytes
            
            with get_eth1_chain_with_remote_db(self.boot_info, self.event_bus) as chain:
                head = chain.get_canonical_head()
                
                # Create attestation data
                import rlp
                attestation_data = rlp.encode([
                    self.current_slot,
                    head.hash,
                    self.validator_index,
                ])
                signing_message = blake3_hash_bytes(attestation_data)
                
                # Sign with Dilithium key
                signature = self.validator_key.sign(signing_message)
                
                # Create attestation object
                attestation = Attestation(
                    slot=self.current_slot,
                    block_hash=head.hash,
                    validator_index=self.validator_index,
                    signature=signature,
                )
                
                logger.info(
                    f"Validator {self.validator_index} created attestation for "
                    f"block #{head.block_number} (slot {self.current_slot})"
                )
                
                # Broadcast attestation to network via IPC
                from trinity.protocol.eth.events import QRPoSAttestationEvent
                
                logger.info(f"[ATTESTATION-BROADCAST] Broadcasting attestation for slot {self.current_slot}")
                self.event_bus.broadcast(
                    QRPoSAttestationEvent(
                        slot=self.current_slot,
                        block_hash=head.hash,
                        validator_index=self.validator_index,
                        signature=signature,
                    ),
                    FIRE_AND_FORGET_BROADCASTING,
                )
                
                logger.info(f"[ATTESTATION-BROADCAST] Broadcast complete for slot {self.current_slot}")
            
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
            
            # Load Dilithium keypair from disk
            # Keys are pre-generated and stored in /tmp/qrdx-validator-keys/
            log_debug("Loading keypair from disk...")
            from eth.crypto import DilithiumPrivateKey, DilithiumPublicKey
            import pickle
            
            log_debug(f"Loading keypair for validator {validator_index}...")
            key_file = f"/tmp/qrdx-validator-keys/validator-{validator_index}.key"
            with open(key_file, 'rb') as f:
                priv_bytes, pub_bytes = pickle.load(f)
            private_key = DilithiumPrivateKey(priv_bytes, pub_bytes)
            public_key = DilithiumPublicKey(pub_bytes)
            log_debug(f"Keypair loaded: private_key type={type(private_key)}, public_key type={type(public_key)}")
            
            logger.info(f"Generated deterministic Dilithium keypair for validator {validator_index}")
            
            # Get genesis time from genesis block timestamp
            log_debug("Getting genesis time from chain...")
            from trinity._utils.connect import get_eth1_chain_with_remote_db
            with get_eth1_chain_with_remote_db(self._boot_info, event_bus) as chain:
                genesis_header = chain.get_canonical_block_header_by_number(BlockNumber(0))
                genesis_time = genesis_header.timestamp
            log_debug(f"Genesis timestamp from header: {genesis_time}")
            logger.info(f"Genesis block timestamp: {genesis_time}")
            
            # Create genesis validator set
            # Number of validators determined by environment or configuration
            # For testnet: fewer validators for easier testing (3-5)
            # For production: 150 validators per whitepaper specification
            log_debug("Creating genesis validator set...")
            from eth.consensus.qrpos import Validator, ValidatorSet, ValidatorStatus, MIN_STAKE
            from eth_utils import to_canonical_address
            import hashlib
            import os
            
            # Read number of validators from environment variable or use testnet default
            # Production deployment should set QRDX_NUM_VALIDATORS=150
            NUM_VALIDATORS = int(os.environ.get('QRDX_NUM_VALIDATORS', '3'))
            
            if NUM_VALIDATORS < 1:
                raise ValueError(f"Invalid number of validators: {NUM_VALIDATORS}")
            
            logger.info(
                f"Initializing validator set with {NUM_VALIDATORS} validators "
                f"(set QRDX_NUM_VALIDATORS=150 for production)"
            )
            
            genesis_validators = []
            for i in range(NUM_VALIDATORS):
                # Load deterministic public keys matching what validators will use
                validator_address = to_canonical_address(f"0x{i:040x}")
                
                # Load same keypair from disk as validators will use
                import pickle
                key_file = f"/tmp/qrdx-validator-keys/validator-{i}.key"
                with open(key_file, 'rb') as f:
                    _, pub_bytes = pickle.load(f)
                validator_pubkey = DilithiumPublicKey(pub_bytes)
                
                validator = Validator(
                    index=i,
                    public_key=validator_pubkey.to_bytes(),  # Convert to bytes
                    address=validator_address,
                    stake=MIN_STAKE,
                    status=ValidatorStatus.ACTIVE,
                    activation_epoch=0,
                    exit_epoch=None,
                    slashed=False,
                )
                genesis_validators.append(validator)
            
            validator_set = ValidatorSet(genesis_validators=genesis_validators)
            log_debug(f"Created validator set with {len(validator_set.validators)} validators")
            
            # Initialize consensus
            log_debug("Creating QRPoSConsensus...")
            consensus = QRPoSConsensus(
                validator_set=validator_set,
                genesis_time=genesis_time
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
