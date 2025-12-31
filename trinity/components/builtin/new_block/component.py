import collections
import math
import random
from typing import (
    DefaultDict,
    Iterable,
    List,
    Tuple,
    Set,
    Dict,
    Optional,
    Any,
)

from async_service import (
    Service,
    background_trio_service,
)
from eth.abc import (
    BlockAPI,
)
from eth.exceptions import HeaderNotFound
from eth_typing import BlockNumber, Hash32
from eth_utils import (
    ValidationError,
    humanize_hash,
    to_tuple,
)
from eth.consensus.qrpos_validator import validate_qrpos_block, validate_qrpos_block_basic
from eth.consensus.qrpos import QRPoSConsensus
from lahja import EndpointAPI
from pyformance import MetricsRegistry
import trio

# On-chain stake verification
from eth.consensus.balance_stake_verifier import (
    verify_validator_stakes_from_state,
    MIN_STAKE,
)
# Import shared validator loading function from validator component
from trinity.components.builtin.qrpos_validator.component import load_validators_with_balance_verification

from p2p.abc import SessionAPI
from trinity.boot_info import BootInfo
# Lazy import to avoid async_lru crash on Python 3.12
# from trinity.components.builtin.metrics.component import metrics_service_from_args
from trinity.components.builtin.metrics.service.noop import NOOP_METRICS_SERVICE
from trinity.constants import TO_NETWORKING_BROADCAST_CONFIG
from trinity.extensibility import TrioIsolatedComponent
from trinity.protocol.eth.events import NewBlockEvent, NewBlockHashesEvent, QRPoSNewBlockEvent
from trinity.protocol.eth.payloads import (
    BlockFields,
    NewBlockHash,
    NewBlockPayload,
)
from trinity.protocol.eth.peer import (
    ETHProxyPeerPool,
    ETHProxyPeer,
)
from trinity.sync.common.events import FetchBlockWitness, NewBlockImported
from trinity._utils.connect import get_eth1_chain_with_remote_db
from trinity._utils.logging import get_logger


class NewBlockComponent(TrioIsolatedComponent):
    """
    Propogate newly received and imported blocks to peers, according to devp2p rules.
    https://github.com/ethereum/devp2p/blob/master/caps/eth.md#block-propagation
    """
    name = "NewBlockComponent"

    @property
    def is_enabled(self) -> bool:
        return True

    async def do_run(self, event_bus: EndpointAPI) -> None:
        self.logger.info("[NEWBLOCK-DEBUG] do_run() called, starting component initialization")
        try:
            if getattr(self._boot_info.args, 'enable_metrics', False):
                # Lazy import to avoid async_lru crash
                from trinity.components.builtin.metrics.component import metrics_service_from_args
                metrics_service = metrics_service_from_args(self._boot_info.args)
            else:
                metrics_service = NOOP_METRICS_SERVICE
            
            self.logger.info("[NEWBLOCK-DEBUG] Creating ETHProxyPeerPool")
            proxy_peer_pool = ETHProxyPeerPool(event_bus, TO_NETWORKING_BROADCAST_CONFIG)
            
            self.logger.info("[NEWBLOCK-DEBUG] Starting background services")
            async with background_trio_service(proxy_peer_pool):
                async with background_trio_service(metrics_service):
                    self.logger.info("[NEWBLOCK-DEBUG] Creating NewBlockService")
                    service = NewBlockService(
                        event_bus, proxy_peer_pool, metrics_service.registry, self._boot_info)
                    self.logger.info("[NEWBLOCK-DEBUG] Starting NewBlockService")
                    async with background_trio_service(service) as manager:
                        self.logger.info("[NEWBLOCK-DEBUG] NewBlockService running, waiting for finish")
                        await manager.wait_finished()
        except Exception as e:
            self.logger.error(f"[NEWBLOCK-DEBUG] Fatal error in do_run: {e}", exc_info=True)
            raise


class NewBlockService(Service):

    logger = get_logger('trinity.components.new_block.NewBlockService')

    def __init__(self,
                 event_bus: EndpointAPI,
                 peer_pool: ETHProxyPeerPool,
                 metrics_registry: MetricsRegistry,
                 boot_info: BootInfo) -> None:
        self._event_bus = event_bus
        self._peer_pool = peer_pool
        self._metrics_registry = metrics_registry
        # TODO: old blocks need to be pruned to avoid unbounded growth of tracker
        self._peer_block_tracker: DefaultDict[bytes, List[str]] = collections.defaultdict(list)
        self._boot_info = boot_info
        self._consensus = None  # Will be initialized in run()
        # Buffer for blocks waiting for their parent
        self._pending_blocks: Dict[bytes, List[Tuple[Any, int]]] = {}  # parent_hash -> [(event, retry_count), ...]
        self._requested_blocks: Set[bytes] = set()  # Track requested block hashes

    async def run(self) -> None:
        self.logger.info("NewBlockService starting up - initializing consensus...")
        
        # Initialize QRPoSConsensus for validating incoming attestations
        self._consensus = await self._initialize_consensus()
        if self._consensus:
            self.logger.info("QRPoSConsensus initialized successfully")
        else:
            self.logger.warning("Failed to initialize QRPoSConsensus, attestation validation disabled")
        
        self.logger.info("Registering event handlers...")
        self.manager.run_daemon_task(self._handle_imported_blocks)
        self.manager.run_daemon_task(self._handle_new_block_hashes)
        self.manager.run_daemon_task(self._handle_qrpos_new_blocks)
        self.manager.run_daemon_task(self._handle_qrpos_attestations)
        self.manager.run_daemon_task(self._handle_incoming_attestations)
        self.manager.run_daemon_task(self._handle_incoming_qrpos_blocks)
        self.logger.info("QR-PoS block and attestation handlers registered, waiting for events...")

        async for event in self._event_bus.stream(NewBlockEvent):
            self.manager.run_task(self._handle_new_block, event.session, event.command.payload)

    async def _initialize_consensus(self) -> QRPoSConsensus:
        """
        Initialize QRPoSConsensus for validating incoming attestations.
        Uses hybrid on-chain/genesis validator loading for production-ready verification.
        
        Returns None if initialization fails (non-critical, just disables attestation validation).
        Will retry a few times since keystores may not exist yet on startup.
        """
        for attempt in range(5):
            try:
                import os
                import json
                from pathlib import Path
                from eth.consensus.qrpos import ValidatorSet
                
                # Determine genesis file location
                data_dir = Path(self._boot_info.trinity_config.data_dir)
                genesis_file = data_dir / "genesis.json"
                
                if not genesis_file.exists():
                    genesis_file = Path(os.environ.get('GENESIS_FILE', '/tmp/qrdx-multi-node-genesis.json'))
                
                if not genesis_file.exists():
                    if attempt < 4:
                        self.logger.debug(f"Genesis file not found yet (attempt {attempt + 1}/5), waiting...")
                        await trio.sleep(2)
                        continue
                    else:
                        self.logger.warning(f"No genesis file found after 5 attempts, cannot initialize consensus")
                        return None
                
                # Load genesis timestamp
                with open(genesis_file, 'r') as f:
                    genesis_config = json.load(f)
                
                genesis_timestamp_hex = genesis_config.get('genesis', {}).get('timestamp', '0x0')
                genesis_time = int(genesis_timestamp_hex, 16)
                self.logger.debug(f"Loaded genesis time from {genesis_file}: {genesis_time}")
                
                # Get state for balance verification
                use_balance_verification = os.environ.get('USE_ONCHAIN_VALIDATORS', 'true').lower() == 'true'
                
                # Get genesis state for balance checking
                from trinity._utils.connect import get_eth1_chain_with_remote_db
                with get_eth1_chain_with_remote_db(self._boot_info, self._event_bus) as chain:
                    genesis_header = chain.get_canonical_block_header_by_number(0)
                    genesis_vm = chain.get_vm(genesis_header)
                    genesis_state = genesis_vm.state
                
                # Get keystore directory
                keystore_dir = os.environ.get("QRDX_KEYSTORE_DIR", "/tmp/qrdx-validator-keys")
                
                # Load validators with balance verification from state
                genesis_validators = load_validators_with_balance_verification(
                    genesis_file_path=str(genesis_file),
                    keystore_dir_path=keystore_dir,
                    state=genesis_state if use_balance_verification else None,
                )
                
                if not genesis_validators:
                    self.logger.warning("No validators loaded, cannot initialize consensus")
                    return None
                
                validator_set = ValidatorSet(genesis_validators=genesis_validators)
                self.logger.info(f"✅ Loaded {len(genesis_validators)} validators for block validation")
                
                # Create consensus instance
                consensus = QRPoSConsensus(
                    validator_set=validator_set,
                    genesis_time=genesis_time
                )
                
                return consensus
                
            except Exception as e:
                if attempt < 4:
                    self.logger.debug(f"Attempt {attempt + 1}/5 to initialize consensus failed: {e}, retrying...")
                    await trio.sleep(2)
                else:
                    self.logger.error(f"Failed to initialize consensus after 5 attempts: {e}", exc_info=True)
                    return None
        
        return None

    async def _handle_new_block_hashes(self) -> None:
        async for event in self._event_bus.stream(NewBlockHashesEvent):
            self.logger.debug(
                "Received NewBlockHashes from %s: %s",
                event.session,
                [humanize_hash(item.hash) for item in event.command.payload],
            )
            for new_block_hash in event.command.payload:
                try:
                    with trio.fail_after(5):
                        # Sometimes we get a NewBlock/NewBlockHashes msg before the BeamSyncer
                        # service has started, and there will be no subscribers to
                        # FetchBlockWitness in that case. This ensures we wait for it to start
                        # before attempting to fire CollectMissingTrieNodes events.
                        await self._event_bus.wait_until_any_endpoint_subscribed_to(
                            FetchBlockWitness)
                except trio.TooSlowError:
                    self.logger.warning(
                        "No subscribers for FetchBlockWitness, couldn't fetch witness for %s",
                        humanize_hash(new_block_hash.hash),
                    )
                    continue
                self.manager.run_task(
                    self._event_bus.request,
                    FetchBlockWitness(event.session, new_block_hash.hash, new_block_hash.number)
                )

    async def _handle_imported_blocks(self) -> None:
        async for event in self._event_bus.stream(NewBlockImported):
            block = event.block
            self.logger.debug("NewBlockImported: %s", block)
            await self._broadcast_new_block_hashes(block)

    async def _handle_qrpos_new_blocks(self) -> None:
        """Handle QR-PoS blocks created by local validator."""
        self.logger.info("QR-PoS block handler started, streaming QRPoSNewBlockEvent events...")
        self.logger.info(f"Event bus: {self._event_bus}, type: {type(self._event_bus)}")
        async for event in self._event_bus.stream(QRPoSNewBlockEvent):
            self.logger.info(f"*** EVENT RECEIVED IN LOOP! Event: {event}")
            # Decode RLP-encoded header
            from eth.rlp.headers import BlockHeader
            import rlp
            header = rlp.decode(event.header_rlp, BlockHeader)
            
            self.logger.info(
                "Received QR-PoS block from local validator %d: block #%d (slot %d)",
                event.validator_index,
                header.block_number,
                event.slot,
            )
            
            # Log the block details
            self.logger.debug(
                "QR-PoS block hash: %s, signature size: %d bytes",
                humanize_hash(header.hash),
                len(event.signature),
            )
            
            # Validate QR-PoS block
            try:
                # Basic validation without full signature check
                validate_qrpos_block_basic(header)
                self.logger.debug("QR-PoS block #%d passed basic validation", header.block_number)
                
                # Load validator set for signature validation
                # Validators are loaded from encrypted keystores
                import os
                import json
                from pathlib import Path
                from eth.consensus.qrpos import Validator, ValidatorSet, ValidatorStatus, MIN_STAKE
                from eth_utils import to_canonical_address
                from eth.crypto import DilithiumPublicKey
                
                NUM_VALIDATORS = int(os.environ.get('QRDX_NUM_VALIDATORS', '3'))
                
                # Get keystore directory
                keystore_dir = Path(os.environ.get("QRDX_KEYSTORE_DIR", "/tmp/qrdx-validator-keys"))
                
                genesis_validators = []
                for i in range(NUM_VALIDATORS):
                    validator_address = to_canonical_address(f"0x{i:040x}")
                    
                    # Load public key from keystore metadata (no password needed)
                    pubkey_found = False
                    for ks_file in keystore_dir.glob("*.json"):
                        with open(ks_file) as f:
                            ks_data = json.load(f)
                            if ks_data.get("path") == f"m/12381/3600/{i}/0/0":
                                pub_bytes = bytes.fromhex(ks_data["pubkey"])
                                pubkey_found = True
                                break
                    
                    if not pubkey_found:
                        raise FileNotFoundError(
                            f"No keystore found for validator {i} in {keystore_dir}"
                        )
                    
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
                
                # Validate signature using validator set
                from eth.consensus.qrpos_validator import validate_qrpos_block
                
                # Get genesis time for slot validation
                with get_eth1_chain_with_remote_db(self._boot_info, self._event_bus) as chain:
                    genesis_header = chain.get_canonical_block_header_by_number(BlockNumber(0))
                    genesis_time = genesis_header.timestamp
                
                validator_pubkeys = [v.public_key for v in validator_set.validators]
                validate_qrpos_block(header, event.signature, validator_pubkeys, genesis_time)
                
                self.logger.info(
                    "QR-PoS block #%d signature validated successfully (validator %d)",
                    header.block_number, event.validator_index
                )
                
            except ValidationError as e:
                self.logger.warning(
                    "QR-PoS block #%d from validator %d failed validation: %s",
                    header.block_number,
                    event.validator_index,
                    e
                )
                continue
            
            # Import block to chain DB
            try:
                with get_eth1_chain_with_remote_db(self._boot_info, self._event_bus) as chain:
                    # Get the block class from the VM
                    vm = chain.get_vm()
                    block_class = vm.get_block_class()
                    
                    # Create block from header (with empty transactions for now)
                    # In QR-PoS, blocks may be empty if no transactions are available
                    block = block_class(header=header, transactions=[], uncles=[])
                    
                    # Import the block to the chain
                    # Note: perform_validation=False because we already validated above
                    # and the standard validation doesn't understand QR-PoS
                    import_result = chain.import_block(block, perform_validation=False)
                    
                    self.logger.info(
                        "Successfully imported QR-PoS block #%d (hash: %s)",
                        header.block_number,
                        humanize_hash(header.hash),
                    )
                    
                    # Store Dilithium signature in proper database
                    chain.chaindb.persist_qrpos_signature(header.hash, event.signature)
                    self.logger.debug(
                        "Stored QR-PoS signature for block #%d (%d bytes)",
                        header.block_number,
                        len(event.signature),
                    )
                    
                    # Try to get and validate attestations if they exist
                    try:
                        attestations = chain.chaindb.get_qrpos_attestations(header.hash)
                        self.logger.info(
                            "Block #%d includes %d attestations",
                            header.block_number,
                            len(attestations),
                        )
                        
                        # Validate each attestation (if consensus is initialized)
                        valid_count = 0
                        if self._consensus:
                            for attestation in attestations:
                                try:
                                    self._consensus.attestation_pool.add_attestation(
                                        attestation,
                                        self._consensus.validator_set,
                                    )
                                    valid_count += 1
                                except Exception as e:
                                    self.logger.warning(
                                        "Invalid attestation in block #%d: %s",
                                        header.block_number,
                                        e,
                                    )
                        else:
                            self.logger.debug(
                                "Consensus not initialized, skipping attestation validation"
                            )
                        
                        self.logger.info(
                            "Validated %d/%d attestations from block #%d",
                            valid_count,
                            len(attestations),
                            header.block_number,
                        )
                    except KeyError:
                        # No attestations stored for this block yet
                        self.logger.debug(
                            "No attestations found for block #%d",
                            header.block_number,
                        )
                    
                    # Get score - with retry to handle IPC database write delay
                    # The score is written during import_block() but via IPC it may not
                    # be immediately visible. Retry a few times with small delays.
                    total_difficulty = None
                    for attempt in range(5):
                        try:
                            total_difficulty = chain.chaindb.get_score(block.hash)
                            break
                        except (KeyError, HeaderNotFound):
                            if attempt < 4:  # Don't sleep on last attempt
                                import trio
                                await trio.sleep(0.01 * (attempt + 1))  # 10ms, 20ms, 30ms, 40ms
                            else:
                                # Last attempt failed, calculate score manually
                                # For PoS, score = parent_score + block_number
                                try:
                                    parent_score = chain.chaindb.get_score(header.parent_hash)
                                    total_difficulty = parent_score + header.block_number
                                    self.logger.warning(
                                        "Score not found for block #%d, calculated as %d",
                                        header.block_number,
                                        total_difficulty
                                    )
                                except Exception as e:
                                    self.logger.error(
                                        "Failed to get or calculate score for block #%d: %s",
                                        header.block_number,
                                        e
                                    )
                                    # Use block number as fallback
                                    total_difficulty = header.block_number
                    
            except Exception as e:
                self.logger.error(
                    "Failed to import QR-PoS block #%d: %s",
                    header.block_number,
                    e,
                    exc_info=True
                )
                continue
            
            # Track the block
            block_hash = header.hash
            if block_hash not in self._peer_block_tracker:
                self._peer_block_tracker[block_hash] = []
            
            # Broadcast QR-PoS block with Dilithium signature to peers
            # Pass total_difficulty from above to avoid DB race condition
            await self._broadcast_qrpos_block(block, event.signature, event.validator_index, event.slot, total_difficulty)
            
            self.logger.info(
                "Broadcast QR-PoS block #%d to peers with Dilithium signature",
                header.block_number,
            )
            
            # Check if any pending blocks can now be imported
            await self._try_import_pending_blocks(header.hash)

    async def _handle_qrpos_attestations(self) -> None:
        """Handle QR-PoS attestations created by local validator."""
        from trinity.protocol.eth.events import QRPoSAttestationEvent
        from eth.consensus.qrpos import Attestation
        
        self.logger.info("[ATTESTATION-HANDLER] QR-PoS attestation handler started, streaming events...")
        async for event in self._event_bus.stream(QRPoSAttestationEvent):
            self.logger.info(
                "[ATTESTATION-HANDLER] Received QR-PoS attestation from validator %d for slot %d",
                event.validator_index,
                event.slot,
            )
            
            # Add to local attestation pool
            from trinity._utils.connect import get_eth1_chain_with_remote_db
            with get_eth1_chain_with_remote_db(self._boot_info, self._event_bus) as chain:
                attestation = Attestation(
                    slot=event.slot,
                    block_hash=event.block_hash,
                    validator_index=event.validator_index,
                    signature=event.signature,
                )
                if self._consensus:
                    self._consensus.add_attestation(attestation)
                    self.logger.info(
                        "[ATTESTATION-HANDLER] Added local attestation from validator %d to pool",
                        event.validator_index,
                    )
                else:
                    self.logger.warning(
                        "[ATTESTATION-HANDLER] Consensus not initialized, cannot add attestation"
                    )
            
            # Broadcast attestation to all peers
            await self._broadcast_attestations([event])

    async def _handle_incoming_attestations(self) -> None:
        """Handle incoming attestations from peers."""
        from trinity.protocol.eth.events import AttestationsEvent
        from eth.consensus.qrpos import Attestation
        
        self.logger.info("Incoming attestation handler started...")
        async for event in self._event_bus.stream(AttestationsEvent):
            self.logger.info(
                "Received %d attestation(s) from peer %s",
                len(event.command.payload),
                event.session,
            )
            
            # Process each attestation
            from trinity._utils.connect import get_eth1_chain_with_remote_db
            with get_eth1_chain_with_remote_db(self._boot_info, self._event_bus) as chain:
                for att_payload in event.command.payload:
                    try:
                        # Create Attestation object
                        attestation = Attestation(
                            slot=att_payload.slot,
                            block_hash=att_payload.block_hash,
                            validator_index=att_payload.validator_index,
                            signature=att_payload.signature,
                        )
                        
                        # Add to consensus attestation pool
                        if self._consensus:
                            self._consensus.add_attestation(attestation)
                            self.logger.debug(
                                "Added attestation from validator %d (slot %d) to pool",
                                att_payload.validator_index,
                                att_payload.slot,
                            )
                        else:
                            self.logger.warning(
                                "Consensus not initialized, cannot add attestation from peer"
                            )
                    except Exception as e:
                        self.logger.warning(
                            "Failed to process attestation from peer %s: %s",
                            event.session,
                            e,
                        )

    async def _handle_incoming_qrpos_blocks(self) -> None:
        """Handle QR-PoS blocks received from peers over the wire protocol."""
        from trinity.protocol.eth.events import QRPoSNewBlockEvent_Wire
        from eth_utils import encode_hex
        
        self.logger.info("Incoming QR-PoS block handler started...")
        async for event in self._event_bus.stream(QRPoSNewBlockEvent_Wire):
            self.logger.info(
                "Received QR-PoS block #%d from peer %s (sig_size=%d bytes)",
                event.command.payload.block.header.block_number,
                event.session,
                len(event.command.payload.signature),
            )
            
            # Import the block with Dilithium signature
            from trinity._utils.connect import get_eth1_chain_with_remote_db
            block_fields = event.command.payload.block
            header = block_fields.header
            
            try:
                with get_eth1_chain_with_remote_db(self._boot_info, self._event_bus) as chain:
                    # Get the block class from the VM
                    vm = chain.get_vm()
                    block_class = vm.get_block_class()
                    
                    # Create block from received data
                    block = block_class(
                        header=header,
                        transactions=block_fields.transactions,
                        uncles=block_fields.uncles
                    )
                    
                    # Import the block
                    chain.import_block(block, perform_validation=False)
                    
                    # Store Dilithium signature
                    chain.chaindb.persist_qrpos_signature(
                        header.hash, 
                        event.command.payload.signature
                    )
                    
                    # Store attestations received from peer (if any)
                    from eth.consensus.qrpos import Attestation
                    attestations = []
                    if event.command.payload.attestations:
                        # Decode RLP attestations from payload
                        import rlp
                        from rlp.sedes import big_endian_int, binary
                        from eth_typing import Hash32
                        
                        for att_rlp in event.command.payload.attestations:
                            att_data = rlp.decode(att_rlp, sedes=rlp.sedes.List([
                                big_endian_int,  # slot
                                binary,          # block_hash  
                                big_endian_int,  # validator_index
                                binary,          # signature
                            ]))
                            attestations.append(Attestation(
                                slot=att_data[0],
                                block_hash=Hash32(att_data[1]),
                                validator_index=att_data[2],
                                signature=att_data[3],
                            ))
                        
                        # Persist attestations
                        chain.chaindb.persist_qrpos_attestations(header.hash, attestations)
                        self.logger.debug(
                            "Persisted %d attestations for block #%d from peer",
                            len(attestations),
                            header.block_number,
                        )
                    if attestations and self._consensus:
                        finality_gadget = self._consensus.finality_gadget
                        slot = event.command.payload.slot
                        epoch = slot // 32  # SLOTS_PER_EPOCH = 32
                        
                        # Calculate and store block weight for fork choice
                        weight = self._consensus.calculate_block_weight(
                            header.hash,
                            attestations,
                            epoch
                        )
                        chain.chaindb.persist_qrpos_block_weight(header.hash, weight)
                        
                        is_justified, is_finalized = finality_gadget.process_attestations(
                            slot,
                            header.hash,
                            attestations
                        )
                        
                        # Update justified checkpoint
                        if is_justified:
                            chain.chaindb.persist_qrpos_justified_checkpoint(
                                finality_gadget.justified_slot,
                                finality_gadget.justified_hash
                            )
                            self.logger.info(
                                "✓ Block #%d JUSTIFIED (slot=%d, hash=%s)",
                                header.block_number,
                                finality_gadget.justified_slot,
                                encode_hex(finality_gadget.justified_hash[:8]),
                            )
                        
                        # Update finalized checkpoint
                        if is_finalized:
                            chain.chaindb.persist_qrpos_finalized_checkpoint(
                                finality_gadget.finalized_slot,
                                finality_gadget.finalized_hash
                            )
                            self.logger.info(
                                "🔒 Block #%d FINALIZED (slot=%d, hash=%s)",
                                header.block_number,
                                finality_gadget.finalized_slot,
                                encode_hex(finality_gadget.finalized_hash[:8]),
                            )
                    
                    self.logger.info(
                        "Successfully imported QR-PoS block #%d from peer (hash: %s)",
                        header.block_number,
                        humanize_hash(header.hash),
                    )
                    
            except ValidationError as e:
                # Check if this is a missing parent error
                if "Cannot import block" in str(e) and "before importing its parent" in str(e):
                    parent_hash = header.parent_hash
                    
                    # Store block for later (max 3 retries)
                    if parent_hash not in self._pending_blocks:
                        self._pending_blocks[parent_hash] = []
                    self._pending_blocks[parent_hash].append((event, 0))
                    
                    self.logger.info(
                        "Buffering block #%d (waiting for parent %s), %d parent hashes pending",
                        header.block_number,
                        encode_hex(parent_hash[:8]),
                        len(self._pending_blocks),
                    )
                    
                    # Request the missing parent from peer if not already requested
                    if parent_hash not in self._requested_blocks:
                        self._requested_blocks.add(parent_hash)
                        # Note: Block hash request would go here
                        # For now, we wait for natural sync
                        self.logger.debug(
                            "Need parent block %s for #%d",
                            encode_hex(parent_hash[:8]),
                            header.block_number,
                        )
                else:
                    self.logger.error(
                        "Failed to import QR-PoS block from peer %s: %s",
                        event.session,
                        e,
                        exc_info=True
                    )
            except Exception as e:
                self.logger.error(
                    "Failed to import QR-PoS block from peer %s: %s",
                    event.session,
                    e,
                    exc_info=True
                )
            else:
                # Block imported successfully - check if any pending blocks can now be imported
                await self._try_import_pending_blocks(header.hash)

    async def _try_import_pending_blocks(self, imported_hash: Hash32) -> None:
        """Try to import blocks that were waiting for this block as parent."""
        if imported_hash not in self._pending_blocks:
            return
        
        # Get all blocks waiting for this parent
        blocks_to_retry = []
        if imported_hash in self._pending_blocks:
            blocks_to_retry = self._pending_blocks.pop(imported_hash)
            if not isinstance(blocks_to_retry, list):
                blocks_to_retry = [blocks_to_retry]
        
        # Remove from requested set
        self._requested_blocks.discard(imported_hash)
        
        for pending_event, retry_count in blocks_to_retry:
            if retry_count >= 3:
                self.logger.warning(
                    "Dropping block after 3 failed retries (parent: %s)",
                    encode_hex(imported_hash[:8]),
                )
                continue
            
            self.logger.info(
                "Retrying import of pending block (parent now available: %s)",
                encode_hex(imported_hash[:8]),
            )
            
            # Update retry count and re-add to pending if needed
            try:
                # Try to import the block
                payload = pending_event.command.payload
                header = payload.block.header
                block = payload.block
                
                # Import via chain
                chain = self.chain
                chain.import_block(block, perform_validation=True)
                
                # Persist attestations if present
                if payload.attestations:
                    for attestation_bytes in payload.attestations:
                        chain.chaindb.persist_qrpos_attestation(
                            header.block_number,
                            attestation_bytes
                        )
                
                self.logger.info(
                    "Successfully imported pending block #%d (hash: %s)",
                    header.block_number,
                    humanize_hash(header.hash),
                )
                
                # Check if this block unblocks other pending blocks
                await self._try_import_pending_blocks(header.hash)
                
            except ValidationError as e:
                if "Cannot import block" in str(e) and "before importing its parent" in str(e):
                    # Still missing parent, re-buffer with incremented retry count
                    new_parent_hash = header.parent_hash
                    if new_parent_hash not in self._pending_blocks:
                        self._pending_blocks[new_parent_hash] = []
                    self._pending_blocks[new_parent_hash].append((pending_event, retry_count + 1))
                    self.logger.debug(
                        "Re-buffering block #%d (still waiting for parent %s), retry %d/3",
                        header.block_number,
                        encode_hex(new_parent_hash[:8]),
                        retry_count + 1,
                    )
                else:
                    self.logger.error(
                        "Failed to import pending block: %s",
                        e,
                        exc_info=True
                    )
            except Exception as e:
                self.logger.error(
                    "Failed to import pending block: %s",
                    e,
                    exc_info=True
                )
    
    async def _broadcast_attestations(self, events: list) -> None:
        """Broadcast attestations to all connected peers."""
        from trinity.protocol.eth.payloads import AttestationPayload
        
        all_peers = await self._peer_pool.get_peers()
        if not all_peers:
            self.logger.debug("No peers connected, skipping attestation broadcast")
            return
            
        # Convert events to payloads
        attestations = [
            AttestationPayload(
                slot=event.slot,
                block_hash=event.block_hash,
                validator_index=event.validator_index,
                signature=event.signature,
            )
            for event in events
        ]
        
        # Send to all peers
        for peer in all_peers:
            try:
                target_peer = await self._peer_pool.ensure_proxy_peer(peer.session)
                target_peer.eth_api.send_attestations(attestations)
                self.logger.debug(
                    "Sent %d attestation(s) to peer %s",
                    len(attestations),
                    target_peer,
                )
                await trio.sleep(0)  # yield to event loop
            except Exception as e:
                self.logger.warning(
                    "Failed to send attestations to peer %s: %s",
                    peer,
                    e,
                )

    async def _handle_new_block(self, sender: SessionAPI, payload: NewBlockPayload) -> None:
        header = payload.block.header
        sender_peer = ETHProxyPeer.from_session(
            sender,
            self._event_bus,
            TO_NETWORKING_BROADCAST_CONFIG
        )
        sender_peer_str = str(sender_peer)
        self.logger.debug("Received NewBlock from %s: %s", sender, header)

        # Add peer to tracker if we've seen this block before
        if header.hash in self._peer_block_tracker:
            if sender_peer_str not in self._peer_block_tracker[header.hash]:
                self._peer_block_tracker[header.hash].append(sender_peer_str)
        else:
            # Verify the validity of block, add to tracker and broadcast to eligible peers
            with get_eth1_chain_with_remote_db(self._boot_info, self._event_bus) as chain:
                try:
                    chain.validate_seal(header)
                except ValidationError as exc:
                    self.logger.info(
                        "Received invalid block from peer: %s. %s",
                        sender_peer_str, exc,
                    )
                else:
                    try:
                        with trio.fail_after(5):
                            # Sometimes we get a NewBlock/NewBlockHashes msg before the BeamSyncer
                            # service has started, and there will be no subscribers to
                            # FetchBlockWitness in that case. This ensures we wait for it to start
                            # before attempting to fire CollectMissingTrieNodes events.
                            await self._event_bus.wait_until_any_endpoint_subscribed_to(
                                FetchBlockWitness)
                    except trio.TooSlowError:
                        self.logger.warning(
                            "No subscribers for FetchBlockWitness, couldn't feth witness for %s",
                            header,
                        )
                    else:
                        self.manager.run_task(
                            self._event_bus.request,
                            FetchBlockWitness(sender, header.hash, header.block_number),
                        )
                    self._peer_block_tracker[header.hash] = [sender_peer_str]
                    # Here we only broadcast a NewBlock msg to a subset of our peers, and once the
                    # block is imported into our chain a NewBlockImported event will be generated
                    # and we'll announce it to the remaining ones, as per the spec.
                    await self._broadcast_new_block(payload.block, payload.total_difficulty)

    async def _broadcast_new_block_hashes(self, block: BlockAPI) -> None:
        """
        Send `NewBlockHashes` msgs to all peers that haven't heard about the given block yet.
        """
        all_peers = await self._peer_pool.get_peers()
        eligible_peers = self._filter_eligible_peers(all_peers, block.hash)
        new_block_hash = NewBlockHash(hash=block.hash, number=block.number)
        for peer in eligible_peers:
            self.logger.debug("Sending NewBlockHashes(%s) to %s", block.header, peer)
            target_peer = await self._peer_pool.ensure_proxy_peer(peer.session)
            target_peer.eth_api.send_new_block_hashes((new_block_hash,))
            self._peer_block_tracker[block.hash].append(str(target_peer))

    async def _broadcast_qrpos_block(self, block: BlockAPI, signature: bytes, 
                                      validator_index: int, slot: int, total_difficulty: int) -> None:
        """
        Send QR-PoS block with Dilithium signature to all peers that haven't heard about it yet.
        
        Args:
            block: The block to broadcast
            signature: Dilithium signature
            validator_index: Index of validator who signed
            slot: Slot number
            total_difficulty: Total difficulty/score (passed to avoid DB race condition)
        """
        all_peers = await self._peer_pool.get_peers()
        eligible_peers = self._filter_eligible_peers(all_peers, block.hash)
        
        # Retrieve attestations for this block to include in broadcast
        import rlp
        from rlp.sedes import big_endian_int, binary
        attestations_rlp = []
        try:
            from trinity._utils.connect import get_eth1_chain_with_remote_db
            with get_eth1_chain_with_remote_db(self._boot_info, self._event_bus) as chain:
                attestations = chain.chaindb.get_qrpos_attestations(block.hash)
                # Encode each attestation as RLP for wire protocol
                for att in attestations:
                    att_rlp = rlp.encode([
                        att.slot,
                        att.block_hash,
                        att.validator_index,
                        att.signature,
                    ], sedes=rlp.sedes.List([
                        big_endian_int,
                        binary,
                        big_endian_int,
                        binary,
                    ]))
                    attestations_rlp.append(att_rlp)
                self.logger.debug(
                    "Including %d attestations in block #%d broadcast",
                    len(attestations_rlp),
                    block.number,
                )
        except KeyError:
            # No attestations for this block (empty block or genesis)
            self.logger.debug(
                "No attestations found for block #%d, broadcasting without",
                block.number,
            )
        
        for peer in eligible_peers:
            self.logger.debug(
                "Sending QRPoSNewBlock(#%d, sig_size=%d bytes, %d attestations) to %s", 
                block.number, len(signature), len(attestations_rlp), peer
            )
            target_peer = await self._peer_pool.ensure_proxy_peer(peer.session)
            target_peer.eth_api.send_qrpos_new_block(
                block, total_difficulty, signature, validator_index, slot, attestations_rlp
            )
            self._peer_block_tracker[block.hash].append(str(target_peer))
            # add checkpoint here to guarantee the event loop is released per iteration
            await trio.sleep(0)

    async def _broadcast_new_block(self, block_fields: BlockFields, total_difficulty: int) -> None:
        """
        Send `NewBlock` msgs to a subset of our peers.
        """
        all_peers = await self._peer_pool.get_peers()
        eligible_peers = self._filter_eligible_peers(all_peers, block_fields.header.hash)
        number_of_broadcasts = int(math.sqrt(len(all_peers)))
        sample_size = min(len(eligible_peers), number_of_broadcasts)
        broadcast_peers = random.sample(eligible_peers, sample_size)

        for peer in broadcast_peers:
            target_peer = await self._peer_pool.ensure_proxy_peer(peer.session)
            self.logger.debug("Sending NewBlock(%s) to %s", block_fields.header, target_peer)
            target_peer.eth_api.send_new_block(block_fields, total_difficulty)
            self._peer_block_tracker[block_fields.header.hash].append(str(target_peer))

    @to_tuple
    def _filter_eligible_peers(self,
                               all_peers: Tuple[ETHProxyPeer],
                               block_hash: bytes) -> Iterable[ETHProxyPeer]:
        """
        Filter and return peers who have not seen the given block hash.
        """
        for peer in all_peers:
            if str(peer) not in self._peer_block_tracker[block_hash]:
                yield peer
