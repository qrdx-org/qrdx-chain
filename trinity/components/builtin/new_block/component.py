import collections
import math
import random
from typing import (
    DefaultDict,
    Iterable,
    List,
    Tuple,
)

from async_service import (
    Service,
    background_trio_service,
)
from eth.abc import (
    BlockAPI,
)
from eth_typing import BlockNumber
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

    async def run(self) -> None:
        self.logger.info("NewBlockService starting up - registering handlers...")
        self.manager.run_daemon_task(self._handle_imported_blocks)
        self.manager.run_daemon_task(self._handle_new_block_hashes)
        self.manager.run_daemon_task(self._handle_qrpos_new_blocks)
        self.manager.run_daemon_task(self._handle_qrpos_attestations)
        self.manager.run_daemon_task(self._handle_incoming_attestations)
        self.manager.run_daemon_task(self._handle_incoming_qrpos_blocks)
        self.logger.info("QR-PoS block and attestation handlers registered, waiting for events...")

        async for event in self._event_bus.stream(NewBlockEvent):
            self.manager.run_task(self._handle_new_block, event.session, event.command.payload)

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
                        
                        # Validate each attestation
                        valid_count = 0
                        for attestation in attestations:
                            try:
                                chain.consensus.attestation_pool.add_attestation(
                                    attestation,
                                    chain.consensus.validator_set,
                                )
                                valid_count += 1
                            except Exception as e:
                                self.logger.warning(
                                    "Invalid attestation in block #%d: %s",
                                    header.block_number,
                                    e,
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
                    
                    # Get score now while DB context is still open
                    # This prevents race condition in broadcast
                    total_difficulty = chain.chaindb.get_score(block.hash)
                    
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

    async def _handle_qrpos_attestations(self) -> None:
        """Handle QR-PoS attestations created by local validator."""
        from trinity.protocol.eth.events import QRPoSAttestationEvent
        
        self.logger.info("[ATTESTATION-HANDLER] QR-PoS attestation handler started, streaming events...")
        async for event in self._event_bus.stream(QRPoSAttestationEvent):
            self.logger.info(
                "[ATTESTATION-HANDLER] Received QR-PoS attestation from validator %d for slot %d",
                event.validator_index,
                event.slot,
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
                        chain.consensus.add_attestation(attestation)
                        
                        self.logger.debug(
                            "Added attestation from validator %d (slot %d) to pool",
                            att_payload.validator_index,
                            att_payload.slot,
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
                    
                    # Get attestations for this block and process for finality
                    attestations = chain.chaindb.get_qrpos_attestations(header.hash)
                    if attestations:
                        finality_gadget = chain.consensus.finality_gadget
                        slot = event.command.payload.slot
                        epoch = slot // 32  # SLOTS_PER_EPOCH = 32
                        
                        # Calculate and store block weight for fork choice
                        weight = chain.consensus.calculate_block_weight(
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
                    
            except Exception as e:
                self.logger.error(
                    "Failed to import QR-PoS block from peer %s: %s",
                    event.session,
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
        
        for peer in eligible_peers:
            self.logger.debug(
                "Sending QRPoSNewBlock(#%d, sig_size=%d bytes) to %s", 
                block.number, len(signature), peer
            )
            target_peer = await self._peer_pool.ensure_proxy_peer(peer.session)
            target_peer.eth_api.send_qrpos_new_block(
                block, total_difficulty, signature, validator_index, slot
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
