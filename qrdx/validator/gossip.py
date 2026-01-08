"""
QRDX P2P Gossip Protocol for PoS

Implements gossip-based message propagation for:
- Beacon blocks
- Attestations
- Sync committee contributions
- Voluntary exits
- Slashing evidence

Based on libp2p gossipsub with QR-PoS specific topics.
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
from enum import Enum, auto
from collections import defaultdict
import json

from ..logger import get_logger
from ..constants import (
    SLOTS_PER_EPOCH,
    SLOT_DURATION,
    MAX_ATTESTATIONS_PER_BLOCK,
)

logger = get_logger(__name__)


# =============================================================================
# GOSSIP TOPICS
# =============================================================================

class GossipTopic(Enum):
    """Gossip topics for PoS messages."""
    # Core consensus
    BEACON_BLOCK = "beacon_block"
    BEACON_ATTESTATION = "beacon_attestation"
    AGGREGATED_ATTESTATION = "aggregated_attestation"
    
    # Sync committee
    SYNC_COMMITTEE_MESSAGE = "sync_committee_message"
    SYNC_COMMITTEE_CONTRIBUTION = "sync_committee_contribution"
    
    # Validator lifecycle
    VOLUNTARY_EXIT = "voluntary_exit"
    PROPOSER_SLASHING = "proposer_slashing"
    ATTESTER_SLASHING = "attester_slashing"
    
    # Subnet topics (attestation subnets)
    ATTESTATION_SUBNET_0 = "attestation_subnet_0"
    ATTESTATION_SUBNET_1 = "attestation_subnet_1"
    ATTESTATION_SUBNET_2 = "attestation_subnet_2"
    ATTESTATION_SUBNET_3 = "attestation_subnet_3"


def get_topic_name(topic: GossipTopic, fork_digest: bytes = b'\x00\x00\x00\x01') -> str:
    """Get the full topic name including fork digest."""
    return f"/qrdx/{fork_digest.hex()}/{topic.value}"


# =============================================================================
# MESSAGE TYPES
# =============================================================================

@dataclass
class GossipMessage:
    """Base gossip message."""
    topic: GossipTopic
    data: bytes
    sender: str
    timestamp: float = field(default_factory=time.time)
    message_id: str = ""
    
    def __post_init__(self):
        if not self.message_id:
            self.message_id = hashlib.sha256(
                self.topic.value.encode() +
                self.data +
                self.sender.encode() +
                str(self.timestamp).encode()
            ).hexdigest()[:16]


@dataclass
class BeaconBlockMessage:
    """Beacon block gossip message."""
    slot: int
    proposer_index: int
    parent_root: str
    state_root: str
    block_hash: str
    signature: str
    body: Dict[str, Any]
    
    def to_bytes(self) -> bytes:
        return json.dumps({
            'slot': self.slot,
            'proposer_index': self.proposer_index,
            'parent_root': self.parent_root,
            'state_root': self.state_root,
            'block_hash': self.block_hash,
            'signature': self.signature,
            'body': self.body,
        }).encode()
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'BeaconBlockMessage':
        d = json.loads(data.decode())
        return cls(**d)


@dataclass
class AttestationMessage:
    """Attestation gossip message."""
    slot: int
    committee_index: int
    beacon_block_root: str
    source_epoch: int
    source_root: str
    target_epoch: int
    target_root: str
    aggregation_bits: str  # Hex-encoded bitfield
    signature: str
    
    def to_bytes(self) -> bytes:
        return json.dumps({
            'slot': self.slot,
            'committee_index': self.committee_index,
            'beacon_block_root': self.beacon_block_root,
            'source_epoch': self.source_epoch,
            'source_root': self.source_root,
            'target_epoch': self.target_epoch,
            'target_root': self.target_root,
            'aggregation_bits': self.aggregation_bits,
            'signature': self.signature,
        }).encode()
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'AttestationMessage':
        d = json.loads(data.decode())
        return cls(**d)


@dataclass
class VoluntaryExitMessage:
    """Voluntary exit gossip message."""
    epoch: int
    validator_index: int
    validator_address: str
    signature: str
    
    def to_bytes(self) -> bytes:
        return json.dumps({
            'epoch': self.epoch,
            'validator_index': self.validator_index,
            'validator_address': self.validator_address,
            'signature': self.signature,
        }).encode()
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'VoluntaryExitMessage':
        d = json.loads(data.decode())
        return cls(**d)


@dataclass
class SlashingMessage:
    """Slashing evidence gossip message."""
    slashing_type: str  # 'proposer' or 'attester'
    evidence: Dict[str, Any]
    reporter: str
    signature: str
    
    def to_bytes(self) -> bytes:
        return json.dumps({
            'slashing_type': self.slashing_type,
            'evidence': self.evidence,
            'reporter': self.reporter,
            'signature': self.signature,
        }).encode()
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SlashingMessage':
        d = json.loads(data.decode())
        return cls(**d)


# =============================================================================
# MESSAGE VALIDATION
# =============================================================================

class MessageValidation(Enum):
    """Message validation results."""
    ACCEPT = auto()
    REJECT = auto()
    IGNORE = auto()


@dataclass
class ValidationResult:
    """Result of message validation."""
    status: MessageValidation
    reason: str = ""


class MessageValidator:
    """
    Validates gossip messages before propagation.
    
    Implements various checks per message type.
    """
    
    def __init__(self, genesis_time: int, current_slot_fn: Callable[[], int]):
        self.genesis_time = genesis_time
        self.get_current_slot = current_slot_fn
        
        # Track seen messages to prevent duplicates
        self._seen_blocks: Dict[str, int] = {}  # hash -> slot
        self._seen_attestations: Set[str] = set()
        self._seen_exits: Set[str] = set()
        self._seen_slashings: Set[str] = set()
        
        # Rate limiting
        self._message_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    
    async def validate_beacon_block(
        self,
        message: BeaconBlockMessage,
        sender: str,
    ) -> ValidationResult:
        """Validate a beacon block message."""
        current_slot = self.get_current_slot()
        
        # Check slot timing
        if message.slot > current_slot + 1:
            return ValidationResult(
                MessageValidation.IGNORE,
                "Block slot too far in future"
            )
        
        if message.slot < current_slot - SLOTS_PER_EPOCH:
            return ValidationResult(
                MessageValidation.IGNORE,
                "Block slot too old"
            )
        
        # Check for duplicates
        if message.block_hash in self._seen_blocks:
            return ValidationResult(
                MessageValidation.IGNORE,
                "Block already seen"
            )
        
        # Record as seen
        self._seen_blocks[message.block_hash] = message.slot
        
        # Basic structure validation
        if not message.block_hash or not message.parent_root:
            return ValidationResult(
                MessageValidation.REJECT,
                "Invalid block structure"
            )
        
        # Note: Full signature verification happens in consensus layer
        return ValidationResult(MessageValidation.ACCEPT)
    
    async def validate_attestation(
        self,
        message: AttestationMessage,
        sender: str,
    ) -> ValidationResult:
        """Validate an attestation message."""
        current_slot = self.get_current_slot()
        current_epoch = current_slot // SLOTS_PER_EPOCH
        
        # Check slot timing
        if message.slot > current_slot + 1:
            return ValidationResult(
                MessageValidation.IGNORE,
                "Attestation slot in future"
            )
        
        # Attestations valid for current and previous epoch
        attestation_epoch = message.slot // SLOTS_PER_EPOCH
        if attestation_epoch < current_epoch - 1:
            return ValidationResult(
                MessageValidation.IGNORE,
                "Attestation too old"
            )
        
        # Check for duplicates
        att_id = f"{message.slot}:{message.committee_index}:{message.aggregation_bits}"
        if att_id in self._seen_attestations:
            return ValidationResult(
                MessageValidation.IGNORE,
                "Attestation already seen"
            )
        
        self._seen_attestations.add(att_id)
        
        # Validate target epoch
        if message.target_epoch > current_epoch:
            return ValidationResult(
                MessageValidation.REJECT,
                "Invalid target epoch"
            )
        
        return ValidationResult(MessageValidation.ACCEPT)
    
    async def validate_voluntary_exit(
        self,
        message: VoluntaryExitMessage,
        sender: str,
    ) -> ValidationResult:
        """Validate a voluntary exit message."""
        current_slot = self.get_current_slot()
        current_epoch = current_slot // SLOTS_PER_EPOCH
        
        # Exit epoch should not be too far in future
        if message.epoch > current_epoch + 1:
            return ValidationResult(
                MessageValidation.IGNORE,
                "Exit epoch too far in future"
            )
        
        # Check for duplicates
        exit_id = f"{message.validator_address}:{message.epoch}"
        if exit_id in self._seen_exits:
            return ValidationResult(
                MessageValidation.IGNORE,
                "Exit already seen"
            )
        
        self._seen_exits.add(exit_id)
        
        return ValidationResult(MessageValidation.ACCEPT)
    
    async def validate_slashing(
        self,
        message: SlashingMessage,
        sender: str,
    ) -> ValidationResult:
        """Validate a slashing evidence message."""
        # Check for duplicates
        slashing_id = hashlib.sha256(message.to_bytes()).hexdigest()[:16]
        if slashing_id in self._seen_slashings:
            return ValidationResult(
                MessageValidation.IGNORE,
                "Slashing evidence already seen"
            )
        
        self._seen_slashings.add(slashing_id)
        
        # Validate slashing type
        if message.slashing_type not in ['proposer', 'attester']:
            return ValidationResult(
                MessageValidation.REJECT,
                "Invalid slashing type"
            )
        
        return ValidationResult(MessageValidation.ACCEPT)
    
    def cleanup_old_messages(self, current_slot: int):
        """Remove old seen messages to prevent memory growth."""
        # Clean old blocks
        cutoff_slot = current_slot - SLOTS_PER_EPOCH * 2
        self._seen_blocks = {
            h: s for h, s in self._seen_blocks.items()
            if s > cutoff_slot
        }
        
        # Clean attestations (keep last 1000)
        if len(self._seen_attestations) > 10000:
            self._seen_attestations = set(list(self._seen_attestations)[-5000:])


# =============================================================================
# GOSSIP HANDLER
# =============================================================================

# Type alias for message handlers (async functions)
MessageHandler = Callable[[GossipMessage], Any]


class GossipHandler:
    """
    Handles gossip message subscriptions and processing.
    
    Manages topic subscriptions and message routing.
    """
    
    def __init__(
        self,
        node_id: str,
        genesis_time: int,
        fork_digest: bytes = b'\x00\x00\x00\x01',
    ):
        self.node_id = node_id
        self.genesis_time = genesis_time
        self.fork_digest = fork_digest
        
        # Subscriptions: topic -> list of handlers
        self._subscriptions: Dict[GossipTopic, List[MessageHandler]] = defaultdict(list)
        
        # Validator
        self._validator = MessageValidator(
            genesis_time,
            self.get_current_slot,
        )
        
        # Message queue for processing
        self._message_queue: asyncio.Queue = asyncio.Queue()
        
        # Running state
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None
    
    def get_current_slot(self) -> int:
        """Get current slot based on genesis time."""
        now = int(time.time())
        if now < self.genesis_time:
            return 0
        return (now - self.genesis_time) // SLOT_DURATION
    
    def subscribe(self, topic: GossipTopic, handler: MessageHandler):
        """Subscribe to a gossip topic."""
        self._subscriptions[topic].append(handler)
        logger.info(f"Subscribed to topic: {topic.value}")
    
    def unsubscribe(self, topic: GossipTopic, handler: Optional[MessageHandler] = None):
        """Unsubscribe from a gossip topic."""
        if handler:
            if handler in self._subscriptions[topic]:
                self._subscriptions[topic].remove(handler)
        else:
            self._subscriptions[topic] = []
    
    async def publish(self, topic: GossipTopic, data: bytes) -> bool:
        """
        Publish a message to a topic.
        
        In production, this would broadcast to P2P network.
        """
        message = GossipMessage(
            topic=topic,
            data=data,
            sender=self.node_id,
        )
        
        # Validate our own message
        validation = await self._validate_message(message)
        if validation.status != MessageValidation.ACCEPT:
            logger.warning(f"Own message rejected: {validation.reason}")
            return False
        
        # Queue for processing
        await self._message_queue.put(message)
        
        logger.debug(f"Published to {topic.value}: {message.message_id}")
        
        return True
    
    async def on_message(self, topic: GossipTopic, data: bytes, sender: str):
        """
        Handle incoming message from P2P network.
        
        Called by network layer when message is received.
        """
        message = GossipMessage(
            topic=topic,
            data=data,
            sender=sender,
        )
        
        # Validate
        validation = await self._validate_message(message)
        
        if validation.status == MessageValidation.REJECT:
            logger.warning(f"Message rejected from {sender[:16]}: {validation.reason}")
            # Could penalize sender here
            return
        
        if validation.status == MessageValidation.IGNORE:
            logger.debug(f"Message ignored: {validation.reason}")
            return
        
        # Queue for processing
        await self._message_queue.put(message)
    
    async def _validate_message(self, message: GossipMessage) -> ValidationResult:
        """Validate a message based on topic."""
        try:
            if message.topic == GossipTopic.BEACON_BLOCK:
                block = BeaconBlockMessage.from_bytes(message.data)
                return await self._validator.validate_beacon_block(block, message.sender)
            
            elif message.topic in [
                GossipTopic.BEACON_ATTESTATION,
                GossipTopic.AGGREGATED_ATTESTATION,
                GossipTopic.ATTESTATION_SUBNET_0,
                GossipTopic.ATTESTATION_SUBNET_1,
                GossipTopic.ATTESTATION_SUBNET_2,
                GossipTopic.ATTESTATION_SUBNET_3,
            ]:
                attestation = AttestationMessage.from_bytes(message.data)
                return await self._validator.validate_attestation(attestation, message.sender)
            
            elif message.topic == GossipTopic.VOLUNTARY_EXIT:
                exit_msg = VoluntaryExitMessage.from_bytes(message.data)
                return await self._validator.validate_voluntary_exit(exit_msg, message.sender)
            
            elif message.topic in [GossipTopic.PROPOSER_SLASHING, GossipTopic.ATTESTER_SLASHING]:
                slashing = SlashingMessage.from_bytes(message.data)
                return await self._validator.validate_slashing(slashing, message.sender)
            
            else:
                return ValidationResult(MessageValidation.ACCEPT)
                
        except Exception as e:
            logger.error(f"Message validation error: {e}")
            return ValidationResult(MessageValidation.REJECT, str(e))
    
    async def _process_messages(self):
        """Background task to process queued messages."""
        while self._running:
            try:
                message = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=1.0,
                )
                
                handlers = self._subscriptions.get(message.topic, [])
                for handler in handlers:
                    try:
                        await handler(message)
                    except Exception as e:
                        logger.error(f"Handler error for {message.topic.value}: {e}")
                
            except asyncio.TimeoutError:
                # Periodic cleanup
                self._validator.cleanup_old_messages(self.get_current_slot())
            except Exception as e:
                logger.error(f"Message processing error: {e}")
    
    async def start(self):
        """Start the gossip handler."""
        if self._running:
            return
        
        self._running = True
        self._processor_task = asyncio.create_task(self._process_messages())
        logger.info("Gossip handler started")
    
    async def stop(self):
        """Stop the gossip handler."""
        self._running = False
        
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Gossip handler stopped")


# =============================================================================
# BEACON NODE GOSSIP INTEGRATION
# =============================================================================

class BeaconGossip:
    """
    High-level gossip interface for beacon node.
    
    Provides typed methods for publishing/receiving PoS messages.
    """
    
    def __init__(
        self,
        node_id: str,
        genesis_time: int,
    ):
        self.handler = GossipHandler(node_id, genesis_time)
        
        # Callbacks for received messages
        self.on_block: Optional[Callable[[BeaconBlockMessage], asyncio.coroutine]] = None
        self.on_attestation: Optional[Callable[[AttestationMessage], asyncio.coroutine]] = None
        self.on_exit: Optional[Callable[[VoluntaryExitMessage], asyncio.coroutine]] = None
        self.on_slashing: Optional[Callable[[SlashingMessage], asyncio.coroutine]] = None
    
    async def start(self):
        """Start gossip and subscribe to topics."""
        await self.handler.start()
        
        # Subscribe to all consensus topics
        self.handler.subscribe(GossipTopic.BEACON_BLOCK, self._handle_block)
        self.handler.subscribe(GossipTopic.BEACON_ATTESTATION, self._handle_attestation)
        self.handler.subscribe(GossipTopic.AGGREGATED_ATTESTATION, self._handle_attestation)
        self.handler.subscribe(GossipTopic.VOLUNTARY_EXIT, self._handle_exit)
        self.handler.subscribe(GossipTopic.PROPOSER_SLASHING, self._handle_slashing)
        self.handler.subscribe(GossipTopic.ATTESTER_SLASHING, self._handle_slashing)
    
    async def stop(self):
        """Stop gossip handler."""
        await self.handler.stop()
    
    async def publish_block(self, block: BeaconBlockMessage) -> bool:
        """Publish a new beacon block."""
        return await self.handler.publish(GossipTopic.BEACON_BLOCK, block.to_bytes())
    
    async def publish_attestation(
        self,
        attestation: AttestationMessage,
        aggregated: bool = False,
    ) -> bool:
        """Publish an attestation."""
        topic = GossipTopic.AGGREGATED_ATTESTATION if aggregated else GossipTopic.BEACON_ATTESTATION
        return await self.handler.publish(topic, attestation.to_bytes())
    
    async def publish_voluntary_exit(self, exit_msg: VoluntaryExitMessage) -> bool:
        """Publish a voluntary exit."""
        return await self.handler.publish(GossipTopic.VOLUNTARY_EXIT, exit_msg.to_bytes())
    
    async def publish_slashing(self, slashing: SlashingMessage) -> bool:
        """Publish slashing evidence."""
        topic = (GossipTopic.PROPOSER_SLASHING if slashing.slashing_type == 'proposer'
                else GossipTopic.ATTESTER_SLASHING)
        return await self.handler.publish(topic, slashing.to_bytes())
    
    async def _handle_block(self, message: GossipMessage):
        """Handle incoming block."""
        if self.on_block:
            block = BeaconBlockMessage.from_bytes(message.data)
            await self.on_block(block)
    
    async def _handle_attestation(self, message: GossipMessage):
        """Handle incoming attestation."""
        if self.on_attestation:
            attestation = AttestationMessage.from_bytes(message.data)
            await self.on_attestation(attestation)
    
    async def _handle_exit(self, message: GossipMessage):
        """Handle incoming voluntary exit."""
        if self.on_exit:
            exit_msg = VoluntaryExitMessage.from_bytes(message.data)
            await self.on_exit(exit_msg)
    
    async def _handle_slashing(self, message: GossipMessage):
        """Handle incoming slashing evidence."""
        if self.on_slashing:
            slashing = SlashingMessage.from_bytes(message.data)
            await self.on_slashing(slashing)
