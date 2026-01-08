"""
QRDX Fork Choice Rule - LMD-GHOST Implementation

Implements Latest Message Driven Greedy Heaviest Observed SubTree (LMD-GHOST)
combined with Casper FFG finality for the QR-PoS consensus.

This is the core algorithm that determines the canonical chain head.

Reference: Ethereum 2.0 Gasper (GHOST + Casper)
"""

import hashlib
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
import asyncio

from ..logger import get_logger

logger = get_logger(__name__)


@dataclass
class BlockNode:
    """
    Represents a block in the fork choice tree.
    """
    block_hash: str
    parent_hash: str
    slot: int
    proposer_address: str
    state_root: str
    
    # Attestation weight (sum of effective balance of attesters)
    weight: Decimal = Decimal("0")
    
    # Children in the tree
    children: List[str] = field(default_factory=list)
    
    # Finality status
    justified: bool = False
    finalized: bool = False
    
    def __hash__(self):
        return hash(self.block_hash)


@dataclass
class Checkpoint:
    """
    A checkpoint for Casper FFG finality.
    
    Checkpoints are epoch boundary blocks that can be justified and finalized.
    """
    epoch: int
    root: str  # Block hash at epoch boundary
    
    def __hash__(self):
        return hash((self.epoch, self.root))
    
    def __eq__(self, other):
        if not isinstance(other, Checkpoint):
            return False
        return self.epoch == other.epoch and self.root == other.root


@dataclass
class LatestMessage:
    """
    Latest attestation message from a validator.
    
    Used for LMD (Latest Message Driven) component of GHOST.
    """
    epoch: int
    root: str  # Block hash being attested to
    

class ForkChoiceStore:
    """
    Stores fork choice state for LMD-GHOST + Casper FFG.
    
    This is the central data structure for determining the chain head.
    """
    
    def __init__(self, genesis_block: BlockNode, genesis_time: int, slots_per_epoch: int = 32):
        # Configuration
        self.slots_per_epoch = slots_per_epoch
        self.genesis_time = genesis_time
        
        # Block storage
        self.blocks: Dict[str, BlockNode] = {genesis_block.block_hash: genesis_block}
        
        # Latest messages from validators (address -> LatestMessage)
        self.latest_messages: Dict[str, LatestMessage] = {}
        
        # Validator balances (address -> effective balance)
        self.balances: Dict[str, Decimal] = {}
        
        # Checkpoints
        self.justified_checkpoint = Checkpoint(epoch=0, root=genesis_block.block_hash)
        self.finalized_checkpoint = Checkpoint(epoch=0, root=genesis_block.block_hash)
        self.best_justified_checkpoint = Checkpoint(epoch=0, root=genesis_block.block_hash)
        
        # Checkpoint states (checkpoint -> set of attesting validators)
        self.checkpoint_states: Dict[Checkpoint, Set[str]] = defaultdict(set)
        
        # Equivocating validators (slashable)
        self.equivocating_indices: Set[str] = set()
        
        # Proposer boost
        self.proposer_boost_root: Optional[str] = None
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
        
        logger.info(f"ForkChoiceStore initialized with genesis: {genesis_block.block_hash[:16]}...")
    
    def get_ancestor(self, block_hash: str, slot: int) -> Optional[str]:
        """
        Get the ancestor of a block at a specific slot.
        
        Used for comparing blocks in different branches.
        """
        block = self.blocks.get(block_hash)
        if not block:
            return None
        
        while block.slot > slot:
            parent = self.blocks.get(block.parent_hash)
            if not parent:
                return None
            block = parent
        
        return block.block_hash if block.slot == slot else None
    
    def get_weight(self, block_hash: str) -> Decimal:
        """
        Calculate the weight of a block (sum of attesting validator balances).
        
        This implements the GHOST weighting mechanism.
        """
        weight = Decimal("0")
        
        for validator_address, message in self.latest_messages.items():
            # Skip equivocating validators
            if validator_address in self.equivocating_indices:
                continue
            
            # Check if this validator's latest message supports this block
            if self._is_supporting_block(message.root, block_hash):
                balance = self.balances.get(validator_address, Decimal("0"))
                weight += balance
        
        return weight
    
    def _is_supporting_block(self, attested_root: str, target_root: str) -> bool:
        """
        Check if an attestation to attested_root supports target_root.
        
        An attestation supports a block if the attested block is a descendant
        of the target block (or is the target itself).
        """
        current = attested_root
        visited = set()
        
        while current and current not in visited:
            if current == target_root:
                return True
            visited.add(current)
            block = self.blocks.get(current)
            if not block:
                break
            current = block.parent_hash
        
        return False
    
    def get_head(self) -> str:
        """
        Get the head of the chain using LMD-GHOST.
        
        Starts from justified checkpoint and greedily follows the heaviest subtree.
        
        Returns:
            Block hash of the chain head
        """
        # Start from justified checkpoint
        head = self.justified_checkpoint.root
        
        while True:
            block = self.blocks.get(head)
            if not block or not block.children:
                break
            
            # Find child with maximum weight
            best_child = None
            best_weight = Decimal("-1")
            best_root = ""
            
            for child_hash in block.children:
                child_weight = self.get_weight(child_hash)
                child_block = self.blocks.get(child_hash)
                
                # Tie-breaker: lexicographically higher hash wins
                if child_weight > best_weight or (
                    child_weight == best_weight and child_hash > best_root
                ):
                    best_weight = child_weight
                    best_child = child_hash
                    best_root = child_hash
            
            if best_child is None:
                break
            
            head = best_child
        
        return head
    
    async def on_block(self, block: BlockNode) -> bool:
        """
        Process a new block.
        
        Args:
            block: The block to add to the fork choice
            
        Returns:
            True if block was accepted
        """
        async with self._lock:
            # Validate parent exists
            if block.parent_hash not in self.blocks and block.slot > 0:
                logger.warning(f"Block {block.block_hash[:16]} has unknown parent")
                return False
            
            # Validate slot is not in the past relative to finalized checkpoint
            finalized_block = self.blocks.get(self.finalized_checkpoint.root)
            if finalized_block and block.slot <= finalized_block.slot:
                logger.warning(f"Block {block.block_hash[:16]} is not after finalized checkpoint")
                return False
            
            # Add block to store
            self.blocks[block.block_hash] = block
            
            # Update parent's children
            if block.parent_hash in self.blocks:
                parent = self.blocks[block.parent_hash]
                if block.block_hash not in parent.children:
                    parent.children.append(block.block_hash)
            
            logger.debug(f"Block added to fork choice: {block.block_hash[:16]} slot={block.slot}")
            return True
    
    async def on_attestation(
        self,
        validator_address: str,
        block_hash: str,
        source: Checkpoint,
        target: Checkpoint,
    ) -> bool:
        """
        Process an attestation.
        
        Args:
            validator_address: Address of attesting validator
            block_hash: Block being attested to
            source: Source checkpoint (must be justified)
            target: Target checkpoint (current epoch)
            
        Returns:
            True if attestation was accepted
        """
        async with self._lock:
            # Validate target block exists
            if block_hash not in self.blocks:
                logger.warning(f"Attestation references unknown block: {block_hash[:16]}")
                return False
            
            # Validate source is justified or genesis
            if source != self.justified_checkpoint and source.epoch != 0:
                # Check if source was ever justified
                pass  # Allow for now, strict validation in production
            
            # Update latest message if newer
            current_message = self.latest_messages.get(validator_address)
            if current_message is None or target.epoch > current_message.epoch:
                self.latest_messages[validator_address] = LatestMessage(
                    epoch=target.epoch,
                    root=block_hash,
                )
            
            # Track checkpoint attestations for FFG
            self.checkpoint_states[target].add(validator_address)
            
            logger.debug(
                f"Attestation processed: validator={validator_address[:16]} "
                f"block={block_hash[:16]} target_epoch={target.epoch}"
            )
            
            return True
    
    async def process_justification_finalization(
        self,
        current_epoch: int,
        total_active_balance: Decimal,
    ):
        """
        Process justification and finalization for Casper FFG.
        
        Called at the end of each epoch.
        """
        async with self._lock:
            # Calculate target checkpoint for current epoch
            current_target = self._get_epoch_boundary_block(current_epoch)
            if not current_target:
                return
            
            # Calculate previous epoch target
            previous_target = self._get_epoch_boundary_block(current_epoch - 1)
            
            # Count attestations for current epoch target
            current_epoch_checkpoint = Checkpoint(epoch=current_epoch, root=current_target)
            current_attesting_balance = self._get_attesting_balance(current_epoch_checkpoint)
            
            # Check for justification (2/3 threshold)
            threshold = total_active_balance * 2 / 3
            
            # Justify current epoch if threshold met
            if current_attesting_balance >= threshold:
                self.best_justified_checkpoint = current_epoch_checkpoint
                
                # Can only update justified if connects to current justified
                if self._is_descendant(
                    self.justified_checkpoint.root,
                    current_target
                ):
                    old_justified = self.justified_checkpoint
                    self.justified_checkpoint = current_epoch_checkpoint
                    
                    logger.info(
                        f"Checkpoint justified: epoch={current_epoch} "
                        f"root={current_target[:16]}"
                    )
                    
                    # Check for finalization
                    # Finalize if we have consecutive justified epochs
                    if old_justified.epoch == current_epoch - 1:
                        self.finalized_checkpoint = old_justified
                        
                        # Mark blocks as finalized
                        self._mark_finalized(old_justified.root)
                        
                        logger.info(
                            f"Checkpoint FINALIZED: epoch={old_justified.epoch} "
                            f"root={old_justified.root[:16]}"
                        )
    
    def _get_epoch_boundary_block(self, epoch: int) -> Optional[str]:
        """Get the block at the start of an epoch (epoch boundary)."""
        target_slot = epoch * self.slots_per_epoch
        
        # Find block at or before target slot on canonical chain
        head = self.get_head()
        return self.get_ancestor(head, target_slot)
    
    def _get_attesting_balance(self, checkpoint: Checkpoint) -> Decimal:
        """Get total balance attesting to a checkpoint."""
        attesters = self.checkpoint_states.get(checkpoint, set())
        return sum(
            self.balances.get(addr, Decimal("0"))
            for addr in attesters
            if addr not in self.equivocating_indices
        )
    
    def _is_descendant(self, ancestor_root: str, descendant_root: str) -> bool:
        """Check if descendant_root is a descendant of ancestor_root."""
        return self._is_supporting_block(descendant_root, ancestor_root)
    
    def _mark_finalized(self, root: str):
        """Mark a block and all ancestors as finalized."""
        current = root
        while current:
            block = self.blocks.get(current)
            if not block or block.finalized:
                break
            block.finalized = True
            current = block.parent_hash
    
    def update_balances(self, balances: Dict[str, Decimal]):
        """Update validator balances for weight calculation."""
        self.balances = balances.copy()
    
    def add_equivocation(self, validator_address: str):
        """Mark a validator as equivocating (slashable)."""
        self.equivocating_indices.add(validator_address)
        logger.warning(f"Validator marked as equivocating: {validator_address[:16]}")
    
    def is_finalized(self, block_hash: str) -> bool:
        """Check if a block is finalized."""
        block = self.blocks.get(block_hash)
        return block.finalized if block else False
    
    def get_finalized_head(self) -> str:
        """Get the finalized chain head."""
        return self.finalized_checkpoint.root
    
    def get_justified_head(self) -> str:
        """Get the justified chain head."""
        return self.justified_checkpoint.root


class ForkChoice:
    """
    High-level fork choice interface.
    
    Provides a clean API for the consensus layer to interact with fork choice.
    """
    
    def __init__(
        self,
        genesis_block_hash: str,
        genesis_state_root: str,
        genesis_time: int,
        slots_per_epoch: int = 32,
    ):
        # Create genesis block node
        genesis_block = BlockNode(
            block_hash=genesis_block_hash,
            parent_hash="0" * 64,
            slot=0,
            proposer_address="genesis",
            state_root=genesis_state_root,
            justified=True,
            finalized=True,
        )
        
        self.store = ForkChoiceStore(
            genesis_block=genesis_block,
            genesis_time=genesis_time,
            slots_per_epoch=slots_per_epoch,
        )
        
        self.slots_per_epoch = slots_per_epoch
    
    async def add_block(
        self,
        block_hash: str,
        parent_hash: str,
        slot: int,
        proposer_address: str,
        state_root: str,
    ) -> bool:
        """
        Add a new block to the fork choice.
        
        Returns:
            True if block was accepted
        """
        block = BlockNode(
            block_hash=block_hash,
            parent_hash=parent_hash,
            slot=slot,
            proposer_address=proposer_address,
            state_root=state_root,
        )
        
        return await self.store.on_block(block)
    
    async def add_attestation(
        self,
        validator_address: str,
        block_hash: str,
        source_epoch: int,
        source_root: str,
        target_epoch: int,
        target_root: str,
    ) -> bool:
        """
        Add an attestation to the fork choice.
        
        Returns:
            True if attestation was accepted
        """
        source = Checkpoint(epoch=source_epoch, root=source_root)
        target = Checkpoint(epoch=target_epoch, root=target_root)
        
        return await self.store.on_attestation(
            validator_address=validator_address,
            block_hash=block_hash,
            source=source,
            target=target,
        )
    
    def get_head(self) -> str:
        """Get the current chain head."""
        return self.store.get_head()
    
    def get_finalized_checkpoint(self) -> Tuple[int, str]:
        """Get the finalized checkpoint (epoch, root)."""
        cp = self.store.finalized_checkpoint
        return (cp.epoch, cp.root)
    
    def get_justified_checkpoint(self) -> Tuple[int, str]:
        """Get the justified checkpoint (epoch, root)."""
        cp = self.store.justified_checkpoint
        return (cp.epoch, cp.root)
    
    async def process_epoch(
        self,
        epoch: int,
        validator_balances: Dict[str, Decimal],
        total_active_balance: Decimal,
    ):
        """
        Process end-of-epoch justification and finalization.
        
        Args:
            epoch: The epoch that just ended
            validator_balances: Current validator effective balances
            total_active_balance: Total active stake
        """
        # Update balances
        self.store.update_balances(validator_balances)
        
        # Process Casper FFG
        await self.store.process_justification_finalization(
            current_epoch=epoch,
            total_active_balance=total_active_balance,
        )
    
    def is_finalized(self, block_hash: str) -> bool:
        """Check if a block is finalized."""
        return self.store.is_finalized(block_hash)
    
    def get_status(self) -> Dict[str, Any]:
        """Get fork choice status."""
        head = self.get_head()
        head_block = self.store.blocks.get(head)
        
        return {
            'head': head,
            'head_slot': head_block.slot if head_block else 0,
            'justified_epoch': self.store.justified_checkpoint.epoch,
            'justified_root': self.store.justified_checkpoint.root,
            'finalized_epoch': self.store.finalized_checkpoint.epoch,
            'finalized_root': self.store.finalized_checkpoint.root,
            'total_blocks': len(self.store.blocks),
            'total_attestations': len(self.store.latest_messages),
        }
