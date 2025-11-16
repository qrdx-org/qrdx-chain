"""
QR-PoS Fork Choice Module

Implements LMD-GHOST (Latest Message Driven Greedy Heaviest Observed SubTree)
fork choice rule for quantum-resistant proof of stake.
"""
from typing import Dict, List, Optional, Set

from eth_typing import Hash32
from eth_utils import encode_hex, ValidationError

from trinity.crypto.pq.blake3_hash import blake3_hash
from trinity.consensus.qrpos.constants import (
    SLOTS_PER_EPOCH,
    FINALITY_THRESHOLD,
)


class Vote:
    """Represents a validator's vote (attestation) for a block"""
    
    def __init__(
        self,
        validator_pq_address: bytes,
        block_hash: Hash32,
        slot: int,
        weight: int,
    ):
        """
        Initialize a vote.
        
        Args:
            validator_pq_address: 32-byte PQ address of the validator
            block_hash: Hash of the block being voted for
            slot: Slot number of the vote
            weight: Validator's effective balance (voting weight)
        """
        self.validator_pq_address = validator_pq_address
        self.block_hash = block_hash
        self.slot = slot
        self.weight = weight


class BlockNode:
    """Represents a block in the fork choice tree"""
    
    def __init__(
        self,
        block_hash: Hash32,
        parent_hash: Hash32,
        slot: int,
        state_root: Hash32,
    ):
        """
        Initialize a block node.
        
        Args:
            block_hash: Hash of this block
            parent_hash: Hash of the parent block
            slot: Slot number of this block
            state_root: Root hash of the state after this block
        """
        self.block_hash = block_hash
        self.parent_hash = parent_hash
        self.slot = slot
        self.state_root = state_root
        self.children: List[Hash32] = []  # Child block hashes
        self.total_weight: int = 0  # Total validator weight supporting this subtree
        self.finalized: bool = False  # Whether this block is finalized


class LMDGHOSTForkChoice:
    """
    LMD-GHOST fork choice implementation for QR-PoS.
    
    LMD-GHOST (Latest Message Driven Greedy Heaviest Observed SubTree) selects
    the canonical chain by following the subtree with the most validator weight
    at each fork, using only the latest vote from each validator.
    """
    
    def __init__(self, genesis_hash: Hash32, genesis_slot: int = 0):
        """
        Initialize the fork choice rule.
        
        Args:
            genesis_hash: Hash of the genesis block
            genesis_slot: Slot number of genesis (typically 0)
        """
        self.genesis_hash = genesis_hash
        
        # Block tree
        self._blocks: Dict[Hash32, BlockNode] = {}
        
        # Genesis block
        genesis_node = BlockNode(
            block_hash=genesis_hash,
            parent_hash=Hash32(b'\x00' * 32),
            slot=genesis_slot,
            state_root=Hash32(b'\x00' * 32),  # Will be set properly
        )
        genesis_node.finalized = True
        self._blocks[genesis_hash] = genesis_node
        
        # Latest votes from each validator (LMD = Latest Message Driven)
        self._latest_votes: Dict[bytes, Vote] = {}  # validator_address -> Vote
        
        # Finalized checkpoint
        self._finalized_checkpoint_hash = genesis_hash
        self._finalized_checkpoint_slot = genesis_slot
        
        # Justified checkpoint (supermajority support, not yet finalized)
        self._justified_checkpoint_hash = genesis_hash
        self._justified_checkpoint_slot = genesis_slot
    
    def add_block(
        self,
        block_hash: Hash32,
        parent_hash: Hash32,
        slot: int,
        state_root: Hash32,
    ) -> None:
        """
        Add a block to the fork choice tree.
        
        Args:
            block_hash: Hash of the block
            parent_hash: Hash of the parent block
            slot: Slot number
            state_root: State root after this block
        
        Raises:
            ValidationError: If parent block is not known
        """
        if block_hash in self._blocks:
            return  # Already added
        
        # Verify parent exists
        if parent_hash not in self._blocks:
            raise ValidationError(
                f"Parent block {encode_hex(parent_hash)} not found for "
                f"block {encode_hex(block_hash)}"
            )
        
        # Create block node
        node = BlockNode(block_hash, parent_hash, slot, state_root)
        self._blocks[block_hash] = node
        
        # Add to parent's children
        self._blocks[parent_hash].children.append(block_hash)
    
    def add_vote(self, vote: Vote) -> None:
        """
        Add or update a validator's vote.
        Only the latest vote from each validator is kept (LMD).
        
        Args:
            vote: Validator's vote for a block
        """
        validator_addr = vote.validator_pq_address
        
        # Check if this is a newer vote from this validator
        if validator_addr in self._latest_votes:
            existing_vote = self._latest_votes[validator_addr]
            if vote.slot <= existing_vote.slot:
                return  # Ignore older votes
        
        # Store latest vote
        self._latest_votes[validator_addr] = vote
        
        # Recompute weights (will be done in get_head())
    
    def _compute_subtree_weight(self, block_hash: Hash32) -> int:
        """
        Compute the total validator weight supporting this subtree.
        Uses latest votes only (LMD).
        
        Args:
            block_hash: Root of the subtree
        
        Returns:
            Total weight of validators whose latest vote is in this subtree
        """
        if block_hash not in self._blocks:
            return 0
        
        # Get all blocks in this subtree
        subtree_blocks = self._get_subtree_blocks(block_hash)
        
        # Sum weight of validators voting for any block in this subtree
        total_weight = 0
        for vote in self._latest_votes.values():
            if vote.block_hash in subtree_blocks:
                total_weight += vote.weight
        
        return total_weight
    
    def _get_subtree_blocks(self, root_hash: Hash32) -> Set[Hash32]:
        """
        Get all block hashes in the subtree rooted at the given block.
        
        Args:
            root_hash: Root of the subtree
        
        Returns:
            Set of all block hashes in the subtree (including root)
        """
        if root_hash not in self._blocks:
            return set()
        
        subtree = {root_hash}
        node = self._blocks[root_hash]
        
        # Recursively add all descendants
        for child_hash in node.children:
            subtree.update(self._get_subtree_blocks(child_hash))
        
        return subtree
    
    def get_head(self) -> Hash32:
        """
        Get the head of the canonical chain using LMD-GHOST.
        
        Starting from the finalized checkpoint, at each fork choose the child
        with the heaviest subtree (most validator weight).
        
        Returns:
            Hash of the head block
        """
        # Start from finalized checkpoint (cannot reorg past finality)
        current_hash = self._finalized_checkpoint_hash
        
        while True:
            node = self._blocks[current_hash]
            
            # If no children, this is the head
            if not node.children:
                return current_hash
            
            # Find child with heaviest subtree (GHOST = Greedy Heaviest Observed SubTree)
            best_child = None
            best_weight = -1
            
            for child_hash in node.children:
                weight = self._compute_subtree_weight(child_hash)
                if weight > best_weight:
                    best_weight = weight
                    best_child = child_hash
            
            # Move to the heaviest child
            if best_child is None:
                return current_hash  # No valid child
            
            current_hash = best_child
    
    def get_ancestor(self, block_hash: Hash32, slot: int) -> Optional[Hash32]:
        """
        Get the ancestor of a block at a specific slot.
        
        Args:
            block_hash: Hash of the block
            slot: Target slot number
        
        Returns:
            Hash of the ancestor at the given slot, or None if not found
        """
        if block_hash not in self._blocks:
            return None
        
        current_hash = block_hash
        
        while current_hash in self._blocks:
            node = self._blocks[current_hash]
            
            if node.slot == slot:
                return current_hash
            
            if node.slot < slot:
                return None  # Went too far back
            
            current_hash = node.parent_hash
        
        return None
    
    def is_descendant(self, ancestor_hash: Hash32, descendant_hash: Hash32) -> bool:
        """
        Check if one block is a descendant of another.
        
        Args:
            ancestor_hash: Potential ancestor block
            descendant_hash: Potential descendant block
        
        Returns:
            True if descendant_hash is a descendant of ancestor_hash
        """
        if ancestor_hash == descendant_hash:
            return True
        
        if descendant_hash not in self._blocks:
            return False
        
        current_hash = descendant_hash
        
        while current_hash in self._blocks:
            if current_hash == ancestor_hash:
                return True
            
            node = self._blocks[current_hash]
            current_hash = node.parent_hash
            
            # Reached genesis or unknown block
            if current_hash == Hash32(b'\x00' * 32):
                break
        
        return False
    
    def update_justified_checkpoint(
        self,
        checkpoint_hash: Hash32,
        checkpoint_slot: int,
        total_validator_weight: int,
        supporting_weight: int,
    ) -> None:
        """
        Update the justified checkpoint if supermajority is reached.
        
        A checkpoint is justified if it has support from >2/3 of validators.
        
        Args:
            checkpoint_hash: Hash of the checkpoint block
            checkpoint_slot: Slot of the checkpoint
            total_validator_weight: Total weight of all active validators
            supporting_weight: Weight of validators supporting this checkpoint
        """
        # Check supermajority (>2/3)
        if supporting_weight * 3 > total_validator_weight * 2:
            # This checkpoint has >2/3 support
            if checkpoint_slot > self._justified_checkpoint_slot:
                self._justified_checkpoint_hash = checkpoint_hash
                self._justified_checkpoint_slot = checkpoint_slot
    
    def update_finalized_checkpoint(
        self,
        checkpoint_hash: Hash32,
        checkpoint_slot: int,
    ) -> None:
        """
        Update the finalized checkpoint.
        
        A checkpoint is finalized when the next epoch's checkpoint is justified
        (Casper FFG finality). Once finalized, blocks cannot be reverted.
        
        Args:
            checkpoint_hash: Hash of the finalized block
            checkpoint_slot: Slot of the finalized block
        """
        if checkpoint_slot > self._finalized_checkpoint_slot:
            # Verify the checkpoint is justified
            if checkpoint_hash == self._justified_checkpoint_hash:
                self._finalized_checkpoint_hash = checkpoint_hash
                self._finalized_checkpoint_slot = checkpoint_slot
                
                # Mark block as finalized
                if checkpoint_hash in self._blocks:
                    self._blocks[checkpoint_hash].finalized = True
                
                # Prune blocks not on the finalized chain
                self._prune_non_finalized_branches(checkpoint_hash)
    
    def _prune_non_finalized_branches(self, finalized_hash: Hash32) -> None:
        """
        Remove blocks that are not ancestors of the finalized block.
        This is safe because finalized blocks cannot be reverted.
        
        Args:
            finalized_hash: Hash of the newly finalized block
        """
        # Find all ancestors of the finalized block
        finalized_ancestors = set()
        current_hash = finalized_hash
        
        while current_hash in self._blocks:
            finalized_ancestors.add(current_hash)
            node = self._blocks[current_hash]
            current_hash = node.parent_hash
            
            if current_hash == Hash32(b'\x00' * 32):
                break
        
        # Remove blocks not in the finalized chain
        blocks_to_remove = []
        for block_hash in self._blocks:
            if block_hash not in finalized_ancestors:
                # Check if this block is a descendant of finalized block
                if not self.is_descendant(finalized_hash, block_hash):
                    blocks_to_remove.append(block_hash)
        
        for block_hash in blocks_to_remove:
            del self._blocks[block_hash]
    
    def get_finalized_checkpoint(self) -> tuple[Hash32, int]:
        """
        Get the current finalized checkpoint.
        
        Returns:
            Tuple of (block_hash, slot)
        """
        return (self._finalized_checkpoint_hash, self._finalized_checkpoint_slot)
    
    def get_justified_checkpoint(self) -> tuple[Hash32, int]:
        """
        Get the current justified checkpoint.
        
        Returns:
            Tuple of (block_hash, slot)
        """
        return (self._justified_checkpoint_hash, self._justified_checkpoint_slot)
