"""
QR-PoS State Management Module

Manages the beacon state for QR-PoS consensus including validator registry,
checkpoints, and state transitions.
"""
from typing import Dict, List, Optional

from eth_typing import Hash32
from eth_utils import ValidationError, encode_hex

from trinity.consensus.qrpos.constants import (
    SLOTS_PER_EPOCH,
    GENESIS_EPOCH,
    MAX_VALIDATORS,
)
from trinity.consensus.qrpos.validator import Validator, ValidatorRegistry, ValidatorStatus
from trinity.consensus.qrpos.finality import Checkpoint, CasperFFG
from trinity.consensus.qrpos.rewards import RewardsCalculator, ValidatorRewards


class BeaconState:
    """
    Represents the complete state of the QR-PoS beacon chain.
    
    This includes:
    - Current slot/epoch
    - Validator registry and balances
    - Finality checkpoints
    - Block roots history
    - Rewards and penalties
    """
    
    def __init__(
        self,
        genesis_slot: int = 0,
        genesis_validators: Optional[List[Validator]] = None,
        genesis_state_root: Optional[Hash32] = None,
    ):
        """
        Initialize the beacon state.
        
        Args:
            genesis_slot: Initial slot number (typically 0)
            genesis_validators: List of genesis validators
            genesis_state_root: Root hash of the genesis state
        """
        # Slot and epoch tracking
        self.slot = genesis_slot
        self.previous_slot = genesis_slot
        
        # Validator registry
        self.validator_registry = ValidatorRegistry()
        
        # Initialize genesis validators
        if genesis_validators:
            for validator in genesis_validators:
                # Genesis validators are immediately active
                self.validator_registry._validators[validator.pq_address] = validator
        
        # Finality tracking
        genesis_checkpoint = Checkpoint(
            epoch=GENESIS_EPOCH,
            block_hash=genesis_state_root or Hash32(b'\x00' * 32),
        )
        self.finality_gadget = CasperFFG(genesis_checkpoint)
        
        # Block roots (for LMD-GHOST)
        self._block_roots: Dict[int, Hash32] = {}  # slot -> block_hash
        
        # State roots (for state verification)
        self._state_roots: Dict[int, Hash32] = {}  # slot -> state_root
        
        # Rewards and penalties tracking
        self.rewards = ValidatorRewards()
        
        # Total active balance cache
        self._total_active_balance: Optional[int] = None
        self._total_active_balance_epoch: int = -1
    
    @property
    def current_epoch(self) -> int:
        """Get the current epoch number."""
        return self.slot // SLOTS_PER_EPOCH
    
    @property
    def previous_epoch(self) -> int:
        """Get the previous epoch number."""
        return max(0, self.current_epoch - 1)
    
    def get_epoch_start_slot(self, epoch: int) -> int:
        """
        Get the first slot of an epoch.
        
        Args:
            epoch: Epoch number
        
        Returns:
            Slot number
        """
        return epoch * SLOTS_PER_EPOCH
    
    def get_total_active_balance(self, epoch: Optional[int] = None) -> int:
        """
        Get the total balance of all active validators in an epoch.
        
        Args:
            epoch: Epoch number (uses current epoch if None)
        
        Returns:
            Total active balance in wei
        """
        if epoch is None:
            epoch = self.current_epoch
        
        # Use cached value if available and current
        if epoch == self._total_active_balance_epoch and self._total_active_balance is not None:
            return self._total_active_balance
        
        # Calculate total balance
        active_validators = self.validator_registry.get_active_validators(epoch)
        total_balance = sum(
            self.validator_registry.get_validator(addr).effective_balance
            for addr in active_validators
        )
        
        # Cache for current epoch
        if epoch == self.current_epoch:
            self._total_active_balance = total_balance
            self._total_active_balance_epoch = epoch
        
        return total_balance
    
    def advance_slot(self, new_slot: int, block_hash: Hash32, state_root: Hash32) -> None:
        """
        Advance the beacon state to a new slot.
        
        Args:
            new_slot: New slot number
            block_hash: Hash of the block at this slot
            state_root: Root hash of the state after this slot
        
        Raises:
            ValidationError: If new_slot is not greater than current slot
        """
        if new_slot <= self.slot:
            raise ValidationError(
                f"Cannot advance to slot {new_slot}, current slot is {self.slot}"
            )
        
        self.previous_slot = self.slot
        self.slot = new_slot
        
        # Record block and state roots
        self._block_roots[new_slot] = block_hash
        self._state_roots[new_slot] = state_root
        
        # Check if we entered a new epoch
        current_epoch = self.current_epoch
        previous_epoch = self.previous_slot // SLOTS_PER_EPOCH
        
        if current_epoch > previous_epoch:
            self._on_new_epoch(current_epoch)
    
    def _on_new_epoch(self, new_epoch: int) -> None:
        """
        Handle epoch transition.
        
        Args:
            new_epoch: New epoch number
        """
        # Process epoch transition
        self._process_epoch_transition(new_epoch - 1)
        
        # Reset epoch-specific data
        self.rewards.reset_epoch_data()
        
        # Invalidate cache
        self._total_active_balance = None
        self._total_active_balance_epoch = -1
    
    def _process_epoch_transition(self, completed_epoch: int) -> None:
        """
        Process rewards, penalties, and validator state changes for a completed epoch.
        
        Args:
            completed_epoch: Epoch that just completed
        """
        # Get active validators for the completed epoch
        active_validators = self.validator_registry.get_active_validators(completed_epoch)
        total_balance = sum(
            self.validator_registry.get_validator(addr).effective_balance
            for addr in active_validators
        )
        
        # Initialize rewards calculator
        calculator = RewardsCalculator(total_balance)
        
        # Process rewards and penalties for each validator
        for validator_addr in active_validators:
            validator = self.validator_registry.get_validator(validator_addr)
            
            # Calculate attestation rewards
            attestation_count = self.rewards.get_attestation_count(validator_addr)
            if attestation_count > 0:
                attestation_reward = calculator.get_attestation_reward(
                    validator.effective_balance,
                    attestation_inclusion_delay=1,
                )
                self.rewards.add_reward(validator_addr, attestation_reward)
            
            # Calculate proposal rewards
            proposal_count = self.rewards.get_proposal_count(validator_addr)
            if proposal_count > 0:
                # Assume average attestation inclusion
                proposer_reward = calculator.get_proposer_reward(
                    attestation_count=len(active_validators) // 2,
                    base_reward=attestation_reward if attestation_count > 0 else 0,
                )
                self.rewards.add_reward(validator_addr, proposer_reward)
            
            # Apply inactivity penalties if not finalizing
            finalized_checkpoint = self.finality_gadget.get_latest_finalized()
            epochs_since_finality = completed_epoch - finalized_checkpoint.epoch
            
            if epochs_since_finality > 4 and attestation_count == 0:
                # Validator was inactive during no-finality period
                inactivity_penalty = calculator.get_inactivity_penalty(
                    validator.effective_balance,
                    epochs_since_finality,
                )
                self.rewards.add_penalty(validator_addr, inactivity_penalty)
            
            # Update validator balance
            net_reward = self.rewards.get_net_reward(validator_addr)
            new_balance = max(0, validator.stake + net_reward)
            validator.stake = new_balance
            validator.effective_balance = min(new_balance, validator.effective_balance)
        
        # Process validator lifecycle transitions
        self._process_validator_lifecycle(completed_epoch)
    
    def _process_validator_lifecycle(self, epoch: int) -> None:
        """
        Process validator activation, exit, and withdrawal.
        
        Args:
            epoch: Current epoch
        """
        from trinity.consensus.qrpos.constants import (
            VALIDATOR_ACTIVATION_DELAY,
            MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
        )
        
        for validator in self.validator_registry._validators.values():
            # Activate pending validators
            if (validator.status == ValidatorStatus.PENDING and
                epoch >= validator.activation_epoch):
                validator.status = ValidatorStatus.ACTIVE
            
            # Process exit requests
            if (validator.status == ValidatorStatus.ACTIVE and
                epoch >= validator.exit_epoch):
                validator.status = ValidatorStatus.EXITING
            
            # Complete exits
            if (validator.status == ValidatorStatus.EXITING and
                epoch >= validator.exit_epoch + VALIDATOR_ACTIVATION_DELAY):
                validator.status = ValidatorStatus.EXITED
                validator.withdrawable_epoch = epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY
            
            # Enable withdrawals
            if (validator.status == ValidatorStatus.EXITED and
                epoch >= validator.withdrawable_epoch):
                validator.status = ValidatorStatus.WITHDRAWABLE
    
    def get_block_root(self, slot: int) -> Optional[Hash32]:
        """
        Get the block root at a specific slot.
        
        Args:
            slot: Slot number
        
        Returns:
            Block hash, or None if not found
        """
        return self._block_roots.get(slot)
    
    def get_state_root(self, slot: int) -> Optional[Hash32]:
        """
        Get the state root at a specific slot.
        
        Args:
            slot: Slot number
        
        Returns:
            State root hash, or None if not found
        """
        return self._state_roots.get(slot)
    
    def get_checkpoint_for_epoch(self, epoch: int) -> Optional[Checkpoint]:
        """
        Get the checkpoint (epoch boundary block) for an epoch.
        
        Args:
            epoch: Epoch number
        
        Returns:
            Checkpoint, or None if not found
        """
        epoch_start_slot = self.get_epoch_start_slot(epoch)
        block_hash = self.get_block_root(epoch_start_slot)
        
        if block_hash:
            return Checkpoint(epoch, block_hash)
        
        return None
    
    def add_validator(
        self,
        pq_pubkey: bytes,
        stake: int,
        withdrawal_credentials: bytes,
        signature: bytes,
    ) -> bytes:
        """
        Add a new validator to the registry.
        
        Args:
            pq_pubkey: Dilithium public key (2592 bytes)
            stake: Initial stake amount
            withdrawal_credentials: Withdrawal credentials
            signature: Dilithium signature over deposit data
        
        Returns:
            PQ address of the new validator
        """
        return self.validator_registry.add_validator(
            pq_pubkey=pq_pubkey,
            stake=stake,
            withdrawal_credentials=withdrawal_credentials,
            current_epoch=self.current_epoch,
            signature=signature,
        )
    
    def slash_validator(
        self,
        validator_pq_address: bytes,
        slashing_reason: str,
    ) -> None:
        """
        Slash a validator for a slashable offense.
        
        Args:
            validator_pq_address: Validator's PQ address
            slashing_reason: Reason for slashing (for audit trail)
        """
        validator = self.validator_registry.get_validator(validator_pq_address)
        if validator is None:
            raise ValidationError(f"Unknown validator: {encode_hex(validator_pq_address)}")
        
        # Slash the validator
        self.validator_registry.slash_validator(
            pq_address=validator_pq_address,
            current_epoch=self.current_epoch,
            slashing_reason=slashing_reason,
        )
        
        # Calculate and apply slashing penalty
        total_active_balance = self.get_total_active_balance()
        calculator = RewardsCalculator(total_active_balance)
        
        # Get total slashed balance (for proportional penalty)
        total_slashed = sum(
            v.stake for v in self.validator_registry._validators.values()
            if v.slashed
        )
        
        slashing_penalty = calculator.get_slashing_penalty(
            slashed_validator_balance=validator.stake,
            total_slashed_balance=total_slashed,
            time_since_slashing_epochs=0,
        )
        
        self.rewards.add_penalty(validator_pq_address, slashing_penalty)
        
        # Update validator balance
        validator.stake = max(0, validator.stake - slashing_penalty)
        validator.effective_balance = min(validator.stake, validator.effective_balance)
    
    def copy(self) -> 'BeaconState':
        """
        Create a copy of this beacon state.
        
        Returns:
            New BeaconState with copied data
        """
        # This is a simplified copy - in production, we would use more
        # efficient copy-on-write structures
        new_state = BeaconState(
            genesis_slot=0,
            genesis_validators=None,
            genesis_state_root=None,
        )
        
        new_state.slot = self.slot
        new_state.previous_slot = self.previous_slot
        
        # Deep copy validator registry
        new_state.validator_registry = self.validator_registry  # TODO: implement proper copy
        
        # Copy finality state
        new_state.finality_gadget = self.finality_gadget  # TODO: implement proper copy
        
        # Copy block and state roots
        new_state._block_roots = self._block_roots.copy()
        new_state._state_roots = self._state_roots.copy()
        
        return new_state
    
    def get_validator_count(self, status: Optional[ValidatorStatus] = None) -> int:
        """
        Get the count of validators with a specific status.
        
        Args:
            status: Validator status to count (None for all validators)
        
        Returns:
            Number of validators
        """
        if status is None:
            return len(self.validator_registry._validators)
        
        count = 0
        for validator in self.validator_registry._validators.values():
            if validator.status == status:
                count += 1
        
        return count
    
    def is_at_capacity(self) -> bool:
        """
        Check if the validator set is at maximum capacity.
        
        Returns:
            True if at MAX_VALIDATORS
        """
        return self.get_validator_count() >= MAX_VALIDATORS
