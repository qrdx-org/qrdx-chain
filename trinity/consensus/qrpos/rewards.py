"""
QR-PoS Rewards and Penalties Module

Implements validator rewards and penalties for QR-PoS consensus.
Incentivizes correct behavior and penalizes malicious/offline validators.
"""
from typing import Dict, List

from trinity.consensus.qrpos.constants import (
    BASE_REWARD_FACTOR,
    PROPOSER_REWARD_QUOTIENT,
    MIN_VALIDATOR_STAKE,
    INACTIVITY_PENALTY_QUOTIENT,
    MIN_SLASHING_PENALTY_QUOTIENT,
    PROPORTIONAL_SLASHING_MULTIPLIER,
    WHISTLEBLOWER_REWARD_QUOTIENT,
    MAX_EFFECTIVE_BALANCE,
)


def calculate_base_reward(
    effective_balance: int = MAX_EFFECTIVE_BALANCE,
    total_active_balance: int = None,
) -> int:
    """
    Calculate the base reward for a validator.
    
    Base reward is proportional to the validator's effective balance and
    inversely proportional to the square root of total active balance.
    
    Args:
        effective_balance: Validator's effective balance (capped at MAX_EFFECTIVE_BALANCE)
        total_active_balance: Total balance of all active validators
    
    Returns:
        Base reward in wei
    """
    if total_active_balance is None:
        # Assume minimum for calculation
        total_active_balance = MIN_VALIDATOR_STAKE * 64  # MIN_VALIDATORS
    
    # Prevent division by zero
    if total_active_balance == 0:
        return 0
    
    # Base reward formula (similar to Ethereum 2.0):
    # base_reward = effective_balance * BASE_REWARD_FACTOR / sqrt(total_active_balance)
    # We use integer approximation for sqrt
    sqrt_total = isqrt(total_active_balance)
    
    if sqrt_total == 0:
        return 0
    
    base_reward = (effective_balance * BASE_REWARD_FACTOR) // sqrt_total
    
    return base_reward


def isqrt(n: int) -> int:
    """
    Integer square root using Newton's method.
    
    Args:
        n: Non-negative integer
    
    Returns:
        Floor of the square root of n
    """
    if n == 0:
        return 0
    
    # Initial guess
    x = n
    y = (x + 1) // 2
    
    while y < x:
        x = y
        y = (x + n // x) // 2
    
    return x


class RewardsCalculator:
    """
    Calculates validator rewards and penalties for QR-PoS.
    """
    
    def __init__(self, total_active_balance: int):
        """
        Initialize the rewards calculator.
        
        Args:
            total_active_balance: Total balance of all active validators
        """
        self.total_active_balance = total_active_balance
    
    def get_proposer_reward(
        self,
        attestation_count: int,
        base_reward: int,
    ) -> int:
        """
        Calculate the block proposer reward.
        
        Proposers receive a fraction of the total attestation rewards
        for including attestations in their block.
        
        Args:
            attestation_count: Number of attestations included in the block
            base_reward: Base reward per validator
        
        Returns:
            Proposer reward in wei
        """
        total_attestation_rewards = base_reward * attestation_count
        proposer_reward = total_attestation_rewards // PROPOSER_REWARD_QUOTIENT
        
        return proposer_reward
    
    def get_attestation_reward(
        self,
        validator_effective_balance: int,
        attestation_inclusion_delay: int = 1,
    ) -> int:
        """
        Calculate the reward for a correct attestation.
        
        Validators are rewarded for:
        1. Attesting to the correct head
        2. Attesting to the correct source checkpoint
        3. Attesting to the correct target checkpoint
        4. Including attestations quickly
        
        Args:
            validator_effective_balance: Validator's effective balance
            attestation_inclusion_delay: Number of slots between attestation and inclusion
        
        Returns:
            Attestation reward in wei
        """
        base_reward = calculate_base_reward(
            validator_effective_balance,
            self.total_active_balance,
        )
        
        # Reward decreases with inclusion delay
        # Full reward if included in next slot, decreasing linearly
        if attestation_inclusion_delay < 1:
            attestation_inclusion_delay = 1
        
        reward = base_reward // attestation_inclusion_delay
        
        return reward
    
    def get_inactivity_penalty(
        self,
        validator_effective_balance: int,
        epochs_since_finality: int,
    ) -> int:
        """
        Calculate the inactivity penalty for a validator.
        
        During periods without finality (network not finalizing), inactive
        validators are penalized more heavily to encourage participation.
        
        Args:
            validator_effective_balance: Validator's effective balance
            epochs_since_finality: Number of epochs since last finality
        
        Returns:
            Inactivity penalty in wei (positive value to subtract)
        """
        if epochs_since_finality <= 4:
            return 0  # No inactivity penalty if finalizing regularly
        
        base_reward = calculate_base_reward(
            validator_effective_balance,
            self.total_active_balance,
        )
        
        # Penalty increases quadratically with time since finality
        penalty = (
            validator_effective_balance * epochs_since_finality
        ) // INACTIVITY_PENALTY_QUOTIENT
        
        return penalty
    
    def get_slashing_penalty(
        self,
        slashed_validator_balance: int,
        total_slashed_balance: int,
        time_since_slashing_epochs: int = 0,
    ) -> int:
        """
        Calculate the slashing penalty for a malicious validator.
        
        Slashed validators face:
        1. Immediate penalty (minimum)
        2. Proportional penalty based on total slashed balance
        3. Ongoing penalties until withdrawal
        
        Args:
            slashed_validator_balance: Balance of the slashed validator
            total_slashed_balance: Total balance of all slashed validators in this period
            time_since_slashing_epochs: Epochs since slashing occurred
        
        Returns:
            Slashing penalty in wei (positive value to subtract)
        """
        # Minimum slashing penalty (immediate)
        min_penalty = slashed_validator_balance // MIN_SLASHING_PENALTY_QUOTIENT
        
        # Proportional penalty (depends on how many validators are slashed)
        # If many validators are slashed together, penalties are higher
        # (indicates coordinated attack)
        proportional_penalty = (
            slashed_validator_balance * PROPORTIONAL_SLASHING_MULTIPLIER *
            min(total_slashed_balance, self.total_active_balance)
        ) // self.total_active_balance
        
        # Ongoing penalties until withdrawal (similar to inactivity)
        if time_since_slashing_epochs > 0:
            base_reward = calculate_base_reward(
                slashed_validator_balance,
                self.total_active_balance,
            )
            ongoing_penalty = base_reward * time_since_slashing_epochs
        else:
            ongoing_penalty = 0
        
        total_penalty = min_penalty + proportional_penalty + ongoing_penalty
        
        # Cap at validator's total balance
        return min(total_penalty, slashed_validator_balance)
    
    def get_whistleblower_reward(
        self,
        slashed_validator_balance: int,
    ) -> int:
        """
        Calculate the reward for reporting a slashable offense.
        
        Validators who report slashable behavior (e.g., double voting)
        receive a portion of the slashed validator's penalty.
        
        Args:
            slashed_validator_balance: Balance of the slashed validator
        
        Returns:
            Whistleblower reward in wei
        """
        slashing_penalty = slashed_validator_balance // MIN_SLASHING_PENALTY_QUOTIENT
        whistleblower_reward = slashing_penalty // WHISTLEBLOWER_REWARD_QUOTIENT
        
        return whistleblower_reward


class ValidatorRewards:
    """
    Tracks and calculates rewards for individual validators.
    """
    
    def __init__(self):
        """Initialize validator rewards tracking."""
        # Rewards by validator address
        self._rewards: Dict[bytes, int] = {}
        
        # Penalties by validator address
        self._penalties: Dict[bytes, int] = {}
        
        # Attestation counts by validator
        self._attestations: Dict[bytes, int] = {}
        
        # Proposals by validator
        self._proposals: Dict[bytes, int] = {}
    
    def add_reward(self, validator_pq_address: bytes, amount: int) -> None:
        """
        Add a reward for a validator.
        
        Args:
            validator_pq_address: Validator's PQ address
            amount: Reward amount in wei
        """
        if validator_pq_address not in self._rewards:
            self._rewards[validator_pq_address] = 0
        
        self._rewards[validator_pq_address] += amount
    
    def add_penalty(self, validator_pq_address: bytes, amount: int) -> None:
        """
        Add a penalty for a validator.
        
        Args:
            validator_pq_address: Validator's PQ address
            amount: Penalty amount in wei (positive value)
        """
        if validator_pq_address not in self._penalties:
            self._penalties[validator_pq_address] = 0
        
        self._penalties[validator_pq_address] += amount
    
    def record_attestation(self, validator_pq_address: bytes) -> None:
        """
        Record that a validator made an attestation.
        
        Args:
            validator_pq_address: Validator's PQ address
        """
        if validator_pq_address not in self._attestations:
            self._attestations[validator_pq_address] = 0
        
        self._attestations[validator_pq_address] += 1
    
    def record_proposal(self, validator_pq_address: bytes) -> None:
        """
        Record that a validator proposed a block.
        
        Args:
            validator_pq_address: Validator's PQ address
        """
        if validator_pq_address not in self._proposals:
            self._proposals[validator_pq_address] = 0
        
        self._proposals[validator_pq_address] += 1
    
    def get_net_reward(self, validator_pq_address: bytes) -> int:
        """
        Get the net reward (rewards - penalties) for a validator.
        
        Args:
            validator_pq_address: Validator's PQ address
        
        Returns:
            Net reward in wei (can be negative if penalties exceed rewards)
        """
        rewards = self._rewards.get(validator_pq_address, 0)
        penalties = self._penalties.get(validator_pq_address, 0)
        
        return rewards - penalties
    
    def get_total_rewards(self, validator_pq_address: bytes) -> int:
        """
        Get total rewards for a validator.
        
        Args:
            validator_pq_address: Validator's PQ address
        
        Returns:
            Total rewards in wei
        """
        return self._rewards.get(validator_pq_address, 0)
    
    def get_total_penalties(self, validator_pq_address: bytes) -> int:
        """
        Get total penalties for a validator.
        
        Args:
            validator_pq_address: Validator's PQ address
        
        Returns:
            Total penalties in wei
        """
        return self._penalties.get(validator_pq_address, 0)
    
    def get_attestation_count(self, validator_pq_address: bytes) -> int:
        """
        Get number of attestations made by a validator.
        
        Args:
            validator_pq_address: Validator's PQ address
        
        Returns:
            Number of attestations
        """
        return self._attestations.get(validator_pq_address, 0)
    
    def get_proposal_count(self, validator_pq_address: bytes) -> int:
        """
        Get number of blocks proposed by a validator.
        
        Args:
            validator_pq_address: Validator's PQ address
        
        Returns:
            Number of proposals
        """
        return self._proposals.get(validator_pq_address, 0)
    
    def reset_epoch_data(self) -> None:
        """
        Reset epoch-specific data (attestations, proposals).
        Should be called at the start of each epoch.
        """
        self._attestations.clear()
        self._proposals.clear()
    
    def get_all_validators(self) -> List[bytes]:
        """
        Get list of all validators with recorded activity.
        
        Returns:
            List of validator PQ addresses
        """
        all_validators = set()
        all_validators.update(self._rewards.keys())
        all_validators.update(self._penalties.keys())
        all_validators.update(self._attestations.keys())
        all_validators.update(self._proposals.keys())
        
        return list(all_validators)
