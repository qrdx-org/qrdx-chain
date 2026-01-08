"""
QRDX Validator Configuration

Configuration classes for validator operations.
"""

import os
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Optional, Dict, Any

try:
    import tomli
except ImportError:
    import tomllib as tomli


@dataclass
class StakingConfig:
    """Staking parameters configuration."""
    
    # Minimum stake to become a validator (100,000 QRDX)
    min_validator_stake: Decimal = Decimal("100000")
    
    # Minimum delegation amount (100 QRDX)
    min_delegation: Decimal = Decimal("100")
    
    # Unbonding period in epochs (approximately 7 days with 64s epochs)
    unbonding_epochs: int = 9450  # ~7 days
    
    # Maximum validators in active set
    max_validators: int = 150
    
    # Auto-restake rewards
    auto_restake_rewards: bool = True
    
    # Target stake amount for this validator
    target_stake: Decimal = Decimal("100000")


@dataclass
class SlashingProtectionConfig:
    """Slashing protection configuration."""
    
    # Enable slashing protection database
    enabled: bool = True
    
    # Path to slashing protection database
    db_path: str = "slashing_protection.db"
    
    # Maximum slots to track (for memory efficiency)
    max_tracked_slots: int = 100000


@dataclass
class AttestationConfig:
    """Attestation configuration."""
    
    # Attestation aggregation delay (seconds)
    aggregation_delay: float = 0.5
    
    # Maximum attestations per block
    max_attestations_per_block: int = 128
    
    # Attestation inclusion distance (slots)
    max_inclusion_distance: int = 32


@dataclass
class ValidatorConfig:
    """
    Main validator configuration.
    
    Loaded from config.toml [validator] section.
    """
    
    # Validator enabled/disabled
    enabled: bool = False
    
    # Path to PQ wallet file (REQUIRED if enabled)
    pq_wallet_path: str = ""
    
    # Wallet password (prefer environment variable)
    pq_wallet_password: str = ""
    
    # Validator fee recipient address (for rewards)
    fee_recipient: str = ""
    
    # Staking configuration
    staking: StakingConfig = field(default_factory=StakingConfig)
    
    # Slashing protection configuration
    slashing_protection: SlashingProtectionConfig = field(default_factory=SlashingProtectionConfig)
    
    # Attestation configuration
    attestation: AttestationConfig = field(default_factory=AttestationConfig)
    
    # Graffiti (included in proposed blocks)
    graffiti: str = "QRDX-QR-PoS"
    
    # Network endpoints
    beacon_api_url: str = "http://127.0.0.1:5052"
    
    def __post_init__(self):
        """Post-initialization validation."""
        # Get password from environment if not set
        if not self.pq_wallet_password:
            self.pq_wallet_password = os.environ.get("QRDX_VALIDATOR_PASSWORD", "")
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ValidatorConfig':
        """Create from dictionary."""
        # Parse nested configurations
        staking_data = data.pop('staking', {})
        slashing_data = data.pop('slashing_protection', {})
        attestation_data = data.pop('attestation', {})
        
        staking = StakingConfig(
            min_validator_stake=Decimal(str(staking_data.get('min_validator_stake', 100000))),
            min_delegation=Decimal(str(staking_data.get('min_delegation', 100))),
            unbonding_epochs=staking_data.get('unbonding_epochs', 9450),
            max_validators=staking_data.get('max_validators', 150),
            auto_restake_rewards=staking_data.get('auto_restake_rewards', True),
            target_stake=Decimal(str(staking_data.get('target_stake', 100000))),
        )
        
        slashing_protection = SlashingProtectionConfig(
            enabled=slashing_data.get('enabled', True),
            db_path=slashing_data.get('db_path', 'slashing_protection.db'),
            max_tracked_slots=slashing_data.get('max_tracked_slots', 100000),
        )
        
        attestation = AttestationConfig(
            aggregation_delay=attestation_data.get('aggregation_delay', 0.5),
            max_attestations_per_block=attestation_data.get('max_attestations_per_block', 128),
            max_inclusion_distance=attestation_data.get('max_inclusion_distance', 32),
        )
        
        return cls(
            enabled=data.get('enabled', False),
            pq_wallet_path=data.get('pq_wallet_path', ''),
            pq_wallet_password=data.get('pq_wallet_password', ''),
            fee_recipient=data.get('fee_recipient', ''),
            staking=staking,
            slashing_protection=slashing_protection,
            attestation=attestation,
            graffiti=data.get('graffiti', 'QRDX-QR-PoS'),
            beacon_api_url=data.get('beacon_api_url', 'http://127.0.0.1:5052'),
        )
    
    @classmethod
    def from_file(cls, config_path: str) -> 'ValidatorConfig':
        """
        Load configuration from TOML file.
        
        Args:
            config_path: Path to config.toml
            
        Returns:
            ValidatorConfig instance
        """
        path = Path(config_path)
        
        if not path.exists():
            # Return default config if file doesn't exist
            return cls()
        
        with open(path, 'rb') as f:
            config_data = tomli.load(f)
        
        validator_data = config_data.get('validator', {})
        return cls.from_dict(validator_data)
    
    def validate(self) -> bool:
        """
        Validate configuration.
        
        Returns:
            True if valid
            
        Raises:
            ValueError: If configuration is invalid
        """
        if not self.enabled:
            return True  # No validation needed if disabled
        
        # Check PQ wallet path
        if not self.pq_wallet_path:
            raise ValueError("pq_wallet_path is required when validator is enabled")
        
        wallet_path = Path(self.pq_wallet_path)
        if not wallet_path.exists():
            raise ValueError(f"PQ wallet file not found: {self.pq_wallet_path}")
        
        # Validate stake requirement
        if self.staking.min_validator_stake <= 0:
            raise ValueError("min_validator_stake must be positive")
        
        # Validate max validators
        if self.staking.max_validators < 1:
            raise ValueError("max_validators must be at least 1")
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'enabled': self.enabled,
            'pq_wallet_path': self.pq_wallet_path,
            'fee_recipient': self.fee_recipient,
            'graffiti': self.graffiti,
            'beacon_api_url': self.beacon_api_url,
            'staking': {
                'min_validator_stake': str(self.staking.min_validator_stake),
                'min_delegation': str(self.staking.min_delegation),
                'unbonding_epochs': self.staking.unbonding_epochs,
                'max_validators': self.staking.max_validators,
                'auto_restake_rewards': self.staking.auto_restake_rewards,
                'target_stake': str(self.staking.target_stake),
            },
            'slashing_protection': {
                'enabled': self.slashing_protection.enabled,
                'db_path': self.slashing_protection.db_path,
                'max_tracked_slots': self.slashing_protection.max_tracked_slots,
            },
            'attestation': {
                'aggregation_delay': self.attestation.aggregation_delay,
                'max_attestations_per_block': self.attestation.max_attestations_per_block,
                'max_inclusion_distance': self.attestation.max_inclusion_distance,
            },
        }


# Default PoS constants (can be overridden by config)
POS_CONSTANTS = {
    # Timing
    'SLOT_DURATION': 2,              # 2 seconds per slot
    'SLOTS_PER_EPOCH': 32,           # 32 slots per epoch (64 seconds)
    
    # Staking
    'MIN_VALIDATOR_STAKE': Decimal("100000"),  # 100,000 QRDX
    'MIN_DELEGATION': Decimal("100"),          # 100 QRDX minimum delegation
    'MAX_VALIDATORS': 150,                     # Maximum active validators
    'UNBONDING_PERIOD_EPOCHS': 9450,           # ~7 days
    
    # Consensus
    'ATTESTATION_THRESHOLD': Decimal("0.667"), # 2/3 for finality
    'MIN_ATTESTATION_INCLUSION_DELAY': 1,      # Minimum slots before attestation included
    'MAX_ATTESTATION_INCLUSION_DELAY': 32,     # Maximum slots for attestation inclusion
    
    # Rewards (per epoch)
    'BASE_REWARD_FACTOR': 64,                  # Base reward calculation factor
    'PROPOSER_REWARD_QUOTIENT': 4,             # Proposer gets 1/4 of attestation rewards
    
    # Slashing
    'SLASH_DOUBLE_SIGN_PERCENT': Decimal("0.50"),        # 50% stake
    'SLASH_INVALID_ATTESTATION_PERCENT': Decimal("0.30"), # 30% stake
    'SLASH_DOWNTIME_PERCENT': Decimal("0.05"),           # 5% stake
    'SLASH_BRIDGE_FRAUD_PERCENT': Decimal("1.00"),       # 100% stake
    
    # Misc
    'MAX_ATTESTATIONS_PER_BLOCK': 128,
    'GENESIS_EPOCH': 0,
    'GENESIS_SLOT': 0,
}


def get_pos_constant(name: str) -> Any:
    """Get a PoS constant by name."""
    return POS_CONSTANTS.get(name)
