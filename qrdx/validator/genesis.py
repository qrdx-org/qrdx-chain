"""
QRDX Genesis Block Creation

Creates the genesis state for QR-PoS chain:
- Genesis block structure
- Initial validator set
- Initial state root
- RANDAO seed initialization
- Pre-funded accounts

This is used to bootstrap a new network.
"""

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field, asdict
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from ..logger import get_logger
from ..crypto.hashing import sha256
from ..constants import (
    SLOTS_PER_EPOCH,
    MIN_VALIDATOR_STAKE,
    MAX_VALIDATORS,
    GENESIS_SLOT,
    GENESIS_EPOCH,
)

logger = get_logger(__name__)


# Genesis constants
GENESIS_VERSION = "1.0.0"
GENESIS_FORK_VERSION = b"\x00\x00\x00\x01"  # Version 1
GENESIS_VALIDATORS_ROOT_PREFIX = b"QRDX_GENESIS_VALIDATORS_V1"
GENESIS_STATE_ROOT_PREFIX = b"QRDX_GENESIS_STATE_V1"

# Minimum validators to start
MIN_GENESIS_VALIDATORS = 4
MIN_GENESIS_ACTIVE_VALIDATORS = 4

# Pre-mine allocation
TREASURY_ADDRESS = "qrdx_treasury_0x0000000000000000000000000000000000000001"
FOUNDATION_ADDRESS = "qrdx_foundation_0x0000000000000000000000000000000000000002"


@dataclass
class GenesisValidator:
    """A validator in the genesis state."""
    address: str
    public_key: str  # Hex-encoded PQ public key
    stake: Decimal
    withdrawal_address: str
    activation_epoch: int = GENESIS_EPOCH
    exit_epoch: Optional[int] = None


@dataclass
class GenesisAccount:
    """A pre-funded account in genesis."""
    address: str
    balance: Decimal
    label: str = ""


@dataclass
class GenesisConfig:
    """Configuration for genesis creation."""
    # Chain identification
    chain_id: int = 1
    network_name: str = "qrdx-mainnet"
    
    # Timing
    genesis_time: int = 0  # Unix timestamp
    genesis_slot: int = GENESIS_SLOT
    genesis_epoch: int = GENESIS_EPOCH
    slots_per_epoch: int = SLOTS_PER_EPOCH
    seconds_per_slot: int = 2
    
    # Validator parameters
    min_genesis_validators: int = MIN_GENESIS_VALIDATORS
    min_validator_stake: Decimal = MIN_VALIDATOR_STAKE
    max_validators: int = MAX_VALIDATORS
    
    # Initial supply
    initial_supply: Decimal = Decimal("100000000")  # 100M QRDX
    
    # Pre-allocations (address -> balance)
    pre_allocations: Dict[str, Decimal] = field(default_factory=dict)
    
    # Validators
    validators: List[GenesisValidator] = field(default_factory=list)
    
    # Extra data
    extra_data: bytes = b""


@dataclass
class GenesisState:
    """Complete genesis state for QR-PoS chain."""
    # Metadata
    version: str = GENESIS_VERSION
    chain_id: int = 1
    network_name: str = "qrdx-mainnet"
    
    # Timing
    genesis_time: int = 0
    genesis_slot: int = GENESIS_SLOT
    
    # Roots
    genesis_validators_root: str = ""
    state_root: str = ""
    
    # RANDAO
    randao_seed: str = ""
    
    # Validators
    validators: List[Dict[str, Any]] = field(default_factory=list)
    balances: Dict[str, str] = field(default_factory=dict)
    
    # Fork info
    fork_version: str = GENESIS_FORK_VERSION.hex()
    
    # Accounts
    accounts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Totals
    total_supply: str = "0"
    total_staked: str = "0"


@dataclass
class GenesisBlock:
    """The genesis block."""
    # Block header
    slot: int = GENESIS_SLOT
    epoch: int = GENESIS_EPOCH
    proposer_index: int = 0
    parent_root: str = "0" * 64  # All zeros
    state_root: str = ""
    
    # Block body (empty for genesis)
    transactions: List[Dict] = field(default_factory=list)
    attestations: List[Dict] = field(default_factory=list)
    
    # Signature (empty for genesis)
    signature: str = ""
    
    # Block hash
    block_hash: str = ""
    
    # Metadata
    timestamp: int = 0
    extra_data: str = ""


class GenesisCreator:
    """
    Creates genesis state for QR-PoS chain.
    
    Handles:
    - Validator registration and validation
    - Initial balance allocation
    - State root computation
    - Genesis block creation
    """
    
    def __init__(self, config: GenesisConfig):
        self.config = config
        self._validators: List[GenesisValidator] = list(config.validators)
        self._accounts: Dict[str, GenesisAccount] = {}
        
        # Initialize pre-allocations
        for address, balance in config.pre_allocations.items():
            self._accounts[address] = GenesisAccount(
                address=address,
                balance=balance,
                label="pre-allocation",
            )
    
    def add_validator(
        self,
        address: str,
        public_key: str,
        stake: Decimal,
        withdrawal_address: Optional[str] = None,
    ) -> bool:
        """
        Add a genesis validator.
        
        Args:
            address: Validator's address
            public_key: Hex-encoded PQ public key (CRYSTALS-Dilithium)
            stake: Initial stake amount
            withdrawal_address: Address for stake withdrawals
            
        Returns:
            True if validator was added successfully
        """
        # Validate stake
        if stake < self.config.min_validator_stake:
            logger.error(
                f"Stake {stake} below minimum {self.config.min_validator_stake}"
            )
            return False
        
        # Check max validators
        if len(self._validators) >= self.config.max_validators:
            logger.error(f"Maximum validators ({self.config.max_validators}) reached")
            return False
        
        # Check for duplicate
        if any(v.address == address for v in self._validators):
            logger.error(f"Validator {address} already exists")
            return False
        
        # Validate public key format (should be hex-encoded Dilithium key)
        try:
            pk_bytes = bytes.fromhex(public_key)
            if len(pk_bytes) < 1000:  # Dilithium public keys are ~1952 bytes
                logger.warning(f"Public key seems too short for Dilithium")
        except ValueError:
            logger.error(f"Invalid public key format")
            return False
        
        validator = GenesisValidator(
            address=address,
            public_key=public_key,
            stake=stake,
            withdrawal_address=withdrawal_address or address,
        )
        self._validators.append(validator)
        
        logger.info(f"Added genesis validator: {address[:16]}... stake={stake}")
        return True
    
    def add_account(
        self,
        address: str,
        balance: Decimal,
        label: str = "",
    ) -> bool:
        """
        Add a pre-funded account.
        
        Args:
            address: Account address
            balance: Initial balance
            label: Optional description
            
        Returns:
            True if account was added
        """
        if address in self._accounts:
            # Add to existing balance
            self._accounts[address].balance += balance
        else:
            self._accounts[address] = GenesisAccount(
                address=address,
                balance=balance,
                label=label,
            )
        
        logger.info(f"Added genesis account: {address[:16]}... balance={balance}")
        return True
    
    def _compute_validators_root(self, validators: List[GenesisValidator]) -> bytes:
        """Compute Merkle root of validator set."""
        if not validators:
            return hashlib.sha256(GENESIS_VALIDATORS_ROOT_PREFIX).digest()
        
        # Hash each validator
        leaves = []
        for v in sorted(validators, key=lambda x: x.address):
            leaf_data = (
                v.address.encode() +
                bytes.fromhex(v.public_key)[:32] +  # First 32 bytes of pubkey
                str(v.stake).encode() +
                v.withdrawal_address.encode()
            )
            leaves.append(hashlib.sha256(leaf_data).digest())
        
        # Simple Merkle tree (pad to power of 2)
        while len(leaves) & (len(leaves) - 1):
            leaves.append(hashlib.sha256(b"").digest())
        
        while len(leaves) > 1:
            new_leaves = []
            for i in range(0, len(leaves), 2):
                combined = leaves[i] + leaves[i + 1]
                new_leaves.append(hashlib.sha256(combined).digest())
            leaves = new_leaves
        
        return hashlib.sha256(
            GENESIS_VALIDATORS_ROOT_PREFIX + leaves[0]
        ).digest()
    
    def _compute_state_root(self, state: GenesisState) -> bytes:
        """Compute state root from genesis state."""
        # Serialize relevant state
        state_data = {
            "chain_id": state.chain_id,
            "genesis_time": state.genesis_time,
            "validators_root": state.genesis_validators_root,
            "balances": state.balances,
            "total_supply": state.total_supply,
        }
        
        state_json = json.dumps(state_data, sort_keys=True)
        
        return hashlib.sha256(
            GENESIS_STATE_ROOT_PREFIX + state_json.encode()
        ).digest()
    
    def _generate_randao_seed(self) -> bytes:
        """Generate initial RANDAO seed."""
        # Combine various entropy sources
        entropy = (
            secrets.token_bytes(32) +
            str(self.config.genesis_time).encode() +
            self.config.network_name.encode() +
            str(len(self._validators)).encode()
        )
        
        return hashlib.sha256(entropy).digest()
    
    def create_genesis(
        self,
        genesis_time: Optional[int] = None,
    ) -> Tuple[GenesisState, GenesisBlock]:
        """
        Create the complete genesis state and block.
        
        Args:
            genesis_time: Unix timestamp for genesis (default: now)
            
        Returns:
            Tuple of (GenesisState, GenesisBlock)
        """
        # Validate minimum validators
        if len(self._validators) < self.config.min_genesis_validators:
            raise ValueError(
                f"Need at least {self.config.min_genesis_validators} validators, "
                f"got {len(self._validators)}"
            )
        
        # Set genesis time
        if genesis_time is None:
            genesis_time = int(time.time())
        
        logger.info(f"Creating genesis for {self.config.network_name}")
        logger.info(f"Genesis time: {datetime.fromtimestamp(genesis_time, tz=timezone.utc)}")
        logger.info(f"Validators: {len(self._validators)}")
        
        # Calculate totals
        total_staked = sum(v.stake for v in self._validators)
        total_pre_allocated = sum(a.balance for a in self._accounts.values())
        
        # Create state
        state = GenesisState(
            chain_id=self.config.chain_id,
            network_name=self.config.network_name,
            genesis_time=genesis_time,
            genesis_slot=self.config.genesis_slot,
        )
        
        # Add validators
        for v in sorted(self._validators, key=lambda x: x.address):
            state.validators.append({
                "address": v.address,
                "public_key": v.public_key,
                "stake": str(v.stake),
                "withdrawal_address": v.withdrawal_address,
                "activation_epoch": v.activation_epoch,
                "exit_epoch": v.exit_epoch,
            })
            state.balances[v.address] = str(v.stake)
        
        # Add accounts
        for a in self._accounts.values():
            state.accounts[a.address] = {
                "balance": str(a.balance),
                "label": a.label,
            }
        
        # Compute roots
        validators_root = self._compute_validators_root(self._validators)
        state.genesis_validators_root = validators_root.hex()
        
        # Generate RANDAO
        randao_seed = self._generate_randao_seed()
        state.randao_seed = randao_seed.hex()
        
        # Set totals
        state.total_supply = str(self.config.initial_supply)
        state.total_staked = str(total_staked)
        
        # Compute state root
        state_root = self._compute_state_root(state)
        state.state_root = state_root.hex()
        
        # Create genesis block
        block = GenesisBlock(
            slot=self.config.genesis_slot,
            epoch=self.config.genesis_epoch,
            state_root=state.state_root,
            timestamp=genesis_time,
            extra_data=self.config.extra_data.hex() if self.config.extra_data else "",
        )
        
        # Compute block hash
        block_data = (
            block.slot.to_bytes(8, 'little') +
            bytes.fromhex(block.parent_root) +
            bytes.fromhex(block.state_root) +
            block.timestamp.to_bytes(8, 'little')
        )
        block.block_hash = hashlib.sha256(block_data).hexdigest()
        
        logger.info(f"Genesis state root: {state.state_root[:16]}...")
        logger.info(f"Genesis block hash: {block.block_hash[:16]}...")
        logger.info(f"Total staked: {total_staked}")
        logger.info(f"Total supply: {self.config.initial_supply}")
        
        return state, block
    
    def export_genesis(
        self,
        state: GenesisState,
        block: GenesisBlock,
        filepath: str,
    ):
        """
        Export genesis to a JSON file.
        
        Args:
            state: Genesis state
            block: Genesis block
            filepath: Output file path
        """
        genesis_data = {
            "state": asdict(state),
            "block": asdict(block),
            "config": {
                "chain_id": self.config.chain_id,
                "network_name": self.config.network_name,
                "slots_per_epoch": self.config.slots_per_epoch,
                "seconds_per_slot": self.config.seconds_per_slot,
                "min_validator_stake": str(self.config.min_validator_stake),
                "max_validators": self.config.max_validators,
            },
        }
        
        with open(filepath, 'w') as f:
            json.dump(genesis_data, f, indent=2)
        
        logger.info(f"Genesis exported to {filepath}")


def create_testnet_genesis(
    validators: List[Tuple[str, str, Decimal]],  # (address, pubkey, stake)
    genesis_time: Optional[int] = None,
) -> Tuple[GenesisState, GenesisBlock]:
    """
    Create a testnet genesis with the given validators.
    
    Args:
        validators: List of (address, public_key, stake) tuples
        genesis_time: Optional genesis timestamp
        
    Returns:
        Tuple of (GenesisState, GenesisBlock)
    """
    config = GenesisConfig(
        chain_id=9999,
        network_name="qrdx-testnet",
        min_genesis_validators=1,  # Lower for testnet
        initial_supply=Decimal("1000000000"),  # 1B for testnet
    )
    
    creator = GenesisCreator(config)
    
    for address, pubkey, stake in validators:
        creator.add_validator(address, pubkey, stake)
    
    return creator.create_genesis(genesis_time)


def create_mainnet_genesis(
    validators: List[Tuple[str, str, Decimal]],
    pre_allocations: Dict[str, Decimal],
    genesis_time: int,
) -> Tuple[GenesisState, GenesisBlock]:
    """
    Create mainnet genesis.
    
    Args:
        validators: List of (address, public_key, stake) tuples
        pre_allocations: Pre-funded accounts
        genesis_time: Genesis timestamp (must be in future)
        
    Returns:
        Tuple of (GenesisState, GenesisBlock)
    """
    if genesis_time < int(time.time()):
        raise ValueError("Genesis time must be in the future")
    
    config = GenesisConfig(
        chain_id=1,
        network_name="qrdx-mainnet",
        genesis_time=genesis_time,
        min_genesis_validators=MIN_GENESIS_VALIDATORS,
        initial_supply=Decimal("100000000"),  # 100M QRDX
        pre_allocations=pre_allocations,
    )
    
    creator = GenesisCreator(config)
    
    for address, pubkey, stake in validators:
        creator.add_validator(address, pubkey, stake)
    
    return creator.create_genesis(genesis_time)
