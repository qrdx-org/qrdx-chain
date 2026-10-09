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
import time
from dataclasses import dataclass, field, asdict
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from ..logger import get_logger
from ..crypto.hashing import sha256
from .. import chain_spec as chain_spec_mod
from ..chain_spec import ChainSpec, ChainSpecError
from ..constants import (
    SLOTS_PER_EPOCH,
    MIN_VALIDATOR_STAKE,
    MAX_VALIDATORS,
    GENESIS_SLOT,
    GENESIS_EPOCH,
)

logger = get_logger(__name__)


# Genesis constants
GENESIS_VERSION = "2.0.0"
GENESIS_FORK_VERSION = b"\x00\x00\x00\x01"  # Version 1
GENESIS_VALIDATORS_ROOT_PREFIX = b"QRDX_GENESIS_VALIDATORS_V1"
# V2: the root commits to the chain spec and to every allocation (V1 left out the prefunded
# accounts, so two genesis files funding different accounts produced the same genesis block).
GENESIS_STATE_ROOT_PREFIX = b"QRDX_GENESIS_STATE_V2"
GENESIS_RANDAO_PREFIX = b"QRDX_GENESIS_RANDAO_V1"
_WEI = Decimal(10) ** 18


def _wei(amount: Any) -> str:
    """An allocation as an exact integer number of wei — the form the state root commits to, so
    "1000000", "1000000.0" and "1E+6" are the same allocation."""
    value = Decimal(str(amount)) * _WEI
    if value != value.to_integral_value():
        raise ValueError(f"genesis amount {amount} has more than 18 decimal places")
    return str(int(value))

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
    """Configuration for genesis creation.

    ``chain_spec`` defines the network (chain id, name, consensus parameters, upgrade schedule)
    and genesis commits to it. Without one, the creator uses the process's spec when
    ``chain_id`` and ``network_name`` are left unset, and otherwise builds a DEV spec from them
    (with the process's parameters) — tooling that creates a real network passes its spec."""
    # Chain identification (taken from chain_spec when one is given; must agree with it)
    chain_id: Optional[int] = None
    network_name: Optional[str] = None
    chain_spec: Optional[ChainSpec] = None
    
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
    
    # System wallets
    system_wallet_controller: Optional[str] = None  # PQ address that controls system wallets
    enable_system_wallets: bool = True
    
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

    # The chain spec this genesis commits to (chain_spec.ChainSpec.genesis_hash)
    chain_spec_hash: str = ""

    # Accounts
    accounts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # System wallets
    system_wallets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    system_wallet_controller: str = ""  # PQ address controlling system wallets
    
    # Totals
    total_supply: str = "0"
    total_staked: str = "0"
    total_system_wallets: str = "0"


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
        self.spec = self._resolve_spec(config)
        config.chain_id = self.spec.chain_id
        config.network_name = self.spec.network
        self._validators: List[GenesisValidator] = list(config.validators)
        self._accounts: Dict[str, GenesisAccount] = {}
        self._system_wallet_manager = None
        
        # Initialize pre-allocations
        for address, balance in config.pre_allocations.items():
            self._accounts[address] = GenesisAccount(
                address=address,
                balance=balance,
                label="pre-allocation",
            )
        
        # Initialize system wallets if enabled
        if config.enable_system_wallets and config.system_wallet_controller:
            self._init_system_wallets(config.system_wallet_controller)
    
    @staticmethod
    def _resolve_spec(config: GenesisConfig) -> ChainSpec:
        spec = config.chain_spec
        if spec is not None:
            if config.chain_id is not None and config.chain_id != spec.chain_id:
                raise ChainSpecError(f"genesis chain_id {config.chain_id} disagrees with its "
                                     f"chain spec ({spec.chain_id})")
            if config.network_name is not None and config.network_name != spec.network:
                raise ChainSpecError(f"genesis network {config.network_name!r} disagrees with "
                                     f"its chain spec ({spec.network!r})")
            return spec
        process = chain_spec_mod.active()
        if config.chain_id is None and config.network_name is None:
            return process
        return chain_spec_mod.build_spec(
            config.network_name or process.network,
            config.chain_id if config.chain_id is not None else process.chain_id,
            process.params, dev=True)

    def _init_system_wallets(self, controller_address: str):
        """Initialize system wallets with controller."""
        from ..crypto.system_wallets import initialize_system_wallets
        
        self._system_wallet_manager = initialize_system_wallets(controller_address)
        logger.info(
            f"System wallets initialized with controller: {controller_address[:16]}..."
        )
    
    def get_system_wallet_manager(self):
        """Get system wallet manager."""
        return self._system_wallet_manager
    
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
        """The genesis state root: a commitment to everything a genesis node initialises — the
        network's chain spec, every allocation (prefunded accounts, validator stakes, system
        wallets and their controller), the validator set and the genesis time. The genesis block
        hash covers this root, so nodes that disagree on any of it cannot share a genesis block.
        Labels are display-only and excluded."""
        state_data = {
            "version": state.version,
            "chain_spec_hash": state.chain_spec_hash,
            "chain_id": state.chain_id,
            "network_name": state.network_name,
            "genesis_time": state.genesis_time,
            "validators_root": state.genesis_validators_root,
            "validators": [
                {"address": v["address"], "public_key": v["public_key"],
                 "stake_wei": _wei(v["stake"]), "withdrawal_address": v["withdrawal_address"]}
                for v in sorted(state.validators, key=lambda v: v["address"])],
            "balances_wei": {a: _wei(b) for a, b in state.balances.items()},
            "accounts_wei": {a: _wei(info["balance"]) for a, info in state.accounts.items()},
            "system_wallets": {
                a: {"balance_wei": _wei(w["balance"]), "type": w.get("type"),
                    "is_burner": bool(w.get("is_burner")), "category": w.get("category")}
                for a, w in state.system_wallets.items()},
            "system_wallet_controller": state.system_wallet_controller,
            "total_supply_wei": _wei(state.total_supply),
        }
        state_json = json.dumps(state_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(GENESIS_STATE_ROOT_PREFIX + state_json.encode()).digest()

    def _generate_randao_seed(self, validators_root: bytes, genesis_time: int) -> bytes:
        """The initial RANDAO mix. Derived, not random: every node that loads the same genesis
        file must arrive at the same seed (a per-node random seed would make any consumer of it
        diverge). Unpredictability comes later, from the proposers' RANDAO reveals."""
        return hashlib.sha256(
            GENESIS_RANDAO_PREFIX + bytes.fromhex(self.spec.genesis_hash()) + validators_root
            + int(genesis_time).to_bytes(8, "little")
        ).digest()
    
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
            genesis_time = self.config.genesis_time or int(time.time())
        
        logger.info(f"Creating genesis for {self.config.network_name}")
        logger.info(f"Genesis time: {datetime.fromtimestamp(genesis_time, tz=timezone.utc)}")
        logger.info(f"Validators: {len(self._validators)}")
        
        # Calculate totals
        total_staked = sum(v.stake for v in self._validators)

        # Create state
        state = GenesisState(
            chain_id=self.spec.chain_id,
            network_name=self.spec.network,
            genesis_time=genesis_time,
            genesis_slot=self.config.genesis_slot,
            chain_spec_hash=self.spec.genesis_hash(),
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
        
        # Add system wallets
        total_system_wallet_balance = Decimal("0")
        if self._system_wallet_manager:
            state.system_wallet_controller = self._system_wallet_manager.controller_address
            for wallet in self._system_wallet_manager.get_all_wallets():
                state.system_wallets[wallet.address] = {
                    "balance": str(wallet.genesis_balance),
                    "name": wallet.name,
                    "description": wallet.description,
                    "type": wallet.wallet_type.value,
                    "is_burner": wallet.is_burner,
                    "category": wallet.category,
                }
                # Add to balances for consistency
                state.balances[wallet.address] = str(wallet.genesis_balance)
                total_system_wallet_balance += wallet.genesis_balance
            
            logger.info(f"Added {len(state.system_wallets)} system wallets")
            logger.info(f"Total system wallet balance: {total_system_wallet_balance}")
        
        # Compute roots
        validators_root = self._compute_validators_root(self._validators)
        state.genesis_validators_root = validators_root.hex()
        
        # Initial RANDAO mix (derived — identical on every node)
        randao_seed = self._generate_randao_seed(validators_root, genesis_time)
        state.randao_seed = randao_seed.hex()
        
        # Set totals
        state.total_supply = str(self.config.initial_supply)
        state.total_staked = str(total_staked)
        if self._system_wallet_manager:
            state.total_system_wallets = str(
                self._system_wallet_manager.get_total_genesis_balance()
            )
        
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
        params = self.spec.params
        genesis_data = {
            # The network's consensus definition. The genesis state root commits to it (minus
            # its upgrade schedule), so a node refuses to start on this genesis under any other.
            "chain_spec": self.spec.to_dict(),
            "state": asdict(state),
            "block": asdict(block),
            # Informational summary of the chain spec (nodes read the chain_spec section).
            "config": {
                "chain_id": self.spec.chain_id,
                "network_name": self.spec.network,
                "slots_per_epoch": params["SLOTS_PER_EPOCH"],
                "seconds_per_slot": params["SLOT_DURATION"],
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
    chain_spec: Optional[ChainSpec] = None,
) -> Tuple[GenesisState, GenesisBlock]:
    """
    Create a testnet genesis with the given validators.

    Args:
        validators: List of (address, public_key, stake) tuples
        genesis_time: Optional genesis timestamp
        chain_spec: The testnet's chain spec (default: qrdx-testnet, chain id 7620, with this
            process's parameters)

    Returns:
        Tuple of (GenesisState, GenesisBlock)
    """
    if chain_spec is None:
        chain_spec = chain_spec_mod.build_spec(
            chain_spec_mod.TESTNET_NETWORK_NAME, chain_spec_mod.TESTNET_CHAIN_ID,
            chain_spec_mod.active().params)
    config = GenesisConfig(
        chain_spec=chain_spec,
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
    chain_spec: ChainSpec,
) -> Tuple[GenesisState, GenesisBlock]:
    """
    Create mainnet genesis.

    Args:
        validators: List of (address, public_key, stake) tuples
        pre_allocations: Pre-funded accounts
        genesis_time: Genesis timestamp (must be in future)
        chain_spec: Mainnet's chain spec — required: mainnet's chain id and parameters are a
            launch decision, never a default (a non-dev spec cannot use another EVM network's
            chain id)

    Returns:
        Tuple of (GenesisState, GenesisBlock)
    """
    if genesis_time < int(time.time()):
        raise ValueError("Genesis time must be in the future")
    if not isinstance(chain_spec, ChainSpec) or chain_spec.dev:
        raise ChainSpecError("mainnet genesis needs a non-dev chain spec")
    if (chain_spec.chain_id, chain_spec.network) != (chain_spec_mod.MAINNET_CHAIN_ID,
                                                     chain_spec_mod.MAINNET_NETWORK_NAME):
        raise ChainSpecError(
            f"mainnet genesis needs chain id {chain_spec_mod.MAINNET_CHAIN_ID} and network "
            f"{chain_spec_mod.MAINNET_NETWORK_NAME!r}; got {chain_spec.chain_id} / "
            f"{chain_spec.network!r}")

    config = GenesisConfig(
        chain_spec=chain_spec,
        genesis_time=genesis_time,
        min_genesis_validators=MIN_GENESIS_VALIDATORS,
        initial_supply=Decimal("100000000"),  # 100M QRDX
        pre_allocations=pre_allocations,
    )

    creator = GenesisCreator(config)

    for address, pubkey, stake in validators:
        creator.add_validator(address, pubkey, stake)

    return creator.create_genesis(genesis_time)
