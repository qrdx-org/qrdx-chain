"""
Testnet Configuration — Chain Parameters & Paths

All testnet-specific parameters live here. Nothing is stubbed:
  - Real chain ID, real port ranges, real file paths.
  - Uses the same constants as mainnet where applicable.

Data directory stays at PROJECT_ROOT/testnet (gitignored).
Scripts live in PROJECT_ROOT/integration_tests (tracked).
"""

import os
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Dict, List, Optional

# ──────────────────────────────────────────────────────────────────
#  Paths
# ──────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTNET_DIR = PROJECT_ROOT / "testnet"          # Data directory (gitignored)
WALLETS_DIR = TESTNET_DIR / "wallets"
DATABASES_DIR = TESTNET_DIR / "databases"
CONFIGS_DIR = TESTNET_DIR / "configs"
LOGS_DIR = TESTNET_DIR / "logs"
DATA_DIR = TESTNET_DIR / "data"
GENESIS_FILE = TESTNET_DIR / "genesis_config.json"

# ──────────────────────────────────────────────────────────────────
#  Chain Parameters
# ──────────────────────────────────────────────────────────────────

CHAIN_ID = 9999
NETWORK_NAME = "qrdx-testnet-integration"
SLOT_DURATION = 2  # seconds
SLOTS_PER_EPOCH = 8  # 16 seconds per epoch (faster for testing)
MIN_VALIDATORS = 1
ATTESTATION_THRESHOLD = Decimal("0.667")

# ──────────────────────────────────────────────────────────────────
#  Node Defaults
# ──────────────────────────────────────────────────────────────────

BASE_NODE_PORT = 3007
BASE_RPC_PORT = 8545
NUM_NODES = 4
NUM_VALIDATORS = 3

# ──────────────────────────────────────────────────────────────────
#  Genesis Allocations
# ──────────────────────────────────────────────────────────────────

VALIDATOR_GENESIS_BALANCE = Decimal("1000000")    # 1M QRDX per validator
VALIDATOR_STAKE = Decimal("100000")               # 100K QRDX stake
TEST_USER_BALANCE = Decimal("500000")             # 500K QRDX for test users
TOKEN_DEPLOYER_BALANCE = Decimal("100000")        # 100K QRDX for token deployer
POOL_CREATOR_BALANCE = Decimal("200000")          # 200K QRDX for pool creator
CONTRACT_TEST_BALANCE = Decimal("1000000000")     # 1B QRDX for contract testing

# ──────────────────────────────────────────────────────────────────
#  Wallet Roster
# ──────────────────────────────────────────────────────────────────

@dataclass
class WalletSpec:
    """Specification for a wallet to be generated at testnet init."""
    label: str
    wallet_type: str  # "pq" or "traditional"
    genesis_balance: Decimal
    is_validator: bool = False
    validator_index: Optional[int] = None


WALLET_ROSTER: List[WalletSpec] = [
    # Validators
    WalletSpec("Validator 0", "pq", VALIDATOR_GENESIS_BALANCE, is_validator=True, validator_index=0),
    WalletSpec("Validator 1", "pq", VALIDATOR_GENESIS_BALANCE, is_validator=True, validator_index=1),
    WalletSpec("Validator 2", "pq", VALIDATOR_GENESIS_BALANCE, is_validator=True, validator_index=2),
    # Test users (numbered to match scenario references)
    WalletSpec("Test User 0", "pq", TEST_USER_BALANCE),
    WalletSpec("Test User 1", "traditional", TEST_USER_BALANCE),
    WalletSpec("Test User 2", "traditional", TEST_USER_BALANCE),
    # Functional wallets
    WalletSpec("Token Deployer", "pq", TOKEN_DEPLOYER_BALANCE),
    WalletSpec("Pool Creator", "pq", POOL_CREATOR_BALANCE),
    # Master controller (no genesis balance of its own)
    WalletSpec("Master Controller", "pq", Decimal("0")),
]


@dataclass
class NodeSpec:
    """Specification for a testnet node."""
    node_id: int
    is_bootstrap: bool
    is_validator: bool
    validator_index: Optional[int]  # Index into WALLET_ROSTER
    node_port: int
    rpc_port: int

    @property
    def name(self) -> str:
        return f"node-{self.node_id}"

    @property
    def db_path(self) -> str:
        return str(DATABASES_DIR / f"node{self.node_id}.db")

    @property
    def log_dir(self) -> str:
        return str(LOGS_DIR / f"node{self.node_id}")

    @property
    def key_dir(self) -> str:
        return str(DATA_DIR / f"node{self.node_id}" / "keys")


def build_node_specs(num_nodes: int = NUM_NODES, num_validators: int = NUM_VALIDATORS) -> List[NodeSpec]:
    """Build node specifications from configuration."""
    specs = []
    for i in range(num_nodes):
        specs.append(NodeSpec(
            node_id=i,
            is_bootstrap=(i == 0),
            is_validator=(i < num_validators),
            validator_index=i if i < num_validators else None,
            node_port=BASE_NODE_PORT + i,
            rpc_port=BASE_RPC_PORT + i,
        ))
    return specs


# ──────────────────────────────────────────────────────────────────
#  Timeouts
# ──────────────────────────────────────────────────────────────────

NODE_STARTUP_TIMEOUT = 45        # seconds to wait for a node to become healthy
PEER_DISCOVERY_TIMEOUT = 30      # seconds to wait for peer mesh formation
BLOCK_PRODUCTION_TIMEOUT = 60    # seconds to wait for first block
TX_CONFIRMATION_TIMEOUT = 30     # seconds to wait for transaction confirmation
SCENARIO_DEFAULT_TIMEOUT = 120   # default timeout for a single scenario

# ──────────────────────────────────────────────────────────────────
#  Token Test Parameters
# ──────────────────────────────────────────────────────────────────

TEST_TOKEN_NAME = "TestCoin"
TEST_TOKEN_SYMBOL = "TRC"
TEST_TOKEN_DECIMALS = 18
TEST_TOKEN_SUPPLY = Decimal("1000000")  # 1M tokens

# ──────────────────────────────────────────────────────────────────
#  Pool Test Parameters
# ──────────────────────────────────────────────────────────────────

TEST_POOL_FEE_TIER = 3000  # 0.30%
TEST_POOL_TYPE = "STANDARD"
TEST_POOL_INITIAL_QRDX = Decimal("50000")
TEST_POOL_INITIAL_TRC = Decimal("10000")
TEST_SWAP_AMOUNT = Decimal("1000")  # 1000 QRDX
