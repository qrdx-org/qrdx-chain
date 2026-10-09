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
# The testnet's scripted price feed: every validator reads it (QRDX_ORACLE_FEED=file:…) and votes
# what it says; scenarios move prices by writing it.
ORACLE_FEED_FILE = TESTNET_DIR / "oracle_prices.json"
WALLETS_DIR = TESTNET_DIR / "wallets"
DATABASES_DIR = TESTNET_DIR / "databases"
CONFIGS_DIR = TESTNET_DIR / "configs"
LOGS_DIR = TESTNET_DIR / "logs"
DATA_DIR = TESTNET_DIR / "data"
GENESIS_FILE = TESTNET_DIR / "genesis_config.json"

# ──────────────────────────────────────────────────────────────────
#  Chain Parameters
# ──────────────────────────────────────────────────────────────────

# The QRDX testnet's chain id and name (chain_spec.TESTNET_CHAIN_ID / TESTNET_NETWORK_NAME).
CHAIN_ID = 7620
NETWORK_NAME = "qrdx-testnet"
SLOT_DURATION = 2  # seconds
SLOTS_PER_EPOCH = 8  # 16 seconds per epoch (faster for testing)
MIN_VALIDATORS = 1
ATTESTATION_THRESHOLD = Decimal("0.667")

# ──────────────────────────────────────────────────────────────────
#  Node Defaults
# ──────────────────────────────────────────────────────────────────

BASE_NODE_PORT = 3007
BASE_RPC_PORT = 8545
# Validator/node counts are env-overridable so a scaled at-scale soak (and the RANDAO enforce
# experiment, whose churn averages out on a larger set) can bump them without a code change; the
# fast dev default stays 3 validators + 1 full node. NUM_NODES defaults to NUM_VALIDATORS + 1.
NUM_VALIDATORS = int(os.getenv("QRDX_NUM_VALIDATORS", "3"))
NUM_NODES = int(os.getenv("QRDX_NUM_NODES", str(max(4, NUM_VALIDATORS + 1))))

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
    # Validators — generated dynamically for NUM_VALIDATORS (env-scalable). Validator 0..2 remain
    # the wallets the scenarios reference by name; extras (3+) just add consensus participants.
    *(WalletSpec(f"Validator {i}", "pq", VALIDATOR_GENESIS_BALANCE, is_validator=True,
                 validator_index=i) for i in range(NUM_VALIDATORS)),
    # Test users (numbered to match scenario references)
    WalletSpec("Test User 0", "pq", TEST_USER_BALANCE),
    WalletSpec("Test User 1", "traditional", TEST_USER_BALANCE),
    WalletSpec("Test User 2", "traditional", TEST_USER_BALANCE),
    # Functional wallets
    WalletSpec("Token Deployer", "pq", TOKEN_DEPLOYER_BALANCE),
    WalletSpec("Pool Creator", "pq", POOL_CREATOR_BALANCE),
    # Dedicated staking-deposit candidate for S16 (dynamic validator membership) —
    # kept untouched by other scenarios so its exchange nonce starts clean at 0.
    WalletSpec("Staker Candidate", "pq", Decimal("500000")),
    # Master controller (no genesis balance of its own)
    WalletSpec("Master Controller", "pq", Decimal("0")),
    # The testnet's oracle reporter: the only key allowed to submit UPDATE_ORACLE
    # (QRDX_ORACLE_REPORTERS, set identically on every node by the orchestrator). Perps
    # execute at the oracle price, so S13 prices its market through this wallet.
    WalletSpec("Oracle Reporter", "pq", Decimal("1000")),
    # S13's second perp trader (the counterparty to Test User 0 on the order book).
    WalletSpec("Perp Trader", "pq", Decimal("500000")),
    # S19's backstop-vault depositor (an HLP-style liquidity provider).
    WalletSpec("Vault Depositor", "pq", Decimal("100000")),
    # Issues the testnet's USD stablecoin (qUSD), which perps settle in — standing in for the
    # bridged stablecoin on mainnet. Its FIRST exchange transaction must be the deploy: the
    # token address is derived from (issuer, nonce 0, "qUSD") and configured on every node.
    WalletSpec("Stablecoin Issuer", "pq", Decimal("1000")),
    # Spot scenarios sign with these and assume a clean exchange nonce. They used validator
    # wallets until validators began submitting exchange transactions — their price votes
    # (docs/PERPS_CLEARINGHOUSE.md §8) advance a validator's nonce with every block it proposes.
    WalletSpec("Spot Trader", "pq", VALIDATOR_GENESIS_BALANCE),     # S15
    WalletSpec("Spot Stranger", "pq", Decimal("1000")),             # S15: not the LP
    # S20: the native token standard — issuer (mint + freeze authority), holder, spender.
    WalletSpec("Token Issuer", "pq", Decimal("1000")),
    WalletSpec("Token Holder", "pq", Decimal("1000")),
    WalletSpec("Token Spender", "pq", Decimal("1000")),
    WalletSpec("Token EVM User", "traditional", Decimal("1000")),   # sends a token from the EVM
    WalletSpec("CLOB Trader", "pq", VALIDATOR_GENESIS_BALANCE),     # S17
    WalletSpec("CLOB Maker", "pq", VALIDATOR_GENESIS_BALANCE),      # S18
    # S21: interfaces — a QRDX pool + book (maker, taker), market data, history, NFTs.
    WalletSpec("Market Maker", "pq", VALIDATOR_GENESIS_BALANCE),
    WalletSpec("Market Taker", "pq", Decimal("1000")),
    WalletSpec("NFT Artist", "pq", Decimal("1000")),
    WalletSpec("NFT Collector", "pq", Decimal("1000")),
]

# The testnet stablecoin perps settle in (S13 deploys it; S13/S19 trade in it).
STABLECOIN_SYMBOL = "qUSD"
STABLECOIN_SUPPLY = Decimal("10000000")


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
