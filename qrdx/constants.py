"""
QRDX Blockchain Constants

This module consolidates all global constants and environment configuration
used throughout the codebase. Constants are organized by category for easy
reference and maintenance.
"""
import ast
import os
import re
from decimal import Decimal
from dotenv import dotenv_values
from fastecdsa import curve

# =============================================================================
# ENVIRONMENT CONFIGURATION
# =============================================================================
# Load environment variables from .env file and merge with os.environ
# os.environ takes precedence over .env file
_config = dotenv_values(".env")

NODE_DEFAULTS = {
    'QRDX_DATABASE_PATH':              'data/qrdx.db',  # SQLite database path
    'QRDX_NODE_HOST':                  '127.0.0.1',
    'QRDX_NODE_PORT':                  '3007',
    'QRDX_SELF_URL':                   '',
    'QRDX_BOOTSTRAP_NODE':             'http://node.qrdx.network',
    # Comma-separated list of bootstrap nodes
    'QRDX_BOOTSTRAP_NODES':            'http://node.qrdx.network,http://node2.qrdx.network,http://node3.qrdx.network',
}

LOGGER_DEFAULTS = {    
    'LOG_LEVEL':                       'INFO',
    'LOG_FORMAT':                      '%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    'LOG_DATE_FORMAT':                 '%Y-%m-%dT%H:%M:%S',
    'LOG_CONSOLE_HIGHLIGHTING':        'True',
    'LOG_INCLUDE_RESPONSE_CONTENT':    'False',
    'LOG_INCLUDE_REQUEST_CONTENT':     'False',
    'LOG_INCLUDE_BLOCK_SYNC_MESSAGES': 'False',
}

LOG_MAX_FILE_SIZE = 10 * 1024 * 1024 # 10MB
LOG_MAX_PATH_LENGTH = 320  # Maximum URL path length to log (truncates longer paths)
LOG_BACKUP_COUNT = 5


# WARNING: SOME OF THE VALUES BELOW ARE NOT MEANT TO BE CHANGED! ONLY CHANGE THESE VALUES IF YOU KNOW
# WHAT YOU ARE DOING, CREATING A NEW BLOCKCHAIN, OR FOR TESTING PURPOSES. DOING SO WHILE CONNECTED TO
# THE QRDX MAINNET MAY RESULT IN THIS NODE HAVING AN INVALID BLOCKCHAIN OR OTHER CONSENSUS PROTOCOL
# VIOLATIONS, WHICH MAINNET NODES WILL SWIFTLY REJECT.

# ==================================================================================
# CORE PROTOCOL CONSTANTS
# ==================================================================================
NODE_VERSION = '2.0.1'
ENDIAN = 'little'
CURVE = curve.P256
SMALLEST = 1000000  # Smallest unit divisor


# ==================================================================================
# BLOCKCHAIN PARAMETERS
# ==================================================================================
START_DIFFICULTY = Decimal('6.0')
BLOCK_TIME = 180  # 180 seconds / 3 minute block time
BLOCKS_PER_ADJUSTMENT = 512  # Difficulty adjustment every 512 blocks
MAX_SUPPLY = 33_554_432  # Maximum coin supply (2^25)
MAX_BLOCK_SIZE_HEX = 4096 * 1024  # 4MB in HEX format, 2MB in raw bytes


# ==================================================================================
# MONETARY POLICY PARAMETERS
# ==================================================================================
INITIAL_REWARD = Decimal(64)  # 2^6 DNR
HALVING_INTERVAL = 262144  # 2^18 blocks (targets ~2.5 years)
MAX_HALVINGS = 64  # 64 halvings


# ==================================================================================
# CHECKPOINT AND REORGANIZATION CONSTANTS
# ==================================================================================
# Maximum reorganization depth allowed.
# Prevents deep chain reorganizations that could rewrite established history.
MAX_REORG_DEPTH = 128


# ==================================================================================
# NETWORK AND SYNC CONSTANTS
# ==================================================================================
# Maximum number of blocks that can be submitted in a single request
MAX_BLOCKS_PER_SUBMISSION = 512

# Maximum block content size (same as MAX_BLOCK_SIZE_HEX for validation)
MAX_BLOCK_CONTENT_SIZE = 4_194_304  # 4MB in HEX format

# Peer management
MAX_PEERS = 64  # Maximum number of peers to maintain active connections with
MAX_PEERS_COUNT = 256  # Maximum number of peers to store in the peers database

# Sync operations
MAX_CONCURRENT_SYNCS = 1  # Maximum concurrent sync operations
MAX_BATCH_BYTES = 20 * 1024 * 1024  # 20MB max batch size for push sync

# Transaction limits
MAX_TX_FETCH_LIMIT = 512  # Maximum transactions to fetch in a single request
MAX_MEMPOOL_SIZE = 8192  # Maximum transactions in mempool

# Network timeouts
CONNECTION_TIMEOUT = 10.0  # 10 seconds

# Peer activity tracking
ACTIVE_NODES_DELTA = 60 * 60 * 24 * 7  # peers inactive longer than 7 days are considered stale


# ==================================================================================
# SYSTEM WALLETS CONFIGURATION
# ==================================================================================
# System wallets are special off-curve addresses that:
# - Cannot be generated from private keys
# - Are pre-funded in genesis
# - Are controlled by a designated PQ controller wallet
# - Provide decentralized treasury and system functions

# System wallet address range: 0x0000...0001 through 0x0000...00FF
SYSTEM_WALLET_ADDRESSES = {
    "GARBAGE_COLLECTOR": "0x0000000000000000000000000000000000000001",
    "COMMUNITY_GRANTS": "0x0000000000000000000000000000000000000002",
    "DEVELOPER_FUND": "0x0000000000000000000000000000000000000003",
    "ECOSYSTEM_FUND": "0x0000000000000000000000000000000000000004",
    "STAKING_REWARDS": "0x0000000000000000000000000000000000000005",
    "MARKETING": "0x0000000000000000000000000000000000000006",
    "LIQUIDITY_RESERVE": "0x0000000000000000000000000000000000000007",
    "TREASURY_MULTISIG": "0x0000000000000000000000000000000000000008",
    "BUG_BOUNTY": "0x0000000000000000000000000000000000000009",
    "AIRDROP": "0x000000000000000000000000000000000000000a",
}

# System wallet genesis balances (in QRDX)
SYSTEM_WALLET_GENESIS_BALANCES = {
    "GARBAGE_COLLECTOR": Decimal("0"),  # Burner wallet, starts empty
    "COMMUNITY_GRANTS": Decimal("5000000"),  # 5M QRDX
    "DEVELOPER_FUND": Decimal("10000000"),  # 10M QRDX
    "ECOSYSTEM_FUND": Decimal("8000000"),  # 8M QRDX
    "STAKING_REWARDS": Decimal("15000000"),  # 15M QRDX
    "MARKETING": Decimal("3000000"),  # 3M QRDX
    "LIQUIDITY_RESERVE": Decimal("7000000"),  # 7M QRDX
    "TREASURY_MULTISIG": Decimal("20000000"),  # 20M QRDX
    "BUG_BOUNTY": Decimal("1000000"),  # 1M QRDX
    "AIRDROP": Decimal("6000000"),  # 6M QRDX
}

# Total system wallet allocation
TOTAL_SYSTEM_WALLET_ALLOCATION = Decimal("75000000")  # 75M QRDX

# System wallet metadata
SYSTEM_WALLET_METADATA = {
    "GARBAGE_COLLECTOR": {
        "name": "Garbage Collector",
        "description": "Automated garbage collection wallet that burns unclaimed tokens and fees",
        "category": "system",
        "is_burner": True,
    },
    "COMMUNITY_GRANTS": {
        "name": "Community Grant Wallet",
        "description": "Distributes grants to community projects and ecosystem development initiatives",
        "category": "treasury",
        "is_burner": False,
    },
    "DEVELOPER_FUND": {
        "name": "Developer Fund",
        "description": "Core development team funding wallet for protocol maintenance and improvements",
        "category": "treasury",
        "is_burner": False,
    },
    "ECOSYSTEM_FUND": {
        "name": "Ecosystem Fund",
        "description": "Strategic investments in projects building on the QRDX network",
        "category": "treasury",
        "is_burner": False,
    },
    "STAKING_REWARDS": {
        "name": "Staking Rewards Pool",
        "description": "Distributes staking rewards to network validators and delegators",
        "category": "system",
        "is_burner": False,
    },
    "MARKETING": {
        "name": "Marketing & Partnerships",
        "description": "Funds marketing initiatives, partnerships, and ecosystem growth campaigns",
        "category": "treasury",
        "is_burner": False,
    },
    "LIQUIDITY_RESERVE": {
        "name": "Liquidity Pool Reserve",
        "description": "Reserve funds for maintaining liquidity across DEX pools",
        "category": "defi",
        "is_burner": False,
    },
    "TREASURY_MULTISIG": {
        "name": "Treasury Multisig",
        "description": "Main protocol treasury controlled by multi-signature governance",
        "category": "treasury",
        "is_burner": False,
    },
    "BUG_BOUNTY": {
        "name": "Bug Bounty Program",
        "description": "Rewards security researchers for finding and reporting vulnerabilities",
        "category": "security",
        "is_burner": False,
    },
    "AIRDROP": {
        "name": "Airdrop Distribution",
        "description": "Manages community airdrops and token distribution campaigns",
        "category": "distribution",
        "is_burner": False,
    },
}


# ==================================================================================
# MINING CONSTANTS
# ==================================================================================
# Maximum transaction candidates to consider for block template
MAX_MINING_CANDIDATES = 5000

# Maximum total transaction data size in block template (hex length approximation)
MAX_TX_DATA_SIZE = 1_900_000


# ==================================================================================
# VALIDATION PATTERNS
# ==================================================================================
# Regex pattern for validating hexadecimal strings
VALID_HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')

# Regex pattern for validating QRDX addresses
# Supports:
# - Traditional QRDX: Q/R + 44 base58 chars
# - PQ addresses: 0xPQ + 64 hex chars  
# - Ethereum addresses: 0x + 40 hex chars
VALID_ADDRESS_PATTERN = re.compile(r'^(?:[QR][1-9A-HJ-NP-Za-km-z]{44}|0xPQ[0-9a-fA-F]{64}|0x[0-9a-fA-F]{40})$')


# ==================================================================================
# CONFIGURATION WRAPPERS
# ==================================================================================
class ConfigString(str):
    """
    String subclass that stores a default value.
    """
    def __new__(cls, value, default):
        obj = str.__new__(cls, value)
        obj._default = default
        return obj

    def default(self):
        return self._default

class ConfigBool(int):
    """
    Int subclass acting as a boolean that stores a default value.
    """
    def __new__(cls, value, default):
        obj = int.__new__(cls, bool(value))
        obj._default = default
        return obj

    def default(self):
        return self._default

    def __repr__(self):
        return str(bool(self))

    def __str__(self):
        return str(bool(self))

    def __eq__(self, other):
        return bool(self) == other


# ==================================================================================
# DYNAMIC CONFIGURATION LOADING
# ==================================================================================
DEFAULTS = NODE_DEFAULTS | LOGGER_DEFAULTS 
namespace = globals()

def parse_bool(v):
    """
    Convert "True"/"False" (any casing, with surrounding whitespace) into bool.
    Avoids exceptions by only calling ast.literal_eval for known literals.
    """
    if not isinstance(v, str):
        return v
    s = v.strip()
    if not s:
        return v
    # Case-insensitive membership check
    if s.casefold() in {"true", "false"}:
        # ast.literal_eval expects "True"/"False"
        return ast.literal_eval(s.title())
    return v

for key, default_raw in DEFAULTS.items():
    # Check environment variables first (highest priority),
    # then .env file, then defaults
    raw = os.environ.get(key) or _config.get(key)
    value_raw = default_raw if raw is None else raw

    # Parses only boolean-literals. Leaves other values untouched.
    value = parse_bool(value_raw)
    default_val = parse_bool(default_raw)

    # Wraps based on parsed value type.
    if isinstance(value, bool):
        namespace[key] = ConfigBool(value, default_val)
    else:
        # Preserves the original raw string for ConfigString storage.
        namespace[key] = ConfigString(value_raw, default_val)


# ==================================================================================
# LEGACY COMPATIBILITY ALIASES
# ==================================================================================
# These aliases maintain backward compatibility with older code references.
# New code should use the QRDX_* prefixed versions.
DENARO_SELF_URL = namespace.get('QRDX_SELF_URL', '')
DENARO_BOOTSTRAP_NODE = namespace.get('QRDX_BOOTSTRAP_NODE', 'http://node.qrdx.network')
DENARO_DATABASE_PATH = namespace.get('QRDX_DATABASE_PATH', 'data/qrdx.db')  # SQLite path
DENARO_NODE_HOST = namespace.get('QRDX_NODE_HOST', '127.0.0.1')
DENARO_NODE_PORT = namespace.get('QRDX_NODE_PORT', '3007')

# ==================================================================================
# BOOTSTRAP NODES CONFIGURATION
# ==================================================================================
# Supports three formats:
# 1. Simple HTTP URLs: http://node.qrdx.network:3007
# 2. qnode:// URIs (legacy): qnode://<pubkey_hex>@hostname:port
# 3. @-schema addresses (PQ): dilithium3@qx<blake3_hex>@hostname:port
#
# @-schema provides the PQ node ID for identity verification during handshake

import re
from typing import NamedTuple
from urllib.parse import urlparse


class ParsedBootstrapNode(NamedTuple):
    """Parsed bootstrap node information."""
    url: str              # HTTP URL for connection (http://host:port)
    public_key: str       # Node's public key (hex) if provided, empty string otherwise
    host: str             # Hostname
    port: int             # Port number
    original: str         # Original URI string
    is_qnode: bool        # True if parsed from qnode:// URI
    node_id: str = ''     # PQ node ID (e.g. 'qx1a2b3c…') from @-schema
    algo: str = ''        # PQ algorithm from @-schema (e.g. 'dilithium3')


# @-schema regex: algo@qx<hex40+>@host:port
_BOOTSTRAP_AT_SCHEMA_RE = re.compile(
    r'^([a-zA-Z0-9-]+)@(qx[a-fA-F0-9]{40,})@([^:]+):(\d+)$'
)


def parse_bootstrap_node(uri: str) -> ParsedBootstrapNode:
    """
    Parse a bootstrap node URI.
    
    Supports:
    - @-schema: dilithium3@qx<node_id>@host:port  (PQ, preferred)
    - qnode URIs: qnode://<pubkey>@host:port       (legacy)
    - HTTP URLs: http://host:port                  (fallback)
    
    Args:
        uri: Bootstrap node URI string
        
    Returns:
        ParsedBootstrapNode with connection details
    """
    uri = uri.strip()
    
    # Check for @-schema format: algo@qx<hex>@host:port
    at_match = _BOOTSTRAP_AT_SCHEMA_RE.match(uri)
    if at_match:
        algo = at_match.group(1)
        node_id = at_match.group(2)
        host = at_match.group(3)
        port = int(at_match.group(4))
        http_url = f"http://{host}:{port}"
        return ParsedBootstrapNode(
            url=http_url,
            public_key="",   # public key obtained during handshake
            host=host,
            port=port,
            original=uri,
            is_qnode=True,
            node_id=node_id,
            algo=algo,
        )
    if uri.startswith('qnode://'):
        # Format: qnode://<pubkey>@<host>:<port>
        # pubkey is hex-encoded, typically 64+ chars
        match = re.match(
            r'^qnode://([a-fA-F0-9]+)@([^:]+):(\d+)$',
            uri
        )
        if match:
            pubkey = match.group(1)
            host = match.group(2)
            port = int(match.group(3))
            # Convert to HTTP URL for API connection
            http_url = f"http://{host}:{port}"
            return ParsedBootstrapNode(
                url=http_url,
                public_key=pubkey,
                host=host,
                port=port,
                original=uri,
                is_qnode=True,
            )
        else:
            # Try simpler qnode format without pubkey: qnode://host:port
            match = re.match(r'^qnode://([^:]+):(\d+)$', uri)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                http_url = f"http://{host}:{port}"
                return ParsedBootstrapNode(
                    url=http_url,
                    public_key="",
                    host=host,
                    port=port,
                    original=uri,
                    is_qnode=True,
                )
    
    # Standard HTTP(S) URL
    parsed = urlparse(uri)
    if parsed.scheme in ('http', 'https'):
        host = parsed.hostname or 'localhost'
        port = parsed.port or (443 if parsed.scheme == 'https' else 3007)
        return ParsedBootstrapNode(
            url=uri.rstrip('/'),
            public_key="",
            host=host,
            port=port,
            original=uri,
            is_qnode=False,
        )
    
    # Fallback: assume it's a host:port without scheme
    if ':' in uri:
        parts = uri.rsplit(':', 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = 3007
    else:
        host = uri
        port = 3007
    
    return ParsedBootstrapNode(
        url=f"http://{host}:{port}",
        public_key="",
        host=host,
        port=port,
        original=uri,
        is_qnode=False,
    )


def parse_bootstrap_nodes(nodes_str: str) -> list:
    """
    Parse a comma-separated list of bootstrap node URIs.
    
    Args:
        nodes_str: Comma-separated bootstrap node URIs
        
    Returns:
        List of ParsedBootstrapNode objects
    """
    if not nodes_str:
        return []
    
    nodes = []
    for uri in nodes_str.split(','):
        uri = uri.strip()
        if uri:
            nodes.append(parse_bootstrap_node(uri))
    return nodes


# Parse bootstrap nodes from environment
_bootstrap_nodes_raw = namespace.get('QRDX_BOOTSTRAP_NODES', '')

# BOOTSTRAP_NODES_PARSED contains full node info including public keys
BOOTSTRAP_NODES_PARSED = parse_bootstrap_nodes(_bootstrap_nodes_raw) if _bootstrap_nodes_raw else [
    parse_bootstrap_node(DENARO_BOOTSTRAP_NODE)
]

# BOOTSTRAP_NODES contains just the HTTP URLs for backward compatibility
BOOTSTRAP_NODES = [node.url for node in BOOTSTRAP_NODES_PARSED]


# ==================================================================================
# PROOF OF STAKE (PoS) CONSTANTS
# ==================================================================================
# These constants define the QR-PoS (Quantum-Resistant Proof-of-Stake) consensus.
# WARNING: Changing these values will break consensus with mainnet nodes!

# --- Slot and Epoch Configuration ---
SLOT_DURATION = 2                      # 2 seconds per slot
SLOTS_PER_EPOCH = 32                   # 32 slots = 64 seconds per epoch
EPOCHS_PER_SYNC_COMMITTEE = 256        # ~4.5 hours per sync committee period

# --- Sync Committee ---
SYNC_COMMITTEE_SIZE = 512              # Number of validators in sync committee
SYNC_COMMITTEE_SUBNET_COUNT = 4        # Number of subnets for distribution

# --- Validator Set ---
MIN_VALIDATORS = 1                     # Minimum validators to operate (testnet: 1)
MAX_VALIDATORS = 150                   # Maximum active validators
MIN_VALIDATOR_STAKE = Decimal('100000')  # 100,000 QRDX minimum stake
MAX_EFFECTIVE_STAKE = Decimal('1000000')  # 1,000,000 QRDX max effective stake

# --- Staking Parameters ---
UNBONDING_PERIOD_EPOCHS = 5040         # ~7 days (5040 epochs * 64 sec)
MIN_DEPOSIT = Decimal('10000')         # Minimum deposit amount
MAX_DEPOSIT = Decimal('10000000')      # Maximum single deposit
ACTIVATION_DELAY_EPOCHS = 4            # Epochs until deposit becomes active
WITHDRAWAL_DELAY_EPOCHS = 256          # Epochs until withdrawal finalizes

# --- Finality ---
ATTESTATION_THRESHOLD = Decimal('0.667')  # 2/3 + 1 of stake for finality
MIN_ATTESTATION_INCLUSION_DELAY = 1    # Minimum slots before attestation included
MAX_ATTESTATION_INCLUSION_DELAY = 32   # Maximum slots for attestation inclusion
MAX_ATTESTATIONS_PER_BLOCK = 128       # Maximum attestations in a block

# --- Rewards ---
BASE_REWARD_FACTOR = 64                # Base reward calculation factor
PROPOSER_REWARD_QUOTIENT = 8           # Proposer gets 1/8 of attestation rewards
ATTESTATION_REWARD_QUOTIENT = 4        # Attestation reward divisor
SYNC_REWARD_QUOTIENT = 2               # Sync committee reward divisor
INACTIVITY_PENALTY_QUOTIENT = 2**26    # ~67M - penalty scaling factor

# --- Slashing Penalties (percentage of stake) ---
SLASHING_DOUBLE_SIGN = Decimal('0.50')          # 50% for double-signing
SLASHING_INVALID_ATTESTATION = Decimal('0.30')  # 30% for invalid attestation
SLASHING_SURROUND_VOTE = Decimal('0.50')        # 50% for surround voting
SLASHING_DOWNTIME = Decimal('0.05')             # 5% for extended downtime
SLASHING_BRIDGE_FRAUD = Decimal('1.00')         # 100% for bridge fraud

# --- Whistleblower Rewards ---
WHISTLEBLOWER_REWARD_QUOTIENT = 512    # Reporter gets 1/512 of slashed amount
PROPOSER_SLASHING_REWARD_QUOTIENT = 32 # Proposer gets 1/32 for including slash

# --- Performance Thresholds ---
MAX_MISSED_BLOCKS_PER_EPOCH = 2        # Max missed proposals before warning
MIN_ATTESTATION_RATE = Decimal('0.95') # 95% attestation rate expected
INACTIVITY_LEAK_EPOCHS = 4             # Epochs of inactivity before leak starts

# --- Block Timing ---
BLOCK_PROPOSAL_DEADLINE = 1            # Seconds into slot for proposal deadline
ATTESTATION_DEADLINE = 2               # Seconds into slot for attestation deadline

# --- Genesis ---
GENESIS_SLOT = 0
GENESIS_EPOCH = 0
GENESIS_FORK_VERSION = b'\x00\x00\x00\x01'

# --- Domain Types for Signatures ---
DOMAIN_BEACON_PROPOSER = b'\x00\x00\x00\x00'
DOMAIN_BEACON_ATTESTER = b'\x01\x00\x00\x00'
DOMAIN_RANDAO = b'\x02\x00\x00\x00'
DOMAIN_DEPOSIT = b'\x03\x00\x00\x00'
DOMAIN_VOLUNTARY_EXIT = b'\x04\x00\x00\x00'
DOMAIN_SELECTION_PROOF = b'\x05\x00\x00\x00'

# --- Consolidated PoS Constants Dict (for validator module) ---
POS_CONSTANTS = {
    # Timing
    'SLOT_DURATION': SLOT_DURATION,
    'SLOTS_PER_EPOCH': SLOTS_PER_EPOCH,
    'EPOCHS_PER_SYNC_COMMITTEE': EPOCHS_PER_SYNC_COMMITTEE,
    
    # Validators
    'MIN_VALIDATORS': MIN_VALIDATORS,
    'MAX_VALIDATORS': MAX_VALIDATORS,
    'MIN_VALIDATOR_STAKE': MIN_VALIDATOR_STAKE,
    'MAX_EFFECTIVE_STAKE': MAX_EFFECTIVE_STAKE,
    
    # Staking
    'UNBONDING_PERIOD_EPOCHS': UNBONDING_PERIOD_EPOCHS,
    'MIN_DEPOSIT': MIN_DEPOSIT,
    'MAX_DEPOSIT': MAX_DEPOSIT,
    'ACTIVATION_DELAY_EPOCHS': ACTIVATION_DELAY_EPOCHS,
    'WITHDRAWAL_DELAY_EPOCHS': WITHDRAWAL_DELAY_EPOCHS,
    
    # Finality
    'ATTESTATION_THRESHOLD': ATTESTATION_THRESHOLD,
    'MIN_ATTESTATION_INCLUSION_DELAY': MIN_ATTESTATION_INCLUSION_DELAY,
    'MAX_ATTESTATION_INCLUSION_DELAY': MAX_ATTESTATION_INCLUSION_DELAY,
    'MAX_ATTESTATIONS_PER_BLOCK': MAX_ATTESTATIONS_PER_BLOCK,
    
    # Rewards
    'BASE_REWARD_FACTOR': BASE_REWARD_FACTOR,
    'PROPOSER_REWARD_QUOTIENT': PROPOSER_REWARD_QUOTIENT,
    'ATTESTATION_REWARD_QUOTIENT': ATTESTATION_REWARD_QUOTIENT,
    
    # Slashing
    'SLASHING_DOUBLE_SIGN': SLASHING_DOUBLE_SIGN,
    'SLASHING_INVALID_ATTESTATION': SLASHING_INVALID_ATTESTATION,
    'SLASHING_SURROUND_VOTE': SLASHING_SURROUND_VOTE,
    'SLASHING_DOWNTIME': SLASHING_DOWNTIME,
    'SLASHING_BRIDGE_FRAUD': SLASHING_BRIDGE_FRAUD,
    
    # Genesis
    'GENESIS_SLOT': GENESIS_SLOT,
    'GENESIS_EPOCH': GENESIS_EPOCH,
}


# ==================================================================================
# MULTISIG & WALLET ARCHITECTURE (Whitepaper §6)
# ==================================================================================

# Threshold Dilithium limits
MULTISIG_MAX_SIGNERS = 150       # Maximum n (total signers in a keyset)
MULTISIG_MAX_THRESHOLD = 100     # Maximum m (required signers)
MULTISIG_MIN_THRESHOLD = 1       # Minimum m (1-of-n is the simplest multisig)
MULTISIG_ADDRESS_PREFIX = "0xPQMS"  # Prefix for derived multisig addresses

# Domain separator for threshold signing (prevents cross-wallet replay)
MULTISIG_DOMAIN_SEPARATOR = b"QRDX-THRESHOLD-DILITHIUM-v1"

# Spending Scope bitmask (Whitepaper §6.2)
SPENDING_SCOPE_NONE     = 0
SPENDING_SCOPE_TRANSFER = 1   # Basic token transfers
SPENDING_SCOPE_SWAP     = 2   # Exchange / DEX operations
SPENDING_SCOPE_STAKE    = 4   # Staking deposits / withdrawals
SPENDING_SCOPE_BRIDGE   = 8   # Cross-chain bridge operations
SPENDING_SCOPE_ALL      = 15  # All operations


# ==================================================================================
# CROSS-CHAIN BRIDGE & ORACLE (Whitepaper §8, §10)
# ==================================================================================

# Chain identifiers (matches bridge.types.ChainId)
BRIDGE_CHAIN_QRDX     = 0
BRIDGE_CHAIN_ETHEREUM  = 1
BRIDGE_CHAIN_BITCOIN   = 2
BRIDGE_CHAIN_SOLANA    = 3
BRIDGE_CHAIN_COSMOS    = 4

# Confirmation requirements per chain (source chain finality)
BRIDGE_CONFIRMATIONS_ETH = 12    # ~3 minutes (Ethereum PoS)
BRIDGE_CONFIRMATIONS_BTC = 6     # ~60 minutes (Bitcoin PoW)
BRIDGE_CONFIRMATIONS_SOL = 32    # ~12.8 seconds (Solana finality)
BRIDGE_CONFIRMATIONS_COSMOS = 1  # Instant finality (Tendermint)

# Bridge fees (basis points: 10 bps = 0.1%)
BRIDGE_FEE_BPS = 10

# Doomsday Protocol (§8.5)
DOOMSDAY_CANARY_ADDRESS = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
DOOMSDAY_CANARY_BOUNTY = Decimal("1000000")  # 1M QRDX

# Fraud proof window for high-value unshields (§8.2)
FRAUD_PROOF_WINDOW_SECONDS = 604800  # 7 days
HIGH_VALUE_THRESHOLD_USD = Decimal("100000")  # $100K

# Oracle attestation threshold (§10.2)
# Minimum fraction of validators required: ≥ 2/3+1
ORACLE_ATTESTATION_QUORUM_NUMERATOR = 2
ORACLE_ATTESTATION_QUORUM_DENOMINATOR = 3

# Oracle precompile addresses (Step 4.5)
ORACLE_PRECOMPILE_GET_CHAIN_STATE = 0x0200
ORACLE_PRECOMPILE_VERIFY_PROOF = 0x0201
ORACLE_PRECOMPILE_SUBMIT_CROSS_CHAIN_TX = 0x0202

# Oracle precompile gas costs
ORACLE_GAS_GET_CHAIN_STATE = 100_000
ORACLE_GAS_VERIFY_PROOF = 200_000
ORACLE_GAS_SUBMIT_CROSS_CHAIN_TX = 500_000

# Bridge token minimum/maximum amounts
BRIDGE_MIN_AMOUNT_ETH = Decimal("0.01")
BRIDGE_MAX_AMOUNT_ETH = Decimal("10000")
BRIDGE_MIN_AMOUNT_BTC = Decimal("0.0001")
BRIDGE_MAX_AMOUNT_BTC = Decimal("1000")
BRIDGE_MIN_AMOUNT_SOL = Decimal("0.01")
BRIDGE_MAX_AMOUNT_SOL = Decimal("100000")

# Default institutional custody thresholds (Whitepaper §6.3)
TREASURY_MULTISIG_THRESHOLD = 5    # 5-of-9 for main treasury
TREASURY_MULTISIG_TOTAL     = 9
EMERGENCY_RECOVERY_THRESHOLD = 3   # 3-of-5 for emergency
EMERGENCY_RECOVERY_TOTAL     = 5


# ==================================================================================
# qRC20 TOKEN STANDARD (Whitepaper §9)
# ==================================================================================

# Maximum supply for a single qRC20 token (2^96 - 1 raw units)
QRC20_MAX_SUPPLY = Decimal("79228162514264337593543950335")

# Default token decimals (same as ERC-20 convention)
QRC20_DEFAULT_DECIMALS = 18

# Maximum tokens that can be registered in one registry
QRC20_MAX_REGISTRY_SIZE = 10_000

# Batch transfer limit per call
QRC20_MAX_BATCH_SIZE = 256

# Domain separators for PQ signature verification
QRC20_DOMAIN_TRANSFER = b"QRDX-QRC20-TRANSFER-v1"
QRC20_DOMAIN_APPROVE  = b"QRDX-QRC20-APPROVE-v1"
QRC20_DOMAIN_PERMIT   = b"QRDX-QRC20-PERMIT-v1"

# Well-known shielded tokens (§9.4) — mapped to bridge source chains
QRC20_SHIELDED_TOKENS = {
    "qETH":  {"source_chain": "ETHEREUM", "post_doomsday_trade": True},
    "qBTC":  {"source_chain": "BITCOIN",  "post_doomsday_trade": True},
    "qSOL":  {"source_chain": "SOLANA",   "post_doomsday_trade": True},
    "qUSDC": {"source_chain": "ETHEREUM", "post_doomsday_trade": True},
    "qUSDT": {"source_chain": "ETHEREUM", "post_doomsday_trade": True},
    "QRDX":  {"source_chain": "NATIVE",   "post_doomsday_trade": True},
}


# ==================================================================================
# ON-CHAIN GOVERNANCE (Whitepaper §13)
# ==================================================================================

# --- Proposal Thresholds ---
GOVERNANCE_PROPOSAL_DEPOSIT = Decimal("10000000")     # 10M QRDX to submit proposal
GOVERNANCE_TEMPERATURE_SUPPORT = Decimal("1000000")   # 1M QRDX temperature-check min
GOVERNANCE_MIN_DISCUSSION_DAYS = 3                    # Days before formal proposal

# --- Voting Configuration ---
GOVERNANCE_VOTING_PERIOD_DAYS = 7                     # 7-day voting window
GOVERNANCE_VOTING_PERIOD_EPOCHS = 7 * 24 * 60         # ~7 days in epochs (1 epoch ≈ 64s)
GOVERNANCE_QUORUM_THRESHOLD = Decimal("0.10")         # 10% of circulating supply
GOVERNANCE_APPROVAL_THRESHOLD = Decimal("0.60")       # 60% for parameter changes
GOVERNANCE_SUPERMAJORITY_THRESHOLD = Decimal("0.75")  # 75% for protocol upgrades

# --- Vote Types ---
GOVERNANCE_VOTE_FOR = 1
GOVERNANCE_VOTE_AGAINST = 2
GOVERNANCE_VOTE_ABSTAIN = 3

# --- Timelock ---
GOVERNANCE_TIMELOCK_MIN_DELAY_SECONDS = 2 * 24 * 3600   # 2 days minimum
GOVERNANCE_TIMELOCK_MAX_DELAY_SECONDS = 14 * 24 * 3600  # 14 days maximum
GOVERNANCE_TIMELOCK_DEFAULT_DELAY_SECONDS = 2 * 24 * 3600  # 2 days default

# --- Guardian Council (§13.4) ---
GOVERNANCE_GUARDIAN_THRESHOLD = 3   # 3-of-5 PQ multisig
GOVERNANCE_GUARDIAN_TOTAL = 5

# --- Governable Parameter Defaults (§13.5) ---
GOVERNANCE_DEFAULT_PARAMETERS = {
    "trading_fee_tiers":           [Decimal("0.0001"), Decimal("0.0005"),
                                    Decimal("0.003"), Decimal("0.01")],
    "orderbook_maker_fee":         Decimal("0.0002"),
    "orderbook_taker_fee":         Decimal("0.0005"),
    "bridge_fee_bps":              10,
    "min_validator_stake":         Decimal("100000"),
    "pool_creation_stake":         Decimal("10000"),
    "pool_creation_subsidy_burn":  Decimal("5000"),
    "validator_set_size":          150,
    "block_time_seconds":          2,
    "proposal_threshold":          Decimal("10000000"),
    "voting_period_days":          7,
    "oracle_attestation_threshold": Decimal("0.667"),
    "min_chain_adapters":          1,
}

# Domain separator for governance signatures
GOVERNANCE_DOMAIN_SEPARATOR = b"QRDX-GOVERNANCE-v1"


# ==================================================================================
# GENESIS PREFUNDED ACCOUNTS
# ==================================================================================
# These accounts are pre-funded at genesis with initial balances.
# Format: {address: (balance, label)}
# The treasury and foundation addresses receive their allocations at network launch.

GENESIS_PREFUNDED_ACCOUNTS = {
    # Treasury - ecosystem development, grants, partnerships
    'Qrdx_treasury_00000000000000000000000000000001': (Decimal('10000000'), 'Treasury'),
    
    # Foundation - long-term development and maintenance
    'Qrdx_foundation_000000000000000000000000000001': (Decimal('5000000'), 'Foundation'),
    
    # Validator incentive fund - bootstrapping initial validators
    'Qrdx_validator_incentive_0000000000000000001': (Decimal('2000000'), 'Validator Incentive Fund'),
    
    # Community fund - airdrops, community initiatives
    'Qrdx_community_fund_00000000000000000000001': (Decimal('3000000'), 'Community Fund'),
}

# Total genesis allocation (20M QRDX)
GENESIS_TOTAL_PREFUNDED = sum(amount for amount, _ in GENESIS_PREFUNDED_ACCOUNTS.values())
