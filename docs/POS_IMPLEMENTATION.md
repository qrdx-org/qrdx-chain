# QRDX Proof-of-Stake (QR-PoS) Implementation Plan

## Executive Summary

This document outlines the comprehensive plan to convert QRDX Chain from Proof-of-Work (PoW) to Quantum-Resistant Proof-of-Stake (QR-PoS). This is a mainnet implementation - no transition logic required.

**Core Priorities:**
1. **Decentralization** - Open validator participation with reasonable stake requirements
2. **Security** - Post-quantum cryptography (Dilithium3), BFT consensus, slashing conditions
3. **Functionality** - Web3-compatible, 2-second block time, sub-second finality

**Critical Requirement:** Validators MUST use Post-Quantum (PQ) wallets for all operations.

---

## 1. Architecture Overview

### 1.1 Consensus Model: QR-PoS

```
┌─────────────────────────────────────────────────────────────────┐
│                     QRDX QR-PoS Consensus                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Validator Set                         │   │
│  │  - 150 active validators (governance expandable)         │   │
│  │  - Minimum stake: 100,000 QRDX                          │   │
│  │  - PQ Wallet REQUIRED (Dilithium3 signatures)           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Block Production (per slot)                 │   │
│  │  1. Validator Selection (stake-weighted + randomness)   │   │
│  │  2. Block Proposal (Dilithium signature)                │   │
│  │  3. Attestation Period (1 second)                       │   │
│  │  4. Finality (2/3+ attestations)                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Finality Gadget (BFT)                   │   │
│  │  - Single-slot finality                                 │   │
│  │  - Safety: <1/3 Byzantine validators                    │   │
│  │  - Liveness: >2/3 online validators                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Key Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Block Time | 2 seconds | Time per slot |
| Epoch Length | 32 slots | 64 seconds per epoch |
| Min Validator Stake | 100,000 QRDX | Minimum to become validator |
| Max Validators | 150 | Active validator set size |
| Attestation Threshold | 2/3 + 1 | Required for finality |
| Unbonding Period | 7 days | Stake withdrawal delay |

### 1.3 Component Structure

```
qrdx/
├── validator/                    # NEW: Validator module
│   ├── __init__.py
│   ├── manager.py               # ValidatorManager - main coordinator
│   ├── stake.py                 # StakeManager - stake operations
│   ├── selection.py             # Validator selection algorithm
│   ├── attestation.py           # Attestation handling
│   ├── slashing.py              # Slashing conditions & executor
│   └── config.py                # Validator configuration
├── consensus.py                 # UPDATED: PoS consensus rules
├── manager.py                   # UPDATED: PoS block management
├── database.py                  # UPDATED: Validator queries
├── schema.sql                   # UPDATED: Validator tables
└── constants.py                 # UPDATED: PoS constants
```

---

## 2. Validator Module Design

### 2.1 Validator Requirements

**CRITICAL: PQ Wallet Requirement**
- Validators MUST operate with a funded PQ (Post-Quantum) wallet
- All validator signatures use Dilithium3 (ML-DSA-65)
- Classical wallets (ECDSA) CANNOT be validators

**Economic Requirements:**
- Minimum stake: 100,000 QRDX
- Stake must be deposited before activation
- 7-day unbonding period for withdrawals

### 2.2 ValidatorManager Class

```python
class ValidatorManager:
    """
    Coordinates all validator operations.
    
    Responsibilities:
    - Validator registration and activation
    - Block proposal coordination
    - Attestation collection
    - Slashing enforcement
    """
    
    def __init__(self, pq_wallet: PQWallet, config: ValidatorConfig):
        self.wallet = pq_wallet
        self.config = config
        self.stake_manager = StakeManager()
        self.selector = ValidatorSelector()
        self.attestation_pool = AttestationPool()
        
    async def register_validator(self) -> bool:
        """Register as a validator with PQ wallet."""
        
    async def propose_block(self, slot: int) -> Optional[Block]:
        """Propose block if selected for slot."""
        
    async def attest_block(self, block: Block) -> Attestation:
        """Create attestation for valid block."""
        
    async def check_slashing(self, evidence: SlashingEvidence) -> bool:
        """Check and process slashing conditions."""
```

### 2.3 StakeManager Class

```python
class StakeManager:
    """
    Manages stake deposits, withdrawals, and tracking.
    """
    
    async def deposit(self, validator_address: str, amount: Decimal) -> bool:
        """Deposit stake for validator."""
        
    async def request_withdrawal(self, validator_address: str, amount: Decimal) -> bool:
        """Request stake withdrawal (starts unbonding)."""
        
    async def process_unbonding(self) -> List[str]:
        """Process unbonding queue after delay."""
        
    async def get_effective_stake(self, validator_address: str) -> Decimal:
        """Get validator's effective stake (excludes pending withdrawals)."""
        
    async def slash(self, validator_address: str, amount: Decimal, reason: str) -> bool:
        """Slash validator stake."""
```

### 2.4 Validator Selection Algorithm

```python
class ValidatorSelector:
    """
    Selects block proposers using weighted random selection.
    
    Selection probability = (stake / total_stake) * uptime_factor
    
    Uses RANDAO-style randomness from previous block signatures.
    """
    
    def __init__(self, seed: bytes = None):
        self.seed = seed or os.urandom(32)
        
    def select_proposer(
        self, 
        slot: int, 
        validators: List[Validator],
        randao_mix: bytes
    ) -> Validator:
        """Select proposer for given slot."""
        
    def select_committee(
        self,
        slot: int,
        validators: List[Validator],
        committee_size: int,
        randao_mix: bytes
    ) -> List[Validator]:
        """Select attestation committee for slot."""
```

---

## 3. Consensus Changes

### 3.1 Removed PoW Components

The following PoW-specific code will be removed:
- `check_block_is_valid()` - PoW hash validation
- `difficulty_to_hashrate()` / `hashrate_to_difficulty()`
- Difficulty adjustment logic
- Nonce/random mining fields
- Mining block templates

### 3.2 New PoS Block Structure

```python
@dataclass
class Block:
    """PoS Block structure."""
    
    # Header
    number: int
    parent_hash: str
    state_root: str
    transactions_root: str
    timestamp: int
    
    # Validator Info (PQ signatures)
    proposer_address: str           # PQ address
    proposer_public_key: bytes      # Dilithium public key
    proposer_signature: bytes       # Dilithium signature
    
    # Consensus Data
    slot: int
    epoch: int
    randao_reveal: bytes            # For randomness
    
    # Attestations (from previous slot)
    attestations: List[Attestation]
    
    # Transactions
    transactions: List[Transaction]
```

### 3.3 Attestation Structure

```python
@dataclass
class Attestation:
    """Validator attestation for block finality."""
    
    slot: int
    block_hash: str
    validator_index: int
    validator_address: str          # PQ address
    signature: bytes                # Dilithium signature
    
    def verify(self, public_key: bytes) -> bool:
        """Verify attestation signature."""
```

### 3.4 PoS Consensus Rules

```python
class PoSConsensusRules(BaseConsensusRules):
    """
    QR-PoS Consensus Implementation
    
    Validator requirements:
    - PQ wallet with Dilithium3 keys
    - Minimum 100,000 QRDX staked
    - Valid registration transaction
    """
    
    @property
    def version(self) -> ConsensusVersion:
        return ConsensusVersion.CONSENSUS_POS
    
    async def validate_block_proposer(
        self, 
        block: Block, 
        slot: int
    ) -> bool:
        """Validate that proposer is authorized for this slot."""
        
    async def validate_attestations(
        self, 
        attestations: List[Attestation],
        block_hash: str
    ) -> Tuple[bool, int]:
        """Validate attestations and return count."""
        
    async def check_finality(
        self, 
        block: Block, 
        attestation_count: int
    ) -> bool:
        """Check if block has achieved finality (2/3+ attestations)."""
        
    def validate_pq_signature(
        self, 
        message: bytes, 
        signature: bytes, 
        public_key: bytes
    ) -> bool:
        """Validate Dilithium signature."""
```

---

## 4. Database Schema Updates

### 4.1 New Tables

```sql
-- Validator registry
CREATE TABLE validators (
    id SERIAL PRIMARY KEY,
    address VARCHAR(128) UNIQUE NOT NULL,      -- PQ address
    public_key TEXT NOT NULL,                  -- Dilithium public key (hex)
    stake NUMERIC(20, 8) NOT NULL DEFAULT 0,
    effective_stake NUMERIC(20, 8) NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending, active, exiting, slashed
    activation_epoch INT,
    exit_epoch INT,
    slashed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Stake deposits
CREATE TABLE stake_deposits (
    id SERIAL PRIMARY KEY,
    validator_address VARCHAR(128) REFERENCES validators(address),
    amount NUMERIC(20, 8) NOT NULL,
    tx_hash CHAR(64) NOT NULL,
    block_number INT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Stake withdrawals (unbonding queue)
CREATE TABLE stake_withdrawals (
    id SERIAL PRIMARY KEY,
    validator_address VARCHAR(128) REFERENCES validators(address),
    amount NUMERIC(20, 8) NOT NULL,
    request_epoch INT NOT NULL,
    completion_epoch INT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',  -- pending, completed, cancelled
    created_at TIMESTAMP DEFAULT NOW()
);

-- Attestations
CREATE TABLE attestations (
    id SERIAL PRIMARY KEY,
    slot INT NOT NULL,
    epoch INT NOT NULL,
    block_hash CHAR(64) NOT NULL,
    validator_address VARCHAR(128) NOT NULL,
    signature TEXT NOT NULL,
    included_in_block INT,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(slot, validator_address)
);

-- Slashing events
CREATE TABLE slashing_events (
    id SERIAL PRIMARY KEY,
    validator_address VARCHAR(128) REFERENCES validators(address),
    slash_type VARCHAR(50) NOT NULL,  -- double_sign, invalid_attestation, downtime
    amount NUMERIC(20, 8) NOT NULL,
    evidence TEXT,
    block_number INT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Epoch data (for consensus state)
CREATE TABLE epochs (
    epoch INT PRIMARY KEY,
    start_slot INT NOT NULL,
    end_slot INT NOT NULL,
    randao_mix CHAR(64),
    finalized BOOLEAN DEFAULT FALSE,
    total_stake NUMERIC(20, 8),
    created_at TIMESTAMP DEFAULT NOW()
);
```

### 4.2 Updated Blocks Table

```sql
-- Updated blocks table for PoS
ALTER TABLE blocks 
    ADD COLUMN slot INT,
    ADD COLUMN epoch INT,
    ADD COLUMN proposer_address VARCHAR(128),
    ADD COLUMN proposer_signature TEXT,
    ADD COLUMN randao_reveal CHAR(64),
    ADD COLUMN attestation_count INT DEFAULT 0,
    ADD COLUMN finalized BOOLEAN DEFAULT FALSE;

-- Remove PoW-specific columns
ALTER TABLE blocks 
    DROP COLUMN IF EXISTS random,
    DROP COLUMN IF EXISTS difficulty;
```

---

## 5. Validator Node Component

### 5.1 Toggle-able Validator Mode

The validator functionality is a **separate, toggle-able component** that can be enabled via configuration:

```toml
# config.toml

[validator]
enabled = false                     # Toggle validator mode
pq_wallet_path = ""                 # Path to PQ wallet file
pq_wallet_password = ""             # Wallet password (env var recommended)

[validator.staking]
auto_restake_rewards = true         # Automatically restake earned rewards
target_stake = 100000               # Target stake amount

[validator.slashing_protection]
enabled = true                      # Enable slashing protection
db_path = "slashing_protection.db"  # Slashing protection database
```

### 5.2 Validator Startup Checks

```python
async def start_validator(config: ValidatorConfig) -> ValidatorManager:
    """
    Initialize validator with required checks.
    
    Raises:
        ValidatorError: If requirements not met
    """
    # Check 1: PQ wallet exists and is accessible
    if not config.pq_wallet_path:
        raise ValidatorError("PQ wallet path required for validator")
    
    wallet = PQWallet.load(config.pq_wallet_path, config.pq_wallet_password)
    
    # Check 2: Wallet is PQ type (not classical)
    if wallet.wallet_type != WalletType.POST_QUANTUM:
        raise ValidatorError("Validator MUST use Post-Quantum wallet")
    
    # Check 3: Check if liboqs is available
    if not PQWallet.is_pq_available():
        raise ValidatorError("liboqs required for validator operations")
    
    # Check 4: Wallet has sufficient stake
    stake = await StakeManager.get_effective_stake(wallet.address)
    if stake < MIN_VALIDATOR_STAKE:
        raise ValidatorError(
            f"Insufficient stake: {stake} < {MIN_VALIDATOR_STAKE} QRDX"
        )
    
    # Initialize validator manager
    return ValidatorManager(wallet, config)
```

---

## 6. Slashing Conditions

### 6.1 Slashing Types

| Condition | Penalty | Description |
|-----------|---------|-------------|
| Double Signing | 50% stake | Proposing two blocks at same height |
| Invalid Attestation | 30% stake | Attesting to provably invalid block |
| Downtime | 5% stake | Missing >10% attestations in epoch |
| Bridge Fraud | 100% stake | Submitting false bridge proofs |

### 6.2 Slashing Implementation

```python
class SlashingConditions(Enum):
    DOUBLE_SIGN = "double_sign"
    INVALID_ATTESTATION = "invalid_attestation"
    DOWNTIME = "downtime"
    BRIDGE_FRAUD = "bridge_fraud"

SLASHING_PENALTIES = {
    SlashingConditions.DOUBLE_SIGN: Decimal("0.50"),        # 50%
    SlashingConditions.INVALID_ATTESTATION: Decimal("0.30"), # 30%
    SlashingConditions.DOWNTIME: Decimal("0.05"),           # 5%
    SlashingConditions.BRIDGE_FRAUD: Decimal("1.00"),       # 100%
}

class SlashingExecutor:
    """Executes slashing when conditions are met."""
    
    async def check_double_sign(
        self, 
        block1: Block, 
        block2: Block
    ) -> Optional[SlashingEvidence]:
        """Check for double signing evidence."""
        
    async def check_downtime(
        self, 
        validator_address: str, 
        epoch: int
    ) -> Optional[SlashingEvidence]:
        """Check for downtime violations."""
        
    async def execute_slash(
        self, 
        evidence: SlashingEvidence
    ) -> bool:
        """Execute slashing penalty."""
```

---

## 7. Block Rewards

### 7.1 Reward Distribution

In PoS, rewards are distributed differently than PoW:

```python
def calculate_pos_reward(
    slot: int,
    base_reward: Decimal,
    attestation_inclusion: List[Attestation]
) -> Dict[str, Decimal]:
    """
    Calculate PoS rewards for a block.
    
    Distribution:
    - Block proposer: 25% of base reward
    - Attesters: 75% of base reward (split among attesters)
    - Attestation inclusion reward: Small bonus for including attestations
    """
    rewards = {}
    
    # Proposer reward
    proposer_reward = base_reward * Decimal("0.25")
    
    # Attester rewards (split among attesters)
    attester_pool = base_reward * Decimal("0.75")
    per_attester = attester_pool / len(attestation_inclusion)
    
    return rewards
```

---

## 8. Security Considerations

### 8.1 PQ Signature Security

All validator operations use Dilithium3 (ML-DSA-65):
- **NIST Level 3** security (equivalent to AES-192)
- Resistant to Shor's algorithm
- Public key: 1,952 bytes
- Signature: 3,309 bytes

### 8.2 BFT Safety Properties

- **Safety**: Guaranteed with <1/3 Byzantine validators
- **Liveness**: Guaranteed with >2/3 online validators
- **Finality**: Single-slot finality with >2/3 attestations

### 8.3 Long-Range Attack Protection

```python
class CheckpointManager:
    """
    Manages checkpoints to prevent long-range attacks.
    
    Checkpoints are finalized blocks that cannot be reverted.
    """
    
    async def create_checkpoint(self, block: Block) -> Checkpoint:
        """Create checkpoint for finalized block."""
        
    async def verify_chain_against_checkpoint(
        self, 
        chain: List[Block]
    ) -> bool:
        """Verify chain doesn't violate checkpoints."""
```

---

## 9. Implementation Timeline

### Phase 1: Core Infrastructure (Tasks 1-3)
- Document implementation plan ✓
- Create validator module structure
- Implement stake management

### Phase 2: Consensus Refactor (Tasks 4-6)
- Update consensus module for PoS
- Modify block manager
- Update database schema

### Phase 3: Integration (Tasks 7-9)
- Create validator node component
- Add RPC endpoints
- Configuration system

### Phase 4: Testing & Validation (Task 10-11)
- Unit tests for all components
- Integration testing
- Network testing

---

## 10. API Endpoints (New/Modified)

### Validator Operations

```
POST /validator/register        - Register as validator
POST /validator/deposit         - Deposit stake
POST /validator/withdraw        - Request withdrawal
GET  /validator/status          - Get validator status
GET  /validator/rewards         - Get pending rewards
```

### Consensus Information

```
GET /consensus/epoch/{epoch}    - Get epoch information
GET /consensus/validators       - Get active validator set
GET /consensus/attestations     - Get recent attestations
GET /consensus/finality         - Get finality status
```

---

## 11. Migration Notes

This is a **mainnet PoS implementation** - no transition from PoW required.

**Genesis Configuration:**
- Initial validator set defined in genesis block
- Initial stakes distributed per tokenomics
- Epoch 0 starts at genesis

**Backward Compatibility:**
- Transaction format remains compatible
- RPC endpoints extended (not replaced)
- Wallet operations unchanged

---

## References

- QRDX Whitepaper v2.3 (Section 9: Consensus Mechanism)
- CRYSTALS-Dilithium NIST FIPS 204
- Ethereum 2.0 Beacon Chain Spec
- Gasper: Combining GHOST and Casper

---

*Document Version: 1.0*
*Last Updated: January 2026*
*Author: QRDX Development Team*
