-- QRDX Chain Database Schema
-- Supports Quantum-Resistant Proof-of-Stake (QR-PoS) consensus

-- =============================================================================
-- CUSTOM TYPES
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type
        WHERE typname = 'tx_output'
    ) THEN
        CREATE TYPE tx_output AS (
            tx_hash CHAR(64),
            index SMALLINT
        );
    END IF;
END$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_type WHERE typname = 'validator_status'
    ) THEN
        CREATE TYPE validator_status AS ENUM (
            'pending',
            'active',
            'exiting',
            'exited',
            'slashed'
        );
    END IF;
END$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_type WHERE typname = 'slashing_condition'
    ) THEN
        CREATE TYPE slashing_condition AS ENUM (
            'double_sign',
            'invalid_attestation',
            'surround_vote',
            'downtime',
            'bridge_fraud'
        );
    END IF;
END$$;

-- =============================================================================
-- BLOCKS TABLE (Updated for PoS)
-- =============================================================================

CREATE TABLE IF NOT EXISTS blocks (
    id SERIAL PRIMARY KEY,
    hash CHAR(64) UNIQUE,
    content TEXT NOT NULL,
    address VARCHAR(128) NOT NULL,
    
    -- Legacy PoW fields (deprecated but kept for migration)
    random BIGINT DEFAULT 0,
    difficulty NUMERIC(3, 1) DEFAULT 0,
    
    -- PoS fields
    slot BIGINT,
    epoch INTEGER,
    proposer_address VARCHAR(128),
    proposer_signature TEXT,           -- Dilithium signature (base64)
    randao_reveal TEXT,                -- RANDAO contribution
    attestations_included INTEGER DEFAULT 0,
    
    reward NUMERIC(14, 6) NOT NULL,
    timestamp TIMESTAMP(0)
);

-- PoS block indexes
CREATE INDEX IF NOT EXISTS blocks_slot_idx ON blocks (slot);
CREATE INDEX IF NOT EXISTS blocks_epoch_idx ON blocks (epoch);
CREATE INDEX IF NOT EXISTS blocks_proposer_idx ON blocks (proposer_address);

CREATE TABLE IF NOT EXISTS transactions (
    block_hash CHAR(64) NOT NULL REFERENCES blocks(hash) ON DELETE CASCADE,
    tx_hash CHAR(64) UNIQUE,
    tx_hex TEXT,
    inputs_addresses TEXT[],
    outputs_addresses TEXT[],
    outputs_amounts BIGINT[],
    fees NUMERIC(14, 6) NOT NULL,
    time_received TIMESTAMP(0)
);

CREATE TABLE IF NOT EXISTS unspent_outputs (
    tx_hash CHAR(64) REFERENCES transactions(tx_hash) ON DELETE CASCADE,
    index SMALLINT NOT NULL,
    address TEXT NULL
);

CREATE TABLE IF NOT EXISTS pending_transactions (
    tx_hash CHAR(64) UNIQUE,
    tx_hex TEXT,
    inputs_addresses TEXT[],
    fees NUMERIC(14, 6) NOT NULL,
    propagation_time TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    time_received TIMESTAMP(0)
);

CREATE TABLE IF NOT EXISTS pending_spent_outputs (
    tx_hash CHAR(64) REFERENCES transactions(tx_hash) ON DELETE CASCADE,
    index SMALLINT NOT NULL
);

CREATE INDEX IF NOT EXISTS tx_hash_idx ON unspent_outputs (tx_hash);
CREATE INDEX IF NOT EXISTS block_hash_idx ON transactions (block_hash);

-- =============================================================================
-- VALIDATORS TABLE
-- Core validator registry for QR-PoS
-- =============================================================================

CREATE TABLE IF NOT EXISTS validators (
    id SERIAL PRIMARY KEY,
    address VARCHAR(128) UNIQUE NOT NULL,
    public_key TEXT NOT NULL,              -- Dilithium public key (hex)
    
    -- Stake information
    stake NUMERIC(20, 6) NOT NULL DEFAULT 0,
    effective_stake NUMERIC(20, 6) NOT NULL DEFAULT 0,
    
    -- Status
    status validator_status NOT NULL DEFAULT 'pending',
    activation_epoch INTEGER,
    exit_epoch INTEGER,
    withdrawable_epoch INTEGER,
    slashed BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Performance metrics
    blocks_proposed INTEGER NOT NULL DEFAULT 0,
    blocks_missed INTEGER NOT NULL DEFAULT 0,
    attestations_made INTEGER NOT NULL DEFAULT 0,
    attestations_missed INTEGER NOT NULL DEFAULT 0,
    
    -- Rewards tracking
    total_rewards NUMERIC(20, 6) NOT NULL DEFAULT 0,
    total_slashed NUMERIC(20, 6) NOT NULL DEFAULT 0,
    
    -- Metadata
    graffiti VARCHAR(32),
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS validators_status_idx ON validators (status);
CREATE INDEX IF NOT EXISTS validators_stake_idx ON validators (effective_stake DESC);

-- =============================================================================
-- STAKES TABLE
-- Individual stake deposits and withdrawals
-- =============================================================================

CREATE TABLE IF NOT EXISTS stakes (
    id SERIAL PRIMARY KEY,
    validator_address VARCHAR(128) NOT NULL REFERENCES validators(address),
    amount NUMERIC(20, 6) NOT NULL,
    deposit_epoch INTEGER NOT NULL,
    
    -- Withdrawal tracking
    withdrawal_requested_epoch INTEGER,
    withdrawal_completed_epoch INTEGER,
    withdrawable_at TIMESTAMP(0),
    
    -- Transaction reference
    deposit_tx_hash CHAR(64),
    withdrawal_tx_hash CHAR(64),
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS stakes_validator_idx ON stakes (validator_address);
CREATE INDEX IF NOT EXISTS stakes_deposit_epoch_idx ON stakes (deposit_epoch);

-- =============================================================================
-- EPOCHS TABLE
-- Epoch metadata and finality tracking
-- =============================================================================

CREATE TABLE IF NOT EXISTS epochs (
    epoch INTEGER PRIMARY KEY,
    
    -- Slot range
    start_slot BIGINT NOT NULL,
    end_slot BIGINT NOT NULL,
    
    -- Validators
    active_validators INTEGER NOT NULL DEFAULT 0,
    total_stake NUMERIC(24, 6) NOT NULL DEFAULT 0,
    
    -- Finality
    finalized BOOLEAN NOT NULL DEFAULT FALSE,
    justified BOOLEAN NOT NULL DEFAULT FALSE,
    finality_root CHAR(64),
    
    -- Randomness
    randao_mix TEXT,
    
    -- Rewards distribution
    total_rewards NUMERIC(20, 6) NOT NULL DEFAULT 0,
    total_penalties NUMERIC(20, 6) NOT NULL DEFAULT 0,
    
    -- Timestamps
    started_at TIMESTAMP(0),
    finalized_at TIMESTAMP(0),
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- ATTESTATIONS TABLE
-- Validator attestations for block finality
-- =============================================================================

CREATE TABLE IF NOT EXISTS attestations (
    id SERIAL PRIMARY KEY,
    
    -- Attestation data
    slot BIGINT NOT NULL,
    epoch INTEGER NOT NULL,
    block_hash CHAR(64) NOT NULL,
    
    -- Validator info
    validator_address VARCHAR(128) NOT NULL,
    validator_index INTEGER NOT NULL,
    signature TEXT NOT NULL,               -- Dilithium signature (base64)
    
    -- Checkpoint data
    source_epoch INTEGER NOT NULL,
    target_epoch INTEGER NOT NULL,
    
    -- Inclusion info
    included_in_block CHAR(64),
    inclusion_slot BIGINT,
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    
    UNIQUE (slot, validator_address)
);

CREATE INDEX IF NOT EXISTS attestations_slot_idx ON attestations (slot);
CREATE INDEX IF NOT EXISTS attestations_epoch_idx ON attestations (epoch);
CREATE INDEX IF NOT EXISTS attestations_block_idx ON attestations (block_hash);
CREATE INDEX IF NOT EXISTS attestations_validator_idx ON attestations (validator_address);
CREATE INDEX IF NOT EXISTS attestations_inclusion_idx ON attestations (included_in_block);

-- =============================================================================
-- SLASHING EVENTS TABLE
-- Record of slashing incidents
-- =============================================================================

CREATE TABLE IF NOT EXISTS slashing_events (
    id SERIAL PRIMARY KEY,
    
    -- Validator being slashed
    validator_address VARCHAR(128) NOT NULL REFERENCES validators(address),
    
    -- Slashing details
    condition slashing_condition NOT NULL,
    slot BIGINT NOT NULL,
    epoch INTEGER NOT NULL,
    
    -- Evidence
    evidence_type VARCHAR(64),
    evidence_data TEXT,                    -- JSON evidence
    
    -- Penalty
    penalty_amount NUMERIC(20, 6) NOT NULL,
    penalty_percentage NUMERIC(5, 2) NOT NULL,
    
    -- Reporter (gets reward)
    reporter_address VARCHAR(128),
    reporter_reward NUMERIC(20, 6),
    
    -- Status
    executed BOOLEAN NOT NULL DEFAULT FALSE,
    executed_at TIMESTAMP(0),
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS slashing_validator_idx ON slashing_events (validator_address);
CREATE INDEX IF NOT EXISTS slashing_epoch_idx ON slashing_events (epoch);

-- =============================================================================
-- SLASHING PROTECTION TABLE
-- Prevent accidental double-signing
-- =============================================================================

CREATE TABLE IF NOT EXISTS slashing_protection (
    id SERIAL PRIMARY KEY,
    validator_address VARCHAR(128) NOT NULL,
    
    -- For block proposals
    signed_blocks JSONB NOT NULL DEFAULT '[]',
    
    -- For attestations: (source_epoch, target_epoch) pairs
    signed_attestations JSONB NOT NULL DEFAULT '[]',
    
    -- Last update
    updated_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    
    UNIQUE (validator_address)
);

-- =============================================================================
-- PROPOSER DUTIES TABLE
-- Pre-computed block proposal schedule
-- =============================================================================

CREATE TABLE IF NOT EXISTS proposer_duties (
    slot BIGINT PRIMARY KEY,
    epoch INTEGER NOT NULL,
    validator_address VARCHAR(128) NOT NULL,
    
    -- Execution status
    proposed BOOLEAN NOT NULL DEFAULT FALSE,
    proposed_block_hash CHAR(64),
    missed BOOLEAN NOT NULL DEFAULT FALSE,
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS proposer_duties_epoch_idx ON proposer_duties (epoch);
CREATE INDEX IF NOT EXISTS proposer_duties_validator_idx ON proposer_duties (validator_address);

-- =============================================================================
-- VALIDATOR REWARDS TABLE
-- Detailed reward tracking per epoch
-- =============================================================================

CREATE TABLE IF NOT EXISTS validator_rewards (
    id SERIAL PRIMARY KEY,
    validator_address VARCHAR(128) NOT NULL REFERENCES validators(address),
    epoch INTEGER NOT NULL,
    
    -- Reward breakdown
    proposal_reward NUMERIC(14, 6) NOT NULL DEFAULT 0,
    attestation_reward NUMERIC(14, 6) NOT NULL DEFAULT 0,
    sync_reward NUMERIC(14, 6) NOT NULL DEFAULT 0,
    
    -- Penalties
    missed_proposal_penalty NUMERIC(14, 6) NOT NULL DEFAULT 0,
    missed_attestation_penalty NUMERIC(14, 6) NOT NULL DEFAULT 0,
    inactivity_penalty NUMERIC(14, 6) NOT NULL DEFAULT 0,
    
    -- Net
    net_reward NUMERIC(14, 6) NOT NULL DEFAULT 0,
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    
    UNIQUE (validator_address, epoch)
);

CREATE INDEX IF NOT EXISTS validator_rewards_epoch_idx ON validator_rewards (epoch);

-- =============================================================================
-- CHECKPOINT TABLE
-- Finality checkpoint tracking
-- =============================================================================

CREATE TABLE IF NOT EXISTS checkpoints (
    id SERIAL PRIMARY KEY,
    epoch INTEGER NOT NULL,
    root CHAR(64) NOT NULL,
    
    -- Justification
    justified BOOLEAN NOT NULL DEFAULT FALSE,
    justified_at TIMESTAMP(0),
    
    -- Finalization
    finalized BOOLEAN NOT NULL DEFAULT FALSE,
    finalized_at TIMESTAMP(0),
    
    -- Votes
    total_stake_voted NUMERIC(24, 6) NOT NULL DEFAULT 0,
    attestation_count INTEGER NOT NULL DEFAULT 0,
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    
    UNIQUE (epoch, root)
);

CREATE INDEX IF NOT EXISTS checkpoints_epoch_idx ON checkpoints (epoch);
CREATE INDEX IF NOT EXISTS checkpoints_finalized_idx ON checkpoints (finalized);

-- =============================================================================
-- SYSTEM WALLETS TABLE
-- Tracks system-owned wallets controlled by a PQ controller wallet
-- =============================================================================

CREATE TABLE IF NOT EXISTS system_wallets (
    address VARCHAR(66) PRIMARY KEY,  -- 0x0000...000X format
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    wallet_type VARCHAR(50) NOT NULL,
    controller_address VARCHAR(128) NOT NULL,  -- PQ address that controls this wallet
    is_burner BOOLEAN NOT NULL DEFAULT FALSE,
    category VARCHAR(50) NOT NULL,  -- system, treasury, defi, distribution, security
    genesis_balance NUMERIC(24, 6) NOT NULL DEFAULT 0,
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS system_wallets_controller_idx ON system_wallets (controller_address);
CREATE INDEX IF NOT EXISTS system_wallets_category_idx ON system_wallets (category);
CREATE INDEX IF NOT EXISTS system_wallets_type_idx ON system_wallets (wallet_type);

-- =============================================================================
-- CHAIN METADATA TABLE
-- Stores genesis and chain configuration metadata
-- =============================================================================

CREATE TABLE IF NOT EXISTS chain_metadata (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS chain_metadata_value_idx ON chain_metadata USING GIN (value);

