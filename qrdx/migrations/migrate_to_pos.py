#!/usr/bin/env python3
"""
QRDX Database Migration Script: PoW to PoS

This script migrates an existing QRDX database from PoW consensus to PoS.
It adds the necessary tables for validators, attestations, epochs, and slashing.

Usage:
    python -m qrdx.migrations.migrate_to_pos --database-url postgresql://user:pass@host/db

IMPORTANT: 
- Always backup your database before running migrations
- This migration is one-way (no automatic rollback)
- Run during a maintenance window when no blocks are being produced
"""

import argparse
import asyncio
import sys
from datetime import datetime

import asyncpg


MIGRATION_VERSION = "2.0.0-pos"
MIGRATION_DATE = "2025-01-01"


# SQL statements for the migration
MIGRATION_SQL = """
-- =============================================================================
-- QRDX PoS Migration
-- Version: 2.0.0-pos
-- =============================================================================

-- Record migration start
INSERT INTO migrations (version, description, started_at) 
VALUES ('2.0.0-pos', 'Proof-of-Stake consensus migration', NOW())
ON CONFLICT (version) DO NOTHING;

-- =============================================================================
-- CUSTOM TYPES
-- =============================================================================

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
-- UPDATE BLOCKS TABLE FOR PoS
-- =============================================================================

-- Add PoS columns to existing blocks table (if not present)
ALTER TABLE blocks ADD COLUMN IF NOT EXISTS slot BIGINT;
ALTER TABLE blocks ADD COLUMN IF NOT EXISTS epoch INTEGER;
ALTER TABLE blocks ADD COLUMN IF NOT EXISTS proposer_address VARCHAR(128);
ALTER TABLE blocks ADD COLUMN IF NOT EXISTS proposer_signature TEXT;
ALTER TABLE blocks ADD COLUMN IF NOT EXISTS randao_reveal TEXT;
ALTER TABLE blocks ADD COLUMN IF NOT EXISTS attestations_included INTEGER DEFAULT 0;

-- Make PoW columns optional (allow NULL for PoS blocks)
ALTER TABLE blocks ALTER COLUMN random DROP NOT NULL;
ALTER TABLE blocks ALTER COLUMN difficulty DROP NOT NULL;

-- Set defaults for PoS blocks
ALTER TABLE blocks ALTER COLUMN random SET DEFAULT 0;
ALTER TABLE blocks ALTER COLUMN difficulty SET DEFAULT 1.0;

-- Add PoS indexes
CREATE INDEX IF NOT EXISTS blocks_slot_idx ON blocks (slot);
CREATE INDEX IF NOT EXISTS blocks_epoch_idx ON blocks (epoch);
CREATE INDEX IF NOT EXISTS blocks_proposer_idx ON blocks (proposer_address);

-- =============================================================================
-- VALIDATORS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS validators (
    id SERIAL PRIMARY KEY,
    address VARCHAR(128) UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    
    stake NUMERIC(20, 6) NOT NULL DEFAULT 0,
    effective_stake NUMERIC(20, 6) NOT NULL DEFAULT 0,
    
    status validator_status NOT NULL DEFAULT 'pending',
    activation_epoch INTEGER,
    exit_epoch INTEGER,
    withdrawable_epoch INTEGER,
    slashed BOOLEAN NOT NULL DEFAULT FALSE,
    
    blocks_proposed INTEGER NOT NULL DEFAULT 0,
    blocks_missed INTEGER NOT NULL DEFAULT 0,
    attestations_made INTEGER NOT NULL DEFAULT 0,
    attestations_missed INTEGER NOT NULL DEFAULT 0,
    
    total_rewards NUMERIC(20, 6) NOT NULL DEFAULT 0,
    total_slashed NUMERIC(20, 6) NOT NULL DEFAULT 0,
    
    graffiti VARCHAR(32),
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS validators_status_idx ON validators (status);
CREATE INDEX IF NOT EXISTS validators_stake_idx ON validators (effective_stake DESC);

-- =============================================================================
-- STAKES TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS stakes (
    id SERIAL PRIMARY KEY,
    validator_address VARCHAR(128) NOT NULL REFERENCES validators(address),
    amount NUMERIC(20, 6) NOT NULL,
    deposit_epoch INTEGER NOT NULL,
    
    withdrawal_requested_epoch INTEGER,
    withdrawal_completed_epoch INTEGER,
    withdrawable_at TIMESTAMP(0),
    
    deposit_tx_hash CHAR(64),
    withdrawal_tx_hash CHAR(64),
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS stakes_validator_idx ON stakes (validator_address);
CREATE INDEX IF NOT EXISTS stakes_deposit_epoch_idx ON stakes (deposit_epoch);

-- =============================================================================
-- EPOCHS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS epochs (
    epoch INTEGER PRIMARY KEY,
    
    start_slot BIGINT NOT NULL,
    end_slot BIGINT NOT NULL,
    
    active_validators INTEGER NOT NULL DEFAULT 0,
    total_stake NUMERIC(24, 6) NOT NULL DEFAULT 0,
    
    finalized BOOLEAN NOT NULL DEFAULT FALSE,
    justified BOOLEAN NOT NULL DEFAULT FALSE,
    finality_root CHAR(64),
    
    randao_mix TEXT,
    
    total_rewards NUMERIC(20, 6) NOT NULL DEFAULT 0,
    total_penalties NUMERIC(20, 6) NOT NULL DEFAULT 0,
    
    started_at TIMESTAMP(0),
    finalized_at TIMESTAMP(0),
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- ATTESTATIONS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS attestations (
    id SERIAL PRIMARY KEY,
    
    slot BIGINT NOT NULL,
    epoch INTEGER NOT NULL,
    block_hash CHAR(64) NOT NULL,
    
    validator_address VARCHAR(128) NOT NULL,
    validator_index INTEGER NOT NULL,
    signature TEXT NOT NULL,
    
    source_epoch INTEGER NOT NULL,
    target_epoch INTEGER NOT NULL,
    
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
-- =============================================================================

CREATE TABLE IF NOT EXISTS slashing_events (
    id SERIAL PRIMARY KEY,
    
    validator_address VARCHAR(128) NOT NULL REFERENCES validators(address),
    
    condition slashing_condition NOT NULL,
    slot BIGINT NOT NULL,
    epoch INTEGER NOT NULL,
    
    evidence_type VARCHAR(64),
    evidence_data TEXT,
    
    penalty_amount NUMERIC(20, 6) NOT NULL,
    penalty_percentage NUMERIC(5, 2) NOT NULL,
    
    reporter_address VARCHAR(128),
    reporter_reward NUMERIC(20, 6),
    
    executed BOOLEAN NOT NULL DEFAULT FALSE,
    executed_at TIMESTAMP(0),
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS slashing_validator_idx ON slashing_events (validator_address);
CREATE INDEX IF NOT EXISTS slashing_epoch_idx ON slashing_events (epoch);

-- =============================================================================
-- SLASHING PROTECTION TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS slashing_protection (
    id SERIAL PRIMARY KEY,
    validator_address VARCHAR(128) NOT NULL,
    
    signed_blocks JSONB NOT NULL DEFAULT '[]',
    signed_attestations JSONB NOT NULL DEFAULT '[]',
    
    updated_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    
    UNIQUE (validator_address)
);

-- =============================================================================
-- PROPOSER DUTIES TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS proposer_duties (
    slot BIGINT PRIMARY KEY,
    epoch INTEGER NOT NULL,
    validator_address VARCHAR(128) NOT NULL,
    
    proposed BOOLEAN NOT NULL DEFAULT FALSE,
    proposed_block_hash CHAR(64),
    missed BOOLEAN NOT NULL DEFAULT FALSE,
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS proposer_duties_epoch_idx ON proposer_duties (epoch);
CREATE INDEX IF NOT EXISTS proposer_duties_validator_idx ON proposer_duties (validator_address);

-- =============================================================================
-- VALIDATOR REWARDS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS validator_rewards (
    id SERIAL PRIMARY KEY,
    validator_address VARCHAR(128) NOT NULL REFERENCES validators(address),
    epoch INTEGER NOT NULL,
    
    proposal_reward NUMERIC(14, 6) NOT NULL DEFAULT 0,
    attestation_reward NUMERIC(14, 6) NOT NULL DEFAULT 0,
    sync_reward NUMERIC(14, 6) NOT NULL DEFAULT 0,
    
    missed_proposal_penalty NUMERIC(14, 6) NOT NULL DEFAULT 0,
    missed_attestation_penalty NUMERIC(14, 6) NOT NULL DEFAULT 0,
    inactivity_penalty NUMERIC(14, 6) NOT NULL DEFAULT 0,
    
    net_reward NUMERIC(14, 6) NOT NULL DEFAULT 0,
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    
    UNIQUE (validator_address, epoch)
);

CREATE INDEX IF NOT EXISTS validator_rewards_epoch_idx ON validator_rewards (epoch);

-- =============================================================================
-- CHECKPOINTS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS checkpoints (
    id SERIAL PRIMARY KEY,
    epoch INTEGER NOT NULL,
    root CHAR(64) NOT NULL,
    
    justified BOOLEAN NOT NULL DEFAULT FALSE,
    justified_at TIMESTAMP(0),
    
    finalized BOOLEAN NOT NULL DEFAULT FALSE,
    finalized_at TIMESTAMP(0),
    
    total_stake_voted NUMERIC(24, 6) NOT NULL DEFAULT 0,
    attestation_count INTEGER NOT NULL DEFAULT 0,
    
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    
    UNIQUE (epoch, root)
);

CREATE INDEX IF NOT EXISTS checkpoints_epoch_idx ON checkpoints (epoch);
CREATE INDEX IF NOT EXISTS checkpoints_finalized_idx ON checkpoints (finalized);

-- =============================================================================
-- MIGRATIONS TABLE (for tracking applied migrations)
-- =============================================================================

CREATE TABLE IF NOT EXISTS migrations (
    version VARCHAR(32) PRIMARY KEY,
    description TEXT,
    started_at TIMESTAMP(0),
    completed_at TIMESTAMP(0),
    success BOOLEAN DEFAULT FALSE
);

-- Mark migration as complete
UPDATE migrations 
SET completed_at = NOW(), success = TRUE 
WHERE version = '2.0.0-pos';

-- =============================================================================
-- VERIFY MIGRATION
-- =============================================================================

-- This query should return all new tables
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN (
    'validators', 'stakes', 'epochs', 'attestations', 
    'slashing_events', 'slashing_protection', 'proposer_duties',
    'validator_rewards', 'checkpoints', 'migrations'
);
"""


async def run_migration(database_url: str, dry_run: bool = False) -> bool:
    """
    Run the PoS database migration.
    
    Args:
        database_url: PostgreSQL connection URL
        dry_run: If True, only validate without applying changes
        
    Returns:
        True if migration successful
    """
    print(f"QRDX PoS Migration - Version {MIGRATION_VERSION}")
    print("=" * 60)
    print(f"Started at: {datetime.now().isoformat()}")
    print(f"Database: {database_url.split('@')[-1] if '@' in database_url else database_url}")
    print()
    
    try:
        # Connect to database
        conn = await asyncpg.connect(database_url)
        print("✓ Connected to database")
        
        # Check if migration already applied
        try:
            result = await conn.fetchrow(
                "SELECT * FROM migrations WHERE version = $1",
                MIGRATION_VERSION
            )
            if result and result['success']:
                print(f"✓ Migration {MIGRATION_VERSION} already applied")
                await conn.close()
                return True
        except asyncpg.UndefinedTableError:
            pass  # migrations table doesn't exist yet
        
        if dry_run:
            print("\n[DRY RUN] Would execute the following changes:")
            print("-" * 40)
            # Just validate SQL syntax
            try:
                await conn.execute("BEGIN")
                await conn.execute(MIGRATION_SQL)
                await conn.execute("ROLLBACK")
                print("✓ SQL syntax validated")
            except Exception as e:
                print(f"✗ SQL validation error: {e}")
                return False
        else:
            print("\nApplying migration...")
            print("-" * 40)
            
            # Run migration in transaction
            async with conn.transaction():
                await conn.execute(MIGRATION_SQL)
            
            print("✓ Migration SQL executed")
            
            # Verify tables created
            tables = await conn.fetch("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN (
                    'validators', 'stakes', 'epochs', 'attestations', 
                    'slashing_events', 'slashing_protection', 'proposer_duties',
                    'validator_rewards', 'checkpoints', 'migrations'
                )
            """)
            
            print(f"✓ Created {len(tables)} tables:")
            for t in tables:
                print(f"  - {t['table_name']}")
            
            # Verify blocks table updated
            columns = await conn.fetch("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'blocks' 
                AND column_name IN ('slot', 'epoch', 'proposer_address')
            """)
            
            print(f"✓ Updated blocks table with {len(columns)} new columns")
        
        await conn.close()
        
        print()
        print("=" * 60)
        if dry_run:
            print("[DRY RUN] Migration validated successfully")
        else:
            print(f"Migration {MIGRATION_VERSION} completed successfully!")
        print(f"Completed at: {datetime.now().isoformat()}")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="QRDX PoS Database Migration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run migration
  python -m qrdx.migrations.migrate_to_pos --database-url postgresql://qrdx:qrdx@localhost/qrdx
  
  # Dry run (validate only)
  python -m qrdx.migrations.migrate_to_pos --database-url postgresql://qrdx:qrdx@localhost/qrdx --dry-run
        """
    )
    
    parser.add_argument(
        "--database-url",
        required=True,
        help="PostgreSQL connection URL",
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate migration without applying changes",
    )
    
    args = parser.parse_args()
    
    # Run migration
    success = asyncio.run(run_migration(args.database_url, args.dry_run))
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
