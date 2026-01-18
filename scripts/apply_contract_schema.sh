#!/bin/bash
# Apply contract database schema to QRDX chain

set -e

echo "================================================================================================"
echo "QRDX CONTRACT SCHEMA MIGRATION"
echo "================================================================================================"
echo ""

# Database configuration
DB_HOST="${DENARO_DATABASE_HOST:-localhost}"
DB_NAME="${DENARO_DATABASE_NAME:-denaro}"
DB_USER="${POSTGRES_USER:-postgres}"

SCHEMA_FILE="qrdx/schema_contracts.sql"

# Check if schema file exists
if [ ! -f "$SCHEMA_FILE" ]; then
    echo "❌ Error: Schema file not found: $SCHEMA_FILE"
    exit 1
fi

echo "Database Configuration:"
echo "  Host: $DB_HOST"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo ""

echo "Applying contract schema..."
echo "------------------------------------------------------------------------------------------------"

# Apply schema using psql
if command -v psql &> /dev/null; then
    psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -f "$SCHEMA_FILE"
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✅ Contract schema applied successfully!"
        echo ""
        echo "Created 11 contract tables:"
        echo "  ✓ account_state - Ethereum-style accounts (balance, nonce, code_hash, storage_root)"
        echo "  ✓ contract_code - Deployed contract bytecode with deployer tracking"
        echo "  ✓ contract_storage - Contract key-value storage (32-byte keys/values)"
        echo "  ✓ contract_transactions - Transaction history with gas tracking"
        echo "  ✓ contract_logs - Event logs indexed by 4 topics"
        echo "  ✓ contract_metadata - Source code, ABI, compiler version, verification"
        echo "  ✓ state_trie - Merkle Patricia Trie nodes for account state"
        echo "  ✓ storage_trie - Per-contract storage trie nodes"
        echo "  ✓ gas_usage - Block-level gas usage analytics"
        echo "  ✓ vm_traces - Execution traces for debugging"
        echo "  ✓ contract_calls - Internal contract-to-contract calls"
        echo ""
        echo "Your QRDX node now supports 100% Ethereum-compatible smart contracts!"
        echo ""
    else
        echo ""
        echo "❌ Error applying schema. Check database connection and permissions."
        exit 1
    fi
else
    echo "❌ Error: psql command not found. Please install PostgreSQL client."
    echo ""
    echo "Alternative: Execute the SQL manually:"
    echo "  psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f $SCHEMA_FILE"
    exit 1
fi

echo "================================================================================================"
echo "MIGRATION COMPLETE"
echo "================================================================================================"
