-- Contract State Tables for QRDX
-- Ethereum-compatible contract storage with state trie support

-- ============================================================================
-- ACCOUNT STATE (Ethereum-style accounts)
-- ============================================================================

CREATE TABLE IF NOT EXISTS account_state (
    address TEXT PRIMARY KEY,  -- Account address (0x... format)
    balance TEXT NOT NULL DEFAULT '0',  -- Account balance in smallest unit
    nonce INTEGER NOT NULL DEFAULT 0,  -- Transaction nonce
    code_hash TEXT,  -- Hash of contract code (NULL for EOA)
    storage_root TEXT,  -- Root hash of storage trie
    created_at INTEGER NOT NULL,  -- Block number when created
    updated_at INTEGER NOT NULL,  -- Last update block number
    is_contract BOOLEAN NOT NULL DEFAULT 0,  -- True if contract account
    FOREIGN KEY (created_at) REFERENCES blocks(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_account_state_address ON account_state(address);
CREATE INDEX IF NOT EXISTS idx_account_state_is_contract ON account_state(is_contract);
CREATE INDEX IF NOT EXISTS idx_account_state_updated_at ON account_state(updated_at);


-- ============================================================================
-- CONTRACT CODE
-- ============================================================================

CREATE TABLE IF NOT EXISTS contract_code (
    code_hash TEXT PRIMARY KEY,  -- keccak256 hash of bytecode
    bytecode BLOB NOT NULL,  -- Contract bytecode
    deployed_at INTEGER NOT NULL,  -- Block number of deployment
    deployer TEXT NOT NULL,  -- Address that deployed contract
    size INTEGER NOT NULL,  -- Bytecode size in bytes
    FOREIGN KEY (deployed_at) REFERENCES blocks(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_code_deployer ON contract_code(deployer);
CREATE INDEX IF NOT EXISTS idx_contract_code_deployed_at ON contract_code(deployed_at);


-- ============================================================================
-- CONTRACT STORAGE
-- ============================================================================

CREATE TABLE IF NOT EXISTS contract_storage (
    contract_address TEXT NOT NULL,  -- Contract address
    storage_key TEXT NOT NULL,  -- Storage slot key (32 bytes hex)
    storage_value TEXT NOT NULL,  -- Storage value (32 bytes hex)
    block_number INTEGER NOT NULL,  -- Block where last modified
    PRIMARY KEY (contract_address, storage_key),
    FOREIGN KEY (contract_address) REFERENCES account_state(address) ON DELETE CASCADE,
    FOREIGN KEY (block_number) REFERENCES blocks(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_storage_address ON contract_storage(contract_address);
CREATE INDEX IF NOT EXISTS idx_contract_storage_block ON contract_storage(block_number);


-- ============================================================================
-- CONTRACT TRANSACTIONS
-- ============================================================================

CREATE TABLE IF NOT EXISTS contract_transactions (
    tx_hash TEXT PRIMARY KEY,  -- Transaction hash
    block_number INTEGER NOT NULL,  -- Block number
    tx_index INTEGER NOT NULL,  -- Transaction index in block
    from_address TEXT NOT NULL,  -- Sender address
    to_address TEXT,  -- Recipient (NULL for contract creation)
    value TEXT NOT NULL DEFAULT '0',  -- Value transferred
    gas_limit INTEGER NOT NULL,  -- Gas limit
    gas_used INTEGER NOT NULL,  -- Actual gas used
    gas_price TEXT NOT NULL,  -- Gas price
    nonce INTEGER NOT NULL,  -- Sender nonce
    input_data BLOB,  -- Transaction input data/bytecode
    contract_address TEXT,  -- Created contract address (if creation)
    status INTEGER NOT NULL DEFAULT 1,  -- 1 = success, 0 = failure
    error_message TEXT,  -- Error if failed
    logs_bloom BLOB,  -- Bloom filter for logs
    created_at INTEGER NOT NULL,  -- Timestamp
    FOREIGN KEY (block_number) REFERENCES blocks(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_tx_block ON contract_transactions(block_number);
CREATE INDEX IF NOT EXISTS idx_contract_tx_from ON contract_transactions(from_address);
CREATE INDEX IF NOT EXISTS idx_contract_tx_to ON contract_transactions(to_address);
CREATE INDEX IF NOT EXISTS idx_contract_tx_contract ON contract_transactions(contract_address);
CREATE INDEX IF NOT EXISTS idx_contract_tx_created ON contract_transactions(created_at);


-- ============================================================================
-- CONTRACT EVENTS/LOGS
-- ============================================================================

CREATE TABLE IF NOT EXISTS contract_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash TEXT NOT NULL,  -- Transaction that emitted log
    block_number INTEGER NOT NULL,  -- Block number
    log_index INTEGER NOT NULL,  -- Log index within transaction
    contract_address TEXT NOT NULL,  -- Contract that emitted log
    topic0 TEXT,  -- Event signature hash
    topic1 TEXT,  -- Indexed parameter 1
    topic2 TEXT,  -- Indexed parameter 2
    topic3 TEXT,  -- Indexed parameter 3
    data BLOB,  -- Non-indexed event data
    removed BOOLEAN NOT NULL DEFAULT 0,  -- True if removed due to reorg
    FOREIGN KEY (tx_hash) REFERENCES contract_transactions(tx_hash) ON DELETE CASCADE,
    FOREIGN KEY (block_number) REFERENCES blocks(id) ON DELETE CASCADE,
    UNIQUE(tx_hash, log_index)
);

CREATE INDEX IF NOT EXISTS idx_contract_logs_tx ON contract_logs(tx_hash);
CREATE INDEX IF NOT EXISTS idx_contract_logs_block ON contract_logs(block_number);
CREATE INDEX IF NOT EXISTS idx_contract_logs_address ON contract_logs(contract_address);
CREATE INDEX IF NOT EXISTS idx_contract_logs_topic0 ON contract_logs(topic0);
CREATE INDEX IF NOT EXISTS idx_contract_logs_topic1 ON contract_logs(topic1);
CREATE INDEX IF NOT EXISTS idx_contract_logs_topic2 ON contract_logs(topic2);
CREATE INDEX IF NOT EXISTS idx_contract_logs_topic3 ON contract_logs(topic3);


-- ============================================================================
-- CONTRACT METADATA
-- ============================================================================

CREATE TABLE IF NOT EXISTS contract_metadata (
    contract_address TEXT PRIMARY KEY,  -- Contract address
    name TEXT,  -- Contract name
    symbol TEXT,  -- Token symbol (if applicable)
    compiler_version TEXT,  -- Solidity/Vyper version
    source_code TEXT,  -- Contract source code
    abi TEXT,  -- Contract ABI (JSON)
    constructor_args BLOB,  -- Constructor arguments
    optimization_enabled BOOLEAN,  -- Compiler optimization flag
    optimization_runs INTEGER,  -- Optimization runs
    verified BOOLEAN NOT NULL DEFAULT 0,  -- Source code verified
    verified_at INTEGER,  -- Verification timestamp
    FOREIGN KEY (contract_address) REFERENCES account_state(address) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_metadata_verified ON contract_metadata(verified);


-- ============================================================================
-- STATE TRIE NODES (for Merkle Patricia Trie)
-- ============================================================================

CREATE TABLE IF NOT EXISTS state_trie (
    node_hash TEXT PRIMARY KEY,  -- Keccak256 hash of node
    node_data BLOB NOT NULL,  -- RLP-encoded node data
    ref_count INTEGER NOT NULL DEFAULT 1,  -- Reference count for pruning
    created_at INTEGER NOT NULL  -- Block number when created
);

CREATE INDEX IF NOT EXISTS idx_state_trie_created ON state_trie(created_at);


-- ============================================================================
-- STORAGE TRIE NODES
-- ============================================================================

CREATE TABLE IF NOT EXISTS storage_trie (
    contract_address TEXT NOT NULL,  -- Contract this trie belongs to
    node_hash TEXT NOT NULL,  -- Keccak256 hash of node
    node_data BLOB NOT NULL,  -- RLP-encoded node data
    ref_count INTEGER NOT NULL DEFAULT 1,  -- Reference count
    created_at INTEGER NOT NULL,  -- Block number when created
    PRIMARY KEY (contract_address, node_hash),
    FOREIGN KEY (contract_address) REFERENCES account_state(address) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_storage_trie_address ON storage_trie(contract_address);
CREATE INDEX IF NOT EXISTS idx_storage_trie_created ON storage_trie(created_at);


-- ============================================================================
-- GAS USAGE TRACKING
-- ============================================================================

CREATE TABLE IF NOT EXISTS gas_usage (
    block_number INTEGER PRIMARY KEY,  -- Block number
    gas_used INTEGER NOT NULL,  -- Total gas used in block
    gas_limit INTEGER NOT NULL,  -- Block gas limit
    base_fee TEXT,  -- EIP-1559 base fee
    avg_gas_price TEXT,  -- Average gas price in block
    tx_count INTEGER NOT NULL,  -- Number of transactions
    contract_tx_count INTEGER NOT NULL,  -- Number of contract transactions
    FOREIGN KEY (block_number) REFERENCES blocks(id) ON DELETE CASCADE
);


-- ============================================================================
-- VM EXECUTION TRACES (for debugging)
-- ============================================================================

CREATE TABLE IF NOT EXISTS vm_traces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash TEXT NOT NULL,  -- Transaction hash
    step_index INTEGER NOT NULL,  -- Execution step number
    opcode TEXT NOT NULL,  -- Opcode executed
    gas_cost INTEGER NOT NULL,  -- Gas cost of operation
    gas_remaining INTEGER NOT NULL,  -- Gas remaining after operation
    stack_depth INTEGER NOT NULL,  -- Stack depth
    memory_size INTEGER NOT NULL,  -- Memory size in bytes
    storage_changes TEXT,  -- JSON of storage changes
    created_at INTEGER NOT NULL,  -- Timestamp
    FOREIGN KEY (tx_hash) REFERENCES contract_transactions(tx_hash) ON DELETE CASCADE,
    UNIQUE(tx_hash, step_index)
);

CREATE INDEX IF NOT EXISTS idx_vm_traces_tx ON vm_traces(tx_hash);


-- ============================================================================
-- CONTRACT CALLS (internal transactions)
-- ============================================================================

CREATE TABLE IF NOT EXISTS contract_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash TEXT NOT NULL,  -- Parent transaction
    call_type TEXT NOT NULL,  -- 'call', 'delegatecall', 'staticcall', 'create', 'create2'
    from_address TEXT NOT NULL,  -- Caller address
    to_address TEXT,  -- Callee address (NULL for CREATE)
    value TEXT NOT NULL DEFAULT '0',  -- Value sent
    gas_limit INTEGER NOT NULL,  -- Gas limit for call
    gas_used INTEGER NOT NULL,  -- Actual gas used
    input_data BLOB,  -- Call data
    output_data BLOB,  -- Return data
    error TEXT,  -- Error message if failed
    call_depth INTEGER NOT NULL,  -- Call stack depth
    created_contract TEXT,  -- Address of created contract (if CREATE)
    FOREIGN KEY (tx_hash) REFERENCES contract_transactions(tx_hash) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_calls_tx ON contract_calls(tx_hash);
CREATE INDEX IF NOT EXISTS idx_contract_calls_from ON contract_calls(from_address);
CREATE INDEX IF NOT EXISTS idx_contract_calls_to ON contract_calls(to_address);
