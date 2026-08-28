"""
SQLite Database Adapter for QRDX Testnet

This is a simplified SQLite adapter for local testnet development.
For production, use the full PostgreSQL database.py implementation.
"""
import aiosqlite
import os
from datetime import datetime, timezone
from typing import Optional
from .logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Column-alias SELECT for the blocks table.
#
# The original PostgreSQL schema used short column names (id, hash, address).
# The SQLite schema uses qualified names (block_height, block_hash, ...).
# By selecting both forms we keep compatibility with every call-site in
# manager.py and node/main.py without touching those files.
# ---------------------------------------------------------------------------
_BLOCK_COLS = (
    "block_hash, block_hash  AS hash, "
    "block_height, block_height AS id, "
    "prev_block_hash, merkle_root, timestamp, difficulty, nonce, "
    "validator_address, validator_address AS address, "
    "validator_signature, content, created_at"
)


class DatabaseSQLite:
    """Simplified SQLite database for testnet"""

    instance = None
    credentials = {}

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection: Optional[aiosqlite.Connection] = None
        self.is_indexed = False
        
    @staticmethod
    async def create(db_path: str, **kwargs):
        """Create and initialize SQLite database"""
        self = DatabaseSQLite(db_path)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Open connection
        self.connection = await aiosqlite.connect(db_path)
        self.connection.row_factory = aiosqlite.Row
        
        # Enable WAL mode for better concurrency
        await self.connection.execute("PRAGMA journal_mode=WAL")
        await self.connection.execute("PRAGMA synchronous=NORMAL")
        
        # Initialize schema
        await self._init_schema()
        
        # Set singleton instance (matching Database pattern for manager.py etc.)
        DatabaseSQLite.instance = self
        
        logger.info(f"SQLite database initialized: {db_path}")
        return self

    @staticmethod
    async def get():
        """Get the singleton instance, matching Database.get() interface."""
        if DatabaseSQLite.instance is None:
            raise RuntimeError("DatabaseSQLite not initialized — call create() first")
        return DatabaseSQLite.instance
        
    async def _init_schema(self):
        """Initialize database schema"""
        schema = """
        CREATE TABLE IF NOT EXISTS blocks (
            block_hash TEXT PRIMARY KEY,
            block_height INTEGER UNIQUE NOT NULL,
            prev_block_hash TEXT,
            merkle_root TEXT,
            timestamp INTEGER,
            difficulty INTEGER,
            nonce INTEGER,
            validator_address TEXT,
            validator_signature TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS transactions (
            tx_hash TEXT PRIMARY KEY,
            tx_hex TEXT NOT NULL,
            block_hash TEXT,
            inputs_addresses TEXT,
            outputs_addresses TEXT,
            outputs_amounts TEXT,
            fees INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (block_hash) REFERENCES blocks(block_hash)
        );
        
        CREATE TABLE IF NOT EXISTS pending_transactions (
            tx_hash TEXT PRIMARY KEY,
            tx_hex TEXT NOT NULL,
            inputs_addresses TEXT,
            fees INTEGER,
            time_received TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            propagation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS unspent_outputs (
            tx_hash TEXT NOT NULL,
            output_index INTEGER NOT NULL,
            address TEXT,
            amount INTEGER NOT NULL,
            PRIMARY KEY (tx_hash, output_index),
            FOREIGN KEY (tx_hash) REFERENCES transactions(tx_hash)
        );
        
        CREATE TABLE IF NOT EXISTS pending_spent_outputs (
            tx_hash TEXT NOT NULL,
            output_index INTEGER NOT NULL,
            FOREIGN KEY (tx_hash) REFERENCES transactions(tx_hash) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS peers (
            node_url TEXT PRIMARY KEY,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reputation INTEGER DEFAULT 0
        );
        
        CREATE TABLE IF NOT EXISTS validator_states (
            epoch INTEGER PRIMARY KEY,
            validator_address TEXT NOT NULL,
            stake INTEGER NOT NULL,
            active BOOLEAN DEFAULT 1,
            last_attestation INTEGER
        );
        
        CREATE TABLE IF NOT EXISTS validator_stakes (
            validator_address TEXT PRIMARY KEY,
            stake INTEGER NOT NULL,
            effective_stake INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            activation_epoch INTEGER,
            exit_epoch INTEGER,
            slashed BOOLEAN DEFAULT 0,
            uptime_score REAL DEFAULT 1.0,
            validator_index INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS stake_deposits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            validator_address TEXT NOT NULL,
            amount INTEGER NOT NULL,
            tx_hash TEXT,
            block_number INTEGER,
            epoch INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (validator_address) REFERENCES validator_stakes(validator_address)
        );
        
        CREATE TABLE IF NOT EXISTS stake_withdrawals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            validator_address TEXT NOT NULL,
            amount INTEGER NOT NULL,
            request_epoch INTEGER NOT NULL,
            completion_epoch INTEGER,
            status TEXT NOT NULL DEFAULT 'PENDING',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (validator_address) REFERENCES validator_stakes(validator_address)
        );
        
        -- Contract tracking tables
        CREATE TABLE IF NOT EXISTS account_state (
            address TEXT PRIMARY KEY,
            balance TEXT NOT NULL DEFAULT '0',
            nonce INTEGER NOT NULL DEFAULT 0,
            code_hash TEXT,
            storage_root TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            is_contract BOOLEAN NOT NULL DEFAULT 0
        );
        
        CREATE TABLE IF NOT EXISTS contract_metadata (
            contract_address TEXT PRIMARY KEY,
            name TEXT,
            symbol TEXT,
            compiler_version TEXT,
            source_code TEXT,
            abi TEXT,
            verified BOOLEAN NOT NULL DEFAULT 0,
            verified_at INTEGER,
            FOREIGN KEY (contract_address) REFERENCES account_state(address)
        );
        
        CREATE TABLE IF NOT EXISTS contract_code (
            code_hash TEXT PRIMARY KEY,
            bytecode BLOB NOT NULL,
            deployed_at INTEGER NOT NULL,
            deployer TEXT NOT NULL,
            size INTEGER NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS contract_storage (
            contract_address TEXT NOT NULL,
            storage_key TEXT NOT NULL,
            storage_value TEXT NOT NULL,
            block_number INTEGER NOT NULL,
            PRIMARY KEY (contract_address, storage_key)
        );
        
        CREATE TABLE IF NOT EXISTS contract_transactions (
            tx_hash TEXT PRIMARY KEY,
            block_number INTEGER NOT NULL,
            tx_index INTEGER NOT NULL,
            from_address TEXT NOT NULL,
            to_address TEXT,
            value TEXT NOT NULL DEFAULT '0',
            gas_limit INTEGER NOT NULL,
            gas_used INTEGER NOT NULL,
            gas_price TEXT NOT NULL,
            nonce INTEGER NOT NULL,
            input_data BLOB,
            contract_address TEXT,
            status INTEGER NOT NULL DEFAULT 1,
            error_message TEXT,
            created_at INTEGER NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS contract_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_hash TEXT NOT NULL,
            block_number INTEGER NOT NULL,
            log_index INTEGER NOT NULL,
            contract_address TEXT NOT NULL,
            topic0 TEXT,
            topic1 TEXT,
            topic2 TEXT,
            topic3 TEXT,
            data BLOB,
            removed BOOLEAN NOT NULL DEFAULT 0,
            UNIQUE(tx_hash, log_index),
            FOREIGN KEY (tx_hash) REFERENCES contract_transactions(tx_hash)
        );
        
        CREATE TABLE IF NOT EXISTS attestations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slot INTEGER NOT NULL,
            epoch INTEGER NOT NULL,
            block_hash TEXT NOT NULL,
            validator_address TEXT NOT NULL,
            validator_index INTEGER NOT NULL,
            signature TEXT NOT NULL,
            source_epoch INTEGER NOT NULL,
            target_epoch INTEGER NOT NULL,
            included_in_block TEXT,
            inclusion_slot INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(slot, validator_address)
        );
        
        CREATE TABLE IF NOT EXISTS epochs (
            epoch INTEGER PRIMARY KEY,
            start_slot INTEGER NOT NULL,
            end_slot INTEGER NOT NULL,
            active_validators INTEGER NOT NULL DEFAULT 0,
            total_stake TEXT NOT NULL DEFAULT '0',
            finalized BOOLEAN NOT NULL DEFAULT 0,
            justified BOOLEAN NOT NULL DEFAULT 0,
            finality_root TEXT,
            randao_mix TEXT,
            total_rewards TEXT NOT NULL DEFAULT '0',
            total_penalties TEXT NOT NULL DEFAULT '0',
            started_at TIMESTAMP,
            finalized_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS validators (
            address TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            stake TEXT NOT NULL,
            effective_stake TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            activation_epoch INTEGER,
            exit_epoch INTEGER,
            slashed BOOLEAN NOT NULL DEFAULT 0,
            total_slashed TEXT NOT NULL DEFAULT '0',
            total_rewards TEXT NOT NULL DEFAULT '0',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS stakes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            validator_address TEXT NOT NULL,
            amount TEXT NOT NULL,
            deposit_epoch INTEGER NOT NULL,
            withdrawal_requested_epoch INTEGER,
            withdrawal_completed_epoch INTEGER,
            withdrawable_at TIMESTAMP,
            deposit_tx_hash TEXT,
            withdrawal_tx_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (validator_address) REFERENCES validators(address)
        );
        
        CREATE TABLE IF NOT EXISTS system_wallets (
            address TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            wallet_type TEXT NOT NULL,
            controller_address TEXT NOT NULL,
            is_burner BOOLEAN NOT NULL DEFAULT 0,
            category TEXT NOT NULL,
            balance TEXT NOT NULL DEFAULT '0',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS block_exchange_transactions (
            block_hash TEXT NOT NULL,
            tx_index INTEGER NOT NULL,
            tx_hash TEXT NOT NULL,
            tx_data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (block_hash, tx_index)
        );

        CREATE TABLE IF NOT EXISTS block_evm_transactions (
            block_hash TEXT NOT NULL,
            tx_index INTEGER NOT NULL,
            raw_tx TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (block_hash, tx_index)
        );

        -- Finality: accumulated attestation VOTES (one per validator per target
        -- epoch — Casper-style). Populated by every node from the attestations
        -- carried in imported block bodies, so finality is computable by full
        -- nodes too (not just validators with an in-memory pool).
        CREATE TABLE IF NOT EXISTS attestation_votes (
            validator_address TEXT NOT NULL,
            target_epoch INTEGER NOT NULL,
            source_epoch INTEGER NOT NULL DEFAULT 0,
            slot INTEGER NOT NULL,
            block_hash TEXT NOT NULL,
            -- Retained so a stored vote can be reconstructed into a fully-signed
            -- Attestation for SELF-VALIDATING surround/double-vote slashing evidence
            -- (finality only needs target/source; slashing detection needs the rest).
            epoch INTEGER NOT NULL DEFAULT 0,
            validator_index INTEGER NOT NULL DEFAULT 0,
            signature TEXT NOT NULL DEFAULT '',
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (validator_address, target_epoch)
        );

        -- Slashing evidence (consensus security). A row is recorded when a node
        -- detects a slashable offence on the import path — primarily DOUBLE_SIGN: the
        -- slot-eligible proposer signed TWO different blocks for the SAME slot (seen as
        -- an equal-height fork with identical proposer+slot but different hash). Keyed
        -- by (validator, slot, condition) so the same offence is recorded once.
        -- OBSERVE foundation: detection + durable evidence only; the deterministic
        -- stake penalty (via the finalized-epoch validator-update path, total_slashed)
        -- is a follow-up that consumes these rows.
        CREATE TABLE IF NOT EXISTS slashing_events (
            validator_address TEXT NOT NULL,
            condition TEXT NOT NULL,
            slot INTEGER NOT NULL,
            epoch INTEGER NOT NULL,
            evidence TEXT NOT NULL,
            processed INTEGER NOT NULL DEFAULT 0,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (validator_address, slot, condition)
        );

        -- QRC-20 token ledger (Phase E spot). Mirrors qrdx.tokens.persistence
        -- TOKEN_SCHEMA so the node owns these tables natively (token state is a
        -- consensus object: balances are bound into the unified state root and
        -- moved only by replayed exchange-section ops). IF NOT EXISTS keeps it
        -- compatible with a DB the token persistence layer also initialized.
        CREATE TABLE IF NOT EXISTS token_registry (
            token_address TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            symbol TEXT NOT NULL,
            decimals INTEGER NOT NULL DEFAULT 18,
            total_supply TEXT NOT NULL,
            owner_address TEXT NOT NULL,
            is_frozen INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS token_balances (
            token_address TEXT NOT NULL,
            holder_address TEXT NOT NULL,
            balance TEXT NOT NULL DEFAULT '0',
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (token_address, holder_address)
        );

        CREATE INDEX IF NOT EXISTS idx_token_balances_holder ON token_balances(holder_address);
        CREATE INDEX IF NOT EXISTS idx_token_balances_token ON token_balances(token_address);

        CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(block_height);
        CREATE INDEX IF NOT EXISTS idx_block_exchange_txs ON block_exchange_transactions(block_hash);
        CREATE INDEX IF NOT EXISTS idx_block_evm_txs ON block_evm_transactions(block_hash);
        CREATE INDEX IF NOT EXISTS idx_attestation_votes_target ON attestation_votes(target_epoch);
        CREATE INDEX IF NOT EXISTS idx_transactions_block ON transactions(block_hash);
        CREATE INDEX IF NOT EXISTS idx_unspent_address ON unspent_outputs(address);
        CREATE INDEX IF NOT EXISTS idx_validator_epoch ON validator_states(epoch);
        CREATE INDEX IF NOT EXISTS idx_stakes_status ON validator_stakes(status);
        CREATE INDEX IF NOT EXISTS idx_stakes_activation ON validator_stakes(activation_epoch);
        CREATE INDEX IF NOT EXISTS idx_deposits_validator ON stake_deposits(validator_address);
        CREATE INDEX IF NOT EXISTS idx_withdrawals_validator ON stake_withdrawals(validator_address);
        CREATE INDEX IF NOT EXISTS idx_account_state_address ON account_state(address);
        CREATE INDEX IF NOT EXISTS idx_account_state_is_contract ON account_state(is_contract);
        CREATE INDEX IF NOT EXISTS idx_contract_metadata_verified ON contract_metadata(verified);
        CREATE INDEX IF NOT EXISTS idx_contract_tx_block ON contract_transactions(block_number);
        CREATE INDEX IF NOT EXISTS idx_contract_tx_from ON contract_transactions(from_address);
        CREATE INDEX IF NOT EXISTS idx_contract_tx_to ON contract_transactions(to_address);
        CREATE INDEX IF NOT EXISTS idx_contract_logs_tx ON contract_logs(tx_hash);
        CREATE INDEX IF NOT EXISTS idx_contract_logs_block ON contract_logs(block_number);
        CREATE INDEX IF NOT EXISTS idx_contract_logs_address ON contract_logs(contract_address);
        CREATE INDEX IF NOT EXISTS idx_system_wallets_controller ON system_wallets(controller_address);
        CREATE INDEX IF NOT EXISTS idx_system_wallets_category ON system_wallets(category);
        CREATE INDEX IF NOT EXISTS idx_contract_logs_topic0 ON contract_logs(topic0);
        CREATE INDEX IF NOT EXISTS idx_contract_logs_topic1 ON contract_logs(topic1);
        CREATE INDEX IF NOT EXISTS idx_contract_logs_topic2 ON contract_logs(topic2);
        CREATE INDEX IF NOT EXISTS idx_attestations_slot ON attestations(slot);
        CREATE INDEX IF NOT EXISTS idx_attestations_epoch ON attestations(epoch);
        CREATE INDEX IF NOT EXISTS idx_attestations_validator ON attestations(validator_address);
        CREATE INDEX IF NOT EXISTS idx_attestations_block ON attestations(block_hash);
        CREATE INDEX IF NOT EXISTS idx_validators_status ON validators(status);
        CREATE INDEX IF NOT EXISTS idx_stakes_validator ON stakes(validator_address);
        """
        
        await self.connection.executescript(schema)
        await self.connection.commit()

        # Idempotent additive migrations for columns added after a DB was first
        # created (CREATE TABLE IF NOT EXISTS won't add them to an existing table).
        # Each ADD COLUMN is wrapped so a re-run (column already present) is a no-op.
        _migrations = [
            "ALTER TABLE validators ADD COLUMN total_slashed TEXT NOT NULL DEFAULT '0'",
            "ALTER TABLE validators ADD COLUMN total_rewards TEXT NOT NULL DEFAULT '0'",
            # Signed-attestation retention for surround/double-vote slashing detection.
            "ALTER TABLE attestation_votes ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE attestation_votes ADD COLUMN validator_index INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE attestation_votes ADD COLUMN signature TEXT NOT NULL DEFAULT ''",
        ]
        for stmt in _migrations:
            try:
                await self.connection.execute(stmt)
            except Exception:
                pass  # duplicate column — already migrated
        await self.connection.commit()

    async def remove_all_pending_transactions(self):
        """Clear pending transaction pool"""
        await self.connection.execute("DELETE FROM pending_transactions")
        await self.connection.execute("DELETE FROM pending_spent_outputs")
        await self.connection.commit()
        logger.info("Pending transactions cleared")
        
    async def close(self):
        """Close database connection"""
        if self.connection:
            await self.connection.close()
            logger.info(f"SQLite database closed: {self.db_path}")
    
    # Compatibility methods for existing code
    
    async def add_pending_transaction(self, transaction, verify: bool = True):
        """Add pending transaction to the mempool table."""
        try:
            import json
            tx_hex = transaction.hex() if isinstance(transaction, bytes) else str(transaction)
            await self.connection.execute(
                "INSERT OR IGNORE INTO pending_transactions (tx_hash, tx_data, added_at) "
                "VALUES (?, ?, datetime('now'))",
                (getattr(transaction, 'hash', tx_hex[:64]), tx_hex),
            )
            await self.connection.commit()
            return True
        except Exception as e:
            logger.warning("add_pending_transaction: %s", e)
            return True
        
    async def get_latest_block(self):
        """Get the latest block from the database."""
        cursor = await self.connection.execute(
            f"SELECT {_BLOCK_COLS} FROM blocks ORDER BY block_height DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
        
    async def get_block_height(self):
        """Get current block height"""
        cursor = await self.connection.execute(
            "SELECT MAX(block_height) as height FROM blocks"
        )
        row = await cursor.fetchone()
        return row['height'] if row and row['height'] is not None else -1
    
    async def get_next_block_id(self):
        """Get next block ID"""
        height = await self.get_block_height()
        return height + 1
        
    async def add_block(self, block_id_or_kw=None, block_hash=None,
                        block_content=None, address=None, random_value=None,
                        difficulty=None, reward=None, timestamp=None, **kwargs):
        """Add block to database.
        
        Accepts both positional args (matching the PostgreSQL API used by
        manager.py's create_block) and keyword args (used by genesis_init
        and node_integration).
        """
        # Merge positional & keyword sources so every caller works.
        _id = (block_id_or_kw if block_id_or_kw is not None
               else kwargs.get('block_id', kwargs.get('block_height', 0)))
        _hash = (block_hash or kwargs.get('block_hash', ''))
        _content = (block_content if block_content is not None
                    else kwargs.get('content', ''))
        _addr = (address or kwargs.get('validator_address', ''))
        _ts = (timestamp if timestamp is not None
               else kwargs.get('timestamp', datetime.now(timezone.utc)))
        
        # Insert block
        await self.connection.execute("""
            INSERT INTO blocks (block_hash, block_height, validator_address, content, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (_hash, _id, _addr, _content, _ts))
        await self.connection.commit()
        logger.info(f"Block {_id} added: {_hash[:16]}...")
        return True
    
    async def add_transaction(self, transaction_or_kw=None, block_hash_arg=None, **kwargs):
        """Add transaction to database.
        
        Supports both:
          - Positional: add_transaction(Transaction, block_hash_str)
          - Keyword: add_transaction(tx_hash=..., tx_hex=..., block_hash=...)
        """
        if transaction_or_kw is not None and not isinstance(transaction_or_kw, dict):
            # Positional call from manager.py: (Transaction, block_hash)
            tx = transaction_or_kw
            tx_hash = tx.hash()
            tx_hex = tx.hex()
            block_hash = block_hash_arg or ''
        else:
            # Keyword call
            kw = transaction_or_kw if isinstance(transaction_or_kw, dict) else kwargs
            tx_hash = kw.get('tx_hash', kwargs.get('tx_hash', ''))
            tx_hex = kw.get('tx_hex', kwargs.get('tx_hex', ''))
            block_hash = kw.get('block_hash', kwargs.get('block_hash', block_hash_arg or ''))
        
        await self.connection.execute("""
            INSERT OR IGNORE INTO transactions (tx_hash, tx_hex, block_hash)
            VALUES (?, ?, ?)
        """, (tx_hash, tx_hex, block_hash))
        await self.connection.commit()
        return True

    async def add_transactions(self, transactions, block_hash: str):
        """Add multiple transactions to database (matches PostgreSQL API)."""
        for tx in transactions:
            await self.add_transaction(tx, block_hash)

    async def add_unspent_transactions_outputs(self, transactions):
        """Create UTXO entries for all outputs of the given transactions."""
        for tx in transactions:
            for idx, output in enumerate(tx.outputs):
                await self.connection.execute("""
                    INSERT OR IGNORE INTO unspent_outputs (tx_hash, output_index, address, amount)
                    VALUES (?, ?, ?, ?)
                """, (tx.hash(), idx, output.address, output.amount))
        await self.connection.commit()

    async def remove_pending_transactions_by_hash(self, hashes: list):
        """Remove specific pending transactions by hash."""
        if not hashes:
            return
        placeholders = ','.join('?' for _ in hashes)
        await self.connection.execute(
            f"DELETE FROM pending_transactions WHERE tx_hash IN ({placeholders})",
            hashes
        )
        await self.connection.commit()

    async def remove_unspent_outputs(self, transactions):
        """Remove spent inputs from the UTXO set."""
        for tx in transactions:
            for tx_input in tx.inputs:
                await self.connection.execute(
                    "DELETE FROM unspent_outputs WHERE tx_hash = ? AND output_index = ?",
                    (tx_input.tx_hash, tx_input.index)
                )
        await self.connection.commit()

    async def remove_pending_spent_outputs(self, transactions):
        """Remove pending spent outputs after block confirmation."""
        for tx in transactions:
            for tx_input in tx.inputs:
                await self.connection.execute(
                    "DELETE FROM pending_spent_outputs WHERE tx_hash = ? AND index_spent = ?",
                    (tx_input.tx_hash, tx_input.index)
                )
        await self.connection.commit()

    async def delete_block(self, block_id: int):
        """Delete a block and its transactions (for rollback)."""
        # Get the block hash first
        block = await self.get_block_by_id(block_id)
        if block:
            block_hash = block.get('hash') or block.get('block_hash')
            if block_hash:
                await self.connection.execute(
                    "DELETE FROM transactions WHERE block_hash = ?", (block_hash,)
                )
            await self.connection.execute(
                "DELETE FROM blocks WHERE block_height = ?", (block_id,)
            )
            await self.connection.commit()

    async def get_unspent_outputs(self, inputs):
        """Get unspent outputs matching the given (tx_hash, index) pairs."""
        result = set()
        for tx_hash, idx in inputs:
            cursor = await self.connection.execute(
                "SELECT tx_hash, output_index FROM unspent_outputs WHERE tx_hash = ? AND output_index = ?",
                (tx_hash, idx)
            )
            row = await cursor.fetchone()
            if row:
                result.add((row[0], row[1]))
        return result

    async def clear_duplicate_pending_transactions(self):
        """Remove duplicate pending transactions (no-op for SQLite with UNIQUE)."""
        pass

    async def remove_pending_transactions(self):
        """Remove all pending transactions."""
        await self.connection.execute("DELETE FROM pending_transactions")
        await self.connection.commit()

    async def remove_pending_transactions_by_contains(self, patterns: list):
        """Remove pending transactions matching patterns."""
        for pattern in patterns:
            await self.connection.execute(
                "DELETE FROM pending_transactions WHERE tx_hex LIKE ?",
                (f'%{pattern}%',)
            )
        await self.connection.commit()
    
    async def add_unspent_output(self, **kwargs):
        """Add unspent output to database"""
        tx_hash = kwargs.get('tx_hash', '')
        output_index = kwargs.get('index', kwargs.get('output_index', 0))
        address = kwargs.get('address', '')
        amount = kwargs.get('amount', 0)
        
        await self.connection.execute("""
            INSERT INTO unspent_outputs (tx_hash, output_index, address, amount)
            VALUES (?, ?, ?, ?)
        """, (tx_hash, output_index, address, amount))
        await self.connection.commit()
        return True
    
    async def execute(self, query: str, *args):
        """Execute raw SQL query"""
        await self.connection.execute(query, args)
        await self.connection.commit()
    
    # Additional methods required by node endpoints
    
    async def get_need_propagate_transactions(self):
        """Get transactions that need propagation (not propagated in the last 30s)."""
        cursor = await self.connection.execute("""
            SELECT tx_hash, tx_hex FROM pending_transactions
            WHERE propagation_time IS NULL
               OR propagation_time < datetime('now', '-30 seconds')
            ORDER BY time_received ASC
            LIMIT 200
        """)
        rows = await cursor.fetchall()
        return [{'tx_hash': row[0], 'tx_hex': row[1]} for row in rows]
    
    async def update_pending_transactions_propagation_time(self, tx_hashes: list):
        """Update propagation time for transactions so they are not re-propagated."""
        if not tx_hashes:
            return
        placeholders = ','.join('?' for _ in tx_hashes)
        await self.connection.execute(
            f"UPDATE pending_transactions SET propagation_time = datetime('now') "
            f"WHERE tx_hash IN ({placeholders})",
            tx_hashes,
        )
        await self.connection.commit()
    
    async def get_unspent_outputs_hash(self):
        """Get deterministic hash of unspent outputs for state root computation."""
        import hashlib
        cursor = await self.connection.execute("""
            SELECT tx_hash, output_index, address, amount
            FROM unspent_outputs
            ORDER BY tx_hash ASC, output_index ASC
        """)
        rows = await cursor.fetchall()
        if not rows:
            return "0" * 64
        hasher = hashlib.sha256()
        for row in rows:
            hasher.update(f"{row[0]}:{row[1]}:{row[2]}:{row[3]}".encode())
        return hasher.hexdigest()
    
    async def get_account_state_root(self) -> str:
        """
        Deterministic BLAKE3-512 root of the account/EVM state (Whitepaper §3.6).

        Hashes every account_state row in a canonical order (by address) over its
        consensus-relevant fields. Empty state → all-zero root. This is the
        account-domain component of the unified block state root (Phase D4).
        """
        cursor = await self.connection.execute("""
            SELECT address, balance, nonce, code_hash, storage_root
            FROM account_state
            ORDER BY address ASC
        """)
        rows = await cursor.fetchall()
        if not rows:
            return "0" * 128  # BLAKE3-512 width
        import blake3
        hasher = blake3.blake3()
        for r in rows:
            addr, balance, nonce, code_hash, storage_root = r[0], r[1], r[2], r[3], r[4]
            hasher.update(
                f"{addr}:{balance}:{nonce}:{code_hash or ''}:{storage_root or ''}".encode()
            )
        return hasher.digest(length=64).hex()

    async def clear_account_state(self) -> None:
        """
        Clear all EVM/account state rows (E-D3b reorg rebuild).

        Used by ``rebuild_account_state_from_chain`` before replaying the
        canonical EVM sections, so orphaned-block account changes do not survive
        a reorg. ``account_state`` is otherwise durable across restarts.

        Also resets the EVM balance-sync registry: ``sync_address_to_evm`` dedups
        account_state→EVM syncs by (address, block_height), so if the registry
        survived the rebuild the replay would SKIP re-syncing (it looks already
        synced for that height) and the freshly-cleared EVM balance would stay 0 —
        the subsequent tx then OVERWRITES the reseeded genesis funding (a 0x-genesis
        address loses its allocation; account_state root diverges from a node that
        never rebuilt). Clearing it makes the replay re-sync exactly as the original
        run did. Best-effort: the sync tables only exist once EVM has initialized.
        """
        await self.connection.execute("DELETE FROM account_state")
        await self.connection.execute("DELETE FROM contract_storage")
        for tbl in ("evm_balance_sync_registry", "evm_balance_changes"):
            try:
                await self.connection.execute(f"DELETE FROM {tbl}")
            except Exception:
                pass  # table not created yet (EVM never initialized) — nothing to reset
        await self.connection.commit()

    async def apply_account_balance_delta(self, address: str, qrdx_delta) -> bool:
        """
        Phase E: apply a QRDX balance delta (negative = debit) to ``account_state``
        in wei. Case-insensitive on address (matches ``get_address_balance``). A
        debit clamps at 0 as a safety net (collateral enforcement should already
        reject an over-debit). Returns True if a row was updated/created.

        Does NOT commit — the caller commits atomically with the rest of the block.
        """
        from decimal import Decimal
        wei_delta = int(Decimal(str(qrdx_delta)) * Decimal(10 ** 18))
        if wei_delta == 0:
            return False
        cur = await self.connection.execute(
            "SELECT address, balance FROM account_state WHERE LOWER(address) = LOWER(?)",
            (address,),
        )
        row = await cur.fetchone()
        if row:
            new_bal = int(row[1] or 0) + wei_delta
            if new_bal < 0:
                new_bal = 0
            await self.connection.execute(
                "UPDATE account_state SET balance = ? WHERE LOWER(address) = LOWER(?)",
                (str(new_bal), address),
            )
            return True
        if wei_delta > 0:
            await self.connection.execute(
                "INSERT INTO account_state (address, balance, nonce, created_at, updated_at, is_contract) "
                "VALUES (?, ?, 0, 0, 0, 0)",
                (address, str(wei_delta)),
            )
            return True
        return False  # debit on a non-existent account — nothing to debit

    async def seed_genesis_account_state(self) -> int:
        """
        Phase E (unified ledger): (re-)apply the genesis allocations to
        ``account_state`` from block 0's ``genesis_allocation`` transactions. This
        is the durable base of the single balance ledger; the EVM reorg rebuild
        (`rebuild_account_state_from_chain`) clears account_state and replays only
        EVM sections, so it must call this first to restore the genesis funding
        that no EVM section produces. Idempotent (sets absolute balances). Returns
        the number of accounts seeded. Does not commit.
        """
        import json as _json
        from decimal import Decimal as _D
        cur = await self.connection.execute(
            "SELECT block_hash FROM blocks WHERE block_height = 0")
        row = await cur.fetchone()
        if not row:
            return 0
        genesis_hash = row[0]
        cur = await self.connection.execute(
            "SELECT tx_hex FROM transactions WHERE block_hash = ?", (genesis_hash,))
        seeded = 0
        for (tx_hex,) in await cur.fetchall():
            try:
                d = _json.loads(tx_hex)
            except Exception:
                continue
            if d.get("type") != "genesis_allocation" or not d.get("recipient"):
                continue
            wei = int(_D(str(d["amount"])) * _D(10 ** 18))
            await self.connection.execute(
                "INSERT INTO account_state (address, balance, nonce, created_at, updated_at, is_contract) "
                "VALUES (?, ?, 0, 0, 0, 0) "
                "ON CONFLICT(address) DO UPDATE SET balance = excluded.balance",
                (d["recipient"], str(wei)),
            )
            seeded += 1
        return seeded

    async def apply_token_balance_delta(self, token_address: str, holder_address: str, delta) -> bool:
        """
        Phase E (spot): apply a token-balance delta (negative = debit) to the
        ``token_balances`` ledger. Balances are stored as Decimal-string token
        units (matching qrdx.tokens.persistence). A debit clamps at 0 as a safety
        net (spot enforcement should already reject an over-debit). The token
        analog of ``apply_account_balance_delta``. Returns True if a row was
        updated/created. Does NOT commit — the caller commits with the block.
        """
        from decimal import Decimal
        d = Decimal(str(delta))
        if d == 0:
            return False
        now = 0  # deterministic (block-replayed); wall-clock would diverge per node
        cur = await self.connection.execute(
            "SELECT balance FROM token_balances WHERE token_address = ? AND holder_address = ?",
            (token_address, holder_address),
        )
        row = await cur.fetchone()
        cur_bal = Decimal(row[0]) if row and row[0] is not None else Decimal("0")
        new_bal = cur_bal + d
        if new_bal < 0:
            new_bal = Decimal("0")
        await self.connection.execute(
            """INSERT INTO token_balances (token_address, holder_address, balance, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(token_address, holder_address) DO UPDATE SET balance = ?, updated_at = ?""",
            (token_address, holder_address, str(new_bal), now, str(new_bal), now),
        )
        return True

    async def apply_token_registry_op(self, op: dict) -> bool:
        """
        Phase E (spot): create a QRC-20 registry row from a TOKEN_DEPLOY op
        (deterministic metadata; the value-bearing state is token_balances). Idem-
        potent on token_address. Does NOT commit — the caller commits with the
        block.
        """
        await self.connection.execute(
            """INSERT INTO token_registry
                 (token_address, name, symbol, decimals, total_supply, owner_address, is_frozen, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0)
               ON CONFLICT(token_address) DO NOTHING""",
            (op["token_address"], op["name"], op["symbol"], int(op.get("decimals", 18)),
             str(op["total_supply"]), op["owner_address"]),
        )
        return True

    async def get_token_balance(self, token_address: str, holder_address: str):
        """Token-units balance for (token, holder); Decimal(0) if no row."""
        from decimal import Decimal
        cur = await self.connection.execute(
            "SELECT balance FROM token_balances WHERE token_address = ? AND holder_address = ?",
            (token_address, holder_address),
        )
        row = await cur.fetchone()
        return Decimal(row[0]) if row and row[0] is not None else Decimal("0")

    async def get_token_balances_root(self) -> str:
        """
        Deterministic BLAKE3-512 root of the QRC-20 token ledger (Whitepaper §3.6),
        the token-domain component of the unified block state root (Phase E spot).

        Hashes every non-zero ``token_balances`` row in canonical order
        (token_address, holder_address) over (token, holder, balance). Zero-value
        rows are skipped so a holder that nets to 0 does not change the root.
        Empty ledger → all-zero root. Determinism comes from identical replay of
        the same token deltas on every node (same as ``get_account_state_root``).
        """
        cursor = await self.connection.execute("""
            SELECT token_address, holder_address, balance
            FROM token_balances
            ORDER BY token_address ASC, holder_address ASC
        """)
        rows = await cursor.fetchall()
        from decimal import Decimal
        import blake3
        hasher = blake3.blake3()
        any_row = False
        for r in rows:
            token, holder, balance = r[0], r[1], r[2]
            try:
                if Decimal(balance) == 0:
                    continue
            except Exception:
                continue
            any_row = True
            hasher.update(f"{token}:{holder}:{balance}".encode())
        if not any_row:
            return "0" * 128  # BLAKE3-512 width
        return hasher.digest(length=64).hex()

    async def clear_token_balances(self) -> None:
        """Clear the token ledger (Phase E spot reorg rebuild). Replayed exchange
        sections re-apply the canonical token deltas afterwards. Commits."""
        await self.connection.execute("DELETE FROM token_balances")
        await self.connection.commit()

    async def get_pending_transaction_count(self):
        """Get count of pending transactions"""
        cursor = await self.connection.execute("SELECT COUNT(*) FROM pending_transactions")
        row = await cursor.fetchone()
        return row[0] if row else 0
    
    async def get_all_pending_transaction_hashes(self):
        """Get all pending transaction hashes"""
        cursor = await self.connection.execute("SELECT tx_hash FROM pending_transactions")
        rows = await cursor.fetchall()
        return [row[0] for row in rows]
    
    # Contract tracking methods
    
    async def add_contract_log(self, tx_hash: str, block_number: int, log_index: int, 
                               contract_address: str, topic0: str = None, topic1: str = None,
                               topic2: str = None, topic3: str = None, data: bytes = None):
        """Add contract event log"""
        await self.connection.execute("""
            INSERT INTO contract_logs 
            (tx_hash, block_number, log_index, contract_address, topic0, topic1, topic2, topic3, data, removed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, (tx_hash, block_number, log_index, contract_address, topic0, topic1, topic2, topic3, data))
        await self.connection.commit()
    
    async def add_contract_metadata(self, contract_address: str, name: str = None, 
                                   symbol: str = None, verified: bool = False, abi: str = None):
        """Add or update contract metadata"""
        await self.connection.execute("""
            INSERT OR REPLACE INTO contract_metadata 
            (contract_address, name, symbol, verified, abi)
            VALUES (?, ?, ?, ?, ?)
        """, (contract_address, name, symbol, verified, abi))
        await self.connection.commit()
    
    async def get_address_tokens(self, address: str, transfer_topic: str):
        """Get tokens owned by address from Transfer events"""
        # Normalize address to 64-char hex (32 bytes)
        address_topic = "0x" + address.lower().replace("0x", "").zfill(64)
        
        cursor = await self.connection.execute("""
            SELECT DISTINCT 
                cl.contract_address,
                cm.name,
                cm.symbol,
                COALESCE(cm.verified, 0) as verified,
                COUNT(DISTINCT cl.id) as transfer_count
            FROM contract_logs cl
            LEFT JOIN contract_metadata cm ON cl.contract_address = cm.contract_address
            WHERE cl.topic0 = ?
              AND cl.topic2 = ?
              AND cl.removed = 0
            GROUP BY cl.contract_address, cm.name, cm.symbol, cm.verified
        """, (transfer_topic, address_topic))
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_token_info(self, token_address: str, transfer_topic: str):
        """Get token contract information"""
        # Get metadata
        cursor = await self.connection.execute("""
            SELECT * FROM contract_metadata WHERE contract_address = ?
        """, (token_address,))
        metadata = await cursor.fetchone()
        
        if not metadata:
            return None
        
        # Get transfer count
        cursor = await self.connection.execute("""
            SELECT COUNT(*) as count FROM contract_logs
            WHERE contract_address = ? AND topic0 = ? AND removed = 0
        """, (token_address, transfer_topic))
        transfer_row = await cursor.fetchone()
        transfer_count = transfer_row[0] if transfer_row else 0
        
        # Get unique holders (distinct topic2 recipients)
        cursor = await self.connection.execute("""
            SELECT COUNT(DISTINCT topic2) as count FROM contract_logs
            WHERE contract_address = ? AND topic0 = ? AND removed = 0
        """, (token_address, transfer_topic))
        holder_row = await cursor.fetchone()
        holder_count = holder_row[0] if holder_row else 0
        
        result = dict(metadata)
        result['total_transfers'] = transfer_count
        result['total_holders'] = holder_count
        return result
    
    async def get_top_addresses_by_balance(self, limit: int, offset: int):
        """Get top addresses by balance (sum of unspent outputs)"""
        cursor = await self.connection.execute("""
            SELECT 
                address,
                SUM(amount) as balance,
                COUNT(*) as output_count
            FROM unspent_outputs
            WHERE address IS NOT NULL AND address != ''
            GROUP BY address
            ORDER BY balance DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_top_addresses_by_transactions(self, limit: int, offset: int):
        """Get most active addresses by transaction count"""
        # SQLite doesn't have UNNEST, so we need a different approach
        # This is a simplified version - for full implementation, we'd need to parse the arrays
        cursor = await self.connection.execute("""
            SELECT DISTINCT
                address,
                COUNT(*) as tx_count
            FROM unspent_outputs
            WHERE address IS NOT NULL AND address != ''
            GROUP BY address
            ORDER BY tx_count DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_top_addresses_by_tokens(self, limit: int, offset: int, transfer_topic: str):
        """Get addresses with most token holdings"""
        cursor = await self.connection.execute("""
            SELECT 
                topic2 as address_topic,
                COUNT(DISTINCT contract_address) as token_count,
                COUNT(*) as transfer_count
            FROM contract_logs
            WHERE topic0 = ? AND removed = 0 AND topic2 IS NOT NULL
            GROUP BY topic2
            ORDER BY token_count DESC
            LIMIT ? OFFSET ?
        """, (transfer_topic, limit, offset))
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_recent_transactions_with_blocks(self, limit: int, offset: int):
        """Get recent transactions with block info"""
        cursor = await self.connection.execute("""
            SELECT 
                t.tx_hash,
                t.block_hash,
                b.block_height as block_number,
                b.timestamp,
                t.fees
            FROM transactions t
            JOIN blocks b ON t.block_hash = b.block_hash
            ORDER BY b.block_height DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_recent_contract_transactions(self, limit: int, offset: int):
        """Get recent contract transactions"""
        cursor = await self.connection.execute("""
            SELECT 
                ct.tx_hash,
                ct.block_number,
                ct.from_address,
                ct.to_address,
                ct.value,
                ct.gas_used,
                ct.status,
                b.timestamp
            FROM contract_transactions ct
            LEFT JOIN blocks b ON b.block_height = ct.block_number
            ORDER BY ct.block_number DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_recent_blocks_with_validators(self, limit: int, offset: int):
        """Get recent blocks with validator information"""
        cursor = await self.connection.execute("""
            SELECT 
                b.block_height as id,
                b.block_hash as hash,
                b.validator_address as address,
                b.validator_address as proposer_address,
                b.timestamp,
                (SELECT COUNT(*) FROM transactions WHERE block_hash = b.block_hash) as tx_count,
                NULL as slot,
                NULL as epoch,
                0 as attestations_included,
                0 as reward
            FROM blocks b
            ORDER BY b.block_height DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_validator_info(self, validator_address: str):
        """Get validator information"""
        cursor = await self.connection.execute("""
            SELECT address, stake, effective_stake, status
            FROM validators
            WHERE address = ?
        """, (validator_address,))

        row = await cursor.fetchone()
        return dict(row) if row else None

    async def add_block_exchange_txs(self, block_hash: str, items: list):
        """
        Persist a block's exchange-transaction section (Phase D2.2b).

        ``items`` is the encoded list (each an ``ExchangeTransaction.to_dict()``)
        in the proposer's canonical order. Idempotent per (block_hash, tx_index).
        Stored as protocol-level state (Whitepaper §3.6) for deterministic replay
        during block import (D3).
        """
        if not items:
            return
        import json
        for idx, item in enumerate(items):
            await self.connection.execute(
                "INSERT OR IGNORE INTO block_exchange_transactions "
                "(block_hash, tx_index, tx_hash, tx_data) VALUES (?, ?, ?, ?)",
                (block_hash, idx, item.get("tx_hash", ""), json.dumps(item, sort_keys=True)),
            )
        await self.connection.commit()

    async def get_block_exchange_txs(self, block_hash: str) -> list:
        """Return a block's exchange-transaction section in canonical order."""
        import json
        cursor = await self.connection.execute(
            "SELECT tx_data FROM block_exchange_transactions "
            "WHERE block_hash = ? ORDER BY tx_index ASC",
            (block_hash,),
        )
        rows = await cursor.fetchall()
        return [json.loads(r[0]) for r in rows]

    async def add_block_evm_txs(self, block_hash: str, raw_txs: list):
        """
        Persist a block's EVM-transaction section (E-D3): the ordered list of raw
        signed eth txs included in the block, for deterministic replay on import
        and rebuild. Idempotent per (block_hash, tx_index).
        """
        if not raw_txs:
            return
        for idx, raw in enumerate(raw_txs):
            await self.connection.execute(
                "INSERT OR IGNORE INTO block_evm_transactions "
                "(block_hash, tx_index, raw_tx) VALUES (?, ?, ?)",
                (block_hash, idx, raw),
            )
        await self.connection.commit()

    async def get_block_evm_txs(self, block_hash: str) -> list:
        """Return a block's EVM-transaction section (raw hex) in canonical order."""
        cursor = await self.connection.execute(
            "SELECT raw_tx FROM block_evm_transactions "
            "WHERE block_hash = ? ORDER BY tx_index ASC",
            (block_hash,),
        )
        rows = await cursor.fetchall()
        return [r[0] for r in rows]

    # ── Finality: attestation votes (link 2) ────────────────────────────

    async def record_attestation_vote(self, validator_address: str, target_epoch: int,
                                      source_epoch: int, slot: int, block_hash: str,
                                      epoch: int = 0, validator_index: int = 0,
                                      signature: str = "") -> None:
        """
        Record a validator's attestation vote for a target epoch (one per
        validator per target — later/duplicate votes for the same target are
        ignored). Idempotent; safe to call from every importer for the same
        block-carried attestation.

        ``epoch``/``validator_index``/``signature`` retain the fully-signed
        attestation so a stored vote can be reconstructed for self-validating
        surround/double-vote slashing evidence (see ``get_validator_votes``).
        """
        await self.connection.execute(
            "INSERT OR IGNORE INTO attestation_votes "
            "(validator_address, target_epoch, source_epoch, slot, block_hash, "
            "epoch, validator_index, signature) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (validator_address, int(target_epoch), int(source_epoch), int(slot), block_hash,
             int(epoch), int(validator_index), str(signature)),
        )
        await self.connection.commit()

    async def get_validator_votes(self, validator_address: str, limit: int = 128) -> list:
        """The validator's retained attestation votes as fully-signed Attestation dicts
        (most recent target first), for surround/double-vote slashing detection. Only rows
        with a retained ``signature`` are returned (pre-retention rows can't form a proof).
        Bounded by ``limit`` — surround votes span a small epoch window in practice."""
        cur = await self.connection.execute(
            "SELECT slot, epoch, block_hash, validator_index, signature, source_epoch, target_epoch "
            "FROM attestation_votes WHERE validator_address = ? AND signature != '' "
            "ORDER BY target_epoch DESC LIMIT ?",
            (validator_address, int(limit)))
        rows = await cur.fetchall()
        return [
            {"slot": s, "epoch": e, "block_hash": bh, "validator_address": validator_address,
             "validator_index": vi, "signature": sig, "source_epoch": se, "target_epoch": te}
            for (s, e, bh, vi, sig, se, te) in rows
        ]

    # ── Slashing evidence (consensus security) ──────────────────────────

    async def record_slashing_event(self, validator_address: str, condition: str,
                                    slot: int, epoch: int, evidence: str) -> bool:
        """Persist a detected slashable offence (idempotent on
        (validator, slot, condition)). Returns True if it was NEW. Commits."""
        cur = await self.connection.execute(
            "INSERT OR IGNORE INTO slashing_events "
            "(validator_address, condition, slot, epoch, evidence) VALUES (?, ?, ?, ?, ?)",
            (validator_address, str(condition), int(slot), int(epoch), str(evidence)),
        )
        await self.connection.commit()
        return bool(cur.rowcount)

    async def get_slashing_events(self, validator_address: str = None) -> list:
        """Return recorded slashing evidence rows (optionally for one validator)."""
        if validator_address:
            cur = await self.connection.execute(
                "SELECT validator_address, condition, slot, epoch, evidence, processed "
                "FROM slashing_events WHERE validator_address = ? ORDER BY slot", (validator_address,))
        else:
            cur = await self.connection.execute(
                "SELECT validator_address, condition, slot, epoch, evidence, processed "
                "FROM slashing_events ORDER BY slot")
        rows = await cur.fetchall()
        return [{"validator_address": r[0], "condition": r[1], "slot": r[2],
                 "epoch": r[3], "evidence": r[4], "processed": bool(r[5])} for r in rows]

    async def get_unprocessed_slashing_events(self, up_to_epoch: int) -> list:
        """Unprocessed slashing evidence whose offence epoch is at or below
        ``up_to_epoch`` (so the finalized-epoch loop applies penalties only for
        offences in already-finalized epochs — deterministic ordering)."""
        cur = await self.connection.execute(
            "SELECT validator_address, condition, slot, epoch FROM slashing_events "
            "WHERE processed = 0 AND epoch <= ? ORDER BY validator_address, slot",
            (int(up_to_epoch),))
        rows = await cur.fetchall()
        return [{"validator_address": r[0], "condition": r[1], "slot": r[2], "epoch": r[3]}
                for r in rows]

    async def get_pending_slashing_evidence(self, limit: int = 16) -> list:
        """The full self-validating PROOFS for unprocessed slashing events, for a proposer to
        include in the block body so they propagate to every node. Returns the parsed evidence
        dicts (the two signed headers). Bounded by ``limit`` to keep block size sane; a proof
        keeps riding blocks until the finalized-epoch penalty marks it processed (deduped by
        every importer via INSERT OR IGNORE)."""
        import json as _json
        cur = await self.connection.execute(
            "SELECT evidence FROM slashing_events WHERE processed = 0 "
            "ORDER BY validator_address, slot LIMIT ?", (int(limit),))
        out = []
        for (ev_json,) in await cur.fetchall():
            try:
                d = _json.loads(ev_json)
                if not isinstance(d, dict):
                    continue
                # DOUBLE_SIGN proofs carry two signed headers; attestation-equivocation
                # (surround/double-vote) proofs carry two signed attestations — include both
                # kinds so either rides the block body to every node.
                if (d.get("header_a") and d.get("header_b")) or (d.get("att_a") and d.get("att_b")):
                    out.append(d)
            except Exception:
                continue
        return out

    async def apply_validator_slash(self, address: str, penalty, enforce: bool = False) -> dict:
        """Apply a slashing penalty to one validator: effective_stake -= penalty
        (clamped at 0), total_slashed += penalty, status='slashed' (ejecting it from the
        eligible set {active,pending,exiting}). Decimal arithmetic, identical on every
        node given the same evidence. ``enforce=False`` previews without writing. No
        commit. Returns {address, penalty, new_stake, applied}."""
        from decimal import Decimal
        c = await self.connection.execute(
            "SELECT effective_stake, total_slashed FROM validators WHERE address = ?", (address,))
        row = await c.fetchone()
        if not row:
            return {"address": address, "penalty": "0", "new_stake": None, "applied": False}
        pen = Decimal(str(penalty))
        cur_stake = Decimal(str(row[0] or 0))
        new_stake = cur_stake - pen
        if new_stake < 0:
            new_stake = Decimal(0)
        new_slashed = Decimal(str(row[1] or 0)) + pen
        if enforce:
            await self.connection.execute(
                "UPDATE validators SET effective_stake = ?, total_slashed = ?, "
                "slashed = 1, status = 'slashed', updated_at = CURRENT_TIMESTAMP WHERE address = ?",
                (str(new_stake), str(new_slashed), address))
        return {"address": address, "penalty": str(pen), "new_stake": str(new_stake),
                "applied": bool(enforce)}

    async def mark_slashing_events_processed(self, address: str, up_to_epoch: int) -> None:
        """Mark a validator's slashing evidence (offence epoch ≤ up_to_epoch) processed,
        so the penalty is applied exactly once. No commit."""
        await self.connection.execute(
            "UPDATE slashing_events SET processed = 1 WHERE validator_address = ? AND epoch <= ?",
            (address, int(up_to_epoch)))

    async def get_epoch_attesters(self, target_epoch: int) -> list:
        """Return the validator addresses that have voted for ``target_epoch``."""
        cursor = await self.connection.execute(
            "SELECT validator_address FROM attestation_votes WHERE target_epoch = ?",
            (int(target_epoch),),
        )
        rows = await cursor.fetchall()
        return [r[0] for r in rows]

    async def set_epoch_finality(self, epoch: int, start_slot: int, end_slot: int,
                                 justified: bool, finalized: bool) -> None:
        """
        Persist an epoch's justified/finalized status (SQLite). The existing
        epoch-processing writer is PostgreSQL-only, so this is the SQLite path the
        finality computation uses; ``get_pos_chain_head`` reads it back.
        """
        await self.connection.execute(
            "INSERT INTO epochs (epoch, start_slot, end_slot, justified, finalized) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(epoch) DO UPDATE SET "
            "  justified = excluded.justified, "
            "  finalized = excluded.finalized, "
            "  finalized_at = CASE WHEN excluded.finalized THEN CURRENT_TIMESTAMP "
            "                      ELSE epochs.finalized_at END",
            (int(epoch), int(start_slot), int(end_slot), 1 if justified else 0,
             1 if finalized else 0),
        )
        await self.connection.commit()

    async def get_validators(self, status: str = None):
        """
        Return the validator set, ordered by effective stake (descending).

        Args:
            status: Optional status filter (e.g. 'active'). None returns all.

        Returns:
            List of validator dicts.
        """
        if status:
            cursor = await self.connection.execute("""
                SELECT address, public_key, stake, effective_stake,
                       status, activation_epoch, exit_epoch, slashed
                FROM validators
                WHERE status = ?
                ORDER BY CAST(effective_stake AS REAL) DESC
            """, (status,))
        else:
            cursor = await self.connection.execute("""
                SELECT address, public_key, stake, effective_stake,
                       status, activation_epoch, exit_epoch, slashed
                FROM validators
                ORDER BY CAST(effective_stake AS REAL) DESC
            """)

        rows = await cursor.fetchall()
        validators = []
        for row in rows:
            entry = dict(row)
            entry['slashed'] = bool(entry.get('slashed'))
            validators.append(entry)
        return validators

    async def get_validators_table_hash(self) -> str:
        """Deterministic hash of the consensus validator set (Validator-lifecycle
        unification probe). Hashes every validator row in canonical address order
        over its consensus-relevant fields, so the per-epoch processing can be
        checked for cross-node convergence (the `validators` table must be identical
        on every node — eligibility is enforced off it). Empty set → all-zero."""
        cursor = await self.connection.execute("""
            SELECT address, effective_stake, status, activation_epoch, exit_epoch,
                   slashed, total_slashed, total_rewards
            FROM validators ORDER BY address ASC
        """)
        rows = await cursor.fetchall()
        if not rows:
            return "0" * 64
        import hashlib
        h = hashlib.sha256()
        for r in rows:
            h.update(
                f"{r[0]}:{r[1]}:{r[2]}:{r[3]}:{r[4]}:{int(bool(r[5]))}:{r[6]}:{r[7]}".encode()
            )
        return h.hexdigest()

    async def apply_epoch_validator_updates(
        self, rewards: dict, penalties: dict, activated: list, exited: list,
        activation_epoch: int, max_effective_balance, enforce: bool = False,
    ) -> dict:
        """
        Validator-lifecycle unification (SQLite port of the PostgreSQL
        ``epoch_processing._persist_epoch_data`` validators-table writes):
        deterministically apply an epoch's per-validator deltas to the consensus
        ``validators`` table —
          * reward  → effective_stake += reward (clamped to max_effective_balance),
                      total_rewards += reward
          * penalty → effective_stake -= penalty (clamped at 0), total_slashed += penalty
          * activated → status='active', activation_epoch set
          * exited    → status='exited'
        All arithmetic is Decimal (the columns are TEXT Decimal strings), so the
        result is identical on every node. ``enforce=False`` (OBSERVE) computes the
        new effective_stake per touched validator and returns it WITHOUT writing —
        for cross-node determinism checks during rollout. Does NOT commit; the
        caller commits atomically at the epoch boundary. Returns a summary dict.
        """
        from decimal import Decimal
        max_bal = Decimal(str(max_effective_balance)) if max_effective_balance is not None else None

        async def _cur(addr):
            c = await self.connection.execute(
                "SELECT effective_stake, total_rewards, total_slashed FROM validators WHERE address = ?",
                (addr,))
            return await c.fetchone()

        preview = {}
        # Rewards
        for addr, amt in (rewards or {}).items():
            amt = Decimal(str(amt))
            if amt <= 0:
                continue
            row = await _cur(addr)
            if not row:
                continue
            new_stake = Decimal(str(row[0] or 0)) + amt
            if max_bal is not None and new_stake > max_bal:
                new_stake = max_bal
            new_rewards = Decimal(str(row[1] or 0)) + amt
            preview[addr] = str(new_stake)
            if enforce:
                await self.connection.execute(
                    "UPDATE validators SET effective_stake = ?, total_rewards = ?, "
                    "updated_at = CURRENT_TIMESTAMP WHERE address = ?",
                    (str(new_stake), str(new_rewards), addr))
        # Penalties
        for addr, amt in (penalties or {}).items():
            amt = Decimal(str(amt))
            if amt <= 0:
                continue
            row = await _cur(addr)
            if not row:
                continue
            new_stake = Decimal(str(row[0] or 0)) - amt
            if new_stake < 0:
                new_stake = Decimal(0)
            new_slashed = Decimal(str(row[2] or 0)) + amt
            preview[addr] = str(new_stake)
            if enforce:
                await self.connection.execute(
                    "UPDATE validators SET effective_stake = ?, total_slashed = ?, "
                    "updated_at = CURRENT_TIMESTAMP WHERE address = ?",
                    (str(new_stake), str(new_slashed), addr))
        # Activations
        if enforce:
            for addr in (activated or []):
                await self.connection.execute(
                    "UPDATE validators SET status = 'active', activation_epoch = ?, "
                    "updated_at = CURRENT_TIMESTAMP WHERE address = ?",
                    (int(activation_epoch), addr))
            for addr in (exited or []):
                await self.connection.execute(
                    "UPDATE validators SET status = 'exited', exit_epoch = COALESCE(exit_epoch, ?), "
                    "updated_at = CURRENT_TIMESTAMP WHERE address = ?",
                    (int(activation_epoch), addr))
        return {
            "rewarded": len([a for a, v in (rewards or {}).items() if Decimal(str(v)) > 0]),
            "penalized": len([a for a, v in (penalties or {}).items() if Decimal(str(v)) > 0]),
            "activated": len(activated or []),
            "exited": len(exited or []),
            "effective_stake_preview": preview,
            "applied": enforce,
        }

    async def schedule_pending_activations(self, activation_epoch: int) -> int:
        """Phase 3: assign an activation epoch to any just-deposited PENDING validator
        that has none yet (activation_epoch IS NULL). Called deterministically by the
        all-nodes epoch loop at a finalized epoch, so every node schedules the same
        validators to the same epoch. Returns the count scheduled. No commit."""
        cur = await self.connection.execute(
            "UPDATE validators SET activation_epoch = ?, updated_at = CURRENT_TIMESTAMP "
            "WHERE status = 'pending' AND activation_epoch IS NULL", (int(activation_epoch),))
        return cur.rowcount if cur.rowcount is not None else 0

    async def schedule_pending_exits(self, exit_epoch: int) -> int:
        """Phase 3: assign an exit epoch to any validator marked 'exiting' without one
        (exit_epoch IS NULL). Deterministic (epoch-loop driven). No commit."""
        cur = await self.connection.execute(
            "UPDATE validators SET exit_epoch = ?, updated_at = CURRENT_TIMESTAMP "
            "WHERE status = 'exiting' AND exit_epoch IS NULL", (int(exit_epoch),))
        return cur.rowcount if cur.rowcount is not None else 0

    async def mark_validator_exiting(self, address: str, exit_epoch=None) -> bool:
        """Phase 3 (voluntary exit): move an active validator to 'exiting' and set its
        ``exit_epoch`` (the finalized epoch at which the epoch loop removes it). The
        caller passes a DETERMINISTIC exit_epoch derived from the exit block's epoch, so
        every node assigns the same value. ``exit_epoch=None`` leaves it unscheduled.
        No-op if not currently active. No commit."""
        cur = await self.connection.execute(
            "UPDATE validators SET status = 'exiting', "
            "exit_epoch = COALESCE(?, exit_epoch), updated_at = CURRENT_TIMESTAMP "
            "WHERE address = ? AND status = 'active'",
            (int(exit_epoch) if exit_epoch is not None else None, address))
        return bool(cur.rowcount)

    async def register_pending_validator(self, address: str, public_key: str, stake,
                                          activation_epoch=None) -> bool:
        """
        Validator-lifecycle Phase 3 (staking deposit / join): insert a PENDING
        validator into the consensus ``validators`` table, scheduled to activate at
        ``activation_epoch``. Idempotent on address (a repeat deposit tops up stake).
        Stake stored as a Decimal string (matching effective_stake). Does NOT commit
        — the caller commits with the block/flush. Deterministic: every node that
        replays the same deposit creates the identical row.
        """
        from decimal import Decimal
        s = str(Decimal(str(stake)))
        cur = await self.connection.execute(
            "SELECT stake, effective_stake FROM validators WHERE address = ?", (address,))
        row = await cur.fetchone()
        if row:
            new_stake = str(Decimal(str(row[0] or 0)) + Decimal(str(stake)))
            new_eff = str(Decimal(str(row[1] or 0)) + Decimal(str(stake)))
            await self.connection.execute(
                "UPDATE validators SET stake = ?, effective_stake = ?, public_key = ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE address = ?",
                (new_stake, new_eff, public_key, address))
            return False  # topped up an existing validator
        await self.connection.execute(
            "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
            "activation_epoch) VALUES (?, ?, ?, ?, 'pending', ?)",
            (address, public_key, s, s,
             int(activation_epoch) if activation_epoch is not None else None))
        return True

    async def seed_genesis_validators(self, genesis_validators: list) -> int:
        """Reset the consensus ``validators`` table to its GENESIS BASE — the reset primitive for
        validators reorg-reconstruction (mirror of ``seed_genesis_account_state``). Removes every
        non-genesis (DEPOSITED) validator and resets each genesis validator's DYNAMIC state
        (effective_stake=stake, status='active', activation_epoch=0, exit_epoch=NULL,
        total_rewards/total_slashed=0, slashed=0). After this, replaying the canonical STAKE ops +
        re-running finalized epoch processing rebuilds the dynamic state as a pure function of the
        chain. ``genesis_validators`` = [{address, public_key, stake}]. Does NOT commit.

        Genesis is defined by this passed-in set (from the genesis config/snapshot), NOT by a
        table heuristic — a deposited validator can also sit at activation_epoch 0 mid-reorg."""
        from decimal import Decimal
        addrs = [v["address"] for v in genesis_validators]
        if addrs:
            ph = ",".join("?" * len(addrs))
            await self.connection.execute(
                f"DELETE FROM validators WHERE address NOT IN ({ph})", addrs)
        else:
            await self.connection.execute("DELETE FROM validators")
        for v in genesis_validators:
            s = str(Decimal(str(v["stake"])))
            await self.connection.execute(
                "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
                "activation_epoch, exit_epoch, slashed, total_slashed, total_rewards) "
                "VALUES (?, ?, ?, ?, 'active', 0, NULL, 0, '0', '0') "
                "ON CONFLICT(address) DO UPDATE SET "
                "public_key=excluded.public_key, stake=excluded.stake, "
                "effective_stake=excluded.effective_stake, status='active', "
                "activation_epoch=0, exit_epoch=NULL, slashed=0, "
                "total_slashed='0', total_rewards='0', updated_at=CURRENT_TIMESTAMP",
                (v["address"], v["public_key"], s, s))
        return len(genesis_validators)

    async def get_genesis_validators(self) -> list:
        """The GENESIS validator set as [{address, public_key, stake}] for the reconstruction
        reset. Genesis validators are uniquely identified by ``activation_epoch = 0`` — a
        DEPOSITED validator always gets ``block_epoch + ACTIVATION_DELAY_EPOCHS`` (≥ 4 > 0), so
        it can never collide. Their ``stake`` column stays at the genesis base (register_pending
        tops up only deposited rows; epoch updates touch effective_stake, not stake), so it is the
        correct base to reset to. Canonical address order for determinism."""
        cur = await self.connection.execute(
            "SELECT address, public_key, stake FROM validators WHERE activation_epoch = 0 "
            "ORDER BY address ASC")
        return [{"address": r[0], "public_key": r[1], "stake": r[2]} for r in await cur.fetchall()]

    async def get_validators_to_activate(self, current_epoch: int) -> list:
        """Pending validators whose scheduled activation_epoch has arrived
        (<= current_epoch). Deterministic, canonical address order."""
        cur = await self.connection.execute(
            "SELECT address FROM validators WHERE status = 'pending' "
            "AND activation_epoch IS NOT NULL AND activation_epoch <= ? "
            "ORDER BY address ASC", (int(current_epoch),))
        return [r[0] for r in await cur.fetchall()]

    async def get_validators_to_exit(self, current_epoch: int) -> list:
        """Validators marked 'exiting' whose exit_epoch has arrived (<= current_epoch),
        to be moved to 'exited'. Deterministic, canonical address order."""
        cur = await self.connection.execute(
            "SELECT address FROM validators WHERE status = 'exiting' "
            "AND exit_epoch IS NOT NULL AND exit_epoch <= ? "
            "ORDER BY address ASC", (int(current_epoch),))
        return [r[0] for r in await cur.fetchall()]

    async def get_attestations_filtered(self, filters: dict, limit: int, offset: int):
        """Get attestations with filters"""
        where_clauses = []
        params = []
        
        if 'slot' in filters and filters['slot'] is not None:
            where_clauses.append("slot = ?")
            params.append(filters['slot'])
        
        if 'epoch' in filters and filters['epoch'] is not None:
            where_clauses.append("epoch = ?")
            params.append(filters['epoch'])
        
        if 'validator_address' in filters and filters['validator_address']:
            where_clauses.append("validator_address = ?")
            params.append(filters['validator_address'])
        
        if 'block_hash' in filters and filters['block_hash']:
            where_clauses.append("block_hash = ?")
            params.append(filters['block_hash'])
        
        where_clause = " AND ".join(where_clauses) if where_clauses else "1=1"
        params.extend([limit, offset])
        
        query = f"""
            SELECT 
                a.id,
                a.slot,
                a.epoch,
                a.block_hash,
                a.validator_address,
                a.validator_index,
                a.source_epoch,
                a.target_epoch,
                a.included_in_block,
                a.inclusion_slot,
                a.created_at,
                v.stake,
                v.effective_stake,
                v.status as validator_status
            FROM attestations a
            LEFT JOIN validators v ON a.validator_address = v.address
            WHERE {where_clause}
            ORDER BY a.slot DESC, a.validator_index ASC
            LIMIT ? OFFSET ?
        """
        
        cursor = await self.connection.execute(query, tuple(params))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_pending_transactions_by_hash(self, hashes: list):
        """Get pending transactions by hash"""
        if not hashes:
            return []
        placeholders = ','.join('?' * len(hashes))
        cursor = await self.connection.execute(
            f"SELECT * FROM pending_transactions WHERE tx_hash IN ({placeholders})",
            hashes
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_block_by_id(self, block_id: int):
        """Get block by ID"""
        cursor = await self.connection.execute(
            f"SELECT {_BLOCK_COLS} FROM blocks WHERE block_height = ?",
            (block_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    
    async def get_block(self, block_hash: str):
        """Get block by hash"""
        cursor = await self.connection.execute(
            f"SELECT {_BLOCK_COLS} FROM blocks WHERE block_hash = ?",
            (block_hash,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    
    async def get_last_block(self):
        """Get latest block"""
        return await self.get_latest_block()
    
    async def get_block_transactions(self, block_hash: str, hex_only: bool = False):
        """Get transactions in a block"""
        cursor = await self.connection.execute(
            "SELECT tx_hex FROM transactions WHERE block_hash = ?",
            (block_hash,)
        )
        rows = await cursor.fetchall()
        if hex_only:
            return [row[0] for row in rows]
        return rows
    
    async def get_block_nice_transactions(self, block_hash: str):
        """Get formatted transactions in a block"""
        return await self.get_block_transactions(block_hash, hex_only=True)
    
    async def remove_blocks(self, start_id: int):
        """Remove blocks starting from ID (rollback / reorg)."""
        await self.connection.execute(
            "DELETE FROM blocks WHERE block_height >= ?",
            (start_id,)
        )
        # Drop exchange/EVM sections for blocks no longer on the canonical chain
        # so no stale protocol-level state lingers after a reorg rollback.
        await self.connection.execute(
            "DELETE FROM block_exchange_transactions "
            "WHERE block_hash NOT IN (SELECT block_hash FROM blocks)"
        )
        await self.connection.execute(
            "DELETE FROM block_evm_transactions "
            "WHERE block_hash NOT IN (SELECT block_hash FROM blocks)"
        )
        await self.connection.commit()
    
    async def get_pending_transactions_limit(self, limit: int):
        """Get limited pending transactions"""
        cursor = await self.connection.execute(
            f"SELECT tx_hex FROM pending_transactions LIMIT ?",
            (limit,)
        )
        rows = await cursor.fetchall()
        return [row[0] for row in rows]
    
    async def get_nice_transaction(self, tx_hash: str, address: str = None):
        """Get formatted transaction"""
        cursor = await self.connection.execute(
            "SELECT * FROM transactions WHERE tx_hash = ?",
            (tx_hash,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    
    async def remove_pending_transaction(self, tx_hash: str):
        """Remove pending transaction"""
        await self.connection.execute(
            "DELETE FROM pending_transactions WHERE tx_hash = ?",
            (tx_hash,)
        )
        await self.connection.commit()
    
    async def get_blocks(self, offset: int, limit: int):
        """Get blocks starting from a given height, ascending.
        
        'offset' is treated as a starting block_height (inclusive) so
        that the sync protocol can request ``get_blocks(start_height, count)``.
        """
        cursor = await self.connection.execute(
            f"SELECT {_BLOCK_COLS} FROM blocks WHERE block_height >= ? ORDER BY block_height ASC LIMIT ?",
            (offset, limit)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_spendable_outputs(self, address: str):
        """Get spendable outputs for address"""
        cursor = await self.connection.execute("""
            SELECT tx_hash, output_index, amount 
            FROM unspent_outputs 
            WHERE address = ?
        """, (address,))
        
        rows = await cursor.fetchall()
        outputs = []
        
        for tx_hash, output_index, amount in rows:
            # Convert tx_hash bytes to hex if needed
            if isinstance(tx_hash, bytes):
                tx_hash = tx_hash.hex()
            
            # Create a simple object with the required attributes
            class Output:
                def __init__(self, address, amount, tx_hash, index):
                    self.address = address
                    self.amount = amount / 1000000  # Convert from microQRDX to QRDX
                    self.tx_hash = tx_hash
                    self.index = index
            
            outputs.append(Output(address, amount, tx_hash, output_index))
        
        return outputs

    async def get_address_balance(self, address: str, check_pending_txs: bool = False) -> 'Decimal':
        """Get total balance for an address.

        Checks account_state first (ETH/EVM accounts populated at genesis),
        then falls back to the UTXO unspent_outputs table.
        Returns balance in QRDX (not micro-QRDX, not wei).
        Uses case-insensitive matching for 0x addresses.
        """
        from decimal import Decimal

        addr_lower = address.lower()

        # 1. Check account_state (ETH/EVM accounts — balance stored as wei string)
        try:
            cursor = await self.connection.execute(
                "SELECT balance FROM account_state WHERE LOWER(address) = ?",
                (addr_lower,),
            )
            row = await cursor.fetchone()
            if row and row[0]:
                bal_wei = int(row[0])
                if bal_wei > 0:
                    return Decimal(bal_wei) / Decimal(10**18)
        except Exception:
            pass

        # 2. Fallback: sum unspent_outputs (stored as micro-QRDX)
        try:
            cursor = await self.connection.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM unspent_outputs WHERE LOWER(address) = ?",
                (addr_lower,),
            )
            row = await cursor.fetchone()
            micro = int(row[0]) if row and row[0] else 0
            if micro > 0:
                return Decimal(micro) / Decimal(10**6)
        except Exception:
            pass

        return Decimal(0)

    async def get_address_transactions(self, address: str, limit: int = 100, offset: int = 0, check_signatures: bool = False):
        """Get transactions for address from the transactions table."""
        cursor = await self.connection.execute("""
            SELECT tx_hash, tx_hex, block_hash, inputs_addresses,
                   outputs_addresses, outputs_amounts, fees, created_at
            FROM transactions
            WHERE inputs_addresses LIKE ? OR outputs_addresses LIKE ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """, (f'%{address}%', f'%{address}%', limit, offset))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    
    async def get_address_pending_transactions(self, address: str, hex_only: bool = False):
        """Get pending transactions for address from the mempool."""
        cursor = await self.connection.execute("""
            SELECT tx_hash, tx_hex, inputs_addresses, fees, time_received
            FROM pending_transactions
            WHERE inputs_addresses LIKE ?
            ORDER BY time_received DESC
        """, (f'%{address}%',))
        rows = await cursor.fetchall()
        if hex_only:
            return [row[1] for row in rows]
        return [dict(row) for row in rows]
    
    async def get_address_pending_spent_outputs(self, address: str):
        """Get pending spent outputs for address."""
        cursor = await self.connection.execute("""
            SELECT pso.tx_hash, pso.output_index
            FROM pending_spent_outputs pso
            JOIN unspent_outputs uo ON pso.tx_hash = uo.tx_hash AND pso.output_index = uo.output_index
            WHERE uo.address = ?
        """, (address,))
        rows = await cursor.fetchall()
        return [(row[0], row[1]) for row in rows]
    
    async def add_peer(self, peer_url: str):
        """Add or update peer"""
        await self.connection.execute("""
            INSERT OR REPLACE INTO peers (node_url, last_seen, reputation)
            VALUES (?, CURRENT_TIMESTAMP, COALESCE((SELECT reputation FROM peers WHERE node_url = ?), 0))
        """, (peer_url, peer_url))
        await self.connection.commit()
        return True
    
    async def get_peers(self, limit: int = 100):
        """Get list of peers"""
        cursor = await self.connection.execute(
            "SELECT node_url, reputation, last_seen FROM peers ORDER BY reputation DESC, last_seen DESC LIMIT ?",
            (limit,)
        )
        rows = await cursor.fetchall()
        return [{'url': row[0], 'reputation': row[1], 'last_seen': row[2]} for row in rows]
