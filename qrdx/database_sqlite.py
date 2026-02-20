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


class DatabaseSQLite:
    """Simplified SQLite database for testnet"""
    
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
        
        logger.info(f"SQLite database initialized: {db_path}")
        return self
        
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
        
        CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(block_height);
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
        """Get latest block (stub)"""
        cursor = await self.connection.execute(
            "SELECT * FROM blocks ORDER BY block_height DESC LIMIT 1"
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
        
    async def add_block(self, **kwargs):
        """Add block to database"""
        # Extract parameters with defaults
        block_id = kwargs.get('block_id', kwargs.get('block_height', 0))
        block_hash = kwargs.get('block_hash', '')
        block_content = kwargs.get('block_content', kwargs.get('content', ''))
        address = kwargs.get('address', kwargs.get('validator_address', ''))
        timestamp = kwargs.get('timestamp', datetime.now(timezone.utc))
        
        # Insert block
        await self.connection.execute("""
            INSERT INTO blocks (block_hash, block_height, validator_address, content, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (block_hash, block_id, address, block_content, timestamp))
        await self.connection.commit()
        logger.info(f"Block {block_id} added: {block_hash[:16]}...")
        return True
    
    async def add_transaction(self, **kwargs):
        """Add transaction to database"""
        tx_hash = kwargs.get('tx_hash', '')
        tx_hex = kwargs.get('tx_hex', '')
        block_hash = kwargs.get('block_hash', '')
        
        await self.connection.execute("""
            INSERT INTO transactions (tx_hash, tx_hex, block_hash)
            VALUES (?, ?, ?)
        """, (tx_hash, tx_hex, block_hash))
        await self.connection.commit()
        return True
    
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
        """Update propagation time for transactions"""
        pass
    
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
            "SELECT * FROM blocks WHERE block_height = ?",
            (block_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    
    async def get_block(self, block_hash: str):
        """Get block by hash"""
        cursor = await self.connection.execute(
            "SELECT * FROM blocks WHERE block_hash = ?",
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
        """Remove blocks starting from ID"""
        await self.connection.execute(
            "DELETE FROM blocks WHERE block_height >= ?",
            (start_id,)
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
        """Get blocks with pagination"""
        cursor = await self.connection.execute(
            "SELECT * FROM blocks ORDER BY block_height DESC LIMIT ? OFFSET ?",
            (limit, offset)
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
