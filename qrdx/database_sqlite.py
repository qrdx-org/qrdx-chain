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
        
        CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(block_height);
        CREATE INDEX IF NOT EXISTS idx_transactions_block ON transactions(block_hash);
        CREATE INDEX IF NOT EXISTS idx_unspent_address ON unspent_outputs(address);
        CREATE INDEX IF NOT EXISTS idx_validator_epoch ON validator_states(epoch);
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
    
    # Stub methods for compatibility with existing code
    # These should be implemented as needed for full functionality
    
    async def add_pending_transaction(self, transaction, verify: bool = True):
        """Add pending transaction (stub)"""
        logger.warning("add_pending_transaction not fully implemented for SQLite")
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
        """Get transactions that need propagation"""
        return []
    
    async def update_pending_transactions_propagation_time(self, tx_hashes: list):
        """Update propagation time for transactions"""
        pass
    
    async def get_unspent_outputs_hash(self):
        """Get hash of unspent outputs"""
        return "0" * 64
    
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
        return []
    
    async def get_address_transactions(self, address: str, limit: int = 100):
        """Get transactions for address"""
        return []
    
    async def get_address_pending_transactions(self, address: str, hex_only: bool = False):
        """Get pending transactions for address"""
        return []
    
    async def get_address_pending_spent_outputs(self, address: str):
        """Get pending spent outputs for address"""
        return []
    
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
