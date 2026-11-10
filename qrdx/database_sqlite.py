"""
SQLite Database Adapter for QRDX Testnet

This is a simplified SQLite adapter for local testnet development.
For production, use the full PostgreSQL database.py implementation.
"""

import json
import os
from collections import OrderedDict
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

import aiosqlite

from . import block_codec
from .logger import get_logger

logger = get_logger(__name__)


def _now() -> str:
    """A row's ``created_at``, as SQLite's CURRENT_TIMESTAMP wrote it (UTC, to the second)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _block_dict(row: Any, content: Any = None, with_body: bool = True) -> Optional[Dict[str, Any]]:
    """A ``blocks`` row (qrdx/store.py) as the dict every caller reads: its columns, the short
    aliases the PostgreSQL schema used (``hash``, ``id``, ``address``), and its body decoded
    (qrdx/block_codec.py) — or without ``content`` (``with_body`` False)."""
    if row is None:
        return None
    block = {
        "block_hash": row.block_hash,
        "hash": row.block_hash,
        "block_height": row.block_height,
        "id": row.block_height,
        "prev_block_hash": row.prev_block_hash,
        "merkle_root": row.merkle_root,
        "timestamp": row.timestamp,
        "difficulty": row.difficulty,
        "nonce": row.nonce,
        "validator_address": row.validator_address,
        "address": row.validator_address,
        "validator_signature": row.validator_signature,
        "created_at": row.created_at,
    }
    if with_body:
        block["content"] = block_codec.decode(content)
    return block


class DatabaseSQLite:
    """Simplified SQLite database for testnet"""

    instance: Optional["DatabaseSQLite"] = None
    credentials: Dict[str, Any] = {}

    def __init__(self, db_path: str):
        self.db_path = db_path
        # Opened by create() — the only way an instance is made — before any use.
        self.connection: aiosqlite.Connection = None  # type: ignore[assignment]
        self.store: Any = None  # (qrdx/store.py)
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
        # Every statement, fetch and commit is a round trip to aiosqlite's thread, and a
        # block's fixed cost is mostly those round trips: counted for its phase log line
        # (observability.Phases).
        from .node.observability import count_db_calls

        count_db_calls(self.connection)

        await self._refuse_before_the_store()
        # Enable WAL mode for better concurrency
        await self.connection.execute("PRAGMA journal_mode=WAL")
        await self.connection.execute("PRAGMA synchronous=NORMAL")

        # Initialize schema
        await self._init_schema()
        # The store beside it (qrdx/store.py): the ledger, its commitments, the undo journal and
        # the state proof tree. Committing (or rolling back) the connection does the same to the
        # store, first, so every caller that ends a block's transaction ends both.
        from .store import Store

        self.store = Store(db_path + ".store")
        self._couple_store()
        from . import state_proofs, undo_journal

        state_proofs.install(self)
        if undo_journal.floor(self) is None:
            await undo_journal.set_floor(self, max(0, await self.get_next_block_id() - 1))
            await self.connection.commit()

        # Set singleton instance (matching Database pattern for manager.py etc.)
        DatabaseSQLite.instance = self

        logger.info(f"SQLite database initialized: {db_path}")
        return self

    # Tables the store holds now (qrdx/store.py): a database that still has them was written before
    # it, and its ledger, journal and sections would be silently left behind.
    _MOVED_TO_THE_STORE = (
        "account_state",
        "contract_storage",
        "token_balances",
        "undo_log",
        "state_commitment",
        "block_exchange_transactions",
        "block_evm_transactions",
        "blocks",
        "chain_index",
    )

    async def _refuse_before_the_store(self) -> None:
        marks = ",".join("?" * len(self._MOVED_TO_THE_STORE))
        rows = await self.connection.execute_fetchall(
            f"SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ({marks})",
            self._MOVED_TO_THE_STORE,
        )
        if rows:
            await self.connection.close()
            raise RuntimeError(
                f"{self.db_path} was written before the node's store (docs/STORAGE.md): it holds "
                f"{', '.join(sorted(r[0] for r in rows))} in SQLite. Start this node from a new "
                "database (sync, or restore a snapshot of format 2)."
            )

    # ── the chain's settings (``chain_metadata``) ──

    def get_metadata(self, key: str) -> Optional[str]:
        row = self.store["chain_metadata"].get(key)
        return None if row is None else row.value

    def set_metadata(self, key: str, value: Any) -> None:
        self.store["chain_metadata"].put(key, str(value))

    def _next_tx_seq(self) -> int:
        """The next transaction's position in the order stored (``transactions.seq``)."""
        seq = self.__dict__.get("_tx_seq")
        if seq is None:
            seq = max((int(r.seq) for r in self.store["transactions"].scan()), default=0)
        self._tx_seq = seq + 1
        return self._tx_seq

    def _couple_store(self) -> None:
        conn, store = self.connection, self.store
        commit, rollback = conn.commit, conn.rollback

        async def commit_both() -> None:
            store.commit()
            await commit()

        async def rollback_both() -> None:
            store.rollback()
            await rollback()
            from . import chain_index

            chain_index.rolled_back(self)

        conn.commit = commit_both  # type: ignore[method-assign]
        conn.rollback = rollback_both  # type: ignore[method-assign]

    @staticmethod
    async def get():
        """Get the singleton instance, matching Database.get() interface."""
        if DatabaseSQLite.instance is None:
            raise RuntimeError("DatabaseSQLite not initialized — call create() first")
        return DatabaseSQLite.instance

    async def _init_schema(self):
        """Initialize database schema"""
        schema = """

        CREATE TABLE IF NOT EXISTS pending_transactions (
            tx_hash TEXT PRIMARY KEY,
            tx_hex TEXT NOT NULL,
            inputs_addresses TEXT,
            fees INTEGER,
            time_received TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            propagation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS pending_spent_outputs (
            tx_hash TEXT NOT NULL,
            output_index INTEGER NOT NULL
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

        CREATE TABLE IF NOT EXISTS contract_metadata (
            contract_address TEXT PRIMARY KEY,
            name TEXT,
            symbol TEXT,
            compiler_version TEXT,
            source_code TEXT,
            abi TEXT,
            verified BOOLEAN NOT NULL DEFAULT 0,
            verified_at INTEGER
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

        -- Transaction index (qrdx/tx_index.py): every transaction of every canonical block —
        -- legacy transfers, exchange operations, EVM transactions — with the accounts each
        -- one touched, for wallet history and the recent-transactions feed. Derived and
        -- node-local (never hashed): written by the indexer behind the tip, cut back by
        -- remove_blocks, and re-indexed when the indexed block hash at a height changes.
        CREATE TABLE IF NOT EXISTS tx_index_blocks (
            block_height INTEGER PRIMARY KEY,
            block_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tx_index (
            block_height INTEGER NOT NULL,
            position INTEGER NOT NULL,
            tx_hash TEXT NOT NULL,
            block_hash TEXT NOT NULL,
            timestamp INTEGER,
            kind TEXT NOT NULL,
            op TEXT,
            sender TEXT,
            target TEXT,
            asset TEXT,
            amount TEXT,
            status INTEGER,
            fee TEXT,
            error TEXT,
            detail TEXT,
            PRIMARY KEY (block_height, position)
        );
        CREATE TABLE IF NOT EXISTS tx_participants (
            account TEXT NOT NULL,
            block_height INTEGER NOT NULL,
            position INTEGER NOT NULL,
            roles TEXT NOT NULL,
            PRIMARY KEY (account, block_height, position)
        );
        CREATE INDEX IF NOT EXISTS idx_tx_index_hash ON tx_index(tx_hash);
        CREATE INDEX IF NOT EXISTS idx_tx_index_kind ON tx_index(kind, block_height);

        -- Trading history (qrdx/trading_history.py): every trade, every order's life, funding
        -- and per-minute market samples, from the exchange journal as blocks commit. Derived
        -- and node-local (never hashed); cut back with the chain.
        CREATE TABLE IF NOT EXISTS hist_trades (
            block_height INTEGER NOT NULL,
            position INTEGER NOT NULL,
            block_time REAL,
            market TEXT,
            venue TEXT,
            kind TEXT,
            price TEXT,
            amount TEXT,
            side TEXT,
            buyer TEXT,
            seller TEXT,
            maker TEXT,
            taker TEXT,
            maker_order_id TEXT,
            taker_order_id TEXT,
            tx_hash TEXT,
            pool_id TEXT,
            fees TEXT,
            realized TEXT,
            PRIMARY KEY (block_height, position)
        );
        CREATE INDEX IF NOT EXISTS idx_hist_trades_market ON hist_trades(market, block_height);
        CREATE TABLE IF NOT EXISTS hist_trade_accounts (
            account TEXT NOT NULL,
            block_height INTEGER NOT NULL,
            position INTEGER NOT NULL,
            block_time REAL,
            venue TEXT,
            role TEXT,
            side TEXT,
            notional TEXT,
            fee TEXT,
            realized TEXT,
            PRIMARY KEY (account, block_height, position)
        );
        CREATE INDEX IF NOT EXISTS idx_hist_trade_accounts_time
            ON hist_trade_accounts(venue, block_time);
        CREATE TABLE IF NOT EXISTS hist_orders (
            block_height INTEGER NOT NULL,
            position INTEGER NOT NULL,
            block_time REAL,
            account TEXT,
            market TEXT,
            order_id TEXT,
            event TEXT,
            tx_hash TEXT,
            detail TEXT,
            PRIMARY KEY (block_height, position)
        );
        CREATE INDEX IF NOT EXISTS idx_hist_orders_account ON hist_orders(account, block_height);
        CREATE INDEX IF NOT EXISTS idx_hist_orders_id ON hist_orders(order_id);
        CREATE TABLE IF NOT EXISTS hist_funding (
            block_height INTEGER NOT NULL,
            position INTEGER NOT NULL,
            block_time REAL,
            market TEXT,
            rate TEXT,
            premium TEXT,
            oracle_price TEXT,
            open_interest TEXT,
            funding_time TEXT,
            PRIMARY KEY (block_height, position)
        );
        CREATE INDEX IF NOT EXISTS idx_hist_funding_market ON hist_funding(market, block_height);
        CREATE TABLE IF NOT EXISTS hist_samples (
            block_height INTEGER NOT NULL,
            position INTEGER NOT NULL,
            block_time REAL,
            market TEXT,
            mark TEXT,
            oracle TEXT,
            open_interest TEXT,
            funding_rate TEXT,
            PRIMARY KEY (block_height, position)
        );
        CREATE INDEX IF NOT EXISTS idx_hist_samples_market ON hist_samples(market, block_time);
        CREATE INDEX IF NOT EXISTS idx_attestation_votes_target ON attestation_votes(target_epoch);
        CREATE INDEX IF NOT EXISTS idx_attestation_votes_block ON attestation_votes(block_hash);
        CREATE INDEX IF NOT EXISTS idx_validator_epoch ON validator_states(epoch);
        CREATE INDEX IF NOT EXISTS idx_stakes_status ON validator_stakes(status);
        CREATE INDEX IF NOT EXISTS idx_stakes_activation ON validator_stakes(activation_epoch);
        CREATE INDEX IF NOT EXISTS idx_deposits_validator ON stake_deposits(validator_address);
        CREATE INDEX IF NOT EXISTS idx_withdrawals_validator ON stake_withdrawals(validator_address);
        -- Balance writes find their row case-insensitively (genesis may store a checksummed
        -- address): without this every write scanned the table (docs/KNOWN_ISSUES.md).
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
            # The FFG vote's checkpoint roots (qrdx/validator/ffg.py): signed, so a retained
            # vote rebuilds into the exact attestation — and two copies of one vote compare
            # equal (without them, seeing an honest vote twice looked like a double vote).
            "ALTER TABLE attestation_votes ADD COLUMN source_root TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE attestation_votes ADD COLUMN target_root TEXT NOT NULL DEFAULT ''",
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
        """Close database connection (and the store: what neither committed is dropped)"""
        if self.connection:
            await self.connection.close()
            logger.info(f"SQLite database closed: {self.db_path}")
        store = getattr(self, "store", None)
        if store is not None:
            store.close()

    # Compatibility methods for existing code

    async def add_pending_transaction(self, transaction, verify: bool = True):
        """Add pending transaction to the mempool table."""
        try:
            tx_hex = transaction.hex() if isinstance(transaction, bytes) else str(transaction)
            await self.connection.execute(
                "INSERT OR IGNORE INTO pending_transactions (tx_hash, tx_data, added_at) "
                "VALUES (?, ?, datetime('now'))",
                (getattr(transaction, "hash", tx_hex[:64]), tx_hex),
            )
            await self.connection.commit()
            return True
        except Exception as e:
            logger.warning("add_pending_transaction: %s", e)
            return True

    async def get_latest_block(self):
        """Get the latest block from the database."""
        rows = self.store["blocks"].scan(reverse=True, limit=1)
        return await self._with_body(rows[0]) if rows else None

    async def _with_body(self, row: Any) -> Optional[Dict[str, Any]]:
        body = self.store["block_bodies"].get(row.block_height)
        return _block_dict(row, body.content if body is not None else None)

    async def get_block_height(self):
        """Get current block height (-1 for an empty chain)."""
        rows = self.store["blocks"].scan(reverse=True, limit=1)
        return int(rows[0].block_height) if rows else -1

    async def get_next_block_id(self):
        """Get next block ID"""
        height = await self.get_block_height()
        return height + 1

    async def add_block(
        self,
        block_id_or_kw=None,
        block_hash=None,
        block_content=None,
        address=None,
        random_value=None,
        difficulty=None,
        reward=None,
        timestamp=None,
        **kwargs,
    ):
        """Add block to database.

        Accepts both positional args (matching the PostgreSQL API used by
        manager.py's create_block) and keyword args (used by genesis_init
        and node_integration).
        """
        # Merge positional & keyword sources so every caller works.
        _id = (
            block_id_or_kw
            if block_id_or_kw is not None
            else kwargs.get("block_id", kwargs.get("block_height", 0))
        )
        _hash = block_hash or kwargs.get("block_hash", "")
        _content = block_content if block_content is not None else kwargs.get("content", "")
        _addr = address or kwargs.get("validator_address", "")
        _ts = (
            timestamp
            if timestamp is not None
            else kwargs.get("timestamp", datetime.now(timezone.utc))
        )

        # Insert block (its body compressed: qrdx/block_codec.py)
        blocks = self.store["blocks"]
        if blocks.exists(_id) or blocks.scan_index("by_hash", _hash, limit=1):
            raise ValueError(f"a block is stored at height {_id} or with hash {_hash[:16]}")
        blocks.put(
            block_height=_id,
            block_hash=_hash,
            validator_address=_addr,
            timestamp=_ts,
            created_at=_now(),
        )
        body = block_codec.encode(_content)
        self.store["block_bodies"].put(_id, body.encode() if isinstance(body, str) else body)
        from . import chain_index

        chain_index.blocks_changed(self)
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
            block_hash = block_hash_arg or ""
        else:
            # Keyword call
            kw = transaction_or_kw if isinstance(transaction_or_kw, dict) else kwargs
            tx_hash = kw.get("tx_hash", kwargs.get("tx_hash", ""))
            tx_hex = kw.get("tx_hex", kwargs.get("tx_hex", ""))
            block_hash = kw.get("block_hash", kwargs.get("block_hash", block_hash_arg or ""))

        txs = self.store["transactions"]
        if not txs.exists(tx_hash):
            txs.put(
                tx_hash=tx_hash,
                tx_hex=tx_hex,
                block_hash=block_hash,
                created_at=_now(),
                seq=self._next_tx_seq(),
            )
        await self.connection.commit()
        return True

    async def add_transactions(self, transactions, block_hash: str):
        """Add multiple transactions to database (matches PostgreSQL API)."""
        for tx in transactions:
            await self.add_transaction(tx, block_hash)

    async def add_unspent_transactions_outputs(self, transactions):
        """Create UTXO entries for all outputs of the given transactions."""
        utxos = self.store["unspent_outputs"]
        for tx in transactions:
            for idx, output in enumerate(tx.outputs):
                utxos.insert(
                    tx_hash=tx.hash(),
                    output_index=idx,
                    address=output.address,
                    amount=output.amount,
                )
        await self.connection.commit()

    async def remove_pending_transactions_by_hash(self, hashes: list):
        """Remove specific pending transactions by hash."""
        if not hashes:
            return
        placeholders = ",".join("?" for _ in hashes)
        await self.connection.execute(
            f"DELETE FROM pending_transactions WHERE tx_hash IN ({placeholders})", hashes
        )
        await self.connection.commit()

    async def remove_unspent_outputs(self, transactions):
        """Remove spent inputs from the UTXO set."""
        utxos = self.store["unspent_outputs"]
        for tx in transactions:
            for tx_input in tx.inputs:
                utxos.delete(tx_input.tx_hash, tx_input.index)
        await self.connection.commit()

    async def remove_pending_spent_outputs(self, transactions):
        """Remove pending spent outputs after block confirmation."""
        for tx in transactions:
            for tx_input in tx.inputs:
                await self.connection.execute(
                    "DELETE FROM pending_spent_outputs WHERE tx_hash = ? AND index_spent = ?",
                    (tx_input.tx_hash, tx_input.index),
                )
        await self.connection.commit()

    async def delete_block(self, block_id: int):
        """Delete a block and its transactions (for rollback)."""
        row = self.store["blocks"].get(block_id)
        if row is None:
            return
        txs = self.store["transactions"]
        for tx in txs.scan_index("by_block", row.block_hash):
            txs.delete(tx.tx_hash)
        self.store["blocks"].delete(block_id)
        self.store["block_bodies"].delete(block_id)
        from . import chain_index

        chain_index.blocks_changed(self)
        await self.connection.commit()

    async def get_unspent_outputs(self, inputs):
        """Get unspent outputs matching the given (tx_hash, index) pairs."""
        utxos = self.store["unspent_outputs"]
        return {(tx_hash, idx) for tx_hash, idx in inputs if utxos.exists(tx_hash, idx)}

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
                "DELETE FROM pending_transactions WHERE tx_hex LIKE ?", (f"%{pattern}%",)
            )
        await self.connection.commit()

    async def add_unspent_output(self, **kwargs):
        """Add unspent output to database"""
        self.store["unspent_outputs"].put(
            kwargs.get("tx_hash", ""),
            kwargs.get("index", kwargs.get("output_index", 0)),
            kwargs.get("address", ""),
            kwargs.get("amount", 0),
        )
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
        return [{"tx_hash": row[0], "tx_hex": row[1]} for row in rows]

    async def update_pending_transactions_propagation_time(self, tx_hashes: list):
        """Update propagation time for transactions so they are not re-propagated."""
        if not tx_hashes:
            return
        placeholders = ",".join("?" for _ in tx_hashes)
        await self.connection.execute(
            f"UPDATE pending_transactions SET propagation_time = datetime('now') "
            f"WHERE tx_hash IN ({placeholders})",
            tx_hashes,
        )
        await self.connection.commit()

    async def _incremental_root(self, domain: str, height: Optional[int]) -> Optional[str]:
        """The domain's incremental root when the chain spec makes it the rule at ``height``
        (None: the next block's height), else None — the caller then hashes every row."""
        from . import state_commitment

        if height is None:
            height = await self.get_next_block_id()
        if not state_commitment.active(height):
            return None
        return await state_commitment.root(self, domain)

    async def get_unspent_outputs_hash(self, height: Optional[int] = None):
        """Get deterministic hash of unspent outputs for state root computation, under the
        rule of the block at ``height`` (see ``_incremental_root``)."""
        import hashlib

        incremental = await self._incremental_root("utxo", height)
        if incremental is not None:
            return incremental
        rows = self.store["unspent_outputs"].scan()  # (by tx_hash, output_index)
        if not rows:
            return "0" * 64
        hasher = hashlib.sha256()
        for row in rows:
            hasher.update(f"{row[0]}:{row[1]}:{row[2]}:{row[3]}".encode())
        return hasher.hexdigest()

    async def get_account_state_root(self, height: Optional[int] = None) -> str:
        """
        Deterministic BLAKE3-512 root of the account/EVM state (Whitepaper §3.6), under the
        rule of the block at ``height`` (None: the next block).

        With ``incremental_state_root`` in force: one hash of the domain's LtHash accumulator
        (qrdx/state_commitment.py). Before it: every account_state row in a canonical order
        (by address) over its consensus-relevant fields. Empty state → all-zero root either
        way. This is the account-domain component of the unified block state root (Phase D4).
        """
        incremental = await self._incremental_root("account", height)
        if incremental is not None:
            return incremental
        rows = self.store["account_state"].scan()  # (by address)
        # Contract storage is account state too. The root used to hash only the account rows,
        # so two nodes whose contracts held different storage agreed on it.
        storage = self.store["contract_storage"].scan()  # (by contract, key)
        if not rows and not storage:
            return "0" * 128  # BLAKE3-512 width
        import blake3

        hasher = blake3.blake3()
        for r in rows:
            hasher.update(
                f"{r.address}:{r.balance}:{r.nonce}:{r.code_hash or ''}:{r.storage_root or ''}".encode()
            )
        for s in storage:
            hasher.update(f"s:{s.contract_address}:{s.storage_key}:{s.storage_value}".encode())
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
        run did.
        """
        from . import state_commitment

        state_commitment.reset(self, "account")  # (account_state and contract_storage)
        # The EVM's receipts and logs index (rewritten as the replay re-executes each section,
        # so an orphaned block's receipts do not survive).
        for tbl in ("contract_logs", "contract_transactions"):
            try:
                await self.connection.execute(f"DELETE FROM {tbl}")
            except Exception:
                pass
        for tbl in ("evm_balance_sync_registry", "evm_balance_changes"):
            self.store[tbl].clear()
        await self.connection.commit()

    async def apply_account_balance_delta(self, address: str, qrdx_delta) -> bool:
        """
        Phase E: apply a QRDX balance delta (negative = debit) to ``account_state``
        in wei, keyed by the account id. A debit clamps at 0 as a safety net (collateral
        enforcement should already reject an over-debit). Returns True if a row was
        updated/created.

        Does NOT commit — the caller commits atomically with the rest of the block.
        """
        return (await self.apply_account_balance_deltas([(address, qrdx_delta)]))[address]

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

        from .crypto.account_id import to_account_id

        genesis = self.store["blocks"].get(0)
        if genesis is None:
            return 0
        seeded = 0
        accounts = self.store["account_state"]
        for (tx_hex,) in await self.get_block_transactions(genesis.block_hash):
            try:
                d = _json.loads(tx_hex)
            except Exception:
                continue
            if isinstance(d, dict) and d.get("type") == "genesis_contract":
                await self.seed_genesis_contract(d)  # a predeploy (qrdx/predeploys.py)
                seeded += 1
                continue
            # Prefunded accounts and system wallets: both are genesis balances in account_state.
            if d.get("type") not in ("genesis_allocation", "genesis_system_wallet") or not d.get(
                "recipient"
            ):
                continue
            wei = int(_D(str(d["amount"])) * _D(10**18))
            accounts.upsert((to_account_id(d["recipient"]),), {"balance": str(wei)}, ("balance",))
            seeded += 1
        return seeded

    async def seed_genesis_contract(self, record: Dict[str, Any]) -> None:
        """A predeployed contract (a block-0 ``genesis_contract`` record, qrdx/predeploys.py):
        its account (nonce 1, as a deployed contract's), its code and its starting storage —
        the rows the EVM's state writes for a contract it deploys. Leaves a balance or nonce the
        chain has since given it, and a slot it has since written. Does not commit."""
        from eth_utils import keccak

        from .crypto.account_id import to_account_id

        code = bytes.fromhex(str(record["code"]))
        code_hash = keccak(code).hex()
        if code_hash != str(record.get("code_hash", code_hash)):
            raise ValueError(f"genesis contract {record['address']}: code hash mismatch")
        address = to_account_id(str(record["address"]))
        self.store["account_state"].upsert(
            (address,),
            {"balance": "0", "nonce": 1, "code_hash": code_hash, "is_contract": 1},
            ("code_hash", "is_contract"),
        )
        self.store["contract_code"].insert(
            code_hash=code_hash, bytecode=code, deployed_at=0, deployer="genesis", size=len(code)
        )
        storage = self.store["contract_storage"]
        for key, value in sorted(dict(record.get("storage") or {}).items()):
            storage.insert(
                contract_address=address,
                storage_key=str(key),
                storage_value=str(value),
                block_number=0,
            )

    async def apply_token_balance_delta(
        self, token_address: str, holder_address: str, delta
    ) -> bool:
        """
        Phase E (spot): apply a token-balance delta (negative = debit) to the
        ``token_balances`` ledger. Balances are stored as Decimal-string token
        units. The token analog of
        ``apply_account_balance_delta``. Returns True if a row was updated/created.
        Does NOT commit — the caller commits with the block.

        A debit is applied IN FULL even if it takes the balance below zero. It used to clamp
        at 0 while the paired credit landed in full — so any accounting slip minted the
        difference. The exchange refuses an operation whose debit its holder cannot cover
        (``ExchangeStateManager._settle_token_move``), so a negative balance here is a bug:
        it is logged as critical, and supply stays exactly conserved.
        """
        from decimal import Decimal

        if Decimal(str(delta)) == 0:
            return False
        await self.apply_token_balance_deltas([((holder_address, token_address), delta)])
        return True

    # ── batched reads and writes for a block's exchange section (docs/PERFORMANCE.md) ──
    # Each matches its one-row form exactly (the same keys, the same rounding, the same clamps
    # and the same order of application): every node must read and write the same values. A
    # block used to make an await per holder, and per delta, through aiosqlite's worker thread.

    async def get_address_balances(self, addresses) -> Dict[str, "Decimal"]:
        """``get_address_balance`` of each address (any form), keyed by the address as given."""
        from decimal import Decimal

        from .crypto.account_id import to_account_id

        ids: Dict[str, Optional[str]] = {}
        for a in addresses:
            if a in ids:
                continue
            try:
                ids[a] = to_account_id(a)
            except ValueError:
                ids[a] = None  # unkeyable: no account can exist for it
        wanted = sorted({i for i in ids.values() if i})
        found = dict(
            zip(wanted, self.store["account_state"].get_many((i,) for i in wanted), strict=True)
        )
        out: Dict[str, Decimal] = {}
        for a, i in ids.items():
            row = found.get(i) if i else None
            try:
                wei = int(row.balance) if row is not None and row.balance else 0
            except (TypeError, ValueError):
                wei = 0
            out[a] = Decimal(wei) / Decimal(10**18) if wei > 0 else Decimal(0)
        return out

    async def get_token_balances_of(self, pairs) -> Dict[Tuple[str, str], "Decimal"]:
        """``get_token_balance(token, holder)`` of each (token, holder) pair, keyed by the pair
        as given."""
        from decimal import Decimal

        from .crypto.account_id import to_account_id

        keys: Dict[Tuple[str, str], Tuple[str, str]] = {}
        for token, holder in pairs:
            try:
                resolved = to_account_id(holder)
            except ValueError:
                resolved = holder
            keys[(token, holder)] = (token, resolved)
        wanted = sorted(set(keys.values()))
        found = dict(zip(wanted, self.store["token_balances"].get_many(wanted), strict=True))
        return {
            pair: (
                Decimal(found[k].balance)
                if found.get(k) is not None and found[k].balance is not None
                else Decimal("0")
            )
            for pair, k in keys.items()
        }

    async def apply_account_balance_deltas(self, deltas) -> Dict[str, bool]:
        """``apply_account_balance_delta`` of each (address, delta), in order: what each
        returned. One read of the accounts, then the writes together (the store folds them into
        the commitment, journals and marks them as it writes)."""
        from decimal import Decimal

        from .crypto.account_id import to_account_id
        from .store import pack, unpack

        steps = []
        for addr, delta in deltas:
            wei = int(Decimal(str(delta)) * Decimal(10**18))
            steps.append((addr, wei, to_account_id(addr) if wei else None))
        ids = sorted({i for _a, _w, i in steps if i})
        for i in ids:
            for listener in getattr(self, "account_write_listeners", ()):
                listener(i)
        table = self.store["account_state"]
        keys = [pack((i,)) for i in ids]
        values: Dict[str, tuple] = {}
        balance: Dict[str, int] = {}  # id → its balance as the deltas leave it
        for i, raw in zip(ids, table._n.get_many(table.id, keys), strict=True):
            if raw is not None:
                v = unpack(raw)
                values[i] = v
                balance[i] = int(v[0] or 0)
        created: set = set()
        results: Dict[str, bool] = {}
        for addr, wei, maybe_id in steps:
            if not wei or maybe_id is None:
                results[addr] = False
                continue
            i = maybe_id
            if i in balance:
                balance[i] = max(0, balance[i] + wei)  # (a debit clamps at 0)
                results[addr] = True
            elif wei > 0:
                balance[i] = wei
                created.add(i)
                results[addr] = True
            else:
                results[addr] = False  # a debit on an account that does not exist
        writes = []
        for i, k in zip(ids, keys, strict=True):
            if i not in balance:
                continue
            if i in created:
                writes.append((k, pack((str(balance[i]), 0, None, None, 0, 0, 0))))
            else:
                v = values[i]
                writes.append((k, pack((str(balance[i]),) + tuple(v[1:]))))
        table.put_raw(writes)
        return results

    async def apply_token_balance_deltas(self, deltas) -> None:
        """``apply_token_balance_delta`` of each ((holder, token), delta), in order. One read
        of the balances, then the writes together."""
        from decimal import Decimal

        from .crypto.account_id import to_account_id

        steps = []
        for (holder, token), delta in deltas:
            d = Decimal(str(delta))
            if d != 0:
                steps.append((token, to_account_id(holder), d))
        if not steps:
            return
        current = await self.get_token_balances_of({(t, h) for t, h, _d in steps})
        balance = dict(current)
        for token, holder, d in steps:
            cur_bal = balance[(token, holder)]
            new_bal = cur_bal + d
            if new_bal < 0:
                logger.critical(
                    "[TOKEN-OVERDRAFT] %s of token %s debited %s with %s: balance %s",
                    holder,
                    token,
                    -d,
                    cur_bal,
                    new_bal,
                )
            balance[(token, holder)] = new_bal
        touched = list(dict.fromkeys((t, h) for t, h, _d in steps))
        table = self.store["token_balances"]
        for t, h in touched:
            table.put(t, h, str(balance[(t, h)]), 0)

    async def apply_token_registry_op(self, op: dict) -> bool:
        """
        Mirror one native token's registry entry (a deploy, or a block that changed its
        supply or authorities) into ``token_registry``, for queries. The authoritative
        registry is exchange state (qrdx/exchange/tokens.py, in the exchange root); this
        row only reflects it. Does NOT commit — the caller commits with the block.
        """
        created = int(op.get("created_height", 0) or 0)
        self.store["token_registry"].upsert(
            (op["token_address"],),
            {
                "name": op["name"],
                "symbol": op["symbol"],
                "decimals": int(op.get("decimals", 18)),
                "total_supply": str(op["total_supply"]),
                "owner_address": op.get("creator") or op.get("owner_address") or "",
                "is_frozen": 0,
                "created_at": created,
                "updated_at": created,
            },
            ("name", "symbol", "decimals", "total_supply", "owner_address", "updated_at"),
        )
        return True

    async def get_token_balance(self, token_address: str, holder_address: str):
        """Token-units balance for (token, holder); Decimal(0) if no row.

        ``holder_address`` may be any address form — it is resolved to the
        canonical account id the ledger is keyed by.
        """
        return (await self.get_token_balances_of([(token_address, holder_address)]))[
            (token_address, holder_address)
        ]

    async def get_token_balances_root(self, height: Optional[int] = None) -> str:
        """
        Deterministic BLAKE3-512 root of the QRC-20 token ledger (Whitepaper §3.6),
        the token-domain component of the unified block state root (Phase E spot). Under
        ``incremental_state_root`` (at ``height``; None: the next block) it is one hash of the
        domain's LtHash accumulator; before it, the sequential hash below.

        Hashes every non-zero ``token_balances`` row in canonical order
        (token_address, holder_address) over (token, holder, balance). Zero-value
        rows are skipped so a holder that nets to 0 does not change the root.
        Empty ledger → all-zero root. Determinism comes from identical replay of
        the same token deltas on every node (same as ``get_account_state_root``).
        """
        incremental = await self._incremental_root("token", height)
        if incremental is not None:
            return incremental
        from decimal import Decimal

        import blake3

        hasher = blake3.blake3()
        any_row = False
        for r in self.store["token_balances"].scan():  # (by token, holder)
            try:
                if Decimal(r.balance) == 0:
                    continue
            except Exception:
                continue
            any_row = True
            hasher.update(f"{r.token_address}:{r.holder_address}:{r.balance}".encode())
        if not any_row:
            return "0" * 128  # BLAKE3-512 width
        return hasher.digest(length=64).hex()

    async def clear_token_balances(self) -> None:
        """Clear the token ledger (Phase E spot reorg rebuild). Replayed exchange
        sections re-apply the canonical token deltas afterwards. Commits."""
        from . import state_commitment

        state_commitment.reset(self, "token")
        # The registry mirror too: a token deployed on an orphaned branch must not survive
        # the replay (which re-mirrors every canonical deploy).
        self.store["token_registry"].clear()
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

    async def add_contract_log(
        self,
        tx_hash: str,
        block_number: int,
        log_index: int,
        contract_address: str,
        topic0: Optional[str] = None,
        topic1: Optional[str] = None,
        topic2: Optional[str] = None,
        topic3: Optional[str] = None,
        data: Optional[bytes] = None,
    ):
        """Add contract event log"""
        await self.connection.execute(
            """
            INSERT INTO contract_logs
            (tx_hash, block_number, log_index, contract_address, topic0, topic1, topic2, topic3, data, removed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """,
            (
                tx_hash,
                block_number,
                log_index,
                contract_address,
                topic0,
                topic1,
                topic2,
                topic3,
                data,
            ),
        )
        await self.connection.commit()

    async def add_contract_metadata(
        self,
        contract_address: str,
        name: Optional[str] = None,
        symbol: Optional[str] = None,
        verified: bool = False,
        abi: Optional[str] = None,
    ):
        """Add or update contract metadata"""
        await self.connection.execute(
            """
            INSERT OR REPLACE INTO contract_metadata
            (contract_address, name, symbol, verified, abi)
            VALUES (?, ?, ?, ?, ?)
        """,
            (contract_address, name, symbol, verified, abi),
        )
        await self.connection.commit()

    async def get_address_tokens(self, address: str, transfer_topic: str):
        """Get tokens owned by address from Transfer events"""
        # Normalize address to 64-char hex (32 bytes)
        address_topic = "0x" + address.lower().replace("0x", "").zfill(64)

        cursor = await self.connection.execute(
            """
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
        """,
            (transfer_topic, address_topic),
        )

        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_token_info(self, token_address: str, transfer_topic: str):
        """Get token contract information"""
        # Get metadata
        cursor = await self.connection.execute(
            """
            SELECT * FROM contract_metadata WHERE contract_address = ?
        """,
            (token_address,),
        )
        metadata = await cursor.fetchone()

        if not metadata:
            return None

        # Get transfer count
        cursor = await self.connection.execute(
            """
            SELECT COUNT(*) as count FROM contract_logs
            WHERE contract_address = ? AND topic0 = ? AND removed = 0
        """,
            (token_address, transfer_topic),
        )
        transfer_row = await cursor.fetchone()
        transfer_count = transfer_row[0] if transfer_row else 0

        # Get unique holders (distinct topic2 recipients)
        cursor = await self.connection.execute(
            """
            SELECT COUNT(DISTINCT topic2) as count FROM contract_logs
            WHERE contract_address = ? AND topic0 = ? AND removed = 0
        """,
            (token_address, transfer_topic),
        )
        holder_row = await cursor.fetchone()
        holder_count = holder_row[0] if holder_row else 0

        result = dict(metadata)
        result["total_transfers"] = transfer_count
        result["total_holders"] = holder_count
        return result

    async def get_top_addresses_by_balance(self, limit: int, offset: int):
        """Get top addresses by balance (sum of unspent outputs)"""
        totals: Dict[str, List[int]] = {}
        for row in self.store["unspent_outputs"].scan():
            if row.address:
                t = totals.setdefault(row.address, [0, 0])
                t[0] += int(row.amount or 0)
                t[1] += 1
        ranked = sorted(totals.items(), key=lambda kv: -kv[1][0])[offset : offset + limit]
        return [{"address": a, "balance": b, "output_count": n} for a, (b, n) in ranked]

    async def get_top_addresses_by_transactions(self, limit: int, offset: int):
        """Get most active addresses by transaction count (outputs received)"""
        counts: Dict[str, int] = {}
        for row in self.store["unspent_outputs"].scan():
            if row.address:
                counts[row.address] = counts.get(row.address, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: -kv[1])[offset : offset + limit]
        return [{"address": a, "tx_count": n} for a, n in ranked]

    async def get_top_addresses_by_tokens(self, limit: int, offset: int, transfer_topic: str):
        """Get addresses with most token holdings"""
        cursor = await self.connection.execute(
            """
            SELECT
                topic2 as address_topic,
                COUNT(DISTINCT contract_address) as token_count,
                COUNT(*) as transfer_count
            FROM contract_logs
            WHERE topic0 = ? AND removed = 0 AND topic2 IS NOT NULL
            GROUP BY topic2
            ORDER BY token_count DESC
            LIMIT ? OFFSET ?
        """,
            (transfer_topic, limit, offset),
        )

        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_recent_transactions_with_blocks(self, limit: int, offset: int):
        """Get recent transactions with block info (newest block first)"""
        out: List[Dict[str, Any]] = []
        txs = self.store["transactions"]
        for b in self.store["blocks"].scan(reverse=True):
            for t in txs.scan_index("by_block", b.block_hash):
                out.append(
                    {
                        "tx_hash": t.tx_hash,
                        "block_hash": t.block_hash,
                        "block_number": b.block_height,
                        "timestamp": b.timestamp,
                        "fees": t.fees,
                    }
                )
            if len(out) >= offset + limit:
                break
        return out[offset : offset + limit]

    async def get_recent_contract_transactions(self, limit: int, offset: int):
        """Get recent contract transactions"""
        cursor = await self.connection.execute(
            """
            SELECT tx_hash, block_number, from_address, to_address, value, gas_used, status
            FROM contract_transactions
            ORDER BY block_number DESC
            LIMIT ? OFFSET ?
        """,
            (limit, offset),
        )
        out = []
        blocks = self.store["blocks"]
        for row in await cursor.fetchall():
            d = dict(row)
            b = blocks.get(d["block_number"]) if d.get("block_number") is not None else None
            d["timestamp"] = b.timestamp if b is not None else None
            out.append(d)
        return out

    async def get_recent_blocks_with_validators(self, limit: int, offset: int):
        """Get recent blocks with validator information"""
        txs = self.store["transactions"]
        out = []
        for b in self.store["blocks"].scan(reverse=True, limit=offset + limit)[offset:]:
            out.append(
                {
                    "id": b.block_height,
                    "hash": b.block_hash,
                    "address": b.validator_address,
                    "proposer_address": b.validator_address,
                    "timestamp": b.timestamp,
                    "tx_count": len(txs.scan_index("by_block", b.block_hash)),
                    "slot": None,
                    "epoch": None,
                    "attestations_included": 0,
                    "reward": 0,
                }
            )
        return out

    async def get_validator_info(self, validator_address: str):
        """Get validator information"""
        cursor = await self.connection.execute(
            """
            SELECT address, stake, effective_stake, status
            FROM validators
            WHERE address = ?
        """,
            (validator_address,),
        )

        row = await cursor.fetchone()
        return dict(row) if row else None

    async def add_block_exchange_txs(self, block_hash: str, items: list, objects=None):
        """
        Persist a block's exchange-transaction section (Phase D2.2b).

        ``items`` is the encoded list (each an ``ExchangeTransaction.to_dict()``)
        in the proposer's canonical order. Idempotent per block. Stored as
        protocol-level state (Whitepaper §3.6) for deterministic replay during
        block import (D3), in the store, whole: one value a block (it was a row an
        item). ``objects``: the same operations decoded, if the caller holds them
        (kept for ``recent_exchange_section``).
        """
        if not items:
            return
        self._remember_section(block_hash, items, objects)
        # (read back only by get_block_exchange_txs, as JSON: orjson writes it several times
        # faster, and a block of 1,000 operations is ~11 MB of signatures and keys)
        from .fastjson import dumps
        from .fee_market import note_exchange_section

        # (its children's base fee reads the gas it declared: noted now, not parsed back — from
        # the operations themselves when the caller holds them, not each item's bytes again)
        whole = objects is not None and len(objects) == len(items)
        note_exchange_section(self, block_hash, objects if whole else items)
        sections = self.store["exchange_sections"]
        if not sections.exists(block_hash):
            sections.put(block_hash, dumps(list(items)).encode())
        await self.connection.commit()

    # The sections of the last blocks stored, and their operations decoded where the caller held
    # them: the transaction index (qrdx/tx_index.py) read each back and parsed it — a megabyte a
    # block at load — holding the block-processing lock.
    RECENT_SECTIONS = 16

    def _remember_section(self, block_hash: str, items: list, objects) -> None:
        recent = self.__dict__.setdefault("_recent_sections", OrderedDict())
        if objects is not None and len(objects) != len(items):
            objects = None
        recent[block_hash] = (items, None if objects is None else list(objects))
        recent.move_to_end(block_hash)
        while len(recent) > self.RECENT_SECTIONS:
            recent.popitem(last=False)

    def recent_exchange_section(self, block_hash: str):
        """(the section as stored, its operations decoded or None) of one of the last blocks
        stored by this process; None for any other. For reading only."""
        return self.__dict__.get("_recent_sections", {}).get(block_hash)

    async def get_block_exchange_txs(self, block_hash: str) -> list:
        """Return a block's exchange-transaction section in canonical order."""
        from .fastjson import loads

        row = self.store["exchange_sections"].get(block_hash)
        return [] if row is None else list(loads(row.data))

    async def add_block_evm_txs(self, block_hash: str, raw_txs: list):
        """
        Persist a block's EVM-transaction section (E-D3): the ordered list of raw
        signed eth txs included in the block, for deterministic replay on import
        and rebuild. Idempotent per block.
        """
        if not raw_txs:
            return
        from .fastjson import dumps

        sections = self.store["evm_sections"]
        if not sections.exists(block_hash):
            sections.put(block_hash, dumps([str(raw) for raw in raw_txs]).encode())
        await self.connection.commit()

    async def get_block_evm_txs(self, block_hash: str) -> list:
        """Return a block's EVM-transaction section (raw hex) in canonical order."""
        from .fastjson import loads

        row = self.store["evm_sections"].get(block_hash)
        return [] if row is None else list(loads(row.data))

    # ── Finality: attestation votes (link 2) ────────────────────────────

    async def record_attestation_vote(
        self,
        validator_address: str,
        target_epoch: int,
        source_epoch: int,
        slot: int,
        block_hash: str,
        epoch: int = 0,
        validator_index: int = 0,
        signature: str = "",
        source_root: str = "",
        target_root: str = "",
    ) -> None:
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
            "epoch, validator_index, signature, source_root, target_root) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                validator_address,
                int(target_epoch),
                int(source_epoch),
                int(slot),
                block_hash,
                int(epoch),
                int(validator_index),
                str(signature),
                str(source_root or ""),
                str(target_root or ""),
            ),
        )
        await self.connection.commit()

    async def prune_attestation_votes(self, below_target_epoch: int) -> int:
        """Drop retained votes for target epochs below ``below_target_epoch`` (ffg.update, as
        finality advances). Returns the rows removed."""
        if below_target_epoch <= 0:
            return 0
        cur = await self.connection.execute(
            "DELETE FROM attestation_votes WHERE target_epoch < ?", (int(below_target_epoch),)
        )
        return cur.rowcount or 0

    async def get_validator_votes(self, validator_address: str, limit: int = 128) -> list:
        """The validator's retained attestation votes as fully-signed Attestation dicts
        (most recent target first), for surround/double-vote slashing detection. Only rows
        with a retained ``signature`` are returned (pre-retention rows can't form a proof).
        Bounded by ``limit`` — surround votes span a small epoch window in practice."""
        cur = await self.connection.execute(
            "SELECT slot, epoch, block_hash, validator_index, signature, source_epoch, target_epoch, "
            "source_root, target_root "
            "FROM attestation_votes WHERE validator_address = ? AND signature != '' "
            "ORDER BY target_epoch DESC LIMIT ?",
            (validator_address, int(limit)),
        )
        rows = await cur.fetchall()
        return [
            {
                "slot": s,
                "epoch": e,
                "block_hash": bh,
                "validator_address": validator_address,
                "validator_index": vi,
                "signature": sig,
                "source_epoch": se,
                "target_epoch": te,
                "source_root": sr,
                "target_root": tr,
            }
            for (s, e, bh, vi, sig, se, te, sr, tr) in rows
        ]

    # ── Slashing evidence (consensus security) ──────────────────────────

    async def record_slashing_event(
        self, validator_address: str, condition: str, slot: int, epoch: int, evidence: str
    ) -> bool:
        """Persist a detected slashable offence (idempotent on
        (validator, slot, condition)). Returns True if it was NEW. Commits."""
        cur = await self.connection.execute(
            "INSERT OR IGNORE INTO slashing_events "
            "(validator_address, condition, slot, epoch, evidence) VALUES (?, ?, ?, ?, ?)",
            (validator_address, str(condition), int(slot), int(epoch), str(evidence)),
        )
        await self.connection.commit()
        return bool(cur.rowcount)

    async def get_slashing_events(self, validator_address: Optional[str] = None) -> list:
        """Return recorded slashing evidence rows (optionally for one validator)."""
        if validator_address:
            cur = await self.connection.execute(
                "SELECT validator_address, condition, slot, epoch, evidence, processed "
                "FROM slashing_events WHERE validator_address = ? ORDER BY slot",
                (validator_address,),
            )
        else:
            cur = await self.connection.execute(
                "SELECT validator_address, condition, slot, epoch, evidence, processed "
                "FROM slashing_events ORDER BY slot"
            )
        rows = await cur.fetchall()
        return [
            {
                "validator_address": r[0],
                "condition": r[1],
                "slot": r[2],
                "epoch": r[3],
                "evidence": r[4],
                "processed": bool(r[5]),
            }
            for r in rows
        ]

    async def get_pending_slashing_evidence(self, limit: int = 16) -> list:
        """The full self-validating PROOFS for unprocessed slashing events, for a proposer to
        include in the block body so they propagate to every node. Returns the parsed evidence
        dicts (the two signed headers). Bounded by ``limit`` to keep block size sane; a proof
        keeps riding blocks until the finalized-epoch penalty marks it processed (deduped by
        every importer via INSERT OR IGNORE)."""
        import json as _json

        cur = await self.connection.execute(
            "SELECT evidence FROM slashing_events WHERE processed = 0 "
            "ORDER BY validator_address, slot LIMIT ?",
            (int(limit),),
        )
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

    async def get_epoch_attesters(self, target_epoch: int) -> list:
        """Return the validator addresses that have voted for ``target_epoch``."""
        cursor = await self.connection.execute(
            "SELECT validator_address FROM attestation_votes WHERE target_epoch = ?",
            (int(target_epoch),),
        )
        rows = await cursor.fetchall()
        return [r[0] for r in rows]

    async def set_epoch_finality(
        self, epoch: int, start_slot: int, end_slot: int, justified: bool, finalized: bool
    ) -> None:
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
            (
                int(epoch),
                int(start_slot),
                int(end_slot),
                1 if justified else 0,
                1 if finalized else 0,
            ),
        )
        await self.connection.commit()

    async def get_validators(self, status: Optional[str] = None):
        """
        Return the validator set, ordered by effective stake (descending).

        Args:
            status: Optional status filter (e.g. 'active'). None returns all.

        Returns:
            List of validator dicts.
        """
        if status:
            cursor = await self.connection.execute(
                """
                SELECT address, public_key, stake, effective_stake,
                       status, activation_epoch, exit_epoch, slashed
                FROM validators
                WHERE status = ?
                ORDER BY CAST(effective_stake AS REAL) DESC
            """,
                (status,),
            )
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
            entry["slashed"] = bool(entry.get("slashed"))
            validators.append(entry)
        return validators

    async def log_validator_deposit(
        self, address: str, public_key: str, stake, block_height: int, block_hash=None
    ) -> None:
        """Log an executed STAKE_DEPOSIT against its carrying block (the validator set's input:
        qrdx/validator/epoch_state.py). Reversed by ``undo_validator_deposits_above``. No
        commit."""
        from decimal import Decimal

        self.store["validator_deposits"].put(
            block_height=int(block_height),
            id=self.store.next_id("validator_deposits"),
            block_hash=block_hash,
            address=address,
            public_key=public_key,
            stake=str(Decimal(str(stake))),
            created_new=0,
            created_at=_now(),
            address_lc=str(address).lower(),
        )

    async def log_staking_op(
        self, kind: str, sender: str, validator, value, block_height: int
    ) -> None:
        """Log an executed delegation operation against its carrying block (the pools' input:
        qrdx/validator/epoch_state.py). Dropped by ``undo_validator_deposits_above``. No
        commit."""
        self.store["staking_ops"].put(
            int(block_height),
            self.store.next_id("staking_ops"),
            kind,
            sender,
            validator,
            None if value is None else str(value),
        )

    async def log_staker_fee_income(self, block_height: int, amount) -> None:
        """Record the stakers' fee income block ``block_height`` took in. The row is the block's
        own: written (or, for nothing, removed) by every path that applies the block, so a rebuild
        writes the same and an orphaned block's row never outlives it. No commit."""
        if amount and amount > 0:
            self.store["staker_fee_income"].put(int(block_height), str(amount))
        else:
            self.store["staker_fee_income"].delete(int(block_height))

    async def undo_validator_deposits_above(self, tip_height: int) -> dict:
        """Drop the deposit log of every block above ``tip_height`` (after a rollback). The
        validator set is computed from the chain and these logs (validator/epoch_state.py),
        so nothing else needs reversing. Does NOT commit. Returns ``{"reversed": n}``."""
        above = {"lo": (int(tip_height) + 1,), "hi": (2**62,)}
        n = self.store["validator_deposits"].delete_prefix(**above)
        n += self.store["staking_ops"].delete_prefix(**above)
        self.store["staker_fee_income"].delete_prefix(**above)
        from . import state_proofs

        await state_proofs.undo_above(self, tip_height)  # orphaned heights' proof roots
        return {"reversed": n}

    async def get_genesis_validators(self) -> list:
        """The GENESIS validator set as [{address, public_key, stake}] for the reconstruction
        reset, in canonical address order.

        Read from the immutable record genesis initialisation writes (chain_metadata
        'genesis_validators'). It used to be read from the live table (``activation_epoch = 0``
        rows) on every reset — but ``register_pending_validator`` tops up ANY existing row, so
        a genesis validator that added stake had that deposit baked into its "genesis" base and
        re-applied on top at every rebuild: its stake grew each finalized epoch, by a different
        amount on each node. A database from before the record existed derives the set from
        the table once and records it."""
        import json

        recorded = self.get_metadata("genesis_validators")
        if recorded is not None:
            return json.loads(recorded)
        cur = await self.connection.execute(
            "SELECT address, public_key, stake FROM validators WHERE activation_epoch = 0 "
            "ORDER BY address ASC"
        )
        base = [{"address": r[0], "public_key": r[1], "stake": r[2]} for r in await cur.fetchall()]
        await self.record_genesis_validators(base)
        return base

    async def record_genesis_validators(self, validators: list) -> None:
        """Record the genesis validator set once (see get_genesis_validators). Never overwrites."""
        import json

        base = sorted(
            (
                {"address": v["address"], "public_key": v["public_key"], "stake": str(v["stake"])}
                for v in validators
            ),
            key=lambda v: v["address"],
        )
        if self.get_metadata("genesis_validators") is None:
            self.set_metadata("genesis_validators", json.dumps(base, sort_keys=True))

    async def get_attestations_filtered(self, filters: dict, limit: int, offset: int):
        """Get attestations with filters"""
        where_clauses = []
        params = []

        if "slot" in filters and filters["slot"] is not None:
            where_clauses.append("slot = ?")
            params.append(filters["slot"])

        if "epoch" in filters and filters["epoch"] is not None:
            where_clauses.append("epoch = ?")
            params.append(filters["epoch"])

        if "validator_address" in filters and filters["validator_address"]:
            where_clauses.append("validator_address = ?")
            params.append(filters["validator_address"])

        if "block_hash" in filters and filters["block_hash"]:
            where_clauses.append("block_hash = ?")
            params.append(filters["block_hash"])

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
        placeholders = ",".join("?" * len(hashes))
        cursor = await self.connection.execute(
            f"SELECT * FROM pending_transactions WHERE tx_hash IN ({placeholders})", hashes
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_block_by_id(self, block_id: int):
        """Get block by ID"""
        row = self.store["blocks"].get(int(block_id))
        return await self._with_body(row) if row is not None else None

    async def get_block_header(self, block_id: int) -> Optional[Dict[str, Any]]:
        """A block's row without its body (``content`` is ~45 KB of signatures): for callers
        that need only the hash, parent, proposer or timestamp. Same keys as get_block_by_id
        otherwise."""
        return _block_dict(self.store["blocks"].get(int(block_id)), with_body=False)

    async def get_block_hashes(self, start: int, end: int) -> Dict[int, str]:
        """{height: block hash} for start..end inclusive, without bodies."""
        if int(end) < int(start):
            return {}
        rows = self.store["blocks"].scan(lo=(int(start),), hi=(int(end) + 1,))
        return {int(r.block_height): r.block_hash for r in rows}

    async def get_block(self, block_hash: str):
        """Get block by hash"""
        rows = self.store["blocks"].scan_index("by_hash", block_hash, limit=1)
        return await self._with_body(rows[0]) if rows else None

    async def get_last_block(self):
        """Get latest block"""
        return await self.get_latest_block()

    async def get_block_transactions(self, block_hash: str, hex_only: bool = False):
        """Get transactions in a block (in the order stored)"""
        rows = self.store["transactions"].scan_index("by_block", block_hash)
        if hex_only:
            return [r.tx_hex for r in rows]
        return [(r.tx_hex,) for r in rows]

    async def get_block_nice_transactions(self, block_hash: str):
        """Get formatted transactions in a block"""
        return await self.get_block_transactions(block_hash, hex_only=True)

    async def remove_blocks(self, start_id: int):
        """Remove blocks starting from ID (rollback / reorg)."""
        # Drop exchange/EVM sections for blocks no longer on the canonical chain
        # so no stale protocol-level state lingers after a reorg rollback.
        blocks = self.store["blocks"]
        for row in blocks.scan(lo=(int(start_id),), hi=(2**62,)):
            self.store["exchange_sections"].delete(row.block_hash)
            self.store["evm_sections"].delete(row.block_hash)
        blocks.delete_prefix(lo=(int(start_id),), hi=(2**62,))
        self.store["block_bodies"].delete_prefix(lo=(int(start_id),), hi=(2**62,))
        from . import chain_index

        chain_index.blocks_changed(self)
        # The removed blocks' EVM receipts and indexed transactions are no longer canonical:
        # a re-applied block writes its own (an orphaned transaction must not keep a receipt).
        await self.connection.execute(
            "DELETE FROM contract_logs WHERE block_number >= ?", (start_id,)
        )
        await self.connection.execute(
            "DELETE FROM contract_transactions WHERE block_number >= ?", (start_id,)
        )
        await self._tx_index_cut(start_id)
        await self._hist_cut(start_id)
        await self.connection.commit()

    # ── trading history (qrdx/trading_history.py) ────────────────────────

    _HIST_TABLES = (
        "hist_trades",
        "hist_trade_accounts",
        "hist_orders",
        "hist_funding",
        "hist_samples",
    )

    async def _hist_cut(self, height: int) -> None:
        for table in self._HIST_TABLES:
            await self.connection.execute(
                f"DELETE FROM {table} WHERE block_height >= ?", (int(height),)
            )

    async def hist_cut(self, height: int) -> None:
        """Forget the trading history at or above ``height``."""
        await self._hist_cut(height)
        await self.connection.commit()

    async def hist_write_block(self, height: int, block: dict) -> None:
        """Replace a height's trading history with ``block``'s rows (the journal's outbox
        entry: ``time``, ``trades``, ``orders``, ``funding``, ``samples``)."""
        from .trading_history import trade_accounts
        from .tx_index import account_key

        height, when = int(height), block.get("time")
        for table in self._HIST_TABLES:
            await self.connection.execute(f"DELETE FROM {table} WHERE block_height = ?", (height,))
        trade_cols = (
            "market",
            "venue",
            "kind",
            "price",
            "amount",
            "side",
            "buyer",
            "seller",
            "maker",
            "taker",
            "maker_order_id",
            "taker_order_id",
            "tx_hash",
            "pool_id",
        )
        trades, accounts = [], []
        for pos, t in enumerate(block.get("trades") or []):
            trades.append(
                (height, pos, when)
                + tuple(None if t.get(c) is None else str(t.get(c)) for c in trade_cols)
                + (json.dumps(t.get("fees") or {}), json.dumps(t.get("realized") or {}))
            )
            for a in trade_accounts(t):
                accounts.append(
                    (a["account"], height, pos, when, t.get("venue"), a["role"], a["side"])
                    + tuple(
                        None if a[k] is None else str(a[k]) for k in ("notional", "fee", "realized")
                    )
                )
        await self.connection.executemany(
            f"INSERT INTO hist_trades (block_height, position, block_time, {', '.join(trade_cols)},"
            f" fees, realized) VALUES ({', '.join('?' * (len(trade_cols) + 5))})",
            trades,
        )
        await self.connection.executemany(
            "INSERT OR REPLACE INTO hist_trade_accounts (account, block_height, position, "
            "block_time, venue, role, side, notional, fee, realized) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            accounts,
        )
        await self.connection.executemany(
            "INSERT INTO hist_orders (block_height, position, block_time, account, market, "
            "order_id, event, tx_hash, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    height,
                    pos,
                    when,
                    account_key(o.get("account")),
                    o.get("market"),
                    None if o.get("order_id") is None else str(o["order_id"]),
                    o.get("event"),
                    o.get("tx_hash"),
                    json.dumps(o.get("detail") or {}, default=str),
                )
                for pos, o in enumerate(block.get("orders") or [])
            ],
        )
        await self.connection.executemany(
            "INSERT INTO hist_funding (block_height, position, block_time, market, rate, premium,"
            " oracle_price, open_interest, funding_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (height, pos, when)
                + tuple(
                    f.get(k)
                    for k in (
                        "market",
                        "rate",
                        "premium",
                        "oracle_price",
                        "open_interest",
                        "funding_time",
                    )
                )
                for pos, f in enumerate(block.get("funding") or [])
            ],
        )
        await self.connection.executemany(
            "INSERT INTO hist_samples (block_height, position, block_time, market, mark, oracle,"
            " open_interest, funding_rate) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (height, pos, when)
                + tuple(
                    x.get(k) for k in ("market", "mark", "oracle", "open_interest", "funding_rate")
                )
                for pos, x in enumerate(block.get("samples") or [])
            ],
        )
        await self.connection.commit()

    async def _hist_rows(self, sql: str, params: tuple) -> list:
        cursor = await self.connection.execute(sql, params)
        names = [d[0] for d in cursor.description]
        return [dict(zip(names, tuple(r), strict=False)) for r in await cursor.fetchall()]

    @staticmethod
    def _hist_before(before, alias: str = "") -> tuple:
        if before is None:
            return "", ()
        a = f"{alias}." if alias else ""
        return (
            f" AND ({a}block_height < ? OR ({a}block_height = ? AND {a}position < ?))",
            (int(before[0]), int(before[0]), int(before[1])),
        )

    async def hist_trades(self, *, account=None, market=None, before=None, limit=100) -> list:
        where, params = "1=1", []
        if account is not None:
            sql = (
                "SELECT t.*, a.role AS role, a.side AS account_side, a.fee AS fee, "
                "a.realized AS account_realized FROM hist_trade_accounts a JOIN hist_trades t "
                "ON t.block_height = a.block_height AND t.position = a.position "
                "WHERE a.account = ?"
            )
            params.append(account)
            alias = "a"
        else:
            sql, alias = f"SELECT t.* FROM hist_trades t WHERE {where}", "t"
        if market is not None:
            sql += " AND t.market = ?"
            params.append(market)
        extra, more = self._hist_before(before, alias)
        sql += extra + f" ORDER BY {alias}.block_height DESC, {alias}.position DESC LIMIT ?"
        return await self._hist_rows(sql, tuple(params) + more + (int(limit),))

    async def hist_orders(
        self, *, account=None, market=None, order_id=None, before=None, limit=100
    ) -> list:
        sql, params = "SELECT * FROM hist_orders WHERE 1=1", []
        for column, value in (("account", account), ("market", market), ("order_id", order_id)):
            if value is not None:
                sql += f" AND {column} = ?"
                params.append(value)
        extra, more = self._hist_before(before)
        sql += extra + " ORDER BY block_height DESC, position DESC LIMIT ?"
        return await self._hist_rows(sql, tuple(params) + more + (int(limit),))

    async def hist_funding(self, market: str, *, before=None, limit=100) -> list:
        extra, more = self._hist_before(before)
        return await self._hist_rows(
            "SELECT * FROM hist_funding WHERE market = ?"
            + extra
            + " ORDER BY block_height DESC, position DESC LIMIT ?",
            (market,) + more + (int(limit),),
        )

    async def hist_samples(self, market: str, *, since=None, until=None, limit=500) -> list:
        sql = "SELECT * FROM hist_samples WHERE market = ?"
        params: list = [market]
        if since is not None:
            sql += " AND block_time >= ?"
            params.append(float(since))
        if until is not None:
            sql += " AND block_time <= ?"
            params.append(float(until))
        sql += " ORDER BY block_time ASC, block_height ASC LIMIT ?"
        return await self._hist_rows(sql, tuple(params) + (int(limit),))

    async def hist_latest_time(self):
        cursor = await self.connection.execute("SELECT MAX(block_time) FROM hist_trade_accounts")
        row = await cursor.fetchone()
        return None if row is None else row[0]

    async def hist_leaderboard(self, *, since=None, metric="pnl", limit=50) -> list:
        """Perps accounts by realized PnL less fees, or by volume (floats: a ranking)."""
        order = "pnl" if metric == "pnl" else "volume"
        sql = (
            "SELECT account, SUM(CAST(COALESCE(realized, '0') AS REAL)) - "
            "SUM(CAST(COALESCE(fee, '0') AS REAL)) AS pnl, "
            "SUM(CAST(COALESCE(notional, '0') AS REAL)) AS volume, COUNT(*) AS trades "
            "FROM hist_trade_accounts WHERE venue = 'perp'"
        )
        params: list = []
        if since is not None:
            sql += " AND block_time >= ?"
            params.append(float(since))
        sql += f" GROUP BY account ORDER BY {order} DESC, account ASC LIMIT ?"
        return await self._hist_rows(sql, tuple(params) + (int(limit),))

    # ── transaction index (qrdx/tx_index.py) ─────────────────────────────

    async def _tx_index_cut(self, height: int) -> None:
        for table in ("tx_participants", "tx_index", "tx_index_blocks"):
            await self.connection.execute(
                f"DELETE FROM {table} WHERE block_height >= ?", (int(height),)
            )

    async def tx_index_cut(self, height: int) -> None:
        """Forget every indexed block at or above ``height``."""
        await self._tx_index_cut(height)
        await self.connection.commit()

    async def tx_index_blocks_from(self, height: int) -> list:
        """``[(height, block_hash)]`` of the indexed blocks at or above ``height``."""
        cursor = await self.connection.execute(
            "SELECT block_height, block_hash FROM tx_index_blocks WHERE block_height >= ? "
            "ORDER BY block_height",
            (int(height),),
        )
        return [(int(r[0]), r[1]) for r in await cursor.fetchall()]

    async def tx_index_head(self) -> int:
        """The highest indexed block height (-1 when nothing is indexed)."""
        cursor = await self.connection.execute("SELECT MAX(block_height) FROM tx_index_blocks")
        row = await cursor.fetchone()
        return -1 if row is None or row[0] is None else int(row[0])

    async def tx_index_write_block(
        self, height: int, block_hash: str, rows: list, participants: list
    ) -> None:
        """Replace a height's indexed transactions. ``rows``: dicts with the tx_index columns;
        ``participants``: ``(account, position, roles)``."""
        await self._tx_index_cut_one(height)
        cols = (
            "block_height",
            "position",
            "tx_hash",
            "block_hash",
            "timestamp",
            "kind",
            "op",
            "sender",
            "target",
            "asset",
            "amount",
            "status",
            "fee",
            "error",
            "detail",
        )
        await self.connection.executemany(
            f"INSERT INTO tx_index ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            [
                tuple(
                    [int(height), r["position"], r["tx_hash"], block_hash]
                    + [r.get(c) for c in cols[4:]]
                )
                for r in rows
            ],
        )
        await self.connection.executemany(
            "INSERT OR REPLACE INTO tx_participants (account, block_height, position, roles) "
            "VALUES (?, ?, ?, ?)",
            [(a, int(height), pos, roles) for a, pos, roles in participants],
        )
        await self.connection.execute(
            "INSERT OR REPLACE INTO tx_index_blocks (block_height, block_hash) VALUES (?, ?)",
            (int(height), block_hash),
        )
        await self.connection.commit()

    async def _tx_index_cut_one(self, height: int) -> None:
        for table in ("tx_participants", "tx_index", "tx_index_blocks"):
            await self.connection.execute(
                f"DELETE FROM {table} WHERE block_height = ?", (int(height),)
            )

    _TX_INDEX_COLS = (
        "i.block_height, i.position, i.tx_hash, i.block_hash, i.timestamp, i.kind, "
        "i.op, i.sender, i.target, i.asset, i.amount, i.status, i.fee, i.error, "
        "i.detail"
    )

    @staticmethod
    def _tx_index_row(row) -> dict:
        keys = (
            "block_height",
            "position",
            "tx_hash",
            "block_hash",
            "timestamp",
            "kind",
            "op",
            "sender",
            "target",
            "asset",
            "amount",
            "status",
            "fee",
            "error",
            "detail",
        )
        out = dict(zip(keys, tuple(row)[: len(keys)], strict=False))
        if len(tuple(row)) > len(keys):
            out["roles"] = tuple(row)[len(keys)]
        return out

    @staticmethod
    def _tx_index_filters(before, kinds, alias="i"):
        sql, args = "", []
        if before is not None:
            h, pos = before
            sql += (
                f" AND ({alias}.block_height < ? OR ({alias}.block_height = ? "
                f"AND {alias}.position < ?))"
            )
            args += [int(h), int(h), int(pos)]
        if kinds:
            sql += f" AND i.kind IN ({', '.join('?' * len(kinds))})"
            args += list(kinds)
        return sql, args

    async def get_account_history(
        self, account: str, limit: int = 50, before=None, kinds=None
    ) -> list:
        """An account's indexed transactions, newest first; ``before`` = (height, position)
        continues a previous page."""
        where, args = self._tx_index_filters(before, kinds, alias="p")
        cursor = await self.connection.execute(
            f"SELECT {self._TX_INDEX_COLS}, p.roles FROM tx_participants p "
            f"JOIN tx_index i ON i.block_height = p.block_height AND i.position = p.position "
            f"WHERE p.account = ?{where} "
            f"ORDER BY p.block_height DESC, p.position DESC LIMIT ?",
            [account] + args + [int(limit)],
        )
        return [self._tx_index_row(r) for r in await cursor.fetchall()]

    async def get_indexed_transactions(self, limit: int = 50, before=None, kinds=None) -> list:
        """The chain's indexed transactions, newest first."""
        where, args = self._tx_index_filters(before, kinds)
        cursor = await self.connection.execute(
            f"SELECT {self._TX_INDEX_COLS} FROM tx_index i WHERE 1 = 1{where} "
            f"ORDER BY i.block_height DESC, i.position DESC LIMIT ?",
            args + [int(limit)],
        )
        return [self._tx_index_row(r) for r in await cursor.fetchall()]

    async def get_indexed_transaction(self, tx_hash: str) -> list:
        """Every indexed occurrence of a transaction hash (normally one), with its accounts."""
        h = str(tx_hash).lower()
        cursor = await self.connection.execute(
            f"SELECT {self._TX_INDEX_COLS} FROM tx_index i WHERE i.tx_hash IN (?, ?)",
            (h.removeprefix("0x"), "0x" + h.removeprefix("0x")),
        )
        out = []
        for r in await cursor.fetchall():
            row = self._tx_index_row(r)
            parts = await self.connection.execute(
                "SELECT account, roles FROM tx_participants WHERE block_height = ? AND "
                "position = ? ORDER BY account",
                (row["block_height"], row["position"]),
            )
            row["accounts"] = {part[0]: part[1] for part in await parts.fetchall()}
            out.append(row)
        return out

    async def get_pending_transactions_limit(self, limit: int):
        """Get limited pending transactions"""
        cursor = await self.connection.execute(
            "SELECT tx_hex FROM pending_transactions LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [row[0] for row in rows]

    async def get_nice_transaction(self, tx_hash: str, address: Optional[str] = None):
        """Get formatted transaction"""
        row = self.store["transactions"].get(tx_hash)
        if row is None:
            return None
        out = row._asdict()
        out.pop("seq", None)
        return out

    async def remove_pending_transaction(self, tx_hash: str):
        """Remove pending transaction"""
        await self.connection.execute(
            "DELETE FROM pending_transactions WHERE tx_hash = ?", (tx_hash,)
        )
        await self.connection.commit()

    async def get_blocks(self, offset: int, limit: int):
        """Get blocks starting from a given height, ascending.

        'offset' is treated as a starting block_height (inclusive) so
        that the sync protocol can request ``get_blocks(start_height, count)``.
        """
        rows = self.store["blocks"].scan(lo=(int(offset),), hi=(2**62,), limit=int(limit))
        return [await self._with_body(r) for r in rows]

    async def get_spendable_outputs(self, address: str):
        """Get spendable outputs for address"""

        class Output:
            def __init__(self, address, amount, tx_hash, index):
                self.address = address
                self.amount = amount / 1000000  # Convert from microQRDX to QRDX
                self.tx_hash = tx_hash
                self.index = index

        return [
            Output(address, row.amount, row.tx_hash, row.output_index)
            for row in self.store["unspent_outputs"].scan()
            if row.address == address
        ]

    async def get_address_balance(self, address: str, check_pending_txs: bool = False) -> "Decimal":
        """Get total balance for an address.

        Accepts ANY address form — ``0x…``, ``0xPQ…``, ``0xPQMS…``, legacy — and
        resolves it to the canonical 20-byte account id, which is the key
        ``account_state`` is stored under. A PQ holder and the 20-byte form of the
        same account therefore read the SAME balance (see
        ``qrdx.crypto.account_id``).

        Reads ``account_state``, the one ledger. (It used to fall back to the legacy UTXO
        table, which nothing writes: the fallback once hid a value-creation bug, and the last
        writer was the refused proof-of-work path — docs/KNOWN_ISSUES.md.)
        Returns balance in QRDX (not micro-QRDX, not wei).
        """
        return (await self.get_address_balances([address]))[address]

    async def get_address_transactions(
        self, address: str, limit: int = 100, offset: int = 0, check_signatures: bool = False
    ):
        """Get transactions for address from the transactions table (newest first)."""
        rows = [
            r
            for r in self.store["transactions"].scan()
            if address in (r.inputs_addresses or "") or address in (r.outputs_addresses or "")
        ]
        rows.sort(key=lambda r: (r.created_at or "", r.seq), reverse=True)
        out = []
        for r in rows[offset : offset + limit]:
            d = r._asdict()
            d.pop("seq", None)
            out.append(d)
        return out

    async def get_address_pending_transactions(self, address: str, hex_only: bool = False):
        """Get pending transactions for address from the mempool."""
        cursor = await self.connection.execute(
            """
            SELECT tx_hash, tx_hex, inputs_addresses, fees, time_received
            FROM pending_transactions
            WHERE inputs_addresses LIKE ?
            ORDER BY time_received DESC
        """,
            (f"%{address}%",),
        )
        rows = await cursor.fetchall()
        if hex_only:
            return [row[1] for row in rows]
        return [dict(row) for row in rows]

    async def get_address_pending_spent_outputs(self, address: str):
        """Get pending spent outputs for address."""
        cursor = await self.connection.execute(
            "SELECT tx_hash, output_index FROM pending_spent_outputs"
        )
        utxos = self.store["unspent_outputs"]
        out = []
        for tx_hash, index in await cursor.fetchall():
            row = utxos.get(tx_hash, index)
            if row is not None and row.address == address:
                out.append((tx_hash, index))
        return out

    async def add_peer(self, peer_url: str):
        """Add or update peer"""
        await self.connection.execute(
            """
            INSERT OR REPLACE INTO peers (node_url, last_seen, reputation)
            VALUES (?, CURRENT_TIMESTAMP, COALESCE((SELECT reputation FROM peers WHERE node_url = ?), 0))
        """,
            (peer_url, peer_url),
        )
        await self.connection.commit()
        return True

    async def get_peers(self, limit: int = 100):
        """Get list of peers"""
        cursor = await self.connection.execute(
            "SELECT node_url, reputation, last_seen FROM peers ORDER BY reputation DESC, last_seen DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [{"url": row[0], "reputation": row[1], "last_seen": row[2]} for row in rows]
