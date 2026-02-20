"""
Contract State Manager

Manages contract accounts, storage, and state trie for EVM execution.
Ethereum-compatible state management for QRDX blockchain.
"""

from typing import Optional, Dict, List, Tuple, Any
from decimal import Decimal
from eth_utils import keccak, to_checksum_address
import rlp
from dataclasses import dataclass, field


@dataclass
class Account:
    """
    Ethereum-style account (EOA or contract).
    
    Attributes:
        address: Account address
        balance: Account balance (smallest unit)
        nonce: Transaction nonce
        code_hash: Hash of contract code (None for EOA)
        storage_root: Root of storage trie (None for EOA)
    """
    address: str
    balance: int = 0
    nonce: int = 0
    code_hash: Optional[bytes] = None
    storage_root: Optional[bytes] = None
    
    @property
    def is_contract(self) -> bool:
        """Check if this is a contract account."""
        return self.code_hash is not None and self.code_hash != keccak(b'')
    
    @property
    def is_empty(self) -> bool:
        """Check if account is empty (EIP-161)."""
        return self.balance == 0 and self.nonce == 0 and not self.is_contract
    
    def to_rlp(self) -> bytes:
        """Encode account to RLP for state trie."""
        return rlp.encode([
            self.nonce,
            self.balance,
            self.storage_root or b'',
            self.code_hash or keccak(b''),
        ])
    
    @classmethod
    def from_rlp(cls, address: str, data: bytes) -> 'Account':
        """Decode account from RLP."""
        nonce, balance, storage_root, code_hash = rlp.decode(data)
        
        return cls(
            address=address,
            balance=int.from_bytes(balance, 'big') if isinstance(balance, bytes) else balance,
            nonce=int.from_bytes(nonce, 'big') if isinstance(nonce, bytes) else nonce,
            code_hash=code_hash if code_hash != keccak(b'') else None,
            storage_root=storage_root if storage_root != b'' else None,
        )


class ContractStateManager:
    """
    Manages contract accounts and storage.
    
    Provides Ethereum-compatible state management with:
    - Account state (balance, nonce, code, storage)
    - State trie (Merkle Patricia Trie)
    - Storage tries (per-contract)
    - State snapshots and reverts
    """
    
    def __init__(self, database: Any):
        """
        Initialize state manager.
        
        Args:
            database: Database instance
        """
        self.db = database
        self._accounts_cache: Dict[str, Account] = {}
        self._storage_cache: Dict[Tuple[str, bytes], bytes] = {}  # (address, key) -> value
        self._code_cache: Dict[bytes, bytes] = {}  # code_hash -> bytecode
        self._snapshots: List[Dict] = []
        self._dirty_accounts: set[str] = set()
        self._dirty_storage: set[Tuple[str, bytes]] = set()
    
    async def get_account(self, address: str) -> Account:
        """
        Get account state.
        
        Args:
            address: Account address
            
        Returns:
            Account object
        """
        address = to_checksum_address(address)
        
        # Check cache
        if address in self._accounts_cache:
            return self._accounts_cache[address]
        
        # Load from database
        cursor = await self.db.connection.execute(
            """
            SELECT balance, nonce, code_hash, storage_root
            FROM account_state
            WHERE address = ?
            """,
            (address,)
        )
        row = await cursor.fetchone()
        
        if row:
            account = Account(
                address=address,
                balance=int(row[0]),
                nonce=int(row[1]),
                code_hash=bytes.fromhex(row[2]) if row[2] else None,
                storage_root=bytes.fromhex(row[3]) if row[3] else None,
            )
        else:
            # New account
            account = Account(address=address)
        
        self._accounts_cache[address] = account
        return account
    
    async def set_account(self, account: Account) -> None:
        """
        Update account state.
        
        Args:
            account: Account to update
        """
        address = to_checksum_address(account.address)
        self._accounts_cache[address] = account
        self._dirty_accounts.add(address)
    
    async def delete_account(self, address: str) -> None:
        """
        Delete account (EIP-161 state clearing).
        
        Args:
            address: Account address
        """
        address = to_checksum_address(address)
        
        # Create empty account
        empty_account = Account(address=address)
        self._accounts_cache[address] = empty_account
        self._dirty_accounts.add(address)
        
        # Clear storage
        await self.clear_storage(address)
    
    async def get_balance(self, address: str) -> int:
        """Get account balance."""
        account = await self.get_account(address)
        return account.balance
    
    async def set_balance(self, address: str, balance: int) -> None:
        """Set account balance."""
        account = await self.get_account(address)
        account.balance = balance
        await self.set_account(account)
    
    async def get_nonce(self, address: str) -> int:
        """Get account nonce."""
        account = await self.get_account(address)
        return account.nonce
    
    async def set_nonce(self, address: str, nonce: int) -> None:
        """Set account nonce."""
        account = await self.get_account(address)
        account.nonce = nonce
        await self.set_account(account)
    
    async def increment_nonce(self, address: str) -> None:
        """Increment account nonce."""
        account = await self.get_account(address)
        account.nonce += 1
        await self.set_account(account)
    
    async def get_code(self, address: str) -> bytes:
        """
        Get contract code.
        
        Args:
            address: Contract address
            
        Returns:
            Contract bytecode
        """
        account = await self.get_account(address)
        
        if not account.code_hash:
            return b''
        
        # Check cache
        if account.code_hash in self._code_cache:
            return self._code_cache[account.code_hash]
        
        # Load from database
        cursor = await self.db.connection.execute(
            "SELECT bytecode FROM contract_code WHERE code_hash = ?",
            (account.code_hash.hex(),)
        )
        row = await cursor.fetchone()
        
        if row:
            bytecode = bytes(row[0]) if isinstance(row[0], (bytes, memoryview)) else bytes.fromhex(row[0])
            self._code_cache[account.code_hash] = bytecode
            return bytecode
        
        return b''
    
    async def set_code(self, address: str, code: bytes, block_number: int, deployer: str) -> None:
        """
        Set contract code.
        
        Args:
            address: Contract address
            code: Contract bytecode
            block_number: Deployment block number
            deployer: Address that deployed contract
        """
        code_hash = keccak(code)
        
        # Update account
        account = await self.get_account(address)
        account.code_hash = code_hash
        await self.set_account(account)
        
        # Cache code
        self._code_cache[code_hash] = code
        
        # Store in database
        await self.db.connection.execute(
            """
            INSERT OR IGNORE INTO contract_code (code_hash, bytecode, deployed_at, deployer, size)
            VALUES (?, ?, ?, ?, ?)
            """,
            (code_hash.hex(), code, block_number, deployer, len(code))
        )
        await self.db.connection.commit()
    
    async def get_code_hash(self, address: str) -> bytes:
        """Get contract code hash."""
        account = await self.get_account(address)
        return account.code_hash or keccak(b'')
    
    async def get_storage(self, address: str, key: bytes) -> bytes:
        """
        Get contract storage value.
        
        Args:
            address: Contract address
            key: Storage key (32 bytes)
            
        Returns:
            Storage value (32 bytes)
        """
        address = to_checksum_address(address)
        cache_key = (address, key)
        
        # Check cache
        if cache_key in self._storage_cache:
            return self._storage_cache[cache_key]
        
        # Load from database
        cursor = await self.db.connection.execute(
            """
            SELECT storage_value
            FROM contract_storage
            WHERE contract_address = ? AND storage_key = ?
            """,
            (address, key.hex())
        )
        row = await cursor.fetchone()
        
        if row:
            value = bytes.fromhex(row[0])
        else:
            value = b'\x00' * 32  # Default empty value
        
        self._storage_cache[cache_key] = value
        return value
    
    async def set_storage(self, address: str, key: bytes, value: bytes) -> None:
        """
        Set contract storage value.
        
        Args:
            address: Contract address
            key: Storage key (32 bytes)
            value: Storage value (32 bytes)
        """
        address = to_checksum_address(address)
        cache_key = (address, key)
        
        self._storage_cache[cache_key] = value
        self._dirty_storage.add(cache_key)
    
    async def clear_storage(self, address: str) -> None:
        """
        Clear all storage for a contract.
        
        Args:
            address: Contract address
        """
        address = to_checksum_address(address)
        
        # Remove from cache
        keys_to_remove = [k for k in self._storage_cache if k[0] == address]
        for key in keys_to_remove:
            del self._storage_cache[key]
            self._dirty_storage.discard(key)
        
        # Mark for database deletion
        await self.db.connection.execute(
            "DELETE FROM contract_storage WHERE contract_address = ?",
            (address,)
        )
        await self.db.connection.commit()
    
    async def account_exists(self, address: str) -> bool:
        """Check if account exists."""
        account = await self.get_account(address)
        return not account.is_empty
    
    async def snapshot(self) -> int:
        """
        Create state snapshot for revert.
        
        Returns:
            Snapshot ID
        """
        snapshot = {
            'accounts': {addr: Account(**vars(acc)) for addr, acc in self._accounts_cache.items()},
            'storage': dict(self._storage_cache),
            'code': dict(self._code_cache),
            'dirty_accounts': set(self._dirty_accounts),
            'dirty_storage': set(self._dirty_storage),
        }
        self._snapshots.append(snapshot)
        return len(self._snapshots) - 1
    
    async def revert(self, snapshot_id: int) -> None:
        """
        Revert state to snapshot.
        
        Args:
            snapshot_id: Snapshot ID from snapshot()
        """
        if snapshot_id < 0 or snapshot_id >= len(self._snapshots):
            raise ValueError(f"Invalid snapshot ID: {snapshot_id}")
        
        snapshot = self._snapshots[snapshot_id]
        self._accounts_cache = snapshot['accounts']
        self._storage_cache = snapshot['storage']
        self._code_cache = snapshot['code']
        self._dirty_accounts = snapshot['dirty_accounts']
        self._dirty_storage = snapshot['dirty_storage']
        
        # Remove newer snapshots
        self._snapshots = self._snapshots[:snapshot_id]
    
    async def commit(self, block_number: int) -> None:
        """
        Commit cached state changes to database.
        
        Args:
            block_number: Current block number
        """
        conn = self.db.connection

        # Commit account changes
        for address in self._dirty_accounts:
            if address in self._accounts_cache:
                account = self._accounts_cache[address]

                if account.is_empty:
                    await conn.execute(
                        "DELETE FROM account_state WHERE address = ?",
                        (address,)
                    )
                else:
                    await conn.execute(
                        """
                        INSERT INTO account_state
                        (address, balance, nonce, code_hash, storage_root,
                         created_at, updated_at, is_contract)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (address) DO UPDATE SET
                            balance = excluded.balance,
                            nonce = excluded.nonce,
                            code_hash = excluded.code_hash,
                            storage_root = excluded.storage_root,
                            updated_at = excluded.updated_at,
                            is_contract = excluded.is_contract
                        """,
                        (
                            address,
                            str(account.balance),
                            account.nonce,
                            account.code_hash.hex() if account.code_hash else None,
                            account.storage_root.hex() if account.storage_root else None,
                            block_number,
                            block_number,
                            account.is_contract,
                        )
                    )

        # Commit storage changes
        for (address, key) in self._dirty_storage:
            if (address, key) in self._storage_cache:
                value = self._storage_cache[(address, key)]

                if value == b'\x00' * 32:
                    await conn.execute(
                        """
                        DELETE FROM contract_storage
                        WHERE contract_address = ? AND storage_key = ?
                        """,
                        (address, key.hex())
                    )
                else:
                    await conn.execute(
                        """
                        INSERT INTO contract_storage
                        (contract_address, storage_key, storage_value, block_number)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT (contract_address, storage_key) DO UPDATE SET
                            storage_value = excluded.storage_value,
                            block_number = excluded.block_number
                        """,
                        (address, key.hex(), value.hex(), block_number)
                    )

        await conn.commit()

        # Clear dirty sets
        self._dirty_accounts.clear()
        self._dirty_storage.clear()
        self._snapshots.clear()
    
    async def get_state_root(self) -> bytes:
        """
        Compute state root (Merkle Patricia Trie root).
        
        Returns:
            State root hash
        """
        # Simplified state root computation
        # In production, this should build a proper MPT
        from eth_hash.auto import keccak
        
        # Collect all accounts
        accounts_data = []
        for address in sorted(self._accounts_cache.keys()):
            account = self._accounts_cache[address]
            if not account.is_empty:
                accounts_data.append(account.to_rlp())
        
        # Hash concatenated account data
        if accounts_data:
            return keccak(b''.join(accounts_data))
        else:
            return keccak(b'')
    
    # ========================================================================
    # SYNCHRONOUS WRAPPERS FOR EVM EXECUTOR
    # ========================================================================
    
    def get_balance_sync(self, address: str) -> int:
        """Sync wrapper for get_balance."""
        if address in self._accounts_cache:
            return self._accounts_cache[address].balance
        # Simple sync DB query (would need async in production)
        return 0
    
    def set_balance_sync(self, address: str, balance: int) -> None:
        """Sync wrapper for set_balance."""
        if address not in self._accounts_cache:
            self._accounts_cache[address] = Account(address=address)
        self._accounts_cache[address].balance = balance
        self._dirty_accounts.add(address)
    
    def get_nonce_sync(self, address: str) -> int:
        """Sync wrapper for get_nonce."""
        if address in self._accounts_cache:
            return self._accounts_cache[address].nonce
        return 0
    
    def set_nonce_sync(self, address: str, nonce: int) -> None:
        """Sync wrapper for set_nonce."""
        if address not in self._accounts_cache:
            self._accounts_cache[address] = Account(address=address)
        self._accounts_cache[address].nonce = nonce
        self._dirty_accounts.add(address)
    
    def get_code_sync(self, address: str) -> bytes:
        """Sync wrapper for get_code."""
        if address not in self._accounts_cache:
            return b''
        account = self._accounts_cache[address]
        if not account.code_hash:
            return b''
        if account.code_hash in self._code_cache:
            return self._code_cache[account.code_hash]
        return b''
    
    def set_code_sync(self, address: str, code: bytes) -> None:
        """Sync wrapper for set_code."""
        if address not in self._accounts_cache:
            self._accounts_cache[address] = Account(address=address)
        
        code_bytes = code if isinstance(code, bytes) else bytes.fromhex(code.replace('0x', ''))
        code_hash = keccak(code_bytes)
        
        self._accounts_cache[address].code_hash = code_hash
        self._code_cache[code_hash] = code_bytes
        self._dirty_accounts.add(address)
    
    def get_storage_sync(self, address: str, key: bytes) -> bytes:
        """Sync wrapper for get_storage."""
        cache_key = (address, key)
        if cache_key in self._storage_cache:
            return self._storage_cache[cache_key]
        return b'\x00' * 32
    
    def set_storage_sync(self, address: str, key: bytes, value: bytes) -> None:
        """Sync wrapper for set_storage."""
        cache_key = (address, key)
        self._storage_cache[cache_key] = value
        self._dirty_storage.add(cache_key)
    
    def get_all_storage_sync(self, address: str) -> Dict[str, str]:
        """Get all storage for an address (sync)."""
        result = {}
        for (addr, key), value in self._storage_cache.items():
            if addr == address:
                result[key.hex()] = value.hex()
        return result
    
    def snapshot_sync(self) -> int:
        """Create state snapshot (sync)."""
        snapshot = {
            'accounts': {addr: Account(**vars(acc)) for addr, acc in self._accounts_cache.items()},
            'storage': dict(self._storage_cache),
            'code': dict(self._code_cache),
            'dirty_accounts': set(self._dirty_accounts),
            'dirty_storage': set(self._dirty_storage),
        }
        self._snapshots.append(snapshot)
        return len(self._snapshots) - 1
    
    def revert_sync(self, snapshot_id: int) -> None:
        """Revert to snapshot (sync)."""
        if snapshot_id < 0 or snapshot_id >= len(self._snapshots):
            return
        
        snapshot = self._snapshots[snapshot_id]
        self._accounts_cache = snapshot['accounts']
        self._storage_cache = snapshot['storage']
        self._code_cache = snapshot['code']
        self._dirty_accounts = snapshot['dirty_accounts']
        self._dirty_storage = snapshot['dirty_storage']
        
        # Remove snapshots after this one
        self._snapshots = self._snapshots[:snapshot_id]

