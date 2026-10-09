"""
QRDX Genesis Database Initialization

Initializes the database with genesis state including:
- Prefunded accounts from genesis
- Genesis block creation
- Initial validator set

This module handles the bootstrap of a new chain.
"""

import asyncio
import hashlib
import json
import os
from dataclasses import asdict
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from ..logger import get_logger
from .. import chain_spec as chain_spec_mod
from ..chain_spec import ChainSpec, ChainSpecError
from ..constants import (
    GENESIS_PREFUNDED_ACCOUNTS,
    GENESIS_TOTAL_PREFUNDED,
    GENESIS_SLOT,
    GENESIS_EPOCH,
    SLOTS_PER_EPOCH,
    MIN_VALIDATOR_STAKE,
)
from .genesis import GenesisCreator, GenesisConfig, GenesisState, GenesisBlock

logger = get_logger(__name__)


class GenesisInitializer:
    """
    Handles genesis initialization for the QRDX chain.
    
    This class is responsible for:
    - Checking if genesis initialization is needed
    - Creating genesis state with prefunded accounts
    - Initializing the database with genesis data
    """
    
    def __init__(self, db):
        """
        Initialize the genesis initializer.
        
        Args:
            db: Database connection instance
        """
        self.db = db
        self._genesis_initialized = False
    
    async def is_genesis_needed(self) -> bool:
        """
        Check if genesis initialization is needed.
        
        Returns:
            True if the chain is empty and needs genesis
        """
        try:
            # Check if we have any blocks
            next_block_id = await self.db.get_next_block_id()
            
            if next_block_id == 0:
                logger.info("No blocks found - genesis initialization needed")
                return True
            
            logger.debug(f"Chain has {next_block_id} blocks - genesis already initialized")
            return False
            
        except Exception as e:
            logger.error(f"Error checking genesis status: {e}")
            # Assume genesis is needed if we can't check
            return True
    
    async def initialize_genesis(
        self,
        prefunded_accounts: Optional[Dict[str, Tuple[Decimal, str]]] = None,
        validators: Optional[List[tuple]] = None,  # (address, pubkey, stake[, withdrawal_address])
        genesis_time: Optional[int] = None,
        system_wallet_controller: Optional[str] = None,
        enable_system_wallets: bool = True,
        chain_spec: Optional[ChainSpec] = None,
        expected_block_hash: Optional[str] = None,
        min_genesis_validators: int = 0,
        initial_supply: Optional[Decimal] = None,
    ) -> GenesisBlock:
        """
        Create the genesis block and initialise the database from it.

        The genesis is computed from ``chain_spec`` (default: the process's spec) and the
        allocations, by the same ``GenesisCreator`` that wrote the network's genesis file —
        so ``expected_block_hash`` (the file's own ``block.block_hash``) must come out
        identical. A mismatch means the file was edited, or was produced under a different
        spec or release: the node refuses rather than starting a different chain.

        Raises on any failure. A node that cannot create its network's genesis must not start
        (returning False used to read as "genesis already exists").
        """
        if self._genesis_initialized:
            raise RuntimeError("genesis was already initialised in this session")

        spec = chain_spec or chain_spec_mod.active()
        if prefunded_accounts is None:
            prefunded_accounts = GENESIS_PREFUNDED_ACCOUNTS

        logger.info(f"Initializing genesis for {spec.network} (chain_id={spec.chain_id}, "
                    f"spec {spec.genesis_hash()[:16]}…)")
        logger.info(f"Prefunded accounts: {len(prefunded_accounts)}")
        logger.info(f"Total prefunded: {sum(amt for amt, _ in prefunded_accounts.values())} QRDX")

        config = GenesisConfig(
            chain_spec=spec,
            genesis_time=genesis_time or int(datetime.now(timezone.utc).timestamp()),
            pre_allocations={addr: amount for addr, (amount, _) in prefunded_accounts.items()},
            min_genesis_validators=min_genesis_validators,
            system_wallet_controller=system_wallet_controller,
            enable_system_wallets=enable_system_wallets,
        )
        if initial_supply is not None:
            config.initial_supply = Decimal(str(initial_supply))
        creator = GenesisCreator(config)
        # pre_allocations already funded each account; set only the display labels here
        # (add_account would ADD the balance a second time).
        for address, (_balance, label) in prefunded_accounts.items():
            if label:
                creator._accounts[address].label = label
        for entry in validators or []:
            address, pubkey, stake = entry[0], entry[1], entry[2]
            withdrawal = entry[3] if len(entry) > 3 else None
            if not creator.add_validator(address, pubkey, stake, withdrawal):
                raise ChainSpecError(f"genesis validator {address[:20]}… was rejected "
                                     f"(stake {stake}); see the log above")

        state, block = creator.create_genesis(config.genesis_time)
        if expected_block_hash and expected_block_hash.lower() != block.block_hash.lower():
            raise ChainSpecError(
                f"the genesis file records block hash {expected_block_hash[:16]}…, but this "
                f"release computes {block.block_hash[:16]}… from it. The file was edited or "
                f"produced by an incompatible release; refusing to start a different chain.")

        await self._init_database_from_genesis(state, block, prefunded_accounts)

        self._genesis_initialized = True
        logger.info("Genesis initialization complete!")
        logger.info(f"Genesis block hash: {block.block_hash}")
        logger.info(f"Genesis state root: {state.state_root}")
        return block

    async def _init_database_from_genesis(
        self,
        state: GenesisState,
        block: GenesisBlock,
        prefunded_accounts: Dict[str, Tuple[Decimal, str]],
    ):
        """
        Initialize the database with genesis data.
        
        This creates:
        - Genesis block
        - Coinbase transactions for prefunded accounts
        - Initial validator records (if any)
        - System wallets (if enabled)
        """
        logger.info("Initializing database with genesis data...")
        
        # Create genesis block content
        genesis_content = {
            "type": "genesis",
            "state_root": state.state_root,
            "chain_id": state.chain_id,
            "network_name": state.network_name,
            "genesis_time": state.genesis_time,
            "randao_seed": state.randao_seed,
            "prefunded_accounts": len(prefunded_accounts),
            "validators": len(state.validators),
            # The genesis validator set itself, not just its size: the validator price oracle's
            # committee starts from it (ExchangeStateManager.load_oracle_committee), and block 0
            # is the one record every node holds identically.
            "validator_set": sorted(
                ({"address": v["address"], "stake": str(Decimal(str(v["stake"])))}
                 for v in state.validators),
                key=lambda v: v["address"]),
            "system_wallets": len(state.system_wallets),
            "system_wallet_controller": state.system_wallet_controller,
            # The chain spec this chain was created under. A node refuses to start on this
            # database with any other (main._verify_chain_identity).
            "chain_spec_hash": state.chain_spec_hash,
            "chain_spec_format": chain_spec_mod.SPEC_FORMAT,
        }

        # Calculate total reward (sum of all prefunded balances + system wallet balances)
        total_reward = sum(amount for amount, _ in prefunded_accounts.values())
        if state.system_wallets:
            total_reward += sum(Decimal(w['balance']) for w in state.system_wallets.values())
        
        # Insert genesis block
        await self.db.add_block(
            block_id=0,
            block_hash=block.block_hash,
            block_content=json.dumps(genesis_content),
            address="genesis",
            random_value=0,
            difficulty=Decimal("0"),
            reward=total_reward,
            timestamp=datetime.fromtimestamp(state.genesis_time, tz=timezone.utc),
        )
        
        logger.info(f"Genesis block inserted: {block.block_hash[:16]}...")
        
        # Create genesis outputs for prefunded accounts
        # Each prefunded account gets a genesis output they can spend
        await self._create_genesis_outputs(block.block_hash, prefunded_accounts)
        
        # Initialize system wallets if present
        if state.system_wallets:
            await self._init_system_wallets(
                block.block_hash,
                state.system_wallets,
                state.system_wallet_controller
            )
        
        # Initialize validators if any
        if state.validators:
            await self._init_validators(state.validators)
        
        # Store genesis metadata
        await self._store_genesis_metadata(state, block)
    
    async def _create_genesis_outputs(
        self,
        genesis_block_hash: str,
        prefunded_accounts: Dict[str, Tuple[Decimal, str]],
    ):
        """
        Fund genesis prefunded accounts in the UNIFIED ledger: ``account_state``
        (balance in wei). This is the single source of truth for ALL addresses —
        0x/EVM and 0xPQ alike — so EVM gas, exchange collateral, and balance reads
        all operate on one ledger (previously 0xPQ funds went to the UTXO set and
        0x funds were mirrored into account_state on demand, leaving the exchange
        unable to debit PQ traders). The EVM native↔account sync becomes a no-op
        because ``get_address_balance`` reads account_state first.

        A genesis transaction record is still written for history/auditability; the
        balance itself lives in account_state (no UTXO output → the UTXO ledger is
        empty at genesis).
        """
        from ..crypto.hashing import sha256
        from decimal import Decimal as _D
        from ..crypto.account_id import to_account_id

        logger.info(f"Funding {len(prefunded_accounts)} genesis accounts in account_state (unified ledger)")

        for idx, (address, (balance, label)) in enumerate(prefunded_accounts.items()):
            tx_data = f"genesis:{idx}:{address}:{balance}".encode()
            tx_hash = sha256(tx_data)

            tx_hex = json.dumps({
                "type": "genesis_allocation",
                "recipient": address,
                "amount": str(balance),
                "label": label,
                "index": idx,
            })

            # Genesis transaction record (history). No UTXO output — funds live in
            # account_state below.
            await self.db.add_transaction(
                block_hash=genesis_block_hash,
                tx_hash=tx_hash,
                tx_hex=tx_hex,
                inputs_addresses=[],
                outputs_addresses=[address],
                outputs_amounts=[int(balance * 1000000)],
                fees=Decimal("0"),
            )

            # Fund the unified ledger (account_state, wei), keyed by the canonical
            # 20-byte ACCOUNT ID — not the display address. A 0xPQ allocation and
            # the EVM's view of that account are then one row, so the EVM can
            # execute against PQ-funded accounts and contracts can pay them.
            # The genesis tx above keeps the display address for auditability.
            account_id = to_account_id(address)
            wei = int(_D(str(balance)) * _D(10 ** 18))
            await self.db.connection.execute(
                "INSERT INTO account_state (address, balance, nonce, created_at, updated_at, is_contract) "
                "VALUES (?, ?, 0, 0, 0, 0) "
                "ON CONFLICT(address) DO UPDATE SET balance = excluded.balance",
                (account_id, str(wei)),
            )

            logger.debug(
                f"Funded genesis account: {address[:20]}... (id {account_id}) "
                f"= {balance} QRDX ({label})"
            )

        await self.db.connection.commit()
        logger.info(f"Funded {len(prefunded_accounts)} genesis accounts in account_state")
    
    async def _init_system_wallets(
        self,
        genesis_block_hash: str,
        system_wallets: Dict[str, Dict[str, Any]],
        controller_address: str,
    ):
        """
        Initialize system wallets in genesis.
        
        Creates:
        - Spendable outputs for system wallets (controlled by controller)
        - System wallet metadata in database
        """
        from ..crypto.hashing import sha256
        
        logger.info(f"Initializing {len(system_wallets)} system wallets")
        logger.info(f"System wallet controller: {controller_address}")
        
        for idx, (address, wallet_info) in enumerate(system_wallets.items()):
            balance = Decimal(wallet_info['balance'])
            name = wallet_info['name']
            is_burner = wallet_info.get('is_burner', False)
            
            # Skip creating outputs for burner wallets (they can only receive, not spend)
            if is_burner:
                logger.info(f"Skipping output for burner wallet: {name} at {address}")
                continue
            
            # Create deterministic transaction hash for system wallet
            tx_data = f"genesis:system:{idx}:{address}:{balance}".encode()
            tx_hash = sha256(tx_data)
            
            # Create genesis transaction for system wallet
            tx_hex = json.dumps({
                "type": "genesis_system_wallet",
                "recipient": address,
                "amount": str(balance),
                "name": name,
                "controller": controller_address,
                "category": wallet_info['category'],
                "index": idx,
            })
            
            # Insert transaction
            await self.db.add_transaction(
                block_hash=genesis_block_hash,
                tx_hash=tx_hash,
                tx_hex=tx_hex,
                inputs_addresses=[],
                outputs_addresses=[address],
                outputs_amounts=[int(balance * 1000000)],
                fees=Decimal("0"),
            )
            
            # Fund it in the unified ledger (account_state, wei), like every other genesis
            # allocation. It used to be a UTXO output, which balance READS fell back to while
            # account_state had no row — so a debit through the balance-delta flush (a governance
            # system_spend) found nothing to debit and was dropped, while its credit landed.
            from ..crypto.account_id import to_account_id
            await self.db.connection.execute(
                "INSERT INTO account_state (address, balance, nonce, created_at, updated_at, is_contract) "
                "VALUES (?, ?, 0, 0, 0, 0) "
                "ON CONFLICT(address) DO UPDATE SET balance = excluded.balance",
                (to_account_id(address), str(int(balance * Decimal(10 ** 18)))),
            )
            
            # Store system wallet metadata
            try:
                # Try PostgreSQL syntax first
                try:
                    await self.db.execute("""
                        INSERT INTO system_wallets (
                            address, name, description, wallet_type,
                            controller_address, is_burner, category, balance
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        ON CONFLICT (address) DO NOTHING
                    """,
                        address,
                        name,
                        wallet_info['description'],
                        wallet_info['type'],
                        controller_address,
                        is_burner,
                        wallet_info['category'],
                        str(balance)
                    )
                    logger.debug(f"Stored system wallet metadata (PostgreSQL): {name}")
                except Exception as pg_err:
                    # Try SQLite syntax
                    logger.debug(f"PostgreSQL insert failed: {pg_err}, trying SQLite syntax")
                    await self.db.execute("""
                        INSERT OR IGNORE INTO system_wallets (
                            address, name, description, wallet_type,
                            controller_address, is_burner, category, balance
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        address,
                        name,
                        wallet_info['description'],
                        wallet_info['type'],
                        controller_address,
                        is_burner,
                        wallet_info['category'],
                        str(balance)
                    )
                    logger.debug(f"Stored system wallet metadata (SQLite): {name}")
            except Exception as e:
                # Log the error but continue - system wallets work via UTXOs even without this table
                logger.error(f"Failed to store system wallet metadata for {name}: {e}")
                import traceback
                traceback.print_exc()
            
            logger.debug(
                f"Initialized system wallet: {name} at {address} = {balance} QRDX"
            )
        
        logger.info(f"System wallets initialized successfully")
    
    async def _init_validators(self, validators: List[Dict[str, Any]]):
        """Initialize validators from genesis state."""
        logger.info(f"Initializing {len(validators)} genesis validators")
        
        for v in validators:
            try:
                # Try PostgreSQL syntax first
                try:
                    await self.db.execute("""
                        INSERT INTO validators (
                            address, public_key, stake, effective_stake,
                            status, activation_epoch, created_at
                        ) VALUES ($1, $2, $3, $3, 'active', 0, NOW())
                        ON CONFLICT (address) DO NOTHING
                    """, v['address'], v['public_key'], Decimal(v['stake']))
                    logger.debug(f"Initialized validator (PostgreSQL): {v['address'][:20]}...")
                except Exception as pg_err:
                    # Fall back to SQLite syntax.
                    # SQLite cannot bind Decimal objects, and stake/effective_stake
                    # are TEXT columns, so the stake must be passed as a string.
                    logger.debug(f"PostgreSQL insert failed: {pg_err}, trying SQLite syntax")
                    stake_str = str(Decimal(v['stake']))
                    await self.db.execute("""
                        INSERT OR IGNORE INTO validators (
                            address, public_key, stake, effective_stake,
                            status, activation_epoch, created_at
                        ) VALUES (?, ?, ?, ?, 'active', 0, datetime('now'))
                    """, v['address'], v['public_key'], stake_str, stake_str)
                    logger.debug(f"Initialized validator (SQLite): {v['address'][:20]}...")
                
            except Exception as e:
                logger.error(f"Failed to initialize validator {v['address']}: {e}")
    
    async def _store_genesis_metadata(
        self,
        state: GenesisState,
        block: GenesisBlock,
    ):
        """
        Store genesis metadata for future reference.
        
        This is stored in a special metadata table or as chain config.
        """
        metadata = {
            "version": state.version,
            "chain_id": state.chain_id,
            "network_name": state.network_name,
            "genesis_time": state.genesis_time,
            "genesis_slot": state.genesis_slot,
            "genesis_block_hash": block.block_hash,
            "state_root": state.state_root,
            "validators_root": state.genesis_validators_root,
            "randao_seed": state.randao_seed,
            "total_supply": state.total_supply,
            "total_staked": state.total_staked,
            "system_wallets": len(state.system_wallets),
            "system_wallet_controller": state.system_wallet_controller,
            "total_system_wallets": state.total_system_wallets,
        }
        
        metadata["chain_spec_hash"] = state.chain_spec_hash
        # In the node's own database (chain_metadata), never beside the package: a file there
        # is shared by every node started from this checkout, and was dirtied by each one.
        await self.db.connection.execute(
            "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES ('genesis', ?)",
            (json.dumps(metadata, sort_keys=True),))
        await self.db.connection.commit()


async def initialize_genesis_if_needed(
    db,
    prefunded_accounts: Optional[Dict[str, Tuple[Decimal, str]]] = None,
    genesis_file: Optional[str] = None,
    chain_spec: Optional[ChainSpec] = None,
) -> bool:
    """
    Create the genesis block if the chain is empty.

    With a genesis file, genesis is built from it — and must reproduce the file's recorded
    genesis block hash under the process's chain spec. Without one, this is a DEV network and
    the built-in allocations are used. Every failure raises: there is no fallback genesis,
    because a node that started one would be running a different chain from its network.

    Returns True if genesis was created now, False if the chain already had one.
    """
    spec = chain_spec or chain_spec_mod.active()
    initializer = GenesisInitializer(db)
    if not await initializer.is_genesis_needed():
        return False

    if genesis_file is None:
        if not spec.dev:
            raise ChainSpecError(f"{spec.network} is not a dev network; its genesis must come "
                                 f"from its genesis file")
        await initializer.initialize_genesis(
            prefunded_accounts=prefunded_accounts or GENESIS_PREFUNDED_ACCOUNTS,
            chain_spec=spec)
        return True

    genesis_data, file_spec = chain_spec_mod.load_genesis_file(genesis_file)
    if file_spec.genesis_hash() != spec.genesis_hash():
        raise ChainSpecError(f"genesis file {genesis_file} defines a different chain spec "
                             f"from the one this process loaded")
    state = genesis_data.get("state") or {}
    block_data = genesis_data.get("block") or {}
    if state.get("chain_id") not in (None, spec.chain_id):
        raise ChainSpecError(f"genesis state chain_id {state.get('chain_id')} disagrees with the "
                             f"chain spec ({spec.chain_id})")
    if state.get("network_name") not in (None, spec.network):
        raise ChainSpecError(f"genesis state network {state.get('network_name')!r} disagrees "
                             f"with the chain spec ({spec.network!r})")

    if not prefunded_accounts:
        prefunded_accounts = {}
        for addr, info in (state.get("accounts") or {}).items():
            if isinstance(info, dict):
                balance, label = Decimal(str(info["balance"])), info.get("label", "genesis-allocation")
            else:
                balance, label = Decimal(str(info)), "genesis-allocation"
            prefunded_accounts[addr] = (balance, label)
        logger.info(f"Loaded {len(prefunded_accounts)} prefunded accounts from genesis file")

    validators = [(v["address"], v["public_key"], Decimal(str(v["stake"])),
                   v.get("withdrawal_address") or None)
                  for v in (state.get("validators") or [])]
    logger.info(f"Loaded {len(validators)} validators from genesis file")

    genesis_time = state.get("genesis_time", block_data.get("timestamp"))
    if genesis_time is None:
        raise ChainSpecError(f"genesis file {genesis_file} has no genesis time")
    controller = state.get("system_wallet_controller") or None
    logger.info(f"Loading genesis for {spec.network} (chain_id={spec.chain_id})")
    if controller:
        logger.info(f"System wallet controller: {controller}")

    await initializer.initialize_genesis(
        prefunded_accounts=prefunded_accounts,
        validators=validators or None,
        genesis_time=int(genesis_time),
        system_wallet_controller=controller,
        enable_system_wallets=bool(controller),
        chain_spec=spec,
        expected_block_hash=block_data.get("block_hash") or None,
        initial_supply=Decimal(str(state["total_supply"])) if state.get("total_supply") else None,
    )
    return True


# Export for easy imports
__all__ = [
    'GenesisInitializer',
    'initialize_genesis_if_needed',
]
