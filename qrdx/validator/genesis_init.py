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
        validators: Optional[List[Tuple[str, str, Decimal]]] = None,
        genesis_time: Optional[int] = None,
        network_name: str = "qrdx-mainnet",
        chain_id: int = 1,
    ) -> bool:
        """
        Initialize the database with genesis state.
        
        Args:
            prefunded_accounts: Dict of {address: (balance, label)}
            validators: List of (address, public_key, stake) tuples
            genesis_time: Unix timestamp for genesis (default: now)
            network_name: Name of the network
            chain_id: Chain ID
            
        Returns:
            True if initialization succeeded
        """
        if self._genesis_initialized:
            logger.warning("Genesis already initialized in this session")
            return True
        
        # Use default prefunded accounts if not provided
        if prefunded_accounts is None:
            prefunded_accounts = GENESIS_PREFUNDED_ACCOUNTS
        
        logger.info(f"Initializing genesis for {network_name} (chain_id={chain_id})")
        logger.info(f"Prefunded accounts: {len(prefunded_accounts)}")
        logger.info(f"Total prefunded: {sum(amt for amt, _ in prefunded_accounts.values())} QRDX")
        
        try:
            # Create genesis config
            pre_allocations = {
                addr: amount 
                for addr, (amount, _) in prefunded_accounts.items()
            }
            
            config = GenesisConfig(
                chain_id=chain_id,
                network_name=network_name,
                genesis_time=genesis_time or int(datetime.now(timezone.utc).timestamp()),
                pre_allocations=pre_allocations,
                min_genesis_validators=0,  # Allow genesis without validators
            )
            
            creator = GenesisCreator(config)
            
            # Add prefunded accounts with labels
            for address, (balance, label) in prefunded_accounts.items():
                creator.add_account(address, balance, label)
            
            # Add validators if provided
            if validators:
                for address, pubkey, stake in validators:
                    creator.add_validator(address, pubkey, stake)
            
            # Create genesis state and block
            # Note: If no validators, we skip the validator check
            if validators and len(validators) >= config.min_genesis_validators:
                state, block = creator.create_genesis(config.genesis_time)
            else:
                # Create simplified genesis without validator check
                state, block = self._create_minimal_genesis(creator, config)
            
            # Initialize database with genesis data
            await self._init_database_from_genesis(state, block, prefunded_accounts)
            
            self._genesis_initialized = True
            logger.info("Genesis initialization complete!")
            logger.info(f"Genesis block hash: {block.block_hash}")
            logger.info(f"Genesis state root: {state.state_root}")
            
            return True
            
        except Exception as e:
            logger.error(f"Genesis initialization failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _create_minimal_genesis(
        self,
        creator: GenesisCreator,
        config: GenesisConfig,
    ) -> Tuple[GenesisState, GenesisBlock]:
        """
        Create minimal genesis without validators.
        
        Used when bootstrapping a network without initial validators.
        """
        import time
        
        genesis_time = config.genesis_time or int(time.time())
        
        # Create state
        state = GenesisState(
            chain_id=config.chain_id,
            network_name=config.network_name,
            genesis_time=genesis_time,
            genesis_slot=GENESIS_SLOT,
        )
        
        # Add accounts
        for address, account in creator._accounts.items():
            state.accounts[address] = {
                "balance": str(account.balance),
                "label": account.label,
            }
        
        # Compute state root
        state_root = creator._compute_state_root(state)
        state.state_root = state_root.hex()
        
        # Generate RANDAO
        randao_seed = creator._generate_randao_seed()
        state.randao_seed = randao_seed.hex()
        
        # Set totals
        total_prefunded = sum(
            Decimal(a['balance']) for a in state.accounts.values()
        )
        state.total_supply = str(config.initial_supply)
        
        # Create genesis block
        block = GenesisBlock(
            slot=GENESIS_SLOT,
            epoch=GENESIS_EPOCH,
            state_root=state.state_root,
            timestamp=genesis_time,
        )
        
        # Compute block hash
        block_data = (
            block.slot.to_bytes(8, 'little') +
            bytes.fromhex(block.parent_root) +
            bytes.fromhex(block.state_root) +
            block.timestamp.to_bytes(8, 'little')
        )
        block.block_hash = hashlib.sha256(block_data).hexdigest()
        
        return state, block
    
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
        }
        
        # Calculate total reward (sum of all prefunded balances)
        total_reward = sum(amount for amount, _ in prefunded_accounts.values())
        
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
        Create spendable outputs for genesis prefunded accounts.
        
        Each prefunded account receives a genesis coinbase transaction
        that they can spend like any normal UTXO.
        """
        from ..crypto.hashing import sha256
        
        logger.info(f"Creating genesis outputs for {len(prefunded_accounts)} accounts")
        
        for idx, (address, (balance, label)) in enumerate(prefunded_accounts.items()):
            # Create a deterministic transaction hash for genesis outputs
            tx_data = f"genesis:{idx}:{address}:{balance}".encode()
            tx_hash = sha256(tx_data)
            
            # Create genesis transaction
            tx_hex = json.dumps({
                "type": "genesis_allocation",
                "recipient": address,
                "amount": str(balance),
                "label": label,
                "index": idx,
            })
            
            # Insert transaction
            await self.db.add_transaction(
                block_hash=genesis_block_hash,
                tx_hash=tx_hash,
                tx_hex=tx_hex,
                inputs_addresses=[],  # No inputs for genesis
                outputs_addresses=[address],
                outputs_amounts=[int(balance * 1000000)],  # Convert to smallest unit
                fees=Decimal("0"),
            )
            
            # Create unspent output
            await self.db.add_unspent_output(
                tx_hash=tx_hash,
                index=0,
                address=address,
                amount=int(balance * 1000000),  # Convert to smallest unit (microQRDX)
            )
            
            logger.debug(f"Created genesis output: {address[:20]}... = {balance} QRDX ({label})")
        
        logger.info(f"Created {len(prefunded_accounts)} genesis outputs")
    
    async def _init_validators(self, validators: List[Dict[str, Any]]):
        """Initialize validators from genesis state."""
        logger.info(f"Initializing {len(validators)} genesis validators")
        
        for v in validators:
            try:
                await self.db.execute("""
                    INSERT INTO validators (
                        address, public_key, stake, effective_stake,
                        status, activation_epoch, created_at
                    ) VALUES ($1, $2, $3, $3, 'active', 0, NOW())
                    ON CONFLICT (address) DO NOTHING
                """, v['address'], v['public_key'], Decimal(v['stake']))
                
                logger.debug(f"Initialized validator: {v['address'][:20]}...")
                
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
        }
        
        # Try to store in a metadata table if it exists
        try:
            await self.db.execute("""
                INSERT INTO chain_metadata (key, value)
                VALUES ('genesis', $1)
                ON CONFLICT (key) DO UPDATE SET value = $1
            """, json.dumps(metadata))
        except Exception as e:
            # Table might not exist, log and continue
            logger.debug(f"Could not store genesis metadata in DB: {e}")
            
            # Fallback: write to file
            try:
                import os
                genesis_file = os.path.join(
                    os.path.dirname(os.path.dirname(__file__)),
                    'genesis_metadata.json'
                )
                with open(genesis_file, 'w') as f:
                    json.dump(metadata, f, indent=2)
                logger.info(f"Genesis metadata written to {genesis_file}")
            except Exception as fe:
                logger.warning(f"Could not write genesis metadata file: {fe}")


async def initialize_genesis_if_needed(
    db,
    prefunded_accounts: Optional[Dict[str, Tuple[Decimal, str]]] = None,
    genesis_file: Optional[str] = None,
) -> bool:
    """
    Convenience function to initialize genesis if the chain is empty.
    
    Args:
        db: Database connection
        prefunded_accounts: Optional custom prefunded accounts
        genesis_file: Optional path to genesis configuration JSON file
        
    Returns:
        True if genesis was initialized or already existed
    """
    initializer = GenesisInitializer(db)
    
    if await initializer.is_genesis_needed():
        # Try to load genesis from file if provided
        if genesis_file and os.path.exists(genesis_file):
            try:
                import json
                with open(genesis_file, 'r') as f:
                    genesis_data = json.load(f)
                
                # Extract accounts and validators from genesis file
                state = genesis_data.get('state', {})
                accounts = state.get('accounts', {})
                validators_data = state.get('validators', [])
                
                # Convert accounts to prefunded_accounts format
                if accounts and not prefunded_accounts:
                    prefunded_accounts = {}
                    for addr, info in accounts.items():
                        balance = Decimal(info.get('balance', info) if isinstance(info, dict) else info)
                        label = info.get('label', 'genesis-allocation') if isinstance(info, dict) else 'genesis-allocation'
                        prefunded_accounts[addr] = (balance, label)
                    logger.info(f"Loaded {len(prefunded_accounts)} prefunded accounts from genesis file")
                
                # Convert validators list to tuple format if present
                validators = []
                if validators_data:
                    for v in validators_data:
                        address = v['address']
                        pubkey = v['public_key']
                        stake = Decimal(v['stake'])
                        validators.append((address, pubkey, stake))
                    logger.info(f"Loaded {len(validators)} validators from genesis file")
                
                return await initializer.initialize_genesis(
                    prefunded_accounts=prefunded_accounts,
                    validators=validators if validators else None,
                )
            except Exception as e:
                logger.warning(f"Failed to load genesis file {genesis_file}: {e}")
                logger.info("Falling back to default genesis")
        
        # Use default or provided prefunded accounts
        return await initializer.initialize_genesis(
            prefunded_accounts=prefunded_accounts or GENESIS_PREFUNDED_ACCOUNTS,
        )
    
    return True


# Export for easy imports
__all__ = [
    'GenesisInitializer',
    'initialize_genesis_if_needed',
]
