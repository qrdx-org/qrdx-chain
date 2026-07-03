"""
QRDX Validator Node Integration

This module integrates the PoS consensus validator into the node lifecycle.
It handles validator initialization, block production, attestation, epoch processing,
and canary wallet monitoring for the Doomsday Protocol (§8.5).
"""
import asyncio
import json
import os
from typing import Optional
from datetime import datetime, timezone, timedelta

from ..logger import get_logger
from ..constants import SLOTS_PER_EPOCH, SLOT_DURATION
from .config import ValidatorConfig
from .manager import ValidatorManager
from .types import Validator, ValidatorSet, ValidatorStatus
from ..wallet_v2.pq_wallet import PQWallet
from ..crypto.pq.dilithium import PQPrivateKey as PrivateKey, PQPublicKey as PublicKey

logger = get_logger(__name__)

# Slot duration in seconds (from SLOT_DURATION constant which is in int format)
SLOT_DURATION_SECONDS = SLOT_DURATION if isinstance(SLOT_DURATION, int) else 12

# Validator-lifecycle unification rollout gate. False = OBSERVE (each epoch the
# reward/penalty deltas are computed + the would-be validators-table hash is logged,
# but NOT written → zero consensus impact, used to confirm cross-node determinism).
# True = ENFORCE (write the deltas to the consensus validators table at each epoch
# boundary, so effective_stake evolves with participation). Flip only after a soak
# shows the validators-table hash is identical across all nodes per epoch.
_ENFORCE_EPOCH_VALIDATOR_UPDATES = False


def parse_block_timestamp(ts) -> Optional[datetime]:
    """
    Parse a block timestamp into a tz-aware UTC datetime, or None.

    Handles BOTH stored forms: an integer/float Unix timestamp (later blocks) and
    an ISO-8601 TEXT string (the genesis block, e.g. "2026-06-08 13:57:09+00:00").
    Returning the wrong thing here pins the slot clock — see ``_get_current_slot``.
    """
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        parsed = datetime.fromisoformat(str(ts))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def assemble_pos_block_data(block, height: int, exchange_txs=None,
                            exchange_state_root: str = None,
                            evm_txs=None, account_state_root: str = None) -> dict:
    """
    Build the broadcast/storage payload for a proposed PoS block (Phase D2.2/D3,
    E-D3b).

    Both the exchange section and the EVM section are **additive**: present only
    when the proposer included transactions of that kind, and ignored by importers
    that don't understand them (backward compatible). Each is encoded with its
    canonical codec so it round-trips and authenticates on the receiving side.
    When a section is present the proposer also declares its state root
    (``exchange_state_root`` / ``account_state_root``) so importers can re-execute
    and verify it (reject-on-mismatch).

    Pure function (no I/O) so it is unit-testable in isolation.
    """
    block_content = str(block.to_dict())
    data = {
        'id': height,
        'block_content': block_content,
        'block_hash': block.hash,
        'validator_address': block.proposer_address,
        'timestamp': getattr(block, 'timestamp', 0),
    }
    if exchange_txs:
        # Imported lazily to avoid a hard dependency when the exchange module
        # is not in use.
        from ..exchange.block_processor import encode_exchange_txs, BLOCK_EXCHANGE_TXS_KEY
        data[BLOCK_EXCHANGE_TXS_KEY] = encode_exchange_txs(exchange_txs)
        if exchange_state_root:
            data['exchange_state_root'] = exchange_state_root
    if evm_txs:
        from ..contracts.evm_block import encode_evm_txs, BLOCK_EVM_TXS_KEY
        data[BLOCK_EVM_TXS_KEY] = encode_evm_txs(evm_txs)
        if account_state_root:
            data['account_state_root'] = account_state_root
    return data


class ValidatorNode:
    """
    Integrates PoS validator consensus into the node.
    
    Responsibilities:
    - Load and validate PQ wallet
    - Initialize ValidatorManager
    - Run block proposal duties
    - Run attestation duties
    - Process epoch boundaries
    - Handle slashing detection
    """
    
    def __init__(self, db, validator_wallet_path: str, password: str = "", broadcast_callback=None):
        """
        Initialize validator node.
        
        Args:
            db: Database instance
            validator_wallet_path: Path to PQ wallet JSON file
            password: Wallet password (optional for testnet)
            broadcast_callback: Async function to broadcast blocks to peers
        """
        self.db = db
        self.wallet_path = validator_wallet_path
        self.password = password
        self.broadcast_callback = broadcast_callback
        
        self.wallet: Optional[PQWallet] = None
        self.config: Optional[ValidatorConfig] = None
        self.manager: Optional[ValidatorManager] = None
        
        self._running = False
        self._block_production_task: Optional[asyncio.Task] = None
        self._attestation_task: Optional[asyncio.Task] = None
        self._epoch_processing_task: Optional[asyncio.Task] = None
        self._canary_monitor_task: Optional[asyncio.Task] = None

        # ── Doomsday / canary monitoring (§8.5) ──
        self._eth_adapter = None       # Set via set_eth_adapter()
        self._doomsday_protocol = None  # Set via set_doomsday_protocol()

        # ── Exchange tx inclusion (Phase D2.2) ──
        # An object exposing select_for_block(limit) -> [ExchangeTransaction]
        # (the node's ExchangeMempool). Set via set_exchange_tx_source().
        self._exchange_tx_source = None

        # ── EVM tx inclusion (E-D3b execute-on-mine) ──
        # _evm_tx_source: the node's EVMMempool (select_for_block / remove).
        # _evm_section_producer: async (height, hash, ts, raw_txs) ->
        #   (account_state_root or None, included_raw_txs) — executes the section
        #   against EVM state and declares the root. Both set from main.py once
        #   the EVM system is initialized.
        self._evm_tx_source = None
        self._evm_section_producer = None
        
        logger.info(f"ValidatorNode initialized for wallet: {validator_wallet_path}")
    
    async def initialize(self) -> bool:
        """
        Load wallet and initialize validator manager.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # Load wallet from JSON
            logger.info(f"Loading PQ wallet from {self.wallet_path}")
            with open(self.wallet_path, 'r') as f:
                wallet_data = json.load(f)
            
            # Extract keys and address
            address = wallet_data['address']
            private_key_hex = wallet_data['private_key']
            public_key_hex = wallet_data.get('public_key')

            # Load PQ wallet from hex private key. CRITICAL: the stored public key
            # MUST be passed — a Dilithium secret key cannot re-derive its public
            # key, so restoring without it makes PQPrivateKey generate a RANDOM new
            # keypair (see dilithium._restore_from_bytes), yielding a wrong address.
            # That made each validator propose under an identity that didn't match
            # its genesis registration → validators never converged on a common set
            # → every node thought it was the sole proposer → reorg churn.
            private_key = PrivateKey.from_hex(private_key_hex, public_key_hex=public_key_hex)
            self.wallet = PQWallet(private_key=private_key)

            # Fail fast if the restored identity does not match the wallet file.
            if public_key_hex and self.wallet.address != address:
                raise Exception(
                    f"validator wallet identity mismatch: file address {address} != "
                    f"restored {self.wallet.address} (public key not preserved on load)"
                )
            logger.info(f"Wallet loaded: {self.wallet.address}")
            
            # Create validator configuration (use defaults)
            self.config = ValidatorConfig(enabled=True)
            
            # Initialize ValidatorManager with database
            logger.info("Initializing ValidatorManager...")
            self.manager = ValidatorManager(
                wallet=self.wallet,
                config=self.config,
                database=self.db  # Pass database for stake persistence
            )
            
            # Load existing stakes from database
            await self.manager.stake_manager.load_from_database()
            
            # Register initial stake (using deposit mechanism)
            from decimal import Decimal
            current_stake = await self.manager.stake_manager.get_stake(self.wallet.address)
            
            # Only deposit if we don't have enough stake
            min_stake = self.config.staking.min_validator_stake
            if current_stake < min_stake:
                stake_needed = min_stake  # Deposit full minimum if no stake exists
                logger.info(f"Depositing {stake_needed} QRDX stake (current: {current_stake})")
                await self.manager.stake_manager.deposit(
                    validator_address=self.wallet.address,
                    amount=stake_needed,
                    tx_hash=f"genesis_{self.wallet.address[:16]}",
                    block_number=0,
                    epoch=0
                )
            else:
                logger.info(f"Validator already has sufficient stake: {current_stake} QRDX")
            
            # Initialize validator state (for now, set to ACTIVE immediately)
            # In production, validators would go through activation queue
            actual_stake = await self.manager.stake_manager.get_stake(self.wallet.address)
            effective_stake = await self.manager.stake_manager.get_effective_stake(self.wallet.address)
            
            # Verify meets minimum stake before creating validator
            if effective_stake < min_stake:
                raise Exception(f"Insufficient stake: {effective_stake} < {min_stake} QRDX required")
            
            # Create and activate validator (bypass activation queue for testnet)
            self.manager._validator = Validator(
                address=self.wallet.address,
                public_key=self.wallet.public_key,
                stake=actual_stake,
                effective_stake=effective_stake,
                status=ValidatorStatus.ACTIVE,
                activation_epoch=0,
                slashed=False,
                uptime_score=1.0,
                index=0
            )
            
            # Build the validator set from the CONSISTENT `validators` table
            # (seeded identically on every node from the shared genesis), NOT from
            # `validator_stakes` (which holds only each node's own self-deposit and
            # so differs per node). Using the consistent set is what lets every
            # node derive the SAME proposer per slot → one proposer per slot
            # instead of every node believing it is the sole proposer.
            all_validators = []
            try:
                validator_rows = await self.db.get_validators()
            except Exception as e:
                logger.warning(f"Could not load validators table: {e}")
                validator_rows = []

            for vr in validator_rows:
                addr = vr.get('address')
                if not addr:
                    continue
                # EXITING is eligible: a validator that requested exit keeps proposing
                # through unbonding (Phase 3c), leaving the set only at its finalized
                # exit_epoch. No-op until exits exist (no row is 'exiting' yet).
                status_str = str(vr.get('status', 'active')).upper()
                if status_str not in ('ACTIVE', 'PENDING', 'EXITING'):
                    continue
                eff = Decimal(str(vr.get('effective_stake') or vr.get('stake') or 0))
                is_self = (addr == self.wallet.address)
                all_validators.append(Validator(
                    address=addr,
                    public_key=self.wallet.public_key if is_self else b'',
                    stake=eff,
                    effective_stake=eff,
                    status=ValidatorStatus.ACTIVE,
                    activation_epoch=0,
                    slashed=bool(vr.get('slashed')),
                    uptime_score=1.0,
                    index=len(all_validators),
                ))

            # Safety net: if the table didn't include us yet, add self so we can
            # still participate (single-validator bootstrap).
            if not any(v.address == self.wallet.address for v in all_validators):
                all_validators.append(self.manager._validator)

            logger.info(
                f"Validator set built from validators table: {len(all_validators)} "
                f"members: {[v.address[:16] + '...' for v in all_validators]}"
            )

            # Calculate total stake
            total_stake = sum(v.stake for v in all_validators)
            
            self.manager._validator_set = ValidatorSet(
                epoch=0,
                validators=all_validators,
                total_stake=total_stake
            )
            
            logger.info(f"Validator set created with {len(all_validators)} validators (total stake: {total_stake} QRDX)")
            
            logger.info(f"Validator stake: {actual_stake} QRDX (effective: {effective_stake} QRDX)")
            
            logger.info(f"✅ Validator registered and activated: {self.wallet.address}")
            logger.info("✅ Validator initialization complete")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize validator: {e}", exc_info=True)
            return False
    
    async def start(self):
        """Start validator consensus duties."""
        if not self.manager:
            logger.error("Cannot start validator - not initialized")
            return
        
        self._running = True
        logger.info("🚀 Starting validator consensus duties...")
        
        # Start validator tasks
        self._block_production_task = asyncio.create_task(self._block_production_loop())
        self._attestation_task = asyncio.create_task(self._attestation_loop())
        self._epoch_processing_task = asyncio.create_task(self._epoch_processing_loop())

        # Start canary monitor if adapter & doomsday are configured
        if self._eth_adapter is not None and self._doomsday_protocol is not None:
            self._canary_monitor_task = asyncio.create_task(self._canary_monitor_loop())
            logger.info("🔍 Canary monitor started (Doomsday §8.5)")
        
        logger.info("✅ Validator tasks started")
    
    async def stop(self):
        """Stop validator consensus duties."""
        self._running = False
        logger.info("Stopping validator consensus duties...")
        
        # Cancel tasks
        if self._block_production_task:
            self._block_production_task.cancel()
        if self._attestation_task:
            self._attestation_task.cancel()
        if self._epoch_processing_task:
            self._epoch_processing_task.cancel()
        if self._canary_monitor_task:
            self._canary_monitor_task.cancel()
        
        logger.info("Validator stopped")
    
    async def _block_production_loop(self):
        """
        Main block production loop.
        Checks if this validator is the proposer for the current slot and produces blocks.
        """
        logger.info("Block production loop started")
        
        while self._running:
            try:
                # Get current slot and epoch
                current_slot = await self._get_current_slot()
                current_epoch = current_slot // SLOTS_PER_EPOCH
                
                logger.info(f"📍 Checking slot {current_slot} (epoch {current_epoch}) for block proposal...")
                
                # Get latest block from database for parent hash and next height
                next_block_id = await self.db.get_next_block_id()
                latest_block = await self.db.get_block_by_id(next_block_id - 1)
                parent_hash = latest_block.get('hash') or latest_block.get('block_hash') if latest_block else '0' * 64
                next_height = next_block_id  # Sequential: 0 (genesis), 1, 2, 3...
                
                # Get pending transactions
                pending_txs = await self.db.get_need_propagate_transactions() or []

                # E-D4 + RANDAO liveness: determine our eligibility RANK for the slot
                # (0 = primary; 1.. = backup, only under enforced RANDAO selection;
                # None = not eligible). The primary executes the sections + proposes
                # immediately; a BACKUP waits proportionally and proposes ONLY if no block
                # for this height has landed — so a slow/offline primary no longer leaves
                # the slot empty. Eligibility is re-checked identically in propose_block +
                # on import (deterministic top-K for the slot).
                rank = await self.manager.proposer_rank(current_slot)
                if rank is None:
                    await asyncio.sleep(SLOT_DURATION_SECONDS)
                    continue
                if rank > 0:
                    await asyncio.sleep(min(rank, 3) * (SLOT_DURATION_SECONDS / 2))
                    if (await self.db.get_next_block_id()) != next_block_id:
                        continue  # a higher-priority proposer already filled this slot

                # Timestamp/parent used as the (non-consensus) execution context for
                # the sections — they affect only audit tables, never the state roots.
                block_timestamp = int(datetime.now(timezone.utc).timestamp())

                # Exchange section: select + execute (commit on success). Drop on
                # failure rather than ship a bad block.
                exchange_txs = []
                exchange_state_root = None
                if self._exchange_tx_source is not None:
                    try:
                        exchange_txs = self._exchange_tx_source.select_for_block() or []
                    except Exception as e:
                        logger.warning(f"Exchange tx selection failed: {e}")
                        exchange_txs = []
                    if exchange_txs:
                        try:
                            from ..exchange.block_processor import (
                                process_exchange_transactions, preload_sender_balances,
                                preload_token_balances, flush_exchange_balance_deltas,
                                flush_token_balance_deltas, flush_validator_lifecycle_deltas,
                                ENFORCE_EXCHANGE_COLLATERAL, ENFORCE_SPOT_SETTLEMENT,
                                ENFORCE_ORDERBOOK_SETTLEMENT,
                            )
                            from ..exchange.state_manager import ExchangeStateManager
                            mgr = ExchangeStateManager.get_instance()
                            mgr.enforce_collateral = ENFORCE_EXCHANGE_COLLATERAL
                            mgr.enforce_spot_settlement = ENFORCE_SPOT_SETTLEMENT
                            mgr.enforce_orderbook_settlement = ENFORCE_ORDERBOOK_SETTLEMENT
                            # Phase E: pre-load senders' real QRDX + token balances for
                            # the collateral + spot-sufficiency checks during processing.
                            await preload_sender_balances(self.db, exchange_txs, mgr)
                            await preload_token_balances(self.db, exchange_txs, mgr)
                            ok, err, root = process_exchange_transactions(
                                next_height, float(block_timestamp), exchange_txs, mgr,
                            )
                            if ok:
                                mgr.commit_block()
                                # Phase E: flush margin debits to account_state +
                                # token moves to the token ledger (before the unified
                                # root is computed below).
                                await flush_exchange_balance_deltas(
                                    self.db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL)
                                await flush_token_balance_deltas(self.db, mgr)
                                await flush_validator_lifecycle_deltas(
                                    self.db, mgr, block_epoch=current_epoch)
                                exchange_state_root = root
                                logger.info(
                                    f"📦 Including {len(exchange_txs)} exchange tx(s) in "
                                    f"block #{next_height} (root={root[:16]}...)"
                                )
                            else:
                                logger.warning(f"Exchange execution failed, dropping section: {err}")
                                exchange_txs = []
                        except Exception as e:
                            logger.warning(f"Exchange execution error, dropping section: {e}")
                            exchange_txs = []

                # EVM/account section: execute-on-mine.
                evm_txs = []
                account_state_root = None
                if self._evm_tx_source is not None and self._evm_section_producer is not None:
                    try:
                        evm_raws = self._evm_tx_source.select_for_block() or []
                    except Exception as e:
                        logger.warning(f"EVM tx selection failed: {e}")
                        evm_raws = []
                    if evm_raws:
                        try:
                            account_state_root, evm_txs = await self._evm_section_producer(
                                next_height, parent_hash, block_timestamp, evm_raws,
                            )
                            evm_txs = evm_txs or []
                            if account_state_root and evm_txs:
                                logger.info(
                                    f"📦 Including {len(evm_txs)} EVM tx(s) in "
                                    f"block #{next_height} (root={account_state_root[:16]}...)"
                                )
                            else:
                                evm_txs = []
                                account_state_root = None
                        except Exception as e:
                            logger.warning(f"EVM section production failed, dropping section: {e}")
                            evm_txs = []
                            account_state_root = None

                # E-D4: compute the post-block unified state root (UTXO + account +
                # exchange) and bind it into the block's signed header. The importer
                # recomputes it after replaying the sections and verifies it matches
                # this signed root — full cryptographic binding of all state domains.
                unified_root = await self._compute_unified_state_root()

                block = await self.manager.propose_block(
                    slot=current_slot,
                    parent_hash=parent_hash,
                    transactions=pending_txs[:100],  # Limit to 100 txs per block
                    state_root=unified_root,
                )

                if block:
                    logger.info(f"📦 Proposed block #{next_height} at slot {current_slot}: {block.hash[:16]}...")

                    block_data = assemble_pos_block_data(
                        block, next_height, exchange_txs, exchange_state_root,
                        evm_txs, account_state_root,
                    )

                    # Add block to database with sequential height
                    await self.db.add_block(
                        block_hash=block.hash,
                        block_height=next_height,
                        block_content=block_data['block_content'],
                        validator_address=block.proposer_address,
                        timestamp=block.timestamp
                    )

                    # D2.2b: persist the exchange section locally (so it is durable
                    # and replayable on this node too) and drain the mempool now
                    # that the txs are included + stored.
                    if exchange_txs:
                        try:
                            from ..exchange.block_processor import BLOCK_EXCHANGE_TXS_KEY
                            section = block_data.get(BLOCK_EXCHANGE_TXS_KEY)
                            if section:
                                await self.db.add_block_exchange_txs(block.hash, section)
                            if self._exchange_tx_source is not None:
                                self._exchange_tx_source.remove([t.tx_hash() for t in exchange_txs])
                        except Exception as e:
                            logger.warning(f"Failed to persist/drain exchange section: {e}")

                    # E-D3b: persist the (now-executed) EVM section so it is durable
                    # + replayable, and drain the included txs from the mempool.
                    if evm_txs:
                        try:
                            from ..contracts.evm_block import BLOCK_EVM_TXS_KEY
                            from ..contracts.evm_mempool import parse_eth_raw_tx
                            evm_section = block_data.get(BLOCK_EVM_TXS_KEY)
                            if evm_section:
                                await self.db.add_block_evm_txs(block.hash, evm_section)
                            if self._evm_tx_source is not None:
                                hashes = []
                                for raw in evm_txs:
                                    try:
                                        hashes.append(parse_eth_raw_tx(raw)["tx_hash"])
                                    except Exception:
                                        pass
                                self._evm_tx_source.remove(hashes)
                        except Exception as e:
                            logger.warning(f"Failed to persist/drain EVM section: {e}")

                    # Finality (observe): record this block's attestation votes +
                    # recompute, so the proposer tracks finality like importers do.
                    try:
                        from .finality import record_finality_from_block
                        await record_finality_from_block(self.db, block_data['block_content'])
                    except Exception as e:
                        logger.debug(f"finality record skipped for block #{next_height}: {e}")

                    # Broadcast block to network peers
                    if self.broadcast_callback:
                        try:
                            await self.broadcast_callback('submit_block', block_data, ignore_node_id=None, db=self.db)
                            logger.info(f"📡 Broadcast block #{next_height} to peers")
                        except Exception as e:
                            logger.warning(f"Failed to broadcast block: {e}")

                    logger.info(f"✅ Block {block.hash[:16]}... added to chain")
                
                # Wait for next slot
                await asyncio.sleep(SLOT_DURATION_SECONDS)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in block production loop: {e}", exc_info=True)
                await asyncio.sleep(SLOT_DURATION_SECONDS)
        
        logger.info("Block production loop stopped")
    
    async def _attestation_loop(self):
        """
        Main attestation loop.
        Creates and broadcasts attestations for proposed blocks.
        """
        logger.info("Attestation loop started")
        
        while self._running:
            try:
                current_slot = await self._get_current_slot()
                current_epoch = current_slot // SLOTS_PER_EPOCH
                
                # Wait briefly for block proposals to arrive
                await asyncio.sleep(SLOT_DURATION_SECONDS / 3)
                
                # Get latest block to attest to
                latest_block = await self.db.get_block_by_id(await self.db.get_next_block_id() - 1)
                if latest_block:
                    block_hash = latest_block.get('hash') or latest_block.get('block_hash')
                    
                    # Create attestation (ValidatorManager checks if we can attest)
                    attestation = await self.manager.create_attestation(
                        slot=current_slot,
                        block_hash=block_hash,
                        source_epoch=max(0, current_epoch - 1),
                        target_epoch=current_epoch
                    )
                    
                    if attestation:
                        # Submit to pool
                        submitted = await self.manager.submit_attestation(attestation)
                        if submitted:
                            logger.info(f"✅ Attested to block {block_hash[:16]}... at slot {current_slot}")
                            logger.debug(f"Attestation broadcast: epoch {current_epoch}, source {attestation.source_epoch}, target {attestation.target_epoch}")
                
                # Wait for rest of slot
                await asyncio.sleep(2 * SLOT_DURATION_SECONDS / 3)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in attestation loop: {e}", exc_info=True)
                await asyncio.sleep(SLOT_DURATION_SECONDS)
        
        logger.info("Attestation loop stopped")

    async def _epoch_validator_updates(self, epoch: int) -> None:
        """Validator-lifecycle unification: deterministically reward/penalize the
        active validator set in the consensus `validators` table based on this
        epoch's attestation participation, then log the table hash so cross-node
        convergence is observable. OBSERVE by default (`_ENFORCE_EPOCH_VALIDATOR_UPDATES`
        False → computed + logged, not written); when enforced it writes + commits.
        Pure deterministic inputs (validators table + epoch attesters), so every
        node computes the same deltas → the table stays identical. See
        docs/VALIDATOR_LIFECYCLE_UNIFICATION.md (Phase 1b/2)."""
        from .epoch_rewards import compute_epoch_reward_deltas
        from .epoch_processing import MAX_EFFECTIVE_BALANCE
        active = await self.db.get_validators(status="active")
        attesters = await self.db.get_epoch_attesters(epoch)
        rewards, penalties = compute_epoch_reward_deltas(active, attesters)
        res = await self.db.apply_epoch_validator_updates(
            rewards, penalties, activated=[], exited=[], activation_epoch=epoch,
            max_effective_balance=MAX_EFFECTIVE_BALANCE,
            enforce=_ENFORCE_EPOCH_VALIDATOR_UPDATES,
        )
        if _ENFORCE_EPOCH_VALIDATOR_UPDATES:
            await self.db.connection.commit()
        vhash = await self.db.get_validators_table_hash()
        logger.info(
            "[epoch-validators %s] epoch=%d active=%d rewarded=%d penalized=%d "
            "validators_hash=%s",
            "ENFORCE" if _ENFORCE_EPOCH_VALIDATOR_UPDATES else "observe",
            epoch, len(active), res["rewarded"], res["penalized"], vhash[:16],
        )

    async def _epoch_processing_loop(self):
        """
        Epoch boundary processing loop.
        Handles rewards, penalties, validator rotation, finalization.

        Runs the consensus validator-updates (_epoch_validator_updates) on the
        `validators` table each completed epoch, plus the legacy LifecycleManager
        (activation/exit/withdrawal queues) when available.
        """
        # BUGFIX: this loop previously imported `ValidatorLifecycleManager`, which
        # does not exist (the class is `LifecycleManager`) — the ImportError crashed
        # the coroutine before its first log, so epoch processing NEVER ran and the
        # validator set stayed frozen at genesis (the core of item 4). Import the
        # correct name and tolerate its absence so the loop always starts and the
        # consensus validator-updates below run regardless of the legacy
        # lifecycle-tables path.
        try:
            from .lifecycle import LifecycleManager
            lifecycle_mgr = LifecycleManager()
        except Exception as e:
            logger.warning(
                "Legacy lifecycle manager unavailable (%s); epoch loop will run "
                "consensus validator-updates only", e)
            lifecycle_mgr = None

        logger.info("Epoch processing loop started")
        last_processed_epoch: int = -1
        
        while self._running:
            try:
                # Process epochs only once they are FINALIZED. A just-completed
                # epoch's attestations are still propagating, so different nodes see
                # different attester sets at that instant and would compute DIVERGENT
                # reward/penalty deltas (observed: boundary epochs diverged across
                # nodes while settled middle epochs converged). Gating on the
                # finalized epoch guarantees every node processes the SAME, converged
                # attester data → identical validators-table updates. Robust to the
                # 2s-sampled loop stepping past a boundary (process the backlog in
                # order up to the finalized epoch).
                from .finality import update_finality
                try:
                    fin = await update_finality(self.db)
                    finalized_epoch = int(fin.get("finalized_epoch", -1))
                except Exception as e:
                    logger.debug(f"epoch loop: finality read failed: {e}")
                    finalized_epoch = -1

                while last_processed_epoch < finalized_epoch:
                    ep = last_processed_epoch + 1
                    logger.info(f"🔄 Processing finalized epoch {ep}")

                    if lifecycle_mgr is not None:
                        try:
                            await lifecycle_mgr.process_epoch(ep)
                            logger.info(f"✅ Epoch {ep} lifecycle processed")
                        except Exception as e:
                            logger.error(f"Legacy lifecycle process_epoch failed for {ep}: {e}")

                    # NOTE: the consensus validators-table update is NOT done here —
                    # it runs in qrdx.validator.epoch_loop.epoch_validator_update_loop,
                    # started for ALL nodes (validators + full) so the set converges
                    # network-wide (Phase 2d). This loop keeps only the legacy
                    # lifecycle-tables tracking.

                    last_processed_epoch = ep
                
                await asyncio.sleep(SLOT_DURATION_SECONDS)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in epoch processing loop: {e}", exc_info=True)
                await asyncio.sleep(SLOT_DURATION_SECONDS)
        
        logger.info("Epoch processing loop stopped")

    # ── Canary / Doomsday Monitoring (§8.5) ─────────────────────────

    def set_eth_adapter(self, adapter) -> None:
        """
        Attach an EthereumAdapter for canary balance monitoring.

        Args:
            adapter: EthereumAdapter instance
        """
        self._eth_adapter = adapter
        logger.info("ValidatorNode: EthereumAdapter attached for canary monitoring")

    def set_doomsday_protocol(self, doomsday) -> None:
        """
        Attach a DoomsdayProtocol for submitting canary attestations.

        Args:
            doomsday: DoomsdayProtocol instance
        """
        self._doomsday_protocol = doomsday
        logger.info("ValidatorNode: DoomsdayProtocol attached for canary monitoring")

    def set_exchange_tx_source(self, source) -> None:
        """
        Attach the exchange mempool the proposer pulls transactions from.

        Args:
            source: object with ``select_for_block(limit) -> [ExchangeTransaction]``
                    (the node's ``ExchangeMempool``).
        """
        self._exchange_tx_source = source
        logger.info("ValidatorNode: exchange tx source attached for block inclusion")

    def set_evm_tx_source(self, source) -> None:
        """Attach the EVM mempool the proposer pulls account-model txs from."""
        self._evm_tx_source = source
        logger.info("ValidatorNode: EVM tx source attached for block inclusion")

    async def _compute_unified_state_root(self) -> str:
        """
        E-D4: the post-block unified state root bound into the block's signed
        header — BLAKE3-512 over (UTXO root, account/EVM root, exchange root,
        token root) in fixed domain order (`crypto.hashing.unified_state_root`).

        Computed at the "after sections, before native add_block" point so an
        importer reproduces it identically after replaying the sections (its UTXO
        is likewise pre-native-apply, and account/exchange/token reflect the
        replayed sections). Each domain falls back to its empty root if unavailable.

        The token domain binds the live ``get_token_balances_root`` — token state is
        now a consensus object (deploy/transfer flow through the exchange section and
        flush to the ledger on every node, see Phase E spot inc4), so the per-node
        token root converges and is safe to enforce.
        """
        from ..crypto.hashing import unified_state_root, TOKEN_ZERO_ROOT
        try:
            utxo_root = await self.db.get_unspent_outputs_hash()
        except Exception:
            utxo_root = "0" * 64
        try:
            account_root = await self.db.get_account_state_root()
        except Exception:
            account_root = "0" * 128
        try:
            from ..exchange.state_manager import ExchangeStateManager
            exchange_root = ExchangeStateManager.get_instance().compute_state_root()
        except Exception:
            exchange_root = "0" * 128
        try:
            token_root = await self.db.get_token_balances_root()
        except Exception:
            token_root = TOKEN_ZERO_ROOT
        return unified_state_root(utxo_root or "0" * 64, account_root, exchange_root, token_root)

    def set_evm_section_producer(self, producer) -> None:
        """
        Attach the async EVM section producer (E-D3b execute-on-mine).

        ``producer(height, block_hash, timestamp, raw_txs)`` executes the section
        against EVM/account state and returns
        ``(account_state_root or None, included_raw_txs)``. Defined in main.py so
        it shares the live executor + state manager.
        """
        self._evm_section_producer = producer
        logger.info("ValidatorNode: EVM section producer attached")

    async def _canary_monitor_loop(self):
        """
        Periodically poll the Ethereum canary wallet balance.

        Runs once per epoch (SLOTS_PER_EPOCH × SLOT_DURATION seconds).
        If the canary balance has dropped below expected, generates a
        DoomsdayAttestation and submits it to the DoomsdayProtocol.

        Once doomsday is triggered, the loop exits.
        """
        epoch_seconds = SLOTS_PER_EPOCH * SLOT_DURATION_SECONDS
        logger.info(
            f"Canary monitor: polling every {epoch_seconds}s (1 epoch)"
        )

        while self._running:
            try:
                # Skip if doomsday already active
                if self._doomsday_protocol and self._doomsday_protocol.is_active:
                    logger.info(
                        "Canary monitor: doomsday already active — stopping"
                    )
                    break

                if self._eth_adapter is None or self._doomsday_protocol is None:
                    await asyncio.sleep(epoch_seconds)
                    continue

                if self.wallet is None:
                    await asyncio.sleep(epoch_seconds)
                    continue

                # Generate attestation (returns None if canary is safe)
                attestation = self._eth_adapter.generate_doomsday_attestation(
                    validator_address=self.wallet.address,
                )

                if attestation is not None:
                    logger.warning(
                        f"Canary monitor: drain detected — submitting attestation "
                        f"(balance={attestation.observed_balance}, "
                        f"block={attestation.observed_block_height})"
                    )
                    triggered = self._doomsday_protocol.submit_canary_attestation(
                        attestation
                    )
                    if triggered:
                        logger.critical(
                            "Canary monitor: DOOMSDAY TRIGGERED by validator quorum"
                        )
                        break
                else:
                    logger.debug("Canary monitor: canary is safe")

                await asyncio.sleep(epoch_seconds)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(
                    f"Error in canary monitor loop: {exc}", exc_info=True
                )
                await asyncio.sleep(epoch_seconds)

        logger.info("Canary monitor loop stopped")
    
    async def _get_current_slot(self) -> int:
        """
        Calculate current slot based on genesis time and slot duration.
        
        Returns:
            Current slot number
        """
        # Get genesis time from database or use a default
        now = datetime.now(timezone.utc)

        # Derive genesis time from the genesis block's timestamp. CRITICAL: the
        # genesis block stores its timestamp as an ISO-8601 TEXT string (e.g.
        # "2026-06-08 13:57:09+00:00"), unlike later blocks which use integer Unix
        # timestamps. The previous code called datetime.fromtimestamp() on that
        # string, which raised and fell back to `now` on EVERY call — pinning the
        # slot to 0 forever and degenerating the whole PoS proposer rotation
        # (every validator thought it was the slot-0 proposer → competing blocks →
        # reorg churn). Parse both forms robustly.
        genesis_time = now  # fallback only if genesis is genuinely unavailable
        try:
            genesis_block = await self.db.get_block_by_id(0)
            parsed = parse_block_timestamp(genesis_block.get('timestamp') if genesis_block else None)
            if parsed is not None:
                genesis_time = parsed
        except Exception as e:
            logger.debug(f"slot: could not read genesis timestamp, using now: {e}")
            genesis_time = now

        elapsed = (now - genesis_time).total_seconds()
        return max(0, int(elapsed // SLOT_DURATION_SECONDS))


async def initialize_validator_node(db, wallet_path: str, password: str = "", broadcast_callback=None) -> Optional[ValidatorNode]:
    """
    Initialize and start a validator node.
    
    Args:
        db: Database instance
        wallet_path: Path to PQ wallet JSON
        password: Wallet password
        broadcast_callback: Async function to broadcast blocks to peers
    
    Returns:
        ValidatorNode instance if successful, None otherwise
    """
    validator = ValidatorNode(db, wallet_path, password, broadcast_callback)
    
    if await validator.initialize():
        await validator.start()
        return validator
    
    return None
