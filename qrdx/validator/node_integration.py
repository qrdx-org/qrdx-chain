"""
QRDX Validator Node Integration

This module integrates the PoS consensus validator into the node lifecycle.
It handles validator initialization, block production, attestation, epoch processing and
oracle votes (prices, bridge deposits and chain heads).
"""

import asyncio
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from ..constants import SLOT_DURATION, SLOTS_PER_EPOCH
from ..logger import get_logger
from ..node.observability import Phases
from ..wallet_v2.pq_wallet import PQWallet
from .config import ValidatorConfig
from .keystore import ValidatorKeyError
from .manager import ValidatorManager
from .types import Validator, ValidatorSet, ValidatorStatus

logger = get_logger(__name__)

# Slot duration in seconds (a float: the chain spec sets it in milliseconds).
SLOT_DURATION_SECONDS = float(SLOT_DURATION)

# Proposer propagation grace (fork PREVENTION). Env-gated for A/B measurement; see the
# comment at the use site and "Block history did not converge" in docs/KNOWN_ISSUES.md.
_PROPOSER_PROPAGATION_GRACE = os.getenv("QRDX_PROPOSER_PROPAGATION_GRACE", "0").lower() in (
    "1",
    "true",
    "yes",
)
# How long a proposer waits for the previous slot's block before building beside it: until it
# lands, at most this long (it slept the whole half slot, even when the block landed at once).
# Waiting a full slot was tried under load and did not reduce competing blocks: the block that
# is late is usually still being built (docs/PERFORMANCE.md).
_PROPOSER_PROPAGATION_GRACE_SECONDS = SLOT_DURATION_SECONDS * float(
    os.environ.get("QRDX_PROPOSER_GRACE_SLOTS", "0.5")
)

# What share of a slot a proposer spends building a block, start to signature, and the fewest
# exchange operations it includes (docs/PERFORMANCE.md). The chain allows a block
# BLOCK_EXCHANGE_GAS_LIMIT of gas, 2,000 transfers; a proposer includes what it measures it can
# build in this share of the slot. Its peers take about as long to import the block, and the
# next proposer builds on it in the next slot: build, propagation and import must fit one slot.
# Filled to the limit, a block took a second to build and as long to import: slots were missed
# and proposers built on stale parents. Sized by its exchange section's time alone (the build is
# about 1.7 times that), a backlog grew blocks until the next proposer built beside them, and the
# block rate fell to one a second. A faster node fills more of the limit.
EXCHANGE_BUILD_SHARE = float(os.environ.get("QRDX_EXCHANGE_BUILD_SHARE", "0.3"))
# Under deferred execution (qrdx/post_state.py) a proposer sends its block before running it,
# and what must fit the slot is one run of it — the next proposer's import — not a build and an
# import: the share is of the proposer's whole work, start to the root of what the block leaves.
DEFERRED_BUILD_SHARE = float(os.environ.get("QRDX_DEFERRED_BUILD_SHARE", "0.5"))
EXCHANGE_BUILD_MIN = 64
EXCHANGE_BUILD_MAX = 10_000
EXCHANGE_BUILD_START = 500


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


def assemble_pos_block_data(
    block,
    height: int,
    exchange_txs=None,
    exchange_state_root: Optional[str] = None,
    evm_txs=None,
    account_state_root: Optional[str] = None,
) -> dict:
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
        "id": height,
        "block_content": block_content,
        "block_hash": block.hash,
        "validator_address": block.proposer_address,
        "timestamp": getattr(block, "timestamp", 0),
    }
    if exchange_txs:
        # Imported lazily to avoid a hard dependency when the exchange module
        # is not in use.
        from ..exchange.block_processor import BLOCK_EXCHANGE_TXS_KEY, encode_exchange_txs

        data[BLOCK_EXCHANGE_TXS_KEY] = encode_exchange_txs(exchange_txs, height)
        # Kept beside the block, never sent: the decoded operations, which name the section by
        # hash when it is relayed compact (qrdx/node/block_relay.py).
        data["_exchange_objects"] = list(exchange_txs)
        if exchange_state_root:
            data["exchange_state_root"] = exchange_state_root
    if evm_txs:
        from ..contracts.evm_block import BLOCK_EVM_TXS_KEY, encode_evm_txs

        data[BLOCK_EVM_TXS_KEY] = encode_evm_txs(evm_txs)
        if account_state_root:
            data["account_state_root"] = account_state_root
    return data


@dataclass
class _Ahead:
    """A block ``ValidatorNode.propose_ahead`` signed and sent before its parent ran."""

    block: Any
    data: Any
    height: int
    slot: int
    epoch: int
    timestamp: Any
    exchange_txs: List[Any]
    evm_raws: List[str]
    phases: Phases
    locked_at: float
    sent_at: float
    broadcast: Optional[asyncio.Future]
    finished: bool = False  # (its parent was stored: ``finish_ahead`` ran or is running)


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
        self._genesis_ts: Optional[float] = None  # genesis block time (unix), read once
        self._block_production_task: Optional[asyncio.Task] = None
        self._attestation_task: Optional[asyncio.Task] = None
        self._epoch_processing_task: Optional[asyncio.Task] = None

        # ── Exchange tx inclusion (Phase D2.2) ──
        # An object exposing select_for_block(limit) -> [ExchangeTransaction]
        # (the node's ExchangeMempool). Set via set_exchange_tx_source().
        self._exchange_tx_source = None
        # How many exchange operations the next block selects (EXCHANGE_BUILD_SHARE): grown while
        # full blocks run inside the share of a slot, cut in proportion when one does not.
        self._exchange_limit = EXCHANGE_BUILD_START

        # ── EVM tx inclusion (E-D3b execute-on-mine) ──
        # _evm_tx_source: the node's EVMMempool (select_for_block / remove).
        # _evm_section_producer: async (height, hash, ts, raw_txs) ->
        #   (account_state_root or None, included_raw_txs) — executes the section
        #   against EVM state and declares the root. Both set from main.py once
        #   the EVM system is initialized.
        self._evm_tx_source = None
        self._evm_section_producer = None
        # deferred execution: async (height, hash, ts, raw_txs, None) -> (ok, err)
        self._evm_section_runner = None
        # The node's block-processing lock (main.block_processing_lock), set from main.py.
        # None only when running standalone.
        self._block_processing_lock = None
        # () -> bool: True while the node is adopting a peer's chain (main.py); the proposer
        # then skips its slot rather than build on a tip that is about to change.
        self._proposal_guard = None
        self._last_skip_reason = None
        self._sent_wall: Dict[str, float] = {}  # block hash → when it was sent (wall clock)
        self._restore_hook = None  # main._restore_after_rejected_block
        # Slashing protection and the doppelganger check (set in initialize()).
        self.protection: Optional[Any] = None
        self._doppelganger: Optional[Any] = None

        logger.info(f"ValidatorNode initialized for wallet: {validator_wallet_path}")

    async def initialize(self) -> bool:
        """
        Load wallet and initialize validator manager.

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # The key must come from an encrypted keystore on a real network; a plaintext key
            # is accepted on dev networks only (qrdx/validator/keystore.py). The loader checks
            # that the file's address, public key and secret key all belong together: a
            # validator proposing under an identity other than its registration never converges.
            from .. import chain_spec as _chain_spec
            from .keystore import load_validator_wallet

            logger.info(f"Loading PQ wallet from {self.wallet_path}")
            self.wallet = load_validator_wallet(
                self.wallet_path, self.password, allow_plaintext=_chain_spec.active().dev
            )
            self.password = ""  # no longer needed once the key is open
            logger.info(f"Wallet loaded: {self.wallet.address}")

            # Create validator configuration (use defaults)
            self.config = ValidatorConfig(enabled=True)

            # Initialize ValidatorManager with database
            logger.info("Initializing ValidatorManager...")
            self.manager = ValidatorManager(
                wallet=self.wallet,
                config=self.config,
                database=self.db,  # Pass database for stake persistence
            )

            # Slashing protection: every block and vote recorded before it is signed, in a
            # record of its own (it survives a resync of the chain database) that one process
            # holds at a time. The chain database's older vote record is folded in. Then the
            # doppelganger check, for the same key signing on another machine.
            from .doppelganger import DoppelgangerGuard, configured_epochs
            from .slashing_protection import SlashingProtection, default_path, network_key

            self.protection = await SlashingProtection.open(default_path(), network_key())
            if await self.protection.import_legacy_votes(self.db):
                logger.info("Folded the chain database's vote record into slashing protection")
            self.manager.slashing_protection = self.protection
            self._doppelganger = DoppelgangerGuard(
                self.db,
                self.protection,
                self.wallet.address,
                configured_epochs(_chain_spec.active().dev),
                SLOTS_PER_EPOCH,
            )
            logger.info(f"Slashing protection: {self.protection.path}")

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
                    epoch=0,
                )
            else:
                logger.info(f"Validator already has sufficient stake: {current_stake} QRDX")

            # Initialize validator state (for now, set to ACTIVE immediately)
            # In production, validators would go through activation queue
            actual_stake = await self.manager.stake_manager.get_stake(self.wallet.address)
            effective_stake = await self.manager.stake_manager.get_effective_stake(
                self.wallet.address
            )

            # Verify meets minimum stake before creating validator
            if effective_stake < min_stake:
                raise Exception(
                    f"Insufficient stake: {effective_stake} < {min_stake} QRDX required"
                )

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
                index=0,
            )

            # Build the validator set from the CONSISTENT `validators` table
            # (seeded identically on every node from the shared genesis), NOT from
            # `validator_stakes` (which holds only each node's own self-deposit and
            # so differs per node). Using the consistent set is what lets every
            # node derive the SAME proposer per slot → one proposer per slot
            # instead of every node believing it is the sole proposer.
            all_validators: List[Any] = []
            try:
                validator_rows = await self.db.get_validators()
            except Exception as e:
                logger.warning(f"Could not load validators table: {e}")
                validator_rows = []

            for vr in validator_rows:
                addr = vr.get("address")
                if not addr:
                    continue
                # EXITING is eligible: a validator that requested exit keeps proposing
                # through unbonding (Phase 3c), leaving the set only at its finalized
                # exit_epoch. No-op until exits exist (no row is 'exiting' yet).
                status_str = str(vr.get("status", "active")).upper()
                if status_str not in ("ACTIVE", "PENDING", "EXITING"):
                    continue
                eff = Decimal(str(vr.get("effective_stake") or vr.get("stake") or 0))
                is_self = addr == self.wallet.address
                all_validators.append(
                    Validator(
                        address=addr,
                        public_key=self.wallet.public_key if is_self else b"",
                        stake=eff,
                        effective_stake=eff,
                        status=ValidatorStatus.ACTIVE,
                        activation_epoch=0,
                        slashed=bool(vr.get("slashed")),
                        uptime_score=1.0,
                        index=len(all_validators),
                    )
                )

            # Safety net: if the table didn't include us yet, add self so we can
            # still participate (single-validator bootstrap).
            if not any(v.address == self.wallet.address for v in all_validators):
                all_validators.append(self.manager._validator)

            logger.info(
                f"Validator set built from validators table: {len(all_validators)} "
                f"members: {[v.address[:16] + '...' for v in all_validators]}"
            )

            # Calculate total stake
            total_stake = sum((v.stake for v in all_validators), Decimal("0"))

            self.manager._validator_set = ValidatorSet(
                epoch=0, validators=all_validators, total_stake=total_stake
            )

            logger.info(
                f"Validator set created with {len(all_validators)} validators (total stake: {total_stake} QRDX)"
            )

            logger.info(f"Validator stake: {actual_stake} QRDX (effective: {effective_stake} QRDX)")

            logger.info(f"✅ Validator registered and activated: {self.wallet.address}")
            logger.info("✅ Validator initialization complete")
            return True

        except ValidatorKeyError:
            raise  # the operator asked for a validator: never fall back to running without one
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
        self._oracle_task = asyncio.create_task(self._oracle_vote_loop())
        from . import pipeline

        pipeline.PROPOSER = self  # (the live import may ask it to build before a parent runs)
        if os.environ.get("QRDX_LOOP_LAG_LOG") == "1":
            self._lag_task = asyncio.create_task(self._loop_lag_monitor())

        logger.info("✅ Validator tasks started")

    async def stop(self):
        """Stop validator consensus duties."""
        self._running = False
        logger.info("Stopping validator consensus duties...")
        from . import pipeline

        if pipeline.PROPOSER is self:
            pipeline.PROPOSER = None

        # Cancel tasks
        if self._block_production_task:
            self._block_production_task.cancel()
        if self._attestation_task:
            self._attestation_task.cancel()
        if self._epoch_processing_task:
            self._epoch_processing_task.cancel()
        if getattr(self, "_oracle_task", None):
            self._oracle_task.cancel()
        if self.protection is not None:
            await self.protection.close()
            self.protection = None

        logger.info("Validator stopped")

    async def _block_production_loop(self):
        """
        Main block production loop.
        Checks if this validator is the proposer for the current slot and produces blocks.
        """
        logger.info("Block production loop started")

        last_slot = -1
        current_slot = 0
        retried_slot = -1  # (a slot whose tip moved while preparing is tried once more)
        iteration_started = time.perf_counter()
        while self._running:
            try:
                # Get current slot and epoch — each slot is handled once, at its start.
                current_slot = await self._get_current_slot()
                if current_slot <= last_slot:
                    await self._sleep_until(last_slot + 1)
                    continue
                if last_slot >= 0 and current_slot > last_slot + 1:
                    # (slots that passed while the last one was handled: never tried)
                    logger.info(
                        f"⏱  Slot loop at slot {current_slot}: slots {last_slot + 1}.."
                        f"{current_slot - 1} passed while slot {last_slot} was handled "
                        f"({1000 * (time.perf_counter() - iteration_started):.0f} ms)"
                    )
                iteration_started = time.perf_counter()
                last_slot = current_slot
                current_epoch = current_slot // SLOTS_PER_EPOCH
                # (what the slot's handling spends before it builds, for the proposal's log line:
                # how late the loop woke, the set and rank, the wait for an in-flight parent)
                phases = Phases()
                woke_at = await self._into_slot(current_slot)

                logger.debug(
                    f"📍 Checking slot {current_slot} (epoch {current_epoch}) for block proposal..."
                )

                # Get latest block from database for parent hash and next height
                next_block_id = await self.db.get_next_block_id()
                latest_block = await self._read_block_header(next_block_id - 1)
                parent_hash = (
                    latest_block.get("hash") or latest_block.get("block_hash")
                    if latest_block
                    else "0" * 64
                )
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
                phases.mark("prep")
                await self._refresh_validator_set(current_slot)
                rank = await self.manager.proposer_rank(current_slot)
                phases.mark("rank")
                if rank is None:
                    await self._sleep_until(current_slot + 1)
                    continue
                if rank > 0:
                    await asyncio.sleep(min(rank, 3) * (SLOT_DURATION_SECONDS / 2))

                # Propagation grace: if our tip is not from the IMMEDIATELY previous slot,
                # that slot's block may simply not have reached us yet. Proposing now would
                # put a competing block at the same height off the same parent — the
                # adjacent-slot race measured as the cause of the persistent block-history
                # fork (docs/KNOWN_ISSUES.md, "Block history did not converge"). Waiting
                # briefly lets it arrive; the tip
                # re-check below then skips this height and the next iteration builds ON TOP
                # of it instead of racing it. A genuinely empty previous slot costs only the
                # grace period. Behaviour-only: no consensus rule changes, so it cannot make
                # any block invalid.
                # With a pipelined proposer (qrdx/validator/pipeline.py) the wait is what lets a late
                # parent be built on: arriving during it, the import builds this slot's block on
                # it before running it — rather than this loop racing it from the grandparent.
                from . import pipeline

                grace = _PROPOSER_PROPAGATION_GRACE or pipeline.enabled()
                if grace and rank == 0 and latest_block:
                    from .. import chain_index

                    try:
                        tip_slot = await chain_index.slot_at(self.db, next_block_id - 1)
                    except Exception:
                        tip_slot = None
                    if tip_slot is not None and int(tip_slot) < current_slot - 1:
                        await self._await_tip_change(_PROPOSER_PROPAGATION_GRACE_SECONDS)
                phases.mark("grace")

                # Everything from the tip re-check to storing the block runs under the node's
                # block-processing lock — the one every import path and the reorg rebuild
                # hold. Without it the proposer interleaved with a rebuild in progress (the
                # rebuild yields at every database await): it computed its unified root over
                # half-rebuilt state, and importers rejected the declared root (the recurring
                # E-D4 observe mismatch). A block's sections could equally land in the middle
                # of a replay, out of order. The block goes to peers as soon as it is signed,
                # while it is stored here: peers' import overlaps this node's writes.
                _build_started = time.perf_counter()
                self._woke_at = woke_at
                broadcast: Optional[asyncio.Task] = None
                async with self._production_lock():
                    phases.mark("lock")
                    _locked_at = time.perf_counter()  # (waiting behind an import is not building)
                    # Re-check the tip for EVERY rank, not just backups.
                    #
                    # next_height/parent_hash were captured at the top of this iteration, and
                    # the section work below (exchange execution, EVM execution, root
                    # computation) takes long enough for a block to land meanwhile. Proposing
                    # at a height that is already filled creates a competing block at that
                    # height off the same parent — precisely the adjacent-slot race that
                    # leaves a permanent fork (docs/KNOWN_ISSUES.md, "Block history did not
                    # converge"). Nothing is lost by
                    # skipping: the height we would have claimed is already taken, and the
                    # next iteration proposes on top of the new tip.
                    #
                    # This cannot fix the fork on its own — the real race is a proposer that
                    # has not yet RECEIVED the previous slot's block, which no local check can
                    # see — but it removes the self-inflicted half, where the block HAD
                    # arrived and we proposed against a stale height anyway.
                    #
                    # Placed BEFORE any section execution deliberately: the exchange and EVM
                    # sections commit as they execute, so aborting after them would leave
                    # committed state with no block to carry it.
                    if (await self.db.get_next_block_id()) != next_block_id:
                        # The block that landed is most often the previous slot's, imported while
                        # this one waited for the lock: build on it, in this slot, from the top
                        # (eligibility and every check again, on the new tip). Once a slot. With a
                        # pipelined proposer next (qrdx/validator/pipeline.py) a block sent late
                        # in its slot is built on before it runs, so it is worth building while
                        # any of the slot is left: a skipped slot is a block lost for good.
                        if (
                            retried_slot != current_slot
                            and await self._slot_left(current_slot) > self._retry_share()
                        ):
                            retried_slot, last_slot = current_slot, current_slot - 1
                            continue
                        logger.info(
                            "⏭  Skipping slot %s: height %s was filled while preparing",
                            current_slot,
                            next_height,
                        )
                        continue
                    # The same height can come back with a different tip: a reorg can remove
                    # the tip read above and apply another block at its height. The tip was
                    # then read as missing, and the block was built on an all-zero parent,
                    # which every peer refused.
                    tip_now = await self._read_block_header(next_block_id - 1)
                    tip_hash = (
                        (tip_now.get("hash") or tip_now.get("block_hash")) if tip_now else None
                    )
                    if not tip_hash or tip_hash != parent_hash:
                        if (
                            retried_slot != current_slot
                            and await self._slot_left(current_slot) > self._retry_share()
                        ):
                            retried_slot, last_slot = current_slot, current_slot - 1
                            continue
                        logger.info(
                            "⏭  Skipping slot %s: the tip changed while preparing", current_slot
                        )
                        continue

                    # Mid-adoption of a peer's chain the tip is about to change: the rollback
                    # has happened, the peer's blocks have not landed yet. A block built now
                    # would compete with the very chain being adopted and make the adoption
                    # fail on the height it just took. Nor before the node's first sync with
                    # its peers: its tip may be far behind the network's.
                    reason = self._proposal_guard() if self._proposal_guard is not None else None
                    reason = reason or await self._block_signing_refusal(current_slot)
                    reason = reason or self._behind_the_network(next_height)
                    if reason:
                        if reason != self._last_skip_reason:
                            logger.info("⏭  Skipping slot %s: %s", current_slot, reason)
                        self._last_skip_reason = reason
                        continue
                    self._last_skip_reason = None

                    # A block's slot must be later than its parent's (verify_slot_progression):
                    # a tip from this slot or a later one — a peer's clock running ahead — means
                    # there is nothing valid to build here.
                    from .. import chain_index

                    tip_slot = await chain_index.slot_at(self.db, next_block_id - 1)
                    if tip_slot is not None and current_slot <= tip_slot:
                        logger.info(
                            "⏭  Skipping slot %s: the tip is already at slot %s",
                            current_slot,
                            tip_slot,
                        )
                        continue

                    # Everything the block changes from here is recorded in the undo journal under its
                    # height (a checkpoint first if it opens an epoch) — what makes a later reorg cheap.
                    from ..derived_state_rebuild import before_block

                    phases.mark("checks")
                    async with await before_block(self.db, next_height, current_epoch):
                        phases.mark("journal")
                        # The block's timestamp, fixed BEFORE the sections execute and passed to
                        # propose_block so the block carries exactly this value: importers execute
                        # the sections at the block's timestamp, and the exchange judges funding,
                        # oracle staleness and swap deadlines by it. Under ``slot_timestamps``
                        # it is the slot's start time, which importers require.
                        from .. import chain_spec as _spec
                        from .block_verification import genesis_time, slot_timestamp

                        origin = await genesis_time(self.db)
                        if _spec.is_active("slot_timestamps", next_height) and origin is not None:
                            block_timestamp = slot_timestamp(origin, current_slot)
                        else:
                            block_timestamp = int(datetime.now(timezone.utc).timestamp())

                        # The base fees the parent sets (qrdx/fee_market.py): the block carries
                        # them, and only transactions offering at least them.
                        from ..fee_market import base_fees_at

                        base_fees = await base_fees_at(self.db, next_height)

                        # Deferred execution (qrdx/post_state.py): judged on the parent's state, signed
                        # with its root and sent, then run. Otherwise run first and sign what it leaves.
                        from .. import post_state

                        if post_state.active(next_height):
                            block, block_data, broadcast = await self._build_deferred(
                                next_height,
                                current_slot,
                                current_epoch,
                                parent_hash,
                                block_timestamp,
                                base_fees,
                                pending_txs,
                                phases,
                                _locked_at,
                            )
                        else:
                            # Exchange section: select + execute (commit on success). Drop on
                            # failure rather than ship a bad block.
                            exchange_txs = []
                            exchange_state_root = None
                            if self._exchange_tx_source is not None:
                                try:
                                    exchange_txs = (
                                        self._exchange_tx_source.select_for_block(
                                            limit=self._exchange_budget(),
                                            min_price=base_fees[1],
                                            height=next_height,
                                        )
                                        or []
                                    )
                                    from .. import chain_spec
                                    from ..exchange.fair_ordering import FEATURE, fair_order

                                    if exchange_txs and chain_spec.is_active(FEATURE, next_height):
                                        exchange_txs = fair_order(exchange_txs)
                                    # Only transactions that will run (``exchange_inclusion``),
                                    # judged before anything is pre-loaded; the rest leave this
                                    # node's mempool (the sender may send them again).
                                    from ..exchange.block_processor import includable_exchange_txs

                                    exchange_txs, refused = await includable_exchange_txs(
                                        self.db,
                                        exchange_txs,
                                        next_height,
                                        float(block_timestamp),
                                        base_fees[1],
                                    )
                                    if refused:
                                        logger.info(
                                            f"Leaving {len(refused)} exchange tx(s) out of block "
                                            f"#{next_height}: {refused[0][1]}"
                                        )
                                        self._exchange_tx_source.remove(
                                            [t.tx_hash() for t, _why in refused]
                                        )
                                except Exception as e:
                                    logger.warning(f"Exchange tx selection failed: {e}")
                                    exchange_txs = []
                                phases.mark("select")
                                if exchange_txs:
                                    try:
                                        from ..exchange.block_processor import (
                                            ENFORCE_EXCHANGE_COLLATERAL,
                                            apply_enforcement,
                                            flush_exchange_balance_deltas,
                                            flush_token_balance_deltas,
                                            flush_validator_lifecycle_deltas,
                                            preload_sender_balances,
                                            preload_token_balances,
                                            process_exchange_transactions,
                                        )
                                        from ..exchange.state_manager import ExchangeStateManager

                                        mgr = ExchangeStateManager.get_instance()
                                        apply_enforcement(mgr)
                                        # Phase E: pre-load senders' real QRDX + token balances for
                                        # the collateral + spot-sufficiency checks during processing.
                                        await preload_sender_balances(
                                            self.db, exchange_txs, mgr, next_height
                                        )
                                        await preload_token_balances(self.db, exchange_txs, mgr)
                                        phases.mark("preload")
                                        ok, err, root = process_exchange_transactions(
                                            next_height,
                                            float(block_timestamp),
                                            exchange_txs,
                                            mgr,
                                        )
                                        phases.mark("execute")
                                        if ok:
                                            mgr.commit_block()
                                            # Phase E: flush margin debits to account_state +
                                            # token moves to the token ledger (before the unified
                                            # root is computed below).
                                            await flush_exchange_balance_deltas(
                                                self.db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL
                                            )
                                            await flush_token_balance_deltas(self.db, mgr)
                                            await flush_validator_lifecycle_deltas(
                                                self.db,
                                                mgr,
                                                block_epoch=current_epoch,
                                                block_height=next_height,
                                            )
                                            exchange_state_root = root
                                            phases.mark("flush")
                                            logger.info(
                                                f"📦 Including {len(exchange_txs)} exchange tx(s) in "
                                                f"block #{next_height} (root={root[:16]}...)"
                                            )
                                        else:
                                            logger.warning(
                                                f"Exchange execution failed, dropping section: {err}"
                                            )
                                            exchange_txs = []
                                            await self._restore_state(next_height, err)
                                    except Exception as e:
                                        logger.warning(
                                            f"Exchange execution error, dropping section: {e}"
                                        )
                                        exchange_txs = []
                                        await self._restore_state(next_height, str(e))

                            # A block without exchange transactions — none selected, or the section
                            # dropped — still ticks: mark prices (and later liquidations and funding)
                            # advance on every block. Importers and the rebuild tick identically.
                            if not exchange_txs:
                                try:
                                    from ..exchange.block_processor import (
                                        ensure_oracle_committee,
                                        tick_and_flush,
                                    )
                                    from ..exchange.state_manager import ExchangeStateManager

                                    await ensure_oracle_committee(
                                        self.db, ExchangeStateManager.get_instance(), next_height
                                    )
                                    await tick_and_flush(
                                        self.db, next_height, float(block_timestamp)
                                    )
                                except Exception as e:
                                    logger.error(
                                        f"Exchange tick failed for block #{next_height}: {e}"
                                    )
                                phases.mark("tick")

                            # EVM/account section: execute-on-mine.
                            evm_txs = []
                            account_state_root = None
                            if (
                                self._evm_tx_source is not None
                                and self._evm_section_producer is not None
                            ):
                                try:
                                    from ..block_limits import evm_gas_limit_at

                                    evm_raws = (
                                        self._evm_tx_source.select_for_block(
                                            min_price=base_fees[0],
                                            gas_limit=evm_gas_limit_at(next_height),
                                        )
                                        or []
                                    )
                                except Exception as e:
                                    logger.warning(f"EVM tx selection failed: {e}")
                                    evm_raws = []
                                # A delegated (system-wallet) spend whose controller's authority has
                                # ended — sunset height reached, or frozen by governance — can never be
                                # included again: evict it, so the controller's later nonces do not
                                # queue behind it forever.
                                if evm_raws:
                                    from ..contracts.evm_mempool import (
                                        parse_eth_raw_tx,
                                        verify_delegated_spend,
                                    )

                                    kept, refused = [], []
                                    for raw in evm_raws:
                                        ok, why = await verify_delegated_spend(
                                            self.db, raw, next_height
                                        )
                                        (kept if ok else refused).append((raw, why))
                                    if refused:
                                        hashes = []
                                        for raw, why in refused:
                                            try:
                                                hashes.append(parse_eth_raw_tx(raw)["tx_hash"])
                                            except Exception:
                                                pass
                                            logger.warning(
                                                f"Evicting delegated spend from the EVM mempool: {why}"
                                            )
                                        self._evm_tx_source.remove(hashes)
                                    evm_raws = [raw for raw, _why in kept]
                                if evm_raws:
                                    try:
                                        account_state_root, evm_txs = (
                                            await self._evm_section_producer(
                                                next_height,
                                                parent_hash,
                                                block_timestamp,
                                                evm_raws,
                                            )
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
                                        logger.warning(
                                            f"EVM section production failed, dropping section: {e}"
                                        )
                                        evm_txs = []
                                        account_state_root = None

                            # Stake withdrawals: credit exited validators' principal as part of THIS
                            # block's state transition. After the EVM section (so the section's own
                            # declared account root is unaffected on both sides) and before the
                            # unified root (so E-D4 binds the credits). Every importer runs the same
                            # computation at the same point. See qrdx/validator/withdrawals.py.
                            try:
                                from .withdrawals import process_block_withdrawals

                                await process_block_withdrawals(self.db, next_height, current_epoch)
                            except Exception as e:
                                logger.error(
                                    f"Withdrawal processing failed for block #{next_height}: {e}"
                                )
                            phases.mark("evm+withdrawals")

                            # E-D4: compute the post-block unified state root (UTXO + account +
                            # exchange) and bind it into the block's signed header. The importer
                            # recomputes it after replaying the sections and verifies it matches
                            # this signed root — full cryptographic binding of all state domains.
                            unified_root = await self._compute_unified_state_root(
                                next_height, current_slot
                            )
                            phases.mark("root")

                            # The sections in their wire form: the header commits to them
                            # (body_root), exactly as importers will receive them.
                            from ..contracts.evm_block import encode_evm_txs
                            from ..exchange.block_processor import encode_exchange_txs
                            from .types import AlreadyProposedError

                            try:
                                block = await self.manager.propose_block(
                                    slot=current_slot,
                                    parent_hash=parent_hash,
                                    transactions=pending_txs[:100],  # Limit to 100 txs per block
                                    state_root=unified_root,
                                    timestamp=block_timestamp,
                                    exchange_section=(
                                        encode_exchange_txs(exchange_txs, next_height)
                                        if exchange_txs
                                        else []
                                    ),
                                    evm_section=encode_evm_txs(evm_txs) if evm_txs else [],
                                    base_fees=base_fees,
                                )
                            except AlreadyProposedError:
                                # Slashing protection refused to sign: the sections already ran
                                # for this height, so undo them before giving up the slot.
                                await self._restore_state(
                                    next_height, "slashing protection refused"
                                )
                                block = None

                            phases.mark("sign")
                            if block and exchange_txs:
                                self._measure_exchange(
                                    len(exchange_txs), time.perf_counter() - _locked_at
                                )
                            if block:
                                logger.info(
                                    f"📦 Proposed block #{next_height} at slot {current_slot}: {block.hash[:16]}... "
                                    f"({1000 * (time.perf_counter() - _build_started):.0f} ms: {phases})"
                                )

                                block_data = assemble_pos_block_data(
                                    block,
                                    next_height,
                                    exchange_txs,
                                    exchange_state_root,
                                    evm_txs,
                                    account_state_root,
                                )
                                if self.broadcast_callback:
                                    broadcast = asyncio.ensure_future(
                                        self.broadcast_callback(
                                            "submit_block",
                                            block_data,
                                            ignore_node_id=None,
                                            db=self.db,
                                        )
                                    )

                                # Add block to database with sequential height
                                await self.db.add_block(
                                    block_hash=block.hash,
                                    block_height=next_height,
                                    block_content=block_data["block_content"],
                                    validator_address=block.proposer_address,
                                    timestamp=block.timestamp,
                                )

                                # D2.2b: persist the exchange section locally (so it is durable
                                # and replayable on this node too) and drain the mempool now
                                # that the txs are included + stored.
                                if exchange_txs:
                                    try:
                                        from ..exchange.block_processor import (
                                            BLOCK_EXCHANGE_TXS_KEY,
                                        )

                                        section = block_data.get(BLOCK_EXCHANGE_TXS_KEY)
                                        if section:
                                            await self.db.add_block_exchange_txs(
                                                block.hash,
                                                section,
                                                block_data.get("_exchange_objects"),
                                            )
                                        if self._exchange_tx_source is not None:
                                            self._exchange_tx_source.remove(
                                                [t.tx_hash() for t in exchange_txs]
                                            )
                                    except Exception as e:
                                        logger.warning(
                                            f"Failed to persist/drain exchange section: {e}"
                                        )

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

                                    await record_finality_from_block(
                                        self.db, block_data["block_content"]
                                    )
                                except Exception as e:
                                    logger.debug(
                                        f"finality record skipped for block #{next_height}: {e}"
                                    )

                # The broadcast, begun once the block was signed, finishes on its own: peers
                # answer once they have imported the block, and waiting for them here (100-300
                # ms under load) held this loop past its next slot — lost without a try when
                # this validator proposes two slots running.
                if broadcast is not None:
                    self._follow_broadcast(broadcast, next_height if block else None)
                if block:
                    logger.info(f"✅ Block {block.hash[:16]}... added to chain")

                # Wait for the next slot to START (not a fixed delay after this one's work).
                await self._sleep_until(current_slot + 1)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in block production loop: {e}", exc_info=True)
                await self._sleep_until(current_slot + 1)

        logger.info("Block production loop stopped")

    async def _attestation_loop(self):
        """
        Main attestation loop.
        Creates and broadcasts attestations for proposed blocks.
        """
        logger.info("Attestation loop started")

        from . import ffg

        voted: set = set()  # epochs this process has voted in (the record is the authority)
        last_slot = -1
        current_slot = 0
        while self._running:
            try:
                current_slot = await self._get_current_slot()
                if current_slot <= last_slot:
                    await self._sleep_until(last_slot + 1, 1 / 3)
                    continue
                last_slot = current_slot
                current_epoch = current_slot // SLOTS_PER_EPOCH

                # One FFG vote per epoch (qrdx/validator/ffg.py), from the epoch's vote slot on —
                # a third into the slot, so the slot's block has had time to arrive. Later slots
                # of the epoch retry only if the vote has not been cast (after a restart, say);
                # the signing record makes a second, different vote impossible.
                if current_slot < ffg.vote_slot(current_epoch) or current_epoch in voted:
                    continue
                # Not before the node's first sync with its peers, nor mid-adoption of a peer's
                # chain: the checkpoint voted for could be one of a chain the network has left.
                # A later slot of the epoch retries.
                if self._proposal_guard is not None and self._proposal_guard():
                    continue
                if await self._signing_hold(current_slot):
                    continue
                await self._sleep_until(current_slot, 1 / 3)
                if await self._cast_vote(current_slot, current_epoch):
                    voted.add(current_epoch)
                    voted.discard(current_epoch - 2)

                # Then the next slot (the loop head waits until a third into it).

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in attestation loop: {e}", exc_info=True)
                await self._sleep_until(current_slot + 1)

        logger.info("Attestation loop stopped")

    async def _refresh_validator_set(self, slot: int) -> None:
        """The set the proposer selects from for ``slot``: ``S_E`` of its tip's chain
        (validator/epoch_state.py) — the very set every importer judges the block against
        (block_verification.verify_proposer_eligibility), recomputed every slot.

        It was once built at startup, then from the node's live ``validators`` table, which
        moved with this node's view of finality: proposer and importers could disagree on
        whose slot it was whenever one had processed a finalized epoch the other had not."""
        if self.manager is None or self.wallet is None:
            return
        from .epoch_state import proposers_for_slot

        try:
            selected = await proposers_for_slot(self.db, slot)
        except Exception as e:
            logger.debug(f"validator set refresh skipped: {e}")
            return
        members: List[Validator] = []
        for addr, stake in selected:
            members.append(
                Validator(
                    address=addr,
                    public_key=self.wallet.public_key if addr == self.wallet.address else b"",
                    stake=stake,
                    effective_stake=stake,
                    status=ValidatorStatus.ACTIVE,
                    activation_epoch=0,
                    index=len(members),
                )
            )
        if members:
            self.manager._validator_set = ValidatorSet(
                epoch=0, validators=members, total_stake=sum((v.stake for v in members), Decimal(0))
            )

    async def _signing_hold(self, slot: int) -> Optional[str]:
        """Why this validator must not sign at ``slot`` (the doppelganger check), or None."""
        if self._doppelganger is None:
            return None
        try:
            return await self._doppelganger.hold(slot)
        except Exception as e:
            # A check that cannot run must not let the validator sign blind.
            logger.error(f"doppelganger check failed: {e}")
            return f"doppelganger check failed: {e}"

    async def _block_signing_refusal(self, slot: int) -> Optional[str]:
        """Why no block may be signed at ``slot``, checked before any section runs: the
        doppelganger check, or a block for the slot already in the slashing-protection record
        (signed just before a restart, say). None if a block may be signed."""
        hold = await self._signing_hold(slot)
        if hold:
            return hold
        if self.protection is not None and self.wallet is not None:
            if not await self.protection.may_sign_block(self.wallet.address, slot):
                return "slashing protection: a block for this slot is already signed"
        return None

    async def _cast_vote(self, slot: int, epoch: int) -> bool:
        """Cast this epoch's FFG vote: from our latest justified checkpoint to the epoch's
        checkpoint, recorded as signed BEFORE it leaves the node (create_attestation, through
        slashing protection). True once the epoch is settled (voted, or a vote would be
        slashable); False to retry next slot."""
        from . import ffg
        from .types import AlreadyAttestedError

        if self.manager is None or self.wallet is None or self.protection is None:
            return False
        vote = await ffg.vote_for(self.db, epoch)
        head = await self._read_block_header(await self.db.get_next_block_id() - 1)
        if vote is None or not head:
            return False
        address = self.wallet.address
        source_epoch, source_root, target_epoch, target_root = vote
        if not await self.protection.may_vote(address, source_epoch, target_epoch):
            logger.warning(
                "Not voting in epoch %d: %s would double- or surround-vote a recorded vote",
                epoch,
                vote,
            )
            return True
        block_hash = str(head.get("hash") or head.get("block_hash"))
        try:
            attestation = await self.manager.create_attestation(
                slot=slot,
                block_hash=block_hash,
                source_epoch=source_epoch,
                target_epoch=target_epoch,
                source_root=source_root,
                target_root=target_root,
            )
        except AlreadyAttestedError:
            return True  # the record refused it: the epoch is settled
        if attestation and await self.manager.submit_attestation(attestation):
            logger.info(
                "✅ Voted %d→%d (%s…) at slot %d",
                source_epoch,
                target_epoch,
                target_root[:16],
                slot,
            )
        return True

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
                "consensus validator-updates only",
                e,
            )
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

                    # NOTE: the validator set is not maintained here: it is a function of
                    # the chain (validator/epoch_state.py). This loop keeps only the legacy
                    # lifecycle-tables tracking.

                    last_processed_epoch = ep

                await asyncio.sleep(SLOT_DURATION_SECONDS)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in epoch processing loop: {e}", exc_info=True)
                await asyncio.sleep(SLOT_DURATION_SECONDS)

        logger.info("Epoch processing loop stopped")

    def set_exchange_submitter(self, submitter) -> None:
        """Attach the node's exchange submitter (admit + gossip): oracle votes go through it."""
        self._exchange_submitter = submitter

    async def _oracle_vote_loop(self) -> None:
        """Vote this validator's prices (docs/PERPS_CLEARINGHOUSE.md §8) like any exchange
        transaction: admitted to the node's mempool and gossiped, so whichever validator proposes
        next includes it. Votes used to ride only in the voter's own blocks — refreshed only as
        often as it proposed — and moved its exchange nonce. Votes when a price changes, and at
        least every quarter of the vote lifetime (PERP_ORACLE_VOTE_MAX_AGE)."""
        from .. import constants

        refresh = max(1.0, float(constants.PERP_ORACLE_VOTE_MAX_AGE) / 4)
        last_content: Any = None
        last_at = 0.0
        while self._running:
            try:
                await asyncio.sleep(1.0)
                submitter = getattr(self, "_exchange_submitter", None)
                if submitter is None:
                    continue
                if self._proposal_guard is not None and self._proposal_guard():
                    continue  # not before the first sync: a stale tip, a stale committee
                vote = await self._oracle_vote()
                if vote is None:
                    continue
                # What the vote says: prices, and bridge deposits (a new one is voted at once).
                content = (
                    vote.params.get("prices"),
                    vote.params.get("deposits"),
                    vote.params.get("freeze"),
                )
                now = time.monotonic()
                if content == last_content and now - last_at < refresh:
                    continue
                ok, err, _hash = await submitter.submit(vote)
                if ok:
                    last_content, last_at = content, now
                else:
                    logger.debug(f"oracle vote not admitted: {err}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"oracle vote skipped: {e}")

    async def _oracle_vote(self):
        """This validator's vote, when it sits on the oracle committee: USD prices from its feed
        (QRDX_ORACLE_FEED) for every perp market, other venues' perp prices for them
        ("<base>:perp"), and the bridge deposits its watcher (QRDX_BRIDGE_SOURCES) has seen and
        the chain has not minted (docs/BRIDGE.md). Its nonce is the current slot — a vote's own
        sequence, not the account's exchange nonce. None when it has nothing to vote."""
        if self.wallet is None:
            return None
        if not hasattr(self, "_price_feed"):
            from .bridge_watcher import watcher_from_env
            from .price_feed import feed_from_env

            self._price_feed = feed_from_env()
            self._bridge_watcher = watcher_from_env()
        watcher = getattr(self, "_bridge_watcher", None)
        if self._price_feed is None and watcher is None:
            return None
        from .. import constants
        from ..exchange.bridge import MAX_VOTE_DEPOSITS
        from ..exchange.state_manager import ExchangeStateManager
        from .epoch_state import committee_for_block
        from .price_feed import PERP_SUFFIX, build_vote

        mgr = ExchangeStateManager.get_instance()
        # Whether the next block would count this vote: read-only — the committee the exchange
        # judges blocks by is set by each block's own processing.
        committee = await committee_for_block(self.db, int(await self.db.get_next_block_id()))
        if self.wallet.address.lower() not in committee:
            return None
        from ..exchange.clearinghouse import Clearinghouse

        # A token perp's spot market prices it, never the validators.
        bases = sorted(
            m.base
            for m in mgr.clearinghouse.markets.values()
            if m.quote == constants.PERP_QUOTE
            and m.settled_price <= 0
            and not Clearinghouse.contained(m)
        )
        # The oracle price, and other venues' perp price where the feed has one (the mark's
        # third input).
        wanted = bases + [b + PERP_SUFFIX for b in bases]
        got = self._price_feed.prices(wanted) if bases and self._price_feed is not None else {}
        keys = [k for k in wanted if k in got]
        limit = ExchangeStateManager.MAX_VOTE_PRICES
        if len(keys) > limit:
            # More prices than a vote carries: each vote takes the next window, so with votes
            # every quarter of the vote lifetime every market's stays fresh up to 4 × limit.
            start = getattr(self, "_vote_cursor", 0) % len(keys)
            self._vote_cursor = start + limit
            keys = (keys + keys)[start : start + limit]
        prices = {k: got[k] for k in keys}
        from .bridge_watcher import deposit_votes_enabled

        deposits = (
            watcher.outstanding(mgr.bridge.done, MAX_VOTE_DEPOSITS)
            if watcher and deposit_votes_enabled()
            else []
        )
        # Source chains' finalized heads the chain has not attested yet (docs/BRIDGE.md).
        heads = [
            h
            for h in (watcher.heads() if watcher else [])
            if (cur := mgr.bridge.head(int(h["chain"]))) is None or int(h["height"]) > cur.height
        ]
        if not prices and not deposits and not heads:
            return None
        return build_vote(self.wallet, await self._get_current_slot(), prices, deposits, heads)

    async def _await_tip_change(self, at_most: float) -> None:
        """Return once the chain's tip moves (a block landed), or after ``at_most`` seconds."""
        start = await self.db.get_next_block_id()
        deadline = time.monotonic() + at_most
        while time.monotonic() < deadline:
            await asyncio.sleep(0.02)
            if await self.db.get_next_block_id() != start:
                return

    def _exchange_budget(self) -> int:
        """How many exchange operations to select: what this node runs in its share of a slot."""
        return self._exchange_limit

    def _measure_exchange(
        self, count: int, seconds: float, share: float = EXCHANGE_BUILD_SHARE
    ) -> None:
        """Size the next block by how long this one took to build, start to signature (a block
        also has fixed costs: a cost per operation alone overstated small blocks'). A full block
        inside the share grows the next by a quarter; any block over it shrinks the next in
        proportion, at most by half. A block the mempool could not fill says nothing about
        growing."""
        budget = SLOT_DURATION_SECONDS * share
        limit = self._exchange_limit
        if seconds > budget:
            limit = int(limit * max(0.5, budget / seconds))
        elif count >= 0.9 * limit:
            limit = int(limit * 1.25) + 1
        self._exchange_limit = max(EXCHANGE_BUILD_MIN, min(EXCHANGE_BUILD_MAX, limit))

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

    async def _compute_unified_state_root(
        self, height: Optional[int] = None, slot: Optional[int] = None
    ) -> str:
        """
        E-D4: the post-block unified state root bound into the block's signed
        header — BLAKE3-512 over (UTXO root, account/EVM root, exchange root,
        token root) in fixed domain order (`crypto.hashing.unified_state_root`), each under
        the rule of the proposed block's ``height``.

        Computed at the "after sections, before native add_block" point so an
        importer reproduces it identically after replaying the sections (its UTXO
        is likewise pre-native-apply, and account/exchange/token reflect the
        replayed sections). Each domain falls back to its empty root if unavailable.

        The token domain binds the live ``get_token_balances_root`` — token state is
        now a consensus object (deploy/transfer flow through the exchange section and
        flush to the ledger on every node, see Phase E spot inc4), so the per-node
        token root converges and is safe to enforce.
        """
        from ..crypto.hashing import TOKEN_ZERO_ROOT, unified_state_root

        try:
            utxo_root = await self.db.get_unspent_outputs_hash(height)
        except Exception:
            utxo_root = "0" * 64
        try:
            account_root = await self.db.get_account_state_root(height)
        except Exception:
            account_root = "0" * 128
        try:
            from ..exchange.state_manager import ExchangeStateManager

            exchange_root = ExchangeStateManager.get_instance().compute_state_root()
        except Exception:
            exchange_root = "0" * 128
        try:
            token_root = await self.db.get_token_balances_root(height)
        except Exception:
            token_root = TOKEN_ZERO_ROOT
        from .. import state_proofs
        from . import validator_root as vroot

        # The validators' state (qrdx/validator/validator_root.py), once its feature is in force.
        validators = None
        if height is not None and slot is not None and vroot.active(height):
            validators = await vroot.compute(self.db, height, slot)
        proof_root = xtree = None
        if height is not None and state_proofs.scheduled():
            # The exchange tree beside the database tree (qrdx/exchange/proofs.py), at the same
            # point as the exchange root.
            from ..exchange.state_manager import ExchangeStateManager

            xroot = ExchangeStateManager.get_instance().exchange_proof_root(height)
            xtree = xroot.hex()
            proof_root = await state_proofs.proof_root(self.db, height, xroot)
            await state_proofs.record_parts(
                self.db,
                height,
                {
                    "utxo": utxo_root or "0" * 64,
                    "account": account_root,
                    "exchange": exchange_root,
                    "token": token_root,
                    "proof": proof_root,
                    "xtree": xtree,
                    "validators": validators,
                },
            )
        return unified_state_root(
            utxo_root or "0" * 64, account_root, exchange_root, token_root, proof_root, validators
        )

    def set_block_processing_lock(self, lock) -> None:
        """Share the node's block-processing lock, so block production never interleaves
        with an import or a derived-state rebuild (see _block_production_loop)."""
        self._block_processing_lock = lock

    def set_restore_hook(self, hook) -> None:
        """Attach main's restore (``_restore_after_rejected_block``): undoes a section this
        proposer applied and then dropped. There is no per-block revert point any more."""
        self._restore_hook = hook

    async def _restore_state(self, height: int, reason: str) -> None:
        if self._restore_hook is not None:
            try:
                await self._restore_hook(height, f"own exchange section dropped: {reason}")
            except Exception as e:
                logger.error(f"restoring state after a dropped section failed: {e}")

    def set_proposal_guard(self, guard) -> None:
        """Attach main.py's guard (_validator_wait_reason): a reason this slot must be skipped,
        such as adopting a peer's chain or the first sync not having run, or None."""
        self._proposal_guard = guard

    def _production_lock(self):
        if self._block_processing_lock is None:
            import contextlib

            return contextlib.nullcontext()
        return self._block_processing_lock

    def set_evm_section_runner(self, runner) -> None:
        """Attach the EVM section runner deferred execution uses (qrdx/post_state.py):
        ``runner(height, block_hash, timestamp, raw_txs)`` runs a signed block's section whole,
        skipping what cannot run, and returns ``(ok, error)``."""
        self._evm_section_runner = runner

    async def _build_deferred(
        self,
        next_height: int,
        current_slot: int,
        current_epoch: int,
        parent_hash: str,
        block_timestamp: Any,
        base_fees: Any,
        pending_txs: List[Any],
        phases: Phases,
        locked_at: float,
    ) -> Tuple[Any, Any, Optional[asyncio.Future]]:
        """Build a block under deferred execution (qrdx/post_state.py): judge it on the state its
        parent left, sign it with that state's root, send it, then run it, keep the root of what
        it leaves, and store it. Returns ``(block, block_data, broadcast)``; block is None when
        nothing was proposed, or when running the signed block failed (every node refuses it the
        same way: its state is restored and it is not stored)."""
        # 1. What the block carries, judged on the state now: its parent's.
        exchange_txs, evm_raws = await self._select_sections(
            next_height, block_timestamp, base_fees
        )
        phases.mark("select")
        # 2. Signed with the root of the state its parent left (its grandparent, under two
        #    blocks), and sent.
        signed = await self._sign_and_send(
            next_height,
            current_slot,
            parent_hash,
            block_timestamp,
            base_fees,
            pending_txs[:100],  # Limit to 100 txs per block
            exchange_txs,
            evm_raws,
            phases,
        )
        if signed is None:
            return None, None, None
        block, block_data, broadcast, sent_at = signed
        # 3–4. Run, as every importer will, and stored.
        if not await self._run_and_store(
            block,
            block_data,
            next_height,
            current_epoch,
            current_slot,
            block_timestamp,
            exchange_txs,
            evm_raws,
            phases,
            locked_at,
            sent_at,
        ):
            return None, None, broadcast
        return block, block_data, broadcast

    async def _select_sections(
        self,
        next_height: int,
        block_timestamp: Any,
        base_fees: Any,
        ahead: Optional[Tuple[Any, Any]] = None,
        phases: Optional[Phases] = None,
    ) -> Tuple[List[Any], List[str]]:
        """A block's exchange and EVM sections, from the mempools, judged on the state now.
        ``ahead``: (``pipeline.ParentEffects``, the fee reserve) when its parent has not run yet
        (qrdx/validator/pipeline.py) — each lane starts after the parent's, fees are judged on
        the bounds the reserve gives, and what must wait for the parent stays in the mempool."""
        from .. import chain_spec
        from ..exchange.block_processor import includable_exchange_txs
        from ..exchange.fair_ordering import FEATURE, fair_order

        exchange_txs: List[Any] = []
        if self._exchange_tx_source is not None:
            try:
                effects = ahead[0] if ahead else None
                exchange_txs = (
                    self._exchange_tx_source.select_for_block(
                        limit=self._exchange_budget(),
                        min_price=base_fees[1],
                        height=next_height,
                        **({"after": effects.lanes, "skip": effects.voters} if effects else {}),
                    )
                    or []
                )
                if exchange_txs and chain_spec.is_active(FEATURE, next_height):
                    exchange_txs = fair_order(exchange_txs)
                if phases is not None:
                    phases.mark("pick")
                if ahead is not None:
                    if exchange_txs:
                        exchange_txs = await self._judge_ahead(
                            exchange_txs, next_height, block_timestamp, base_fees, ahead
                        )
                else:
                    exchange_txs, refused = await includable_exchange_txs(
                        self.db, exchange_txs, next_height, float(block_timestamp), base_fees[1]
                    )
                    if refused:
                        logger.info(
                            f"Leaving {len(refused)} exchange tx(s) out of block #{next_height}: "
                            f"{refused[0][1]}"
                        )
                        self._exchange_tx_source.remove([t.tx_hash() for t, _why in refused])
            except Exception as e:
                logger.warning(f"Exchange tx selection failed: {e}")
                exchange_txs = []
        evm_raws: List[str] = []
        # (a parent not run yet that carries EVM transactions could change what a delegated
        # spend's authority reads: the block's EVM transactions wait for it)
        if ahead is not None and ahead[0].evm_senders:
            return exchange_txs, evm_raws
        if self._evm_tx_source is not None and self._evm_section_runner is not None:
            from ..block_limits import evm_gas_limit_at
            from ..contracts.evm_mempool import parse_eth_raw_tx, verify_delegated_spend

            try:
                selected = (
                    self._evm_tx_source.select_for_block(
                        min_price=base_fees[0], gas_limit=evm_gas_limit_at(next_height)
                    )
                    or []
                )
            except Exception as e:
                logger.warning(f"EVM tx selection failed: {e}")
                selected = []
            gone = []
            for raw in selected:
                ok, why = await verify_delegated_spend(self.db, raw, next_height)
                if ok:
                    evm_raws.append(raw)
                    continue
                logger.warning(f"Evicting delegated spend from the EVM mempool: {why}")
                try:
                    gone.append(parse_eth_raw_tx(raw)["tx_hash"])
                except Exception:
                    pass
            if gone:
                self._evm_tx_source.remove(gone)
        return exchange_txs, evm_raws

    async def propose_ahead(self, block_data: Dict[str, Any], parent_height: int) -> Optional[Any]:
        """Build on block ``parent_height`` before it runs (two blocks; qrdx/validator/pipeline.py).

        Called by the live import, holding the block-processing lock, once the block is verified
        and before it runs. When this node proposes the next slot and the block arrived within
        half a slot of that slot's start (or after it), the next block is judged on the state now
        (before the parent) and the parent's contents, signed with the root of the state now and
        sent at once; the import then runs the parent, and ``finish_ahead`` runs and stores this
        one. The slot loop, finding the height filled, passes. Returns the pending block, or None
        to import as usual (a parent that opens an epoch, carries operations the bounds do not
        cover, or arrived in time to run first; another proposer's slot; anything a proposal
        checks)."""
        from .. import chain_index, chain_spec, post_state
        from ..exchange.block_processor import decode_exchange_txs
        from ..exchange.state_manager import ExchangeStateManager, fee_reserve_at
        from ..fee_market import base_fees_at, parent_inputs
        from . import pipeline
        from .block_verification import _parse_block_content, genesis_time, slot_timestamp
        from .randao import randao_selection_active

        if not (self._running and self.manager is not None and pipeline.enabled()):
            return None
        height = int(parent_height) + 1
        reserve = fee_reserve_at(height)
        if reserve is None or post_state.lag(height) != 2 or randao_selection_active(height):
            return None
        try:
            content = _parse_block_content(block_data.get("block_content"))
            parent_slot = int(content["slot"])
            parent_hash = str(block_data["block_hash"])
        except Exception:
            return None
        slot = parent_slot + 1
        epoch = slot // SLOTS_PER_EPOCH
        if epoch != parent_slot // SLOTS_PER_EPOCH or await self._get_current_slot() > slot:
            return None
        grand_slot = await chain_index.slot_at(self.db, height - 2)
        if grand_slot is None or int(grand_slot) // SLOTS_PER_EPOCH != epoch:
            return None  # (the parent opens an epoch)
        genesis = await self._genesis_timestamp()
        if genesis is None:
            return None
        start = genesis + slot * SLOT_DURATION_SECONDS
        if time.time() < start - SLOT_DURATION_SECONDS / 2:
            # (it arrived in time to run before the slot: run it now, build on it as usual)
            return None
        # Within half a slot of the slot's start, the block is built and sent now: its timestamp
        # is the slot's start whenever it is built, and importers take a slot up to a second
        # ahead of their clock (block_verification). Waiting for the slot, holding the lock,
        # kept the parent and every block behind it waiting.
        await self._refresh_validator_set(slot)
        if await self.manager.proposer_rank(slot) != 0:
            return None
        if (
            (self._proposal_guard() if self._proposal_guard is not None else None)
            or await self._block_signing_refusal(slot)
            or self._behind_the_network(height)
        ):
            return None
        section = block_data.get("exchange_transactions") or []
        evm_section = block_data.get("evm_transactions") or []
        parent_txs = block_data.get("_exchange_objects") or decode_exchange_txs(section)
        effects = pipeline.parent_effects(
            ExchangeStateManager.get_instance(), parent_txs, evm_section
        )
        if effects.unbounded:
            logger.debug(f"Block #{height} waits for its parent to run: {effects.unbounded}")
            return None
        phases = Phases()
        locked_at = time.perf_counter()
        base_fees = await base_fees_at(
            self.db, height, parent=parent_inputs(content, section, evm_section)
        )
        phases.mark("fees")
        origin = await genesis_time(self.db)
        if chain_spec.is_active("slot_timestamps", height) and origin is not None:
            block_timestamp: Any = slot_timestamp(origin, slot)
        else:
            block_timestamp = int(datetime.now(timezone.utc).timestamp())
        exchange_txs, evm_raws = await self._select_sections(
            height, block_timestamp, base_fees, ahead=(effects, reserve), phases=phases
        )
        phases.mark("select")
        signed = await self._sign_and_send(
            height,
            slot,
            parent_hash,
            block_timestamp,
            base_fees,
            [],
            exchange_txs,
            evm_raws,
            phases,
            parent_carries=pipeline.parent_carries(content),
        )
        if signed is None:
            return None
        block, data, broadcast, sent_at = signed
        if broadcast is not None:
            self._follow_broadcast(broadcast, height)
        return _Ahead(
            block, data, height, slot, epoch, block_timestamp, exchange_txs, evm_raws, phases,
            locked_at, sent_at, broadcast,
        )  # fmt: skip

    async def finish_ahead(self, ahead: Any) -> None:
        """Run and store a block ``propose_ahead`` built, once its parent has run and is stored
        (called by the import, still holding the lock). A parent that was not stored takes it
        with it: every node refuses a block whose parent it refused."""
        from ..derived_state_rebuild import before_block

        tip = await self._read_block_header(ahead.height - 1)
        if not tip or (tip.get("hash") or tip.get("block_hash")) != ahead.block.parent_hash:
            logger.warning(f"Block #{ahead.height} dropped: its parent was not stored here")
            return
        ahead.phases.mark("parent")
        waited = time.perf_counter() - ahead.sent_at  # (the parent's run: not this block's)
        async with await before_block(self.db, ahead.height, ahead.epoch):
            await self._run_and_store(
                ahead.block,
                ahead.data,
                ahead.height,
                ahead.epoch,
                ahead.slot,
                ahead.timestamp,
                ahead.exchange_txs,
                ahead.evm_raws,
                ahead.phases,
                ahead.locked_at + waited,
                ahead.sent_at + waited,
            )

    async def _judge_ahead(
        self,
        txs: List[Any],
        next_height: int,
        block_timestamp: Any,
        base_fees: Any,
        ahead: Tuple[Any, Any],
    ) -> List[Any]:
        """``pipeline.judge`` of a selection for a block whose parent has not run: fees on the
        bounds the reserve gives, from the balances now (the state before the parent)."""
        from ..exchange.block_processor import _balances, apply_enforcement
        from ..exchange.state_manager import ExchangeStateManager
        from . import pipeline

        mgr = ExchangeStateManager.get_instance()
        apply_enforcement(mgr)
        holders = list(dict.fromkeys(h for t in txs for h in (t.sender, mgr.fee_payer(t))))
        bound = pipeline.bounds(ahead[0], await _balances(self.db, holders), ahead[1])
        return pipeline.judge(
            mgr, txs, next_height, float(block_timestamp), base_fees[1], ahead[0], bound.get
        )

    async def _sign_and_send(
        self,
        next_height: int,
        current_slot: int,
        parent_hash: str,
        block_timestamp: Any,
        base_fees: Any,
        pending_txs: List[Any],
        exchange_txs: List[Any],
        evm_raws: List[str],
        phases: Phases,
        parent_carries: Optional[Tuple[Any, Any]] = None,
    ) -> Optional[Tuple[Any, Any, Optional[asyncio.Future], float]]:
        """Sign the block with the root of the state ``post_state.lag`` blocks back and send it.
        Returns ``(block, block_data, broadcast, sent_at)``, or None when nothing was signed."""
        from .. import post_state
        from ..contracts.evm_block import encode_evm_txs
        from ..exchange.block_processor import encode_exchange_txs
        from .types import AlreadyProposedError

        if self.manager is None:
            return None
        before = next_height - post_state.lag(next_height)
        try:
            state_root = await post_state.root_after(
                self.db, before, parent_hash if before == next_height - 1 else None
            )
        except LookupError as e:
            logger.warning(f"Block #{next_height} not proposed: {e}")
            return None
        try:
            block = await self.manager.propose_block(
                slot=current_slot,
                parent_hash=parent_hash,
                transactions=pending_txs,
                state_root=state_root,
                timestamp=block_timestamp,
                exchange_section=(
                    encode_exchange_txs(exchange_txs, next_height) if exchange_txs else []
                ),
                evm_section=encode_evm_txs(evm_raws) if evm_raws else [],
                base_fees=base_fees,
                parent_carries=parent_carries,
            )
        except AlreadyProposedError:
            return None
        if not block:
            return None
        phases.mark("sign")
        block_data = assemble_pos_block_data(block, next_height, exchange_txs, None, evm_raws, None)
        broadcast = None
        if self.broadcast_callback:
            broadcast = asyncio.ensure_future(
                self.broadcast_callback("submit_block", block_data, ignore_node_id=None, db=self.db)
            )
        self._sent_wall[block.hash] = time.time()  # (for the log: how far into its slot)
        while len(self._sent_wall) > 64:
            self._sent_wall.pop(next(iter(self._sent_wall)))
        return block, block_data, broadcast, time.perf_counter()

    async def _run_and_store(
        self,
        block: Any,
        block_data: Any,
        next_height: int,
        current_epoch: int,
        current_slot: int,
        block_timestamp: Any,
        exchange_txs: List[Any],
        evm_raws: List[str],
        phases: Phases,
        locked_at: float,
        sent_at: float,
    ) -> bool:
        """Run a block this node signed and sent, as every importer will; keep the root of what it
        leaves; store it and take its operations out of the mempools. False when it could not
        run (its state is restored and it is not stored)."""
        from .. import post_state

        failed = await self._run_signed_block(
            block, next_height, current_epoch, block_timestamp, exchange_txs, evm_raws
        )
        if failed:
            logger.warning(f"Block #{next_height} could not run, not stored: {failed}")
            await self._restore_state(next_height, failed)
            if self._exchange_tx_source is not None and exchange_txs:
                self._exchange_tx_source.remove([t.tx_hash() for t in exchange_txs])
            return False
        phases.mark("run")
        await post_state.settle(self.db, next_height, block.hash, current_slot)
        phases.mark("root")
        if exchange_txs:
            self._measure_exchange(
                len(exchange_txs), time.perf_counter() - locked_at, DEFERRED_BUILD_SHARE
            )
        genesis = await self._genesis_timestamp()
        sent_wall = self._sent_wall.pop(block.hash, None)
        into = ""
        if genesis is not None and sent_wall is not None:
            offset = sent_wall - genesis - current_slot * SLOT_DURATION_SECONDS
            into = f", sent +{1000 * offset:.0f} ms into its slot"
        woke = self.__dict__.pop("_woke_at", None)
        if woke is not None and "parent" not in str(phases):
            into += f", the slot loop woke +{1000 * woke:.0f} ms into it"
        logger.info(
            f"📦 Proposed block #{next_height} at slot {current_slot}: {block.hash[:16]}... "
            f"({len(exchange_txs)} ops, {1000 * (sent_at - locked_at):.0f} ms to send, "
            f"{1000 * (time.perf_counter() - locked_at):.0f} ms in all: {phases}{into})"
        )

        # Stored, its operations out of the mempools.
        await self.db.add_block(
            block_hash=block.hash,
            block_height=next_height,
            block_content=block_data["block_content"],
            validator_address=block.proposer_address,
            timestamp=block.timestamp,
        )
        try:
            from ..exchange.block_processor import BLOCK_EXCHANGE_TXS_KEY

            section = block_data.get(BLOCK_EXCHANGE_TXS_KEY)
            if section:
                await self.db.add_block_exchange_txs(
                    block.hash, section, block_data.get("_exchange_objects")
                )
            if self._exchange_tx_source is not None and exchange_txs:
                self._exchange_tx_source.remove([t.tx_hash() for t in exchange_txs])
        except Exception as e:
            logger.warning(f"Failed to persist/drain exchange section: {e}")
        if evm_raws:
            try:
                from ..contracts.evm_block import BLOCK_EVM_TXS_KEY
                from ..contracts.evm_mempool import parse_eth_raw_tx

                evm_section = block_data.get(BLOCK_EVM_TXS_KEY)
                if evm_section:
                    await self.db.add_block_evm_txs(block.hash, evm_section)
                if self._evm_tx_source is not None:
                    hashes = []
                    for raw in evm_raws:
                        try:
                            hashes.append(parse_eth_raw_tx(raw)["tx_hash"])
                        except Exception:
                            pass
                    self._evm_tx_source.remove(hashes)
            except Exception as e:
                logger.warning(f"Failed to persist/drain EVM section: {e}")
        try:
            from .finality import record_finality_from_block

            await record_finality_from_block(self.db, block_data["block_content"])
        except Exception as e:
            logger.debug(f"finality record skipped for block #{next_height}: {e}")
        phases.mark("store")
        return True

    async def _run_signed_block(
        self,
        block: Any,
        height: int,
        epoch: int,
        block_timestamp: Any,
        exchange_txs: List[Any],
        evm_raws: List[str],
    ) -> str:
        """Run a block this node signed, in the importers' order (exchange section, EVM section,
        withdrawals). Returns why it could not run ("" if it ran)."""
        from ..exchange.block_processor import (
            ENFORCE_EXCHANGE_COLLATERAL,
            apply_enforcement,
            ensure_oracle_committee,
            flush_exchange_balance_deltas,
            flush_token_balance_deltas,
            flush_validator_lifecycle_deltas,
            preload_sender_balances,
            preload_token_balances,
            process_exchange_transactions,
            tick_and_flush,
        )
        from ..exchange.state_manager import ExchangeStateManager

        mgr = ExchangeStateManager.get_instance()
        try:
            if exchange_txs:
                apply_enforcement(mgr)
                await preload_sender_balances(self.db, exchange_txs, mgr, height)
                await preload_token_balances(self.db, exchange_txs, mgr)
                ok, err, _root = process_exchange_transactions(
                    height, float(block_timestamp), exchange_txs, mgr
                )
                if not ok:
                    return f"exchange section: {err}"
                mgr.commit_block()
                await flush_exchange_balance_deltas(
                    self.db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL
                )
                await flush_token_balance_deltas(self.db, mgr)
                await flush_validator_lifecycle_deltas(
                    self.db, mgr, block_epoch=epoch, block_height=height
                )
                logger.info(f"📦 Including {len(exchange_txs)} exchange tx(s) in block #{height}")
            else:
                await ensure_oracle_committee(self.db, mgr, height)
                await tick_and_flush(self.db, height, float(block_timestamp))
        except Exception as e:
            return f"exchange section raised: {e}"
        if evm_raws and self._evm_section_runner is not None:
            ok, err = await self._evm_section_runner(
                height, block.hash, int(block_timestamp), evm_raws, None
            )
            if not ok:
                return f"EVM section: {err}"
        try:
            from .withdrawals import process_block_withdrawals

            await process_block_withdrawals(self.db, height, epoch)
        except Exception as e:
            logger.error(f"Withdrawal processing failed for block #{height}: {e}")
        return ""

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

    async def _read_block_header(self, height: int) -> Optional[dict]:
        """The block at ``height`` without its ~45 KB body when the database can (hash,
        parent, timestamp); the full block otherwise."""
        read = getattr(self.db, "get_block_header", None) or self.db.get_block_by_id
        return await read(height)

    async def _genesis_timestamp(self) -> Optional[float]:
        """The genesis block's time (unix seconds). Immutable, so read once and cached; None
        while the genesis block is not available (never cached)."""
        if self._genesis_ts is not None:
            return self._genesis_ts
        # CRITICAL: the genesis block stores its timestamp as an ISO-8601 TEXT string (e.g.
        # "2026-06-08 13:57:09+00:00"), unlike later blocks which use integer Unix timestamps;
        # parse_block_timestamp reads both. (Reading it as a number used to fail on EVERY call
        # and fall back to `now`, pinning the slot to 0 — every validator the slot-0 proposer.)
        try:
            genesis_block = await self.db.get_block_by_id(0)
            parsed = parse_block_timestamp(
                genesis_block.get("timestamp") if genesis_block else None
            )
        except Exception as e:
            logger.debug(f"slot: could not read genesis timestamp: {e}")
            parsed = None
        if parsed is not None:
            self._genesis_ts = parsed.timestamp()
        return self._genesis_ts

    async def _get_current_slot(self) -> int:
        """
        Calculate current slot based on genesis time and slot duration.

        Returns:
            Current slot number
        """
        genesis = await self._genesis_timestamp()
        if genesis is None:
            return 0
        elapsed = datetime.now(timezone.utc).timestamp() - genesis
        return max(0, int(elapsed // SLOT_DURATION_SECONDS))

    async def _loop_lag_monitor(self, tick: float = 0.01, report: float = 0.1) -> None:
        """(``QRDX_LOOP_LAG_LOG=1``, a diagnostic) Log each time the event loop woke this task
        ``report`` seconds or more late: synchronous work held the loop that long. A watchdog
        thread logs what the loop was running when its heartbeat went ``report`` seconds stale."""
        import sys
        import threading
        import traceback

        beat = [time.perf_counter()]
        main = threading.get_ident()

        def watch() -> None:
            seen = 0.0
            while self._running:
                time.sleep(0.02)
                stale = time.perf_counter() - beat[0]
                if stale >= report and beat[0] != seen:
                    seen = beat[0]
                    frame = sys._current_frames().get(main)
                    if frame is not None:
                        where = " < ".join(
                            f"{f.name} ({f.filename.rsplit('/', 2)[-1]}:{f.lineno})"
                            for f in reversed(traceback.extract_stack(frame)[-8:])
                        )
                        logger.info(f"⏳ Loop held {1000 * stale:.0f} ms so far, in: {where}")

        threading.Thread(target=watch, name="loop-lag-watchdog", daemon=True).start()
        # The cyclic garbage collector's pauses (each collection of 20 ms or more): they stop
        # the process wherever it allocates.
        import gc

        gc_started: List[float] = []
        gc_slow: List[Tuple[int, float, int]] = []
        gc_totals = [[0, 0.0] for _ in range(3)]  # per generation: collections, seconds
        totals_since = time.perf_counter()

        def on_gc(phase: str, info: Dict[str, Any]) -> None:
            if phase == "start":
                gc_started[:] = [time.perf_counter()]
            elif gc_started:
                spent = time.perf_counter() - gc_started.pop()
                generation = int(info["generation"])
                gc_totals[generation][0] += 1
                gc_totals[generation][1] += spent
                if spent >= 0.02:
                    gc_slow.append((generation, spent, int(info["collected"])))

        gc.callbacks.append(on_gc)
        while self._running:
            asked = time.perf_counter()
            beat[0] = asked
            await asyncio.sleep(tick)
            late = time.perf_counter() - asked - tick
            if late >= report:
                logger.info(f"⏳ Event loop held {1000 * late:.0f} ms")
            while gc_slow:
                generation, spent, collected = gc_slow.pop(0)
                logger.info(
                    f"🗑  Garbage collection (generation {generation}): {1000 * spent:.0f} ms, "
                    f"{collected} collected"
                )
            if time.perf_counter() - totals_since >= 10.0:
                logger.info(
                    "🗑  Garbage collection in the last %.0f s: %s",
                    time.perf_counter() - totals_since,
                    ", ".join(
                        f"generation {g} {n} × = {1000 * t:.0f} ms"
                        for g, (n, t) in enumerate(gc_totals)
                    ),
                )
                gc_totals[:] = [[0, 0.0] for _ in range(3)]
                totals_since = time.perf_counter()

    def _follow_broadcast(self, broadcast: "asyncio.Future", height: Optional[int]) -> None:
        """Log a block's broadcast when it finishes (kept referenced until then). ``height`` is
        None for a block that could not run here: sent, and refused everywhere."""
        pending = self.__dict__.setdefault("_broadcasts", set())
        pending.add(broadcast)

        def done(task: "asyncio.Future") -> None:
            pending.discard(task)
            if height is None or task.cancelled():
                return
            error = task.exception()
            if error is not None:
                logger.warning(f"Failed to broadcast block #{height}: {error}")
            else:
                logger.info(f"📡 Broadcast block #{height} to peers")

        broadcast.add_done_callback(done)

    @staticmethod
    def _behind_the_network(next_height: int) -> Optional[str]:
        """Why not to propose at ``next_height``: a block two or more heights above it is known
        (a peer sent it, its proposer's signature checked, within the last second) — the block
        would compete with a longer chain, lose, and cost this node a rollback while it falls
        further behind. None otherwise."""
        from . import pipeline

        ahead = pipeline.network_ahead()
        if ahead is not None and ahead > next_height:
            return f"behind the network (block {ahead} is known): catching up"
        return None

    @staticmethod
    def _retry_share() -> float:
        """How much of its slot must be left for a proposer whose tip moved while it prepared to
        build again on the new tip: half, or a twentieth with a pipelined proposer next."""
        from . import pipeline

        return 0.05 if pipeline.enabled() else 0.5

    async def _into_slot(self, slot: int) -> Optional[float]:
        """Seconds since ``slot`` began (None before genesis is known)."""
        genesis = await self._genesis_timestamp()
        if genesis is None:
            return None
        return datetime.now(timezone.utc).timestamp() - genesis - slot * SLOT_DURATION_SECONDS

    async def _slot_left(self, slot: int) -> float:
        """The share of ``slot`` still to come (0 once it has passed)."""
        genesis = await self._genesis_timestamp()
        if genesis is None:
            return 0.0
        end = genesis + (slot + 1) * SLOT_DURATION_SECONDS
        left = (end - datetime.now(timezone.utc).timestamp()) / SLOT_DURATION_SECONDS
        return min(1.0, max(0.0, left))

    async def _sleep_until(self, slot: int, fraction: float = 0.0) -> None:
        """Sleep until ``fraction`` of the way into ``slot`` (wall clock, from genesis) — the
        slot clock. The loops used to sleep a fixed SLOT_DURATION after doing their work, so
        every iteration took work + one slot: a lone validator's block time was 2 s plus its
        per-block work, and with several validators each one drifted off its own slots."""
        genesis = await self._genesis_timestamp()
        if genesis is None:
            await asyncio.sleep(SLOT_DURATION_SECONDS)
            return
        target = genesis + (slot + fraction) * SLOT_DURATION_SECONDS
        delay = target - datetime.now(timezone.utc).timestamp()
        if delay > 0:
            await asyncio.sleep(delay)


async def initialize_validator_node(
    db, wallet_path: str, password: str = "", broadcast_callback=None
) -> Optional[ValidatorNode]:
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
