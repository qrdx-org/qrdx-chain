"""
QRDX Exchange State Manager  (Whitepaper §7 — State Layer)

Central singleton that bridges the blockchain layer with the exchange engine.
Every node maintains an identical exchange state by processing the same
sequence of ExchangeTransactions deterministically during block validation.

Responsibilities:
  - Owns all exchange engine instances (pools, books, oracles, perps)
  - Processes ExchangeTransactions deterministically
  - Computes exchange state root for block commitment
  - Serializes / deserializes state for persistence
  - Provides read-only query interface for API layer
  - Block-boundary lifecycle (new_block, finalize_block, revert_block)

Security:
  - All mutations go through process_transaction() — no direct engine access
  - State root is blake2b of sorted pool/book/position/oracle hashes
  - Revert support for chain reorganizations
  - Deterministic execution — identical inputs produce identical outputs
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import logging
import time
from dataclasses import asdict
from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal
from typing import Any, Dict, List, Optional, Tuple

from .amm import (
    ConcentratedLiquidityPool,
    FEE_CREATOR_SHARE,
    FEE_TREASURY_SHARE,
    FEE_VALIDATOR_SHARE,
    FeeTier,
    PoolManager,
    PoolType,
    Q96,
)
from .hooks import CircuitBreaker, HookContext, HookRegistry
from .oracle import TWAPOracle
from .orderbook import Order, OrderBook, OrderSide, OrderType, SelfTradeAction, _pinned
from .clearinghouse import Clearinghouse, ClearinghouseError
from .perpetual import PerpEngine, PerpSide
from .router import FillSource, UnifiedRouter
from .nfts import NftError, NftRegistry, token_id as nft_token_id
from .tokens import (
    NATIVE_ASSET, TokenError, TokenRegistry, account as token_account, amount as token_amount,
    canonical_asset, is_native_asset, memo as token_memo,
)
from .transactions import (
    EXCHANGE_GAS_COSTS,
    ExchangeOpType,
    ExchangeTransaction,
)

logger = logging.getLogger(__name__)

ZERO = Decimal("0")


# ---------------------------------------------------------------------------
# Transaction execution result
# ---------------------------------------------------------------------------

class ExchangeExecResult:
    """Result of executing a single exchange transaction."""

    __slots__ = ("success", "gas_used", "data", "error", "logs", "fee")

    def __init__(
        self,
        success: bool = True,
        gas_used: int = 0,
        data: Optional[Dict[str, Any]] = None,
        error: str = "",
        logs: Optional[List[Dict[str, Any]]] = None,
    ):
        self.success = success
        self.gas_used = gas_used
        self.data = data or {}
        self.error = error
        self.logs = logs or []
        self.fee = ZERO                  # QRDX paid for gas (burned)


# ---------------------------------------------------------------------------
# Exchange State Manager
# ---------------------------------------------------------------------------

class ExchangeStateManager:
    """
    Singleton bridge between the blockchain consensus layer and the
    exchange engine.  Every validator runs an identical instance.

    Usage in block production / validation:

        mgr = ExchangeStateManager.instance
        mgr.begin_block(block_height, block_timestamp)
        for tx in exchange_txs:
            result = mgr.process_transaction(tx)
        state_root = mgr.finalize_block()
    """

    instance: Optional[ExchangeStateManager] = None

    def __init__(self) -> None:
        # --- Engine instances (consensus-critical state) ---
        self.pool_manager = PoolManager()
        # Legacy: no consensus path reaches PerpEngine any more (its positions had no
        # counterparty). Perps trade through the clearinghouse (docs/PERPS_CLEARINGHOUSE.md).
        self.perp_engine = PerpEngine()
        self.clearinghouse = Clearinghouse()
        # Validator price oracle (docs/PERPS_CLEARINGHOUSE.md §8). The committee — address →
        # stake — starts from the genesis block's validator set (loaded before the first block
        # section by block_processor.preload_sender_balances) and follows STAKE_DEPOSIT /
        # STAKE_EXIT. None: not loaded, or a genesis without a validator set — votes disabled.
        self.oracle_committee: Optional[Dict[str, Decimal]] = None
        # market_id → voter → (price, block time of the vote)
        self.oracle_votes: Dict[str, Dict[str, Tuple[Decimal, Decimal]]] = {}
        # Node-local receipts + perps event feed for wallets, the API and streams — NOT
        # consensus state (see journal.py). Recorded at commit, rebuilt with the manager.
        from .journal import ExchangeJournal
        self.journal = ExchangeJournal()
        self._block_tick_events: List[Dict[str, Any]] = []
        self.router = UnifiedRouter(pool_manager=self.pool_manager)
        # Funding cadence, oracle staleness and swap deadlines are judged by the block being
        # processed (begin_block sets it), so every node — and every rebuild or catching-up
        # sync — decides them identically. They used to read the wall clock.
        self.perp_engine.clock = self._block_clock
        self.router.clock = self._block_clock
        self.hook_registry = HookRegistry()
        self.circuit_breaker = CircuitBreaker()

        # Register built-in hooks
        self.hook_registry.register(self.circuit_breaker)

        # Order books: pair_key → OrderBook
        self._order_books: Dict[str, OrderBook] = {}
        # Oracles: pair_key → TWAPOracle
        self._oracles: Dict[str, TWAPOracle] = {}
        # Per-sender nonces for replay protection
        self._nonces: Dict[str, int] = {}

        # --- Block-level tracking ---
        self._current_block_height: int = 0
        self._current_block_timestamp: float = 0.0
        self._block_exchange_txs: List[ExchangeTransaction] = []
        self._block_results: List[ExchangeExecResult] = []
        self._block_fees: Decimal = ZERO

        # --- State snapshot for revert ---
        self._snapshot: Optional[Dict[str, Any]] = None

        # --- Phase E: real-balance bridge (collateralization) ---
        # Per-sender available QRDX balance, PRE-LOADED from account_state by the
        # async block paths before the (sync) section is processed. None ⇒ not
        # loaded (skip the check). These are inputs derived deterministically from
        # account_state, not state-root state, so they are not snapshotted.
        self._available_balances: Dict[str, Decimal] = {}
        # Per-block net balance deltas (address -> QRDX; negative = debit) the
        # block's exchange ops would apply to real account_state — e.g. margin
        # locked on open. Deterministic (derived from the same txs + pre-loaded
        # balances on every node). Reset per block; flushed to account_state
        # atomically with the block by the async wrapper when collateral is
        # enforced. Block-scoped, so not part of the exchange state root.
        self._balance_deltas: Dict[str, Decimal] = {}
        # Collateral enforcement gate (set by the node when enforcing): when True,
        # open_position rejects if margin exceeds available balance.
        self.enforce_collateral: bool = False

        # --- Phase E (spot): real token-balance bridge (settlement) ---
        # Per-(holder, token_address) available token balance, PRE-LOADED from the
        # token_balances ledger by the async block paths before the (sync) section
        # is processed. Mirrors the QRDX bridge above but for QRC-20 holdings.
        # None ⇒ not loaded (skip the sufficiency check).
        self._available_token_balances: Dict[Tuple[str, str], Decimal] = {}
        # Per-block net token deltas ((holder, token) -> amount; negative = debit)
        # the block's spot ops (swap / liquidity) would apply to the real
        # token_balances ledger. Deterministic (same txs + pre-loaded balances on
        # every node), reset per block, flushed atomically with the block by the
        # async wrapper when spot settlement is enforced. Block-scoped, so not part
        # of the exchange state root.
        self._token_balance_deltas: Dict[Tuple[str, str], Decimal] = {}
        # The native token standard (qrdx/exchange/tokens.py): every token's registry entry
        # (supply, authorities), the allowances and the frozen accounts. Exchange state —
        # replayed on every path and committed in the exchange root; the balances live in
        # the token ledger. Tokens it changes in a block are mirrored to the DB registry.
        self.tokens = TokenRegistry()
        # Native NFTs (qrdx/exchange/nfts.py): collections, their NFTs, approvals, operators.
        self.nfts = NftRegistry()
        # Per-block validator-lifecycle ops (STAKE_DEPOSIT / STAKE_EXIT) to flush to
        # the consensus validators table. Deterministic (same txs on every node),
        # reset per block. See qrdx.validator.epoch_loop for activation scheduling.
        self._validator_lifecycle_ops: List[Dict[str, Any]] = []
        # Spot settlement enforcement gate (set by the node when enforcing): when
        # True, a transfer/swap rejects if the holder lacks sufficient balance.
        self.enforce_spot_settlement: bool = False
        # CLOB order-book settlement gate (observe-first, SEPARATE from the AMM
        # enforce_spot_settlement so it can be soaked independently). When True,
        # PLACE_ORDER escrows the order's funds, matched trades settle real token
        # moves maker↔taker via the book escrow, and CANCEL_ORDER refunds — and an
        # unaffordable LIMIT order (or any MARKET/STOP order) is rejected BEFORE it
        # mutates the book. When False (default) the book matches as before and moves
        # no value (behaviour-neutral). See docs/CONSENSUS_REMAINING_WORK.md item 7.
        self.enforce_orderbook_settlement: bool = False
        # Pool-creation stake gate (observe-first, SEPARATE gate so it soaks
        # independently). When True, CREATE_POOL debits the creator's real QRDX
        # (account_state) stake — held in pool.state.stake_amount, returnable by a
        # future remove-pool op (staking pools) or forfeit (subsidized = burn) — and
        # rejects a creator who cannot afford it. Because the shared account_state
        # flush (flush_exchange_balance_deltas) is ALREADY enforced for collateral,
        # this gate must guard the DELTA RECORDING itself (not just the flush), or the
        # stake would debit as soon as collateral is enforced. When False (default) the
        # pool is created as before and no value moves (behaviour-neutral).
        self.enforce_pool_stake: bool = False

        # Validator-stake gate. A STAKE_DEPOSIT registers the sender as a consensus
        # validator with the stake it CLAIMS, and that claimed figure becomes the
        # validator's effective_stake — which weights proposer selection and
        # fork-choice attesting weight. So an unbacked claim is a consensus attack,
        # not just an accounting error: a zero-balance account could claim more stake
        # than the honest set combined and dominate both.
        #
        # ON: the deposit must clear MIN_VALIDATOR_STAKE, the sender must actually
        # hold the stake, and it is DEBITED from account_state (refunded at the
        # deterministic finalized exit epoch — see epoch_loop). Like
        # enforce_pool_stake this must gate the delta RECORDING, because the shared
        # account_state flush is already enforced for collateral.
        self.enforce_validator_stake: bool = False
        # Exchange fees: every executed operation pays gas_used × gas_price (wei) in QRDX,
        # burned like EVM gas. The gas_limit × gas_price maximum is reserved before the
        # operation runs and the unused part refunded. Like the stake gates it governs the
        # delta RECORDING (the account_state flush is already enforced for collateral).
        self.enforce_fees: bool = False

        # --- Counters ---
        self._total_swaps: int = 0
        self._total_orders: int = 0
        self._total_pools: int = 0
        self._total_positions: int = 0

    @classmethod
    def get_instance(cls) -> ExchangeStateManager:
        """Get or create the singleton instance."""
        if cls.instance is None:
            cls.instance = cls()
            logger.info("Exchange state manager initialized")
        return cls.instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton (for testing)."""
        cls.instance = None

    # =====================================================================
    #  Block lifecycle
    # =====================================================================

    def _block_clock(self) -> float:
        """Timestamp of the block being processed — the exchange's only consensus clock."""
        return float(self._current_block_timestamp)

    def begin_block(self, block_height: int, block_timestamp: float) -> None:
        """
        Called at the start of block processing.

        Resets per-block accumulators and rate-limit counters.
        """
        self._current_block_height = block_height
        self._current_block_timestamp = block_timestamp
        self._block_exchange_txs = []
        self._block_results = []
        self._block_fees = ZERO
        self._balance_deltas = {}  # Phase E: reset per-block balance deltas
        self._token_balance_deltas = {}  # Phase E (spot): reset per-block token deltas
        self.tokens.changed.clear()      # the DB registry mirror is written per block
        self._validator_lifecycle_ops = []  # Phase 3: reset per-block staking deposit/exit ops
        self._block_tick_events = []        # journal: this block's liquidations + funding
        self._block_journaled = False

        # Reset per-block rate limits on all order books; expiry is judged by block time
        for book in self._order_books.values():
            book.new_block(block_timestamp)

        # Reset circuit breaker per-block counters
        self.circuit_breaker.new_block()
        self.clearinghouse.new_block(block_timestamp)

    def finalize_block(self) -> str:
        """
        Called after all transactions in a block are processed.

        Returns:
            The exchange state root hash for this block.
        """
        state_root = self.compute_state_root()
        logger.debug(
            "Block %d finalized: %d exchange txs, fees=%s, state_root=%s",
            self._current_block_height,
            len(self._block_exchange_txs),
            self._block_fees,
            state_root[:16],
        )
        return state_root

    def revert_block(self) -> None:
        """
        Revert the state changes from the current block.

        Called during chain reorganization.
        """
        if self._snapshot is not None:
            self._restore_snapshot(self._snapshot)
            self._snapshot = None
            logger.warning(
                "Block %d reverted — exchange state restored",
                self._current_block_height,
            )

    def commit_block(self) -> None:
        """
        Accept the current block's state changes as final.

        Discards the pre-block revert snapshot so a later ``revert_block`` cannot
        undo committed state. Called once a block (its exchange section) has been
        validated and accepted by consensus. Records the block in the journal.
        """
        self._snapshot = None
        if not getattr(self, "_block_journaled", False):
            self._block_journaled = True
            try:
                self.journal.record_block(
                    self._current_block_height, self._current_block_timestamp,
                    self._block_exchange_txs, self._block_results, self._block_tick_events)
            except Exception as e:              # the journal must never break a block
                logger.warning("exchange journal: block %s not recorded: %s",
                               self._current_block_height, e)
        self._block_tick_events = []

    def record_tick_events(self, events: List[Dict[str, Any]]) -> None:
        """The block-boundary tick's liquidations and funding, for the journal at commit."""
        self._block_tick_events.extend(events or [])

    # =====================================================================
    #  Transaction processing (consensus-critical)
    # =====================================================================

    @_pinned
    def process_transaction(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """
        Execute a single exchange transaction deterministically.

        This is the ONLY entry point for exchange state mutations.
        Every validator must produce identical results for identical inputs.

        Args:
            tx: The exchange transaction to execute

        Returns:
            ExchangeExecResult with success/failure and gas used
        """
        # 1. Basic structural validation
        try:
            tx.validate_basic()
        except ValueError as e:
            return ExchangeExecResult(success=False, gas_used=0, error=str(e))

        # 2. Nonce check (replay protection)
        expected_nonce = self._nonces.get(tx.sender, 0)
        if tx.nonce != expected_nonce:
            return ExchangeExecResult(
                success=False, gas_used=0,
                error=f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}",
            )

        # 3. Gas limit check
        base_gas = EXCHANGE_GAS_COSTS.get(tx.op_type, 100_000)
        if tx.gas_limit < base_gas:
            return ExchangeExecResult(
                success=False, gas_used=0,
                error=f"Gas limit too low: need {base_gas}, got {tx.gas_limit}",
            )

        # 3b. Fees: a price of at least the floor, and QRDX for the whole gas limit at that
        #     price, reserved before the operation runs (so the operation cannot spend it).
        #     Refused here, an operation is not includable and consumes nothing.
        reserved = ZERO
        if self.enforce_fees:
            try:
                tx.validate_fee()
            except ValueError as e:
                return ExchangeExecResult(success=False, gas_used=0, error=str(e))
            reserved = tx.max_fee()
            avail = self.available_balance(tx.sender)
            if avail is None or avail < reserved:
                return ExchangeExecResult(
                    success=False, gas_used=0,
                    error=f"insufficient QRDX for gas: need {reserved}, available {avail}")
            self._record_balance_delta(tx.sender, -reserved)

        # 4. Execute the operation
        try:
            result = self._execute_op(tx)
        except Exception as e:
            logger.error("Exchange op %s failed: %s", tx.op_type.name, e)
            result = ExchangeExecResult(
                success=False, gas_used=base_gas, error=str(e)
            )

        # 5. Consume the nonce once the operation has EXECUTED — success or failure. It used
        #    to advance only on success, so a failing operation could be re-submitted and
        #    re-included indefinitely at the same nonce: one signed transaction, unlimited
        #    block space. Transactions rejected before execution (malformed, wrong nonce,
        #    under-gassed — steps 1-3) are not includable and consume nothing.
        self._nonces[tx.sender] = tx.nonce + 1

        # 6. Charge gas: gas_used × gas_price, burned; the rest of the reservation comes back.
        if result.gas_used == 0:
            result.gas_used = base_gas
        tx.gas_used = result.gas_used
        fee = tx.fee()
        if self.enforce_fees:
            self._record_balance_delta(tx.sender, reserved - fee)
            result.fee = fee
        self._block_fees += fee

        # 7. Record for block tracking
        tx.gas_used = result.gas_used
        tx.success = result.success
        tx.result = result.data
        tx.error = result.error
        self._block_exchange_txs.append(tx)
        self._block_results.append(result)

        return result

    def _execute_op(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Dispatch to the appropriate handler."""
        handlers = {
            ExchangeOpType.CREATE_POOL: self._op_create_pool,
            ExchangeOpType.REMOVE_POOL: self._op_remove_pool,
            ExchangeOpType.ADD_LIQUIDITY: self._op_add_liquidity,
            ExchangeOpType.REMOVE_LIQUIDITY: self._op_remove_liquidity,
            ExchangeOpType.SWAP: self._op_swap,
            ExchangeOpType.PLACE_ORDER: self._op_place_order,
            ExchangeOpType.CANCEL_ORDER: self._op_cancel_order,
            ExchangeOpType.OPEN_POSITION: self._op_retired_perp,
            ExchangeOpType.CLOSE_POSITION: self._op_retired_perp,
            ExchangeOpType.PARTIAL_CLOSE: self._op_retired_perp,
            ExchangeOpType.ADD_MARGIN: self._op_retired_perp,
            ExchangeOpType.PERP_DEPOSIT: self._op_perp_deposit,
            ExchangeOpType.PERP_WITHDRAW: self._op_perp_withdraw,
            ExchangeOpType.PERP_SET_LEVERAGE: self._op_perp_set_leverage,
            ExchangeOpType.PERP_ORDER: self._op_perp_order,
            ExchangeOpType.PERP_CANCEL: self._op_perp_cancel,
            ExchangeOpType.VAULT_DEPOSIT: self._op_vault_deposit,
            ExchangeOpType.VAULT_WITHDRAW: self._op_vault_withdraw,
            ExchangeOpType.ORACLE_VOTE: self._op_oracle_vote,
            ExchangeOpType.UPDATE_ORACLE: self._op_update_oracle,
            ExchangeOpType.CREATE_MARKET: self._op_create_market,
            ExchangeOpType.TOKEN_DEPLOY: self._op_token_deploy,
            ExchangeOpType.TOKEN_TRANSFER: self._op_token_transfer,
            ExchangeOpType.TOKEN_MINT: self._op_token_mint,
            ExchangeOpType.TOKEN_BURN: self._op_token_burn,
            ExchangeOpType.TOKEN_APPROVE: self._op_token_approve,
            ExchangeOpType.TOKEN_TRANSFER_FROM: self._op_token_transfer_from,
            ExchangeOpType.TOKEN_SET_AUTHORITY: self._op_token_set_authority,
            ExchangeOpType.TOKEN_FREEZE: self._op_token_freeze,
            ExchangeOpType.TOKEN_THAW: self._op_token_freeze,
            ExchangeOpType.TOKEN_UPDATE_METADATA: self._op_token_update_metadata,
            ExchangeOpType.TOKEN_SET_TRANSFER_FEE: self._op_token_set_transfer_fee,
            ExchangeOpType.TOKEN_WITHDRAW_FEES: self._op_token_withdraw_fees,
            ExchangeOpType.TOKEN_PAUSE: self._op_token_pause,
            ExchangeOpType.TOKEN_RESUME: self._op_token_pause,
            ExchangeOpType.TOKEN_AUTHORIZE_OPERATOR: self._op_token_operator,
            ExchangeOpType.TOKEN_REVOKE_OPERATOR: self._op_token_operator,
            ExchangeOpType.NFT_CREATE_COLLECTION: self._op_nft_create_collection,
            ExchangeOpType.NFT_MINT: self._op_nft_mint,
            ExchangeOpType.NFT_TRANSFER: self._op_nft_transfer,
            ExchangeOpType.NFT_BURN: self._op_nft_burn,
            ExchangeOpType.NFT_APPROVE: self._op_nft_approve,
            ExchangeOpType.NFT_SET_APPROVAL_FOR_ALL: self._op_nft_set_approval_for_all,
            ExchangeOpType.NFT_UPDATE: self._op_nft_update,
            ExchangeOpType.NFT_SET_AUTHORITY: self._op_nft_set_authority,
            ExchangeOpType.STAKE_DEPOSIT: self._op_stake_deposit,
            ExchangeOpType.STAKE_EXIT: self._op_stake_exit,
        }
        handler = handlers.get(tx.op_type)
        if handler is None:
            return ExchangeExecResult(
                success=False, error=f"Unknown op type: {tx.op_type}"
            )
        return handler(tx)

    # =====================================================================
    #  Operation handlers
    # =====================================================================

    def _op_create_pool(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        fee_tier = FeeTier(int(p["fee_tier"]))
        pool_type = PoolType[p["pool_type"]] if isinstance(p["pool_type"], str) else PoolType(int(p["pool_type"]))
        if p.get("initial_price") is not None:
            # Plain price, token1 per token0 of the CANONICAL (sorted) pair.
            sqrt_price = Decimal(str(p["initial_price"])).sqrt() * Q96
        else:
            sqrt_price = Decimal(str(p["initial_sqrt_price"]))
        stake = Decimal(str(p["stake_amount"]))

        # Phase E: pool creation must be backed by real QRDX. Check affordability of
        # the declared stake BEFORE creating (a failed op is not reverted), mirroring
        # the perp-margin path. create_pool() separately validates stake >= the
        # per-type minimum (raises) — this is the additional can-the-creator-afford-it
        # check.
        avail = self.available_balance(tx.sender)
        if avail is not None and avail < stake:
            if self.enforce_pool_stake:
                return ExchangeExecResult(
                    success=False,
                    error=(f"insufficient balance for pool stake: need {stake}, "
                           f"available {avail}"),
                )
            logger.warning(
                "[Phase E observe] create_pool by %s: stake %s exceeds available "
                "balance %s — would REJECT once pool stake is enforced",
                tx.sender[:20], stake, avail,
            )

        for asset in (self.canonical_asset(p["token0"]), self.canonical_asset(p["token1"])):
            t = self.tokens.get(asset)
            if t is not None and (t.fee_enabled or t.non_transferable):
                # Spot moves are exact (a pool's reserves, a book's escrow): a fee withheld
                # on the way in would break their accounting; a soulbound token cannot move.
                kind = "charges a transfer fee" if t.fee_enabled else "is non-transferable"
                return ExchangeExecResult(
                    success=False, error=f"{t.symbol} {kind}: it cannot be pooled or traded")
        try:
            pool = self.pool_manager.create_pool(
                self.canonical_asset(p["token0"]), self.canonical_asset(p["token1"]), fee_tier,
                pool_type, sqrt_price, tx.sender, stake,
            )
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))

        # Debit the stake as a real-balance move (flushed to account_state by the
        # async wrapper). Only RECORD the delta when enforcing — the shared flush is
        # already on for collateral, so recording unconditionally would debit even
        # while this gate is off. The stake is held in pool.state.stake_amount for a
        # future remove-pool return (staking pools) / forfeit (subsidized = burn).
        if self.enforce_pool_stake and stake > ZERO:
            self._record_balance_delta(tx.sender, -stake)

        # Create matching orderbook and oracle
        pair_key = f"{pool.state.token0}:{pool.state.token1}"
        if pair_key not in self._order_books:
            book = OrderBook(
                pool_id=pair_key,
                self_trade_action=SelfTradeAction.CANCEL_TAKER,
            )
            self._order_books[pair_key] = book
            self.router.register_order_book(pair_key, book)

        if pair_key not in self._oracles:
            oracle = TWAPOracle(pool_id=pair_key)
            self._oracles[pair_key] = oracle
            self.router.register_oracle(pair_key, oracle)

        self._total_pools += 1
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CREATE_POOL],
            data={"pool_id": pool.state.id, "pair": pair_key},
        )

    def _op_remove_pool(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Remove a pool the sender created and REFUND its staked QRDX (the mirror of the
        CREATE_POOL stake debit). Only the creator may, and only once no position remains —
        any position, in range or not, still owns tokens in the pool. The protocol's share of
        the fees it collected is paid out as §7.6 splits it: the creator's part (15 of 30) to
        the creator, the treasury's and validators' to the treasury. SUBSIDIZED pools burned
        their stake, so it is never refunded."""
        p = tx.params
        pool = self.pool_manager.get_pool(p["pool_id"]) if p.get("pool_id") else None
        if pool is None:
            return ExchangeExecResult(success=False, error=f"no such pool: {p.get('pool_id')}")
        if tx.sender != pool.state.creator:
            return ExchangeExecResult(success=False, error="only the pool creator may remove it")
        if pool.state.positions:
            return ExchangeExecResult(
                success=False,
                error=f"pool still has {len(pool.state.positions)} position(s); remove them first")

        from .amm import PoolType
        from .. import constants
        stake = Decimal(str(pool.state.stake_amount or 0))
        pool_type = pool.state.pool_type
        pair_key = f"{pool.state.token0}:{pool.state.token1}"
        holder = self.pool_holder_address(pool.state.id)
        treasury = constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"]
        share = FEE_CREATOR_SHARE / (FEE_CREATOR_SHARE + FEE_TREASURY_SHARE + FEE_VALIDATOR_SHARE)
        try:
            with self._atomic(pool):
                for token, fees in ((pool.state.token0, pool.state.protocol_fees_0),
                                    (pool.state.token1, pool.state.protocol_fees_1)):
                    to_creator = (fees * share).quantize(Decimal("1e-18"), rounding=ROUND_FLOOR)
                    self._settle_token_move(holder, pool.state.creator, token, to_creator)
                    self._settle_token_move(holder, treasury, token, fees - to_creator)
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))

        self.pool_manager.remove_pool(pool.state.id)
        # The order book and reporter oracle are per PAIR; keep them while another pool of the
        # pair remains (removing them would strand that book's resting orders).
        if not self.pool_manager.get_pools_for_pair(pool.state.token0, pool.state.token1):
            book = self._order_books.get(pair_key)
            if book is not None and not book._orders:
                self._order_books.pop(pair_key, None)
                self.router.unregister_order_book(pair_key)
            self._oracles.pop(pair_key, None)

        refunded = ZERO
        if self.enforce_pool_stake and pool_type != PoolType.SUBSIDIZED and stake > ZERO:
            self._record_balance_delta(tx.sender, stake)
            refunded = stake

        self._total_pools = max(0, self._total_pools - 1)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.REMOVE_POOL],
            data={"pool_id": pool.state.id, "refunded_stake": str(refunded),
                  "burned_stake": str(stake) if pool_type == PoolType.SUBSIDIZED else "0",
                  "protocol_fees": [str(pool.state.protocol_fees_0),
                                    str(pool.state.protocol_fees_1)]},
        )

    def _op_add_liquidity(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Deposit liquidity ``amount`` (L) in [tick_lower, tick_upper). The tokens it costs —
        rounded up, in the pool's favour — move from the provider to the pool's holder. The pool
        is named by ``pool_id``, or by ``token0`` / ``token1`` (+ ``fee_tier`` when the pair has
        several pools)."""
        p = tx.params
        pool = self.pool_manager.get_pool(p["pool_id"]) if p.get("pool_id") else None
        if pool is None and p.get("token0") and p.get("token1"):
            pool = self._find_pool_for_pair(self.canonical_asset(p["token0"]),
                                            self.canonical_asset(p["token1"]), p.get("fee_tier"))
        if pool is None:
            return ExchangeExecResult(success=False, error="Pool not found")
        tick_lower, tick_upper = int(p["tick_lower"]), int(p["tick_upper"])
        liquidity = Decimal(str(p["amount"]))
        try:
            pool._check_range(tick_lower, tick_upper)
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))
        if liquidity <= 0:
            return ExchangeExecResult(success=False, error="Liquidity amount must be positive")
        amt0, amt1 = pool.amounts_for_liquidity(tick_lower, tick_upper, liquidity, round_up=True)
        if self.enforce_spot_settlement:
            for tok, amt in ((pool.state.token0, amt0), (pool.state.token1, amt1)):
                av = self.available_token_balance(tx.sender, tok)
                if av is not None and av < amt:
                    return ExchangeExecResult(
                        success=False,
                        error=f"insufficient {tok[:10]} for liquidity: need {amt}, available {av}")
        holder = self.pool_holder_address(pool.state.id)
        with self._atomic(pool):
            position = pool.add_liquidity(tx.sender, tick_lower, tick_upper, liquidity,
                                          now=int(self._block_clock()))
            self._settle_token_move(tx.sender, holder, pool.state.token0, amt0)
            self._settle_token_move(tx.sender, holder, pool.state.token1, amt1)
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ADD_LIQUIDITY],
            data={"pool_id": pool.state.id, "position_id": position.id,
                  "liquidity": str(liquidity), "amount0": str(amt0), "amount1": str(amt1)})

    def _op_remove_liquidity(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Withdraw ``amount`` of L (default: all) from one of the SENDER's positions: its
        principal at the current price (rounded down) plus every fee it has earned move from
        the pool's holder to the owner. ``amount`` 0 collects fees only."""
        p = tx.params
        pool = self.pool_manager.get_pool(p["pool_id"])
        if pool is None:
            return ExchangeExecResult(success=False, error="Pool not found")
        position = pool.state.positions.get(str(p["position_id"]))
        if position is None:
            return ExchangeExecResult(success=False, error=f"Position {p['position_id']} not found")
        if position.owner != tx.sender:
            return ExchangeExecResult(
                success=False, error="only the position's owner may remove its liquidity")
        raw = p.get("amount")
        amount = Decimal(str(raw)) if raw not in (None, "", "all") else None
        if amount is not None and amount < 0:
            return ExchangeExecResult(success=False, error="amount must not be negative")
        holder = self.pool_holder_address(pool.state.id)
        try:
            with self._atomic(pool):
                out0, out1 = pool.remove_liquidity(position.id, amount, owner=tx.sender,
                                                   now=int(self._block_clock()))
                self._settle_token_move(holder, tx.sender, pool.state.token0, out0)
                self._settle_token_move(holder, tx.sender, pool.state.token1, out1)
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.REMOVE_LIQUIDITY],
            data={"pool_id": pool.state.id, "position_id": position.id,
                  "amount0": str(out0), "amount1": str(out1),
                  "removed": str((out0, out1))})

    def _find_pool_for_pair(self, token_a: str, token_b: str, fee_tier=None):
        """A pool for the pair: the one with ``fee_tier`` if given, else — only when the pair
        has exactly one pool — that one. Several pools and no fee tier is ambiguous: None."""
        pools = sorted(self.pool_manager.get_pools_for_pair(token_a, token_b),
                       key=lambda p: p.state.id)
        if fee_tier is not None:
            pools = [p for p in pools if int(p.state.fee_tier) == int(fee_tier)]
        return pools[0] if len(pools) == 1 else None

    @contextlib.contextmanager
    def _atomic(self, *engines):
        """All or nothing for one operation: if anything below raises, every touched pool or
        book and every recorded balance move is put back as it was. (``process_transaction``
        turns the exception into a failed result — and a failed operation must change
        nothing, or a swap that misses its own slippage limit could still move a pool's price
        for free.)"""
        saved = [(e, e.snapshot() if hasattr(e, "snapshot") else copy.deepcopy(e.__dict__))
                 for e in engines]
        ledgers = (dict(self._token_balance_deltas), dict(self._balance_deltas),
                   dict(self._available_token_balances), dict(self._available_balances))
        try:
            yield
        except Exception:
            for engine, snap in saved:
                if hasattr(engine, "restore"):
                    engine.restore(snap)
                else:
                    engine.__dict__.clear()
                    engine.__dict__.update(snap)
            (self._token_balance_deltas, self._balance_deltas,
             self._available_token_balances, self._available_balances) = ledgers
            raise

    def _op_swap(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Exact-input swap through the best venue — any of the pair's AMM pools or its order
        book (``pool_id`` pins a pool; ``venue`` = auto | amm | clob). Every check runs on the
        router's exact quote before anything changes, and the fill settles with its real
        counterparty: the pool's holder, or the matched makers' escrow."""
        p = tx.params
        token_in = self.canonical_asset(p["token_in"])
        token_out = self.canonical_asset(p["token_out"])
        amount_in = Decimal(str(p["amount_in"]))
        min_out = Decimal(str(p.get("min_amount_out", "0") or "0"))
        deadline = float(p.get("deadline", 0) or 0)
        if token_in == token_out:
            return ExchangeExecResult(success=False, error="token_in and token_out are the same")
        if amount_in <= 0:
            return ExchangeExecResult(success=False, error="amount_in must be positive")
        if deadline > 0 and self._block_clock() > deadline:
            return ExchangeExecResult(success=False, error="Transaction deadline expired")
        avail = self.available_token_balance(tx.sender, token_in)
        if avail is not None and avail < amount_in:
            if self.enforce_spot_settlement:
                return ExchangeExecResult(
                    success=False,
                    error=f"insufficient token_in: need {amount_in}, available {avail}")
            logger.warning("[Phase E observe] swap by %s: amount_in %s exceeds available %s",
                           tx.sender[:20], amount_in, avail)

        route = self.router.best_route(token_in, token_out, amount_in, tx.sender,
                                       pool_id=p.get("pool_id"),
                                       venue=str(p.get("venue", "auto")).lower())
        if route is None:
            return ExchangeExecResult(success=False, error="No liquidity available for this pair")
        if min_out > 0 and route.amount_out < min_out:
            return ExchangeExecResult(
                success=False,
                error=f"Slippage exceeded: got {route.amount_out}, minimum {min_out}")

        if route.source == FillSource.AMM:
            engine = self.pool_manager.get_pool(route.pool_id)
        else:
            engine = self._order_books[route.pair]
        try:
            with self._atomic(engine):
                result = self.router.apply_route(route, tx.sender, now=int(self._block_clock()))
                if route.source == FillSource.AMM:
                    holder = self.pool_holder_address(route.pool_id)
                    self._settle_token_move(tx.sender, holder, token_in, route.amount_in)
                    self._settle_token_move(holder, tx.sender, token_out, route.amount_out)
                else:
                    base, quote = route.pair.split(":", 1)
                    self._settle_orderbook(result.order, result.trades, base, quote, route.pair)
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))

        self._total_swaps += 1
        if route.source == FillSource.AMM:
            fills = [self._amm_fill(route, tx.sender)]
        else:
            fills = self._clob_fills(route.pair, result.trades, tx.sender, route.side)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.SWAP],
            data={
                "amount_in": str(route.amount_in),
                "amount_out": str(route.amount_out),
                "fee_total": str(route.fee_total),
                "price": str(route.price),
                "source": route.source.value,
                "pool_id": route.pool_id,
                "fills": fills,
            },
        )

    # A spot trade as the market-data feed sees it (journal.py → market_data.py): the pair in
    # canonical "base:quote" order, the price in quote per base, the base amount, and the
    # TAKER's side. Result data only — never hashed.

    @staticmethod
    def _clob_fills(pair: str, trades, taker: str, side) -> List[Dict[str, Any]]:
        side = getattr(side, "value", side)
        return [{"market": pair, "venue": "clob", "trade_id": t.id, "price": str(t.price),
                 "amount": str(t.amount), "buyer": t.buyer, "seller": t.seller,
                 "maker": t.seller if t.buyer == taker else t.buyer, "taker": taker,
                 "side": side} for t in trades]

    def _amm_fill(self, route, taker: str) -> Dict[str, Any]:
        pair = self._canonical_pair(f"{route.token_in}:{route.token_out}")
        base = pair.split(":", 1)[0]
        holder = self.pool_holder_address(route.pool_id)
        if route.token_in == base:          # selling base into the pool
            amount, quote_amount, side = route.amount_in, route.amount_out, "sell"
            buyer, seller = holder, taker
        else:
            amount, quote_amount, side = route.amount_out, route.amount_in, "buy"
            buyer, seller = taker, holder
        return {"market": pair, "venue": "amm", "pool_id": route.pool_id,
                "price": str(quote_amount / amount) if amount > 0 else "0",
                "amount": str(amount), "quote_amount": str(quote_amount), "buyer": buyer,
                "seller": seller, "maker": holder, "taker": taker, "side": side}

    def canonical_asset(self, value) -> str:
        """Spot's name for an asset: "QRDX" for native QRDX, a registered token's canonical
        address, anything else as given (qrdx/exchange/tokens.py)."""
        return canonical_asset(value, self.tokens)

    def _canonical_pair(self, pair: str) -> str:
        """Order books (like AMM pools) are keyed by the SORTED pair of canonical asset names —
        create_pool canonicalizes ``token0:token1`` (swaps if token0 > token1). Normalize a
        caller's pair the same way so PLACE_ORDER/CANCEL_ORDER find the book in either input
        order and with any spelling of QRDX or a token address."""
        if ":" in pair:
            a, b = (self.canonical_asset(x) for x in pair.split(":", 1))
            return f"{b}:{a}" if a > b else f"{a}:{b}"
        return pair

    def _op_place_order(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        pair = self._canonical_pair(p["pair"])
        book = self._order_books.get(pair)
        if book is None:
            return ExchangeExecResult(success=False, error=f"No order book for {pair}")

        # Robust enum parsing: accept string values ("buy") or names ("BUY")
        raw_side = p["side"]
        try:
            side = OrderSide(raw_side)
        except ValueError:
            side = OrderSide[str(raw_side).upper()]

        raw_otype = p["order_type"]
        try:
            order_type = OrderType(raw_otype)
        except ValueError:
            order_type = OrderType[str(raw_otype).upper()]

        order = Order(
            id=tx.tx_hash()[:16],  # deterministic from tx hash
            owner=tx.sender,
            side=side,
            order_type=order_type,
            price=Decimal(str(p.get("price", "0"))),
            amount=Decimal(str(p["amount"])),
            stop_price=Decimal(str(p["stop_price"])) if p.get("stop_price") else None,
            nonce=tx.nonce,
        )

        # Phase E CLOB settlement: reject what we cannot settle BEFORE matching mutates
        # the book (a failed op is NOT reverted — the block continues). Only plain LIMIT
        # orders are settled in this increment; MARKET/STOP need affordability handling
        # not yet built. The worst-case cost (full amount at the limit price) bounds the
        # taker's total outflow (fills at maker prices ≤ limit, + resting escrow), so a
        # taker that affords it can never overdraw.
        base, quote = (pair.split(":", 1) + [""])[:2] if ":" in pair else (pair, "")
        if self.enforce_orderbook_settlement:
            if order_type is not OrderType.LIMIT:
                return ExchangeExecResult(
                    success=False,
                    error=f"CLOB settlement supports LIMIT orders only (got {order_type.value})")
            need_token = quote if side == OrderSide.BUY else base
            need_amount = (order.amount * order.price) if side == OrderSide.BUY else order.amount
            avail = self.available_token_balance(tx.sender, need_token)
            if avail is not None and avail < need_amount:
                return ExchangeExecResult(
                    success=False,
                    error=f"insufficient balance for order: need {need_amount} {need_token[:10]}, "
                          f"available {avail}")

        try:
            with self._atomic(book):
                trades = book.place_order(order)
                if self.enforce_orderbook_settlement:
                    self._settle_orderbook(order, trades, base, quote, pair)
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))

        self._total_orders += 1
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER],
            data={
                "order_id": order.id,
                "trades": len(trades),
                "filled": str(order.filled),
                "fills": self._clob_fills(pair, trades, tx.sender, side),
            },
        )

    def _settle_orderbook(self, order, trades, base: str, quote: str, pair: str) -> None:
        """Settle a CLOB order's matched trades + escrow its resting remainder as real
        token moves (Phase E). Conserves both tokens: each trade moves base seller→buyer
        and quote buyer→seller; the MAKER's side (the resting party) comes from the book
        escrow it funded at placement, the TAKER's (this order's owner) comes live; the
        taker keeps any price improvement automatically (it pays the maker's price, not
        its limit). The resting remainder is escrowed; CANCEL_ORDER refunds it."""
        taker = order.owner
        escrow = self.orderbook_escrow_address(pair)
        for tr in trades:
            f = Decimal(str(tr.amount))
            notional = f * Decimal(str(tr.price))
            # base: seller → buyer (taker pays live; resting maker's side from escrow)
            base_src = tr.seller if tr.seller == taker else escrow
            self._settle_token_move(base_src, tr.buyer, base, f)
            # quote: buyer → seller (same maker-escrow / taker-live split)
            quote_src = tr.buyer if tr.buyer == taker else escrow
            self._settle_token_move(quote_src, tr.seller, quote, notional)
        # Escrow this order's UNFILLED remainder (it now rests on the book).
        r = Decimal(str(order.remaining))
        if r > ZERO and order.is_active:
            if order.side == OrderSide.BUY:
                self._settle_token_move(taker, escrow, quote, r * Decimal(str(order.price)))
            else:
                self._settle_token_move(taker, escrow, base, r)

    def _op_cancel_order(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        order_id = p["order_id"]
        pair = self._canonical_pair(p.get("pair", ""))

        # Search across all books if pair not specified
        if pair and pair in self._order_books:
            books_to_check = [self._order_books[pair]]
        else:
            books_to_check = list(self._order_books.values())

        for book in books_to_check:
            try:
                with self._atomic(book):
                    result = book.cancel_order(order_id, caller=tx.sender)
                    # Phase E CLOB: refund the cancelled order's escrowed remainder
                    # (exactly what it locked at placement: remaining*price quote for a BUY,
                    # remaining base for a SELL — the book's pair is token0:token1).
                    if result is not None and self.enforce_orderbook_settlement:
                        book_pair = getattr(book, "pool_id", "") or ""
                        rbase, rquote = (book_pair.split(":", 1) + [""])[:2] if ":" in book_pair else (book_pair, "")
                        r = Decimal(str(result.remaining))
                        if r > ZERO:
                            escrow = self.orderbook_escrow_address(book_pair)
                            if result.side == OrderSide.BUY:
                                self._settle_token_move(escrow, result.owner, rquote, r * Decimal(str(result.price)))
                            else:
                                self._settle_token_move(escrow, result.owner, rbase, r)
            except ValueError as e:
                return ExchangeExecResult(success=False, error=str(e))
            if result is not None:
                return ExchangeExecResult(
                    success=True,
                    gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CANCEL_ORDER],
                    data={"order_id": order_id, "status": "cancelled"},
                )

        return ExchangeExecResult(success=False, error=f"Order {order_id} not found")

    def _op_create_market(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Create a perp market — an order book in the clearinghouse (consensus path).

        Maintenance margin is half the initial margin at ``max_leverage``; the old
        ``initial_margin_rate`` / ``maintenance_margin_rate`` params are no longer read.
        A duplicate market is a non-critical failure, not a block-breaking error.
        """
        from .. import constants
        p = tx.params
        base = str(p["base_token"])
        quote = str(p.get("quote_token", constants.PERP_QUOTE))
        try:
            if "max_leverage" in p:
                market = self.clearinghouse.create_market(
                    base, quote, max_leverage=Decimal(str(p["max_leverage"])))
            else:
                market = self.clearinghouse.create_market(base, quote)
        except ClearinghouseError as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CREATE_MARKET],
            data={"market_id": market.id},
        )

    @staticmethod
    def derive_token_address(sender: str, nonce: int, symbol: str) -> str:
        """Deterministic QRC-20 token address from the deploy tx (consensus-stable:
        every node derives the same address from the same tx)."""
        seed = f"{sender}:{int(nonce)}:{symbol}".encode()
        return "0x" + hashlib.blake2b(seed, digest_size=20).hexdigest()

    @staticmethod
    def pool_holder_address(pool_id: str) -> str:
        """Deterministic token-ledger holder address for an AMM pool's reserves
        (Phase E spot). Liquidity providers' tokens move INTO this holder; swap
        outputs move OUT of it — so pool reserves are real, conserved token balances."""
        return "0xPOOL" + hashlib.blake2b(f"pool:{pool_id}".encode(), digest_size=18).hexdigest()

    @staticmethod
    def orderbook_escrow_address(pair: str) -> str:
        """Deterministic token-ledger holder for a CLOB book's RESTING-order funds
        (Phase E spot). A placed limit order's funds move INTO this holder; matched
        fills + cancels move OUT — so resting orders are backed by real, conserved
        token balances (the same pattern as ``pool_holder_address`` for AMM reserves)."""
        return "0xCLOB" + hashlib.blake2b(f"book:{pair}".encode(), digest_size=18).hexdigest()

    def _settle_token_move(self, frm: str, to: str, token: str, amount: Decimal) -> None:
        """Phase E spot: record a token move frm→to as paired deltas (no-op for 0). Raises if
        ``frm`` — a trader, a pool's holder or a book's escrow — cannot cover it, so the
        enclosing operation fails whole (see ``_atomic``) instead of the ledger flush clamping a
        debit while its credit lands, which would mint the difference."""
        if amount and amount > ZERO:
            if not is_native_asset(token):
                if self.tokens.is_frozen(token, frm):
                    raise ValueError(f"{frm[:16]}…'s {token[:12]}… balance is frozen")
                t = self.tokens.get(token)
                if t is not None and t.paused:
                    raise ValueError(f"{t.symbol} is paused")
            avail = self.available_token_balance(frm, token)
            if avail is None:
                # Every debit's balance is loaded with its block (block_processor.
                # preload_token_balances). One that was not is a gap in that list: refuse it
                # rather than let an unchecked debit overdraw the ledger.
                if self.enforce_spot_settlement:
                    raise ValueError(f"{frm[:16]}…'s {token[:12]}… balance was not loaded "
                                     "for this block")
            elif avail < amount:
                # The protocol's holders (pool reserves, book escrow, the perps clearinghouse)
                # are always held to it; a trader only once spot settlement is enforced (in
                # observe mode their overdraft is logged by the flush, not refused).
                from ..crypto.account_id import is_synthetic_holder
                if self.enforce_spot_settlement or is_synthetic_holder(frm):
                    raise ValueError(f"{frm[:16]}… cannot cover {amount} of {token[:12]}… "
                                     f"(holds {avail})")
            if is_native_asset(token):
                # Native QRDX lives in account_state: the move rides the balance flush.
                self._record_balance_delta(frm, -amount)
                self._record_balance_delta(to, amount)
            else:
                self._record_token_delta(frm, token, -amount)
                self._record_token_delta(to, token, amount)

    def _op_token_deploy(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Deploy a native token (qrdx/exchange/tokens.py): its registry entry — name, symbol,
        display decimals, optional supply cap, mint and freeze authorities — and its initial
        supply, credited to the deployer. The address derives from the deploy transaction, so
        every node agrees on it. A token with no initial supply needs a mint authority (a
        bridge's stablecoin starts at zero and is minted as deposits arrive)."""
        p = tx.params
        symbol = str(p.get("symbol", ""))
        address = self.derive_token_address(tx.sender, tx.nonce, symbol)
        try:
            token = self.tokens.deploy(
                address, tx.sender, self._current_block_height,
                name=p.get("name", ""), symbol=symbol, decimals=p.get("decimals", 18),
                initial_supply=p.get("initial_supply", p.get("total_supply", 0)),
                max_supply=p.get("max_supply"), mint_authority=p.get("mint_authority"),
                freeze_authority=p.get("freeze_authority"), extensions=p)
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_DEPLOY: {e}")
        if token.supply > 0:
            self._record_token_delta(tx.sender, token.address, token.supply)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_DEPLOY],
            data={"token_address": token.address, "symbol": token.symbol,
                  "total_supply": str(token.supply), "decimals": token.decimals,
                  "mint_authority": token.mint_authority,
                  "freeze_authority": token.freeze_authority,
                  "extensions": token.extensions()},
        )

    def _token_move(self, op: str, token: str, frm: str, to: str, value) -> Tuple[Any, Decimal, Decimal]:
        """Validate a holder-to-holder move of a registered token: the token, the amount, a
        keyable recipient (an unkeyable one would have its credit dropped while the debit
        applied — burning the tokens), the token's transfer rules (paused, non-transferable,
        a frozen sender) and the sender's balance. Returns the token, the amount and the
        transfer fee it withholds. Raises TokenError."""
        t = self.tokens.require(token)
        v = token_amount(value)
        token_account(to)
        fee = self.tokens.check_transfer(t.address, frm, self._current_block_height, v)
        avail = self.available_token_balance(frm, t.address)
        if avail is not None and avail < v:
            if self.enforce_spot_settlement:
                raise TokenError(f"insufficient token balance: need {v}, available {avail}")
            logger.warning("[Phase E observe] %s by %s: amount %s exceeds available %s — would "
                           "REJECT once spot settlement is enforced", op, frm[:20], v, avail)
        return t, v, fee

    def _transfer_with_fee(self, frm: str, to: str, t, v: Decimal, fee: Decimal) -> None:
        """``to`` receives ``v`` less the fee; the fee is withheld at the token's own address
        (the withdraw authority collects it with TOKEN_WITHDRAW_FEES)."""
        self._settle_token_move(frm, to, t.address, v - fee)
        if fee > ZERO:
            self._settle_token_move(frm, t.address, t.address, fee)

    def _op_token_transfer(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Move tokens from the sender to ``to`` in the token ledger (less any transfer fee),
        with an optional ``memo``."""
        p = tx.params
        to = str(p["to"])
        try:
            note = token_memo(p.get("memo"))
            t, v, fee = self._token_move("token_transfer", str(p["token_address"]), tx.sender,
                                         to, p["amount"])
            self._transfer_with_fee(tx.sender, to, t, v, fee)
        except (TokenError, ValueError) as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_TRANSFER: {e}")
        data = {"token_address": t.address, "to": to, "amount": str(v)}
        if fee:
            data.update(fee=str(fee), received=str(v - fee))
        if note:
            data["memo"] = note
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_TRANSFER], data=data)

    def _spend_authority(self, t, owner: str, spender: str, v: Decimal) -> str:
        """How ``spender`` may move ``owner``'s tokens: as the permanent delegate, as an
        operator (ERC-777), or within an allowance. Raises TokenError if none."""
        if self.tokens.is_permanent_delegate(t.address, spender):
            return "permanent_delegate"
        if self.tokens.is_operator(t.address, owner, spender):
            return "operator"
        have = self.tokens.allowance(t.address, owner, spender)
        if have < v:
            raise TokenError(f"allowance {have} is less than {v}")
        return "allowance"

    def _op_token_transfer_from(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The sender moves ``from``'s tokens to ``to``: within the allowance ``from``
        approved (which it consumes), as one of ``from``'s operators, or as the token's
        permanent delegate."""
        p = tx.params
        owner, to = str(p["from"]), str(p["to"])
        try:
            note = token_memo(p.get("memo"))
            t, v, fee = self._token_move("token_transfer_from", str(p["token_address"]), owner,
                                         to, p["amount"])
            via = self._spend_authority(t, owner, tx.sender, v)
            self._transfer_with_fee(owner, to, t, v, fee)
        except (TokenError, ValueError) as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_TRANSFER_FROM: {e}")
        data = {"token_address": t.address, "from": owner, "to": to, "amount": str(v), "via": via}
        if via == "allowance":
            data["allowance_left"] = str(self.tokens.spend_allowance(t.address, owner,
                                                                     tx.sender, v))
        if fee:
            data.update(fee=str(fee), received=str(v - fee))
        if note:
            data["memo"] = note
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_TRANSFER_FROM],
            data=data)

    def _op_token_mint(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The mint authority mints ``amount`` to ``to`` (default: itself), within any cap."""
        p = tx.params
        to = str(p.get("to") or tx.sender)
        try:
            token_account(to)
            t = self.tokens.require(str(p["token_address"]))
            v = self.tokens.mint(t.address, tx.sender, p["amount"])
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_MINT: {e}")
        self._record_token_delta(to, t.address, v)
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_MINT],
            data={"token_address": t.address, "to": to, "amount": str(v),
                  "total_supply": str(t.supply)})

    def _op_token_burn(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A holder burns ``amount`` of its own balance — or, naming ``from``, an operator or
        the permanent delegate burns another holder's; the supply falls by as much."""
        p = tx.params
        holder = str(p.get("from") or tx.sender)
        try:
            t = self.tokens.require(str(p["token_address"]))
            v = token_amount(p["amount"])
            via = "holder"
            if token_account(holder) != token_account(tx.sender):
                if self.tokens.is_permanent_delegate(t.address, tx.sender):
                    via = "permanent_delegate"
                elif self.tokens.is_operator(t.address, holder, tx.sender):
                    via = "operator"
                else:
                    raise TokenError("only the holder, its operators or the permanent delegate "
                                     "may burn its balance")
            if self.tokens.is_frozen(t.address, holder):
                raise TokenError("the holder's balance is frozen")
            avail = self.available_token_balance(holder, t.address)
            if self.enforce_spot_settlement and (avail is None or avail < v):
                raise TokenError(f"insufficient token balance: need {v}, available {avail}")
            self.tokens.burn(t.address, v)
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_BURN: {e}")
        self._record_token_delta(holder, t.address, -v)
        data = {"token_address": t.address, "amount": str(v), "total_supply": str(t.supply)}
        if via != "holder":
            data.update(**{"from": holder, "via": via})
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_BURN], data=data)

    def _op_token_approve(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Set ``spender``'s allowance over the sender's tokens to ``amount`` (0 revokes)."""
        p = tx.params
        try:
            t = self.tokens.require(str(p["token_address"]))
            v = self.tokens.approve(t.address, tx.sender, str(p["spender"]), p["amount"])
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_APPROVE: {e}")
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_APPROVE],
            data={"token_address": t.address, "spender": str(p["spender"]), "amount": str(v)})

    def _op_token_set_authority(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Hand the mint or freeze authority to ``new_authority``, or renounce it (empty) —
        irreversibly."""
        p = tx.params
        try:
            t = self.tokens.require(str(p["token_address"]))
            new = self.tokens.set_authority(t.address, tx.sender, str(p["authority"]),
                                            p.get("new_authority"))
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_SET_AUTHORITY: {e}")
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_SET_AUTHORITY],
            data={"token_address": t.address, "authority": str(p["authority"]).lower(),
                  "new_authority": new})

    def _op_token_freeze(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """TOKEN_FREEZE / TOKEN_THAW: the freeze authority stops (or lets again) ``account``
        moving its balance of the token."""
        p = tx.params
        frozen = tx.op_type == ExchangeOpType.TOKEN_FREEZE
        try:
            t = self.tokens.require(str(p["token_address"]))
            self.tokens.freeze(t.address, tx.sender, str(p["account"]), frozen)
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"{tx.op_type.name}: {e}")
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[tx.op_type],
            data={"token_address": t.address, "account": str(p["account"]), "frozen": frozen})

    def _op_token_update_metadata(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The metadata authority edits the token's name, symbol, uri and extra fields."""
        p = tx.params
        try:
            t = self.tokens.update_metadata(str(p["token_address"]), tx.sender, p)
        except (TokenError, KeyError) as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_UPDATE_METADATA: {e}")
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_UPDATE_METADATA],
            data={"token_address": t.address, "name": t.name, "symbol": t.symbol,
                  "uri": t.uri, "fields": dict(t.fields)})

    def _op_token_set_transfer_fee(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The fee authority sets a new transfer-fee rate and cap, effective
        FEE_UPDATE_DELAY_BLOCKS later."""
        p = tx.params
        try:
            bps, cap, height = self.tokens.set_transfer_fee(
                str(p["token_address"]), tx.sender, self._current_block_height,
                p["transfer_fee_bps"], p.get("max_transfer_fee"))
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_SET_TRANSFER_FEE: {e}")
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_SET_TRANSFER_FEE],
            data={"token_address": str(p["token_address"]).lower(), "transfer_fee_bps": bps,
                  "max_transfer_fee": None if cap is None else str(cap), "from_height": height})

    def _op_token_withdraw_fees(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The withdraw authority moves every withheld transfer fee to ``to`` (default: itself)."""
        p = tx.params
        to = str(p.get("to") or tx.sender)
        try:
            token_account(to)
            t = self.tokens.check_withdraw_authority(str(p["token_address"]), tx.sender)
            withheld = self.available_token_balance(t.address, t.address)
            if withheld is None:
                raise TokenError("the withheld balance was not loaded for this block")
            if withheld > ZERO:
                self._settle_token_move(t.address, to, t.address, withheld)
        except (TokenError, ValueError) as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_WITHDRAW_FEES: {e}")
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_WITHDRAW_FEES],
            data={"token_address": t.address, "to": to, "amount": str(withheld)})

    def _op_token_pause(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """TOKEN_PAUSE / TOKEN_RESUME: the pause authority stops (or restarts) every transfer,
        mint and burn of the token — spot and perps moves of it included."""
        p = tx.params
        paused = tx.op_type == ExchangeOpType.TOKEN_PAUSE
        try:
            self.tokens.set_paused(str(p["token_address"]), tx.sender, paused)
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"{tx.op_type.name}: {e}")
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[tx.op_type],
            data={"token_address": str(p["token_address"]).lower(), "paused": paused})

    def _op_token_operator(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """TOKEN_AUTHORIZE_OPERATOR / TOKEN_REVOKE_OPERATOR (ERC-777): the sender lets
        ``operator`` move (and burn) its balance of the token without an allowance — or stops
        it, a default operator included."""
        p = tx.params
        authorized = tx.op_type == ExchangeOpType.TOKEN_AUTHORIZE_OPERATOR
        try:
            self.tokens.set_operator(str(p["token_address"]), tx.sender, str(p["operator"]),
                                     authorized)
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"{tx.op_type.name}: {e}")
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[tx.op_type],
            data={"token_address": str(p["token_address"]).lower(),
                  "operator": str(p["operator"]), "authorized": authorized})

    # ── native NFTs (qrdx/exchange/nfts.py) ─────────────────────────────

    @staticmethod
    def derive_collection_address(sender: str, nonce: int, symbol: str) -> str:
        """Deterministic NFT collection address from the creating transaction (a different
        domain from token addresses, so the two never collide)."""
        seed = f"nft-collection:{sender}:{int(nonce)}:{symbol}".encode()
        return "0x" + hashlib.blake2b(seed, digest_size=20).hexdigest()

    def _nft(self, tx: ExchangeTransaction, fn) -> ExchangeExecResult:
        try:
            data = fn(tx.params)
        except (NftError, TokenError) as e:
            return ExchangeExecResult(success=False, error=f"{tx.op_type.name}: {e}")
        return ExchangeExecResult(success=True, gas_used=EXCHANGE_GAS_COSTS[tx.op_type],
                                  data=data)

    def _op_nft_create_collection(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Create an NFT collection: name, symbol, uri, optional size cap, royalties, update and
        mint authorities (both the creator unless given), optionally soulbound."""
        def go(p):
            address = self.derive_collection_address(tx.sender, tx.nonce, str(p.get("symbol", "")))
            if self.tokens.get(address) is not None:
                raise NftError(f"{address} is a token")
            return self.nfts.create(address, tx.sender, self._current_block_height, p).summary()
        return self._nft(tx, go)

    def _op_nft_mint(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The collection's mint authority mints the next NFT (or ``token_id``) to ``to``
        (default: itself), with its own uri and name."""
        def go(p):
            to = str(p.get("to") or tx.sender)
            i = self.nfts.mint(str(p["collection"]), tx.sender, to, self._current_block_height,
                               uri=p.get("uri", ""), name=p.get("name", ""),
                               tid=p.get("token_id"))
            return {"collection": str(p["collection"]).lower(), "token_id": str(i), "to": to}
        return self._nft(tx, go)

    def _op_nft_transfer(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Move an NFT to ``to``: by its owner, its approved account or an operator of the
        owner's (``from`` names the owner when the sender is not it)."""
        def go(p):
            note = token_memo(p.get("memo"))
            frm = str(p.get("from") or tx.sender)
            self.nfts.transfer(str(p["collection"]), p["token_id"], tx.sender, frm, str(p["to"]))
            out = {"collection": str(p["collection"]).lower(),
                   "token_id": str(nft_token_id(p["token_id"])), "from": frm, "to": str(p["to"])}
            if note:
                out["memo"] = note
            return out
        return self._nft(tx, go)

    def _op_nft_burn(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        def go(p):
            owner = self.nfts.item(str(p["collection"]), p["token_id"]).owner
            self.nfts.burn(str(p["collection"]), p["token_id"], tx.sender)
            return {"collection": str(p["collection"]).lower(),
                    "token_id": str(nft_token_id(p["token_id"])), "owner": owner}
        return self._nft(tx, go)

    def _op_nft_approve(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The owner (or an operator) approves one account for one NFT ("" clears it)."""
        def go(p):
            spender = self.nfts.approve(str(p["collection"]), p["token_id"], tx.sender,
                                        p.get("spender"))
            return {"collection": str(p["collection"]).lower(),
                    "token_id": str(nft_token_id(p["token_id"])), "spender": spender}
        return self._nft(tx, go)

    def _op_nft_set_approval_for_all(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The sender approves (``approved``, default true) or revokes an operator for all its
        NFTs in the collection."""
        def go(p):
            approved = p.get("approved", True)
            approved = (str(approved).lower() in ("1", "true", "yes")
                        if isinstance(approved, str) else bool(approved))
            self.nfts.set_operator(str(p["collection"]), tx.sender, str(p["operator"]), approved)
            return {"collection": str(p["collection"]).lower(), "operator": str(p["operator"]),
                    "approved": approved}
        return self._nft(tx, go)

    def _op_nft_update(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        return self._nft(tx, lambda p: self.nfts.update(str(p["collection"]), tx.sender, p))

    def _op_nft_set_authority(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        def go(p):
            new = self.nfts.set_authority(str(p["collection"]), tx.sender, str(p["authority"]),
                                          p.get("new_authority"))
            return {"collection": str(p["collection"]).lower(),
                    "authority": str(p["authority"]).lower(), "new_authority": new}
        return self._nft(tx, go)

    def token_registry_ops(self) -> List[Dict[str, Any]]:
        """The registry rows of the tokens this block deployed or changed (supply,
        authorities), for the DB mirror (``token_registry``)."""
        return [self.tokens.tokens[a].summary() for a in sorted(self.tokens.changed)
                if a in self.tokens.tokens]

    def _op_stake_deposit(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """
        Validator-lifecycle Phase 3: a staking deposit registers the SENDER as a
        validator. Records a deterministic 'deposit' op (address=sender, the supplied
        validator public key, stake) flushed to the consensus validators table as a
        PENDING validator; the all-nodes epoch loop schedules + activates it (so every
        node agrees on membership).

        **The stake must be real.** The claimed ``stake_amount`` becomes the
        validator's ``effective_stake`` in the consensus ``validators`` table, and that
        figure weights BOTH stake-weighted proposer selection and fork-choice attesting
        weight. An unbacked claim is therefore a consensus attack: without these checks
        an account holding nothing could claim more stake than the whole honest set and
        dominate block production and fork choice. So under
        ``enforce_validator_stake`` a deposit must:

          1. clear ``MIN_VALIDATOR_STAKE`` — the same floor the local registration API
             (``validator/manager.py``) and epoch activation already apply, which the
             consensus join path was silently skipping;
          2. be backed by the sender's real ``account_state`` balance; and
          3. be DEBITED, so the stake is genuinely at risk and cannot be spent twice.

        The debit is refunded at the deterministic finalized exit epoch (see
        ``epoch_loop._refund_exited_validator_stakes``). A SLASHED validator moves to
        status 'slashed', never reaches 'exited', and so forfeits its stake — which is
        what makes slashing bite.

        Genesis validators are NOT debited: their stake is declared by the genesis file,
        which is the chain's trust root. This gate governs *joining* validators.
        """
        p = tx.params
        try:
            stake = Decimal(str(p["stake_amount"]))
        except Exception:
            return ExchangeExecResult(success=False, error="STAKE_DEPOSIT: invalid stake_amount")
        if stake <= 0:
            return ExchangeExecResult(success=False, error="STAKE_DEPOSIT: stake must be positive")

        if self.enforce_validator_stake:
            from ..constants import MIN_VALIDATOR_STAKE

            # (1) Minimum stake. Deterministic — a pure comparison against a constant.
            if stake < MIN_VALIDATOR_STAKE:
                return ExchangeExecResult(
                    success=False,
                    error=(f"STAKE_DEPOSIT: stake {stake} below minimum "
                           f"{MIN_VALIDATOR_STAKE} QRDX"),
                )

            # (2) Ownership. ``available_balance`` is pre-loaded from account_state by
            # preload_sender_balances on every path, so this reads the same value on
            # every node. A missing pre-load (None) means the balance could not be
            # read; refuse rather than assume solvency — a deposit is too dangerous to
            # admit unverified.
            avail = self.available_balance(tx.sender)
            if avail is None:
                return ExchangeExecResult(
                    success=False,
                    error="STAKE_DEPOSIT: sender balance unavailable; cannot verify stake",
                )
            if avail < stake:
                return ExchangeExecResult(
                    success=False,
                    error=(f"STAKE_DEPOSIT: insufficient balance for stake: need {stake}, "
                           f"available {avail}"),
                )
        else:
            avail = self.available_balance(tx.sender)
            if avail is not None and avail < stake:
                logger.warning(
                    "[observe] stake_deposit by %s: claimed stake %s exceeds available "
                    "balance %s — would REJECT once validator stake is enforced",
                    tx.sender[:20], stake, avail,
                )

        self._validator_lifecycle_ops.append({
            "type": "deposit", "address": tx.sender,
            "public_key": str(p["validator_public_key"]), "stake": str(stake),
        })
        if self.oracle_committee is not None:
            key = tx.sender.lower()
            self.oracle_committee[key] = self.oracle_committee.get(key, ZERO) + stake

        # (3) Lock it. Gate the RECORDING, not just the flush: the shared
        # account_state flush is already enforced for collateral, so recording
        # unconditionally would debit even while this gate is off.
        if self.enforce_validator_stake:
            self._record_balance_delta(tx.sender, -stake)

        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_DEPOSIT],
            data={"validator": tx.sender, "stake": str(stake), "status": "pending",
                  "staked_debit": str(stake) if self.enforce_validator_stake else "0"},
        )

    def _op_stake_exit(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Validator-lifecycle Phase 3: the sender signals a voluntary exit. Records a
        deterministic 'exit' op; the all-nodes epoch loop schedules exit_epoch and moves
        the validator exiting→exited."""
        self._validator_lifecycle_ops.append({"type": "exit", "address": tx.sender})
        if self.oracle_committee is not None:
            self.oracle_committee.pop(tx.sender.lower(), None)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_EXIT],
            data={"validator": tx.sender, "status": "exiting"},
        )

    def validator_lifecycle_ops(self) -> List[Dict[str, Any]]:
        """This block's accumulated staking deposit/exit ops (Phase 3)."""
        return list(self._validator_lifecycle_ops)

    # =====================================================================
    #  Perps clearinghouse (docs/PERPS_CLEARINGHOUSE.md)
    # =====================================================================

    @staticmethod
    def perps_holder_address() -> str:
        """The single holder of all perp collateral. Real QRDX moves only between a trader and
        this holder (deposit / withdraw); trading moves value between internal records."""
        return "0xPERP" + hashlib.blake2b(b"perps:clearinghouse", digest_size=18).hexdigest()

    def _op_retired_perp(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        return ExchangeExecResult(
            success=False,
            error=(f"{tx.op_type.name} is retired: it traded against nobody, so it minted and "
                   f"burned QRDX. Perps trade on the order book — PERP_DEPOSIT, then PERP_ORDER."))

    @staticmethod
    def perp_collateral_token() -> str:
        """What perps settle in: a QRC-20 token address (production: the bridged USD
        stablecoin), "QRDX" for native QRDX, or "" when none is configured."""
        from .. import constants
        return constants.PERP_COLLATERAL_TOKEN

    def _op_perp_deposit(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        token = self.perp_collateral_token()
        if not token:
            return ExchangeExecResult(
                success=False, error="perps have no collateral token configured")
        amount = Decimal(str(tx.params["amount"]))
        native = token.upper() == "QRDX"
        if native:
            avail = self.available_balance(tx.sender)
            if avail is not None and avail < amount and self.enforce_collateral:
                return ExchangeExecResult(
                    success=False, error=f"insufficient balance: need {amount}, available {avail}")
        else:
            # Always enforced: the token flush is not gated, so admitting an unaffordable
            # deposit would apply the holder's credit while the sender's debit could not land.
            avail = self.available_token_balance(tx.sender, token)
            if avail is None or avail < amount:
                return ExchangeExecResult(
                    success=False,
                    error=f"insufficient collateral token balance: need {amount}, available {avail}")
        try:
            amount = self.clearinghouse.deposit(tx.sender, amount)
        except ClearinghouseError as e:
            return ExchangeExecResult(success=False, error=str(e))
        if native:
            self._record_balance_delta(tx.sender, -amount)
            self._record_balance_delta(self.perps_holder_address(), amount)
        else:
            self._settle_token_move(tx.sender, self.perps_holder_address(), token, amount)
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_DEPOSIT],
            data={"collateral": str(self.clearinghouse.accounts[tx.sender].collateral)})

    def _op_perp_withdraw(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        token = self.perp_collateral_token()
        if not token:
            return ExchangeExecResult(
                success=False, error="perps have no collateral token configured")
        try:
            amount = self.clearinghouse.withdraw(tx.sender, Decimal(str(tx.params["amount"])))
        except ClearinghouseError as e:
            return ExchangeExecResult(success=False, error=str(e))
        if token.upper() == "QRDX":
            self._record_balance_delta(self.perps_holder_address(), -amount)
            self._record_balance_delta(tx.sender, amount)
        else:
            self._settle_token_move(self.perps_holder_address(), tx.sender, token, amount)
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_WITHDRAW],
            data={"collateral": str(self.clearinghouse.accounts[tx.sender].collateral)})

    def _op_vault_deposit(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Perp collateral → backstop vault shares at NAV. Internal to the clearinghouse: no
        real balance moves (the vault's collateral is inside the perps holder too)."""
        from .. import constants
        seeder = tx.sender.lower() in {a.lower() for a in constants.PERP_VAULT_SEEDERS}
        try:
            shares = self.clearinghouse.vault_deposit(
                tx.sender, Decimal(str(tx.params["amount"])), self._block_clock(),
                constants.PERP_VAULT_LOCKUP_SECONDS, protocol=seeder)
        except (ClearinghouseError, ValueError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_DEPOSIT],
            data={"shares": str(shares), "protocol_owned": seeder})

    def _op_vault_withdraw(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        try:
            value = self.clearinghouse.vault_withdraw(
                tx.sender, Decimal(str(tx.params["shares"])), self._block_clock())
        except (ClearinghouseError, ValueError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_WITHDRAW],
            data={"value": str(value)})

    def _op_perp_set_leverage(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        mode = str(p.get("mode", "cross")).lower()
        if mode not in ("cross", "isolated"):
            return ExchangeExecResult(success=False, error=f"unknown margin mode {mode!r}")
        try:
            self.clearinghouse.set_leverage(tx.sender, str(p["market_id"]),
                                            Decimal(str(p["leverage"])), mode == "isolated")
        except ClearinghouseError as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_SET_LEVERAGE])

    def _op_perp_order(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        order_id = tx.tx_hash()[:16]
        from .. import constants
        m = self.clearinghouse.markets.get(str(p["market_id"]))
        if (m is not None and not bool(p.get("reduce_only", False)) and m.oracle_time > 0
                and Decimal(str(self._block_clock())) - m.oracle_time
                > constants.PERP_ORACLE_STALE_SECONDS):
            return ExchangeExecResult(
                success=False,
                error=f"the oracle for {m.id} is stale; only reduce-only orders are accepted")
        try:
            fills = self.clearinghouse.place_order(
                tx.sender, str(p["market_id"]), order_id, str(p["side"]),
                Decimal(str(p["size"])), Decimal(str(p["price"])), tx.nonce,
                reduce_only=bool(p.get("reduce_only", False)),
                ioc=str(p.get("tif", "gtc")).lower() == "ioc")
        except (ClearinghouseError, ValueError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        # Not resting after its fills: filled, IOC, or stopped by self-trade prevention
        # (an order that would hit the sender's own resting order is cancelled there).
        resting = order_id in self.clearinghouse.markets[str(p["market_id"])].orders
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER],
            data={"order_id": order_id, "fills": fills, "resting": resting})

    def _op_perp_cancel(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        try:
            self.clearinghouse.cancel_order(tx.sender, str(p["market_id"]), str(p["order_id"]))
        except (ClearinghouseError, ValueError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_CANCEL])

    def _op_update_oracle(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        pair = p["pair"]
        price = Decimal(str(p["price"]))
        # The oracle price is what perps execute, settle and liquidate at — so only an
        # authorized reporter may set it (constants.ORACLE_REPORTERS). Unrestricted, any
        # user could move the price their own position closes at.
        from .. import constants
        if tx.sender.lower() not in {a.lower() for a in constants.ORACLE_REPORTERS}:
            return ExchangeExecResult(success=False,
                                      error="sender is not an authorized oracle reporter")
        if price <= 0:
            return ExchangeExecResult(success=False, error="oracle price must be positive")

        oracle = self._oracles.get(pair)
        if oracle is None:
            # Auto-create oracle for new pairs
            oracle = TWAPOracle(pool_id=pair)
            self._oracles[pair] = oracle
            self.router.register_oracle(pair, oracle)

        oracle.record(price, timestamp=self._current_block_timestamp)

        # Price the perp market that tracks this pair: "BTC:USD" → BTC-USD-PERP.
        base, _, quote = pair.partition(":")
        market_id = Clearinghouse.market_id(base, quote or constants.PERP_QUOTE)
        if market_id in self.clearinghouse.markets:
            self.clearinghouse.set_oracle_price(market_id, price, self._block_clock())

        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.UPDATE_ORACLE],
            data={"pair": pair, "price": str(price)},
        )

    # =====================================================================
    #  Validator price oracle (docs/PERPS_CLEARINGHOUSE.md §8)
    # =====================================================================

    MAX_VOTE_PRICES = 64

    def load_oracle_committee(self, genesis_content: Any) -> None:
        """Seed the committee from the genesis block's ``validator_set`` (address, stake) — the
        one source every node holds identically. A genesis without one leaves votes disabled
        (None): a committee built from joiners alone would hand the oracle to the first one."""
        if self.oracle_committee is not None:
            return
        try:
            content = json.loads(genesis_content) if isinstance(genesis_content, str) else genesis_content
            members = content.get("validator_set") if isinstance(content, dict) else None
        except Exception:
            members = None
        if not members:
            return
        committee: Dict[str, Decimal] = {}
        for v in members:
            stake = Decimal(str(v["stake"]))
            if stake > 0:
                key = str(v["address"]).lower()
                committee[key] = committee.get(key, ZERO) + stake
        self.oracle_committee = committee

    def _op_oracle_vote(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A committee member's USD prices, keyed by market base ("BTC" → BTC-USD-PERP). Votes
        only for existing markets; each replaces the voter's previous one for that market."""
        from .. import constants
        committee = self.oracle_committee
        if not committee or tx.sender.lower() not in committee:
            return ExchangeExecResult(success=False, error="sender is not in the oracle committee")
        prices = tx.params.get("prices")
        if not isinstance(prices, dict) or not prices or len(prices) > self.MAX_VOTE_PRICES:
            return ExchangeExecResult(
                success=False, error=f"a vote carries 1 to {self.MAX_VOTE_PRICES} prices")
        parsed: Dict[str, Decimal] = {}
        for base in sorted(prices):
            market_id = Clearinghouse.market_id(str(base), constants.PERP_QUOTE)
            if market_id not in self.clearinghouse.markets:
                return ExchangeExecResult(success=False, error=f"no market {market_id}")
            try:
                price = Decimal(str(prices[base]))
            except Exception:
                return ExchangeExecResult(success=False, error=f"invalid price for {base}")
            if not price.is_finite() or price <= 0:
                return ExchangeExecResult(success=False, error=f"invalid price for {base}")
            parsed[market_id] = price
        now = Decimal(str(self._block_clock()))
        voter = tx.sender.lower()
        for market_id, price in parsed.items():
            self.oracle_votes.setdefault(market_id, {})[voter] = (price, now)
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ORACLE_VOTE],
            data={"markets": sorted(parsed)})

    def apply_oracle_votes(self, now) -> None:
        """Each block (before the clearinghouse tick): set every voted market's oracle to the
        stake-weighted median of fresh committee votes — when they carry a majority of the
        committee's stake. Without that the oracle is not refreshed, and goes stale. Votes
        older than the window are dropped, so the state stays small."""
        from .. import constants
        committee = self.oracle_committee
        if not committee:
            return
        now = Decimal(str(now))
        max_age = Decimal(constants.PERP_ORACLE_VOTE_MAX_AGE)
        total = sum(committee.values(), ZERO)
        for market_id in sorted(self.oracle_votes):
            votes = {v: pt for v, pt in self.oracle_votes[market_id].items()
                     if v in committee and now - pt[1] <= max_age}
            self.oracle_votes[market_id] = votes
            if market_id not in self.clearinghouse.markets or not votes:
                continue
            weighted = sorted((price, committee[v]) for v, (price, _t) in votes.items())
            weight = sum((w for _p, w in weighted), ZERO)
            if weight * 2 <= total:
                continue
            acc = ZERO
            for price, w in weighted:            # lower weighted median
                acc += w
                if acc * 2 >= weight:
                    self.clearinghouse.set_oracle_price(market_id, price, now)
                    break
        self.oracle_votes = {m: v for m, v in self.oracle_votes.items() if v}

    def oracle_state_hash(self) -> bytes:
        """The live votes. (Not the committee: see block_processor.ensure_oracle_committee —
        it is a function of genesis and the staking ops, which the chain already commits to.)"""
        votes = {m: {v: [str(p), str(t)] for v, (p, t) in sorted(vs.items())}
                 for m, vs in sorted(self.oracle_votes.items())}
        blob = json.dumps(votes, sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()

    # =====================================================================
    #  State root computation (consensus-critical)
    # =====================================================================

    @_pinned
    def compute_state_root(self) -> str:
        """
        Compute a deterministic hash of the entire exchange state.

        This is included in the block header to commit to the exchange
        state at each block boundary.

        Returns:
            128-char hex string (BLAKE3-512, Whitepaper §3.6 quantum-resistant
            state root). Internal per-component digests use blake2b as a
            deterministic compression step; the committed root is BLAKE3.
        """
        import blake3
        hasher = blake3.blake3()

        # 1. Pool state hashes (sorted by pool ID)
        # Each pool's full state — price, liquidity, fee growth, protocol fees, every tick,
        # every position (owner, range, liquidity, fees owed) and its oracle observations.
        for pid in sorted(self.pool_manager._pools.keys()):
            hasher.update(self.pool_manager._pools[pid].state_digest())

        # 2. Order books (sorted by pair key): every resting order in priority order, the
        #    parked stop orders, owners' order nonces, last trade price, totals. (It used to
        #    commit only the totals and level counts — two nodes could hold different orders
        #    under one root.)
        for pair_key in sorted(self._order_books.keys()):
            hasher.update(pair_key.encode())
            hasher.update(self._order_books[pair_key].state_digest())

        # 3. Oracle state hashes
        for pair_key in sorted(self._oracles.keys()):
            oracle = self._oracles[pair_key]
            price = oracle.latest_price or ZERO
            count = oracle.observation_count
            oracle_hash = hashlib.blake2b(
                f"{pair_key}:{price}:{count}".encode(),
                digest_size=16,
            ).digest()
            hasher.update(oracle_hash)

        # 4. Perp market state hashes
        for market_id in sorted(self.perp_engine._markets.keys()):
            market = self.perp_engine._markets[market_id]
            market_hash = hashlib.blake2b(
                (f"{market_id}:{market.index_price}:{market.mark_price}:"
                 f"{market.open_interest_long}:{market.open_interest_short}:"
                 f"{market.insurance_fund}").encode(),
                digest_size=16,
            ).digest()
            hasher.update(market_hash)

        # 4b. Perps clearinghouse: books, accounts, positions, vault, holder mirror.
        hasher.update(self.clearinghouse.state_hash())

        # 4c. Validator price oracle: committee and live votes.
        hasher.update(self.oracle_state_hash())

        # 4d. Native tokens: registry (supply, authorities), allowances, frozen accounts.
        hasher.update(self.tokens.state_hash())
        if self.nfts.collections:            # (nothing until the first collection exists)
            hasher.update(self.nfts.state_hash())

        # 5. Nonce state
        for addr in sorted(self._nonces.keys()):
            hasher.update(f"{addr}:{self._nonces[addr]}".encode())

        # 6. Block metadata
        hasher.update(self._current_block_height.to_bytes(8, "big"))

        from ..crypto.hashing import STATE_ROOT_SIZE
        return hasher.digest(length=STATE_ROOT_SIZE).hex()

    # =====================================================================
    #  Snapshot / restore (for revert)
    # =====================================================================

    def take_snapshot(self) -> Dict[str, Any]:
        """
        Capture a COMPLETE deep copy of all consensus-critical state so that
        revert_block() restores the exact pre-block state — including entities
        CREATED during the block (new pools, order books, oracles, perp markets
        and positions), which a field-level snapshot cannot remove. Correctness
        over speed: a rejected block must leave local state byte-identical.
        """
        import copy

        snapshot = {
            "nonces": dict(self._nonces),
            "block_height": self._current_block_height,
            "block_timestamp": self._current_block_timestamp,
            "total_swaps": self._total_swaps,
            "total_orders": self._total_orders,
            "total_pools": self._total_pools,
            "total_positions": self._total_positions,
            # Full deep copies of the mutable engine containers.
            "pools": copy.deepcopy(self.pool_manager._pools),
            "pair_index": copy.deepcopy(self.pool_manager._pair_index),
            "pool_sequence": self.pool_manager._pool_sequence,
            "order_books": copy.deepcopy(self._order_books),
            "oracles": copy.deepcopy(self._oracles),
            "perp_markets": copy.deepcopy(self.perp_engine._markets),
            "perp_positions": copy.deepcopy(self.perp_engine._positions),
            "perp_owner_positions": copy.deepcopy(self.perp_engine._owner_positions),
            "perp_pos_sequence": self.perp_engine._pos_sequence,
            "perp_paused": self.perp_engine._paused,
            "clearinghouse": copy.deepcopy(self.clearinghouse),
            "oracle_committee": copy.deepcopy(self.oracle_committee),
            "oracle_votes": copy.deepcopy(self.oracle_votes),
            "tokens": copy.deepcopy(self.tokens),
            "nfts": copy.deepcopy(self.nfts),
            "router_clob_sequence": self.router._clob_sequence,
        }
        self._snapshot = snapshot
        return snapshot

    def _restore_snapshot(self, snapshot: Dict[str, Any]) -> None:
        """
        Restore the EXACT pre-block state from a snapshot.

        Containers are restored IN PLACE (clear + repopulate) so external
        references stay valid — notably the router's order-book/oracle registries
        and its handle to ``pool_manager``.
        """
        import copy

        self._nonces = dict(snapshot["nonces"])
        self._current_block_height = snapshot["block_height"]
        self._current_block_timestamp = snapshot["block_timestamp"]
        self._total_swaps = snapshot["total_swaps"]
        self._total_orders = snapshot["total_orders"]
        self._total_pools = snapshot["total_pools"]
        self._total_positions = snapshot["total_positions"]

        # Pools (in place; the router shares this pool_manager).
        self.pool_manager._pools.clear()
        self.pool_manager._pools.update(copy.deepcopy(snapshot["pools"]))
        self.pool_manager._pair_index.clear()
        self.pool_manager._pair_index.update(copy.deepcopy(snapshot["pair_index"]))
        self.pool_manager._pool_sequence = snapshot["pool_sequence"]

        # Order books + oracles: put the SAME restored objects into both the
        # manager and the router registries so they remain consistent.
        restored_books = copy.deepcopy(snapshot["order_books"])
        self._order_books.clear()
        self._order_books.update(restored_books)
        self.router._order_books.clear()
        self.router._order_books.update(restored_books)

        restored_oracles = copy.deepcopy(snapshot["oracles"])
        self._oracles.clear()
        self._oracles.update(restored_oracles)
        self.router._oracles.clear()
        self.router._oracles.update(restored_oracles)

        # Perp engine.
        self.perp_engine._markets.clear()
        self.perp_engine._markets.update(copy.deepcopy(snapshot["perp_markets"]))
        self.perp_engine._positions.clear()
        self.perp_engine._positions.update(copy.deepcopy(snapshot["perp_positions"]))
        self.perp_engine._owner_positions.clear()
        self.perp_engine._owner_positions.update(copy.deepcopy(snapshot["perp_owner_positions"]))
        self.perp_engine._pos_sequence = snapshot["perp_pos_sequence"]
        self.perp_engine._paused = snapshot["perp_paused"]
        self.clearinghouse = copy.deepcopy(snapshot["clearinghouse"])
        self.oracle_committee = copy.deepcopy(snapshot.get("oracle_committee"))
        self.oracle_votes = copy.deepcopy(snapshot.get("oracle_votes", {}))

        self.tokens = copy.deepcopy(snapshot.get("tokens", TokenRegistry()))
        self.nfts = copy.deepcopy(snapshot.get("nfts", NftRegistry()))
        self.router._clob_sequence = snapshot.get("router_clob_sequence", 0)

    # =====================================================================
    #  Query interface (read-only, for API layer)
    # =====================================================================

    def get_pool(self, pool_id: str) -> Optional[ConcentratedLiquidityPool]:
        return self.pool_manager.get_pool(pool_id)

    def get_order_book(self, pair: str) -> Optional[OrderBook]:
        return self._order_books.get(pair)

    def get_oracle(self, pair: str) -> Optional[TWAPOracle]:
        return self._oracles.get(pair)

    def get_perp_market(self, market_id: str):
        return self.perp_engine.get_market(market_id)

    def get_nonce(self, address: str) -> int:
        return self._nonces.get(address, 0)

    # --- Phase E: real-balance bridge ---

    def set_available_balance(self, address: str, qrdx: Decimal) -> None:
        """Pre-load a sender's available QRDX balance (from account_state) for the
        collateral check. Called by the async block paths before processing."""
        self._available_balances[address] = Decimal(qrdx)

    def available_balance(self, address: str) -> Optional[Decimal]:
        """Pre-loaded available balance, or None if not loaded (check is skipped)."""
        return self._available_balances.get(address)

    def clear_available_balances(self) -> None:
        """Reset the pre-loaded balances (call per block)."""
        self._available_balances.clear()

    def _record_balance_delta(self, address: str, delta_qrdx: Decimal) -> None:
        """Accumulate a real-balance delta for this block (negative = debit) and
        keep the in-memory available balance in step so later ops in the same
        block see the locked amount."""
        self._balance_deltas[address] = self._balance_deltas.get(address, ZERO) + delta_qrdx
        if address in self._available_balances:
            self._available_balances[address] = self._available_balances[address] + delta_qrdx

    def balance_deltas(self) -> Dict[str, Decimal]:
        """This block's accumulated per-address balance deltas (QRDX)."""
        return dict(self._balance_deltas)

    # --- Phase E (spot): token-balance bridge -----------------------------

    def set_available_token_balance(self, holder: str, token: str, amount: Decimal) -> None:
        """Pre-load a holder's available balance of ``token`` (from the
        token_balances ledger, or account_state for native QRDX) for the spot sufficiency
        check. Called by the async block paths before processing."""
        if is_native_asset(token):
            self.set_available_balance(holder, amount)
        else:
            self._available_token_balances[(holder, token)] = Decimal(amount)

    def available_token_balance(self, holder: str, token: str) -> Optional[Decimal]:
        """Pre-loaded available balance of an asset (native QRDX: the account balance), or
        None if not loaded."""
        if is_native_asset(token):
            return self.available_balance(holder)
        return self._available_token_balances.get((holder, token))

    def clear_available_token_balances(self) -> None:
        """Reset the pre-loaded token balances (call per block)."""
        self._available_token_balances.clear()

    def _record_token_delta(self, holder: str, token: str, delta: Decimal) -> None:
        """Accumulate a token-balance delta for this block (negative = debit) and
        keep the in-memory available token balance in step so later ops in the same
        block see the moved amount."""
        key = (holder, token)
        self._token_balance_deltas[key] = self._token_balance_deltas.get(key, ZERO) + delta
        if key in self._available_token_balances:
            self._available_token_balances[key] = self._available_token_balances[key] + delta

    def token_balance_deltas(self) -> Dict[Tuple[str, str], Decimal]:
        """This block's accumulated per-(holder, token) balance deltas."""
        return dict(self._token_balance_deltas)

    @property
    def pool_count(self) -> int:
        return len(self.pool_manager._pools)

    @property
    def pair_count(self) -> int:
        return len(self._order_books)

    @property
    def block_fees(self) -> Decimal:
        return self._block_fees

    def get_stats(self) -> Dict[str, Any]:
        """Exchange-wide statistics."""
        return {
            "pools": self.pool_count,
            "pairs": self.pair_count,
            "perp_markets": self.perp_engine.market_count,
            "total_swaps": self._total_swaps,
            "total_orders": self._total_orders,
            "total_positions": self._total_positions,
            "block_height": self._current_block_height,
        }
