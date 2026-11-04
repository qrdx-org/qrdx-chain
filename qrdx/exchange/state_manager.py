"""
QRDX Exchange State Manager  (Whitepaper §7 — State Layer)

Central singleton that bridges the blockchain layer with the exchange engine.
Every node maintains an identical exchange state by processing the same
sequence of ExchangeTransactions deterministically during block validation.

Responsibilities:
  - Owns all exchange engine instances (pools, books, perps)
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
import logging
from decimal import ROUND_DOWN, Decimal
from typing import Any, Dict, List, Optional, Set, Tuple

from . import undo
from .amm import (
    ConcentratedLiquidityPool,
    PoolManager,
)
from .authority import AccountAuthority
from .bridge import (
    Bridge,
)
from .clearinghouse import Clearinghouse
from .commitment import Section, committed, encode_value, tracked, verifying
from .governance import Governance
from .handlers import (
    accounts as _accounts,
    oracle as _oracle,
    perps as _perps,
    spot as _spot,
    staking as _staking,
    tokens as _tokens,
    trading as _trading,
)
from .handlers.common import (  # noqa: F401  (re-exported: imported from here)
    _CONTROLLER_ADDRESS,
    _TRIGGER_KINDS,
    MAX_SWAP_HOPS,
    SPOT_FEE_QUANTUM,
    STAKER_FEE_CONVERT_MAKERS,
    STAKER_FEE_CONVERT_SECONDS,
    STAKER_FEE_CONVERT_SLIPPAGE,
    STAKER_FEE_TWAP_SECONDS,
    ExchangeExecResult,
    _account_key,
    _apply_policy,
    _attached_legs,
    _BatchAction,
    _book_nonce,
    _default_policy,
    _describe_policy,
    _encode_fee_token,
    _EvmAction,
    _flag,
    _id_or_raw,
    _OperationFailed,
    _parse_value,
    _policy_value,
    _trigger_makers,
)
from .nfts import NftRegistry
from .orderbook import (
    OrderBook,
    _pinned,
)
from .qns import NameService
from .router import UnifiedRouter
from .tokens import (
    TokenRegistry,
    is_native_asset,
)
from .trading import TradingState
from .transactions import (
    EXCHANGE_GAS_COSTS,
    ExchangeOpType,
    ExchangeTransaction,
)

logger = logging.getLogger(__name__)

ZERO = Decimal("0")


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

    # Each sender's next exchange nonce, committed entry by entry (qrdx/exchange/commitment.py).
    _nonces = committed("exchange.nonces", encode_value, mutable=False)
    # The stakers' fee share received in assets other than QRDX, waiting at the fee holder to be
    # sold for QRDX (``convert_staker_fees``): token → (amount, block time of the next attempt).
    fee_tokens = committed("fees.tokens", _encode_fee_token, mutable=False)

    instance: Optional[ExchangeStateManager] = None

    def __init__(self) -> None:
        # --- Engine instances (consensus-critical state) ---
        self.pool_manager = PoolManager()
        # Perps trade through the clearinghouse (docs/PERPS_CLEARINGHOUSE.md).
        self.clearinghouse = Clearinghouse()
        # Validator price oracle (docs/PERPS_CLEARINGHOUSE.md §8). The committee — address →
        # stake — starts from the genesis block's validator set (loaded before the first block
        # section by block_processor.preload_sender_balances) and follows STAKE_DEPOSIT /
        # STAKE_EXIT. None: not loaded, or a genesis without a validator set — votes disabled.
        self.oracle_committee: Optional[Dict[str, Decimal]] = None
        # market_id → voter → (price, block time of the vote)
        self.oracle_votes: Dict[str, Dict[str, Tuple[Decimal, Decimal]]] = {}
        # Each voter's last applied vote sequence: an ORACLE_VOTE's nonce is this sequence,
        # not the account's exchange nonce (process_transaction).
        self.oracle_vote_seqs: Dict[str, int] = {}
        # Votes for other venues' perp price, per market (the mark price's third input).
        self.perp_votes: Dict[str, Dict[str, Tuple[Decimal, Decimal]]] = {}
        # validator → how many of its applied votes fell outside ORACLE_OUTLIER_BAND_BPS of the
        # median (docs/CONSENSUS_ROADMAP.md 5): a public record penalties can build on.
        self.oracle_outliers: Dict[str, int] = {}
        # Committee members convicted by slashing evidence (block_processor.ensure_oracle_committee).
        self.oracle_excluded: Set[str] = set()
        # Node-local receipts + perps event feed for wallets, the API and streams — NOT
        # consensus state (see journal.py). Recorded at commit, rebuilt with the manager.
        from .journal import ExchangeJournal

        self.journal = ExchangeJournal()
        self._block_tick_events: List[Dict[str, Any]] = []
        self.router = UnifiedRouter(pool_manager=self.pool_manager)
        # Funding cadence, oracle staleness and swap deadlines are judged by the block being
        # processed (begin_block sets it), so every node — and every rebuild or catching-up
        # sync — decides them identically. They used to read the wall clock.
        self.router.clock = self._block_clock

        # Order books: pair_key → OrderBook
        self._order_books: Dict[str, OrderBook] = {}
        # Per-sender nonces for replay protection
        self._nonces = {}  # sender → next nonce (committed: see the class attribute)
        self.fee_tokens = {}  # token → (amount, next attempt) (committed: the class attribute)

        # --- Block-level tracking ---
        self._current_block_height: int = 0
        self._current_block_timestamp: float = 0.0
        # Per block, not state: free trading actions each account has taken in it, and the
        # block's exchange base fee (set with the block's balances, block_processor; None
        # outside a block: the free lane is judged open).
        self._block_free_actions: Dict[str, int] = {}
        self.exchange_base_fee: Optional[int] = None
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
        # On-chain governance (qrdx/exchange/governance.py): proposals, votes, vetoes, the
        # master controller's freeze and fork approvals. Exchange state like the rest — replayed
        # on every path, committed in the root, snapshotted, rebuilt after a reorg.
        self.governance = Governance()
        # The consensus bridge (docs/BRIDGE.md): attested deposits, minted ids, withdrawals.
        self.bridge = Bridge()
        # Trading state outside the books and the clearinghouse (docs/TRADING_FEATURES.md).
        self.trading = TradingState()
        # Who may sign for an account (docs/ACCOUNT_CONTROL.md).
        self.authority = AccountAuthority()
        # QNS, the name service (docs/QNS.md); its names are NFTs in ``self.nfts``.
        self.qns = NameService()
        # Spot order-book fees (``_spot_fee``): the router quotes net of the taker's.
        self.router.taker_fee = lambda sender, value: self._spot_fee(sender, False, value)[0]
        # Per-block validator-lifecycle ops (STAKE_DEPOSIT / STAKE_EXIT) to flush to
        # the consensus validators table. Deterministic (same txs on every node),
        # reset per block. See qrdx.validator.epoch_loop for activation scheduling.
        self._validator_lifecycle_ops: List[Dict[str, Any]] = []
        # The stakers' share of QRDX fee income this block (docs/CONSENSUS_ROADMAP.md 6).
        self._block_staker_fees: Decimal = ZERO
        # The pairs whose book holds an order that can expire (derived: ``_expiring_book_pairs``).
        self._expiring_pairs: Optional[Set[str]] = None
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
        self.tokens.changed.clear()  # the DB registry mirror is written per block
        self._validator_lifecycle_ops = []  # Phase 3: reset per-block staking deposit/exit ops
        self._block_staker_fees = ZERO
        self._block_tick_events = []  # journal: this block's liquidations + funding
        self._block_journaled = False
        self._block_free_actions = {}  # free trading actions taken in this block, by account

        # Each order book starts the block when the block first uses it (its per-block rate
        # limits reset, its time set: ``OrderBook.enter_block``). Only a book holding orders that
        # can expire starts here, so expiry is judged every block. (Starting every book cost 15
        # ms a block at 10,000 pairs: docs/EXCHANGE_AUDIT.md 8.)
        for pair in self._expiring_book_pairs():
            self._order_books[pair].enter_block(block_height, block_timestamp)

        self.clearinghouse.new_block(block_timestamp)

    def _expiring_book_pairs(self) -> List[str]:
        """The pairs whose book holds an order that can expire, sorted: derived from the books
        (rebuilt after a restore) and kept as orders are placed."""
        pairs = self.__dict__.get("_expiring_pairs")
        if pairs is None:
            pairs = {
                p for p, b in self._order_books.items() if b.__dict__.get("_has_expiring", True)
            }
            self._expiring_pairs = pairs
        return sorted(p for p in pairs if p in self._order_books)

    def _note_expiring(self, pair: str) -> None:
        """``pair``'s book now holds an order that can expire: it starts every block."""
        self._expiring_book_pairs()
        if self._expiring_pairs is not None:
            self._expiring_pairs.add(pair)

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
        # A replay after a reorg re-applies blocks the journal already holds (it was rolled back
        # only to the new tip): record only the blocks above what it has.
        if not getattr(self, "_block_journaled", False) and (
            self._current_block_height > self.journal.height
        ):
            self._block_journaled = True
            try:
                self.journal.record_block(
                    self._current_block_height,
                    self._current_block_timestamp,
                    self._block_exchange_txs,
                    self._block_results,
                    self._block_tick_events,
                    samples=self._market_samples(),
                )
            except Exception as e:  # the journal must never break a block
                logger.warning(
                    "exchange journal: block %s not recorded: %s", self._current_block_height, e
                )
        self._block_tick_events = []

    def _market_samples(self) -> List[Dict[str, Any]]:
        """Each perp market's mark, oracle, open interest and funding rate, for the trading
        history's charts — once a minute of block time (the first block of each minute)."""
        minute = int(float(self._current_block_timestamp) // 60)
        if minute == getattr(self, "_sampled_minute", None):
            return []
        self._sampled_minute = minute
        ch = self.clearinghouse
        return [
            {
                "market": mid,
                "mark": str(ch.markets[mid].mark_price),
                "oracle": str(ch.markets[mid].oracle_price),
                "open_interest": str(ch.markets[mid].open_interest),
                "funding_rate": str(ch.markets[mid].funding_rate),
            }
            for mid in sorted(ch.markets)
        ]

    def record_tick_events(self, events: List[Dict[str, Any]]) -> None:
        """The block-boundary tick's liquidations and funding, for the journal at commit."""
        self._block_tick_events.extend(events or [])

    # =====================================================================
    #  Transaction processing (consensus-critical)
    # =====================================================================

    @_pinned
    def process_transaction(
        self,
        tx: ExchangeTransaction,
        prepaid: Optional[Tuple[str, Decimal]] = None,
        checked: bool = False,
    ) -> ExchangeExecResult:
        """
        Execute a single exchange transaction deterministically.

        This is the ONLY entry point for exchange state mutations.
        Every validator must produce identical results for identical inputs.

        Args:
            tx: The exchange transaction to execute
            prepaid: (payer, QRDX) of its gas, reserved by the block up front
                (``reserve_section_fees``)
            checked: the block's transactions were judged together before any ran
                (``section_errors``, chain-spec feature ``exchange_inclusion``). Such a
                transaction always executes: one whose signer an earlier transaction in the
                block took the right to act from fails, paying for its gas and consuming its
                nonce like any failed operation.

        Returns:
            ExchangeExecResult with success/failure and gas used
        """
        denied = ""
        if checked:
            # Its form, expiry, gas limit and free-lane standing were judged with the block's;
            # only who may sign for its account can have changed since (an approval revoked,
            # a key turned off, earlier in the block).
            denied = self.signer_error(tx)
        else:
            # 1. Basic structural validation
            try:
                tx.validate_basic()
            except ValueError as e:
                return ExchangeExecResult(success=False, gas_used=0, error=str(e))

            # 1b. Acting for an account: an agent it approved, or a sub-account's master. One
            #     the account never authorized is refused before anything — no nonce, no gas:
            #     the account did not sign it.
            unauthorized = self.signer_error(tx)
            if unauthorized:
                return ExchangeExecResult(success=False, gas_used=0, error=unauthorized)

            # 1c. An action signed to expire (``params.expires_at``) is not includable after
            #     that block time: refused before its nonce or any gas, as if never sent.
            expires = tx.expires_at()
            if expires is not None and Decimal(str(self._block_clock())) > expires:
                return ExchangeExecResult(
                    success=False, gas_used=0, error=f"expired at block time {expires}"
                )

        # 2. Nonce check (replay protection). An oracle vote carries its own sequence instead:
        #    it must be newer than the voter's last applied vote, and never moves the account's
        #    exchange nonce — which used to advance with every vote, so a validator's own
        #    transactions signed elsewhere with a predicted nonce went stale.
        is_vote = tx.op_type == ExchangeOpType.ORACLE_VOTE
        stale = ""
        if is_vote:
            last = self.oracle_vote_seq(tx.sender)
            if tx.nonce <= last:
                stale = f"Stale oracle vote: sequence {tx.nonce} is not after {last}"
        else:
            expected_nonce = self._nonces.get(tx.nonce_key(), 0)
            if tx.nonce != expected_nonce:
                stale = f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}"

        # 3. Gas limit check (a multisig's every partial signature costs a verification too)
        base_gas = EXCHANGE_GAS_COSTS.get(tx.op_type, 100_000) + tx.signature_gas()
        if not stale and tx.gas_limit < base_gas:
            stale = f"Gas limit too low: need {base_gas}, got {tx.gas_limit}"
        if stale:
            if checked:  # (judged with its block: only a bug gets here — the block is refused)
                raise RuntimeError(f"a transaction judged includable was refused: {stale}")
            return ExchangeExecResult(success=False, gas_used=0, error=stale)

        # 3a. The free trading lane (docs/TOKENOMICS.md): a trading operation sent at gas price 0
        #     pays nothing while its account has free actions and blocks are not running full;
        #     otherwise it is refused here — not includable, consuming nothing — and must pay.
        #     (A judged block's free operations were checked against its start, in its order.)
        free = tx.free_eligible()
        if free and not checked:
            refused = self.free_action_error(tx)
            if refused:
                return ExchangeExecResult(success=False, gas_used=0, error=refused)

        # 3b. Fees: a price of at least the floor, and QRDX for the whole gas limit at that
        #     price, reserved before the operation runs (so the operation cannot spend it).
        #     Refused here, an operation is not includable and consumes nothing. A judged block
        #     reserved every transaction's before any ran (``reserve_section_fees``).
        reserved = ZERO
        if self.enforce_fees and not free:
            if prepaid is not None:
                payer, reserved = prepaid
            else:
                try:
                    tx.validate_fee()
                except ValueError as e:
                    return ExchangeExecResult(success=False, gas_used=0, error=str(e))
                reserved = tx.max_fee()
                payer = self.fee_payer(tx)
                avail = self.available_balance(payer)
                if avail is None or avail < reserved:
                    return ExchangeExecResult(
                        success=False,
                        gas_used=0,
                        error=f"insufficient QRDX for gas: need {reserved}, available {avail}",
                    )
                self._record_balance_delta(payer, -reserved)

        # 4. Execute the operation — all or nothing (qrdx/exchange/undo.py): an operation that
        #    raises or fails changes nothing; it only pays for its gas and consumes its nonce
        #    (below). It used to keep whatever it had done before failing: a perp order that
        #    matched and then could not rest (the book's limits) kept the makers' fills in the
        #    book without the trades — a maker lost its order and got no position.
        try:
            with self.atomic():
                if denied:
                    raise _OperationFailed(ExchangeExecResult(success=False, error=denied))
                limited = self._charge_agent(tx)
                if limited:
                    raise _OperationFailed(ExchangeExecResult(success=False, error=limited))
                result = self._execute_op(tx)
                if not result.success:
                    raise _OperationFailed(result)
        except _OperationFailed as refused:
            result = refused.result
        except Exception as e:
            logger.error("Exchange op %s failed: %s", tx.op_type.name, e)
            result = ExchangeExecResult(success=False, gas_used=base_gas, error=str(e))

        # 5. Consume the nonce once the operation has EXECUTED — success or failure. It used
        #    to advance only on success, so a failing operation could be re-submitted and
        #    re-included indefinitely at the same nonce: one signed transaction, unlimited
        #    block space. Transactions rejected before execution (malformed, wrong nonce,
        #    under-gassed — steps 1-3) are not includable and consume nothing — and, under
        #    ``exchange_inclusion``, a block carrying one is invalid (``section_errors``).
        if is_vote:
            self.oracle_vote_seqs[tx.sender.lower()] = tx.nonce
        else:
            self._nonces[tx.nonce_key()] = tx.nonce + 1
        if free:
            self._spend_free_action(tx)
        # A multisig that signed an executed transaction: its members become public record
        # (``account_getAuthority``), once.
        if tx.public_key[:1] == b"{":
            try:
                self.authority.record_keyset(tx.public_key)
            except ValueError:
                pass  # (verified at admission and import: cannot happen for a valid block)

        # 6. Charge gas: gas_used × gas_price, burned; the rest of the reservation comes back.
        #    (A multisig's signatures are charged on top of what the operation used — never
        #    beyond the gas limit, which is what was reserved.)
        if result.gas_used == 0:
            result.gas_used = base_gas
        else:
            result.gas_used = min(int(tx.gas_limit), result.gas_used + tx.signature_gas())
        tx.gas_used = result.gas_used
        fee = tx.fee()  # (0 in the free lane: its price is 0)
        if self.enforce_fees and not free:
            self._record_balance_delta(payer, reserved - fee)
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

    # ── which transactions a block may carry (chain-spec feature ``exchange_inclusion``) ──

    def section_errors(
        self,
        txs: List[ExchangeTransaction],
        block_height: int,
        block_timestamp: float,
        balance_of: Optional[Any] = None,
        base_fee: Any = "block",
    ) -> Dict[int, str]:
        """Why each of a block's exchange transactions may not be in it, by index — empty: the
        block may carry them all. Judged together, as of the block's start, before any runs:

        * each must pass what ``process_transaction`` checks before executing — its form, its
          signer, its expiry, its gas limit, the free lane (in the block's order: per-block and
          budget counts include the block's earlier free operations);
        * each nonce lane's transactions continue its nonce in sequence (an oracle voter's
          votes, its sequence);
        * each payer holds QRDX for the maximum fees of all its transactions in the block, which
          the block reserves before anything runs (``reserve_section_fees``).

        A transaction that fails takes nothing from the block, so the rest of its lane fails on
        its nonce. Read only. The block's own height and time are the clock. ``balance_of``
        (default: the pre-loaded balances) and ``base_fee`` (default: the block's, as pre-loaded)
        are how a proposer judges its selection before pre-loading anything — the balances every
        importer will pre-load."""
        balance = balance_of or self.available_balance
        nonces: Dict[str, int] = {}
        votes: Dict[str, int] = {}
        owed: Dict[str, Decimal] = {}
        free_in_block: Dict[str, int] = {}
        free_spent: Dict[str, Tuple[int, Decimal]] = {}
        errors: Dict[int, str] = {}
        saved = (self._current_block_height, self._current_block_timestamp, self.exchange_base_fee)
        self._current_block_height, self._current_block_timestamp = block_height, block_timestamp
        if base_fee != "block":
            self.exchange_base_fee = base_fee
        try:
            for i, tx in enumerate(txs):
                err = self._inclusion_error(
                    tx, balance, nonces, votes, owed, free_in_block, free_spent
                )
                if err:
                    errors[i] = err
        finally:
            (
                self._current_block_height,
                self._current_block_timestamp,
                self.exchange_base_fee,
            ) = saved
        return errors

    def _inclusion_error(self, tx, balance, nonces, votes, owed, free_in_block, free_spent) -> str:
        """``section_errors`` for one transaction, after the block's earlier ones: what it would
        take from the block is recorded in the last five arguments only if it may be in it."""
        from .transactions import trading_actions

        try:
            tx.validate_basic()
        except ValueError as e:
            return str(e)
        refused = self.signer_error(tx)
        if refused:
            return refused
        expires = tx.expires_at()
        if expires is not None and Decimal(str(self._block_clock())) > expires:
            return f"expired at block time {expires}"
        is_vote = tx.op_type == ExchangeOpType.ORACLE_VOTE
        voter, lane = tx.sender.lower(), tx.nonce_key()
        if is_vote:
            last = votes.get(voter, self.oracle_vote_seq(tx.sender))
            if tx.nonce <= last:
                return f"stale oracle vote: sequence {tx.nonce} is not after {last}"
        else:
            expected = nonces.get(lane, self._nonces.get(lane, 0))
            if tx.nonce != expected:
                return f"nonce {tx.nonce} out of sequence: expected {expected}"
        base_gas = EXCHANGE_GAS_COSTS.get(tx.op_type, 100_000) + tx.signature_gas()
        if tx.gas_limit < base_gas:
            return f"gas limit too low: need {base_gas}, got {tx.gas_limit}"
        free = tx.free_eligible()
        account = tx.sender
        if free:
            refused = self.free_action_error(
                tx,
                held=balance(account) or ZERO,
                in_block=free_in_block.get(account, 0),
                spent=free_spent.get(account),
            )
            if refused:
                return refused
        elif self.enforce_fees:
            try:
                tx.validate_fee()
            except ValueError as e:
                return str(e)
            payer = self.fee_payer(tx)
            need = owed.get(payer, ZERO) + tx.max_fee()
            avail = balance(payer)
            if avail is None or avail < need:
                return (
                    f"insufficient QRDX for gas: {payer[:16]}… holds {avail}, and its "
                    f"transactions in the block may cost {need} (gas_limit × gas_price)"
                )
            owed[payer] = need
        # It may be in the block: what it takes from it.
        if is_vote:
            votes[voter] = tx.nonce
        else:
            nonces[lane] = tx.nonce + 1
        if free:
            count, _cancels = trading_actions(tx.op_type, tx.params or {})
            free_in_block[account] = free_in_block.get(account, 0) + count
            used, _last = free_spent.get(account) or self.trading.action_budgets.peek(
                account, (0, ZERO)
            )
            free_spent[account] = (used + count, Decimal(str(self._block_clock())))
        return ""

    def reserve_section_fees(
        self, txs: List[ExchangeTransaction]
    ) -> List[Optional[Tuple[str, Decimal]]]:
        """Reserve each transaction's maximum fee from its payer before anything in the block
        runs (``exchange_inclusion``), so no earlier operation can spend what a later
        transaction's gas needs; ``section_errors`` checked that every payer holds it. Each
        gets back what its gas did not use once it has run. Returns each transaction's
        (payer, reserved), None where it pays nothing (the free lane, or fees not enforced)."""
        out: List[Optional[Tuple[str, Decimal]]] = []
        for tx in txs:
            if not self.enforce_fees or tx.free_eligible():
                out.append(None)
                continue
            payer, fee = self.fee_payer(tx), tx.max_fee()
            self._record_balance_delta(payer, -fee)
            out.append((payer, fee))
        return out

    # ── the free trading lane (docs/TOKENOMICS.md) ──

    def free_action_budget(self, account: str) -> int:
        """The free trading actions ``account`` has: FREE_ACTIONS_INITIAL, plus
        FREE_ACTIONS_PER_VOLUME for each unit of settlement-asset volume it has ever traded."""
        from .. import constants

        volume = self.clearinghouse.lifetime_volume.peek(account, ZERO)
        earned = int((volume * constants.FREE_ACTIONS_PER_VOLUME).to_integral_value(ROUND_DOWN))
        return int(constants.FREE_ACTIONS_INITIAL) + earned

    def free_lane_open(self) -> bool:
        """Blocks are not running full: the block's exchange base fee is within
        FREE_TRADING_MAX_BASE_FEE_BPS of its floor (free operations' gas counts toward it too, so
        a flood of them closes the lane until blocks clear)."""
        from .. import constants

        fee, floor = self.exchange_base_fee, int(constants.EXCHANGE_MIN_GAS_PRICE_WEI)
        if fee is None or floor <= 0:
            return True
        return int(fee) * 10_000 <= floor * int(constants.FREE_TRADING_MAX_BASE_FEE_BPS)

    def free_action_error(
        self,
        tx: ExchangeTransaction,
        held: Optional[Decimal] = None,
        in_block: Optional[int] = None,
        spent: Optional[Tuple[int, Decimal]] = None,
    ) -> str:
        """Why ``tx`` may not go free — "" if it may (read only). An account needs a holding
        (FREE_ACTION_MIN_QRDX of QRDX or FREE_ACTION_MIN_EQUITY of perps equity), at most
        FREE_ACTIONS_PER_BLOCK of its free actions are in one block, and it spends from its
        budget (cancels: up to twice it); past the budget, one free action every
        FREE_ACTION_REFILL_SECONDS. While blocks run full, only cancels go free.

        ``held``, ``in_block`` and ``spent`` stand in for the account's QRDX, its free actions
        in this block and its budget use (used, last) — for judging a block's transactions
        before any runs (``section_errors``)."""
        from .. import constants
        from .transactions import trading_actions

        account = tx.sender
        count, cancels = trading_actions(tx.op_type, tx.params or {})
        if not cancels and not self.free_lane_open():
            return (
                "blocks are running full: the free trading lane is paused — pay gas "
                f"(at least the exchange base fee, {self.exchange_base_fee} wei)"
            )
        if held is None:
            held = self.available_balance(account) or ZERO
        equity = (
            self.clearinghouse.total_equity(account)
            if self.clearinghouse.accounts.peek(account) is not None
            else ZERO
        )
        if held < constants.FREE_ACTION_MIN_QRDX and equity < constants.FREE_ACTION_MIN_EQUITY:
            return (
                f"free trading needs a holding: {constants.FREE_ACTION_MIN_QRDX} QRDX or "
                f"{constants.FREE_ACTION_MIN_EQUITY} of perps equity — or pay gas"
            )
        if in_block is None:
            in_block = self._block_free_actions.get(account, 0)
        if in_block + count > constants.FREE_ACTIONS_PER_BLOCK:
            return (
                f"at most {constants.FREE_ACTIONS_PER_BLOCK} free actions of an account a block "
                "— pay gas, or wait a block"
            )
        used, last = spent or self.trading.action_budgets.peek(account, (0, ZERO))
        budget = self.free_action_budget(account)
        if used + count <= (budget * 2 if cancels else budget):
            return ""
        now = Decimal(str(self._block_clock()))
        if count == 1 and now - last >= constants.FREE_ACTION_REFILL_SECONDS:
            return ""  # past the budget: one every FREE_ACTION_REFILL_SECONDS after the last
        return (
            f"{account[:16]}… has used its {budget} free actions (trading earns more): pay gas, "
            f"or wait {constants.FREE_ACTION_REFILL_SECONDS}s for the next"
        )

    def _spend_free_action(self, tx: ExchangeTransaction) -> None:
        """An executed free operation — success or failure — spends its actions."""
        from .transactions import trading_actions

        account = tx.sender
        count, cancels = trading_actions(tx.op_type, tx.params or {})
        used, _last = self.trading.action_budgets.peek(account, (0, ZERO))
        # (Its last free action's block time: past the budget, the next waits from here.)
        self.trading.action_budgets[account] = (used + count, Decimal(str(self._block_clock())))
        self._block_free_actions[account] = self._block_free_actions.get(account, 0) + count

    def _signed_by_delegate(self, tx: ExchangeTransaction) -> bool:
        """Signed for the account by a trading-only delegate — an agent, or a vault's leader —
        rather than by the account, one of its controllers or its sub-account's master."""
        signer = tx.signer
        if not signer:
            return False
        if self.authority.may_control(tx.sender, signer):
            return False
        return self.trading.master_of(tx.sender) != signer

    def signer_error(self, tx: ExchangeTransaction) -> str:
        """Why ``tx.signer`` may not act for ``tx.sender`` ("" if it may, or signs for itself).
        An account whose own key is turned off is signed for only by its controllers
        (qrdx/exchange/authority.py), and a key turned off signs for nothing. A controller may do
        anything for the account; so may a sub-account's master. An agent the account approved
        — or that a sub-account's master approved — may sign trading operations
        (``AGENT_SCOPE``; a batch only of those) until its approval expires, while the account's
        own key is on."""
        signer = tx.signer
        auth = self.authority
        if not signer:
            if not auth.own_key_enabled(tx.sender):
                return f"{tx.sender[:16]}…'s own key is turned off: its controllers sign for it"
            return ""
        if not auth.own_key_enabled(signer):
            return f"{signer[:16]}…'s key is turned off"
        if auth.may_control(tx.sender, signer):
            return ""  # a controller signs anything for the account
        master = self.trading.master_of(tx.sender)
        if master is not None and master == signer:
            return ""
        vault = self.clearinghouse.user_vaults.peek(tx.sender)
        if vault is not None and vault.managed:
            return "a market's liquidity vault is quoted by the protocol: no one signs for it"
        if vault is not None:
            # A user vault trades by its leader's signature (or an agent of its leader's) —
            # trading only: its funds leave only by its holders' own withdrawals.
            master = vault.leader
            if signer == vault.leader:
                return self._scope_error(tx, "a vault's leader")
        grant = self.trading.grant(tx.sender, signer)
        if (
            grant is not None
            and tx.op_type == ExchangeOpType.AGENT_REVOKE
            and str(tx.params.get("agent")) == signer
        ):
            return ""  # an agent may always give up its own approval
        grantor = tx.sender
        if grant is None and master is not None:
            grant, grantor = self.trading.grant(master, signer), master
        if grant is None:
            return f"{signer[:16]}… may not act for {tx.sender[:16]}…"
        if grant.valid_until > 0 and Decimal(str(self._block_clock())) >= grant.valid_until:
            return f"the agent {signer[:16]}…'s approval has expired"
        if not auth.own_key_enabled(grantor):
            return f"{grantor[:16]}…'s own key is turned off: its agents act for it no more"
        return self._scope_error(tx, "an agent")

    def _agent_grant(self, tx: ExchangeTransaction) -> Optional[Tuple[Any, str]]:
        """(the approval, its grantor) when ``tx`` is signed by an agent — of the sender, or of
        a sub-account's master or a vault's leader (as ``signer_error`` judges it); else None."""
        signer = tx.signer
        if not signer or self.authority.may_control(tx.sender, signer):
            return None
        master = self.trading.master_of(tx.sender)
        if master == signer:
            return None
        vault = self.clearinghouse.user_vaults.peek(tx.sender)
        if vault is not None:
            if signer == vault.leader:
                return None
            master = vault.leader
        grant = self.trading.grant(tx.sender, signer)
        if grant is not None:
            return grant, tx.sender
        if master is None:
            return None
        grant = self.trading.grant(master, signer)
        return (grant, master) if grant is not None else None

    def _charge_agent(self, tx: ExchangeTransaction) -> str:
        """An agent with a daily limit (``max_notional_per_day``): count what ``tx`` places
        against it, inside the operation's undo scope (a failed operation counts nothing). Why
        it may not ("" if it may)."""
        found = self._agent_grant(tx)
        if found is None or found[0].max_notional_per_day <= 0:
            return ""
        grant, grantor = found
        try:
            notional = self._agent_notional(tx.op_type, tx.params, tx.sender)
            if notional > 0:
                day = int(Decimal(str(self._block_clock())) // 86400)
                self.trading.spend(grantor, grant, day, notional)
        except (ValueError, KeyError, TypeError, ArithmeticError) as e:
            return str(e)
        return ""

    def _agent_notional(self, op: ExchangeOpType, p: Dict[str, Any], sender: str) -> Decimal:
        """What an operation a limited agent signs places, in the perps settlement asset: every
        order at its full size × limit price, filled or not; cancels nothing. ValueError for
        what cannot be valued before it runs (a limited agent may not do it): a spot market
        order, a swap or spot TWAP that does not spend the settlement asset, a pair not priced
        in it."""
        from .transactions import batch_actions

        Op = ExchangeOpType

        def dec(value: Any) -> Decimal:
            out = Decimal(str(value))
            if not out.is_finite() or out < 0:
                raise ValueError(f"invalid amount {value!r}")
            return out

        settlement = self.perp_collateral_token()
        unit = self.canonical_asset(settlement) if settlement else ""
        if op in (Op.CANCEL_ORDER, Op.PERP_CANCEL, Op.CANCEL_ALL, Op.TWAP_CANCEL):
            return ZERO
        if op in (Op.PERP_SET_LEVERAGE, Op.AGENT_REVOKE):
            return ZERO
        if op == Op.BATCH:
            return sum((self._agent_notional(o, ap, sender) for o, ap in batch_actions(p)), ZERO)
        if op == Op.PERP_ORDER:
            return dec(p["size"]) * dec(p["price"])
        if op == Op.PERP_TRIGGER:
            price = dec(p.get("limit_price") or p["trigger_price"])
            if p.get("position"):
                acct = self.clearinghouse.accounts.peek(sender)
                pos = acct.positions.get(str(p["market_id"])) if acct is not None else None
                return abs(pos.size) * price if pos is not None else ZERO
            return dec(p["size"]) * price
        if op == Op.PERP_MODIFY:
            m = self.clearinghouse.markets.get(str(p["market_id"]))
            if m is None:
                return ZERO  # (it will fail)
            oid = str(p["order_id"])
            trig = tracked(m.triggers).peek(oid)
            if trig is not None:
                size = dec(p.get("size") or trig.size)
                return size * dec(
                    p.get("limit_price") or p.get("trigger_price") or trig.trigger_price
                )
            order = m.book.get_order(oid)
            if order is None:
                return ZERO
            return dec(p.get("size") or order.remaining) * dec(p.get("price") or order.price)
        if op == Op.TWAP_ORDER:
            if "market_id" in p:
                m = self.clearinghouse.markets.get(str(p["market_id"]))
                mark = m.mark_price if m is not None else ZERO
                slip = dec(p.get("max_slippage", "0.05"))
                return dec(p["size"]) * mark * (1 + slip)
            if not unit or self.canonical_asset(p["token_in"]) != unit:
                raise ValueError(
                    f"a spending-limited agent's spot TWAP spends {unit or 'the settlement asset'}"
                )
            return dec(p["amount_in"])
        if op == Op.SWAP:
            first = (p.get("path") or [p.get("token_in")])[0]
            if not unit or self.canonical_asset(first) != unit:
                raise ValueError(
                    f"a spending-limited agent swaps from {unit or 'the settlement asset'}"
                )
            return dec(p["amount_in"])
        if op in (Op.PLACE_ORDER, Op.MODIFY_ORDER):
            pair = self._canonical_pair(str(p["pair"]))
            base, quote = pair.split(":", 1) if ":" in pair else ("", "")
            if op == Op.MODIFY_ORDER:
                book = self._order_books.get(pair)
                order = book._orders.get(str(p["order_id"])) if book is not None else None
                if order is None:
                    return ZERO
                amount = dec(p.get("amount", order.remaining))
                price = dec(p.get("price", order.price))
            else:
                amount = dec(p["amount"])
                price = dec(p.get("price") or p.get("stop_price") or 0)
            if unit and base == unit:
                return amount
            if unit and quote == unit and price > 0:
                return amount * price
            raise ValueError(
                f"a spending-limited agent trades spot only priced in {unit or 'the settlement asset'}"
                " (and with a limit price)"
            )
        raise ValueError(f"a spending-limited agent may not sign {op.name}")

    def _signed_by_account(self, tx: ExchangeTransaction) -> bool:
        """Signed by the account itself — its own key, or a controller (which may do anything
        it may: docs/ACCOUNT_CONTROL.md) — not by an agent, a master or a leader."""
        return not tx.signer or self.authority.may_control(tx.sender, tx.signer)

    @staticmethod
    def _scope_error(tx: ExchangeTransaction, who: str) -> str:
        """Why ``tx`` is not a trading operation (``AGENT_SCOPE``; a batch only of those)."""
        from .transactions import AGENT_SCOPE, batch_actions

        ops = [tx.op_type]
        if tx.op_type == ExchangeOpType.BATCH:
            try:
                ops += [op for op, _params in batch_actions(tx.params)]
            except ValueError as e:
                return str(e)
        outside = [op.name for op in ops if op not in AGENT_SCOPE]
        if outside:
            return f"{who} may not sign {outside[0]}: it trades, it does not move funds"
        return ""

    def fee_payer(self, tx: ExchangeTransaction) -> str:
        """Who pays the transaction's gas: its sender — but a user vault's leader for the
        vault (a vault holds no QRDX of its own outside the clearinghouse)."""
        vault = self.clearinghouse.user_vaults.peek(tx.sender)
        return vault.leader if vault is not None else tx.sender

    # Each operation's handler, by name (looked up on the instance, so a test's patch of one
    # still takes). The table used to be rebuilt — a hundred bound methods — for every operation.
    _HANDLERS: Dict[ExchangeOpType, str] = {
        ExchangeOpType.CREATE_POOL: "_op_create_pool",
        ExchangeOpType.REMOVE_POOL: "_op_remove_pool",
        ExchangeOpType.ADD_LIQUIDITY: "_op_add_liquidity",
        ExchangeOpType.REMOVE_LIQUIDITY: "_op_remove_liquidity",
        ExchangeOpType.SWAP: "_op_swap",
        ExchangeOpType.PLACE_ORDER: "_op_place_order",
        ExchangeOpType.CANCEL_ORDER: "_op_cancel_order",
        ExchangeOpType.OPEN_POSITION: "_op_retired_perp",
        ExchangeOpType.CLOSE_POSITION: "_op_retired_perp",
        ExchangeOpType.PARTIAL_CLOSE: "_op_retired_perp",
        ExchangeOpType.ADD_MARGIN: "_op_retired_perp",
        ExchangeOpType.PERP_DEPOSIT: "_op_perp_deposit",
        ExchangeOpType.PERP_WITHDRAW: "_op_perp_withdraw",
        ExchangeOpType.PERP_SET_LEVERAGE: "_op_perp_set_leverage",
        ExchangeOpType.PERP_ORDER: "_op_perp_order",
        ExchangeOpType.PERP_CANCEL: "_op_perp_cancel",
        ExchangeOpType.VAULT_DEPOSIT: "_op_vault_deposit",
        ExchangeOpType.VAULT_WITHDRAW: "_op_vault_withdraw",
        ExchangeOpType.ORACLE_VOTE: "_op_oracle_vote",
        ExchangeOpType.CREATE_MARKET: "_op_create_market",
        ExchangeOpType.TOKEN_DEPLOY: "_op_token_deploy",
        ExchangeOpType.TOKEN_TRANSFER: "_op_token_transfer",
        ExchangeOpType.TOKEN_MINT: "_op_token_mint",
        ExchangeOpType.TOKEN_BURN: "_op_token_burn",
        ExchangeOpType.TOKEN_APPROVE: "_op_token_approve",
        ExchangeOpType.TOKEN_TRANSFER_FROM: "_op_token_transfer_from",
        ExchangeOpType.TOKEN_SET_AUTHORITY: "_op_token_set_authority",
        ExchangeOpType.TOKEN_FREEZE: "_op_token_freeze",
        ExchangeOpType.TOKEN_THAW: "_op_token_freeze",
        ExchangeOpType.TOKEN_UPDATE_METADATA: "_op_token_update_metadata",
        ExchangeOpType.TOKEN_SET_TRANSFER_FEE: "_op_token_set_transfer_fee",
        ExchangeOpType.TOKEN_WITHDRAW_FEES: "_op_token_withdraw_fees",
        ExchangeOpType.TOKEN_PAUSE: "_op_token_pause",
        ExchangeOpType.TOKEN_RESUME: "_op_token_pause",
        ExchangeOpType.TOKEN_AUTHORIZE_OPERATOR: "_op_token_operator",
        ExchangeOpType.TOKEN_REVOKE_OPERATOR: "_op_token_operator",
        ExchangeOpType.NFT_CREATE_COLLECTION: "_op_nft_create_collection",
        ExchangeOpType.NFT_MINT: "_op_nft_mint",
        ExchangeOpType.NFT_TRANSFER: "_op_nft_transfer",
        ExchangeOpType.NFT_BURN: "_op_nft_burn",
        ExchangeOpType.NFT_APPROVE: "_op_nft_approve",
        ExchangeOpType.NFT_SET_APPROVAL_FOR_ALL: "_op_nft_set_approval_for_all",
        ExchangeOpType.NFT_UPDATE: "_op_nft_update",
        ExchangeOpType.NFT_SET_AUTHORITY: "_op_nft_set_authority",
        ExchangeOpType.STAKE_DEPOSIT: "_op_stake_deposit",
        ExchangeOpType.STAKE_EXIT: "_op_stake_exit",
        ExchangeOpType.GOV_PROPOSE: "_op_gov_propose",
        ExchangeOpType.GOV_VOTE: "_op_gov_vote",
        ExchangeOpType.GOV_VETO: "_op_gov_veto",
        ExchangeOpType.GOV_EXECUTE: "_op_gov_execute",
        ExchangeOpType.BRIDGE_WITHDRAW: "_op_bridge_withdraw",
        ExchangeOpType.BRIDGE_PROVE_DEPOSIT: "_op_bridge_prove_deposit",
        ExchangeOpType.MIGRATION_CLAIM: "_op_migration_claim",
        ExchangeOpType.DOOMSDAY_PROVE: "_op_doomsday_prove",
        ExchangeOpType.STAKE_DELEGATE: "_op_stake_delegate",
        ExchangeOpType.STAKE_UNDELEGATE: "_op_stake_undelegate",
        ExchangeOpType.STAKE_SET_COMMISSION: "_op_stake_set_commission",
        ExchangeOpType.PERP_TRIGGER: "_op_perp_trigger",
        ExchangeOpType.CANCEL_ALL: "_op_cancel_all",
        ExchangeOpType.PERP_MODIFY: "_op_perp_modify",
        ExchangeOpType.MODIFY_ORDER: "_op_modify_order",
        ExchangeOpType.BATCH: "_op_batch",
        ExchangeOpType.TWAP_ORDER: "_op_twap_order",
        ExchangeOpType.TWAP_CANCEL: "_op_twap_cancel",
        ExchangeOpType.AGENT_APPROVE: "_op_agent_approve",
        ExchangeOpType.AGENT_REVOKE: "_op_agent_revoke",
        ExchangeOpType.SUBACCOUNT_CREATE: "_op_subaccount_create",
        ExchangeOpType.SUBACCOUNT_TRANSFER: "_op_subaccount_transfer",
        ExchangeOpType.VAULT_CREATE: "_op_vault_create",
        ExchangeOpType.REFERRAL_REGISTER: "_op_referral",
        ExchangeOpType.REFERRAL_JOIN: "_op_referral",
        ExchangeOpType.ACCOUNT_POLICY: "_op_account_policy",
        ExchangeOpType.QNS_REGISTER: "_op_qns_register",
        ExchangeOpType.QNS_RENEW: "_op_qns_renew",
        ExchangeOpType.QNS_SET_RECORD: "_op_qns_set_record",
        ExchangeOpType.QNS_SET_PRIMARY: "_op_qns_set_primary",
        ExchangeOpType.ACCOUNT_RECOVER: "_op_account_recover",
        ExchangeOpType.PERP_ISOLATED_MARGIN: "_op_perp_isolated_margin",
        ExchangeOpType.SCHEDULE_CANCEL: "_op_schedule_cancel",
        ExchangeOpType.APPROVE_BUILDER_FEE: "_op_approve_builder_fee",
        ExchangeOpType.TICKER_CLAIM: "_op_ticker_claim",
    }

    def _execute_op(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Dispatch to the appropriate handler."""
        name = self._HANDLERS.get(tx.op_type)
        if name is None:
            return ExchangeExecResult(success=False, error=f"Unknown op type: {tx.op_type}")
        return getattr(self, name)(tx)

    # =====================================================================
    #  Operation scopes: all or nothing (the operations themselves: qrdx/exchange/handlers/)
    # =====================================================================

    # What an undo scope records of the manager itself: its counters and the length of the
    # block's staking-op log (append-only). The balance ledgers record each entry they change
    # (``_record_balance_delta`` …); nonces, tokens, books and the clearinghouse keep themselves
    # (qrdx/exchange/undo.py).
    _UNDO_FIELDS = (
        "_block_staker_fees",
        "_total_swaps",
        "_total_orders",
        "_total_pools",
        "_total_positions",
    )

    @contextlib.contextmanager
    def atomic(self):
        """All or nothing for everything the body does to the exchange: if it raises, each
        piece of state it touched is put back as it was, at the cost of what it touched — never
        a copy of the whole exchange (qrdx/exchange/undo.py). Scopes nest."""
        with undo.atomic() as scope:
            undo.keep(self, self._UNDO_FIELDS, "manager", shallow=True)
            undo.keep_length(self._validator_lifecycle_ops)
            yield scope

    @contextlib.contextmanager
    def _atomic(self, *engines):
        """All or nothing for one operation: if anything below raises, every touched pool or
        book and every recorded balance move is put back as it was. (``process_transaction``
        turns the exception into a failed result — and a failed operation must change
        nothing, or a swap that misses its own slippage limit could still move a pool's price
        for free.) Order books and committed state undo themselves; an AMM pool is still
        snapshotted. A spot order used to deep-copy its whole book (every resting order).

        The snapshot is recorded with the operation's undo scope, so a failure AFTER this
        block — a multi-hop swap short of its ``min_amount_out``, an order whose book step
        fails after its pool fills — puts the pool back too (it used to stay moved)."""
        with self.atomic() as scope:
            for e in engines:
                if isinstance(e, OrderBook) or not scope.first(e, "engine"):
                    continue
                snap = e.snapshot() if hasattr(e, "snapshot") else copy.deepcopy(e.__dict__)

                def restore(engine=e, snap=snap) -> None:
                    if hasattr(engine, "restore"):
                        engine.restore(snap)
                    else:
                        engine.__dict__.clear()
                        engine.__dict__.update(snap)

                scope.record(e, "engine", restore)
            yield

    # =====================================================================
    #  Validator price oracle (docs/PERPS_CLEARINGHOUSE.md §8)
    # =====================================================================

    MAX_VOTE_PRICES = 64

    # =====================================================================
    #  State root computation (consensus-critical)
    # =====================================================================

    @_pinned
    def compute_state_root(self) -> str:
        """
        Compute a deterministic hash of the entire exchange state.

        This is included in the block header to commit to the exchange
        state at each block boundary — under the rule of the block being processed
        (``_current_block_height``): the incremental commitment once
        ``incremental_state_root`` is in force, the full serialization before it.

        Returns:
            128-char hex string (BLAKE3-512, Whitepaper §3.6 quantum-resistant
            state root). Internal per-component digests use blake2b as a
            deterministic compression step; the committed root is BLAKE3.
        """
        from .. import chain_spec

        if chain_spec.is_active("incremental_state_root", self._current_block_height):
            return self._incremental_state_root()
        return self._sequential_state_root()

    def _incremental_state_root(self) -> str:
        """Every section of the sequential root, each from its incremental commitment: the
        pools and books that changed are re-digested (and within a pool only the ticks and
        positions touched); accounts, nonces, tokens, NFTs and proposals by the entries that
        changed. The small parts (each market's own fields, the votes) are
        recomputed. QRDX_VERIFY_STATE_COMMITMENTS=1 checks every part from scratch."""
        import blake3

        from ..crypto.hashing import STATE_ROOT_SIZE

        pools = Section("pools")
        for pid in sorted(self.pool_manager._pools):
            pools.value(pid).raw(self.pool_manager._pools[pid].cached_digest())
        books = Section("books")
        for pair_key in sorted(self._order_books):
            books.value(pair_key).raw(self._order_books[pair_key].cached_digest())
        # The retired PerpEngine's section, always empty: its digest stays in the formula so
        # the root is unchanged now that the engine is gone.
        perps = Section("perp_engine")
        hasher = blake3.blake3(b"QRDX-EXCHANGE-ROOT-v2\x00")
        for part in (
            pools.digest(),
            books.digest(),
            perps.digest(),
            self.clearinghouse.commitment(),
            self.oracle_state_hash(),
            self.tokens.commitment(),
            self.nfts.commitment(),
            self.governance.commitment(),
            Section("nonces").raw(self._nonces.commitment()).digest(),
            self._current_block_height.to_bytes(8, "big"),
        ):
            hasher.update(part)
        if self.bridge.touched:  # (nothing until the first deposit or withdrawal)
            hasher.update(self.bridge.commitment())
        if self.trading.touched:  # (nothing until the first trigger order)
            hasher.update(self.trading.commitment())
        if self.authority.touched:  # (nothing until the first account policy)
            hasher.update(self.authority.commitment())
        if self.qns.touched:  # (nothing until the first name)
            hasher.update(self.qns.commitment())
        if len(self.fee_tokens):  # (nothing until a fee is shared in another asset)
            hasher.update(Section("fees").raw(self.fee_tokens.commitment()).digest())
        if verifying():
            self.verify_commitments()
        return hasher.digest(length=STATE_ROOT_SIZE).hex()

    def verify_commitments(self) -> None:
        """Check every incremental commitment against a from-scratch recomputation (raises
        ``CommitmentMismatch``): a mutation that bypassed the tracking shows up here."""
        for pool in self.pool_manager._pools.values():
            pool.verify_digest()
        for book in self._order_books.values():
            book.verify_digest()
        self.clearinghouse.verify_commitment()
        self.tokens.verify_commitment()
        self.nfts.verify_commitment()
        self.governance.verify_commitment()
        self.bridge.verify_commitment()
        self.trading.verify_commitment()
        self.authority.verify_commitment()
        self.qns.verify_commitment()
        self._nonces.verify()
        self.fee_tokens.verify()

    @_pinned
    def _sequential_state_root(self) -> str:
        """The exchange root before ``incremental_state_root``: every entry, in order."""
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

        # 4b. Perps clearinghouse: books, accounts, positions, vault, holder mirror.
        hasher.update(self.clearinghouse.state_hash())

        # 4c. Validator price oracle: committee and live votes.
        hasher.update(self.oracle_state_hash())

        # 4d. Native tokens: registry (supply, authorities), allowances, frozen accounts.
        hasher.update(self.tokens.state_hash())
        if self.nfts.collections:  # (nothing until the first collection exists)
            hasher.update(self.nfts.state_hash())
        if self.governance.touched:  # (nothing until the first proposal)
            hasher.update(self.governance.state_hash())
        if self.bridge.touched:  # (nothing until the first deposit or withdrawal)
            hasher.update(self.bridge.commitment())
        if self.trading.touched:  # (nothing until the first trigger order)
            hasher.update(self.trading.state_hash())
        if self.authority.touched:  # (nothing until the first account policy)
            hasher.update(self.authority.state_hash())
        if self.qns.touched:  # (nothing until the first name)
            hasher.update(self.qns.state_hash())

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
        CREATED during the block (new pools, order books, perp markets
        and positions), which a field-level snapshot cannot remove. Correctness
        over speed: a rejected block must leave local state byte-identical.
        """
        self._snapshot = self.capture()
        return self._snapshot

    def capture(self) -> Dict[str, Any]:
        """The deep copy ``take_snapshot`` keeps, without making it this block's revert point —
        for the reorg checkpoints (qrdx/derived_state_rebuild.py). ``_restore_snapshot`` copies
        out of it again, so one capture can be restored more than once."""
        import copy

        snapshot = {
            "nonces": self._nonces.copy(),
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
            "clearinghouse": copy.deepcopy(self.clearinghouse),
            "oracle_committee": copy.deepcopy(self.oracle_committee),
            "oracle_votes": copy.deepcopy(self.oracle_votes),
            "oracle_vote_seqs": dict(self.oracle_vote_seqs),
            "perp_votes": copy.deepcopy(self.perp_votes),
            "oracle_outliers": dict(self.oracle_outliers),
            "oracle_excluded": set(self.oracle_excluded),
            "tokens": copy.deepcopy(self.tokens),
            "nfts": copy.deepcopy(self.nfts),
            "governance": copy.deepcopy(self.governance),
            "bridge": copy.deepcopy(self.bridge),
            "trading": copy.deepcopy(self.trading),
            "authority": copy.deepcopy(self.authority),
            "qns": copy.deepcopy(self.qns),
            "fee_tokens": copy.deepcopy(self.fee_tokens),
            "router_clob_sequence": self.router._clob_sequence,
        }
        return snapshot

    def _restore_snapshot(self, snapshot: Dict[str, Any]) -> None:
        """
        Restore the EXACT pre-block state from a snapshot.

        Containers are restored IN PLACE (clear + repopulate) so external
        references stay valid — notably the router's order-book/oracle registries
        and its handle to ``pool_manager``.
        """
        import copy

        self._nonces = snapshot["nonces"].copy()
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
        self._expiring_pairs = None  # (derived from the books: rebuilt on next use)

        # Perp engine.
        self.clearinghouse = copy.deepcopy(snapshot["clearinghouse"])
        self.oracle_committee = copy.deepcopy(snapshot.get("oracle_committee"))
        self.oracle_votes = copy.deepcopy(snapshot.get("oracle_votes", {}))
        self.oracle_vote_seqs = dict(snapshot.get("oracle_vote_seqs", {}))
        self.perp_votes = copy.deepcopy(snapshot.get("perp_votes", {}))
        self.oracle_outliers = dict(snapshot.get("oracle_outliers", {}))
        self.oracle_excluded = set(snapshot.get("oracle_excluded", set()))

        self.tokens = copy.deepcopy(snapshot.get("tokens", TokenRegistry()))
        self.nfts = copy.deepcopy(snapshot.get("nfts", NftRegistry()))
        self.governance = copy.deepcopy(snapshot.get("governance", Governance()))
        self.bridge = copy.deepcopy(snapshot.get("bridge", Bridge()))
        self.trading = copy.deepcopy(snapshot.get("trading", TradingState()))
        self.authority = copy.deepcopy(snapshot.get("authority", AccountAuthority()))
        self.qns = copy.deepcopy(snapshot.get("qns", NameService()))
        self.fee_tokens = copy.deepcopy(snapshot.get("fee_tokens", {}))
        self.router._clob_sequence = snapshot.get("router_clob_sequence", 0)

    # =====================================================================
    #  Query interface (read-only, for API layer)
    # =====================================================================

    def get_pool(self, pool_id: str) -> Optional[ConcentratedLiquidityPool]:
        return self.pool_manager.get_pool(pool_id)

    def get_order_book(self, pair: str) -> Optional[OrderBook]:
        return self._order_books.get(pair)

    def get_nonce(self, address: str) -> int:
        return self._nonces.get(address, 0)

    def oracle_vote_seq(self, address: str) -> int:
        """The voter's last applied oracle vote sequence (-1: none)."""
        return self.oracle_vote_seqs.get(str(address).lower(), -1)

    # --- Phase E: real-balance bridge ---

    def set_available_balance(self, address: str, qrdx: Decimal) -> None:
        """Pre-load a sender's available QRDX balance (from account_state) for the
        collateral check. Called by the async block paths before processing."""
        undo.keep_entry(self._available_balances, address, mutable=False)
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
        undo.keep_entry(self._balance_deltas, address, mutable=False)
        self._balance_deltas[address] = self._balance_deltas.get(address, ZERO) + delta_qrdx
        if address in self._available_balances:
            undo.keep_entry(self._available_balances, address, mutable=False)
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
            undo.keep_entry(self._available_token_balances, (holder, token), mutable=False)
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
        undo.keep_entry(self._token_balance_deltas, key, mutable=False)
        self._token_balance_deltas[key] = self._token_balance_deltas.get(key, ZERO) + delta
        if key in self._available_token_balances:
            undo.keep_entry(self._available_token_balances, key, mutable=False)
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
            "perp_markets": len(self.clearinghouse.markets),
            "total_swaps": self._total_swaps,
            "total_orders": self._total_orders,
            "total_positions": self._total_positions,
            "block_height": self._current_block_height,
        }

    # ── operations, by domain (qrdx/exchange/handlers/): bound as methods ──────────────

    # spot (handlers/spot.py)
    _op_create_pool = _spot._op_create_pool
    _keep_pair_registries = _spot._keep_pair_registries
    _op_remove_pool = _spot._op_remove_pool
    _op_add_liquidity = _spot._op_add_liquidity
    _op_remove_liquidity = _spot._op_remove_liquidity
    _find_pool_for_pair = _spot._find_pool_for_pair
    routing_hubs = _spot.routing_hubs
    swap_paths = _spot.swap_paths
    _route_gas = staticmethod(_spot._route_gas)
    plan_swap = _spot.plan_swap
    choose_swap_path = _spot.choose_swap_path
    _op_swap = _spot._op_swap
    _swap_hop = _spot._swap_hop
    _flag_self_pass = _spot._flag_self_pass
    pair_price = _spot.pair_price
    pair_quotes = _spot.pair_quotes
    _record_spot_prices = _spot._record_spot_prices
    _clob_fills = staticmethod(_spot._clob_fills)
    _amm_fill = _spot._amm_fill
    canonical_asset = _spot.canonical_asset_method
    _canonical_pair = _spot._canonical_pair
    _op_place_order = _spot._op_place_order
    _pool_part = staticmethod(_spot._pool_part)
    _pools_of = _spot._pools_of
    _fill_from_pools = _spot._fill_from_pools
    _pay_spot_builder = _spot._pay_spot_builder
    _spot_fee = _spot._spot_fee
    _staker_fee_part = staticmethod(_spot._staker_fee_part)
    _accrue_staker_fee = _spot._accrue_staker_fee
    move_perps_staker_fees = _spot.move_perps_staker_fees
    convert_staker_fees = _spot.convert_staker_fees
    _due_fee_tokens = _spot._due_fee_tokens
    _qrdx_twap = _spot._qrdx_twap
    _sell_staker_fee = _spot._sell_staker_fee
    staker_fee_holder = staticmethod(_spot.staker_fee_holder)
    block_staker_fees = _spot.block_staker_fees
    _settles_in_tier_unit = _spot._settles_in_tier_unit
    _settle_spot_trade = _spot._settle_spot_trade
    _bracket_for = _spot._bracket_for
    _drop_empty_bracket = _spot._drop_empty_bracket
    _fill_bracket = _spot._fill_bracket
    _record_spot_volume = _spot._record_spot_volume
    _settle_orderbook = _spot._settle_orderbook
    _op_cancel_order = _spot._op_cancel_order
    _place_spot_trigger = _spot._place_spot_trigger
    _new_spot_trigger = _spot._new_spot_trigger
    _cancel_spot_trigger = _spot._cancel_spot_trigger
    _fired_leg = staticmethod(_spot._fired_leg)
    _refund_trigger = _spot._refund_trigger
    fire_spot_triggers = _spot.fire_spot_triggers
    uncross_spot_books = _spot.uncross_spot_books
    _best_resting = staticmethod(_spot._best_resting)
    _uncross_order = _spot._uncross_order
    _fire_spot_trigger = _spot._fire_spot_trigger
    _refund_escrow = _spot._refund_escrow
    _op_modify_order = _spot._op_modify_order

    # trading (handlers/trading.py)
    _op_agent_approve = _trading._op_agent_approve
    _op_agent_revoke = _trading._op_agent_revoke
    _op_subaccount_create = _trading._op_subaccount_create
    _op_subaccount_transfer = _trading._op_subaccount_transfer
    _op_twap_order = _trading._op_twap_order
    _op_twap_cancel = _trading._op_twap_cancel
    _cancel_twap = _trading._cancel_twap
    run_twaps = _trading.run_twaps
    _twap_view = staticmethod(_trading._twap_view)
    _twap_slice = _trading._twap_slice
    _perp_twap_slice = _trading._perp_twap_slice
    _spot_twap_slice = _trading._spot_twap_slice
    _op_approve_builder_fee = _trading._op_approve_builder_fee
    _builder_of = _trading._builder_of
    _op_cancel_all = _trading._op_cancel_all
    _cancel_all_of = _trading._cancel_all_of
    _op_schedule_cancel = _trading._op_schedule_cancel
    run_scheduled_cancels = _trading.run_scheduled_cancels
    queue_evm_actions = _trading.queue_evm_actions
    _queued_evm_actions = _trading._queued_evm_actions
    evm_action_txs = _trading.evm_action_txs
    run_evm_actions = _trading.run_evm_actions
    _op_batch = _trading._op_batch

    # tokens (handlers/tokens.py)
    derive_token_address = staticmethod(_tokens.derive_token_address)
    pool_holder_address = staticmethod(_tokens.pool_holder_address)
    orderbook_escrow_address = staticmethod(_tokens.orderbook_escrow_address)
    _settle_token_move = _tokens._settle_token_move
    _op_token_deploy = _tokens._op_token_deploy
    _token_move = _tokens._token_move
    _transfer_with_fee = _tokens._transfer_with_fee
    _op_token_transfer = _tokens._op_token_transfer
    _spend_authority = _tokens._spend_authority
    _op_token_transfer_from = _tokens._op_token_transfer_from
    _op_token_mint = _tokens._op_token_mint
    _op_token_burn = _tokens._op_token_burn
    _op_token_approve = _tokens._op_token_approve
    _op_token_set_authority = _tokens._op_token_set_authority
    _op_token_freeze = _tokens._op_token_freeze
    _op_token_update_metadata = _tokens._op_token_update_metadata
    _op_token_set_transfer_fee = _tokens._op_token_set_transfer_fee
    _op_token_withdraw_fees = _tokens._op_token_withdraw_fees
    _op_token_pause = _tokens._op_token_pause
    _op_token_operator = _tokens._op_token_operator
    derive_collection_address = staticmethod(_tokens.derive_collection_address)
    _nft = _tokens._nft
    _op_nft_create_collection = _tokens._op_nft_create_collection
    _op_nft_mint = _tokens._op_nft_mint
    _op_nft_transfer = _tokens._op_nft_transfer
    _op_nft_burn = _tokens._op_nft_burn
    _op_nft_approve = _tokens._op_nft_approve
    _op_nft_set_approval_for_all = _tokens._op_nft_set_approval_for_all
    _op_nft_update = _tokens._op_nft_update
    _op_nft_set_authority = _tokens._op_nft_set_authority
    token_registry_ops = _tokens.token_registry_ops

    # perps (handlers/perps.py)
    _op_create_market = _perps._op_create_market
    _delist_market = _perps._delist_market
    perps_holder_address = staticmethod(_perps.perps_holder_address)
    _op_retired_perp = _perps._op_retired_perp
    perp_collateral_token = staticmethod(_perps.perp_collateral_token)
    _op_portfolio_asset = _perps._op_portfolio_asset
    unwind_vault_assets = _perps.unwind_vault_assets
    _op_perp_deposit = _perps._op_perp_deposit
    _op_perp_withdraw = _perps._op_perp_withdraw
    _op_vault_create = _perps._op_vault_create
    _op_vault_deposit = _perps._op_vault_deposit
    _op_vault_withdraw = _perps._op_vault_withdraw
    _op_perp_set_leverage = _perps._op_perp_set_leverage
    _trade_leverage = _perps._trade_leverage
    reserved_tickers = staticmethod(_perps.reserved_tickers)
    ticker_price = _perps.ticker_price
    ticker_of = _perps.ticker_of
    _op_ticker_claim = _perps._op_ticker_claim
    _list_market = _perps._list_market
    create_genesis_markets = _perps.create_genesis_markets
    _token_perp_asset = _perps._token_perp_asset
    _settlement_asset = _perps._settlement_asset
    _spot_paths = _perps._spot_paths
    _path_reading = _perps._path_reading
    spot_reading = _perps.spot_reading
    update_spot_oracles = _perps.update_spot_oracles
    _op_perp_isolated_margin = _perps._op_perp_isolated_margin
    _op_perp_order = _perps._op_perp_order
    _reduce_only_reason = _perps._reduce_only_reason
    _perp_oracle_stale = _perps._perp_oracle_stale
    _op_perp_trigger = _perps._op_perp_trigger
    _op_perp_modify = _perps._op_perp_modify
    _op_perp_cancel = _perps._op_perp_cancel

    # accounts (handlers/accounts.py)
    qns_authority = _accounts.qns_authority
    _qns_pay = _accounts._qns_pay
    _qns_years = staticmethod(_accounts._qns_years)
    _op_qns_register = _accounts._op_qns_register
    _op_qns_renew = _accounts._op_qns_renew
    _op_qns_set_record = _accounts._op_qns_set_record
    _op_qns_set_primary = _accounts._op_qns_set_primary
    _op_account_policy = _accounts._op_account_policy
    _op_account_recover = _accounts._op_account_recover
    apply_policy_changes = _accounts.apply_policy_changes
    _op_referral = _accounts._op_referral

    # staking (handlers/staking.py)
    _op_stake_deposit = _staking._op_stake_deposit
    _op_stake_exit = _staking._op_stake_exit
    _op_stake_delegate = _staking._op_stake_delegate
    _op_stake_undelegate = _staking._op_stake_undelegate
    _op_stake_set_commission = _staking._op_stake_set_commission
    validator_lifecycle_ops = _staking.validator_lifecycle_ops
    _gov = _staking._gov
    _release_vetoes = _staking._release_vetoes
    _op_gov_propose = _staking._op_gov_propose
    _op_gov_vote = _staking._op_gov_vote
    _op_gov_veto = _staking._op_gov_veto
    _op_gov_execute = _staking._op_gov_execute

    # oracle (handlers/oracle.py)
    load_oracle_committee = _oracle.load_oracle_committee
    _op_oracle_vote = _oracle._op_oracle_vote
    _mint_deposit = _oracle._mint_deposit
    _bridge_mint = _oracle._bridge_mint
    _op_bridge_prove_deposit = _oracle._op_bridge_prove_deposit
    _op_migration_claim = _oracle._op_migration_claim
    doomsday_cutoff = _oracle.doomsday_cutoff
    _trigger_doomsday = _oracle._trigger_doomsday
    _op_doomsday_prove = _oracle._op_doomsday_prove
    _op_bridge_withdraw = _oracle._op_bridge_withdraw
    _oracle_members = _oracle._oracle_members
    apply_oracle_votes = _oracle.apply_oracle_votes
    _aggregate_votes = _oracle._aggregate_votes
    oracle_state_hash = _oracle.oracle_state_hash
    oracle_state = _oracle.oracle_state
    exchange_proof_root = _oracle.exchange_proof_root
