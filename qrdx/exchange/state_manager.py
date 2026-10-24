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
import re
from decimal import ROUND_CEILING, ROUND_DOWN, ROUND_FLOOR, ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..validator.epoch_state import STAKER_FEE_HOLDER
from . import undo
from .amm import (
    FEE_CREATOR_SHARE,
    FEE_TREASURY_SHARE,
    FEE_VALIDATOR_SHARE,
    Q96,
    ConcentratedLiquidityPool,
    FeeTier,
    PoolManager,
    PoolType,
)
from .authority import AccountAuthority
from .bridge import (
    BRIDGE_AUTHORITY,
    MAX_VOTE_DEPOSITS,
    MAX_VOTE_HEADS,
    Bridge,
    BridgeError,
    Deposit,
    asset_by_token,
    configured_assets,
    parse_deposit,
    parse_head,
)
from .clearinghouse import Clearinghouse, ClearinghouseError
from .commitment import Section, committed, encode_value, tracked, verifying
from .governance import Governance, GovernanceError, veto_escrow_address
from .nfts import NftError, NftRegistry, token_id as nft_token_id
from .oracle import TWAPOracle
from .orderbook import (
    MatchBudget,
    Order,
    OrderBook,
    OrderSide,
    OrderType,
    SelfTradeAction,
    _pinned,
)
from .perpetual import PerpEngine
from .qns import NameService
from .router import FillSource, UnifiedRouter
from .tokens import (
    TokenError,
    TokenRegistry,
    account as token_account,
    amount as token_amount,
    canonical_asset,
    is_native_asset,
    memo as token_memo,
)
from .trading import TradingState
from .transactions import (
    EXCHANGE_GAS_COSTS,
    EXCHANGE_GAS_PER_CANCEL,
    EXCHANGE_GAS_PER_MAKER,
    ExchangeOpType,
    ExchangeTransaction,
    batch_actions,
    match_budget,
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
        self.fee = ZERO  # QRDX paid for gas (burned)


class _OperationFailed(Exception):
    """An operation returned a failed result: its changes are undone like a raise's."""

    def __init__(self, result: ExchangeExecResult) -> None:
        super().__init__(result.error)
        self.result = result


class _BatchAction(ExchangeTransaction):
    """One action of a BATCH, run as an operation of its own: the batch's (verified) sender, no
    nonce of its own (the batch's covers it), and a hash — the ids of the orders it places —
    derived from the batch's hash and the action's place in it."""

    def __init__(self, batch_hash: str, index: int, **fields: Any) -> None:
        super().__init__(**fields)
        self._hash = hashlib.blake2b(f"{batch_hash}:{index}".encode(), digest_size=32).hexdigest()

    def tx_hash(self) -> str:
        return self._hash


class _EvmAction(ExchangeTransaction):
    """An exchange action an EVM contract sent (qrdx/contracts/exchange_evm.py), run as an
    operation of the contract's account: authorized by the EVM execution that sent it (no
    signature, no nonce, its gas paid in the EVM), and a hash — the ids of the orders it places
    — derived from its place in the queue, which no other action ever takes."""

    def __init__(self, key: str, **fields: Any) -> None:
        super().__init__(**fields)
        self._hash = hashlib.blake2b(f"evm-action:{key}".encode(), digest_size=32).hexdigest()

    def tx_hash(self) -> str:
        return self._hash


# Spot fees are whole in an 18-decimal asset.
SPOT_FEE_QUANTUM = Decimal("1e-18")
# The stakers' fee share in other assets is sold for QRDX (convert_staker_fees, the tick): at
# most once every STAKER_FEE_CONVERT_SECONDS a token, at no less than STAKER_FEE_CONVERT_SLIPPAGE
# under its QRDX pool's TWAP over STAKER_FEE_TWAP_SECONDS, visiting at most so many resting orders.
STAKER_FEE_CONVERT_SECONDS = Decimal(60)
STAKER_FEE_CONVERT_SLIPPAGE = Decimal("0.02")
STAKER_FEE_TWAP_SECONDS = 600
STAKER_FEE_CONVERT_MAKERS = 20

# The most deployer markets one ORACLE_VOTE may vote to freeze (``freeze``).
MAX_VOTE_FREEZES = 16

# The most hops one SWAP may take (``path``).
MAX_SWAP_HOPS = 4

# PLACE_ORDER order types that make a spot trigger (qrdx/exchange/trading.py).
_TRIGGER_KINDS = {"stop_loss": "sl", "stop": "sl", "take_profit": "tp", "oco": "oco"}


def _attached_legs(params: Dict[str, Any]) -> List[Tuple[str, Decimal, Decimal, int]]:
    """An order's attached ``tp`` / ``sl``: [(kind, trigger price, limit price — 0 for a market
    order — and the matching it prepays)]."""
    from .clearinghouse import TRIGGER_DEFAULT_MAKERS

    legs = []
    for kind in ("tp", "sl"):
        leg = params.get(kind)
        if leg is None:
            continue
        if not isinstance(leg, dict) or "trigger_price" not in leg:
            raise ValueError(f"{kind} is {{trigger_price, limit_price?, max_makers?}}")
        makers = leg.get("max_makers", TRIGGER_DEFAULT_MAKERS)
        if isinstance(makers, bool) or not isinstance(makers, int):
            raise ValueError(f"{kind}.max_makers must be a whole number")
        trigger = Decimal(str(leg["trigger_price"]))
        limit = Decimal(str(leg.get("limit_price") or "0"))
        if not trigger.is_finite() or trigger <= 0 or not limit.is_finite() or limit < 0:
            raise ValueError(f"{kind}: prices must be positive")
        legs.append((kind, trigger, limit, makers))
    return legs


def _trigger_makers(value: Any) -> int:
    """A spot trigger's prepaid matching (``max_makers``; default SPOT_TRIGGER_DEFAULT_MAKERS)."""
    from .trading import SPOT_TRIGGER_DEFAULT_MAKERS, SPOT_TRIGGER_MAX_MAKERS

    makers = SPOT_TRIGGER_DEFAULT_MAKERS if value is None else value
    if isinstance(makers, bool) or not isinstance(makers, int):
        raise ValueError("max_makers must be a whole number")
    if not 1 <= makers <= SPOT_TRIGGER_MAX_MAKERS:
        raise ValueError(f"max_makers must be 1 to {SPOT_TRIGGER_MAX_MAKERS}")
    return makers


def _encode_fee_token(_token: str, value: Any) -> Any:
    # (Module-level: committed collections are pickled with their encoder in the exchange
    # checkpoints — a lambda cannot be.)
    return [str(value[0]), str(value[1])]


def _book_nonce(tx: ExchangeTransaction) -> int:
    """The nonce an order carries into its book's own per-owner replay check. A transaction
    signed in another lane (an agent's, a master's, a leader's: ``nonce_key``) passes 0, which the
    book does not check: lanes number independently, and the manager's lane nonce already
    refuses a replay. (Passing the lane's nonce refused an agent's orders once the owner's own
    nonce had passed it, and the owner's once its agent's had.)"""
    return 0 if getattr(tx, "signer", "") else tx.nonce


def _id_or_raw(address: str) -> str:
    """An address's canonical account id, or the address itself (lowercase) if it has none."""
    try:
        return _account_key(address)
    except ValueError:
        return str(address).lower()


def _account_key(address: str) -> str:
    from .authority import account_id

    return account_id(address)


def _default_policy():
    from .authority import Policy

    return Policy()


def _describe_policy(policy) -> Dict[str, Any]:
    from .authority import describe

    return describe(policy)


def _policy_value(action: str, p: Dict[str, Any]) -> Any:
    """The ACCOUNT_POLICY action's value, checked for its type."""
    if action in ("add_controller", "remove_controller"):
        return str(p["controller"])
    if action == "own_key":
        if not isinstance(p["enabled"], bool):
            raise ValueError("enabled must be true or false")
        return p["enabled"]
    if action == "guardians":
        from .authority import DEFAULT_RECOVERY_DELAY

        guardians, threshold = p["guardians"], p.get("threshold", 0)
        delay = p.get("recovery_delay", DEFAULT_RECOVERY_DELAY)
        if not isinstance(guardians, list) or not all(isinstance(g, str) for g in guardians):
            raise ValueError("guardians is a list of addresses")
        for name, n in (("threshold", threshold), ("recovery_delay", delay)):
            if isinstance(n, bool) or not isinstance(n, int):
                raise ValueError(f"{name} must be a whole number")
        # (Queued as text when the own key signs it: one canonical form.)
        return json.dumps(
            {"guardians": sorted(guardians), "threshold": threshold, "recovery_delay": delay},
            sort_keys=True,
            separators=(",", ":"),
        )
    seconds = p["seconds"]
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise ValueError("seconds must be a whole number")
    return seconds


def _parse_value(change) -> Any:
    if change.action == "own_key":
        return change.value == "True"
    if change.action == "delay":
        return int(change.value)
    return change.value


_CONTROLLER_ADDRESS = re.compile(r"0x[Pp][Qq]([0-9a-fA-F]{64}|[Mm][Ss][0-9a-fA-F]{38})")


def _apply_policy(policy, action: str, value: Any, account: str):
    """``policy`` with the change made — or ValueError if it may not be: a controller is a
    post-quantum key or a multisig, never the account, at most MAX_CONTROLLERS; an account
    whose own key is off keeps at least one controller."""
    from dataclasses import replace

    from .authority import MAX_CONTROLLERS, MAX_DELAY_SECONDS, account_id

    if action == "add_controller":
        if not _CONTROLLER_ADDRESS.fullmatch(value):
            raise ValueError("a controller is a post-quantum (0xPQ…) or multisig (0xPQMS…) address")
        if account_id(value) == account_id(account):
            raise ValueError("an account does not control itself")
        if account_id(value) in policy.controller_ids():
            raise ValueError("already a controller")
        if len(policy.controllers) >= MAX_CONTROLLERS:
            raise ValueError(f"at most {MAX_CONTROLLERS} controllers")
        return replace(policy, controllers=tuple(sorted(policy.controllers + (value,))))
    if action == "remove_controller":
        ids = policy.controller_ids()
        if account_id(value) not in ids:
            raise ValueError("not a controller")
        kept = tuple(c for c in policy.controllers if account_id(c) != account_id(value))
        if not kept and not policy.own_key:
            raise ValueError("an account whose own key is off keeps a controller")
        return replace(policy, controllers=kept)
    if action == "own_key":
        if not value and not policy.controllers:
            raise ValueError("bind a controller before turning the own key off")
        return replace(policy, own_key=bool(value))
    if action == "delay":
        if not 0 <= int(value) <= MAX_DELAY_SECONDS:
            raise ValueError(f"the delay is 0 to {MAX_DELAY_SECONDS} seconds")
        return replace(policy, delay=int(value))
    if action == "guardians":
        from .authority import MAX_GUARDIANS, MIN_RECOVERY_DELAY

        spec = json.loads(value)
        guardians, threshold, delay = spec["guardians"], spec["threshold"], spec["recovery_delay"]
        if not guardians:
            return replace(policy, guardians=(), guardian_threshold=0, recovery_delay=0)
        if len(guardians) > MAX_GUARDIANS:
            raise ValueError(f"at most {MAX_GUARDIANS} guardians")
        ids = []
        for g in guardians:
            if not _CONTROLLER_ADDRESS.fullmatch(g):
                raise ValueError(
                    "a guardian is a post-quantum (0xPQ…) or multisig (0xPQMS…) address"
                )
            ids.append(account_id(g))
        if account_id(account) in ids:
            raise ValueError("an account is not its own guardian")
        if len(set(ids)) != len(ids):
            raise ValueError("a guardian is named twice")
        if not 1 <= threshold <= len(guardians):
            raise ValueError(f"the threshold is 1 to {len(guardians)}")
        if not MIN_RECOVERY_DELAY <= delay <= MAX_DELAY_SECONDS:
            raise ValueError(
                f"the recovery delay is {MIN_RECOVERY_DELAY} to {MAX_DELAY_SECONDS} seconds"
            )
        return replace(
            policy,
            guardians=tuple(sorted(guardians)),
            guardian_threshold=threshold,
            recovery_delay=delay,
        )
    if action == "recover":  # queued by the guardians (ACCOUNT_RECOVER), never signed
        if not _CONTROLLER_ADDRESS.fullmatch(value):
            raise ValueError("a controller is a post-quantum (0xPQ…) or multisig (0xPQMS…) address")
        if account_id(value) == account_id(account):
            raise ValueError("an account does not control itself")
        return replace(policy, controllers=(value,), own_key=False)
    raise ValueError(f"unknown action {action!r}")


def _flag(params: Dict[str, Any], key: str) -> bool:
    """A yes/no parameter: JSON true or false (absent: false). Anything else is refused — a
    string "false" is not false."""
    value = params.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false, got {value!r}")
    return value


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

    # Each sender's next exchange nonce, committed entry by entry (qrdx/exchange/commitment.py).
    _nonces = committed("exchange.nonces", encode_value, mutable=False)
    # The stakers' fee share received in assets other than QRDX, waiting at the fee holder to be
    # sold for QRDX (``convert_staker_fees``): token → (amount, block time of the next attempt).
    fee_tokens = committed("fees.tokens", _encode_fee_token, mutable=False)

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
        self.perp_engine.clock = self._block_clock
        self.router.clock = self._block_clock

        # Order books: pair_key → OrderBook
        self._order_books: Dict[str, OrderBook] = {}
        # Oracles: pair_key → TWAPOracle
        self._oracles: Dict[str, TWAPOracle] = {}
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

        # Reset per-block rate limits on all order books; expiry is judged by block time
        for book in self._order_books.values():
            book.new_block(block_timestamp)

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

        # 1b. Acting for an account: an agent it approved, or a sub-account's master. One the
        #     account never authorized is refused before anything — no nonce, no gas: the
        #     account did not sign it.
        unauthorized = self.signer_error(tx)
        if unauthorized:
            return ExchangeExecResult(success=False, gas_used=0, error=unauthorized)

        # 1c. An action signed to expire (``params.expires_at``) is not includable after that
        #     block time: refused before its nonce or any gas, as if never sent.
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
        if is_vote:
            last = self.oracle_vote_seq(tx.sender)
            if tx.nonce <= last:
                return ExchangeExecResult(
                    success=False,
                    gas_used=0,
                    error=f"Stale oracle vote: sequence {tx.nonce} is not after {last}",
                )
        else:
            expected_nonce = self._nonces.get(tx.nonce_key(), 0)
            if tx.nonce != expected_nonce:
                return ExchangeExecResult(
                    success=False,
                    gas_used=0,
                    error=f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}",
                )

        # 3. Gas limit check (a multisig's every partial signature costs a verification too)
        base_gas = EXCHANGE_GAS_COSTS.get(tx.op_type, 100_000) + tx.signature_gas()
        if tx.gas_limit < base_gas:
            return ExchangeExecResult(
                success=False,
                gas_used=0,
                error=f"Gas limit too low: need {base_gas}, got {tx.gas_limit}",
            )

        # 3a. The free trading lane (docs/TOKENOMICS.md): a trading operation sent at gas price 0
        #     pays nothing while its account has free actions and blocks are not running full;
        #     otherwise it is refused here — not includable, consuming nothing — and must pay.
        free = tx.free_eligible()
        if free:
            refused = self.free_action_error(tx)
            if refused:
                return ExchangeExecResult(success=False, gas_used=0, error=refused)

        # 3b. Fees: a price of at least the floor, and QRDX for the whole gas limit at that
        #     price, reserved before the operation runs (so the operation cannot spend it).
        #     Refused here, an operation is not includable and consumes nothing.
        reserved = ZERO
        if self.enforce_fees and not free:
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
        #    under-gassed — steps 1-3) are not includable and consume nothing.
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

    def free_action_error(self, tx: ExchangeTransaction) -> str:
        """Why ``tx`` may not go free — "" if it may (read only). An account needs a holding
        (FREE_ACTION_MIN_QRDX of QRDX or FREE_ACTION_MIN_EQUITY of perps equity), at most
        FREE_ACTIONS_PER_BLOCK of its free actions are in one block, and it spends from its
        budget (cancels: up to twice it); past the budget, one free action every
        FREE_ACTION_REFILL_SECONDS. While blocks run full, only cancels go free."""
        from .. import constants
        from .transactions import trading_actions

        account = tx.sender
        count, cancels = trading_actions(tx.op_type, tx.params or {})
        if not cancels and not self.free_lane_open():
            return (
                "blocks are running full: the free trading lane is paused — pay gas "
                f"(at least the exchange base fee, {self.exchange_base_fee} wei)"
            )
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
        if self._block_free_actions.get(account, 0) + count > constants.FREE_ACTIONS_PER_BLOCK:
            return (
                f"at most {constants.FREE_ACTIONS_PER_BLOCK} free actions of an account a block "
                "— pay gas, or wait a block"
            )
        used, last = self.trading.action_budgets.peek(account, (0, ZERO))
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
            ExchangeOpType.GOV_PROPOSE: self._op_gov_propose,
            ExchangeOpType.GOV_VOTE: self._op_gov_vote,
            ExchangeOpType.GOV_VETO: self._op_gov_veto,
            ExchangeOpType.GOV_EXECUTE: self._op_gov_execute,
            ExchangeOpType.BRIDGE_WITHDRAW: self._op_bridge_withdraw,
            ExchangeOpType.STAKE_DELEGATE: self._op_stake_delegate,
            ExchangeOpType.STAKE_UNDELEGATE: self._op_stake_undelegate,
            ExchangeOpType.STAKE_SET_COMMISSION: self._op_stake_set_commission,
            ExchangeOpType.PERP_TRIGGER: self._op_perp_trigger,
            ExchangeOpType.CANCEL_ALL: self._op_cancel_all,
            ExchangeOpType.PERP_MODIFY: self._op_perp_modify,
            ExchangeOpType.MODIFY_ORDER: self._op_modify_order,
            ExchangeOpType.BATCH: self._op_batch,
            ExchangeOpType.TWAP_ORDER: self._op_twap_order,
            ExchangeOpType.TWAP_CANCEL: self._op_twap_cancel,
            ExchangeOpType.AGENT_APPROVE: self._op_agent_approve,
            ExchangeOpType.AGENT_REVOKE: self._op_agent_revoke,
            ExchangeOpType.SUBACCOUNT_CREATE: self._op_subaccount_create,
            ExchangeOpType.SUBACCOUNT_TRANSFER: self._op_subaccount_transfer,
            ExchangeOpType.VAULT_CREATE: self._op_vault_create,
            ExchangeOpType.REFERRAL_REGISTER: self._op_referral,
            ExchangeOpType.REFERRAL_JOIN: self._op_referral,
            ExchangeOpType.ACCOUNT_POLICY: self._op_account_policy,
            ExchangeOpType.QNS_REGISTER: self._op_qns_register,
            ExchangeOpType.QNS_RENEW: self._op_qns_renew,
            ExchangeOpType.QNS_SET_RECORD: self._op_qns_set_record,
            ExchangeOpType.QNS_SET_PRIMARY: self._op_qns_set_primary,
            ExchangeOpType.ACCOUNT_RECOVER: self._op_account_recover,
            ExchangeOpType.PERP_ISOLATED_MARGIN: self._op_perp_isolated_margin,
            ExchangeOpType.SCHEDULE_CANCEL: self._op_schedule_cancel,
            ExchangeOpType.APPROVE_BUILDER_FEE: self._op_approve_builder_fee,
            ExchangeOpType.DEPLOYER_BOND: self._op_deployer_bond,
            ExchangeOpType.DEPLOYER_UNBOND: self._op_deployer_unbond,
            ExchangeOpType.DEPLOYER_SET_ORACLE: self._op_deployer_set_oracle,
            ExchangeOpType.DEPLOYER_HALT: self._op_deployer_halt,
            ExchangeOpType.TICKER_CLAIM: self._op_ticker_claim,
        }
        handler = handlers.get(tx.op_type)
        if handler is None:
            return ExchangeExecResult(success=False, error=f"Unknown op type: {tx.op_type}")
        return handler(tx)

    # =====================================================================
    #  Operation handlers
    # =====================================================================

    def _op_create_pool(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        fee_tier = FeeTier(int(p["fee_tier"]))
        pool_type = (
            PoolType[p["pool_type"]]
            if isinstance(p["pool_type"], str)
            else PoolType(int(p["pool_type"]))
        )
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
                    error=(
                        f"insufficient balance for pool stake: need {stake}, " f"available {avail}"
                    ),
                )
            logger.warning(
                "[Phase E observe] create_pool by %s: stake %s exceeds available "
                "balance %s — would REJECT once pool stake is enforced",
                tx.sender[:20],
                stake,
                avail,
            )

        for asset in (self.canonical_asset(p["token0"]), self.canonical_asset(p["token1"])):
            t = self.tokens.get(asset)
            if t is not None and (t.fee_enabled or t.non_transferable):
                # Spot moves are exact (a pool's reserves, a book's escrow): a fee withheld
                # on the way in would break their accounting; a soulbound token cannot move.
                kind = "charges a transfer fee" if t.fee_enabled else "is non-transferable"
                return ExchangeExecResult(
                    success=False, error=f"{t.symbol} {kind}: it cannot be pooled or traded"
                )
        try:
            pool = self.pool_manager.create_pool(
                self.canonical_asset(p["token0"]),
                self.canonical_asset(p["token1"]),
                fee_tier,
                pool_type,
                sqrt_price,
                tx.sender,
                stake,
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
                error=f"pool still has {len(pool.state.positions)} position(s); remove them first",
            )

        from .. import constants
        from .amm import PoolType

        stake = Decimal(str(pool.state.stake_amount or 0))
        pool_type = pool.state.pool_type
        pair_key = f"{pool.state.token0}:{pool.state.token1}"
        holder = self.pool_holder_address(pool.state.id)
        treasury = constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"]
        share = FEE_CREATOR_SHARE / (FEE_CREATOR_SHARE + FEE_TREASURY_SHARE + FEE_VALIDATOR_SHARE)
        try:
            with self._atomic(pool):
                for token, fees in (
                    (pool.state.token0, pool.state.protocol_fees_0),
                    (pool.state.token1, pool.state.protocol_fees_1),
                ):
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
            data={
                "pool_id": pool.state.id,
                "refunded_stake": str(refunded),
                "burned_stake": str(stake) if pool_type == PoolType.SUBSIDIZED else "0",
                "protocol_fees": [str(pool.state.protocol_fees_0), str(pool.state.protocol_fees_1)],
            },
        )

    def _op_add_liquidity(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Deposit liquidity ``amount`` (L) in [tick_lower, tick_upper). The tokens it costs —
        rounded up, in the pool's favour — move from the provider to the pool's holder. The pool
        is named by ``pool_id``, or by ``token0`` / ``token1`` (+ ``fee_tier`` when the pair has
        several pools)."""
        p = tx.params
        pool = self.pool_manager.get_pool(p["pool_id"]) if p.get("pool_id") else None
        if pool is None and p.get("token0") and p.get("token1"):
            pool = self._find_pool_for_pair(
                self.canonical_asset(p["token0"]),
                self.canonical_asset(p["token1"]),
                p.get("fee_tier"),
            )
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
                        error=f"insufficient {tok[:10]} for liquidity: need {amt}, available {av}",
                    )
        holder = self.pool_holder_address(pool.state.id)
        with self._atomic(pool):
            position = pool.add_liquidity(
                tx.sender, tick_lower, tick_upper, liquidity, now=int(self._block_clock())
            )
            self._settle_token_move(tx.sender, holder, pool.state.token0, amt0)
            self._settle_token_move(tx.sender, holder, pool.state.token1, amt1)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ADD_LIQUIDITY],
            data={
                "pool_id": pool.state.id,
                "position_id": position.id,
                "liquidity": str(liquidity),
                "amount0": str(amt0),
                "amount1": str(amt1),
            },
        )

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
                success=False, error="only the position's owner may remove its liquidity"
            )
        raw = p.get("amount")
        amount = Decimal(str(raw)) if raw not in (None, "", "all") else None
        if amount is not None and amount < 0:
            return ExchangeExecResult(success=False, error="amount must not be negative")
        holder = self.pool_holder_address(pool.state.id)
        try:
            with self._atomic(pool):
                out0, out1 = pool.remove_liquidity(
                    position.id, amount, owner=tx.sender, now=int(self._block_clock())
                )
                self._settle_token_move(holder, tx.sender, pool.state.token0, out0)
                self._settle_token_move(holder, tx.sender, pool.state.token1, out1)
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.REMOVE_LIQUIDITY],
            data={
                "pool_id": pool.state.id,
                "position_id": position.id,
                "amount0": str(out0),
                "amount1": str(out1),
                "removed": str((out0, out1)),
            },
        )

    def _find_pool_for_pair(self, token_a: str, token_b: str, fee_tier=None):
        """A pool for the pair: the one with ``fee_tier`` if given, else — only when the pair
        has exactly one pool — that one. Several pools and no fee tier is ambiguous: None."""
        pools = sorted(
            self.pool_manager.get_pools_for_pair(token_a, token_b), key=lambda p: p.state.id
        )
        if fee_tier is not None:
            pools = [p for p in pools if int(p.state.fee_tier) == int(fee_tier)]
        return pools[0] if len(pools) == 1 else None

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
        snapshotted. A spot order used to deep-copy its whole book (every resting order)."""
        with self.atomic():
            saved = [
                (e, e.snapshot() if hasattr(e, "snapshot") else copy.deepcopy(e.__dict__))
                for e in engines
                if not isinstance(e, OrderBook)
            ]
            try:
                yield
            except Exception:
                for engine, snap in saved:
                    if hasattr(engine, "restore"):
                        engine.restore(snap)
                    else:
                        engine.__dict__.clear()
                        engine.__dict__.update(snap)
                raise

    def _op_swap(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Exact-input swap through the best venue — any of the pair's AMM pools or its order
        book (``pool_id`` pins a pool; ``venue`` = auto | amm | clob). Every check runs on the
        router's exact quote before anything changes, and the fill settles with its real
        counterparty: the pool's holder, or the matched makers' escrow.

        ``path`` [A, B, C, …] (instead of ``token_in``/``token_out``): a multi-hop swap, up to
        MAX_SWAP_HOPS hops, each through its pair's best venue and each spending exactly what
        the one before it bought; ``min_amount_out`` bounds the last. All or nothing.

        Gas: SWAP's base gas for each hop, and EXCHANGE_GAS_PER_MAKER for each resting order
        an order-book fill visits — no more than the gas limit pays for (an order-book route
        is quoted within that budget)."""
        p = tx.params
        if p.get("path") is not None:
            path = p["path"]
            if (
                not isinstance(path, list)
                or not 2 <= len(path) <= MAX_SWAP_HOPS + 1
                or not all(isinstance(t, str) and t for t in path)
            ):
                return ExchangeExecResult(
                    success=False,
                    error=f"path is a list of 2 to {MAX_SWAP_HOPS + 1} tokens",
                )
            path = [self.canonical_asset(t) for t in path]
        else:
            path = [self.canonical_asset(p["token_in"]), self.canonical_asset(p["token_out"])]
        if len(set(path)) != len(path):
            return ExchangeExecResult(success=False, error="a swap path visits each token once")
        amount_in = Decimal(str(p["amount_in"]))
        min_out = Decimal(str(p.get("min_amount_out", "0") or "0"))
        deadline = float(p.get("deadline", 0) or 0)
        token_in = path[0]
        if amount_in <= 0:
            return ExchangeExecResult(success=False, error="amount_in must be positive")
        if deadline > 0 and self._block_clock() > deadline:
            return ExchangeExecResult(success=False, error="Transaction deadline expired")
        avail = self.available_token_balance(tx.sender, token_in)
        if avail is not None and avail < amount_in:
            if self.enforce_spot_settlement:
                return ExchangeExecResult(
                    success=False,
                    error=f"insufficient token_in: need {amount_in}, available {avail}",
                )
            logger.warning(
                "[Phase E observe] swap by %s: amount_in %s exceeds available %s",
                tx.sender[:20],
                amount_in,
                avail,
            )

        hops = len(path) - 1
        gas = EXCHANGE_GAS_COSTS[ExchangeOpType.SWAP] * hops
        gas_limit = getattr(tx, "gas_limit", None)  # (None: built in process, never in a block)
        if gas_limit is not None and gas > gas_limit:
            return ExchangeExecResult(
                success=False, error=f"a {hops}-hop swap needs at least {gas} gas"
            )
        amount, spent_in = amount_in, ZERO
        routes, fills = [], []
        for i in range(hops):
            makers = (
                None
                if gas_limit is None
                else max(0, (int(gas_limit) - gas) // EXCHANGE_GAS_PER_MAKER)
            )
            route = self.router.best_route(
                path[i],
                path[i + 1],
                amount,
                tx.sender,
                pool_id=p.get("pool_id") if hops == 1 else None,
                venue=str(p.get("venue", "auto")).lower(),
                max_makers=makers,
            )
            if route is None:
                error = "No liquidity available for this pair"
                return ExchangeExecResult(
                    success=False, gas_used=gas, error=error if hops == 1 else f"hop {i}: {error}"
                )
            if hops == 1 and min_out > 0 and route.amount_out < min_out:
                return ExchangeExecResult(
                    success=False,
                    error=f"Slippage exceeded: got {route.amount_out}, minimum {min_out}",
                )
            try:
                visited, hop_fills = self._swap_hop(tx.sender, route)
            except ValueError as e:
                return ExchangeExecResult(success=False, gas_used=gas, error=str(e))
            gas += visited * EXCHANGE_GAS_PER_MAKER
            spent_in = route.amount_in if i == 0 else spent_in
            amount = route.amount_out
            routes.append(route)
            fills += hop_fills
        if min_out > 0 and amount < min_out:  # (a multi-hop swap: undone whole)
            return ExchangeExecResult(
                success=False,
                gas_used=gas,
                error=f"Slippage exceeded: got {amount}, minimum {min_out}",
            )

        self._total_swaps += 1
        first = routes[0]
        data: Dict[str, Any] = {
            "amount_in": str(spent_in),
            "amount_out": str(amount),
            "fee_total": str(sum((r.fee_total for r in routes), ZERO)),
            "price": str(spent_in / amount) if amount > 0 else "0",
            "source": first.source.value,
            "pool_id": first.pool_id,
            "fills": fills,
        }
        if hops > 1:
            data["path"] = path
            data["hops"] = [
                {
                    "token_in": r.token_in,
                    "token_out": r.token_out,
                    "amount_in": str(r.amount_in),
                    "amount_out": str(r.amount_out),
                    "source": r.source.value,
                    "pool_id": r.pool_id,
                }
                for r in routes
            ]
        return ExchangeExecResult(success=True, gas_used=gas, data=data)

    def _swap_hop(
        self, sender: str, route, payer: Optional[str] = None
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """Execute one quoted swap route and settle it; returns the resting orders it visited
        and its fills. Raises ValueError (its changes undone) if it cannot settle. ``payer``:
        the protocol holder its input comes out of instead of ``sender`` (a TWAP slice's
        escrow, in the block's tick: every debit covered by protocol records)."""
        engine: Any
        if route.source == FillSource.AMM:
            engine = self.pool_manager.get_pool(route.amm()[0])
        else:
            engine = self._order_books[route.clob()[0]]
        covered = payer is not None
        with self._atomic(engine):
            result = self.router.apply_route(route, sender, now=int(self._block_clock()))
            if route.source == FillSource.AMM:
                holder = self.pool_holder_address(route.amm()[0])
                self._settle_token_move(
                    payer or sender, holder, route.token_in, route.amount_in, covered=covered
                )
                self._settle_token_move(
                    holder, sender, route.token_out, route.amount_out, covered=covered
                )
            else:
                pair = route.clob()[0]
                base, quote = pair.split(":", 1)
                self._settle_orderbook(result.order, result.trades, base, quote, pair, payer)
        if route.source == FillSource.AMM:
            return 0, [self._amm_fill(route, sender)]
        pair, side = route.clob()
        return result.makers_visited, self._clob_fills(pair, result.trades, sender, side)

    # A spot trade as the market-data feed sees it (journal.py → market_data.py): the pair in
    # canonical "base:quote" order, the price in quote per base, the base amount, and the
    # TAKER's side. Result data only — never hashed.

    @staticmethod
    def _clob_fills(pair: str, trades, taker: str, side) -> List[Dict[str, Any]]:
        side = getattr(side, "value", side)
        return [
            {
                "market": pair,
                "venue": "clob",
                "trade_id": t.id,
                "price": str(t.price),
                "amount": str(t.amount),
                "buyer": t.buyer,
                "seller": t.seller,
                "maker": t.seller if t.buyer == taker else t.buyer,
                "taker": taker,
                "side": side,
                "maker_order_id": t.maker_order_id,
                "taker_order_id": t.taker_order_id,
                # Each side's fee, in the asset it received (the buyer's in base).
                "fees": {
                    t.buyer: str(t.taker_fee if t.buyer == taker else t.maker_fee),
                    t.seller: str(t.taker_fee if t.seller == taker else t.maker_fee),
                },
            }
            for t in trades
        ]

    def _amm_fill(self, route, taker: str) -> Dict[str, Any]:
        pair = self._canonical_pair(f"{route.token_in}:{route.token_out}")
        base = pair.split(":", 1)[0]
        holder = self.pool_holder_address(route.pool_id)
        if route.token_in == base:  # selling base into the pool
            amount, quote_amount, side = route.amount_in, route.amount_out, "sell"
            buyer, seller = holder, taker
        else:
            amount, quote_amount, side = route.amount_out, route.amount_in, "buy"
            buyer, seller = taker, holder
        return {
            "market": pair,
            "venue": "amm",
            "pool_id": route.pool_id,
            "price": str(quote_amount / amount) if amount > 0 else "0",
            "amount": str(amount),
            "quote_amount": str(quote_amount),
            "buyer": buyer,
            "seller": seller,
            "maker": holder,
            "taker": taker,
            "side": side,
        }

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
        kind = _TRIGGER_KINDS.get(str(raw_otype).lower())
        if kind is not None:
            return self._place_spot_trigger(tx, pair, book, side, kind)
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
            nonce=_book_nonce(tx),
            tif=str(p.get("tif", "gtc")).lower(),
            hidden=_flag(p, "hidden"),
            display_size=Decimal(str(p.get("display_size", "0"))),
        )

        # Phase E CLOB settlement: reject what we cannot settle BEFORE matching mutates
        # the book (a failed op is NOT reverted — the block continues). Only plain LIMIT
        # orders are settled in this increment; MARKET/STOP need affordability handling
        # not yet built. The worst-case cost (full amount at the limit price) bounds the
        # taker's total outflow (fills at maker prices ≤ limit, + resting escrow), so a
        # taker that affords it can never overdraw.
        base, quote = (pair.split(":", 1) + [""])[:2] if ":" in pair else (pair, "")
        if self.enforce_orderbook_settlement:
            # A market order takes what the book has and never rests: each fill is paid live
            # (a payment its balance cannot cover fails it whole), so there is no worst case to
            # check first — nor any escrow.
            need_token = quote if side == OrderSide.BUY else base
            need_amount = (order.amount * order.price) if side == OrderSide.BUY else order.amount
            avail = self.available_token_balance(tx.sender, need_token)
            if order_type is OrderType.LIMIT and avail is not None and avail < need_amount:
                return ExchangeExecResult(
                    success=False,
                    error=f"insufficient balance for order: need {need_amount} {need_token[:10]}, "
                    f"available {avail}",
                )

        # An attached take-profit / stop-loss (``tp`` / ``sl``: each {trigger_price, price?}) on
        # a buy: a sell trigger — a one-cancels-the-other with both — that starts empty; each
        # fill of this order puts the base it bought (after its fee) into the trigger's escrow.
        # It costs what a trigger costs; the order's matching gets what is left of the gas.
        bracket_gas = 0
        bracket_id = f"{order.id}.b"
        gas_limit = getattr(tx, "gas_limit", None)
        try:
            legs = {
                leg: (p[leg].get("trigger_price"), p[leg].get("price"))
                for leg in ("tp", "sl")
                if isinstance(p.get(leg), dict)
            }
            if any(p.get(leg) is not None and not isinstance(p[leg], dict) for leg in ("tp", "sl")):
                raise ValueError("tp and sl are {trigger_price, price?}")
            builder = self._builder_of(tx, spot=True)
            if builder is not None and legs:
                # (the bracket takes what the order buys: no builder fee can come out of it)
                raise ValueError("a builder fee and an attached TP/SL do not combine on spot")
            if legs:
                if side != OrderSide.BUY:
                    raise ValueError("an attached TP/SL protects what a buy order buys")
                makers_tp = _trigger_makers(p.get("tp_sl_max_makers"))
                bracket_gas = (
                    EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER]
                    + makers_tp * EXCHANGE_GAS_PER_MAKER
                )
                if (
                    gas_limit is not None
                    and bracket_gas
                    > int(gas_limit) - EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER]
                ):
                    raise ValueError(
                        f"the attached TP/SL needs {bracket_gas} gas beyond the order's"
                    )
                self.trading.spot_triggers[bracket_id] = self._new_spot_trigger(
                    tx.sender,
                    pair,
                    book,
                    "sell",
                    legs,
                    ZERO,
                    str(p.get("tp_sl_tif", "gtc")),
                    makers_tp,
                    parent=order.id,
                )
        except (ValueError, KeyError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))

        makers = match_budget(
            ExchangeOpType.PLACE_ORDER, None if gas_limit is None else gas_limit - bracket_gas
        )
        budget = MatchBudget(makers) if makers is not None else None
        try:
            with self._atomic(book):
                trades = book.place_order(order, budget=budget)
                if self.enforce_orderbook_settlement:
                    self._settle_orderbook(order, trades, base, quote, pair)
                builder_fee = self._pay_spot_builder(tx.sender, builder, trades, base, quote)
        except ValueError as e:
            # It pays for the resting orders it visited before failing (a fill-or-kill that
            # could not fill whole), as it would have had it succeeded.
            return ExchangeExecResult(
                success=False,
                error=str(e),
                gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER]
                + (budget.visited if budget is not None else 0) * EXCHANGE_GAS_PER_MAKER,
            )
        data: Dict[str, Any] = {
            "order_id": order.id,
            "trades": len(trades),
            "filled": str(order.filled),
            "fills": self._clob_fills(pair, trades, tx.sender, side),
        }
        if builder is not None:
            data["builder_fee"] = {"builder": builder[0], **builder_fee}
        if bracket_gas:
            bracket = self.trading.spot_triggers.peek(bracket_id)
            if not order.is_active and (bracket is None or bracket.amount <= 0):
                if bracket is not None:  # (an order that bought nothing protects nothing)
                    del self.trading.spot_triggers[bracket_id]
            else:
                data["attached"] = bracket_id

        self._total_orders += 1
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER]
            + (budget.visited if budget is not None else 0) * EXCHANGE_GAS_PER_MAKER
            + (bracket_gas if "attached" in data else 0),
            data=data,
        )

    def _pay_spot_builder(
        self, taker: str, builder: Optional[Tuple[str, Decimal]], trades, base: str, quote: str
    ) -> Dict[str, str]:
        """A builder's fee on the fills a spot order took: its rate of what the taker received in
        each (base for a buy, quote for a sell), out of it, to the builder. Returns the amounts
        by asset."""
        paid: Dict[str, Decimal] = {}
        if builder is None:
            return {}
        for tr in trades:
            if taker not in (tr.buyer, tr.seller) or tr.maker_order_id is None:
                continue
            token, value = (
                (base, Decimal(str(tr.amount)))
                if tr.buyer == taker
                else (quote, Decimal(str(tr.amount)) * Decimal(str(tr.price)))
            )
            fee = (value * builder[1]).quantize(SPOT_FEE_QUANTUM, rounding=ROUND_DOWN)
            if fee > 0:
                self._settle_token_move(taker, builder[0], token, fee)
                paid[token] = paid.get(token, ZERO) + fee
        return {t: str(v) for t, v in sorted(paid.items())}

    # ── spot fees ───────────────────────────────────────────────────────────

    def _spot_fee(self, owner: str, is_maker: bool, value: Decimal) -> Tuple[Decimal, Decimal, str]:
        """(fee, referral reward, referrer) on ``value`` of the asset ``owner`` receives in a
        spot order-book fill: its fee tier's rate (the perps tiers — one tier an account; a
        spot maker pays no less than nothing: its fee and a taker's are in different assets),
        less a referee's discount; the referrer's share of what is left."""
        from .clearinghouse import (
            REFEREE_DISCOUNT,
            REFERRAL_VOLUME_CAP,
            REFERRER_SHARE,
        )

        ch = self.clearinghouse
        taker, maker = ch.fee_rates(owner)
        rate = max(ZERO, maker) if is_maker else taker
        fee = (value * rate).quantize(SPOT_FEE_QUANTUM, rounding=ROUND_HALF_UP)
        ref = ch.referrals.peek(owner)
        if fee <= 0 or ref is None:
            return fee, ZERO, ""
        if ref.volume < REFERRAL_VOLUME_CAP:
            fee = (fee * (1 - REFEREE_DISCOUNT)).quantize(SPOT_FEE_QUANTUM, rounding=ROUND_HALF_UP)
        reward = (fee * REFERRER_SHARE).quantize(SPOT_FEE_QUANTUM, rounding=ROUND_DOWN)
        return fee, reward, ref.referrer

    @staticmethod
    def _staker_fee_part(token: str, protocol_fee: Decimal) -> Decimal:
        """The stakers' share (STAKER_FEE_SHARE_BPS) of a spot fee the protocol keeps
        (docs/CONSENSUS_ROADMAP.md 6) — in whatever asset it was paid: QRDX is staker income at
        once, another token waits at the fee holder to be sold for QRDX
        (``convert_staker_fees``)."""
        from .. import constants

        if protocol_fee <= 0:
            return ZERO
        share = min(Decimal(1), Decimal(int(constants.STAKER_FEE_SHARE_BPS)) / 10_000)
        return (protocol_fee * share).quantize(SPOT_FEE_QUANTUM, rounding=ROUND_DOWN)

    def _accrue_staker_fee(self, token: str, amount: Decimal) -> None:
        """The stakers' fee share has reached the fee holder: QRDX is this block's staker income;
        another token is recorded for conversion (the record covers the holder's tick-time sale
        of it)."""
        if token == "QRDX":
            self._block_staker_fees += amount
            return
        pending, next_time = self.fee_tokens.get(token, (ZERO, ZERO))
        self.fee_tokens[token] = (pending + amount, next_time)

    def move_perps_staker_fees(self) -> Decimal:
        """At the block's end: the stakers' share of perps fees the clearinghouse withheld moves
        from the perps holder to the fee holder on the ledger (in the perps collateral)."""
        amount = self.clearinghouse.take_staker_fees()
        if amount > 0:
            token = self.canonical_asset(self.perp_collateral_token() or "QRDX")
            if token == "QRDX":
                self._record_balance_delta(self.perps_holder_address(), -amount)
                self._record_balance_delta(STAKER_FEE_HOLDER, amount)
            else:
                self._settle_token_move(
                    self.perps_holder_address(), STAKER_FEE_HOLDER, token, amount, covered=True
                )
            self._accrue_staker_fee(token, amount)
        return amount

    @_pinned
    def convert_staker_fees(self, now: Decimal) -> List[Dict[str, Any]]:
        """The block's tick for the stakers' fee share in other assets: each token whose attempt
        is due is sold for QRDX through the best route, out of the fee holder — only at no less
        than STAKER_FEE_CONVERT_SLIPPAGE under the TWAP of its deepest QRDX pool over
        STAKER_FEE_TWAP_SECONDS (an attacker must hold a price that long to move the floor): all
        of it, else a quarter, else it waits STAKER_FEE_CONVERT_SECONDS. The QRDX it brings is
        this block's staker income. A token with no QRDX pool, or no TWAP yet, waits."""
        if not len(self.fee_tokens):
            return []
        events: List[Dict[str, Any]] = []
        for token, (pending, next_time) in sorted(self.fee_tokens.peek_items()):
            if pending <= 0 or now < next_time:
                continue
            retry = (pending, now + STAKER_FEE_CONVERT_SECONDS)
            ref = self._qrdx_twap(token, int(now))
            sold = None
            if ref is not None and ref > 0:
                for amount in (pending, (pending / 4).quantize(SPOT_FEE_QUANTUM, ROUND_DOWN)):
                    if amount <= 0:
                        continue
                    sold = self._sell_staker_fee(token, amount, ref, now)
                    if sold is not None:
                        break
            if sold is None:
                self.fee_tokens[token] = retry
                continue
            amount_in, amount_out, fills = sold
            left = pending - amount_in
            if left > 0:
                self.fee_tokens[token] = (left, now + STAKER_FEE_CONVERT_SECONDS)
            else:
                del self.fee_tokens[token]
            self._block_staker_fees += amount_out
            events.append(
                {
                    "type": "staker_fee_conversion",
                    "token": token,
                    "sold": str(amount_in),
                    "proceeds": str(amount_out),
                    "fills": fills,
                }
            )
        return events

    def _qrdx_twap(self, token: str, now: int) -> Optional[Decimal]:
        """QRDX per ``token`` over STAKER_FEE_TWAP_SECONDS, from its deepest QRDX pool (most
        liquidity, then the lowest id); None without one or without the history."""
        pools = self.pool_manager.get_pools_for_pair(token, "QRDX")
        if not pools:
            return None
        pool = max(pools, key=lambda p: (p.state.liquidity, [-ord(c) for c in p.state.id]))
        price = pool.twap_price(STAKER_FEE_TWAP_SECONDS, now)  # token1 per token0
        if price is None or price <= 0:
            return None
        return price if pool.state.token0 == token else Decimal(1) / price

    def _sell_staker_fee(self, token: str, amount: Decimal, ref: Decimal, now: Decimal):
        """Sell ``amount`` of the fee holder's ``token`` for QRDX if the route pays at least the
        floor; (sold, proceeds, fills), or None (nothing changed)."""
        route = self.router.best_route(
            token, "QRDX", amount, STAKER_FEE_HOLDER, max_makers=STAKER_FEE_CONVERT_MAKERS
        )
        floor = amount * ref * (1 - STAKER_FEE_CONVERT_SLIPPAGE)
        if route is None or route.amount_in != amount or route.amount_out < floor:
            return None
        try:
            with undo.atomic():
                _visited, fills = self._swap_hop(STAKER_FEE_HOLDER, route, payer=STAKER_FEE_HOLDER)
        except Exception as e:  # noqa: BLE001 — deterministic on every node; never fails a block
            logger.warning("staker fee conversion of %s failed: %s", token, e)
            return None
        return route.amount_in, route.amount_out, fills

    @staticmethod
    def staker_fee_holder() -> str:
        """Where the stakers' fee share waits for its epoch's share-out (validator/epoch_state)."""
        return STAKER_FEE_HOLDER

    def block_staker_fees(self) -> Decimal:
        """The stakers' fee income this block took in (logged per block: staker_fee_income)."""
        return self._block_staker_fees

    def _settles_in_tier_unit(self, quote: str) -> bool:
        """A pair quoted in the perps settlement asset: its volume counts toward fee tiers."""
        token = self.perp_collateral_token()
        return bool(token) and self.canonical_asset(token) == quote

    def _settle_spot_trade(
        self,
        tr,
        base: str,
        quote: str,
        taker: str,
        base_src: str,
        quote_src: str,
        covered: bool = False,
        base_to: Optional[str] = None,
    ) -> Decimal:
        """One spot order-book fill: base seller → buyer, quote buyer → seller, each side
        paying its fee out of what it receives (the buyer in base, the seller in quote) to the
        treasury, less a referrer's share. The debits come from ``base_src`` / ``quote_src``;
        ``base_to``: where the buyer's base goes instead of the buyer (an attached TP/SL's
        escrow). Records the fees on the trade (its ``maker_fee`` / ``taker_fee``, each in the
        asset that side received). Returns the base the buyer received, after its fee."""
        from .. import constants

        treasury = constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"]
        f = Decimal(str(tr.amount))
        notional = f * Decimal(str(tr.price))
        moves = (
            (tr.buyer, base, f, base_src, base_to or tr.buyer),
            (tr.seller, quote, notional, quote_src, tr.seller),
        )
        for owner, token, value, src, dst in moves:
            fee, reward, referrer = self._spot_fee(owner, owner != taker, value)
            self._settle_token_move(src, dst, token, value - fee, covered=covered)
            staker = self._staker_fee_part(token, fee - reward)
            if staker > 0:
                self._settle_token_move(src, STAKER_FEE_HOLDER, token, staker, covered=covered)
                self._accrue_staker_fee(token, staker)
            self._settle_token_move(src, treasury, token, fee - reward - staker, covered=covered)
            if reward > 0:
                self._settle_token_move(src, referrer, token, reward, covered=covered)
            if owner == taker:
                tr.taker_fee = fee
            else:
                tr.maker_fee = fee
            if owner == tr.buyer:
                received = value - fee
        return received

    def _bracket_for(self, tr, taker: str) -> Optional[str]:
        """The TP/SL attached to a fill's BUY order, if it has one: the base it buys goes into
        that bracket's escrow (``_fill_bracket``), not to the buyer."""
        buy_order = tr.taker_order_id if tr.buyer == taker else tr.maker_order_id
        return self.trading.bracket_of(buy_order) if len(self.trading.spot_triggers) else None

    def _drop_empty_bracket(self, order_id: str) -> None:
        """An order cancelled before it bought anything: its attached TP/SL (empty) goes too.
        (One that holds what the order bought stays: it protects that.)"""
        tid = self.trading.bracket_of(order_id) if len(self.trading.spot_triggers) else None
        t = self.trading.spot_triggers.peek(tid) if tid else None
        if t is not None and t.amount <= 0:
            del self.trading.spot_triggers[tid]

    def _fill_bracket(self, tid: str, received: Decimal) -> None:
        from dataclasses import replace

        t = self.trading.spot_triggers.peek(tid)
        self.trading.spot_triggers[tid] = replace(
            t, amount=t.amount + received, escrowed=t.escrowed + received
        )

    def _record_spot_volume(self, trades, quote: str) -> None:
        """After an operation's fills settle (so its quote held throughout): their notional
        counts toward each side's fee tier, if the pair is quoted in the settlement asset."""
        if not self._settles_in_tier_unit(quote):
            return
        for tr in trades:
            notional = Decimal(str(tr.amount)) * Decimal(str(tr.price))
            for owner in (tr.buyer, tr.seller):
                self.clearinghouse._record_volume(owner, notional)

    def _settle_orderbook(
        self, order, trades, base: str, quote: str, pair: str, payer: Optional[str] = None
    ) -> None:
        """Settle a CLOB order's matched trades + escrow its resting remainder as real
        token moves (Phase E). Conserves both tokens: each trade moves base seller→buyer
        and quote buyer→seller; the MAKER's side (the resting party) comes from the book
        escrow it funded at placement, the TAKER's (this order's owner) comes live; the
        taker keeps any price improvement automatically (it pays the maker's price, not
        its limit). The resting remainder is escrowed; CANCEL_ORDER refunds it.

        ``payer``: the protocol holder the taker's side comes out of instead (a TWAP slice's
        escrow, in the block's tick); every debit is then covered by escrow records."""
        taker = order.owner
        escrow = self.orderbook_escrow_address(pair)
        covered = payer is not None
        for tr in trades:
            # Taker's side live (or from ``payer``); the resting maker's from the book escrow.
            bracket = self._bracket_for(tr, taker)
            received = self._settle_spot_trade(
                tr,
                base,
                quote,
                taker,
                (payer or taker) if tr.seller == taker else escrow,
                (payer or taker) if tr.buyer == taker else escrow,
                covered,
                base_to=escrow if bracket else None,
            )
            if bracket:
                self._fill_bracket(bracket, received)
        self._record_spot_volume(trades, quote)
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
        if self._cancel_spot_trigger(tx.sender, str(order_id)):
            return ExchangeExecResult(
                success=True,
                gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CANCEL_ORDER],
                data={"order_id": order_id, "status": "cancelled"},
            )

        # Search across all books if pair not specified
        if pair and pair in self._order_books:
            books_to_check = [self._order_books[pair]]
        else:
            books_to_check = list(self._order_books.values())

        for book in books_to_check:
            try:
                with self._atomic(book):
                    result = book.cancel_order(order_id, caller=tx.sender)
                    if result is not None:
                        self._refund_escrow(book, result, Decimal(str(result.remaining)))
                        self._drop_empty_bracket(str(order_id))
            except ValueError as e:
                return ExchangeExecResult(success=False, error=str(e))
            if result is not None:
                return ExchangeExecResult(
                    success=True,
                    gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CANCEL_ORDER],
                    data={"order_id": order_id, "status": "cancelled"},
                )

        return ExchangeExecResult(success=False, error=f"Order {order_id} not found")

    # ── spot trigger orders (qrdx/exchange/trading.py) ──────────────────────

    def _place_spot_trigger(
        self, tx: ExchangeTransaction, pair: str, book: OrderBook, side: OrderSide, kind: str
    ) -> ExchangeExecResult:
        """PLACE_ORDER of a stop_loss / take_profit / oco: a spot trigger, its funds escrowed
        now. ``trigger_price`` (or ``stop_price``) and ``price`` (its limit; none: a market
        order) — an oco's stop leg; an oco's take-profit leg: ``tp_price``, ``tp_limit``.
        ``tif`` gtc or ioc; ``max_makers``: the matching it prepays."""
        p = tx.params
        try:
            makers = _trigger_makers(p.get("max_makers"))
            gas = EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER] + makers * EXCHANGE_GAS_PER_MAKER
            if gas > tx.gas_limit:
                raise ValueError(
                    f"gas limit {tx.gas_limit} does not cover the trigger's prepaid matching "
                    f"({gas})"
                )
            amount = Decimal(str(p["amount"]))
            if not amount.is_finite() or amount <= 0:
                raise ValueError("amount must be positive")
            if amount < book.min_order_size:
                raise ValueError(f"Order amount below minimum ({book.min_order_size})")
            legs = {
                ("sl" if kind == "oco" else kind): (
                    p.get("trigger_price", p.get("stop_price", "0")),
                    p.get("price"),
                )
            }
            if kind == "oco":
                legs["tp"] = (p.get("tp_price", "0"), p.get("tp_limit"))
            trigger = self._new_spot_trigger(
                tx.sender, pair, book, side.value, legs, amount, str(p.get("tif", "gtc")), makers
            )
            if self.enforce_orderbook_settlement:
                base, quote = pair.split(":", 1)
                self._settle_token_move(
                    tx.sender,
                    self.orderbook_escrow_address(pair),
                    quote if side == OrderSide.BUY else base,
                    trigger.escrowed,
                )
        except (ValueError, KeyError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        trigger_id = tx.tx_hash()[:16]
        self.trading.spot_triggers[trigger_id] = trigger
        return ExchangeExecResult(
            success=True, gas_used=gas, data={"order_id": trigger_id, "trigger": True}
        )

    def _new_spot_trigger(
        self,
        owner: str,
        pair: str,
        book: OrderBook,
        side: str,
        legs: Dict[str, Tuple[Any, Any]],
        amount: Decimal,
        tif: str,
        makers: int,
        parent: str = "",
    ):
        """A checked spot trigger: ``legs`` {"sl" | "tp": (trigger price, limit price or
        None)} — both: a one-cancels-the-other. Its escrow is what it may spend: ``amount`` of
        base for a sell, ``amount`` × its highest price of quote for a buy (an attached TP/SL
        starts empty: ``amount`` 0, filled by its order's fills). Refused if the pair's last
        price has already reached a leg."""
        from dataclasses import replace

        from .trading import SPOT_TRIGGERS_PER_ACCOUNT

        parsed = {}
        for leg, (trigger, limit) in legs.items():
            trigger, limit = Decimal(str(trigger or "0")), Decimal(str(limit or "0"))
            if not trigger.is_finite() or trigger <= 0:
                raise ValueError(f"the {leg} trigger price must be positive")
            if not limit.is_finite() or limit < 0:
                raise ValueError(f"the {leg} limit price must be positive (or none: market)")
            parsed[leg] = (trigger, limit)
        kind = "oco" if len(parsed) == 2 else next(iter(parsed))
        stop = parsed["sl"] if "sl" in parsed else parsed["tp"]
        tp = parsed.get("tp", (ZERO, ZERO)) if kind == "oco" else (ZERO, ZERO)
        tif = str(tif).lower()
        if tif not in ("gtc", "ioc"):
            raise ValueError("a trigger order fires as gtc or ioc")
        if len(self.trading.owned(owner, pair)) >= SPOT_TRIGGERS_PER_ACCOUNT:
            raise ValueError(f"at most {SPOT_TRIGGERS_PER_ACCOUNT} trigger orders per pair")
        trigger = self.trading.new_spot_trigger(
            owner=owner,
            pair=pair,
            side=side,
            kind=kind,
            trigger_price=stop[0],
            amount=amount,
            limit_price=stop[1],
            tif=tif,
            max_makers=makers,
            escrowed=ZERO,
            tp_price=tp[0],
            tp_limit=tp[1],
            parent=parent,
        )
        last = book.last_price
        if last and trigger.crossed(Decimal(str(last))):
            raise ValueError(f"the last price ({last}) has already reached a trigger price")
        return replace(trigger, escrowed=amount * trigger.price if side == "buy" else amount)

    def _cancel_spot_trigger(self, owner: str, trigger_id: str) -> bool:
        """Cancel ``owner``'s spot trigger and hand back its escrow; False if there is none."""
        t = self.trading.spot_triggers.peek(trigger_id)
        if t is None or t.owner != owner:
            return False
        del self.trading.spot_triggers[trigger_id]
        self._refund_trigger(t, t.escrowed)
        return True

    def _refund_trigger(self, t, amount: Decimal) -> None:
        if self.enforce_orderbook_settlement and amount > ZERO:
            base, quote = t.pair.split(":", 1)
            self._settle_token_move(
                self.orderbook_escrow_address(t.pair),
                t.owner,
                quote if t.side == "buy" else base,
                amount,
                covered=True,
            )

    @_pinned
    def fire_spot_triggers(self, now: Decimal) -> List[Dict[str, Any]]:
        """The block's tick for spot triggers: those the pairs' last prices reached fire, the
        price passed furthest first, then the first placed, within the block's limits. A pair
        whose token is paused fires nothing (its triggers wait)."""
        from .trading import SPOT_TRIGGER_FIRES_PER_BLOCK, SPOT_TRIGGER_MAKERS_PER_BLOCK

        if not len(self.trading.spot_triggers):
            return []
        queue = []
        for pair in sorted(self._order_books):
            last = self._order_books[pair].last_price
            if not last or any(
                (t := self.tokens.get(tok)) is not None and t.paused for tok in pair.split(":", 1)
            ):
                continue
            last = Decimal(str(last))
            for tid in self.trading.crossed(pair, last):
                t = self.trading.spot_triggers.peek(tid)
                leg = t.crossed_leg(last)
                if leg is None or t.amount <= 0:  # (an attached TP/SL before its order fills)
                    continue
                passed = abs(last - leg[1]) / last
                queue.append(((-passed, t.seq, tid), pair, tid))
        queue.sort()
        events: List[Dict[str, Any]] = []
        fired = makers = 0
        for _key, pair, tid in queue:
            t = self.trading.spot_triggers.peek(tid)
            if t is None:
                continue
            if (
                fired >= SPOT_TRIGGER_FIRES_PER_BLOCK
                or makers + t.max_makers > SPOT_TRIGGER_MAKERS_PER_BLOCK
            ):
                break
            fired += 1
            makers += t.max_makers
            events.append(self._fire_spot_trigger(pair, tid, t))
        return events

    def _fire_spot_trigger(self, pair: str, tid: str, t) -> Dict[str, Any]:
        """Place a reached trigger's order for its owner, settled out of its escrow; it is gone
        either way, and what it did not use goes back to its owner."""
        book = self._order_books[pair]
        base, quote = pair.split(":", 1)
        escrow = self.orderbook_escrow_address(pair)
        buy = t.side == "buy"
        event: Dict[str, Any] = {"pair": pair, "trigger_id": tid, "owner": t.owner}
        leg = t.crossed_leg(Decimal(str(book.last_price))) or t.legs()[0]
        price = t.leg_price(leg[1], leg[2])
        order = Order(
            id=tid,
            owner=t.owner,
            side=OrderSide.BUY if buy else OrderSide.SELL,
            order_type=OrderType.LIMIT,
            price=price,
            amount=t.amount,
            nonce=0,
            timestamp=0.0,
            tif=t.tif if leg[2] > 0 else "ioc",
        )
        try:
            with undo.atomic():
                del self.trading.spot_triggers[tid]
                trades = book.place_order(order, protocol=True, budget=MatchBudget(t.max_makers))
                used = ZERO
                settle = self.enforce_orderbook_settlement
                for tr in trades:
                    f = Decimal(str(tr.amount))
                    notional = f * Decimal(str(tr.price))
                    if settle:  # both sides out of escrow: the maker's order, this trigger's
                        bracket = self._bracket_for(tr, t.owner)
                        received = self._settle_spot_trade(
                            tr,
                            base,
                            quote,
                            t.owner,
                            escrow,
                            escrow,
                            covered=True,
                            base_to=escrow if bracket else None,
                        )
                        if bracket:
                            self._fill_bracket(bracket, received)
                    used += notional if buy else f
                if settle:
                    self._record_spot_volume(trades, quote)
                if order.is_active:  # resting: it keeps what its remainder escrows
                    used += order.remaining * order.price if buy else order.remaining
                self._refund_trigger(t, t.escrowed - used)
        except Exception as e:  # noqa: BLE001 — deterministic on every node; never fails the block
            if not isinstance(e, (ValueError, ArithmeticError)):
                logger.error("spot trigger %s failed unexpectedly: %r", tid, e)
            try:
                with undo.atomic():
                    del self.trading.spot_triggers[tid]
                    self._refund_trigger(t, t.escrowed)
            except Exception:  # noqa: BLE001 — it waits (a paused or frozen token)
                return {"type": "spot_trigger_waiting", **event, "reason": str(e)}
            return {"type": "spot_trigger_cancelled", **event, "reason": str(e)}
        return {
            "type": "spot_trigger_fired",
            **event,
            "side": t.side,
            "kind": leg[0],
            "amount": str(t.amount),
            "price": str(price),
            "fills": self._clob_fills(pair, trades, t.owner, t.side),
            "resting": order.is_active,
        }

    # ── acting for an account (qrdx/exchange/trading.py) ───────────────────

    def _op_agent_approve(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Approve ``agent`` (a PQ address) to sign trading operations for the account until
        ``valid_until`` (block time; 0 or absent: until revoked); ``name`` labels it.
        Approving it again replaces its approval. Only the account itself may approve."""
        import re

        from .trading import AGENTS_PER_ACCOUNT, NAME_MAX, AgentGrant

        p = tx.params
        agent = str(p["agent"])
        try:
            if not self._signed_by_account(tx):
                raise ValueError("only the account itself approves agents")
            if self.trading.master_of(tx.sender) is not None:
                raise ValueError("a sub-account's agents are its master's")
            if not re.fullmatch(r"0x[Pp][Qq][0-9a-fA-F]{64}", agent):
                raise ValueError("an agent is a post-quantum (0xPQ…) address")
            if agent.lower() == tx.sender.lower():
                raise ValueError("an account does not approve itself")
            valid_until = Decimal(str(p.get("valid_until", 0) or 0))
            if not valid_until.is_finite() or valid_until < 0:
                raise ValueError("valid_until is a block time (0: until revoked)")
            if 0 < valid_until <= Decimal(str(self._block_clock())):
                raise ValueError("valid_until has already passed")
            name = str(p.get("name", ""))
            if len(name) > NAME_MAX:
                raise ValueError(f"a name is at most {NAME_MAX} characters")
            limit = Decimal(str(p.get("max_notional_per_day", 0) or 0))
            if not limit.is_finite() or limit < 0:
                raise ValueError("max_notional_per_day is an amount (0: no limit)")
        except (ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        grants = [g for g in self.trading.agents.peek(tx.sender, ()) if g.agent != agent]
        if len(grants) >= AGENTS_PER_ACCOUNT:
            return ExchangeExecResult(
                success=False, error=f"at most {AGENTS_PER_ACCOUNT} agents per account"
            )
        grant = AgentGrant(
            agent=agent, valid_until=valid_until, name=name, max_notional_per_day=limit
        )
        self.trading.agents[tx.sender] = tuple(sorted(grants + [grant], key=lambda g: g.agent))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.AGENT_APPROVE],
            data={
                "agent": agent,
                "valid_until": str(grant.valid_until),
                "max_notional_per_day": str(limit),
            },
        )

    def _op_agent_revoke(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Revoke an agent: it signs nothing more for the account. (An agent may revoke itself.)"""
        agent = str(tx.params["agent"])
        grants = self.trading.agents.peek(tx.sender, ())
        if not any(g.agent == agent for g in grants) or tx.signer not in ("", agent):
            return ExchangeExecResult(success=False, error=f"{agent[:16]}… is not an agent here")
        kept = tuple(g for g in grants if g.agent != agent)
        if kept:
            self.trading.agents[tx.sender] = kept
        else:
            del self.trading.agents[tx.sender]
        self.trading.forget_spend(tx.sender, agent)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.AGENT_REVOKE],
            data={"agent": agent, "status": "revoked"},
        )

    def _op_subaccount_create(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A new sub-account: its own balances, margin account and orders, at an address no key
        controls — the master signs for it (``signer``). Returns its address."""
        from .trading import NAME_MAX, SUBACCOUNTS_PER_ACCOUNT, SubAccount, subaccount_address

        name = str(tx.params.get("name", ""))
        if not self._signed_by_account(tx):
            return ExchangeExecResult(success=False, error="only the account itself creates one")
        if self.trading.master_of(tx.sender) is not None:
            return ExchangeExecResult(success=False, error="a sub-account has no sub-accounts")
        if len(name) > NAME_MAX:
            return ExchangeExecResult(
                success=False, error=f"a name is at most {NAME_MAX} characters"
            )
        index = int(self.trading.subaccount_counts.peek(tx.sender, 0))
        if index >= SUBACCOUNTS_PER_ACCOUNT:
            return ExchangeExecResult(
                success=False, error=f"at most {SUBACCOUNTS_PER_ACCOUNT} sub-accounts"
            )
        address = subaccount_address(tx.sender, index)
        self.trading.subaccounts[address] = SubAccount(master=tx.sender, index=index, name=name)
        self.trading.subaccount_counts[tx.sender] = index + 1
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.SUBACCOUNT_CREATE],
            data={"subaccount": address, "index": index},
        )

    def _op_subaccount_transfer(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Move ``amount`` of ``asset`` (QRDX or a token) between the master (the sender) and
        one of its sub-accounts: ``direction`` "to_sub" or "from_sub"."""
        p = tx.params
        sub = str(p["subaccount"])
        if not self._signed_by_account(tx) or self.trading.master_of(sub) != tx.sender:
            return ExchangeExecResult(success=False, error=f"{sub[:16]}… is not a sub-account here")
        direction = str(p["direction"])
        if direction not in ("to_sub", "from_sub"):
            return ExchangeExecResult(success=False, error="direction is to_sub or from_sub")
        try:
            amount = Decimal(str(p["amount"]))
            if not amount.is_finite() or amount <= 0:
                raise ValueError("amount must be positive")
            asset = self.canonical_asset(p["asset"])
            frm, to = (tx.sender, sub) if direction == "to_sub" else (sub, tx.sender)
            avail = self.available_token_balance(frm, asset)
            if avail is None or avail < amount:
                raise ValueError(f"insufficient {p['asset']}: need {amount}, available {avail}")
            self._settle_token_move(frm, to, asset, amount)
        except (ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.SUBACCOUNT_TRANSFER],
            data={"subaccount": sub, "asset": asset, "amount": str(amount)},
        )

    # ── TWAP orders (qrdx/exchange/trading.py) ──────────────────────────────

    def _op_twap_order(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A TWAP: ``duration`` seconds, in ``slices`` (default: one every TWAP_MIN_INTERVAL
        seconds, at most TWAP_MAX_SLICES), each within ``max_slippage``. Perps: ``market_id``,
        ``side``, ``size``, ``reduce_only``. Spot: ``token_in``, ``token_out``, ``amount_in`` —
        escrowed now, swapped slice by slice. Gas: the base, and each slice's work and its
        ``max_makers`` of matching, up front. The first slice runs in this block's tick."""
        from dataclasses import replace

        from .trading import (
            TWAP_DEFAULT_MAKERS,
            TWAP_DEFAULT_SLIPPAGE,
            TWAP_MAX_DURATION,
            TWAP_MAX_MAKERS,
            TWAP_MAX_SLICES,
            TWAP_MAX_SLIPPAGE,
            TWAP_MIN_DURATION,
            TWAP_MIN_INTERVAL,
            TWAP_SLICE_GAS,
            TWAPS_PER_ACCOUNT,
            Twap,
        )

        p = tx.params
        try:
            duration, slices, makers = (
                p["duration"],
                p.get("slices", min(TWAP_MAX_SLICES, int(p["duration"]) // TWAP_MIN_INTERVAL)),
                p.get("max_makers", TWAP_DEFAULT_MAKERS),
            )
            for name, value in (("duration", duration), ("slices", slices), ("makers", makers)):
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError(f"{name} must be a whole number")
            if not TWAP_MIN_DURATION <= duration <= TWAP_MAX_DURATION:
                raise ValueError(
                    f"duration must be {TWAP_MIN_DURATION} to {TWAP_MAX_DURATION} seconds"
                )
            if not 1 <= slices <= TWAP_MAX_SLICES or duration < slices * TWAP_MIN_INTERVAL:
                raise ValueError(
                    f"slices must be 1 to {TWAP_MAX_SLICES}, at least {TWAP_MIN_INTERVAL} s apart"
                )
            if not 1 <= makers <= TWAP_MAX_MAKERS:
                raise ValueError(f"max_makers must be 1 to {TWAP_MAX_MAKERS}")
            slippage = Decimal(str(p.get("max_slippage", TWAP_DEFAULT_SLIPPAGE)))
            if not slippage.is_finite() or not ZERO < slippage <= TWAP_MAX_SLIPPAGE:
                raise ValueError(f"max_slippage must be above 0 and at most {TWAP_MAX_SLIPPAGE}")
            gas = EXCHANGE_GAS_COSTS[ExchangeOpType.TWAP_ORDER] + slices * (
                TWAP_SLICE_GAS + makers * EXCHANGE_GAS_PER_MAKER
            )
            if gas > tx.gas_limit:
                raise ValueError(f"a TWAP of {slices} slices needs {gas} gas")
            if len(self.trading.twaps_of(tx.sender)) >= TWAPS_PER_ACCOUNT:
                raise ValueError(f"at most {TWAPS_PER_ACCOUNT} TWAPs per account")
            perp = "market_id" in p
            if perp:
                market = str(p["market_id"])
                if market not in self.clearinghouse.markets:
                    raise ValueError(f"market {market} not found")
                if self.clearinghouse.markets[market].settled_price > 0:
                    raise ValueError(f"{market} is delisted")
                side = str(p["side"]).lower()
                side = {"long": "buy", "bid": "buy", "short": "sell", "ask": "sell"}.get(side, side)
                if side not in ("buy", "sell"):
                    raise ValueError(f"unknown side {p['side']!r}")
                total = Decimal(str(p["size"]))
                token_in = token_out = ""
                self._trade_leverage(tx.sender, market, p)  # its slices trade at it
            else:
                token_in = self.canonical_asset(p["token_in"])
                token_out = self.canonical_asset(p["token_out"])
                if token_in == token_out:
                    raise ValueError("token_in and token_out are the same")
                market = self._canonical_pair(f"{token_in}:{token_out}")
                if market not in self._order_books and not self.pool_manager.get_pools_for_pair(
                    token_in, token_out
                ):
                    raise ValueError(f"no market for {market}")
                side = "sell" if token_in == market.split(":", 1)[0] else "buy"
                total = Decimal(str(p["amount_in"]))
            if not total.is_finite() or total <= 0:
                raise ValueError("the size must be positive")
            twap = Twap(
                owner=tx.sender,
                market=market,
                perp=perp,
                side=side,
                token_in=token_in,
                token_out=token_out,
                total=total,
                done=ZERO,
                received=ZERO,
                slices=slices,
                slices_done=0,
                interval=Decimal(duration) / slices,
                next_time=Decimal(str(self._block_clock())),
                reduce_only=_flag(p, "reduce_only") if perp else False,
                max_slippage=slippage,
                max_makers=makers,
                seq=0,
            )
            if not perp:  # what it will spend, escrowed for the tick to swap
                self._settle_token_move(
                    tx.sender, self.orderbook_escrow_address(market), token_in, total
                )
        except (ValueError, KeyError, TypeError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        twap_id = tx.tx_hash()[:16]
        self.trading.twaps[twap_id] = replace(twap, seq=self.trading.next_seq())
        return ExchangeExecResult(success=True, gas_used=gas, data={"twap_id": twap_id})

    def _op_twap_cancel(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        if not self._cancel_twap(tx.sender, str(tx.params["twap_id"])):
            return ExchangeExecResult(success=False, error=f"no TWAP {tx.params['twap_id']}")
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TWAP_CANCEL],
            data={"twap_id": tx.params["twap_id"], "status": "cancelled"},
        )

    def _cancel_twap(self, owner: str, twap_id: str) -> bool:
        """Stop ``owner``'s TWAP; a spot TWAP's unspent escrow goes back (covered by the TWAP's
        own record of it). False if there is none."""
        t = self.trading.twaps.peek(twap_id)
        if t is None or t.owner != owner:
            return False
        del self.trading.twaps[twap_id]
        if not t.perp and t.remaining > 0:
            self._settle_token_move(
                self.orderbook_escrow_address(t.market),
                t.owner,
                t.token_in,
                t.remaining,
                covered=True,
            )
        return True

    @_pinned
    def run_twaps(self, now: Decimal, liquidations: Iterable[Dict[str, Any]] = ()) -> List[dict]:
        """The block's tick for TWAPs: an account just liquidated loses its perp TWAPs in those
        markets; then each TWAP whose slice is due runs one, the longest due first, within the
        block's limits."""
        from .trading import TWAP_MAKERS_PER_BLOCK, TWAP_SLICES_PER_BLOCK

        if not len(self.trading.twaps):
            return []
        events: List[dict] = []
        for ev in liquidations:
            if ev.get("type") != "liquidation":
                continue
            for tid in self.trading.twaps_of(ev["owner"]):
                t = self.trading.twaps.peek(tid)
                if t.perp and t.market in ev.get("markets", ()):
                    self._cancel_twap(t.owner, tid)
                    events.append(
                        {"type": "twap_finished", **self._twap_view(tid, t), "reason": "liquidated"}
                    )
        ran = makers = 0
        for tid in self.trading.due_twaps(now):
            t = self.trading.twaps.peek(tid)
            if ran >= TWAP_SLICES_PER_BLOCK or makers + t.max_makers > TWAP_MAKERS_PER_BLOCK:
                break
            ran += 1
            makers += t.max_makers
            events += self._twap_slice(tid, t)
        return events

    @staticmethod
    def _twap_view(tid: str, t) -> Dict[str, Any]:
        return {
            "twap_id": tid,
            "owner": t.owner,
            "market": t.market,
            "side": t.side,
            "total": str(t.total),
            "done": str(t.done),
            "received": str(t.received),
            "slices": t.slices,
            "slices_done": t.slices_done,
        }

    def _twap_slice(self, tid: str, t) -> List[dict]:
        """Run one slice — an IOC of the slice's size within the TWAP's slippage of the price
        now — and move the TWAP on; the last slice (or one that finds nothing left to do)
        finishes it. Never fails the block: a slice that cannot run fills nothing."""
        from dataclasses import replace

        size = t.slice_size()
        filled = got = ZERO
        fills: List[dict] = []
        reason = ""
        try:
            if t.perp:
                filled, got, fills, reason = self._perp_twap_slice(tid, t, size)
            else:
                filled, got, fills, reason = self._spot_twap_slice(t, size)
        except Exception as e:  # noqa: BLE001 — deterministic on every node; never fails the block
            if not isinstance(e, (ValueError, ArithmeticError)):
                logger.error("TWAP %s slice failed unexpectedly: %r", tid, e)
            filled, got, fills, reason = ZERO, ZERO, [], str(e)
        moved = replace(
            t,
            done=t.done + filled,
            received=t.received + got,
            slices_done=t.slices_done + 1,
            next_time=t.next_time + t.interval,
        )
        events = [
            {
                "type": "twap_slice",
                **self._twap_view(tid, moved),
                "filled": str(filled),
                "fills": fills,
                **({"reason": reason} if reason else {}),
            }
        ]
        finished = moved.slices_done >= moved.slices or moved.remaining <= 0
        if reason == "no position to reduce":
            finished = True
        self.trading.twaps[tid] = moved
        if finished:
            try:
                with undo.atomic():
                    self._cancel_twap(moved.owner, tid)
            except Exception as e:  # noqa: BLE001 — a paused token: it finishes once it can
                events.append(
                    {"type": "twap_waiting", **self._twap_view(tid, moved), "reason": str(e)}
                )
            else:
                events.append({"type": "twap_finished", **self._twap_view(tid, moved)})
        return events

    def _perp_twap_slice(self, tid: str, t, size: Decimal):
        from .clearinghouse import ENTRY_QUANTUM

        m = self.clearinghouse.markets.get(t.market)
        if m is None or m.mark_price <= 0:
            return ZERO, ZERO, [], "the market has no price"
        if not t.reduce_only and self._perp_oracle_stale(m):
            return ZERO, ZERO, [], "the oracle is stale"
        buy = t.side == "buy"
        if t.reduce_only:
            acct = self.clearinghouse.accounts.peek(t.owner)
            pos = acct.positions.get(t.market) if acct is not None else None
            held = pos.size if pos is not None else ZERO
            if held == 0 or (held > 0) == buy:
                return ZERO, ZERO, [], "no position to reduce"
            size = min(size, abs(held))
        price = (m.mark_price * (1 + t.max_slippage if buy else 1 - t.max_slippage)).quantize(
            ENTRY_QUANTUM, rounding=ROUND_FLOOR if buy else ROUND_CEILING
        )
        fills, _cancelled = self.clearinghouse.protocol_ioc(
            t.owner,
            t.market,
            f"{tid}.{t.slices_done}",
            t.side,
            size,
            price,
            reduce_only=t.reduce_only,
            max_makers=t.max_makers,
        )
        filled = sum((Decimal(f["amount"]) for f in fills), ZERO)
        notional = sum((Decimal(f["amount"]) * Decimal(f["price"]) for f in fills), ZERO)
        return filled, notional, fills, ""

    def _spot_twap_slice(self, t, size: Decimal):
        """A swap of ``size`` out of the TWAP's escrow, through the best venue, refused if its
        price is more than ``max_slippage`` worse than the marginal price (a thousandth of the
        slice's quote)."""
        route = self.router.best_route(
            t.token_in, t.token_out, size, t.owner, max_makers=t.max_makers
        )
        probe = self.router.best_route(t.token_in, t.token_out, size / 1000, t.owner)
        if route is None or probe is None or probe.amount_in <= 0:
            return ZERO, ZERO, [], "no liquidity"
        marginal = probe.amount_out / probe.amount_in
        if route.amount_out < route.amount_in * marginal * (1 - t.max_slippage):
            return ZERO, ZERO, [], "beyond its slippage"
        _visited, fills = self._swap_hop(
            t.owner, route, payer=self.orderbook_escrow_address(t.market)
        )
        return route.amount_in, route.amount_out, fills, ""

    def _refund_escrow(
        self, book: OrderBook, order: Order, amount: Decimal, covered: bool = False
    ) -> None:
        """Phase E CLOB: hand back what ``amount`` of a spot order locked in its book's escrow
        (``amount`` × price of the quote token for a buy, ``amount`` of the base for a sell —
        what it escrowed at placement)."""
        if not self.enforce_orderbook_settlement or amount <= ZERO:
            return
        pair = getattr(book, "pool_id", "") or ""
        base, quote = (pair.split(":", 1) + [""])[:2] if ":" in pair else (pair, "")
        escrow = self.orderbook_escrow_address(pair)
        if order.side == OrderSide.BUY:
            self._settle_token_move(
                escrow, order.owner, quote, amount * Decimal(str(order.price)), covered=covered
            )
        else:
            self._settle_token_move(escrow, order.owner, base, amount, covered=covered)

    def _op_modify_order(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Change a resting spot order in one step: what is left of it (``amount``) and its
        ``price``. A smaller amount at the same price keeps its place in the queue and hands
        back the escrow it no longer needs; any other change cancels it (refunding its escrow)
        and places the new order (escrowing again) — all or nothing."""
        p = tx.params
        pair = self._canonical_pair(p["pair"])
        book = self._order_books.get(pair)
        order = book._orders.get(str(p["order_id"])) if book is not None else None
        if (
            book is None
            or order is None
            or not order.is_active
            or order.owner != tx.sender
            or order.order_type != OrderType.LIMIT
        ):
            return ExchangeExecResult(
                success=False, error=f"no resting limit order {p['order_id']}"
            )
        amount = Decimal(str(p.get("amount", order.remaining)))
        price = Decimal(str(p.get("price", order.price)))
        if amount <= 0 or price <= 0:
            return ExchangeExecResult(success=False, error="amount and price must be positive")
        if price == order.price and amount < order.remaining:
            freed = order.remaining - amount
            try:
                book.reduce_order(order.id, order.filled + amount, caller=tx.sender)
                self._refund_escrow(book, order, freed)
            except ValueError as e:
                return ExchangeExecResult(success=False, error=str(e))
            return ExchangeExecResult(
                success=True,
                gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.MODIFY_ORDER],
                data={"order_id": order.id, "trades": 0, "filled": "0", "fills": []},
            )
        try:
            cancelled = book.cancel_order(order.id, caller=tx.sender)
            self._refund_escrow(book, cancelled, Decimal(str(cancelled.remaining)))
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))
        replacement_tx = _BatchAction(
            tx.tx_hash(),
            0,
            op_type=ExchangeOpType.PLACE_ORDER,
            sender=tx.sender,
            nonce=0,
            params={},
            gas_limit=tx.gas_limit
            - EXCHANGE_GAS_COSTS[ExchangeOpType.MODIFY_ORDER]
            + EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER],
            gas_price=tx.gas_price,
            chain_id=tx.chain_id,
            timestamp=tx.timestamp,
        )
        bracket = self.trading.bracket_of(order.id) if len(self.trading.spot_triggers) else None
        if bracket:  # its attached TP/SL follows it to the replacement
            from dataclasses import replace as _replace

            t = self.trading.spot_triggers.peek(bracket)
            self.trading.spot_triggers[bracket] = _replace(t, parent=replacement_tx.tx_hash()[:16])
        replacement = {
            "pair": pair,
            "side": order.side.value,
            "order_type": "limit",
            "price": str(price),
            "amount": str(amount),
            "tif": "alo" if order.tif == "alo" else "gtc",
            "hidden": order.hidden,
        }
        if order.is_iceberg and order.display_size < amount:
            replacement["display_size"] = str(order.display_size)
        replacement_tx.params = replacement
        placed = self._op_place_order(replacement_tx)
        placed.gas_used += (
            EXCHANGE_GAS_COSTS[ExchangeOpType.MODIFY_ORDER]
            - EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER]
        )
        return placed

    def _op_create_market(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Create a perp market — an order book in the clearinghouse (consensus path).

        Maintenance margin is half the initial margin at ``max_leverage``; the old
        ``initial_margin_rate`` / ``maintenance_margin_rate`` params are no longer read.
        A duplicate market is a non-critical failure, not a block-breaking error. With the fee
        gate on, the creator burns PERP_MARKET_LISTING_FEE QRDX: a market costs every node work
        in every block, so listing one must not be nearly free.

        ``liquidity`` (at least PERP_MARKET_MIN_LIQUIDITY of the creator's perps collateral)
        seeds the market's liquidity vault, which the protocol quotes on its book from its first
        tick with a price (``Clearinghouse._quote``); ``liquidity_profit_share`` (default 10 %)
        is the creator's cut of others' gains in it. The creator's shares are locked for
        PERP_MARKET_LIQUIDITY_LOCKUP_SECONDS.
        """
        from .. import constants
        from .clearinghouse import USER_VAULT_DEFAULT_PROFIT_SHARE, market_maker_address

        p = tx.params
        base = str(p["base_token"])
        quote = str(p.get("quote_token", constants.PERP_QUOTE))
        deployer, fee_share, oracle_price = "", ZERO, ZERO
        try:
            liquidity = Decimal(str(p.get("liquidity", "0")))
            if not liquidity.is_finite() or liquidity < 0:
                raise ValueError("liquidity must be a positive amount")
            if ":" not in base and not constants.PERP_OPEN_LISTING:
                # Whoever lists a validator-priced market chooses its settings (its maximum
                # leverage, its grid) and takes its name for good: governance lists them.
                raise ValueError(
                    "a validator-priced market is listed by governance (list_market); a "
                    "bonded deployer lists its own as dex:ASSET"
                )
            if ":" in base:
                # A deployer market (docs/HYPERLIQUID_PARITY.md): ``dex:ASSET``, listed only by
                # that namespace's bonded deployer, which runs its oracle. (The namespace keeps
                # deployers' markets apart from the validator-priced ones.)
                dex, _, asset = base.partition(":")
                d = self.trading.deployers.peek(tx.sender)
                if d is None or d.dex != dex or not asset or ":" in asset:
                    raise ValueError(
                        f"a market named {base} is listed by the deployer of the namespace {dex}"
                    )
                if d.bond < constants.DEPLOYER_MIN_BOND:
                    raise ValueError(
                        f"a deployer lists markets with {constants.DEPLOYER_MIN_BOND} QRDX bonded"
                    )
                if len(self.deployer_markets(tx.sender)) >= constants.DEPLOYER_MAX_MARKETS:
                    raise ValueError(
                        f"a deployer runs at most {constants.DEPLOYER_MAX_MARKETS} markets"
                    )
                bps = p.get("fee_share_bps", 0)
                cap = min(int(constants.DEPLOYER_MAX_FEE_SHARE_BPS), 10_000)
                if isinstance(bps, bool) or not isinstance(bps, int) or not 0 <= bps <= cap:
                    raise ValueError(f"fee_share_bps is 0 to {cap}")
                oracle_price = Decimal(str(p.get("oracle_price", "0")))
                if not oracle_price.is_finite() or oracle_price <= 0:
                    raise ValueError("a deployer market starts at its deployer's oracle_price")
                deployer, fee_share = tx.sender, Decimal(bps) / 10_000
        except (ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        if liquidity < constants.PERP_MARKET_MIN_LIQUIDITY:
            return ExchangeExecResult(
                success=False,
                error=f"a market is listed with at least {constants.PERP_MARKET_MIN_LIQUIDITY} "
                "of liquidity (perps collateral) for its book",
            )
        fee = Decimal(constants.PERP_MARKET_LISTING_FEE) if self.enforce_fees else ZERO
        if fee > 0:
            avail = self.available_balance(tx.sender)  # less this transaction's gas reservation
            if avail is None or avail < fee:
                return ExchangeExecResult(
                    success=False,
                    error=f"insufficient QRDX for the market listing fee: need {fee}, "
                    f"available {avail}",
                )
        try:
            # The order grid: sizes in ``sz_decimals`` decimals (docs/HYPERLIQUID_PARITY.md).
            sz = p.get("sz_decimals", constants.PERP_DEFAULT_SZ_DECIMALS)
            if isinstance(sz, bool) or not isinstance(sz, int):
                raise ValueError("sz_decimals is a whole number")
            extra: Dict[str, Any] = {}
            if "max_leverage" in p:
                extra["max_leverage"] = Decimal(str(p["max_leverage"]))
            market = self.clearinghouse.create_market(
                base,
                quote,
                sz_decimals=sz,
                deployer=deployer,
                deployer_fee_share=fee_share,
                **extra,
            )
            if deployer:
                self.clearinghouse.set_oracle_price(market.id, oracle_price, self._block_clock())
        except (ClearinghouseError, ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        data: Dict[str, Any] = {"market_id": market.id}
        if deployer:
            data["deployer"] = deployer
        if liquidity > 0:
            vault = market_maker_address(market.id)
            try:
                self.clearinghouse.create_user_vault(
                    tx.sender,
                    vault,
                    f"{market.id} liquidity",
                    liquidity,
                    Decimal(str(p.get("liquidity_profit_share", USER_VAULT_DEFAULT_PROFIT_SHARE))),
                    self._block_clock(),
                    managed=market.id,
                    lockup=constants.PERP_MARKET_LIQUIDITY_LOCKUP_SECONDS,
                )
            except (ClearinghouseError, ValueError, ArithmeticError) as e:
                return ExchangeExecResult(success=False, error=str(e))
            data["liquidity_vault"] = vault
        if fee > 0:
            self._record_balance_delta(tx.sender, -fee)  # burned
            data["listing_fee"] = str(fee)
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CREATE_MARKET], data=data
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

    def _settle_token_move(
        self, frm: str, to: str, token: str, amount: Decimal, *, covered: bool = False
    ) -> None:
        """Phase E spot: record a token move frm→to as paired deltas (no-op for 0). Raises if
        ``frm`` — a trader, a pool's holder or a book's escrow — cannot cover it, so the
        enclosing operation fails whole (see ``_atomic``) instead of the ledger flush clamping a
        debit while its credit lands, which would mint the difference.

        ``covered``: ``frm`` is a protocol holder paying out what its own records say it holds
        — a book's escrow what an order escrowed there, a pool's holder its reserves — in the
        block's tick (a fired trigger, a TWAP slice). That record is its cover, not a balance
        loaded for the block: the tick runs on blocks for which no balance is loaded, so a check
        of one would judge the same move differently on different paths."""
        if amount and amount > ZERO:
            if not is_native_asset(token):
                if self.tokens.is_frozen(token, frm):
                    raise ValueError(f"{frm[:16]}…'s {token[:12]}… balance is frozen")
                t = self.tokens.get(token)
                if t is not None and t.paused:
                    raise ValueError(f"{t.symbol} is paused")
            avail = None if covered else self.available_token_balance(frm, token)
            if covered:
                pass
            elif avail is None:
                # Every debit's balance is loaded with its block (block_processor.
                # preload_token_balances). One that was not is a gap in that list: refuse it
                # rather than let an unchecked debit overdraw the ledger.
                if self.enforce_spot_settlement:
                    raise ValueError(
                        f"{frm[:16]}…'s {token[:12]}… balance was not loaded " "for this block"
                    )
            elif avail < amount:
                # The protocol's holders (pool reserves, book escrow, the perps clearinghouse)
                # are always held to it; a trader only once spot settlement is enforced (in
                # observe mode their overdraft is logged by the flush, not refused).
                from ..crypto.account_id import is_synthetic_holder

                if self.enforce_spot_settlement or is_synthetic_holder(frm):
                    raise ValueError(
                        f"{frm[:16]}… cannot cover {amount} of {token[:12]}… " f"(holds {avail})"
                    )
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
                address,
                tx.sender,
                self._current_block_height,
                name=p.get("name", ""),
                symbol=symbol,
                decimals=p.get("decimals", 18),
                initial_supply=p.get("initial_supply", p.get("total_supply", 0)),
                max_supply=p.get("max_supply"),
                mint_authority=p.get("mint_authority"),
                freeze_authority=p.get("freeze_authority"),
                extensions=p,
            )
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_DEPLOY: {e}")
        if token.supply > 0:
            self._record_token_delta(tx.sender, token.address, token.supply)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_DEPLOY],
            data={
                "token_address": token.address,
                "symbol": token.symbol,
                "total_supply": str(token.supply),
                "decimals": token.decimals,
                "mint_authority": token.mint_authority,
                "freeze_authority": token.freeze_authority,
                "extensions": token.extensions(),
            },
        )

    def _token_move(
        self, op: str, token: str, frm: str, to: str, value
    ) -> Tuple[Any, Decimal, Decimal]:
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
            logger.warning(
                "[Phase E observe] %s by %s: amount %s exceeds available %s — would "
                "REJECT once spot settlement is enforced",
                op,
                frm[:20],
                v,
                avail,
            )
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
            t, v, fee = self._token_move(
                "token_transfer", str(p["token_address"]), tx.sender, to, p["amount"]
            )
            self._transfer_with_fee(tx.sender, to, t, v, fee)
        except (TokenError, ValueError) as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_TRANSFER: {e}")
        data = {"token_address": t.address, "to": to, "amount": str(v)}
        if fee:
            data.update(fee=str(fee), received=str(v - fee))
        if note:
            data["memo"] = note
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_TRANSFER], data=data
        )

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
            t, v, fee = self._token_move(
                "token_transfer_from", str(p["token_address"]), owner, to, p["amount"]
            )
            via = self._spend_authority(t, owner, tx.sender, v)
            self._transfer_with_fee(owner, to, t, v, fee)
        except (TokenError, ValueError) as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_TRANSFER_FROM: {e}")
        data = {"token_address": t.address, "from": owner, "to": to, "amount": str(v), "via": via}
        if via == "allowance":
            data["allowance_left"] = str(
                self.tokens.spend_allowance(t.address, owner, tx.sender, v)
            )
        if fee:
            data.update(fee=str(fee), received=str(v - fee))
        if note:
            data["memo"] = note
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_TRANSFER_FROM], data=data
        )

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
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_MINT],
            data={
                "token_address": t.address,
                "to": to,
                "amount": str(v),
                "total_supply": str(t.supply),
            },
        )

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
                    raise TokenError(
                        "only the holder, its operators or the permanent delegate "
                        "may burn its balance"
                    )
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
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_BURN], data=data
        )

    def _op_token_approve(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Set ``spender``'s allowance over the sender's tokens to ``amount`` (0 revokes)."""
        p = tx.params
        try:
            t = self.tokens.require(str(p["token_address"]))
            v = self.tokens.approve(t.address, tx.sender, str(p["spender"]), p["amount"])
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_APPROVE: {e}")
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_APPROVE],
            data={"token_address": t.address, "spender": str(p["spender"]), "amount": str(v)},
        )

    def _op_token_set_authority(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Hand the mint or freeze authority to ``new_authority``, or renounce it (empty) —
        irreversibly."""
        p = tx.params
        try:
            t = self.tokens.require(str(p["token_address"]))
            new = self.tokens.set_authority(
                t.address, tx.sender, str(p["authority"]), p.get("new_authority")
            )
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_SET_AUTHORITY: {e}")
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_SET_AUTHORITY],
            data={
                "token_address": t.address,
                "authority": str(p["authority"]).lower(),
                "new_authority": new,
            },
        )

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
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[tx.op_type],
            data={"token_address": t.address, "account": str(p["account"]), "frozen": frozen},
        )

    def _op_token_update_metadata(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The metadata authority edits the token's name, symbol, uri and extra fields."""
        p = tx.params
        try:
            ticker = self.ticker_of(str(p.get("token_address", "")))
            if (
                ticker is not None
                and p.get("symbol") not in (None, "")
                and str(p["symbol"]).strip().upper() != ticker
            ):
                # A ticker's token keeps its symbol: renamed, it would show one asset's symbol
                # under another's ticker (docs/HYPERLIQUID_PARITY.md 11).
                raise TokenError(f"the token holds the ticker {ticker}: its symbol stays")
            t = self.tokens.update_metadata(str(p["token_address"]), tx.sender, p)
        except (TokenError, KeyError) as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_UPDATE_METADATA: {e}")
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_UPDATE_METADATA],
            data={
                "token_address": t.address,
                "name": t.name,
                "symbol": t.symbol,
                "uri": t.uri,
                "fields": dict(t.fields),
            },
        )

    def _op_token_set_transfer_fee(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The fee authority sets a new transfer-fee rate and cap, effective
        FEE_UPDATE_DELAY_BLOCKS later."""
        p = tx.params
        try:
            bps, cap, height = self.tokens.set_transfer_fee(
                str(p["token_address"]),
                tx.sender,
                self._current_block_height,
                p["transfer_fee_bps"],
                p.get("max_transfer_fee"),
            )
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_SET_TRANSFER_FEE: {e}")
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_SET_TRANSFER_FEE],
            data={
                "token_address": str(p["token_address"]).lower(),
                "transfer_fee_bps": bps,
                "max_transfer_fee": None if cap is None else str(cap),
                "from_height": height,
            },
        )

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
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_WITHDRAW_FEES],
            data={"token_address": t.address, "to": to, "amount": str(withheld)},
        )

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
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[tx.op_type],
            data={"token_address": str(p["token_address"]).lower(), "paused": paused},
        )

    def _op_token_operator(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """TOKEN_AUTHORIZE_OPERATOR / TOKEN_REVOKE_OPERATOR (ERC-777): the sender lets
        ``operator`` move (and burn) its balance of the token without an allowance — or stops
        it, a default operator included."""
        p = tx.params
        authorized = tx.op_type == ExchangeOpType.TOKEN_AUTHORIZE_OPERATOR
        try:
            self.tokens.set_operator(
                str(p["token_address"]), tx.sender, str(p["operator"]), authorized
            )
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"{tx.op_type.name}: {e}")
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[tx.op_type],
            data={
                "token_address": str(p["token_address"]).lower(),
                "operator": str(p["operator"]),
                "authorized": authorized,
            },
        )

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
        return ExchangeExecResult(success=True, gas_used=EXCHANGE_GAS_COSTS[tx.op_type], data=data)

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
            i = self.nfts.mint(
                str(p["collection"]),
                tx.sender,
                to,
                self._current_block_height,
                uri=p.get("uri", ""),
                name=p.get("name", ""),
                tid=p.get("token_id"),
            )
            return {"collection": str(p["collection"]).lower(), "token_id": str(i), "to": to}

        return self._nft(tx, go)

    def _op_nft_transfer(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Move an NFT to ``to``: by its owner, its approved account or an operator of the
        owner's (``from`` names the owner when the sender is not it)."""

        def go(p):
            note = token_memo(p.get("memo"))
            frm = str(p.get("from") or tx.sender)
            self.nfts.transfer(str(p["collection"]), p["token_id"], tx.sender, frm, str(p["to"]))
            out = {
                "collection": str(p["collection"]).lower(),
                "token_id": str(nft_token_id(p["token_id"])),
                "from": frm,
                "to": str(p["to"]),
            }
            if note:
                out["memo"] = note
            return out

        return self._nft(tx, go)

    def _op_nft_burn(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        def go(p):
            owner = self.nfts.item(str(p["collection"]), p["token_id"]).owner
            self.nfts.burn(str(p["collection"]), p["token_id"], tx.sender)
            return {
                "collection": str(p["collection"]).lower(),
                "token_id": str(nft_token_id(p["token_id"])),
                "owner": owner,
            }

        return self._nft(tx, go)

    def _op_nft_approve(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The owner (or an operator) approves one account for one NFT ("" clears it)."""

        def go(p):
            spender = self.nfts.approve(
                str(p["collection"]), p["token_id"], tx.sender, p.get("spender")
            )
            return {
                "collection": str(p["collection"]).lower(),
                "token_id": str(nft_token_id(p["token_id"])),
                "spender": spender,
            }

        return self._nft(tx, go)

    def _op_nft_set_approval_for_all(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The sender approves (``approved``, default true) or revokes an operator for all its
        NFTs in the collection."""

        def go(p):
            approved = p.get("approved", True)
            approved = (
                str(approved).lower() in ("1", "true", "yes")
                if isinstance(approved, str)
                else bool(approved)
            )
            self.nfts.set_operator(str(p["collection"]), tx.sender, str(p["operator"]), approved)
            return {
                "collection": str(p["collection"]).lower(),
                "operator": str(p["operator"]),
                "approved": approved,
            }

        return self._nft(tx, go)

    def _op_nft_update(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        return self._nft(tx, lambda p: self.nfts.update(str(p["collection"]), tx.sender, p))

    def _op_nft_set_authority(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        def go(p):
            new = self.nfts.set_authority(
                str(p["collection"]), tx.sender, str(p["authority"]), p.get("new_authority")
            )
            return {
                "collection": str(p["collection"]).lower(),
                "authority": str(p["authority"]).lower(),
                "new_authority": new,
            }

        return self._nft(tx, go)

    def token_registry_ops(self) -> List[Dict[str, Any]]:
        """The registry rows of the tokens this block deployed or changed (supply,
        authorities), for the DB mirror (``token_registry``)."""
        return [
            self.tokens.tokens[a].summary()
            for a in sorted(self.tokens.changed)
            if a in self.tokens.tokens
        ]

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
                    error=(
                        f"STAKE_DEPOSIT: stake {stake} below minimum " f"{MIN_VALIDATOR_STAKE} QRDX"
                    ),
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
                    error=(
                        f"STAKE_DEPOSIT: insufficient balance for stake: need {stake}, "
                        f"available {avail}"
                    ),
                )
        else:
            avail = self.available_balance(tx.sender)
            if avail is not None and avail < stake:
                logger.warning(
                    "[observe] stake_deposit by %s: claimed stake %s exceeds available "
                    "balance %s — would REJECT once validator stake is enforced",
                    tx.sender[:20],
                    stake,
                    avail,
                )

        self._validator_lifecycle_ops.append(
            {
                "type": "deposit",
                "address": tx.sender,
                "public_key": str(p["validator_public_key"]),
                "stake": str(stake),
            }
        )
        # (It joins the committee that weighs votes when it activates: the committee is the
        # chain-derived validator set — block_processor.ensure_oracle_committee.)

        # (3) Lock it. Gate the RECORDING, not just the flush: the shared
        # account_state flush is already enforced for collateral, so recording
        # unconditionally would debit even while this gate is off.
        if self.enforce_validator_stake:
            self._record_balance_delta(tx.sender, -stake)

        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_DEPOSIT],
            data={
                "validator": tx.sender,
                "stake": str(stake),
                "status": "pending",
                "staked_debit": str(stake) if self.enforce_validator_stake else "0",
            },
        )

    def _op_stake_exit(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The sender signals a voluntary exit: logged against the block, it moves the validator
        to exiting in the next epoch's set and out after unbonding (validator/epoch_state.py)."""
        self._validator_lifecycle_ops.append({"type": "exit", "address": tx.sender})
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_EXIT],
            data={"validator": tx.sender, "status": "exiting"},
        )

    def _op_stake_delegate(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Lock ``amount`` QRDX in ``validator``'s delegation pool (docs/STAKING.md): debited
        now, it joins the pool after a warm-up of ACTIVATION_DELAY_EPOCHS — or comes back, if
        the address is not a validator then (validator/epoch_state.py). The pool's shares earn
        the staking rate, less the validator's commission."""
        from ..constants import STAKE_MIN_DELEGATION

        p = tx.params
        try:
            amount = Decimal(str(p["amount"]))
            validator = str(p["validator"])
            token_account(validator)
        except (InvalidOperation, ValueError, TypeError, TokenError) as e:
            return ExchangeExecResult(success=False, error=f"STAKE_DELEGATE: {e}")
        if not amount.is_finite() or amount < STAKE_MIN_DELEGATION:
            return ExchangeExecResult(
                success=False, error=f"STAKE_DELEGATE: at least {STAKE_MIN_DELEGATION} QRDX"
            )
        if amount != amount.quantize(Decimal("1e-18")):
            return ExchangeExecResult(success=False, error="STAKE_DELEGATE: whole wei only")
        if self.enforce_validator_stake:
            avail = self.available_balance(tx.sender)
            if avail is None or avail < amount:
                return ExchangeExecResult(
                    success=False,
                    error=f"STAKE_DELEGATE: insufficient balance: need {amount}, "
                    f"available {avail}",
                )
            self._record_balance_delta(tx.sender, -amount)
        self._validator_lifecycle_ops.append(
            {
                "type": "delegate",
                "address": tx.sender,
                "validator": validator,
                "amount": str(amount),
            }
        )
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_DELEGATE],
            data={"validator": validator, "amount": str(amount), "status": "warming up"},
        )

    def _op_stake_undelegate(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Redeem ``shares`` (default: all, warming-up delegations included) of the sender's
        stake in ``validator``'s pool: worth the pool's price at the end of the epoch, paid
        after UNBONDING_PERIOD_EPOCHS and the withdrawal delay — slashed with the pool
        meanwhile."""
        p = tx.params
        raw = p.get("shares", "all")
        shares: Optional[str] = None
        if str(raw).lower() != "all":
            try:
                value = Decimal(str(raw))
            except InvalidOperation:
                value = Decimal(0)
            if not value.is_finite() or value <= 0:
                return ExchangeExecResult(
                    success=False, error="STAKE_UNDELEGATE: shares must be positive, or all"
                )
            shares = str(value)
        self._validator_lifecycle_ops.append(
            {
                "type": "undelegate",
                "address": tx.sender,
                "validator": str(p["validator"]),
                "shares": shares,
            }
        )
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_UNDELEGATE],
            data={"validator": str(p["validator"]), "shares": shares or "all"},
        )

    def _op_stake_set_commission(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A validator sets its commission on its pool's rewards (basis points, 0–10,000),
        from the next epoch. From an address that is not a validator it does nothing."""
        try:
            bps = int(tx.params["commission_bps"])
        except (TypeError, ValueError):
            bps = -1
        if not 0 <= bps <= 10_000:
            return ExchangeExecResult(
                success=False, error="STAKE_SET_COMMISSION: 0 to 10,000 basis points"
            )
        self._validator_lifecycle_ops.append(
            {"type": "commission", "address": tx.sender, "commission_bps": bps}
        )
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_SET_COMMISSION],
            data={"commission_bps": bps},
        )

    def validator_lifecycle_ops(self) -> List[Dict[str, Any]]:
        """This block's executed staking operations: deposits, exits, delegations."""
        return list(self._validator_lifecycle_ops)

    # =====================================================================
    #  On-chain governance (qrdx/exchange/governance.py, docs/GOVERNANCE.md)
    # =====================================================================

    def _gov(self, tx: ExchangeTransaction, fn) -> ExchangeExecResult:
        try:
            data = fn()
        except GovernanceError as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(success=True, gas_used=EXCHANGE_GAS_COSTS[tx.op_type], data=data)

    def _release_vetoes(self, refunds: Dict[str, Decimal]) -> None:
        """Return locked veto QRDX from the escrow holder to each holder."""
        escrow = veto_escrow_address()
        for holder in sorted(refunds):
            amount = refunds[holder]
            if amount > 0:
                self._record_balance_delta(escrow, -amount)
                self._record_balance_delta(holder, amount)

    def _op_gov_propose(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A validator opens a proposal; its committee's stake is snapshotted for the vote."""

        def go():
            p = self.governance.propose(
                tx.sender, tx.params, self._current_block_height, self._oracle_members()
            )
            return {
                "proposal_id": p.id,
                "action": p.action,
                "params": p.params,
                "voting_ends": p.voting_ends,
            }

        return self._gov(tx, go)

    def _op_gov_vote(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        def go():
            p = self.governance.vote(tx.sender, tx.params, self._current_block_height)
            return {
                "proposal_id": p.id,
                "status": p.status,
                "yes": str(p.yes),
                "no": str(p.no),
                "timelock_ends": p.timelock_ends,
            }

        return self._gov(tx, go)

    def _op_gov_veto(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A holder locks QRDX in the veto escrow against a passed proposal. Reaching the veto
        threshold stops the proposal and returns every holder's QRDX."""

        def go():
            p, amount, refunds = self.governance.veto(
                tx.sender, tx.params, self._current_block_height, self.available_balance(tx.sender)
            )
            self._record_balance_delta(tx.sender, -amount)
            self._record_balance_delta(veto_escrow_address(), amount)
            self._release_vetoes(refunds)
            return {
                "proposal_id": p.id,
                "status": p.status,
                "locked": str(amount),
                "veto_total": str(p.veto_total),
            }

        return self._gov(tx, go)

    def _op_gov_execute(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Anyone executes a passed proposal once its timelock has ended (or closes an expired
        one). A system_spend reads the wallet's balance pre-loaded for this transaction
        (block_processor.preload_sender_balances)."""

        def go():
            p, result, moves, refunds = self.governance.execute(
                tx.params, self._current_block_height, self.available_balance
            )
            for address, delta in moves:
                self._record_balance_delta(address, delta)
            if result.get("executed") and result.get("action") == "delist_market":
                result.update(self._delist_market(result["market_id"], result.get("price")))
            if result.get("executed") and result.get("action") == "list_market":
                result.update(self._list_market(result))
            if result.get("executed") and result.get("action") == "slash_deployer":
                result.update(
                    self._slash_deployer(result["deployer"], result["bps"], result["halt"])
                )
            self._release_vetoes(refunds)
            return {"proposal_id": p.id, "status": p.status, **result}

        return self._gov(tx, go)

    def _delist_market(self, market_id: str, price: Optional[str]) -> Dict[str, Any]:
        """A passed ``delist_market``: the clearinghouse settles the market, and its TWAPs end.
        A refusal (no such market, already delisted, no price) fails the execution, which may
        be retried within the proposal's execution window."""
        try:
            settled = self.clearinghouse.delist(
                market_id, Decimal(price) if price is not None else None
            )
        except ClearinghouseError as e:
            raise GovernanceError(str(e)) from None
        for tid, t in sorted(self.trading.twaps.peek_items()):
            if t.perp and t.market == market_id:
                self._cancel_twap(t.owner, tid)
        return settled

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
            error=(
                f"{tx.op_type.name} is retired: it traded against nobody, so it minted and "
                f"burned QRDX. Perps trade on the order book — PERP_DEPOSIT, then PERP_ORDER."
            ),
        )

    @staticmethod
    def perp_collateral_token() -> str:
        """What perps settle in: a QRC-20 token address (production: the bridged USD
        stablecoin), "QRDX" for native QRDX, or "" when none is configured."""
        from .. import constants

        return constants.PERP_COLLATERAL_TOKEN

    def _op_portfolio_asset(self, tx: ExchangeTransaction, deposit: bool) -> ExchangeExecResult:
        """PERP_DEPOSIT / PERP_WITHDRAW of a portfolio-margin token (``asset``): it moves between
        the sender and the perps holder on the ledger, and is held as margin in between."""
        asset = self.canonical_asset(tx.params["asset"])
        holder = self.perps_holder_address()
        op = ExchangeOpType.PERP_DEPOSIT if deposit else ExchangeOpType.PERP_WITHDRAW
        try:
            amount = Decimal(str(tx.params["amount"]))
            if deposit:
                if self.clearinghouse.asset_price(asset) <= 0:
                    raise ValueError(f"{asset} is not accepted as margin")
                avail = self.available_token_balance(tx.sender, asset)
                if avail is None or avail < amount:
                    raise ValueError(f"insufficient {asset}: need {amount}, available {avail}")
                held = self.clearinghouse.deposit_asset(tx.sender, asset, amount)
                self._settle_token_move(tx.sender, holder, asset, amount)
            else:
                self.clearinghouse.withdraw_asset(tx.sender, asset, amount)
                self._settle_token_move(holder, tx.sender, asset, amount)
                acct = self.clearinghouse.accounts.peek(tx.sender)
                held = acct.assets.get(asset.lower(), ZERO) if acct is not None else ZERO
        except (ClearinghouseError, ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[op], data={"asset": asset, "held": str(held)}
        )

    @_pinned
    def unwind_vault_assets(self, now: Decimal) -> List[Dict[str, Any]]:
        """The block's tick for portfolio margin: the backstop vault sells a slice of each margin
        token it took over (``Clearinghouse.unwind_assets_due``) for the settlement token
        through the best venue, out of the perps holder (covered: the clearinghouse records
        it), within its bound under the oracle — or waits for the next interval."""
        token_out = self.perp_collateral_token()
        due = self.clearinghouse.unwind_assets_due(now) if token_out else []
        events: List[Dict[str, Any]] = []
        holder = self.perps_holder_address()
        for token, part, floor in due:
            route = self.router.best_route(
                token, self.canonical_asset(token_out), part, holder, max_makers=20
            )
            if route is None or route.amount_out < floor * route.amount_in / part:
                self.clearinghouse.mark_asset_unwind(token, now)
                continue
            try:
                with undo.atomic():
                    _visited, fills = self._swap_hop(holder, route, payer=holder)
                    self.clearinghouse.record_asset_sale(
                        token, route.amount_in, route.amount_out, now
                    )
            except (
                Exception
            ) as e:  # noqa: BLE001 — deterministic on every node; never fails the block
                logger.warning("vault asset sale of %s failed: %s", token, e)
                self.clearinghouse.mark_asset_unwind(token, now)
                continue
            events.append(
                {
                    "type": "vault_asset_sale",
                    "asset": token,
                    "sold": str(route.amount_in),
                    "proceeds": str(route.amount_out),
                    "fills": fills,
                }
            )
        return events

    def _op_perp_deposit(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        if tx.params.get("asset"):
            return self._op_portfolio_asset(tx, deposit=True)
        token = self.perp_collateral_token()
        if not token:
            return ExchangeExecResult(
                success=False, error="perps have no collateral token configured"
            )
        amount = Decimal(str(tx.params["amount"]))
        native = token.upper() == "QRDX"
        if native:
            avail = self.available_balance(tx.sender)
            if avail is not None and avail < amount and self.enforce_collateral:
                return ExchangeExecResult(
                    success=False, error=f"insufficient balance: need {amount}, available {avail}"
                )
        else:
            # Always enforced: the token flush is not gated, so admitting an unaffordable
            # deposit would apply the holder's credit while the sender's debit could not land.
            avail = self.available_token_balance(tx.sender, token)
            if avail is None or avail < amount:
                return ExchangeExecResult(
                    success=False,
                    error=f"insufficient collateral token balance: need {amount}, available {avail}",
                )
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
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_DEPOSIT],
            data={"collateral": str(self.clearinghouse.accounts[tx.sender].collateral)},
        )

    def _op_perp_withdraw(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        if tx.params.get("asset"):
            return self._op_portfolio_asset(tx, deposit=False)
        token = self.perp_collateral_token()
        if not token:
            return ExchangeExecResult(
                success=False, error="perps have no collateral token configured"
            )
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
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_WITHDRAW],
            data={"collateral": str(self.clearinghouse.accounts[tx.sender].collateral)},
        )

    # ── QNS, the QRDX Name Service (qrdx/exchange/qns.py) ─────────────────────

    def qns_authority(self) -> str:
        from .qns import QNS_AUTHORITY

        return QNS_AUTHORITY

    def _qns_pay(self, payer: str, years: int, name: str = "") -> Decimal:
        """Take a name's price for ``years`` from ``payer`` for the treasury: QNS_PRICE_PER_YEAR
        a year, times the name's length factor (qns.price_factor)."""
        from .. import constants
        from .qns import price_factor

        price = Decimal(constants.QNS_PRICE_PER_YEAR) * years * price_factor(name)
        if price <= 0:
            return ZERO
        avail = self.available_balance(payer)  # less this transaction's gas reservation
        if avail is None or avail < price:
            raise ValueError(f"a name costs {price} QRDX; {payer[:16]}… has {avail}")
        self._record_balance_delta(payer, -price)
        self._record_balance_delta(constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"], price)
        return price

    @staticmethod
    def _qns_years(value: Any) -> int:
        from .qns import QNS_MAX_YEARS

        years = 1 if value is None else value
        if isinstance(years, bool) or not isinstance(years, int) or not 1 <= years <= QNS_MAX_YEARS:
            raise ValueError(f"years must be 1 to {QNS_MAX_YEARS}")
        return years

    def _op_qns_register(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Register ``name`` (label.qrdx) for ``years``: its NFT minted to the sender, resolving
        to ``target`` (default: the sender). Refused while it is taken (until its expiry's grace
        period ends — then the old NFT is burned)."""
        from .qns import (
            QNS_AUTHORITY,
            QNS_COLLECTION,
            YEAR_SECONDS,
            NameRecord,
            QnsError,
            name_token_id,
            normalize,
        )

        p = tx.params
        now = Decimal(str(self._block_clock()))
        try:
            name = normalize(p["name"])
            years = self._qns_years(p.get("years"))
            target = str(p.get("target") or tx.sender)
            from ..crypto.account_id import to_account_id

            to_account_id(target)  # (a real address)
            svc, nfts = self.qns, self.nfts
            if not svc.available(nfts, name, now):
                raise QnsError(f"{name} is registered")
            paid = self._qns_pay(tx.sender, years, name)
            if nfts.get(QNS_COLLECTION) is None:
                nfts.create(
                    QNS_COLLECTION,
                    QNS_AUTHORITY,
                    self._current_block_height,
                    {
                        "name": "QRDX Name Service",
                        "symbol": "QNS",
                        "mint_authority": QNS_AUTHORITY,
                        "update_authority": QNS_AUTHORITY,
                    },
                )
            tid = name_token_id(name)
            if nfts.items.peek((QNS_COLLECTION, tid)) is not None:  # expired: reclaimed
                nfts.set_owner(QNS_COLLECTION, tid, None)
            nfts.mint(
                QNS_COLLECTION,
                QNS_AUTHORITY,
                tx.sender,
                self._current_block_height,
                uri=f"qns://{name}",
                name=name,
                tid=tid,
            )
            record = NameRecord(expires=now + years * YEAR_SECONDS, target=target)
            svc.names[name] = record  # (a reclaimed name's old records go with it)
        except (ValueError, KeyError, NftError, TokenError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.QNS_REGISTER],
            data={
                "name": name,
                "token_id": str(tid),
                "collection": QNS_COLLECTION,
                "expires": str(record.expires),
                "paid": str(paid),
            },
        )

    def _op_qns_renew(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Extend ``name`` by ``years`` from its expiry (anyone may pay), to at most
        QNS_MAX_YEARS ahead; not once its grace period has ended."""
        from dataclasses import replace

        from .qns import QNS_GRACE_SECONDS, QNS_MAX_YEARS, YEAR_SECONDS, QnsError, normalize

        now = Decimal(str(self._block_clock()))
        try:
            name = normalize(tx.params["name"])
            years = self._qns_years(tx.params.get("years"))
            r = self.qns.record(name)
            if r is None or self.qns.owner(self.nfts, name) is None:
                raise QnsError(f"{name} is not registered")
            if now >= r.expires + QNS_GRACE_SECONDS:
                raise QnsError(f"{name} has lapsed: register it")
            expires = r.expires + years * YEAR_SECONDS
            if expires > now + QNS_MAX_YEARS * YEAR_SECONDS:
                raise QnsError(f"a name is held at most {QNS_MAX_YEARS} years ahead")
            paid = self._qns_pay(tx.sender, years, name)
            self.qns.names[name] = replace(r, expires=expires)
        except (ValueError, KeyError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.QNS_RENEW],
            data={"name": name, "expires": str(expires), "paid": str(paid)},
        )

    def _op_qns_set_record(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The name's owner (or an account it approved for the NFT, or an operator) sets
        ``key``: ``address`` (where it resolves; "" clears) or a text record ("" removes)."""
        from dataclasses import replace

        from .qns import (
            MAX_KEY_LENGTH,
            MAX_TEXT_RECORDS,
            MAX_VALUE_LENGTH,
            QNS_COLLECTION,
            QnsError,
            name_token_id,
            normalize,
        )

        p = tx.params
        now = Decimal(str(self._block_clock()))
        try:
            name = normalize(p["name"])
            r = self.qns.record(name)
            if r is None or self.qns.owner(self.nfts, name) is None or now >= r.expires:
                raise QnsError(f"{name} is not registered (or has expired)")
            if not self.nfts.may_spend(QNS_COLLECTION, name_token_id(name), tx.sender):
                raise QnsError(f"only {name}'s owner (or an account it approved) sets its records")
            key, value = str(p["key"]), str(p.get("value", ""))
            if key == "address":
                if value:
                    from ..crypto.account_id import to_account_id

                    to_account_id(value)
                updated = replace(r, target=value)
            else:
                if not 1 <= len(key) <= MAX_KEY_LENGTH or len(value) > MAX_VALUE_LENGTH:
                    raise QnsError(
                        f"a record key is 1 to {MAX_KEY_LENGTH} characters, its value at most "
                        f"{MAX_VALUE_LENGTH}"
                    )
                texts = dict(r.texts)
                if value:
                    texts[key] = value
                else:
                    texts.pop(key, None)
                if len(texts) > MAX_TEXT_RECORDS:
                    raise QnsError(f"at most {MAX_TEXT_RECORDS} text records")
                updated = replace(r, texts=tuple(sorted(texts.items())))
            self.qns.names[name] = updated
        except (ValueError, KeyError, NftError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.QNS_SET_RECORD],
            data={"name": name, "key": key, "value": value},
        )

    def _op_qns_set_primary(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The sender's reverse record: ``name`` must resolve to the sender ("" clears it)."""
        from ..crypto.account_id import to_account_id
        from .qns import QnsError, normalize

        now = Decimal(str(self._block_clock()))
        key = to_account_id(tx.sender)
        try:
            raw = str(tx.params["name"])
            if not raw:
                if key in self.qns.primary:
                    del self.qns.primary[key]
                name = ""
            else:
                name = normalize(raw)
                target = self.qns.resolve(self.nfts, name, now)
                if target is None or to_account_id(target) != key:
                    raise QnsError(f"{name} does not resolve to {tx.sender[:16]}…")
                self.qns.primary[key] = name
        except (ValueError, KeyError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.QNS_SET_PRIMARY],
            data={"primary": name or None},
        )

    # ── account control (qrdx/exchange/authority.py) ─────────────────────────

    def _op_account_policy(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Change who may sign for the sender (docs/ACCOUNT_CONTROL.md). ``action``:
        ``add_controller`` / ``remove_controller`` {controller}, ``own_key`` {enabled},
        ``delay`` {seconds}, ``cancel`` {change_id}. Signed by a controller it applies at once;
        by the account's own key it waits out the delay (lengthening it excepted)."""
        p = tx.params
        account, action = tx.sender, str(p["action"])
        auth = self.authority
        by_controller = bool(tx.signer) and auth.may_control(account, tx.signer)
        now = Decimal(str(self._block_clock()))
        try:
            if action == "publish_keyset":  # public information: anyone may record a keyset
                from ..crypto.multisig_wire import encode_keyset, keyset_of

                ks = p["keyset"]
                if not isinstance(ks, dict) or not isinstance(ks.get("public_keys"), list):
                    raise ValueError("keyset is {m, public_keys}")
                from ..crypto.pq.dilithium import PQPublicKey

                keyset = keyset_of(
                    [PQPublicKey.from_hex(h) for h in ks["public_keys"]], int(ks["m"])
                )
                address = auth.record_keyset(encode_keyset(keyset))
                return ExchangeExecResult(
                    success=True,
                    gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ACCOUNT_POLICY],
                    data={"multisig": address},
                )
            if tx.signer and not by_controller:
                raise ValueError("only the account itself or its controllers change its policy")
            if action == "cancel":
                change = auth.pending.peek(str(p["change_id"]))
                if change is None or change.account != _account_key(account):
                    raise ValueError(f"no waiting change {p['change_id']}")
                del auth.pending[str(p["change_id"])]
                return ExchangeExecResult(
                    success=True,
                    gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ACCOUNT_POLICY],
                    data={"cancelled": str(p["change_id"])},
                )
            value = _policy_value(action, p)
            current = auth.policy(account)
            changed = _apply_policy(current, action, value, account)  # (checks it)
            immediate = (
                by_controller
                or current.delay == 0
                or (action == "delay" and int(value) > current.delay)
            )
            if immediate:
                auth.set_policy(account, changed)
                data: Dict[str, Any] = {"applied": True, **_describe_policy(changed)}
            else:
                cid = auth.queue(account, action, str(value), now + current.delay, "own_key")
                data = {"applied": False, "change_id": cid, "due": str(now + current.delay)}
        except (ValueError, KeyError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ACCOUNT_POLICY], data=data
        )

    def _op_account_recover(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A guardian of ``account`` backs ``new_controller`` ("" withdraws its backing). When
        the account's threshold of guardians back the same one, the recovery is queued: after
        the account's recovery delay it binds that controller in place of all others and turns
        the own key off — unless the own key or a controller cancels it first (ACCOUNT_POLICY
        cancel)."""
        p = tx.params
        account, new = str(p["account"]), str(p.get("new_controller", ""))
        auth = self.authority
        now = Decimal(str(self._block_clock()))
        try:
            policy = auth.policy(account)
            key = _account_key(account)
            if _account_key(tx.sender) not in policy.guardian_ids():
                raise ValueError(f"{tx.sender[:16]}… is not a guardian of {account[:16]}…")
            if new:
                _apply_policy(policy, "recover", new, account)  # (checks the address)
                target = _account_key(new)
                for _cid, c in auth.pending_of(account):
                    if c.action == "recover" and _account_key(c.value) == target:
                        raise ValueError(f"a recovery to {new[:16]}… is already waiting")
            backing = auth.back_recovery(account, tx.sender, new)
            data: Dict[str, Any] = {"account": key, "new_controller": new, "backing": backing}
            if new and backing >= policy.guardian_threshold:
                due = now + policy.recovery_delay
                data["change_id"] = auth.queue(account, "recover", new, due, "guardians")
                data["due"] = str(due)
                auth.clear_recovery_votes(
                    key,
                    [
                        g
                        for g in policy.guardian_ids()
                        if (v := auth.recovery_votes.peek(f"{key}|{g}")) is not None
                        and _account_key(v) == _account_key(new)
                    ],
                )
        except (ValueError, KeyError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ACCOUNT_RECOVER], data=data
        )

    @_pinned
    def apply_policy_changes(self, now: Decimal) -> List[Dict[str, Any]]:
        """The block's tick for account control: changes the own key signed whose delay has
        passed take effect — unless the own key was turned off meanwhile, or the change no
        longer fits the policy (it is dropped)."""
        auth = self.authority
        if not len(auth.pending):
            return []
        events = []
        for cid in auth.due_changes(now):
            change = auth.pending.peek(cid)
            del auth.pending[cid]
            policy = auth.policies.peek(change.account) or _default_policy()
            event = {"change_id": cid, "account": change.account, "action": change.action}
            try:
                if not policy.own_key and change.action != "recover":
                    raise ValueError("the own key that signed it was turned off")
                updated = _apply_policy(policy, change.action, _parse_value(change), change.account)
            except ValueError as e:
                events.append({"type": "policy_change_dropped", **event, "reason": str(e)})
                continue
            if change.action == "recover":  # done: the guardians' backing is spent
                auth.clear_recovery_votes(change.account, policy.guardian_ids())
            auth.store_policy(change.account, updated)
            events.append({"type": "policy_change_applied", **event})
        return events

    def _op_referral(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """REFERRAL_REGISTER: take ``code``. REFERRAL_JOIN: join ``code``'s referrer."""
        code = str(tx.params["code"])
        try:
            if tx.op_type == ExchangeOpType.REFERRAL_REGISTER:
                self.clearinghouse.register_referral_code(tx.sender, code)
                data = {"code": code}
            else:
                data = {"code": code, "referrer": self.clearinghouse.join_referral(tx.sender, code)}
        except (ClearinghouseError, ValueError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(success=True, gas_used=EXCHANGE_GAS_COSTS[tx.op_type], data=data)

    def _op_vault_create(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A user vault (``Clearinghouse.create_user_vault``): ``amount`` of the leader's perp
        collateral to start, ``profit_share`` of depositors' gains, ``name``. The leader signs
        its trades as ``signer`` with the vault as ``sender``."""
        from .clearinghouse import USER_VAULT_DEFAULT_PROFIT_SHARE, user_vault_address
        from .trading import NAME_MAX

        p = tx.params
        vault = user_vault_address(tx.sender, tx.tx_hash())
        try:
            if not self._signed_by_account(tx):
                raise ValueError("only the leader itself creates a vault")
            name = str(p.get("name", ""))
            if len(name) > NAME_MAX:
                raise ValueError(f"a name is at most {NAME_MAX} characters")
            shares = self.clearinghouse.create_user_vault(
                tx.sender,
                vault,
                name,
                Decimal(str(p["amount"])),
                Decimal(str(p.get("profit_share", USER_VAULT_DEFAULT_PROFIT_SHARE))),
                self._block_clock(),
            )
        except (ClearinghouseError, ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_CREATE],
            data={"vault": vault, "shares": str(shares)},
        )

    def _op_vault_deposit(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Perp collateral → backstop vault shares at NAV — or, with ``vault``, a user vault's.
        Internal to the clearinghouse: no real balance moves (every vault's collateral is
        inside the perps holder too)."""
        from .. import constants

        if tx.params.get("vault"):
            try:
                shares = self.clearinghouse.user_vault_deposit(
                    tx.sender,
                    str(tx.params["vault"]),
                    Decimal(str(tx.params["amount"])),
                    self._block_clock(),
                )
            except (ClearinghouseError, ValueError, ArithmeticError) as e:
                return ExchangeExecResult(success=False, error=str(e))
            return ExchangeExecResult(
                success=True,
                gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_DEPOSIT],
                data={"vault": tx.params["vault"], "shares": str(shares)},
            )
        seeder = tx.sender.lower() in {a.lower() for a in constants.PERP_VAULT_SEEDERS}
        try:
            shares = self.clearinghouse.vault_deposit(
                tx.sender,
                Decimal(str(tx.params["amount"])),
                self._block_clock(),
                constants.PERP_VAULT_LOCKUP_SECONDS,
                protocol=seeder,
            )
        except (ClearinghouseError, ValueError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_DEPOSIT],
            data={"shares": str(shares), "protocol_owned": seeder},
        )

    def _op_vault_withdraw(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        if tx.params.get("vault"):
            try:
                paid, fee = self.clearinghouse.user_vault_withdraw(
                    tx.sender,
                    str(tx.params["vault"]),
                    Decimal(str(tx.params["shares"])),
                    self._block_clock(),
                )
            except (ClearinghouseError, ValueError, ArithmeticError) as e:
                return ExchangeExecResult(success=False, error=str(e))
            return ExchangeExecResult(
                success=True,
                gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_WITHDRAW],
                data={"vault": tx.params["vault"], "value": str(paid), "profit_share": str(fee)},
            )
        try:
            value = self.clearinghouse.vault_withdraw(
                tx.sender, Decimal(str(tx.params["shares"])), self._block_clock()
            )
        except (ClearinghouseError, ValueError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_WITHDRAW],
            data={"value": str(value)},
        )

    def _op_perp_set_leverage(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        mode = str(p.get("mode", "cross")).lower()
        if mode not in ("cross", "isolated"):
            return ExchangeExecResult(success=False, error=f"unknown margin mode {mode!r}")
        try:
            moved = self.clearinghouse.set_leverage(
                tx.sender, str(p["market_id"]), Decimal(str(p["leverage"])), mode == "isolated"
            )
        except (ClearinghouseError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_SET_LEVERAGE],
            data={"margin_moved": str(moved)} if moved else {},
        )

    def _trade_leverage(self, owner: str, market_id: str, p: Dict[str, Any]) -> None:
        """An order's, trigger's or TWAP's own ``leverage`` (and ``margin_mode``): the market's
        setting for the account becomes it, as PERP_SET_LEVERAGE would make it, inside the
        operation — so it is all or nothing with the order. Absent: the setting stays."""
        if p.get("leverage") is None and p.get("margin_mode") is None:
            return
        from .clearinghouse import DEFAULT_LEVERAGE

        ch = self.clearinghouse
        m = ch.market(market_id)
        acct = ch.accounts.peek(owner)
        mode = p.get("margin_mode")
        if mode is None:
            isolated = Clearinghouse.contained(m) or (
                acct is not None and acct.isolated.get(market_id, False)
            )
        else:
            mode = str(mode).lower()
            if mode not in ("cross", "isolated"):
                raise ValueError(f"unknown margin mode {mode!r}")
            isolated = mode == "isolated"
        raw = p.get("leverage")
        if raw is None:
            leverage = (
                ch._leverage(acct, m) if acct is not None else min(DEFAULT_LEVERAGE, m.max_leverage)
            )
        else:
            if isinstance(raw, bool):
                raise ValueError("leverage is a number")
            leverage = Decimal(str(raw))
        ch.set_leverage(owner, market_id, leverage, isolated)

    # ── tickers (docs/HYPERLIQUID_PARITY.md 11, Hyperliquid's HIP-1 deploy auction) ──

    @staticmethod
    def reserved_tickers() -> Set[str]:
        """Tickers no one buys: the native asset's, the perps quote's, and every bridged
        asset's — bound to the bridge's own token when it is created (``_mint_deposit``)."""
        from .. import constants

        out = {"QRDX", str(constants.PERP_QUOTE).upper()}
        for entry in constants.BRIDGE_ASSETS:
            out.add(str(entry).split(":", 1)[0].upper())
        return out

    def ticker_price(self, now: Optional[Decimal] = None) -> Decimal:
        """The ticker auction's price at block time ``now``: the opening price until the first
        sale; then twice the last sale's price, falling linearly to the floor over
        TICKER_AUCTION_SECONDS after it."""
        from .. import constants

        now = Decimal(str(self._block_clock() if now is None else now))
        floor = Decimal(constants.TICKER_MIN_PRICE)
        last = self.trading.ticker_auction.peek("last")
        if last is None:
            return max(Decimal(constants.TICKER_OPENING_PRICE), floor)
        price, at = last
        start = max(price * 2, floor)
        span = Decimal(int(constants.TICKER_AUCTION_SECONDS))
        left = max(ZERO, span - max(ZERO, now - at)) / span
        return (floor + (start - floor) * left).quantize(Decimal("1e-18"), rounding=ROUND_DOWN)

    def ticker_of(self, token: str) -> Optional[str]:
        """The ticker a token holds, if any."""
        token = str(token).lower()
        for ticker, address in self.trading.tickers.peek_items():
            if address == token:
                return ticker
        return None

    def _op_ticker_claim(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A token's creator buys its symbol, upper-cased, as the token's ticker — one token per
        ticker, for good — at the ticker auction's price, burned. ``max_price``: the most the
        sender pays (the price moves with block time)."""
        from ..crypto.account_id import same_account

        p = tx.params
        now = Decimal(str(self._block_clock()))
        try:
            t = self.tokens.get(str(p["token_address"]))
            if t is None:
                raise ValueError(f"no token {p['token_address']}")
            if not same_account(t.creator, tx.sender):
                raise ValueError("only the token's creator claims its ticker")
            ticker = t.symbol.upper()
            if not re.fullmatch(r"[A-Z0-9]{1,12}", ticker):
                raise ValueError("a ticker is 1 to 12 letters and digits: this symbol is not one")
            if ticker in self.reserved_tickers():
                raise ValueError(f"{ticker} is reserved")
            if self.trading.tickers.peek(ticker) is not None:
                raise ValueError(f"the ticker {ticker} is taken")
            if self.ticker_of(t.address) is not None:
                raise ValueError(f"{t.address} already holds {self.ticker_of(t.address)}")
            price = self.ticker_price(now)
            if p.get("max_price") is not None:
                cap = Decimal(str(p["max_price"]))
                if not cap.is_finite() or price > cap:
                    raise ValueError(f"the ticker auction is at {price}, above max_price {cap}")
            avail = self.available_balance(tx.sender)
            if price > 0 and (avail is None or avail < price):
                raise ValueError(f"a ticker costs {price} QRDX now; available {avail}")
        except (ValueError, ArithmeticError, KeyError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        if price > 0:
            self._record_balance_delta(tx.sender, -price)  # burned
        self.trading.tickers[ticker] = t.address
        self.trading.ticker_auction["last"] = (price, now)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TICKER_CLAIM],
            data={"ticker": ticker, "token_address": t.address, "price": str(price)},
        )

    # ── deployer markets (docs/HYPERLIQUID_PARITY.md, Hyperliquid's HIP-3) ──

    @staticmethod
    def deployer_bond_address() -> str:
        """The protocol holder of market deployers' QRDX bonds (a synthetic holder, like 0xVETO)."""
        return "0xDBND" + hashlib.blake2b(b"deployers:bond-holder", digest_size=18).hexdigest()

    def deployer_markets(self, deployer: str) -> List[str]:
        """The markets ``deployer`` runs: listed by it, not settled."""
        return sorted(
            mid
            for mid, m in self.clearinghouse.markets.items()
            if m.deployer == deployer and m.settled_price <= 0
        )

    @staticmethod
    def _qrdx_amount(raw: Any) -> Decimal:
        amount = Decimal(str(raw))
        if not amount.is_finite() or amount <= 0:
            raise ValueError("amount must be a positive amount of QRDX")
        return amount.quantize(Decimal("1e-18"), rounding=ROUND_DOWN)

    def _op_deployer_bond(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Bond ``amount`` QRDX as a market deployer. The first bond names the deployer's
        namespace (``dex``: 1 to 8 lowercase letters and digits, a letter first), which its
        markets are listed under (``dex:ASSET``) and which stays its own for good."""
        from dataclasses import replace

        from .trading import Deployer

        p = tx.params
        try:
            amount = self._qrdx_amount(p["amount"])
            d = self.trading.deployers.peek(tx.sender)
            if d is None:
                dex = str(p.get("dex", ""))
                if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", dex):
                    raise ValueError(
                        "a deployer's first bond names its namespace (dex): 1 to 8 lowercase "
                        "letters and digits, a letter first"
                    )
                if any(other.dex == dex for _a, other in self.trading.deployers.peek_items()):
                    raise ValueError(f"the namespace {dex} is taken")
                d = Deployer(dex=dex, bond=ZERO)
            elif p.get("dex") not in (None, d.dex):
                raise ValueError(f"this deployer's namespace is {d.dex}")
            avail = self.available_balance(tx.sender)
            if avail is None or avail < amount:
                raise ValueError(f"insufficient QRDX to bond: need {amount}, available {avail}")
        except (ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        self._record_balance_delta(tx.sender, -amount)
        self._record_balance_delta(self.deployer_bond_address(), amount)
        self.trading.deployers[tx.sender] = replace(d, bond=d.bond + amount)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.DEPLOYER_BOND],
            data={"dex": d.dex, "bond": str(d.bond + amount)},
        )

    def _op_deployer_unbond(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Start unbonding ``amount`` (claimable DEPLOYER_UNBOND_SECONDS after the latest start,
        and slashable until then), or ``claim`` what has unbonded. A deployer that runs markets
        keeps at least DEPLOYER_MIN_BOND bonded."""
        from dataclasses import replace

        from .. import constants

        p = tx.params
        now = Decimal(str(self._block_clock()))
        d = self.trading.deployers.peek(tx.sender)
        try:
            if d is None:
                raise ValueError("not a market deployer")
            if p.get("claim"):
                if d.unbonding <= 0 or now < d.unlock:
                    raise ValueError(
                        "nothing has unbonded yet"
                        + (f" (claimable at block time {d.unlock})" if d.unbonding > 0 else "")
                    )
                claimed = d.unbonding
                self._record_balance_delta(self.deployer_bond_address(), -claimed)
                self._record_balance_delta(tx.sender, claimed)
                self.trading.deployers[tx.sender] = replace(d, unbonding=ZERO, unlock=ZERO)
                data: Dict[str, Any] = {"claimed": str(claimed)}
            else:
                amount = self._qrdx_amount(p["amount"])
                if amount > d.bond:
                    raise ValueError(f"only {d.bond} is bonded")
                left = d.bond - amount
                if self.deployer_markets(tx.sender) and left < constants.DEPLOYER_MIN_BOND:
                    raise ValueError(
                        f"a deployer running markets keeps {constants.DEPLOYER_MIN_BOND} bonded"
                    )
                unlock = now + Decimal(constants.DEPLOYER_UNBOND_SECONDS)
                self.trading.deployers[tx.sender] = replace(
                    d, bond=left, unbonding=d.unbonding + amount, unlock=unlock
                )
                data = {"unbonding": str(d.unbonding + amount), "unlock": str(unlock)}
        except (ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.DEPLOYER_UNBOND], data=data
        )

    def _deployer_market(self, tx: ExchangeTransaction) -> Tuple[str, Any]:
        """The live, unfrozen market of the sender's that ``tx`` names (ValueError otherwise)."""
        mid = str(tx.params["market_id"])
        m = self.clearinghouse.markets.get(mid)
        if m is None or not m.deployer or m.deployer != tx.sender:
            raise ValueError(f"{mid} is not a market this account deployed")
        if m.settled_price > 0:
            raise ValueError(f"{mid} is settled")
        if Clearinghouse.frozen(m, self._block_clock()):
            raise ValueError(
                f"the validators have frozen {mid} (until block time {m.frozen_until}): its "
                "oracle is theirs, and only governance settles it"
            )
        return mid, m

    def _op_deployer_set_oracle(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The deployer's oracle price for one of its markets: once a block time, moved at most
        DEPLOYER_ORACLE_MAX_STEP_BPS a second since the last (counting at most 10 seconds) —
        a price further away is applied at the bound. The market's price band, circuit breaker
        and the validators' freeze watch it as any market."""
        from .. import constants

        now = Decimal(str(self._block_clock()))
        try:
            mid, m = self._deployer_market(tx)
            price = Decimal(str(tx.params["price"]))
            if not price.is_finite() or price <= 0:
                raise ValueError("the oracle price must be positive")
            if m.oracle_time >= now:
                raise ValueError(f"{mid}'s oracle is set at most once a block time")
            step = Decimal(int(constants.DEPLOYER_ORACLE_MAX_STEP_BPS)) / 10_000
            prev, prev_time = m.oracle_price, m.oracle_time
            if step > 0 and prev > 0 and prev_time > 0:
                bound = step * min(now - prev_time, Decimal(10))
                lo, hi = prev * (1 - min(bound, Decimal("0.99"))), prev * (1 + bound)
                price = min(max(price, lo), hi)
            price = price.quantize(Decimal(1).scaleb(-18))
            self.clearinghouse.set_oracle_price(mid, price, now)
        except (ValueError, ArithmeticError, ClearinghouseError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.DEPLOYER_SET_ORACLE],
            data={"market_id": mid, "price": str(price)},
        )

    def _op_deployer_halt(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """The deployer settles one of its markets for good, at its oracle price (as a passed
        ``delist_market`` does). Not while the validators hold it frozen."""
        try:
            mid, _m = self._deployer_market(tx)
            settled = self._delist_market(mid, None)
        except (ValueError, GovernanceError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.DEPLOYER_HALT], data=settled
        )

    def _list_market(self, listing: Dict[str, Any]) -> Dict[str, Any]:
        """A passed ``list_market``: a validator-priced market with the settings the proposal
        named. A refusal (the market exists, a setting out of bounds) fails the execution."""
        from .. import constants

        try:
            spot_token, spot_pools = str(listing.get("spot_token") or ""), ()
            if spot_token.upper() == "QRDX":
                spot_token = "QRDX"  # (the native asset, as pools name it)
            max_leverage = Decimal(str(listing.get("max_leverage", "20")))
            if spot_token:
                spot_pools = tuple(listing.get("spot_pools") or ())
                self._check_spot_listing(str(listing["base_token"]), spot_token, spot_pools)
                cap = Decimal(int(constants.PERP_SPOT_MAX_LEVERAGE))
                if "max_leverage" not in listing:
                    max_leverage = min(max_leverage, cap)
                if max_leverage > cap:
                    raise ValueError(f"a native-token market's maximum leverage is at most {cap}")
            m = self.clearinghouse.create_market(
                str(listing["base_token"]),
                constants.PERP_QUOTE,
                max_leverage=max_leverage,
                sz_decimals=int(listing.get("sz_decimals", constants.PERP_DEFAULT_SZ_DECIMALS)),
                spot_token=spot_token,
                spot_pools=spot_pools,
            )
        except (ClearinghouseError, ValueError, ArithmeticError) as e:
            raise GovernanceError(str(e)) from None
        return {"market_id": m.id}

    # ── native-token perps (docs/HYPERLIQUID_PARITY.md 13) ──

    def _check_spot_listing(self, base: str, token: str, pools: Tuple[str, ...]) -> None:
        """A native-token market's listing: the token holds ``base`` as its unique ticker (its
        name cannot be anyone else's), and ``pools`` lead from it to the settlement asset. QRDX
        itself may be one — ``spot_token`` "QRDX", listed as QRDX — priced off its pools to a
        stablecoin settlement asset."""
        settlement = self._settlement_asset()
        if str(token).upper() == "QRDX":
            if base.upper() != "QRDX":
                raise ValueError("QRDX's market is listed as QRDX")
            if settlement == "QRDX":
                raise ValueError("perps settle in QRDX here: QRDX has no price in itself")
            start = "QRDX"
        else:
            t = self.tokens.get(token)
            if t is None:
                raise ValueError(f"no native token {token}")
            if self.ticker_of(t.address) != base.upper():
                raise ValueError(f"{base} is not {t.address}'s ticker: list it by its ticker")
            start = t.address
        if self._spot_path_end(start, pools) != settlement:
            raise ValueError("the spot pools must lead from the token to the settlement asset")

    def _settlement_asset(self) -> str:
        """The perps settlement asset as spot pools name it ("QRDX", or a token address)."""
        token = self.perp_collateral_token()
        return "QRDX" if token.upper() == "QRDX" else self.canonical_asset(token)

    def _spot_path_end(self, start: str, pools: Tuple[str, ...]) -> Optional[str]:
        """Where ``pools`` lead from ``start`` (None if a pool is missing or not on the way)."""
        current = start
        for pid in pools:
            pool = self.pool_manager.get_pool(pid)
            if pool is None or current not in (pool.state.token0, pool.state.token1):
                return None
            current = pool.state.token1 if pool.state.token0 == current else pool.state.token0
        return current

    def _spot_reading(self, m, now: Decimal) -> Tuple[Optional[Decimal], Decimal]:
        """(price, depth) of a native-token market's spot market now, in the settlement asset:
        the price the TWAP over SPOT_ORACLE_TWAP_SECONDS along its pools (None without that much
        history), the depth the smallest of the pools' virtual reserves on the way out, each in
        the settlement asset."""
        from .. import constants
        from .amm import Q96

        window, at = int(constants.SPOT_ORACLE_TWAP_SECONDS), int(now)
        current, prices, reserves = m.spot_token, [], []
        for pid in m.spot_pools:
            pool = self.pool_manager.get_pool(pid)
            if pool is None or current not in (pool.state.token0, pool.state.token1):
                return None, ZERO
            st = pool.state
            forward = st.token0 == current
            twap = pool.twap_price(window, at)
            prices.append(None if not twap or twap <= 0 else (twap if forward else 1 / twap))
            root = st.sqrt_price / Q96
            if root <= 0 or st.liquidity <= 0:
                reserves.append(ZERO)
            else:  # virtual reserves: token0 L/√P, token1 L·√P — the side the path leaves by
                reserves.append(st.liquidity * root if forward else st.liquidity / root)
            current = st.token1 if forward else st.token0
        if current != self._settlement_asset():
            return None, ZERO
        depth: Optional[Decimal] = None
        for i, reserve in enumerate(reserves):
            onward = Decimal(1)
            for p in prices[i + 1 :]:
                if p is None:
                    onward = ZERO
                    break
                onward *= p
            value = reserve * onward
            depth = value if depth is None else min(depth, value)
        price: Optional[Decimal] = Decimal(1)
        for p in prices:
            if p is None:
                price = None
                break
            price = price * p if price is not None else None
        return price, (depth or ZERO).quantize(Decimal("1e-18"), rounding=ROUND_DOWN)

    @_pinned
    def update_spot_oracles(self, now: Decimal) -> List[Dict[str, Any]]:
        """Each block, before the clearinghouse's tick: every live native-token market reads its
        spot market. Its depth at most doubles over SPOT_ORACLE_TWAP_SECONDS (falls at once), so
        liquidity added for a block raises no cap. Its oracle is the TWAP, moved at most ORACLE_MAX_STEP_BPS a second — only while
        the depth is at least SPOT_ORACLE_MIN_DEPTH; otherwise it goes stale, and the market
        takes only reduce-only orders. Not while the validators hold the market frozen."""
        from .. import constants

        now = Decimal(str(now))
        ch = self.clearinghouse
        window = Decimal(int(constants.SPOT_ORACLE_TWAP_SECONDS))
        step = Decimal(int(constants.ORACLE_MAX_STEP_BPS)) / 10_000
        events: List[Dict[str, Any]] = []
        for mid in sorted(ch.markets):
            m = ch.markets[mid]
            if not m.spot_token or m.settled_price > 0 or Clearinghouse.frozen(m, now):
                continue
            price, depth = self._spot_reading(m, now)
            if depth > m.spot_depth:
                # Up at most doubling over SPOT_ORACLE_TWAP_SECONDS (from SPOT_ORACLE_MIN_DEPTH
                # at the first reading), down at once: liquidity added for a moment, however
                # much, raises the cap by a sliver — only liquidity that stays raises it.
                dt = max(ZERO, now - m.spot_time) if m.spot_time > 0 else ZERO
                base = max(m.spot_depth, Decimal(int(constants.SPOT_ORACLE_MIN_DEPTH)))
                allowed = base * (1 + min(Decimal(1), dt / window))
                depth = min(depth, allowed).quantize(Decimal("1e-18"), rounding=ROUND_DOWN)
            if price is not None and depth < Decimal(int(constants.SPOT_ORACLE_MIN_DEPTH)):
                price = None
            if price is not None and step > 0 and m.oracle_price > 0 and m.oracle_time > 0:
                bound = step * max(ZERO, now - m.oracle_time)
                lo = m.oracle_price * (1 - min(bound, Decimal("0.99")))
                hi = m.oracle_price * (1 + bound)
                price = min(max(price, lo), hi)
            if price is not None:
                price = price.quantize(Decimal(1).scaleb(-18))
            ch.set_spot_reading(mid, price, depth, now)
            if price is None:
                events.append({"type": "spot_oracle_waiting", "market": mid, "depth": str(depth)})
        return events

    def _slash_deployer(self, deployer: str, bps: int, halt: bool) -> Dict[str, Any]:
        """A passed ``slash_deployer``: ``bps`` of the deployer's bond — what is unbonding too —
        burned, and with ``halt`` every market it runs settled at its oracle price (a frozen
        market's oracle is the validators')."""
        from dataclasses import replace

        d = self.trading.deployers.peek(deployer)
        if d is None:
            raise GovernanceError(f"{deployer} is not a market deployer")
        share = Decimal(int(bps)) / 10_000
        cut_bond = (d.bond * share).quantize(Decimal("1e-18"), rounding=ROUND_DOWN)
        cut_unbonding = (d.unbonding * share).quantize(Decimal("1e-18"), rounding=ROUND_DOWN)
        burned = cut_bond + cut_unbonding
        self.trading.deployers[deployer] = replace(
            d, bond=d.bond - cut_bond, unbonding=d.unbonding - cut_unbonding
        )
        if burned > 0:
            self._record_balance_delta(self.deployer_bond_address(), -burned)  # burned
        settled = []
        if halt:
            for mid in self.deployer_markets(deployer):
                self._delist_market(mid, None)
                settled.append(mid)
        return {"burned": str(burned), "settled": settled}

    def _op_approve_builder_fee(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Let ``builder`` (a front-end) charge up to ``max_fee_rate`` of the notional of the fills
        orders it routes take (0: revoke). Signed by the account itself, never an agent."""
        from .trading import BUILDER_FEE_MAX_SPOT

        p = tx.params
        builder = str(p["builder"])
        try:
            if not self._signed_by_account(tx):
                raise ValueError("only the account itself approves a builder")
            if not re.fullmatch(r"0x([Pp][Qq])?[0-9a-fA-F]{40}([0-9a-fA-F]{24})?", builder):
                raise ValueError("a builder is an address")
            if _id_or_raw(builder) == _id_or_raw(tx.sender):
                raise ValueError("an account does not approve itself")
            rate = Decimal(str(p["max_fee_rate"]))
            if not rate.is_finite() or not ZERO <= rate <= BUILDER_FEE_MAX_SPOT:
                raise ValueError(f"max_fee_rate is 0 to {BUILDER_FEE_MAX_SPOT}")
        except (ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        key = f"{_id_or_raw(tx.sender)}|{_id_or_raw(builder)}"
        if rate == 0:
            if key in self.trading.builder_approvals:
                del self.trading.builder_approvals[key]
        else:
            self.trading.builder_approvals[key] = str(rate)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.APPROVE_BUILDER_FEE],
            data={"builder": builder, "max_fee_rate": str(rate)},
        )

    def _builder_of(self, tx: ExchangeTransaction, spot: bool) -> Optional[Tuple[str, Decimal]]:
        """An order's builder code (``builder: {b, f}``) — checked against the account's
        approval and the cap; None without one. ValueError if it is not allowed."""
        from .trading import BUILDER_FEE_MAX_PERP, BUILDER_FEE_MAX_SPOT

        raw = tx.params.get("builder")
        if raw is None:
            return None
        if not isinstance(raw, dict) or "b" not in raw or "f" not in raw:
            raise ValueError("builder is {b: address, f: fee rate}")
        builder, rate = str(raw["b"]), Decimal(str(raw["f"]))
        cap = BUILDER_FEE_MAX_SPOT if spot else BUILDER_FEE_MAX_PERP
        if not rate.is_finite() or not ZERO < rate <= cap:
            raise ValueError(f"a builder fee is above 0 and at most {cap}")
        approved = (
            self.trading.builder_approvals.peek(f"{_id_or_raw(tx.sender)}|{_id_or_raw(builder)}")
            if len(self.trading.builder_approvals)
            else None
        )
        if approved is None or rate > Decimal(approved):
            raise ValueError(f"the account has not approved {builder[:16]}… for that fee")
        return builder, rate

    def _op_perp_isolated_margin(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Add ``amount`` of free cross margin to an isolated position (negative: take it back,
        keeping the position's initial margin) — Hyperliquid's ``updateIsolatedMargin``."""
        p = tx.params
        try:
            margin = self.clearinghouse.adjust_isolated_margin(
                tx.sender, str(p["market_id"]), Decimal(str(p["amount"]))
            )
        except (ClearinghouseError, ArithmeticError, ValueError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ISOLATED_MARGIN],
            data={"market_id": str(p["market_id"]), "isolated_margin": str(margin)},
        )

    def _op_perp_order(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A perp order — and its attached take-profit / stop-loss (``tp`` / ``sl``: each
        ``{trigger_price, limit_price?, max_makers?}``): reduce-only triggers on the other side,
        sized to the order, one cancelling the other, placed with it. Each costs what a
        PERP_TRIGGER costs; the order's matching gets what is left of the gas limit."""
        p = tx.params
        order_id = tx.tx_hash()[:16]
        m = self.clearinghouse.markets.get(str(p["market_id"]))
        if m is not None and not bool(p.get("reduce_only", False)) and self._perp_oracle_stale(m):
            return ExchangeExecResult(
                success=False,
                error=self._reduce_only_reason(m),
            )
        try:
            legs = _attached_legs(p)
            builder = self._builder_of(tx, spot=False)
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))
        legs_gas = sum(
            EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_TRIGGER] + makers * EXCHANGE_GAS_PER_MAKER
            for _kind, _trigger, _limit, makers in legs
        )
        gas_limit = getattr(tx, "gas_limit", None)
        try:
            if (
                gas_limit is not None
                and legs_gas > int(gas_limit) - EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
            ):
                raise ValueError(f"the attached TP/SL need {legs_gas} gas beyond the order's")
            self._trade_leverage(tx.sender, str(p["market_id"]), p)
            fills = self.clearinghouse.place_order(
                tx.sender,
                str(p["market_id"]),
                order_id,
                str(p["side"]),
                Decimal(str(p["size"])),
                Decimal(str(p["price"])),
                _book_nonce(tx),
                reduce_only=bool(p.get("reduce_only", False)),
                tif=str(p.get("tif", "gtc")),
                hidden=_flag(p, "hidden"),
                display_size=Decimal(str(p.get("display_size", "0"))),
                max_makers=match_budget(
                    ExchangeOpType.PERP_ORDER, None if gas_limit is None else gas_limit - legs_gas
                ),
            )
            builder_fee = ZERO
            if builder is not None:  # on the notional of the fills this order took
                taken = sum(
                    (
                        Decimal(f["amount"]) * Decimal(f["price"])
                        for f in fills
                        if f.get("taker_order_id") == order_id
                    ),
                    ZERO,
                )
                builder_fee = (taken * builder[1]).quantize(SPOT_FEE_QUANTUM, ROUND_DOWN)
                self.clearinghouse.pay_builder(tx.sender, builder[0], builder_fee)
            # Not resting after its fills: filled, IOC, or stopped by self-trade prevention
            # (an order that would hit the sender's own resting order is cancelled there).
            resting = order_id in self.clearinghouse.markets[str(p["market_id"])].orders
            attached = []
            if legs and (resting or fills):  # (an order that did nothing protects nothing)
                buy = str(p["side"]).lower() in ("buy", "long", "bid")
                for kind, trigger, limit, makers in legs:
                    self.clearinghouse.place_trigger(
                        tx.sender,
                        str(p["market_id"]),
                        f"{order_id}.{kind}",
                        "sell" if buy else "buy",
                        kind,
                        trigger,
                        size=Decimal(str(p["size"])),
                        limit_price=limit,
                        reduce_only=True,
                        max_makers=makers,
                        group=order_id,
                        parent=order_id,
                    )
                    attached.append(f"{order_id}.{kind}")
        except (ClearinghouseError, ValueError, ArithmeticError) as e:
            # It pays for the resting orders it visited before failing (a fill-or-kill that
            # could not fill whole), as it would have had it succeeded.
            return ExchangeExecResult(
                success=False,
                error=str(e),
                gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
                + self.clearinghouse.last_makers_visited * EXCHANGE_GAS_PER_MAKER,
            )
        data: Dict[str, Any] = {"order_id": order_id, "fills": fills, "resting": resting}
        if builder is not None:
            data["builder_fee"] = {"builder": builder[0], "amount": str(builder_fee)}
        if attached:
            data["attached"] = attached
        if self.clearinghouse.last_cancelled:
            # Resting orders the fills left an account unqualified for (theirs or a maker's).
            data["cancelled"] = self.clearinghouse.last_cancelled
        visited = self.clearinghouse.last_makers_visited
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
            + visited * EXCHANGE_GAS_PER_MAKER
            + (legs_gas if attached else 0),
            data=data,
        )

    def _reduce_only_reason(self, m) -> str:
        """Why ``m`` takes only reduce-only orders now (``_perp_oracle_stale``)."""
        if Clearinghouse.frozen(m, self._block_clock()):
            return f"the validators have frozen {m.id}: only reduce-only orders are accepted"
        if self.clearinghouse.halted(m):
            return f"{m.id}'s circuit breaker has tripped: only reduce-only orders are accepted"
        return f"the oracle for {m.id} is stale; only reduce-only orders are accepted"

    def _perp_oracle_stale(self, m) -> bool:
        """A market whose oracle has not been set for PERP_ORACLE_STALE_SECONDS of block time
        accepts only orders that reduce exposure."""
        from .. import constants

        return m is not None and (
            (
                m.oracle_time > 0
                and Decimal(str(self._block_clock())) - m.oracle_time
                > constants.PERP_ORACLE_STALE_SECONDS
            )
            or self.clearinghouse.halted(m)
        )

    def _op_perp_trigger(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """A stop or take-profit order (``Clearinghouse.place_trigger``). It prepays the
        matching it may do when it fires: ``max_makers`` resting orders (default
        TRIGGER_DEFAULT_MAKERS) at EXCHANGE_GAS_PER_MAKER each."""
        from .clearinghouse import TRIGGER_DEFAULT_MAKERS

        p = tx.params
        base = EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_TRIGGER]
        try:
            makers = p.get("max_makers", TRIGGER_DEFAULT_MAKERS)
            if isinstance(makers, bool) or not isinstance(makers, int):
                raise ValueError("max_makers must be a whole number")
            gas = base + makers * EXCHANGE_GAS_PER_MAKER
            if gas > tx.gas_limit:
                raise ValueError(
                    f"gas limit {tx.gas_limit} does not cover the trigger's prepaid matching "
                    f"({gas})"
                )
            trigger_id = tx.tx_hash()[:16]
            self._trade_leverage(tx.sender, str(p["market_id"]), p)
            self.clearinghouse.place_trigger(
                tx.sender,
                str(p["market_id"]),
                trigger_id,
                str(p["side"]),
                str(p["kind"]),
                Decimal(str(p["trigger_price"])),
                size=Decimal(str(p.get("size", "0"))),
                limit_price=Decimal(str(p.get("limit_price", "0"))),
                reduce_only=_flag(p, "reduce_only"),
                position=_flag(p, "position"),
                tif=str(p.get("tif", "gtc")),
                max_makers=makers,
            )
        except (ClearinghouseError, ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(success=True, gas_used=gas, data={"order_id": trigger_id})

    def _op_perp_modify(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params

        def opt(key):
            return None if p.get(key) is None else Decimal(str(p[key]))

        m = self.clearinghouse.markets.get(str(p["market_id"]))
        meta = tracked(m.orders).peek(str(p["order_id"])) if m is not None else None
        if (
            m is not None
            and meta is not None
            and not meta.reduce_only
            and self._perp_oracle_stale(m)
        ):
            return ExchangeExecResult(
                success=False,
                error=self._reduce_only_reason(m),
            )
        try:
            out = self.clearinghouse.modify_order(
                tx.sender,
                str(p["market_id"]),
                str(p["order_id"]),
                tx.tx_hash()[:16],
                size=opt("size"),
                price=opt("price"),
                trigger_price=opt("trigger_price"),
                limit_price=opt("limit_price"),
                max_makers=match_budget(ExchangeOpType.PERP_MODIFY, getattr(tx, "gas_limit", None)),
            )
        except (ClearinghouseError, ValueError, ArithmeticError) as e:
            return ExchangeExecResult(
                success=False,
                error=str(e),
                gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_MODIFY]
                + self.clearinghouse.last_makers_visited * EXCHANGE_GAS_PER_MAKER,
            )
        if self.clearinghouse.last_cancelled:
            out["cancelled"] = self.clearinghouse.last_cancelled
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_MODIFY]
            + self.clearinghouse.last_makers_visited * EXCHANGE_GAS_PER_MAKER,
            data=out,
        )

    def _op_cancel_all(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Every resting order and trigger of the sender — spot (escrow refunded), perps, or
        both (``scope``), or those of one ``market`` (a pair or a perp market id). Each one
        cancelled costs EXCHANGE_GAS_PER_CANCEL; a gas limit that does not cover them all
        cancels none."""
        p = tx.params
        count = self._cancel_all_of(tx.sender, p.get("scope", "all"), p.get("market"))
        gas = EXCHANGE_GAS_COSTS[ExchangeOpType.CANCEL_ALL] + count * EXCHANGE_GAS_PER_CANCEL
        if gas > tx.gas_limit:
            return ExchangeExecResult(
                success=False,
                gas_used=tx.gas_limit,
                error=f"cancelling {count} orders needs {gas} gas; the limit is {tx.gas_limit}",
            )
        return ExchangeExecResult(success=True, gas_used=gas, data={"cancelled": count})

    def _cancel_all_of(
        self, owner: str, scope: str = "all", market: Any = None, covered: bool = False
    ) -> int:
        """Every resting order, trigger and TWAP of ``owner`` in ``scope`` (or one ``market``);
        spot escrow refunded (``covered``: out of the books' own records — in the tick, where no
        balance is loaded). Returns how many."""
        count = 0
        if scope in ("all", "spot") and (market is None or ":" in str(market)):
            pairs = sorted(self._order_books)
            if market is not None:
                pairs = [k for k in pairs if k == self._canonical_pair(str(market))]
            for pair in pairs:
                for tid in self.trading.owned(owner, pair):
                    count += self._cancel_spot_trigger(owner, tid)
                book = self._order_books[pair]
                if not book._owner_order_count.get(owner) and not any(
                    o.owner == owner for o in book._stop_orders.values()
                ):
                    continue
                mine = sorted(
                    oid
                    for index in (book._orders, book._stop_orders)
                    for oid, o in index.items()
                    if o.owner == owner
                )
                for oid in mine:
                    stop = oid in book._stop_orders  # (a stop order escrowed nothing)
                    cancelled = book.cancel_order(oid, caller=owner)
                    if cancelled is not None:
                        count += 1
                        if not stop:
                            self._refund_escrow(
                                book, cancelled, cancelled.remaining, covered=covered
                            )
        if scope in ("all", "perps") and (market is None or ":" not in str(market)):
            if market is None or str(market) in self.clearinghouse.markets:
                count += self.clearinghouse.cancel_all(
                    owner, None if market is None else str(market)
                )
        wanted = None if market is None else str(market)
        if wanted is not None and ":" in wanted:
            wanted = self._canonical_pair(wanted)
        for tid in self.trading.twaps_of(owner):  # and its TWAPs, by the same filter
            t = self.trading.twaps.peek(tid)
            if (scope == "all" or (scope == "perps") == t.perp) and wanted in (None, t.market):
                count += self._cancel_twap(owner, tid)
        return count

    def _op_schedule_cancel(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Hyperliquid's dead man's switch: at block time ``time`` every order, trigger and TWAP
        of the sender is cancelled — unless it schedules again or clears it first (no ``time``).
        At least CANCEL_MIN_DELAY ahead; at most CANCEL_TRIGGERS_PER_DAY may fire a block day."""
        from .trading import CANCEL_MIN_DELAY, CANCEL_TRIGGERS_PER_DAY

        now = Decimal(str(self._block_clock()))
        day = int(now // 86400)
        _t, d, fired = self.trading.cancel_at.get(tx.sender, (ZERO, day, 0))
        fired = fired if d == day else 0
        raw = tx.params.get("time")
        if raw is None:
            if tx.sender in self.trading.cancel_at:
                del self.trading.cancel_at[tx.sender]
            data: Dict[str, Any] = {"cleared": True}
        else:
            try:
                when = Decimal(str(raw))
            except (ArithmeticError, ValueError):
                return ExchangeExecResult(success=False, error="time is a block time")
            if not when.is_finite() or when < now + CANCEL_MIN_DELAY:
                return ExchangeExecResult(
                    success=False, error=f"time must be at least {CANCEL_MIN_DELAY} s ahead"
                )
            if fired >= CANCEL_TRIGGERS_PER_DAY:
                return ExchangeExecResult(
                    success=False,
                    error=f"at most {CANCEL_TRIGGERS_PER_DAY} scheduled cancels fire a day",
                )
            self.trading.cancel_at[tx.sender] = (when, day, fired)
            data = {"time": str(when)}
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.SCHEDULE_CANCEL], data=data
        )

    @_pinned
    def run_scheduled_cancels(self, now: Decimal) -> List[Dict[str, Any]]:
        """The block's tick for scheduled cancels: each due account's orders, triggers and TWAPs
        are cancelled (at most CANCELS_PER_BLOCK accounts a block; the rest wait one)."""
        from .trading import CANCELS_PER_BLOCK

        events: List[Dict[str, Any]] = []
        for owner in self.trading.due_cancels(now)[:CANCELS_PER_BLOCK]:
            when, day, fired = self.trading.cancel_at[owner]
            today = int(now // 86400)
            try:
                with undo.atomic():
                    count = self._cancel_all_of(owner, covered=True)
            except Exception as e:  # noqa: BLE001 — deterministic; never fails the block
                logger.warning("scheduled cancel of %s failed: %s", owner, e)
                count = 0
            self.trading.cancel_at[owner] = (ZERO, today, (fired if day == today else 0) + 1)
            events.append(
                {"type": "scheduled_cancel", "owner": owner, "time": str(when), "cancelled": count}
            )
        return events

    # ── exchange actions of EVM contracts (qrdx/contracts/exchange_evm.py) ──

    def queue_evm_actions(self, actions: List[Tuple[str, str, str, int]]) -> None:
        """An accepted EVM section's exchange actions — (contract, operation, params JSON,
        exchange gas limit), in the order its transactions sent them — queued for the start of
        the next block. Called as the section commits, inside the block being processed (its
        height keys them)."""
        if not actions:
            return
        prefix = f"{int(self._current_block_height):012d}:"
        q = self.trading.evm_actions
        start = sum(1 for k, _v in q.peek_items() if k.startswith(prefix))
        for i, (sender, op, params, gas) in enumerate(actions, start):
            q[f"{prefix}{i:05d}"] = (str(sender), str(op), str(params), int(gas))

    def _queued_evm_actions(self) -> List[Tuple[str, ExchangeTransaction]]:
        from .trading import EVM_ACTIONS_PER_BLOCK

        q = self.trading.evm_actions
        if not len(q):
            return []
        out: List[Tuple[str, ExchangeTransaction]] = []
        for key, (sender, op, params, gas) in sorted(q.peek_items())[:EVM_ACTIONS_PER_BLOCK]:
            try:
                decoded = json.loads(params)
            except ValueError:
                decoded = {}
            op_type = ExchangeOpType[op]
            action = _EvmAction(
                key,
                op_type=op_type,
                sender=sender,
                nonce=0,
                params=decoded if isinstance(decoded, dict) else {},
                gas_limit=int(gas),
                gas_price=0,
                timestamp=1.0,
            )
            out.append((key, action))
        return out

    def evm_action_txs(self) -> List[ExchangeTransaction]:
        """The queued actions the next block runs, as the operations they are, oldest first
        (what the block's balance preloads must cover)."""
        return [action for _key, action in self._queued_evm_actions()]

    @_pinned
    def run_evm_actions(self) -> List[Dict[str, Any]]:
        """The start of a block, before its transactions: the actions EVM contracts sent in the
        blocks before, each as an operation of its contract's account, all or nothing (one that
        fails changes nothing; it was checked to be well formed when it was sent). At most
        EVM_ACTIONS_PER_BLOCK; the rest wait a block."""
        events: List[Dict[str, Any]] = []
        for key, action in self._queued_evm_actions():
            del self.trading.evm_actions[key]
            try:
                with self.atomic():
                    result = self._execute_op(action)
                    if not result.success:
                        raise _OperationFailed(result)
            except _OperationFailed as refused:
                result = refused.result
            except Exception as e:  # noqa: BLE001 — deterministic; never fails the block
                logger.warning("EVM action %s of %s failed: %s", key, action.sender, e)
                result = ExchangeExecResult(success=False, error=str(e) or type(e).__name__)
            # Its receipt, fills and order history in the node's journal, under its own hash.
            action.gas_used = result.gas_used = min(
                int(action.gas_limit), int(result.gas_used or action.gas_limit)
            )
            action.success, action.result, action.error = result.success, result.data, result.error
            self._block_exchange_txs.append(action)
            self._block_results.append(result)
            events.append(
                {
                    "type": "evm_action",
                    "key": key,
                    "owner": action.sender,
                    "op": action.op_type.name,
                    "success": result.success,
                    "error": result.error,
                    "id": action.tx_hash()[:16],
                    **({"data": result.data} if result.success and result.data else {}),
                }
            )
        return events

    def _op_batch(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Run the actions in order as the sender, all or nothing: the first that fails fails
        the batch, and the operation's undo scope puts back everything before it. Gas: the
        batch's own plus each action's, within the batch's gas limit — an action may use what
        the earlier ones left."""
        batch_hash = tx.tx_hash()
        used = EXCHANGE_GAS_COSTS[ExchangeOpType.BATCH]
        results = []
        for i, (op, params) in enumerate(batch_actions(tx.params)):
            action = _BatchAction(
                batch_hash,
                i,
                op_type=op,
                sender=tx.sender,
                nonce=0,
                params=params,
                gas_limit=max(0, tx.gas_limit - used),
                gas_price=tx.gas_price,
                chain_id=tx.chain_id,
                timestamp=tx.timestamp,
            )
            base = EXCHANGE_GAS_COSTS[op]
            if action.gas_limit < base:
                return ExchangeExecResult(
                    success=False,
                    gas_used=tx.gas_limit,
                    error=f"action {i} ({op.name}): out of gas",
                )
            try:
                result = self._execute_op(action)
            except (ValueError, KeyError, TypeError, ArithmeticError) as e:
                result = ExchangeExecResult(success=False, error=str(e) or type(e).__name__)
            used += result.gas_used or base
            if used > tx.gas_limit:
                return ExchangeExecResult(
                    success=False, gas_used=tx.gas_limit, error=f"action {i}: out of gas"
                )
            if not result.success:
                return ExchangeExecResult(
                    success=False,
                    gas_used=used,
                    error=f"action {i} ({op.name}): {result.error}",
                )
            results.append({"op": op.name, "order_id": action.tx_hash()[:16], **result.data})
        return ExchangeExecResult(success=True, gas_used=used, data={"results": results})

    def _op_perp_cancel(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        try:
            self.clearinghouse.cancel_order(tx.sender, str(p["market_id"]), str(p["order_id"]))
        except (ClearinghouseError, ValueError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_CANCEL]
        )

    def _op_update_oracle(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        pair = p["pair"]
        price = Decimal(str(p["price"]))
        # The oracle price is what perps execute, settle and liquidate at — so only an
        # authorized reporter may set it (constants.ORACLE_REPORTERS). Unrestricted, any
        # user could move the price their own position closes at.
        from .. import constants

        if tx.sender.lower() not in {a.lower() for a in constants.ORACLE_REPORTERS}:
            return ExchangeExecResult(
                success=False, error="sender is not an authorized oracle reporter"
            )
        if not price.is_finite() or price <= 0:
            return ExchangeExecResult(success=False, error="oracle price must be positive")
        base, _, quote = pair.partition(":")
        market_id = Clearinghouse.market_id(base, quote or constants.PERP_QUOTE)
        m = self.clearinghouse.markets.get(market_id)
        if m is not None and Clearinghouse.contained(m):
            return ExchangeExecResult(
                success=False, error=f"{market_id} is not priced by reporters or votes"
            )
        if m is not None:
            # As the validators' oracle walks (``_aggregate_votes``): at most ORACLE_MAX_STEP_BPS
            # a second of block time from the last price — a reporter cannot jump it either.
            step = Decimal(int(constants.ORACLE_MAX_STEP_BPS)) / 10_000
            now = Decimal(str(self._block_clock()))
            prev, prev_time = m.oracle_price, m.oracle_time
            if step > 0 and prev > 0 and prev_time > 0 and now > prev_time:
                bound = step * (now - prev_time)
                lo, hi = prev * (1 - min(bound, Decimal("0.99"))), prev * (1 + bound)
                price = min(max(price, lo), hi).quantize(Decimal(1).scaleb(-18))

        oracle = self._oracles.get(pair)
        if oracle is None:
            # Auto-create oracle for new pairs
            oracle = TWAPOracle(pool_id=pair)
            self._oracles[pair] = oracle
            self.router.register_oracle(pair, oracle)

        oracle.record(price, timestamp=self._current_block_timestamp)

        # Price the perp market that tracks this pair: "BTC:USD" → BTC-USD-PERP.
        if m is not None:
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
        """Seed the committee from a genesis block's ``validator_set`` (address, stake) — for a
        manager with no chain behind it (tests, tools). On a node the committee is set before
        every block from the chain-derived validator set (block_processor.ensure_oracle_committee).
        A genesis without a validator set leaves votes disabled (None)."""
        if self.oracle_committee is not None:
            return
        try:
            content = (
                json.loads(genesis_content) if isinstance(genesis_content, str) else genesis_content
            )
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
        """A committee member's USD prices, keyed by market base ("BTC" → BTC-USD-PERP), and
        other venues' perp prices ("BTC:perp", the mark's third input). Votes only for existing
        markets; each replaces the voter's previous one for that market. A vote may also attest
        bridge deposits (``deposits``, docs/BRIDGE.md): the one that brings a deposit to a
        quorum mints it."""
        from .. import constants

        committee = self._oracle_members()
        if not committee or tx.sender.lower() not in committee:
            return ExchangeExecResult(success=False, error="sender is not in the oracle committee")
        prices = tx.params.get("prices", {})
        deposits_raw = tx.params.get("deposits", [])
        heads_raw = tx.params.get("heads", [])
        freeze_raw = tx.params.get("freeze", [])
        if not isinstance(freeze_raw, list) or len(freeze_raw) > MAX_VOTE_FREEZES:
            return ExchangeExecResult(
                success=False, error=f"a vote freezes at most {MAX_VOTE_FREEZES} markets"
            )
        if not isinstance(deposits_raw, list) or len(deposits_raw) > MAX_VOTE_DEPOSITS:
            return ExchangeExecResult(
                success=False, error=f"a vote attests at most {MAX_VOTE_DEPOSITS} deposits"
            )
        if not isinstance(heads_raw, list) or len(heads_raw) > MAX_VOTE_HEADS:
            return ExchangeExecResult(
                success=False, error=f"a vote attests at most {MAX_VOTE_HEADS} chain heads"
            )
        if (
            not isinstance(prices, dict)
            or len(prices) > self.MAX_VOTE_PRICES
            or not (prices or deposits_raw or heads_raw or freeze_raw)
        ):
            return ExchangeExecResult(
                success=False,
                error=f"a vote carries 1 to {self.MAX_VOTE_PRICES} prices, or only attestations",
            )
        try:
            heads = [parse_head(raw) for raw in heads_raw]
        except BridgeError as e:
            return ExchangeExecResult(success=False, error=f"chain head: {e}")
        if len({h.chain for h in heads}) != len(heads):
            return ExchangeExecResult(success=False, error="one head per chain")
        deposits: List[Deposit] = []
        if deposits_raw:
            assets = configured_assets()
            for raw in deposits_raw:
                try:
                    deposits.append(parse_deposit(raw, assets))
                except BridgeError as e:
                    return ExchangeExecResult(success=False, error=f"deposit: {e}")
        parsed: Dict[str, Decimal] = {}
        perp: Dict[str, Decimal] = {}
        ignored: List[str] = []
        for key in sorted(prices):
            base = str(key)
            is_perp = base.endswith(":perp")
            if is_perp:
                base = base[: -len(":perp")]
            market_id = Clearinghouse.market_id(base, constants.PERP_QUOTE)
            if market_id not in self.clearinghouse.markets:
                return ExchangeExecResult(success=False, error=f"no market {market_id}")
            try:
                price = Decimal(str(prices[key]))
            except Exception:
                return ExchangeExecResult(success=False, error=f"invalid price for {base}")
            if not price.is_finite() or price <= 0:
                return ExchangeExecResult(success=False, error=f"invalid price for {base}")
            m = self.clearinghouse.markets[market_id]
            if Clearinghouse.contained(m) and not Clearinghouse.frozen(m, self._block_clock()):
                # Its deployer prices it until the validators freeze it. Skipped, not refused: a
                # freeze can lapse between a vote and its block, and the rest of the vote stands.
                ignored.append(str(key))
                continue
            (perp if is_perp else parsed)[market_id] = price
        freezes = []
        for raw in freeze_raw:
            target = self.clearinghouse.markets.get(str(raw))
            if target is None or not Clearinghouse.contained(target) or target.settled_price > 0:
                ignored.append(f"freeze:{raw}")  # (settled since the vote, say)
                continue
            freezes.append(target.id)
        now = Decimal(str(self._block_clock()))
        voter = tx.sender.lower()
        for market_id in sorted(set(freezes)):
            self.trading.freeze_votes[f"{market_id}|{voter}"] = str(now)
        for market_id, price in parsed.items():
            self.oracle_votes.setdefault(market_id, {})[voter] = (price, now)
        for market_id, price in perp.items():
            self.perp_votes.setdefault(market_id, {})[voter] = (price, now)
        data: Dict[str, Any] = {"markets": sorted(parsed)}
        if perp:
            data["perp_prices"] = sorted(perp)
        if freezes:
            data["freeze"] = sorted(set(freezes))
        if ignored:
            data["ignored"] = ignored
        if heads:
            data["heads"] = [h.chain for h in heads]
            attested = [h.chain for h in heads if self.bridge.attest_head(h, voter, now, committee)]
            if attested:
                data["attested_heads"] = attested
        if deposits:
            data["deposits"] = [d.id for d in deposits]
            minted = []
            for d in deposits:
                if not self.bridge.attest(d, voter, now, committee):
                    continue
                try:
                    self._mint_deposit(d)
                except TokenError as e:  # left pending: a later attestation retries
                    logger.warning(
                        "bridge deposit %s reached a quorum but cannot mint: %s", d.id, e
                    )
                    continue
                self.bridge.complete(d)
                minted.append(d.id)
            if minted:
                data["minted"] = minted
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ORACLE_VOTE], data=data
        )

    def _mint_deposit(self, d: Deposit) -> None:
        """Mint a deposit that reached a quorum to its recipient, creating the bridged token at
        its first deposit (zero supply, the bridge's mint authority)."""
        asset = configured_assets()[(d.chain, d.token)]
        if self.tokens.get(asset.address) is None:
            self.tokens.deploy(
                asset.address,
                BRIDGE_AUTHORITY,
                self._current_block_height,
                name=f"{asset.symbol} (bridged)",
                symbol=asset.symbol,
                decimals=asset.decimals,
                initial_supply=0,
                mint_authority=BRIDGE_AUTHORITY,
            )
            # Its symbol is a reserved ticker: the bridge's token holds it (no one buys it).
            ticker = asset.symbol.upper()
            if self.trading.tickers.peek(ticker) is None and re.fullmatch(
                r"[A-Z0-9]{1,12}", ticker
            ):
                self.trading.tickers[ticker] = str(asset.address).lower()
        minted = self.tokens.mint(asset.address, BRIDGE_AUTHORITY, d.amount)
        self._record_token_delta(d.to, asset.address, minted)

    def _op_bridge_withdraw(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Burn ``amount`` of a bridged token and record the withdrawal to ``to`` on its source
        chain, for the lockbox's custodian to release (docs/BRIDGE.md)."""
        p = tx.params
        asset = asset_by_token(str(p["token_address"]))
        if asset is None:
            return ExchangeExecResult(success=False, error="BRIDGE_WITHDRAW: not a bridged token")
        to = str(p["to"]).strip().lower()
        if not (
            len(to) == 42 and to.startswith("0x") and all(c in "0123456789abcdef" for c in to[2:])
        ):
            return ExchangeExecResult(
                success=False,
                error="BRIDGE_WITHDRAW: the recipient is a 0x address on the source chain",
            )
        try:
            v = token_amount(p["amount"])
            if v != v.quantize(Decimal(1).scaleb(-asset.decimals)):
                raise TokenError(f"{asset.symbol} has {asset.decimals} decimals")
            self.tokens.require(asset.address)
            avail = self.available_token_balance(tx.sender, asset.address)
            if self.enforce_spot_settlement and (avail is None or avail < v):
                raise TokenError(f"insufficient token balance: need {v}, available {avail}")
            self.tokens.burn(asset.address, v)
        except TokenError as e:
            return ExchangeExecResult(success=False, error=f"BRIDGE_WITHDRAW: {e}")
        self._record_token_delta(tx.sender, asset.address, -v)
        wid = self.bridge.record_withdrawal(
            {
                "chain": asset.chain,
                "token": asset.source_token,
                "to": to,
                "amount": str(v),
                "from": tx.sender,
                "height": self._current_block_height,
                "tx_hash": tx.tx_hash(),
            }
        )
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.BRIDGE_WITHDRAW],
            data={"withdrawal_id": wid, "amount": str(v), "chain": asset.chain, "to": to},
        )

    def _oracle_members(self) -> Dict[str, Decimal]:
        """The committee less the members slashing evidence has convicted."""
        committee = self.oracle_committee or {}
        excluded: Set[str] = getattr(self, "oracle_excluded", set())
        return {v: w for v, w in committee.items() if v not in excluded}

    def apply_oracle_votes(self, now) -> None:
        """Each block (before the clearinghouse tick): set every voted market's oracle to the
        stake-weighted median of fresh committee votes — when they carry a majority of the
        committee's stake. Without that the oracle is not refreshed, and goes stale. Votes
        older than the window are dropped, so the state stays small. Votes for other venues'
        perp price (``"<base>:perp"`` keys) set each market's external price the same way."""
        now = Decimal(str(now))
        self.bridge.expire(now)  # deposits that never reached a quorum
        committee = self._oracle_members()
        if not committee:
            return
        self._apply_freeze_votes(committee, now)
        self.oracle_votes = self._aggregate_votes(
            self.oracle_votes,
            committee,
            now,
            self.clearinghouse.set_oracle_price,
            lambda m: (m.oracle_price, m.oracle_time),
        )
        self.perp_votes = self._aggregate_votes(
            self.perp_votes,
            committee,
            now,
            self.clearinghouse.set_external_perp_price,
            lambda m: (m.external_price, m.external_time),
        )

    def _apply_freeze_votes(self, committee: Dict[str, Decimal], now: Decimal) -> None:
        """Validators' votes to freeze a deployer market (ORACLE_VOTE ``freeze``): while fresh
        votes carry more than two thirds of the committee's stake, the market is held to
        reduce-only orders and its oracle is the validators' — until a vote window after the
        last block they did. Stale votes, non-members' and settled markets' are dropped."""
        from .. import constants

        votes = self.trading.freeze_votes
        if not len(votes):
            return
        max_age = Decimal(constants.PERP_ORACLE_VOTE_MAX_AGE)
        weight: Dict[str, Decimal] = {}
        for key, when in sorted(votes.peek_items()):
            market_id, voter = key.rsplit("|", 1)
            m = self.clearinghouse.markets.get(market_id)
            if (
                voter not in committee
                or now - Decimal(when) > max_age
                or m is None
                or m.settled_price > 0
            ):
                del votes[key]
                continue
            weight[market_id] = weight.get(market_id, ZERO) + committee[voter]
        total = sum(committee.values(), ZERO)
        for market_id, w in sorted(weight.items()):
            if w * 3 > total * 2:
                self.clearinghouse.freeze(market_id, now + max_age)

    def _aggregate_votes(
        self, all_votes, committee, now: Decimal, apply, current
    ) -> Dict[str, Any]:
        """Per market: drop votes older than the window or from non-members; when the fresh
        ones carry a majority of the committee's stake and number at least ORACLE_MIN_VOTERS
        (or the whole committee), ``apply`` their stake-weighted (lower) median — moved at most
        ORACLE_MAX_STEP_BPS a second of block time from the current price (``current``), so a
        captured or mistaken majority can only walk the price, while the circuit breaker
        watches. Votes outside ORACLE_OUTLIER_BAND_BPS of the median are recorded against
        their validators. Returns the votes kept."""
        from .. import constants

        max_age = Decimal(constants.PERP_ORACLE_VOTE_MAX_AGE)
        min_voters = min(int(constants.ORACLE_MIN_VOTERS), len(committee))
        step = Decimal(int(constants.ORACLE_MAX_STEP_BPS)) / 10_000
        band = Decimal(int(constants.ORACLE_OUTLIER_BAND_BPS)) / 10_000
        total = sum(committee.values(), ZERO)
        kept: Dict[str, Any] = {}
        for market_id in sorted(all_votes):
            votes = {
                v: pt
                for v, pt in all_votes[market_id].items()
                if v in committee and now - pt[1] <= max_age
            }
            if votes:
                kept[market_id] = votes
            if market_id not in self.clearinghouse.markets or len(votes) < max(1, min_voters):
                continue
            m = self.clearinghouse.markets[market_id]
            if Clearinghouse.contained(m) and not Clearinghouse.frozen(m, now):
                continue  # its deployer or its spot market prices it, until a freeze
            weighted = sorted((price, committee[v]) for v, (price, _t) in votes.items())
            weight = sum((w for _p, w in weighted), ZERO)
            if weight * 2 <= total:
                continue
            acc = ZERO
            median = ZERO
            for price, w in weighted:  # lower weighted median
                acc += w
                if acc * 2 >= weight:
                    median = price
                    break
            if band > 0:
                for v in sorted(votes):
                    if abs(votes[v][0] - median) > median * band:
                        self.oracle_outliers[v] = self.oracle_outliers.get(v, 0) + 1
            prev, prev_time = current(self.clearinghouse.markets[market_id])
            if step > 0 and prev > 0 and prev_time > 0 and now > prev_time:
                bound = step * (now - prev_time)
                lo, hi = prev * (1 - min(bound, Decimal("0.99"))), prev * (1 + bound)
                median = min(max(median, lo), hi).quantize(Decimal(1).scaleb(-18))
            apply(market_id, median, now)
        return kept

    def oracle_state_hash(self) -> bytes:
        """The live votes. (Not the committee: see block_processor.ensure_oracle_committee —
        it is a function of genesis and the staking ops, which the chain already commits to.)"""
        blob = json.dumps(self.oracle_state(), sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()

    def oracle_state(self) -> Any:
        """What ``oracle_state_hash`` commits to (and a state proof's ``oracle`` part holds)."""
        votes = {
            m: {v: [str(p), str(t)] for v, (p, t) in sorted(vs.items())}
            for m, vs in sorted(self.oracle_votes.items())
        }
        state: Any = votes
        if self.oracle_vote_seqs:  # absent while no vote has run (a root unchanged till then)
            state = {"votes": votes, "seqs": dict(sorted(self.oracle_vote_seqs.items()))}
            if self.oracle_outliers:
                state["outliers"] = dict(sorted(self.oracle_outliers.items()))
            if self.perp_votes:
                state["perp"] = {
                    m: {v: [str(p), str(t)] for v, (p, t) in sorted(vs.items())}
                    for m, vs in sorted(self.perp_votes.items())
                }
        return state

    def exchange_proof_root(self, height: Optional[int] = None) -> bytes:
        """The exchange tree root (qrdx/exchange/proofs.py): every in-memory entry under one root,
        bound into the signed state root beside the database tree's. With the block's
        ``height``, the trees are kept for proofs of it."""
        from .proofs import fold

        return fold(self, height)

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
        changed. The small parts (each market's own fields, the oracles, the votes) are
        recomputed. QRDX_VERIFY_STATE_COMMITMENTS=1 checks every part from scratch."""
        import blake3

        from ..crypto.hashing import STATE_ROOT_SIZE

        pools = Section("pools")
        for pid in sorted(self.pool_manager._pools):
            pools.value(pid).raw(self.pool_manager._pools[pid].cached_digest())
        books = Section("books")
        for pair_key in sorted(self._order_books):
            books.value(pair_key).raw(self._order_books[pair_key].cached_digest())
        oracles = Section("oracles")
        for pair_key in sorted(self._oracles):
            o = self._oracles[pair_key]
            oracles.value([pair_key, str(o.latest_price or ZERO), o.observation_count])
        perps = Section("perp_engine")
        for market_id in sorted(self.perp_engine._markets):
            m = self.perp_engine._markets[market_id]
            perps.value(
                [
                    market_id,
                    str(m.index_price),
                    str(m.mark_price),
                    str(m.open_interest_long),
                    str(m.open_interest_short),
                    str(m.insurance_fund),
                ]
            )
        hasher = blake3.blake3(b"QRDX-EXCHANGE-ROOT-v2\x00")
        for part in (
            pools.digest(),
            books.digest(),
            oracles.digest(),
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
                (
                    f"{market_id}:{market.index_price}:{market.mark_price}:"
                    f"{market.open_interest_long}:{market.open_interest_short}:"
                    f"{market.insurance_fund}"
                ).encode(),
                digest_size=16,
            ).digest()
            hasher.update(market_hash)

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
        CREATED during the block (new pools, order books, oracles, perp markets
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
            "oracles": copy.deepcopy(self._oracles),
            "perp_markets": copy.deepcopy(self.perp_engine._markets),
            "perp_positions": copy.deepcopy(self.perp_engine._positions),
            "perp_owner_positions": copy.deepcopy(self.perp_engine._owner_positions),
            "perp_pos_sequence": self.perp_engine._pos_sequence,
            "perp_paused": self.perp_engine._paused,
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

    def get_oracle(self, pair: str) -> Optional[TWAPOracle]:
        return self._oracles.get(pair)

    def get_perp_market(self, market_id: str):
        return self.perp_engine.get_market(market_id)

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
            "perp_markets": self.perp_engine.market_count,
            "total_swaps": self._total_swaps,
            "total_orders": self._total_orders,
            "total_positions": self._total_positions,
            "block_height": self._current_block_height,
        }
