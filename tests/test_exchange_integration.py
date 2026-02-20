"""
Test suite for QRDX Exchange ↔ Blockchain Integration

Covers:
  - ExchangeTransaction creation, serialization, validation
  - ExchangeStateManager lifecycle (begin_block → process → finalize)
  - Deterministic state root computation
  - Nonce enforcement and replay protection
  - All 11 operation types through state manager
  - Block processor integration
  - Block revert / snapshot support
  - Consensus integration (execute_and_validate_exchange)
  - Block builder integration (exchange_state_root in block data)
  - Validator duties (oracle updates, fee share)
"""

import hashlib
import json
import time
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from qrdx.exchange.transactions import (
    EXCHANGE_GAS_COSTS,
    ExchangeOpType,
    ExchangeTransaction,
)
from qrdx.exchange.state_manager import (
    ExchangeExecResult,
    ExchangeStateManager,
)
from qrdx.exchange.block_processor import (
    build_oracle_update_tx,
    extract_exchange_transactions,
    get_validator_fee_share,
    process_exchange_transactions,
    validate_exchange_state_root,
)
from qrdx.exchange.amm import tick_to_sqrt_price

# Q96-format sqrt price at tick 0 (price = 1.0)
SQRT_PRICE_1 = str(tick_to_sqrt_price(0))


# ============================================================================
# Fixtures
# ============================================================================

ALICE = "0xPQ" + "a" * 64
BOB = "0xPQ" + "b" * 64
VALIDATOR = "0xPQ" + "v" * 64


@pytest.fixture(autouse=True)
def reset_state_manager():
    """Reset the singleton before every test."""
    ExchangeStateManager.reset_instance()
    yield
    ExchangeStateManager.reset_instance()


@pytest.fixture
def mgr() -> ExchangeStateManager:
    return ExchangeStateManager.get_instance()


def make_tx(
    op_type: ExchangeOpType,
    sender: str = ALICE,
    nonce: int = 0,
    params: dict = None,
    gas_limit: int = 0,
) -> ExchangeTransaction:
    """Helper to create an ExchangeTransaction with sensible defaults."""
    if gas_limit == 0:
        gas_limit = EXCHANGE_GAS_COSTS.get(op_type, 100_000)
    return ExchangeTransaction(
        op_type=op_type,
        sender=sender,
        nonce=nonce,
        params=params or {},
        gas_limit=gas_limit,
        gas_price=Decimal("1"),
    )


# ============================================================================
# 1. ExchangeTransaction — creation / serialization / hashing
# ============================================================================

class TestExchangeTransaction:
    """Tests for ExchangeTransaction dataclass."""

    def test_create_basic(self):
        tx = make_tx(ExchangeOpType.SWAP, params={"token_in": "QRDX", "token_out": "qETH", "amount_in": "100"})
        assert tx.op_type == ExchangeOpType.SWAP
        assert tx.sender == ALICE
        assert tx.nonce == 0

    def test_tx_hash_deterministic(self):
        tx1 = ExchangeTransaction(
            op_type=ExchangeOpType.SWAP, sender=ALICE, nonce=0,
            params={"token_in": "A", "token_out": "B", "amount_in": "1"},
            gas_limit=65_000, gas_price=Decimal("1"), timestamp=1000.0,
        )
        tx2 = ExchangeTransaction(
            op_type=ExchangeOpType.SWAP, sender=ALICE, nonce=0,
            params={"token_in": "A", "token_out": "B", "amount_in": "1"},
            gas_limit=65_000, gas_price=Decimal("1"), timestamp=2000.0,
        )
        # Timestamp is NOT included in canonical bytes → same hash
        assert tx1.tx_hash() == tx2.tx_hash()

    def test_tx_hash_changes_with_params(self):
        tx1 = make_tx(ExchangeOpType.SWAP, params={"token_in": "A", "token_out": "B", "amount_in": "1"})
        tx2 = make_tx(ExchangeOpType.SWAP, params={"token_in": "A", "token_out": "B", "amount_in": "2"})
        assert tx1.tx_hash() != tx2.tx_hash()

    def test_to_dict_from_dict(self):
        tx = make_tx(ExchangeOpType.PLACE_ORDER, params={
            "pair": "QRDX:qETH", "side": 1, "order_type": 1, "amount": "50", "price": "100",
        })
        d = tx.to_dict()
        assert d["op_type"] == int(ExchangeOpType.PLACE_ORDER)
        assert d["sender"] == ALICE

        tx2 = ExchangeTransaction.from_dict(d)
        assert tx2.op_type == tx.op_type
        assert tx2.sender == tx.sender
        assert tx2.nonce == tx.nonce
        assert tx2.params == tx.params
        assert tx2.tx_hash() == tx.tx_hash()

    def test_to_hex_from_hex(self):
        tx = make_tx(ExchangeOpType.CANCEL_ORDER, params={"order_id": "abc123"})
        hex_str = tx.to_hex()
        tx2 = ExchangeTransaction.from_hex(hex_str)
        assert tx2.tx_hash() == tx.tx_hash()

    def test_fee_calculation(self):
        tx = make_tx(ExchangeOpType.SWAP, params={"token_in": "A", "token_out": "B", "amount_in": "1"})
        tx.gas_used = 65_000
        assert tx.fee() == Decimal("65000")
        assert tx.max_fee() == Decimal("65000")

    def test_is_exchange_transaction_marker(self):
        tx = make_tx(ExchangeOpType.SWAP, params={"token_in": "A", "token_out": "B", "amount_in": "1"})
        assert tx.is_exchange_transaction() is True


# ============================================================================
# 2. ExchangeTransaction — validation
# ============================================================================

class TestExchangeTransactionValidation:
    """Tests for validate_basic() and _validate_params()."""

    def test_valid_swap(self):
        tx = make_tx(ExchangeOpType.SWAP, params={"token_in": "A", "token_out": "B", "amount_in": "1"})
        assert tx.validate_basic() is True

    def test_missing_sender(self):
        tx = make_tx(ExchangeOpType.SWAP, sender="", params={"token_in": "A", "token_out": "B", "amount_in": "1"})
        with pytest.raises(ValueError, match="Missing sender"):
            tx.validate_basic()

    def test_negative_nonce(self):
        tx = make_tx(ExchangeOpType.SWAP, nonce=-1, params={"token_in": "A", "token_out": "B", "amount_in": "1"})
        with pytest.raises(ValueError, match="non-negative"):
            tx.validate_basic()

    def test_zero_gas_limit(self):
        tx = ExchangeTransaction(
            op_type=ExchangeOpType.SWAP, sender=ALICE, nonce=0,
            params={"token_in": "A", "token_out": "B", "amount_in": "1"},
            gas_limit=0, gas_price=Decimal("1"),
        )
        with pytest.raises(ValueError, match="Gas limit"):
            tx.validate_basic()

    def test_create_pool_missing_params(self):
        tx = make_tx(ExchangeOpType.CREATE_POOL, params={"token0": "A"})
        with pytest.raises(ValueError, match="CREATE_POOL missing"):
            tx.validate_basic()

    def test_add_liquidity_missing_params(self):
        tx = make_tx(ExchangeOpType.ADD_LIQUIDITY, params={})
        with pytest.raises(ValueError, match="ADD_LIQUIDITY missing"):
            tx.validate_basic()

    def test_remove_liquidity_missing_params(self):
        tx = make_tx(ExchangeOpType.REMOVE_LIQUIDITY, params={})
        with pytest.raises(ValueError, match="REMOVE_LIQUIDITY missing"):
            tx.validate_basic()

    def test_swap_missing_params(self):
        tx = make_tx(ExchangeOpType.SWAP, params={"token_in": "A"})
        with pytest.raises(ValueError, match="SWAP missing"):
            tx.validate_basic()

    def test_place_order_missing_params(self):
        tx = make_tx(ExchangeOpType.PLACE_ORDER, params={})
        with pytest.raises(ValueError, match="PLACE_ORDER missing"):
            tx.validate_basic()

    def test_cancel_order_missing_params(self):
        tx = make_tx(ExchangeOpType.CANCEL_ORDER, params={})
        with pytest.raises(ValueError, match="CANCEL_ORDER missing"):
            tx.validate_basic()

    def test_open_position_missing_params(self):
        tx = make_tx(ExchangeOpType.OPEN_POSITION, params={})
        with pytest.raises(ValueError, match="OPEN_POSITION missing"):
            tx.validate_basic()

    def test_close_position_missing_params(self):
        tx = make_tx(ExchangeOpType.CLOSE_POSITION, params={})
        with pytest.raises(ValueError, match="CLOSE_POSITION missing"):
            tx.validate_basic()

    def test_partial_close_missing_params(self):
        tx = make_tx(ExchangeOpType.PARTIAL_CLOSE, params={})
        with pytest.raises(ValueError, match="PARTIAL_CLOSE missing"):
            tx.validate_basic()

    def test_add_margin_missing_params(self):
        tx = make_tx(ExchangeOpType.ADD_MARGIN, params={})
        with pytest.raises(ValueError, match="ADD_MARGIN missing"):
            tx.validate_basic()

    def test_update_oracle_missing_params(self):
        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, params={})
        with pytest.raises(ValueError, match="UPDATE_ORACLE missing"):
            tx.validate_basic()

    def test_valid_create_pool(self):
        tx = make_tx(ExchangeOpType.CREATE_POOL, params={
            "token0": "QRDX", "token1": "qETH", "fee_tier": 3000,
            "pool_type": "STANDARD", "initial_sqrt_price": "1000",
            "stake_amount": "10000",
        })
        assert tx.validate_basic() is True

    def test_valid_update_oracle(self):
        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, params={"pair": "QRDX:qETH", "price": "2000"})
        assert tx.validate_basic() is True


# ============================================================================
# 3. ExchangeStateManager — singleton and lifecycle
# ============================================================================

class TestExchangeStateManagerLifecycle:
    """Tests for state manager singleton, begin/finalize/revert block."""

    def test_singleton(self):
        m1 = ExchangeStateManager.get_instance()
        m2 = ExchangeStateManager.get_instance()
        assert m1 is m2

    def test_reset_instance(self):
        m1 = ExchangeStateManager.get_instance()
        ExchangeStateManager.reset_instance()
        m2 = ExchangeStateManager.get_instance()
        assert m1 is not m2

    def test_begin_block(self, mgr):
        mgr.begin_block(1, 1000.0)
        assert mgr._current_block_height == 1
        assert mgr._current_block_timestamp == 1000.0
        assert mgr._block_fees == Decimal("0")

    def test_finalize_block_returns_state_root(self, mgr):
        mgr.begin_block(1, 1000.0)
        root = mgr.finalize_block()
        assert isinstance(root, str)
        assert len(root) == 64  # blake2b-256 hex

    def test_state_root_deterministic(self, mgr):
        mgr.begin_block(1, 1000.0)
        root1 = mgr.finalize_block()
        # Reset and replay
        ExchangeStateManager.reset_instance()
        mgr2 = ExchangeStateManager.get_instance()
        mgr2.begin_block(1, 1000.0)
        root2 = mgr2.finalize_block()
        assert root1 == root2

    def test_state_root_changes_with_height(self, mgr):
        mgr.begin_block(1, 1000.0)
        root1 = mgr.finalize_block()
        mgr.begin_block(2, 2000.0)
        root2 = mgr.finalize_block()
        assert root1 != root2

    def test_get_stats(self, mgr):
        stats = mgr.get_stats()
        assert "pools" in stats
        assert "total_swaps" in stats
        assert "block_height" in stats


# ============================================================================
# 4. ExchangeStateManager — nonce enforcement
# ============================================================================

class TestNonceEnforcement:
    """Tests for replay protection via monotonic nonces."""

    def test_nonce_starts_at_zero(self, mgr):
        assert mgr.get_nonce(ALICE) == 0

    def test_nonce_increments_on_success(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                      params={"pair": "TEST:USD", "price": "100"})
        result = mgr.process_transaction(tx)
        assert result.success
        assert mgr.get_nonce(ALICE) == 1

    def test_nonce_rejects_replay(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                      params={"pair": "TEST:USD", "price": "100"})
        mgr.process_transaction(tx)

        # Replay same nonce
        tx2 = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                       params={"pair": "TEST:USD", "price": "200"})
        result = mgr.process_transaction(tx2)
        assert not result.success
        assert "nonce" in result.error.lower()

    def test_nonce_rejects_skip(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=5,
                      params={"pair": "TEST:USD", "price": "100"})
        result = mgr.process_transaction(tx)
        assert not result.success
        assert "nonce" in result.error.lower()

    def test_nonce_per_sender(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx_a = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                        params={"pair": "A:USD", "price": "100"})
        tx_b = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=BOB, nonce=0,
                        params={"pair": "B:USD", "price": "200"})
        assert mgr.process_transaction(tx_a).success
        assert mgr.process_transaction(tx_b).success
        assert mgr.get_nonce(ALICE) == 1
        assert mgr.get_nonce(BOB) == 1


# ============================================================================
# 5. ExchangeStateManager — gas enforcement
# ============================================================================

class TestGasEnforcement:
    """Tests for gas limit checks."""

    def test_gas_limit_too_low(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = ExchangeTransaction(
            op_type=ExchangeOpType.CREATE_POOL, sender=ALICE, nonce=0,
            params={
                "token0": "A", "token1": "B", "fee_tier": 3000,
                "pool_type": "STANDARD", "initial_sqrt_price": "1000",
                "stake_amount": "10000",
            },
            gas_limit=100,  # way too low for CREATE_POOL
            gas_price=Decimal("1"),
        )
        result = mgr.process_transaction(tx)
        assert not result.success
        assert "Gas limit too low" in result.error

    def test_gas_charged_on_success(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                      params={"pair": "X:Y", "price": "50"})
        result = mgr.process_transaction(tx)
        assert result.success
        assert result.gas_used == EXCHANGE_GAS_COSTS[ExchangeOpType.UPDATE_ORACLE]
        assert mgr.block_fees > Decimal("0")


# ============================================================================
# 6. ExchangeStateManager — operation handlers (all 11 types)
# ============================================================================

class TestOperationHandlers:
    """Tests for all 11 exchange operation types through state manager."""

    def test_create_pool(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = make_tx(ExchangeOpType.CREATE_POOL, sender=ALICE, nonce=0, params={
            "token0": "QRDX", "token1": "qETH", "fee_tier": 3000,
            "pool_type": "STANDARD", "initial_sqrt_price": SQRT_PRICE_1,
            "stake_amount": "10000",
        })
        result = mgr.process_transaction(tx)
        assert result.success
        assert "pool_id" in result.data
        assert mgr.pool_count == 1

    def _create_pool(self, mgr, sender=ALICE, nonce=0, token0="QRDX", token1="qETH"):
        tx = make_tx(ExchangeOpType.CREATE_POOL, sender=sender, nonce=nonce, params={
            "token0": token0, "token1": token1, "fee_tier": 3000,
            "pool_type": "STANDARD", "initial_sqrt_price": SQRT_PRICE_1,
            "stake_amount": "10000",
        })
        result = mgr.process_transaction(tx)
        assert result.success, result.error
        return result.data["pool_id"], result.data["pair"]

    def test_add_liquidity(self, mgr):
        mgr.begin_block(1, 1000.0)
        pool_id, _ = self._create_pool(mgr)
        tx = make_tx(ExchangeOpType.ADD_LIQUIDITY, sender=ALICE, nonce=1, params={
            "pool_id": pool_id, "tick_lower": -60, "tick_upper": 60, "amount": "500",
        })
        result = mgr.process_transaction(tx)
        assert result.success
        assert "position_id" in result.data

    def test_remove_liquidity(self, mgr):
        mgr.begin_block(1, 1000.0)
        pool_id, _ = self._create_pool(mgr)
        add_tx = make_tx(ExchangeOpType.ADD_LIQUIDITY, sender=ALICE, nonce=1, params={
            "pool_id": pool_id, "tick_lower": -60, "tick_upper": 60, "amount": "500",
        })
        add_result = mgr.process_transaction(add_tx)
        assert add_result.success

        rm_tx = make_tx(ExchangeOpType.REMOVE_LIQUIDITY, sender=ALICE, nonce=2, params={
            "pool_id": pool_id, "position_id": add_result.data["position_id"],
        })
        result = mgr.process_transaction(rm_tx)
        assert result.success

    def test_swap_via_amm(self, mgr):
        mgr.begin_block(1, 1000.0)
        pool_id, pair = self._create_pool(mgr)
        # Add liquidity first
        add_tx = make_tx(ExchangeOpType.ADD_LIQUIDITY, sender=ALICE, nonce=1, params={
            "pool_id": pool_id, "tick_lower": -600, "tick_upper": 600, "amount": "10000",
        })
        assert mgr.process_transaction(add_tx).success

        # Now swap (bob)
        swap_tx = make_tx(ExchangeOpType.SWAP, sender=BOB, nonce=0, params={
            "token_in": "QRDX", "token_out": "qETH", "amount_in": "100",
        })
        result = mgr.process_transaction(swap_tx)
        assert result.success
        assert Decimal(result.data["amount_out"]) > 0

    def test_place_order(self, mgr):
        mgr.begin_block(1, 1000.0)
        _, pair = self._create_pool(mgr)

        order_tx = make_tx(ExchangeOpType.PLACE_ORDER, sender=BOB, nonce=0, params={
            "pair": pair, "side": "buy", "order_type": "limit",
            "amount": "100", "price": "900",
        })
        result = mgr.process_transaction(order_tx)
        assert result.success
        assert "order_id" in result.data

    def test_cancel_order(self, mgr):
        mgr.begin_block(1, 1000.0)
        _, pair = self._create_pool(mgr)

        order_tx = make_tx(ExchangeOpType.PLACE_ORDER, sender=BOB, nonce=0, params={
            "pair": pair, "side": "buy", "order_type": "limit",
            "amount": "100", "price": "900",
        })
        order_result = mgr.process_transaction(order_tx)
        assert order_result.success

        cancel_tx = make_tx(ExchangeOpType.CANCEL_ORDER, sender=BOB, nonce=1, params={
            "order_id": order_result.data["order_id"], "pair": pair,
        })
        result = mgr.process_transaction(cancel_tx)
        assert result.success

    def test_update_oracle(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=VALIDATOR, nonce=0,
                      params={"pair": "QRDX:USDC", "price": "2.50"})
        result = mgr.process_transaction(tx)
        assert result.success
        oracle = mgr.get_oracle("QRDX:USDC")
        assert oracle is not None
        assert oracle.latest_price == Decimal("2.50")

    def test_open_position(self, mgr):
        mgr.begin_block(1, 1000.0)
        # Create perp market: create_market(base_token, quote_token, init_margin, maint_margin, max_lev)
        market = mgr.perp_engine.create_market("BTC")
        mgr.perp_engine.update_price(market.id, Decimal("50000"))
        tx = make_tx(ExchangeOpType.OPEN_POSITION, sender=BOB, nonce=0, params={
            "market_id": market.id, "side": "long", "size": "1",
            "leverage": "10", "price": "50000",
        })
        result = mgr.process_transaction(tx)
        assert result.success
        assert "position_id" in result.data

    def test_close_position(self, mgr):
        mgr.begin_block(1, 1000.0)
        market = mgr.perp_engine.create_market("ETH")
        mgr.perp_engine.update_price(market.id, Decimal("3000"))
        open_tx = make_tx(ExchangeOpType.OPEN_POSITION, sender=BOB, nonce=0, params={
            "market_id": market.id, "side": "long", "size": "5",
            "leverage": "5", "price": "3000",
        })
        open_result = mgr.process_transaction(open_tx)
        assert open_result.success

        close_tx = make_tx(ExchangeOpType.CLOSE_POSITION, sender=BOB, nonce=1, params={
            "position_id": open_result.data["position_id"], "price": "3100",
        })
        result = mgr.process_transaction(close_tx)
        assert result.success
        assert "pnl" in result.data

    def test_partial_close(self, mgr):
        mgr.begin_block(1, 1000.0)
        market = mgr.perp_engine.create_market("SOL")
        mgr.perp_engine.update_price(market.id, Decimal("100"))
        open_tx = make_tx(ExchangeOpType.OPEN_POSITION, sender=BOB, nonce=0, params={
            "market_id": market.id, "side": "long", "size": "10",
            "leverage": "5", "price": "100",
        })
        open_result = mgr.process_transaction(open_tx)
        assert open_result.success

        partial_tx = make_tx(ExchangeOpType.PARTIAL_CLOSE, sender=BOB, nonce=1, params={
            "position_id": open_result.data["position_id"],
            "close_size": "5", "price": "110",
        })
        result = mgr.process_transaction(partial_tx)
        assert result.success

    def test_add_margin(self, mgr):
        mgr.begin_block(1, 1000.0)
        market = mgr.perp_engine.create_market("AVAX")
        mgr.perp_engine.update_price(market.id, Decimal("30"))
        open_tx = make_tx(ExchangeOpType.OPEN_POSITION, sender=BOB, nonce=0, params={
            "market_id": market.id, "side": "long", "size": "10",
            "leverage": "5", "price": "30",
        })
        open_result = mgr.process_transaction(open_tx)
        assert open_result.success

        margin_tx = make_tx(ExchangeOpType.ADD_MARGIN, sender=BOB, nonce=1, params={
            "position_id": open_result.data["position_id"], "amount": "50",
        })
        result = mgr.process_transaction(margin_tx)
        assert result.success
        assert "new_margin" in result.data


# ============================================================================
# 7. Block processor — process_exchange_transactions
# ============================================================================

class TestBlockProcessor:
    """Tests for the block-level exchange processing function."""

    def test_empty_block(self):
        success, error, root = process_exchange_transactions(1, 1000.0, [])
        assert success
        assert error == ""
        assert len(root) == 64

    def test_single_oracle_update(self):
        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=VALIDATOR, nonce=0,
                      params={"pair": "TEST:USD", "price": "42"})
        success, error, root = process_exchange_transactions(1, 1000.0, [tx])
        assert success
        assert len(root) == 64

    def test_multiple_transactions(self):
        txs = [
            make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                     params={"pair": "A:B", "price": "10"}),
            make_tx(ExchangeOpType.UPDATE_ORACLE, sender=BOB, nonce=0,
                     params={"pair": "C:D", "price": "20"}),
        ]
        success, error, root = process_exchange_transactions(1, 1000.0, txs)
        assert success

    def test_failed_tx_non_critical(self):
        """A single failing tx should not invalidate the block."""
        txs = [
            make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                     params={"pair": "A:B", "price": "10"}),
            # This will fail because nonce=5 when expected 0
            make_tx(ExchangeOpType.UPDATE_ORACLE, sender=BOB, nonce=5,
                     params={"pair": "C:D", "price": "20"}),
        ]
        success, error, root = process_exchange_transactions(1, 1000.0, txs)
        # Block still succeeds — individual tx failure is non-critical
        assert success

    def test_deterministic_state_root(self):
        """Same transactions in same order produce identical state root."""
        txs = [
            make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                     params={"pair": "X:Y", "price": "100"}),
        ]
        _, _, root1 = process_exchange_transactions(1, 1000.0, txs)

        # Reset and replay
        ExchangeStateManager.reset_instance()
        _, _, root2 = process_exchange_transactions(1, 1000.0, txs)
        assert root1 == root2


# ============================================================================
# 8. Block processor — validate_exchange_state_root
# ============================================================================

class TestValidateExchangeStateRoot:
    """Tests for state root validation during block sync."""

    def test_valid_state_root(self):
        txs = [
            make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                     params={"pair": "A:B", "price": "10"}),
        ]
        _, _, root = process_exchange_transactions(1, 1000.0, txs)

        # Reset and validate
        ExchangeStateManager.reset_instance()
        valid, error = validate_exchange_state_root(1, 1000.0, txs, root)
        assert valid
        assert error == ""

    def test_invalid_state_root(self):
        txs = [
            make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                     params={"pair": "A:B", "price": "10"}),
        ]
        valid, error = validate_exchange_state_root(1, 1000.0, txs, "0" * 64)
        assert not valid
        assert "mismatch" in error.lower()


# ============================================================================
# 9. Block processor — extract and utility functions
# ============================================================================

class TestBlockProcessorUtilities:
    """Tests for extract, oracle builder, fee share."""

    def test_extract_exchange_transactions(self):
        class Block:
            pass
        block = Block()
        normal_tx = MagicMock()
        normal_tx.__class__ = type("RegularTx", (), {})()  # not an ExchangeTransaction
        del normal_tx.is_exchange_transaction  # remove auto mock attr

        ex_tx = make_tx(ExchangeOpType.SWAP, params={"token_in": "A", "token_out": "B", "amount_in": "1"})
        block.transactions = [normal_tx, ex_tx]

        extracted = extract_exchange_transactions(block)
        assert len(extracted) == 1
        assert extracted[0] is ex_tx

    def test_extract_no_transactions(self):
        class Block:
            pass
        block = Block()
        block.transactions = []
        assert extract_exchange_transactions(block) == []

    def test_extract_no_attr(self):
        class Block:
            pass
        block = Block()
        assert extract_exchange_transactions(block) == []

    def test_build_oracle_update_tx(self):
        tx = build_oracle_update_tx(VALIDATOR, "QRDX:USDC", Decimal("2.50"), 7)
        assert tx.op_type == ExchangeOpType.UPDATE_ORACLE
        assert tx.sender == VALIDATOR
        assert tx.nonce == 7
        assert tx.params["pair"] == "QRDX:USDC"
        assert tx.params["price"] == "2.50"

    def test_get_validator_fee_share(self):
        from qrdx.constants import EXCHANGE_FEE_VALIDATOR_SHARE
        share = get_validator_fee_share(Decimal("1000"), VALIDATOR)
        expected = (Decimal("1000") * EXCHANGE_FEE_VALIDATOR_SHARE).quantize(Decimal("0.00000001"))
        assert share == expected


# ============================================================================
# 10. Snapshot / revert support
# ============================================================================

class TestSnapshotRevert:
    """Tests for block revert during chain reorganization."""

    def test_snapshot_preserves_nonces(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                      params={"pair": "A:B", "price": "100"})
        mgr.process_transaction(tx)
        assert mgr.get_nonce(ALICE) == 1

        # Take snapshot and process more (price within 50% of previous)
        mgr.take_snapshot()
        mgr.begin_block(2, 2000.0)
        tx2 = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=1,
                       params={"pair": "A:B", "price": "110"})
        result2 = mgr.process_transaction(tx2)
        assert result2.success, result2.error
        assert mgr.get_nonce(ALICE) == 2

        # Revert
        mgr.revert_block()
        assert mgr.get_nonce(ALICE) == 1

    def test_revert_without_snapshot(self, mgr):
        """Revert with no snapshot should be a no-op."""
        mgr.begin_block(1, 1000.0)
        mgr.revert_block()  # should not raise


# ============================================================================
# 11. Consensus integration — execute_and_validate_exchange
# ============================================================================

class TestConsensusIntegration:
    """Tests for the consensus-level exchange validation function."""

    @pytest.mark.asyncio
    async def test_no_exchange_txs(self):
        from qrdx.consensus import execute_and_validate_exchange

        class Block:
            transactions = []
            height = 1
            timestamp = 1000.0

        valid, error = await execute_and_validate_exchange(Block())
        assert valid

    @pytest.mark.asyncio
    async def test_with_exchange_txs(self):
        from qrdx.consensus import execute_and_validate_exchange

        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                      params={"pair": "A:B", "price": "42"})

        class Block:
            transactions = [tx]
            height = 1
            number = 1
            timestamp = 1000.0
            exchange_state_root = None  # no expected root → skip root check

        valid, error = await execute_and_validate_exchange(Block())
        assert valid, error

    @pytest.mark.asyncio
    async def test_state_root_mismatch(self):
        from qrdx.consensus import execute_and_validate_exchange

        tx = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                      params={"pair": "A:B", "price": "42"})

        class Block:
            transactions = [tx]
            height = 1
            number = 1
            timestamp = 1000.0
            exchange_state_root = "f" * 64  # wrong root

        valid, error = await execute_and_validate_exchange(Block())
        assert not valid
        assert "mismatch" in error.lower()


# ============================================================================
# 12. Full block lifecycle — end-to-end
# ============================================================================

class TestFullBlockLifecycle:
    """End-to-end test: create pool → add liquidity → swap in one block."""

    def test_multi_op_block(self, mgr):
        mgr.begin_block(1, time.time())

        # Alice creates pool
        pool_tx = make_tx(ExchangeOpType.CREATE_POOL, sender=ALICE, nonce=0, params={
            "token0": "QRDX", "token1": "qETH", "fee_tier": 3000,
            "pool_type": "STANDARD", "initial_sqrt_price": SQRT_PRICE_1,
            "stake_amount": "10000",
        })
        pool_result = mgr.process_transaction(pool_tx)
        assert pool_result.success, pool_result.error
        pool_id = pool_result.data["pool_id"]
        pair = pool_result.data["pair"]

        # Alice adds liquidity (ticks must be multiples of tick_spacing=60)
        liq_tx = make_tx(ExchangeOpType.ADD_LIQUIDITY, sender=ALICE, nonce=1, params={
            "pool_id": pool_id, "tick_lower": -600,
            "tick_upper": 600, "amount": "10000",
        })
        assert mgr.process_transaction(liq_tx).success

        # Bob updates oracle (price = 1.0 matches tick 0 pool)
        oracle_tx = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=BOB, nonce=0,
                             params={"pair": pair, "price": "1"})
        assert mgr.process_transaction(oracle_tx).success

        # Bob swaps
        swap_tx = make_tx(ExchangeOpType.SWAP, sender=BOB, nonce=1, params={
            "token_in": "QRDX", "token_out": "qETH", "amount_in": "100",
        })
        swap_result = mgr.process_transaction(swap_tx)
        assert swap_result.success
        assert Decimal(swap_result.data["amount_out"]) > 0

        # Finalize
        root = mgr.finalize_block()
        assert len(root) == 64

        # Stats updated
        assert mgr._total_pools == 1
        assert mgr._total_swaps == 1
        assert mgr.block_fees > Decimal("0")

    def test_multi_block_sequence(self, mgr):
        """Process two sequential blocks."""
        # Block 1
        mgr.begin_block(1, 1000.0)
        tx1 = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=0,
                       params={"pair": "X:Y", "price": "100"})
        assert mgr.process_transaction(tx1).success
        root1 = mgr.finalize_block()

        # Block 2 (price within 50% of previous to avoid outlier rejection)
        mgr.begin_block(2, 2000.0)
        tx2 = make_tx(ExchangeOpType.UPDATE_ORACLE, sender=ALICE, nonce=1,
                       params={"pair": "X:Y", "price": "110"})
        assert mgr.process_transaction(tx2).success
        root2 = mgr.finalize_block()

        assert root1 != root2
        assert mgr.get_nonce(ALICE) == 2


# ============================================================================
# 13. ExchangeOpType enum coverage
# ============================================================================

class TestExchangeOpTypeEnum:
    """Tests for the operation type enum."""

    def test_all_types_defined(self):
        assert len(ExchangeOpType) == 11

    def test_values_unique(self):
        values = [e.value for e in ExchangeOpType]
        assert len(values) == len(set(values))

    def test_gas_costs_for_all_types(self):
        for op in ExchangeOpType:
            assert op in EXCHANGE_GAS_COSTS, f"Missing gas cost for {op.name}"

    def test_int_enum(self):
        assert ExchangeOpType.SWAP == 4
        assert int(ExchangeOpType.CREATE_POOL) == 1


# ============================================================================
# 14. ExchangeExecResult
# ============================================================================

class TestExchangeExecResult:
    """Tests for the execution result type."""

    def test_default_success(self):
        r = ExchangeExecResult()
        assert r.success is True
        assert r.gas_used == 0
        assert r.error == ""

    def test_failure(self):
        r = ExchangeExecResult(success=False, error="boom")
        assert not r.success
        assert r.error == "boom"

    def test_with_data(self):
        r = ExchangeExecResult(data={"pool_id": "abc"}, logs=[{"event": "PoolCreated"}])
        assert r.data["pool_id"] == "abc"
        assert len(r.logs) == 1


# ============================================================================
# 15. Edge cases
# ============================================================================

class TestEdgeCases:
    """Edge cases and error paths."""

    def test_cancel_nonexistent_order(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = make_tx(ExchangeOpType.CANCEL_ORDER, sender=ALICE, nonce=0,
                      params={"order_id": "nonexistent"})
        result = mgr.process_transaction(tx)
        assert not result.success
        assert "not found" in result.error.lower()

    def test_add_liquidity_nonexistent_pool(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = make_tx(ExchangeOpType.ADD_LIQUIDITY, sender=ALICE, nonce=0, params={
            "pool_id": "nonexistent", "tick_lower": -100,
            "tick_upper": 100, "amount": "100",
        })
        result = mgr.process_transaction(tx)
        assert not result.success
        assert "not found" in result.error.lower()

    def test_place_order_no_book(self, mgr):
        mgr.begin_block(1, 1000.0)
        tx = make_tx(ExchangeOpType.PLACE_ORDER, sender=ALICE, nonce=0, params={
            "pair": "DOESNT:EXIST", "side": 1, "order_type": 1,
            "amount": "100", "price": "50",
        })
        result = mgr.process_transaction(tx)
        assert not result.success
        assert "no order book" in result.error.lower()

    def test_process_tx_invalid_struct(self, mgr):
        """Transaction with invalid structure fails gracefully."""
        mgr.begin_block(1, 1000.0)
        tx = ExchangeTransaction(
            op_type=ExchangeOpType.SWAP, sender="", nonce=0,
            params={}, gas_limit=65000, gas_price=Decimal("1"),
        )
        result = mgr.process_transaction(tx)
        assert not result.success
