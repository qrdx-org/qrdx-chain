"""
QRDX Exchange Engine Precompile Tests

Step 4.4: Tests for exchange precompiles 0x0100–0x0104.
Covers: createPool, swap, addLiquidity, placeLimitOrder, cancelOrder.

Gates: Implemented, Verified, Security Tested, Consensus/Decentralized
"""

import struct
import hashlib
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

import sys
sys.path.insert(0, "/workspaces/qrdx-chain-denaro/py-evm")

from eth_typing import Address
from eth.vm.forks.qrdx.precompiles import (
    # Functions
    exchange_create_pool,
    exchange_swap,
    exchange_add_liquidity,
    exchange_place_limit_order,
    exchange_cancel_order,
    # Addresses
    EXCHANGE_CREATE_POOL_ADDRESS,
    EXCHANGE_SWAP_ADDRESS,
    EXCHANGE_ADD_LIQUIDITY_ADDRESS,
    EXCHANGE_PLACE_LIMIT_ORDER_ADDRESS,
    EXCHANGE_CANCEL_ORDER_ADDRESS,
    # Gas
    GAS_EXCHANGE_CREATE_POOL,
    GAS_EXCHANGE_SWAP,
    GAS_EXCHANGE_ADD_LIQUIDITY,
    GAS_EXCHANGE_PLACE_LIMIT_ORDER,
    GAS_EXCHANGE_CANCEL_ORDER,
    # Helpers
    _decode_uint256,
    _encode_uint256,
    _decode_token,
    _encode_token,
    AMOUNT_PRECISION,
    # State (for cleanup)
    _exchange_pools,
    _exchange_orderbooks,
    QRDX_PRECOMPILES,
)


def _encode_amount(value: Decimal) -> bytes:
    """Encode a Decimal amount into 32-byte uint256."""
    return _encode_uint256(value)


def _make_computation(input_data: bytes, sender: bytes = b'\x01' * 20) -> MagicMock:
    """Create a mock ComputationAPI for precompile testing."""
    comp = MagicMock()
    comp.msg.data = input_data
    comp.msg.sender = sender
    comp.output = b""
    comp.consume_gas = MagicMock()
    return comp


@pytest.fixture(autouse=True)
def _clean_exchange_state():
    """Reset exchange state between tests."""
    _exchange_pools.clear()
    _exchange_orderbooks.clear()
    yield
    _exchange_pools.clear()
    _exchange_orderbooks.clear()


# ── Registry Tests ────────────────────────────────────────────────────

class TestPrecompileRegistry:
    """Exchange precompiles must be in the QRDX_PRECOMPILES registry."""

    def test_create_pool_registered(self):
        assert EXCHANGE_CREATE_POOL_ADDRESS in QRDX_PRECOMPILES

    def test_swap_registered(self):
        assert EXCHANGE_SWAP_ADDRESS in QRDX_PRECOMPILES

    def test_add_liquidity_registered(self):
        assert EXCHANGE_ADD_LIQUIDITY_ADDRESS in QRDX_PRECOMPILES

    def test_place_limit_order_registered(self):
        assert EXCHANGE_PLACE_LIMIT_ORDER_ADDRESS in QRDX_PRECOMPILES

    def test_cancel_order_registered(self):
        assert EXCHANGE_CANCEL_ORDER_ADDRESS in QRDX_PRECOMPILES

    def test_total_precompile_count(self):
        """4 PQ + 5 exchange + 3 oracle = 12 total."""
        assert len(QRDX_PRECOMPILES) == 12


# ── createPool (0x0100) ──────────────────────────────────────────────

class TestCreatePool:
    """Precompile 0x0100: createPool tests."""

    def _create_pool_input(
        self,
        token_a="QRDX",
        token_b="USDC",
        fee_bps=3000,
        tick_spacing=60,
        initial_sqrt_price=2**96,
    ):
        return (
            _encode_token(token_a)
            + _encode_token(token_b)
            + fee_bps.to_bytes(4, "big")
            + struct.pack(">i", tick_spacing)
            + initial_sqrt_price.to_bytes(32, "big")
        )

    def test_create_pool_success(self):
        data = self._create_pool_input()
        comp = _make_computation(data)
        result = exchange_create_pool(comp)
        assert result.output != b"\x00" * 32
        assert len(result.output) == 32

    def test_create_pool_charges_gas(self):
        data = self._create_pool_input()
        comp = _make_computation(data)
        exchange_create_pool(comp)
        comp.consume_gas.assert_called_once()

    def test_create_pool_deterministic(self):
        data = self._create_pool_input()
        comp1 = _make_computation(data)
        exchange_create_pool(comp1)
        pool_id = comp1.output
        # Clean state and create again
        _exchange_pools.clear()
        comp2 = _make_computation(data)
        exchange_create_pool(comp2)
        assert comp2.output == pool_id

    def test_create_pool_duplicate_rejected(self):
        data = self._create_pool_input()
        comp1 = _make_computation(data)
        exchange_create_pool(comp1)
        assert comp1.output != b"\x00" * 32
        # Attempt duplicate
        comp2 = _make_computation(data)
        exchange_create_pool(comp2)
        assert comp2.output == b"\x00" * 32

    def test_create_pool_same_token_rejected(self):
        data = self._create_pool_input(token_a="QRDX", token_b="QRDX")
        comp = _make_computation(data)
        exchange_create_pool(comp)
        assert comp.output == b"\x00" * 32

    def test_create_pool_zero_fee_rejected(self):
        data = self._create_pool_input(fee_bps=0)
        comp = _make_computation(data)
        exchange_create_pool(comp)
        assert comp.output == b"\x00" * 32

    def test_create_pool_excessive_fee_rejected(self):
        data = self._create_pool_input(fee_bps=10_001)
        comp = _make_computation(data)
        exchange_create_pool(comp)
        assert comp.output == b"\x00" * 32

    def test_create_pool_negative_tick_spacing_rejected(self):
        data = self._create_pool_input(tick_spacing=-1)
        comp = _make_computation(data)
        exchange_create_pool(comp)
        assert comp.output == b"\x00" * 32

    def test_create_pool_zero_sqrt_price_rejected(self):
        data = self._create_pool_input(initial_sqrt_price=0)
        comp = _make_computation(data)
        exchange_create_pool(comp)
        assert comp.output == b"\x00" * 32

    def test_create_pool_short_input_rejected(self):
        comp = _make_computation(b"\x00" * 50)
        exchange_create_pool(comp)
        assert comp.output == b"\x00" * 32

    def test_create_pool_stores_state(self):
        data = self._create_pool_input()
        comp = _make_computation(data)
        exchange_create_pool(comp)
        pool_id = comp.output
        assert pool_id in _exchange_pools
        pool = _exchange_pools[pool_id]
        assert pool["token_a"] == "QRDX"
        assert pool["token_b"] == "USDC"
        assert pool["fee_bps"] == 3000


# ── swap (0x0101) ────────────────────────────────────────────────────

class TestSwap:
    """Precompile 0x0101: swap tests."""

    def _setup_pool(self):
        """Create a pool with liquidity for swap tests."""
        token_a = _encode_token("QRDX")
        token_b = _encode_token("USDC")
        fee_bps = (3000).to_bytes(4, "big")
        tick_spacing = struct.pack(">i", 60)
        sqrt_price = (2**96).to_bytes(32, "big")
        data = token_a + token_b + fee_bps + tick_spacing + sqrt_price
        comp = _make_computation(data)
        exchange_create_pool(comp)
        pool_id = comp.output
        # Add liquidity
        pool = _exchange_pools[pool_id]
        pool["liquidity"] = 10**18  # ample liquidity
        return pool_id

    def _swap_input(self, pool_id, amount_in, zero_for_one=True, min_out=Decimal(0), deadline=0):
        return (
            pool_id
            + _encode_amount(amount_in)
            + (b"\x01" if zero_for_one else b"\x00")
            + _encode_amount(min_out)
            + deadline.to_bytes(32, "big")
        )

    def test_swap_success(self):
        pool_id = self._setup_pool()
        data = self._swap_input(pool_id, Decimal("100"), zero_for_one=False)
        comp = _make_computation(data)
        exchange_swap(comp)
        assert len(comp.output) == 64
        # With sqrt_price=2^96 the one_for_zero direction produces output
        amount_out = _decode_uint256(comp.output[0:32])
        fee = _decode_uint256(comp.output[32:64])
        assert fee > 0, "Swap must charge fee"

    def test_swap_charges_gas(self):
        pool_id = self._setup_pool()
        data = self._swap_input(pool_id, Decimal("100"))
        comp = _make_computation(data)
        exchange_swap(comp)
        comp.consume_gas.assert_called_once()

    def test_swap_zero_amount_rejected(self):
        pool_id = self._setup_pool()
        data = self._swap_input(pool_id, Decimal("0"))
        comp = _make_computation(data)
        exchange_swap(comp)
        assert comp.output == b"\x00" * 64

    def test_swap_unknown_pool_rejected(self):
        data = self._swap_input(b"\xff" * 32, Decimal("100"))
        comp = _make_computation(data)
        exchange_swap(comp)
        assert comp.output == b"\x00" * 64

    def test_swap_slippage_protection(self):
        pool_id = self._setup_pool()
        # Set min_amount_out impossibly high
        data = self._swap_input(pool_id, Decimal("100"), min_out=Decimal("999999999"))
        comp = _make_computation(data)
        exchange_swap(comp)
        assert comp.output == b"\x00" * 64, "Slippage exceeded must return zeros"

    def test_swap_expired_deadline_rejected(self):
        pool_id = self._setup_pool()
        data = self._swap_input(pool_id, Decimal("100"), deadline=1)  # expired
        comp = _make_computation(data)
        exchange_swap(comp)
        assert comp.output == b"\x00" * 64

    def test_swap_no_liquidity_returns_zero(self):
        """Pool with zero liquidity should return zero output."""
        token_a = _encode_token("ETH")
        token_b = _encode_token("DAI")
        data = (
            token_a + token_b
            + (500).to_bytes(4, "big")
            + struct.pack(">i", 10)
            + (2**96).to_bytes(32, "big")
        )
        comp = _make_computation(data)
        exchange_create_pool(comp)
        pool_id = comp.output
        # Swap without adding liquidity
        swap_data = self._swap_input(pool_id, Decimal("100"))
        comp2 = _make_computation(swap_data)
        exchange_swap(comp2)
        assert comp2.output == b"\x00" * 64

    def test_swap_short_input_rejected(self):
        comp = _make_computation(b"\x00" * 50)
        exchange_swap(comp)
        assert comp.output == b"\x00" * 64


# ── addLiquidity (0x0102) ────────────────────────────────────────────

class TestAddLiquidity:
    """Precompile 0x0102: addLiquidity tests."""

    def _setup_pool(self, tick_spacing=60):
        token_a = _encode_token("QRDX")
        token_b = _encode_token("USDC")
        fee_bps = (3000).to_bytes(4, "big")
        ts = struct.pack(">i", tick_spacing)
        sqrt_price = (2**96).to_bytes(32, "big")
        data = token_a + token_b + fee_bps + ts + sqrt_price
        comp = _make_computation(data)
        exchange_create_pool(comp)
        return comp.output

    def _add_liq_input(self, pool_id, amount_a, amount_b, tick_lower, tick_upper, recipient=b'\x01' * 32):
        return (
            pool_id
            + _encode_amount(amount_a)
            + _encode_amount(amount_b)
            + struct.pack(">i", tick_lower)
            + struct.pack(">i", tick_upper)
            + recipient
        )

    def test_add_liquidity_success(self):
        pool_id = self._setup_pool()
        data = self._add_liq_input(pool_id, Decimal("1000"), Decimal("1000"), -120, 120)
        comp = _make_computation(data)
        exchange_add_liquidity(comp)
        liquidity = _decode_uint256(comp.output[0:32])
        pos_id = comp.output[32:64]
        assert liquidity > 0
        assert pos_id != b"\x00" * 32

    def test_add_liquidity_charges_gas(self):
        pool_id = self._setup_pool()
        data = self._add_liq_input(pool_id, Decimal("1000"), Decimal("1000"), -120, 120)
        comp = _make_computation(data)
        exchange_add_liquidity(comp)
        comp.consume_gas.assert_called_once()

    def test_add_liquidity_unknown_pool_rejected(self):
        data = self._add_liq_input(b"\xff" * 32, Decimal("1000"), Decimal("1000"), -120, 120)
        comp = _make_computation(data)
        exchange_add_liquidity(comp)
        assert comp.output == b"\x00" * 64

    def test_add_liquidity_invalid_tick_range(self):
        pool_id = self._setup_pool()
        # tick_lower >= tick_upper
        data = self._add_liq_input(pool_id, Decimal("1000"), Decimal("1000"), 120, 120)
        comp = _make_computation(data)
        exchange_add_liquidity(comp)
        assert comp.output == b"\x00" * 64

    def test_add_liquidity_unaligned_ticks(self):
        pool_id = self._setup_pool(tick_spacing=60)
        # Ticks not aligned to 60
        data = self._add_liq_input(pool_id, Decimal("1000"), Decimal("1000"), -50, 50)
        comp = _make_computation(data)
        exchange_add_liquidity(comp)
        assert comp.output == b"\x00" * 64

    def test_add_liquidity_zero_amounts(self):
        pool_id = self._setup_pool()
        data = self._add_liq_input(pool_id, Decimal("0"), Decimal("0"), -120, 120)
        comp = _make_computation(data)
        exchange_add_liquidity(comp)
        assert comp.output == b"\x00" * 64

    def test_add_liquidity_deterministic_position_id(self):
        pool_id = self._setup_pool()
        recipient = b"\xaa" * 32
        data = self._add_liq_input(pool_id, Decimal("1000"), Decimal("1000"), -120, 120, recipient)
        comp = _make_computation(data)
        exchange_add_liquidity(comp)
        pos_id_1 = comp.output[32:64]
        # Same params should produce same position ID (idempotent)
        expected = hashlib.blake2b(
            pool_id + recipient + struct.pack(">ii", -120, 120),
            digest_size=32,
        ).digest()
        assert pos_id_1 == expected

    def test_add_liquidity_short_input_rejected(self):
        comp = _make_computation(b"\x00" * 50)
        exchange_add_liquidity(comp)
        assert comp.output == b"\x00" * 64


# ── placeLimitOrder (0x0103) ─────────────────────────────────────────

class TestPlaceLimitOrder:
    """Precompile 0x0103: placeLimitOrder tests."""

    def _order_input(self, token_in="QRDX", token_out="USDC", amount=Decimal("100"),
                     price=Decimal("1.50"), side=0):
        return (
            _encode_token(token_in)
            + _encode_token(token_out)
            + _encode_amount(amount)
            + _encode_amount(price)
            + bytes([side])
        )

    def test_place_order_success(self):
        data = self._order_input()
        comp = _make_computation(data)
        exchange_place_limit_order(comp)
        assert comp.output[0] == 0x01  # success
        order_id = comp.output[1:33]
        assert order_id != b"\x00" * 32

    def test_place_order_charges_gas(self):
        data = self._order_input()
        comp = _make_computation(data)
        exchange_place_limit_order(comp)
        comp.consume_gas.assert_called_once()

    def test_place_order_same_token_rejected(self):
        data = self._order_input(token_in="QRDX", token_out="QRDX")
        comp = _make_computation(data)
        exchange_place_limit_order(comp)
        assert comp.output == b"\x00" * 33

    def test_place_order_zero_amount_rejected(self):
        data = self._order_input(amount=Decimal("0"))
        comp = _make_computation(data)
        exchange_place_limit_order(comp)
        assert comp.output == b"\x00" * 33

    def test_place_order_zero_price_rejected(self):
        data = self._order_input(price=Decimal("0"))
        comp = _make_computation(data)
        exchange_place_limit_order(comp)
        assert comp.output == b"\x00" * 33

    def test_place_order_invalid_side_rejected(self):
        data = self._order_input()
        data = data[:-1] + bytes([2])  # invalid side
        comp = _make_computation(data)
        exchange_place_limit_order(comp)
        assert comp.output == b"\x00" * 33

    def test_place_buy_order(self):
        data = self._order_input(side=0)
        comp = _make_computation(data)
        exchange_place_limit_order(comp)
        assert comp.output[0] == 0x01

    def test_place_sell_order(self):
        data = self._order_input(side=1)
        comp = _make_computation(data)
        exchange_place_limit_order(comp)
        assert comp.output[0] == 0x01

    def test_place_order_stores_in_book(self):
        data = self._order_input()
        comp = _make_computation(data)
        exchange_place_limit_order(comp)
        order_id = comp.output[1:33]
        assert "QRDX:USDC" in _exchange_orderbooks
        assert order_id in _exchange_orderbooks["QRDX:USDC"]

    def test_place_order_short_input_rejected(self):
        comp = _make_computation(b"\x00" * 50)
        exchange_place_limit_order(comp)
        assert comp.output == b"\x00" * 33


# ── cancelOrder (0x0104) ─────────────────────────────────────────────

class TestCancelOrder:
    """Precompile 0x0104: cancelOrder tests."""

    def _place_and_get_order_id(self, sender=b'\x01' * 20):
        data = (
            _encode_token("QRDX")
            + _encode_token("USDC")
            + _encode_amount(Decimal("100"))
            + _encode_amount(Decimal("1.50"))
            + bytes([0])
        )
        comp = _make_computation(data, sender=sender)
        exchange_place_limit_order(comp)
        return comp.output[1:33]

    def test_cancel_order_success(self):
        sender = b'\x01' * 20
        order_id = self._place_and_get_order_id(sender)
        cancel_data = _encode_token("QRDX") + _encode_token("USDC") + order_id
        comp = _make_computation(cancel_data, sender=sender)
        exchange_cancel_order(comp)
        assert comp.output == b"\x01"

    def test_cancel_order_charges_gas(self):
        sender = b'\x01' * 20
        order_id = self._place_and_get_order_id(sender)
        cancel_data = _encode_token("QRDX") + _encode_token("USDC") + order_id
        comp = _make_computation(cancel_data, sender=sender)
        exchange_cancel_order(comp)
        comp.consume_gas.assert_called_once()

    def test_cancel_nonexistent_order(self):
        cancel_data = _encode_token("QRDX") + _encode_token("USDC") + b"\xff" * 32
        comp = _make_computation(cancel_data)
        exchange_cancel_order(comp)
        assert comp.output == b"\x00"

    def test_cancel_order_wrong_owner(self):
        sender_a = b'\x01' * 20
        sender_b = b'\x02' * 20
        order_id = self._place_and_get_order_id(sender_a)
        cancel_data = _encode_token("QRDX") + _encode_token("USDC") + order_id
        comp = _make_computation(cancel_data, sender=sender_b)
        exchange_cancel_order(comp)
        assert comp.output == b"\x00", "Non-owner must not cancel"

    def test_cancel_removes_from_book(self):
        sender = b'\x01' * 20
        order_id = self._place_and_get_order_id(sender)
        assert order_id in _exchange_orderbooks["QRDX:USDC"]
        cancel_data = _encode_token("QRDX") + _encode_token("USDC") + order_id
        comp = _make_computation(cancel_data, sender=sender)
        exchange_cancel_order(comp)
        assert order_id not in _exchange_orderbooks["QRDX:USDC"]

    def test_cancel_short_input_rejected(self):
        comp = _make_computation(b"\x00" * 50)
        exchange_cancel_order(comp)
        assert comp.output == b"\x00"


# ── Encoding / Decoding ──────────────────────────────────────────────

class TestEncoding:
    """Deterministic encoding must be consensus-safe."""

    def test_uint256_roundtrip(self):
        values = [Decimal("0"), Decimal("1"), Decimal("100.12345678"), Decimal("999999999")]
        for v in values:
            encoded = _encode_uint256(v)
            decoded = _decode_uint256(encoded)
            assert decoded == v, f"Roundtrip failed for {v}"

    def test_token_roundtrip(self):
        for sym in ["QRDX", "USDC", "ETH", "BTC", "WQRDX"]:
            encoded = _encode_token(sym)
            assert len(encoded) == 32
            decoded = _decode_token(encoded)
            assert decoded == sym

    def test_token_padding(self):
        encoded = _encode_token("A")
        assert encoded == b"A" + b"\x00" * 31


# ── Address Assignments ──────────────────────────────────────────────

class TestAddressAssignments:
    """Exchange precompile addresses must be in the 0x0100 range."""

    def test_create_pool_at_0x0100(self):
        assert EXCHANGE_CREATE_POOL_ADDRESS == Address(b'\x00' * 18 + b'\x01\x00')

    def test_swap_at_0x0101(self):
        assert EXCHANGE_SWAP_ADDRESS == Address(b'\x00' * 18 + b'\x01\x01')

    def test_add_liquidity_at_0x0102(self):
        assert EXCHANGE_ADD_LIQUIDITY_ADDRESS == Address(b'\x00' * 18 + b'\x01\x02')

    def test_place_limit_order_at_0x0103(self):
        assert EXCHANGE_PLACE_LIMIT_ORDER_ADDRESS == Address(b'\x00' * 18 + b'\x01\x03')

    def test_cancel_order_at_0x0104(self):
        assert EXCHANGE_CANCEL_ORDER_ADDRESS == Address(b'\x00' * 18 + b'\x01\x04')
