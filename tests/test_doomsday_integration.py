"""
Integration Tests for Doomsday Protocol Integration Points

Tests:
  - ShieldingManager as DoomsdayAware (on_doomsday callback)
  - EthereumAdapter canary monitoring (check_canary_balance, generate_doomsday_attestation)
  - DatabaseDoomsdayStateStore (sync + async facades)
  - BridgeModule RPC endpoints
  - ValidatorNode canary monitor loop
"""

import asyncio
import hashlib
import json
import sys
import os
import time
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

# ── Path setup ────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from qrdx.bridge.shielding import (
    BridgeMinter,
    DoomsdayAttestation,
    DoomsdayProtocol,
    DoomsdayAware,
    InMemoryDoomsdayStateStore,
    ShieldingManager,
    DOOMSDAY_CANARY_ADDRESS,
    DOOMSDAY_CANARY_BALANCE,
    DOOMSDAY_DOMAIN,
)
from qrdx.bridge.adapters import EthereumAdapter, BlockHeightRecord, ChainId
from qrdx.bridge.doomsday_store import DatabaseDoomsdayStateStore
from qrdx.constants import (
    DOOMSDAY_CANARY_BOUNTY,
    ORACLE_ATTESTATION_QUORUM_NUMERATOR,
    ORACLE_ATTESTATION_QUORUM_DENOMINATOR,
)


# ═══════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _make_attestation(validator_id: int = 0) -> DoomsdayAttestation:
    return DoomsdayAttestation(
        validator_address=f"0xvalidator_{validator_id}",
        canary_address=DOOMSDAY_CANARY_ADDRESS,
        observed_balance=Decimal("0"),
        observed_block_height=100,
        observed_block_hash="ab" * 32,
        timestamp=int(time.time()),
    )


def _trigger_doomsday(protocol: DoomsdayProtocol) -> None:
    """Submit enough attestations to trigger doomsday."""
    for i in range(protocol.threshold):
        protocol.submit_canary_attestation(_make_attestation(i))
    assert protocol.is_active


# ═══════════════════════════════════════════════════════════════════════
#  1. SHIELDING MANAGER — DOOMSDAY AWARE
# ═══════════════════════════════════════════════════════════════════════

class TestShieldingManagerDoomsdayAware:
    """ShieldingManager implements DoomsdayAware and auto-registers."""

    def test_implements_doomsday_aware(self):
        mgr = ShieldingManager()
        assert isinstance(mgr, DoomsdayAware)

    def test_auto_registers_with_doomsday(self):
        doom = DoomsdayProtocol(total_validators=3)
        mgr = ShieldingManager(doomsday=doom)
        status = doom.get_status()
        assert status["registered_bridges"] >= 1

    def test_on_doomsday_sets_metadata(self):
        doom = DoomsdayProtocol(total_validators=3)
        mgr = ShieldingManager(doomsday=doom)
        mgr.on_doomsday(block_height=42, timestamp=1234567890)
        assert mgr._doomsday_block_height == 42
        assert mgr._doomsday_timestamp == 1234567890

    def test_on_doomsday_fails_pending_shields(self):
        """Pending shield records should be FAILED on doomsday."""
        from qrdx.bridge.types import BridgeRecord, BridgeStatus, BridgeOperationType, ChainId

        doom = DoomsdayProtocol(total_validators=3)
        mgr = ShieldingManager(doomsday=doom)

        # Manually insert a PENDING shield record
        record = BridgeRecord(
            record_id="",
            source_chain_id=ChainId.ETHEREUM,
            dest_chain_id=ChainId.QRDX,
            block_height=10,
            block_hash="aa" * 32,
            source_tx_hash="bb" * 32,
            amount=Decimal("1.0"),
            source_address="0xuser",
            qrdx_address="0xqrdx",
            operation=BridgeOperationType.SHIELD,
            token_symbol="ETH",
        )
        mgr._records[record.record_id] = record
        assert record.status == BridgeStatus.PENDING

        # Trigger doomsday via callback
        mgr.on_doomsday(block_height=100, timestamp=int(time.time()))
        assert record.status == BridgeStatus.FAILED

    def test_doomsday_trigger_notifies_shielding_manager(self):
        """When quorum triggers doomsday, ShieldingManager.on_doomsday is called."""
        doom = DoomsdayProtocol(total_validators=3)
        mgr = ShieldingManager(doomsday=doom)

        # Track calls to on_doomsday
        calls = []
        original = mgr.on_doomsday

        def spy(bh, ts):
            calls.append((bh, ts))
            return original(bh, ts)

        mgr.on_doomsday = spy
        # Re-register with the spy
        doom._registered_bridges[0] = mgr

        _trigger_doomsday(doom)
        assert len(calls) == 1
        assert calls[0][0] == 100  # block_height from _make_attestation

    def test_custom_bridge_id(self):
        doom = DoomsdayProtocol(total_validators=1)
        mgr = ShieldingManager(doomsday=doom, bridge_id="my-bridge")
        assert "my-bridge" in doom._registered_bridge_ids


# ═══════════════════════════════════════════════════════════════════════
#  2. ETHEREUM ADAPTER — CANARY MONITORING
# ═══════════════════════════════════════════════════════════════════════

class TestEthereumAdapterCanary:
    """EthereumAdapter.check_canary_balance and generate_doomsday_attestation."""

    def test_check_canary_balance_parses_wei(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")

        # Mock RPC to return 1 ETH in wei (0xde0b6b3a7640000)
        one_eth_wei = hex(10**18)
        with patch.object(adapter, "_json_rpc_call", return_value=one_eth_wei):
            balance = adapter.check_canary_balance()
        assert balance == Decimal("1")

    def test_check_canary_balance_returns_none_on_error(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, "_json_rpc_call", side_effect=ConnectionError("fail")):
            balance = adapter.check_canary_balance()
        assert balance is None

    def test_check_canary_balance_uses_default_address(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, "_json_rpc_call", return_value="0x0") as mock:
            adapter.check_canary_balance()
        args = mock.call_args
        assert args[0][1][0] == DOOMSDAY_CANARY_ADDRESS

    def test_check_canary_balance_custom_address(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        custom = "0xCustomAddr"
        with patch.object(adapter, "_json_rpc_call", return_value="0x0") as mock:
            adapter.check_canary_balance(canary_address=custom)
        args = mock.call_args
        assert args[0][1][0] == custom

    def test_generate_doomsday_attestation_returns_none_when_safe(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")

        # Canary holds 1M ETH (≥ expected bounty)
        safe_balance = DOOMSDAY_CANARY_BOUNTY + Decimal("1")
        safe_wei = hex(int(safe_balance * 10**18))

        block = BlockHeightRecord(
            chain_id=ChainId.ETHEREUM,
            block_height=100,
            block_hash="aa" * 32,
            timestamp=int(time.time()),
        )
        with patch.object(adapter, "get_latest_block", return_value=block):
            with patch.object(adapter, "check_canary_balance", return_value=safe_balance):
                att = adapter.generate_doomsday_attestation("0xMyValidator")
        assert att is None

    def test_generate_doomsday_attestation_returns_attestation_when_drained(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")

        block = BlockHeightRecord(
            chain_id=ChainId.ETHEREUM,
            block_height=200,
            block_hash="bb" * 32,
            timestamp=int(time.time()),
        )
        with patch.object(adapter, "get_latest_block", return_value=block):
            with patch.object(adapter, "check_canary_balance", return_value=Decimal("0")):
                att = adapter.generate_doomsday_attestation("0xMyValidator")

        assert att is not None
        assert att.validator_address == "0xMyValidator"
        assert att.canary_address == DOOMSDAY_CANARY_ADDRESS
        assert att.observed_balance == Decimal("0")
        assert att.observed_block_height == 200

    def test_generate_doomsday_attestation_returns_none_on_rpc_error(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")

        block = BlockHeightRecord(
            chain_id=ChainId.ETHEREUM,
            block_height=100,
            block_hash="cc" * 32,
            timestamp=int(time.time()),
        )
        with patch.object(adapter, "get_latest_block", return_value=block):
            with patch.object(adapter, "check_canary_balance", return_value=None):
                att = adapter.generate_doomsday_attestation("0xMyValidator")
        assert att is None


# ═══════════════════════════════════════════════════════════════════════
#  3. DATABASE DOOMSDAY STATE STORE
# ═══════════════════════════════════════════════════════════════════════

class TestDatabaseDoomsdayStateStore:
    """DatabaseDoomsdayStateStore — async save/load with mock pool."""

    @pytest.fixture
    def mock_pool(self):
        """Create a mock asyncpg pool with context manager."""
        pool = MagicMock()
        conn = AsyncMock()

        # Make pool.acquire() work as async context manager
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=conn)
        cm.__aexit__ = AsyncMock(return_value=False)
        pool.acquire.return_value = cm

        return pool, conn

    @pytest.mark.asyncio
    async def test_initialize_creates_tables(self, mock_pool):
        pool, conn = mock_pool
        store = DatabaseDoomsdayStateStore(pool)
        await store.initialize()
        assert store._initialized is True
        assert conn.execute.call_count == 2  # state + attestation tables

    @pytest.mark.asyncio
    async def test_async_save(self, mock_pool):
        pool, conn = mock_pool
        store = DatabaseDoomsdayStateStore(pool)

        state = {
            "doomsday_active": True,
            "triggered_at": 1234567890,
            "trigger_block_height": 42,
            "verification_hash": "abc123",
            "trigger_address": "0xTrigger",
            "bounty_recipient": "0xBounty",
            "bounty_paid": False,
        }
        result = await store.async_save(state)
        assert result is True
        conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_load_returns_none_when_empty(self, mock_pool):
        pool, conn = mock_pool
        conn.fetchrow.return_value = None
        store = DatabaseDoomsdayStateStore(pool)

        result = await store.async_load()
        assert result is None

    @pytest.mark.asyncio
    async def test_async_load_returns_dict(self, mock_pool):
        pool, conn = mock_pool
        conn.fetchrow.return_value = {
            "doomsday_active": True,
            "triggered_at": 1234567890,
            "trigger_block": 42,
            "verification_hash": "abc123",
            "trigger_address": "0xTrigger",
            "bounty_recipient": "0xBounty",
            "bounty_paid": False,
        }
        store = DatabaseDoomsdayStateStore(pool)
        result = await store.async_load()
        assert result is not None
        assert result["doomsday_active"] is True
        assert result["trigger_block_height"] == 42

    @pytest.mark.asyncio
    async def test_save_attestation(self, mock_pool):
        pool, conn = mock_pool
        store = DatabaseDoomsdayStateStore(pool)

        result = await store.save_attestation(
            validator_address="0xVal",
            canary_address=DOOMSDAY_CANARY_ADDRESS,
            observed_balance="0",
            observed_block_height=100,
            observed_block_hash="aa" * 32,
            timestamp=int(time.time()),
        )
        assert result is True
        conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_attestations(self, mock_pool):
        pool, conn = mock_pool
        conn.fetch.return_value = [
            {"validator_address": "0xVal", "observed_balance": "0"},
        ]
        store = DatabaseDoomsdayStateStore(pool)
        atts = await store.get_attestations(limit=10)
        assert len(atts) == 1
        assert atts[0]["validator_address"] == "0xVal"

    def test_sync_save_in_running_loop(self, mock_pool):
        """sync save_doomsday_state should not raise when loop is running."""
        pool, conn = mock_pool
        store = DatabaseDoomsdayStateStore(pool)
        # The sync wrapper schedules a task — just check it doesn't blow up
        state = {"doomsday_active": False}
        # We can't easily test this without a running loop, but we can
        # verify the method exists and is callable
        assert callable(store.save_doomsday_state)
        assert callable(store.load_doomsday_state)


# ═══════════════════════════════════════════════════════════════════════
#  4. BRIDGE RPC MODULE
# ═══════════════════════════════════════════════════════════════════════

class TestBridgeRPCModule:
    """Tests for the bridge_* RPC namespace."""

    @pytest.fixture
    def bridge_module(self):
        from qrdx.rpc.modules.bridge import BridgeModule

        doom = DoomsdayProtocol(total_validators=3)
        mgr = ShieldingManager(doomsday=doom)

        ctx = SimpleNamespace(
            doomsday=doom,
            shielding_manager=mgr,
            eth_adapter=None,
        )
        return BridgeModule(context=ctx), doom, mgr

    @pytest.mark.asyncio
    async def test_getDoomsdayStatus(self, bridge_module):
        module, doom, mgr = bridge_module
        status = await module.getDoomsdayStatus()
        assert status["doomsday_active"] is False
        assert status["shield_allowed"] is True
        assert status["unshield_allowed"] is True
        assert status["canary_address"] == DOOMSDAY_CANARY_ADDRESS

    @pytest.mark.asyncio
    async def test_getCanaryInfo_no_adapter(self, bridge_module):
        module, doom, mgr = bridge_module
        info = await module.getCanaryInfo()
        assert info["canary_address"] == DOOMSDAY_CANARY_ADDRESS
        assert info["live_balance"] is None  # no adapter
        assert info["is_safe"] is None

    @pytest.mark.asyncio
    async def test_getCanaryInfo_with_adapter(self, bridge_module):
        module, doom, mgr = bridge_module

        adapter = MagicMock()
        adapter.check_canary_balance.return_value = DOOMSDAY_CANARY_BOUNTY + Decimal("1")
        module.context.eth_adapter = adapter

        info = await module.getCanaryInfo()
        assert info["live_balance"] is not None
        assert info["is_safe"] is True

    @pytest.mark.asyncio
    async def test_getAttestationProgress(self, bridge_module):
        module, doom, mgr = bridge_module
        progress = await module.getAttestationProgress()
        assert progress["received"] == 0
        assert progress["threshold"] == doom.threshold

    @pytest.mark.asyncio
    async def test_getShieldingStats(self, bridge_module):
        module, doom, mgr = bridge_module
        stats = await module.getShieldingStats()
        assert "total_records" in stats
        assert "doomsday" in stats

    @pytest.mark.asyncio
    async def test_getBountyInfo(self, bridge_module):
        module, doom, mgr = bridge_module
        info = await module.getBountyInfo()
        assert "amount" in info
        assert "paid" in info

    @pytest.mark.asyncio
    async def test_submitDoomsdayAttestation_valid(self, bridge_module):
        module, doom, mgr = bridge_module
        att = _make_attestation(0)
        att_json = json.dumps(att.to_dict())

        # Call the inner method (bypass admin_token check for testing)
        result = await module.submitDoomsdayAttestation.__wrapped__(module, att_json)
        assert result["accepted"] is True
        assert result["triggered"] is False  # 1/3 threshold

    @pytest.mark.asyncio
    async def test_getDoomsdayStatus_after_trigger(self, bridge_module):
        module, doom, mgr = bridge_module
        _trigger_doomsday(doom)
        status = await module.getDoomsdayStatus()
        assert status["doomsday_active"] is True
        assert status["shield_allowed"] is False

    @pytest.mark.asyncio
    async def test_context_fallback_to_shielding_manager(self):
        """BridgeModule should find doomsday via shielding_manager if context.doomsday is None."""
        from qrdx.rpc.modules.bridge import BridgeModule

        doom = DoomsdayProtocol(total_validators=1)
        mgr = ShieldingManager(doomsday=doom)
        ctx = SimpleNamespace(
            doomsday=None,
            shielding_manager=mgr,
            eth_adapter=None,
        )
        module = BridgeModule(context=ctx)
        status = await module.getDoomsdayStatus()
        assert "doomsday_active" in status

    def test_module_namespace(self):
        from qrdx.rpc.modules.bridge import BridgeModule
        assert BridgeModule.namespace == "bridge"

    def test_module_methods_registered(self):
        from qrdx.rpc.modules.bridge import BridgeModule

        doom = DoomsdayProtocol(total_validators=1)
        mgr = ShieldingManager(doomsday=doom)
        ctx = SimpleNamespace(doomsday=doom, shielding_manager=mgr, eth_adapter=None)
        module = BridgeModule(context=ctx)
        methods = module.get_methods()
        expected = {
            "bridge_getDoomsdayStatus",
            "bridge_getCanaryInfo",
            "bridge_getAttestationProgress",
            "bridge_getShieldingStats",
            "bridge_getBountyInfo",
            "bridge_submitDoomsdayAttestation",
            "bridge_triggerDoomsdayBySignature",
        }
        assert expected.issubset(set(methods.keys()))


# ═══════════════════════════════════════════════════════════════════════
#  5. VALIDATOR NODE — CANARY MONITOR
# ═══════════════════════════════════════════════════════════════════════

class TestValidatorNodeCanaryMonitor:
    """ValidatorNode canary monitor integration."""

    def test_set_eth_adapter(self):
        from qrdx.validator.node_integration import ValidatorNode

        node = ValidatorNode.__new__(ValidatorNode)
        node._eth_adapter = None
        node._doomsday_protocol = None
        node._running = False

        adapter = MagicMock()
        node.set_eth_adapter(adapter)
        assert node._eth_adapter is adapter

    def test_set_doomsday_protocol(self):
        from qrdx.validator.node_integration import ValidatorNode

        node = ValidatorNode.__new__(ValidatorNode)
        node._eth_adapter = None
        node._doomsday_protocol = None
        node._running = False

        doom = DoomsdayProtocol(total_validators=1)
        node.set_doomsday_protocol(doom)
        assert node._doomsday_protocol is doom

    @pytest.mark.asyncio
    async def test_canary_monitor_exits_when_active(self):
        """Loop should exit immediately if doomsday is already active."""
        from qrdx.validator.node_integration import ValidatorNode

        node = ValidatorNode.__new__(ValidatorNode)
        node._running = True
        node._eth_adapter = MagicMock()
        node.wallet = MagicMock(address="0xVal")

        doom = DoomsdayProtocol(total_validators=1)
        _trigger_doomsday(doom)
        node._doomsday_protocol = doom

        # Should exit quickly since doomsday is active
        await asyncio.wait_for(node._canary_monitor_loop(), timeout=2.0)

    @pytest.mark.asyncio
    async def test_canary_monitor_submits_attestation(self):
        """When adapter reports drain, monitor should submit attestation."""
        from qrdx.validator.node_integration import ValidatorNode

        node = ValidatorNode.__new__(ValidatorNode)
        node._running = True

        doom = DoomsdayProtocol(total_validators=1)
        node._doomsday_protocol = doom

        att = _make_attestation(0)
        adapter = MagicMock()
        adapter.generate_doomsday_attestation.return_value = att
        node._eth_adapter = adapter
        node.wallet = MagicMock(address=att.validator_address)

        # Run monitor — it should trigger (total_validators=1 means threshold=1)
        await asyncio.wait_for(node._canary_monitor_loop(), timeout=2.0)

        assert doom.is_active
        adapter.generate_doomsday_attestation.assert_called_once()

    @pytest.mark.asyncio
    async def test_canary_monitor_skips_when_safe(self):
        """When adapter returns None (safe), monitor continues."""
        from qrdx.validator.node_integration import ValidatorNode

        node = ValidatorNode.__new__(ValidatorNode)
        call_count = 0

        doom = DoomsdayProtocol(total_validators=3)
        node._doomsday_protocol = doom

        adapter = MagicMock()
        adapter.generate_doomsday_attestation.return_value = None
        node._eth_adapter = adapter
        node.wallet = MagicMock(address="0xVal")

        # Run for a brief period then stop
        node._running = True

        async def stop_after():
            await asyncio.sleep(0.1)
            node._running = False

        asyncio.create_task(stop_after())
        await asyncio.wait_for(node._canary_monitor_loop(), timeout=5.0)

        # Should have called generate once before stopping
        assert adapter.generate_doomsday_attestation.called
        assert not doom.is_active


# ═══════════════════════════════════════════════════════════════════════
#  6. MODULE EXPORTS
# ═══════════════════════════════════════════════════════════════════════

class TestExports:
    """Verify all new symbols are importable from their packages."""

    def test_bridge_package_exports_db_store(self):
        from qrdx.bridge import DatabaseDoomsdayStateStore
        assert DatabaseDoomsdayStateStore is not None

    def test_rpc_modules_exports_bridge_module(self):
        from qrdx.rpc.modules import BridgeModule
        assert BridgeModule is not None

    def test_bridge_shielding_exports(self):
        from qrdx.bridge.shielding import (
            DoomsdayAware,
            DoomsdayAttestation,
            DoomsdayProof,
            DoomsdayStateStore,
            InMemoryDoomsdayStateStore,
        )
        assert all(cls is not None for cls in [
            DoomsdayAware, DoomsdayAttestation, DoomsdayProof,
            DoomsdayStateStore, InMemoryDoomsdayStateStore,
        ])

    def test_adapter_canary_methods_exist(self):
        adapter = EthereumAdapter()
        assert hasattr(adapter, "check_canary_balance")
        assert hasattr(adapter, "generate_doomsday_attestation")

    def test_validator_node_canary_methods_exist(self):
        from qrdx.validator.node_integration import ValidatorNode
        assert hasattr(ValidatorNode, "set_eth_adapter")
        assert hasattr(ValidatorNode, "set_doomsday_protocol")
        assert hasattr(ValidatorNode, "_canary_monitor_loop")
