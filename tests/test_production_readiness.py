"""
QRDX Phase 8 — Production Readiness Tests

Tests for:
  - Step 12.2: Unified TOML config loader
  - Step 11.1: JSON-RPC 2.0 server (verification)
  - Step 11.2: WebSocket subscriptions
  - Step 12.3: Prometheus metrics
  - Step 12.4: TLS support
  - Step 12.1: Docker production config validation
  - Step 13.2: Integration helpers

Total target: ≥150 tests
"""

import asyncio
import json
import math
import os
import ssl
import tempfile
import textwrap
import threading
import time
from decimal import Decimal
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ===================================================================
# Imports under test
# ===================================================================

# Config loader
from qrdx.config.loader import (
    ConsensusConfig,
    DatabaseConfig,
    DiscoveryConfig,
    GenesisConfig,
    HealthConfig,
    MetricsConfig,
    NodeConfig,
    NodeSectionConfig,
    P2PConfig,
    P2PSecurityConfig,
    PoSConfig,
    SQLiteConfig,
    SyncConfig,
    TLSConfig,
    load_config,
)

# RPC server
from qrdx.rpc.server import (
    RPCError,
    RPCErrorCode,
    RPCModule,
    RPCRequest,
    RPCResponse,
    RPCServer,
    rpc_method,
)

# RPC config
from qrdx.rpc.config import (
    HTTPConfig,
    LegacyConfig,
    ModulesConfig,
    RPCConfig,
    WebSocketConfig,
)

# WebSocket subscriptions
from qrdx.rpc.websocket import (
    Subscription,
    SubscriptionType,
    WSConnection,
    WebSocketManager,
)

# Metrics
from qrdx.metrics.collector import (
    Counter,
    Gauge,
    Histogram,
    MetricsCollector,
    MetricsRegistry,
    DEFAULT_BUCKETS,
)

# TLS
from qrdx.network.tls import (
    TLSContextBuilder,
    hsts_header,
)


# ===================================================================
# FIXTURES
# ===================================================================

@pytest.fixture
def sample_toml_content():
    """Minimal valid TOML config."""
    return textwrap.dedent("""\
        [node]
        chain_id = 42
        network_name = "qrdx-testnet"
        data_dir = "/tmp/qrdx-test"
        log_level = "DEBUG"

        [p2p]
        enabled = true
        listen_port = 30304
        max_peers = 25

        [p2p.discovery]
        enabled = true
        bootnodes = ["http://boot1:3007"]

        [p2p.security]
        post_quantum_enabled = true
        pq_kem_algorithm = "Kyber768"

        [rpc]
        enabled = true

        [rpc.http]
        enabled = true
        host = "0.0.0.0"
        port = 8545

        [rpc.websocket]
        enabled = true
        port = 8546
        max_connections = 50

        [rpc.modules]
        eth = true
        net = true
        web3 = true
        qrdx = true
        admin = false
        debug = false

        [rpc.legacy]
        enabled = false

        [database]
        type = "sqlite"

        [database.sqlite]
        path = "/tmp/test.db"
        wal_mode = true

        [genesis]
        chain_id = 42
        initial_supply = 50000000

        [consensus]
        mechanism = "pos"

        [consensus.pos]
        slot_duration = 2
        slots_per_epoch = 32

        [validator]
        enabled = false

        [sync]
        mode = "full"
        batch_size = 64

        [metrics]
        enabled = true
        host = "0.0.0.0"
        port = 9090

        [health]
        enabled = true
        path = "/health"

        [tls]
        enabled = false
    """)


@pytest.fixture
def toml_file(tmp_path, sample_toml_content):
    """Write sample TOML to a temp file."""
    path = tmp_path / "config.toml"
    path.write_text(sample_toml_content)
    return str(path)


@pytest.fixture
def ws_manager():
    """Fresh WebSocketManager."""
    return WebSocketManager(max_connections=5, max_subscriptions_per_conn=3)


@pytest.fixture
def metrics_collector():
    """Fresh MetricsCollector."""
    return MetricsCollector()


@pytest.fixture
def registry():
    """Fresh MetricsRegistry."""
    return MetricsRegistry()


# ===================================================================
# SECTION 1: Unified TOML Config Loader  (Step 12.2)
# ===================================================================

class TestNodeSectionConfig:
    """Tests for [node] section parsing."""

    def test_defaults(self):
        cfg = NodeSectionConfig()
        assert cfg.chain_id == 1
        assert cfg.network_name == "qrdx-mainnet"
        assert cfg.data_dir == "./data"
        assert cfg.log_level == "INFO"

    def test_from_dict(self):
        cfg = NodeSectionConfig.from_dict({
            "chain_id": 42,
            "network_name": "testnet",
            "log_level": "DEBUG",
        })
        assert cfg.chain_id == 42
        assert cfg.network_name == "testnet"

    def test_env_override(self):
        cfg = NodeSectionConfig()
        with patch.dict(os.environ, {"QRDX_CHAIN_ID": "99", "QRDX_LOG_LEVEL": "ERROR"}):
            cfg.apply_env()
        assert cfg.chain_id == 99
        assert cfg.log_level == "ERROR"


class TestP2PConfig:
    """Tests for [p2p] section."""

    def test_defaults(self):
        cfg = P2PConfig()
        assert cfg.enabled is True
        assert cfg.listen_port == 30303
        assert cfg.max_peers == 50
        assert cfg.discovery.enabled is True
        assert cfg.security.post_quantum_enabled is True

    def test_from_dict(self):
        cfg = P2PConfig.from_dict({
            "listen_port": 31313,
            "max_peers": 10,
            "discovery": {"enabled": False, "bootnodes": ["http://a:1"]},
            "security": {"pq_required": True},
        })
        assert cfg.listen_port == 31313
        assert cfg.max_peers == 10
        assert cfg.discovery.enabled is False
        assert cfg.discovery.bootnodes == ["http://a:1"]
        assert cfg.security.pq_required is True

    def test_env_override_bootnodes(self):
        cfg = P2PConfig()
        with patch.dict(os.environ, {"QRDX_BOOTSTRAP_NODES": "http://x:1,http://y:2"}):
            cfg.apply_env()
        assert cfg.discovery.bootnodes == ["http://x:1", "http://y:2"]

    def test_env_override_port(self):
        cfg = P2PConfig()
        with patch.dict(os.environ, {"QRDX_P2P_PORT": "40404"}):
            cfg.apply_env()
        assert cfg.listen_port == 40404


class TestDatabaseConfig:
    """Tests for [database] section."""

    def test_defaults(self):
        cfg = DatabaseConfig()
        assert cfg.type == "sqlite"
        assert cfg.sqlite.path == "data/qrdx.db"
        assert cfg.sqlite.wal_mode is True

    def test_from_dict(self):
        cfg = DatabaseConfig.from_dict({
            "type": "sqlite",
            "sqlite": {"path": "/custom/db.sqlite", "wal_mode": False},
        })
        assert cfg.sqlite.path == "/custom/db.sqlite"
        assert cfg.sqlite.wal_mode is False

    def test_env_override(self):
        cfg = DatabaseConfig()
        with patch.dict(os.environ, {"QRDX_DB_PATH": "/env/db.sqlite"}):
            cfg.apply_env()
        assert cfg.sqlite.path == "/env/db.sqlite"


class TestGenesisConfig:
    def test_defaults(self):
        cfg = GenesisConfig()
        assert cfg.initial_supply == 100_000_000

    def test_from_dict_with_prefunded(self):
        cfg = GenesisConfig.from_dict({
            "chain_id": 42,
            "prefunded_accounts": {"addr1": [1000, "test"]},
        })
        assert cfg.chain_id == 42
        assert "addr1" in cfg.prefunded_accounts


class TestConsensusConfig:
    def test_defaults(self):
        cfg = ConsensusConfig()
        assert cfg.mechanism == "pos"
        assert cfg.pos.slot_duration == 2

    def test_from_dict(self):
        cfg = ConsensusConfig.from_dict({
            "mechanism": "pos",
            "pos": {"slot_duration": 4, "slots_per_epoch": 64},
        })
        assert cfg.pos.slot_duration == 4
        assert cfg.pos.slots_per_epoch == 64


class TestSyncConfig:
    def test_defaults(self):
        cfg = SyncConfig()
        assert cfg.mode == "full"
        assert cfg.batch_size == 128

    def test_from_dict(self):
        cfg = SyncConfig.from_dict({"mode": "fast", "batch_size": 256})
        assert cfg.mode == "fast"
        assert cfg.batch_size == 256


class TestMetricsConfigSection:
    def test_defaults(self):
        cfg = MetricsConfig()
        assert cfg.enabled is False
        assert cfg.port == 9090

    def test_env_override(self):
        cfg = MetricsConfig()
        with patch.dict(os.environ, {"QRDX_METRICS_ENABLED": "true", "QRDX_METRICS_PORT": "9191"}):
            cfg.apply_env()
        assert cfg.enabled is True
        assert cfg.port == 9191

    def test_env_false_values(self):
        cfg = MetricsConfig()
        with patch.dict(os.environ, {"QRDX_METRICS_ENABLED": "false"}):
            cfg.apply_env()
        assert cfg.enabled is False


class TestHealthConfig:
    def test_defaults(self):
        cfg = HealthConfig()
        assert cfg.enabled is True
        assert cfg.path == "/health"


class TestTLSConfigSection:
    def test_defaults(self):
        cfg = TLSConfig()
        assert cfg.enabled is False
        assert cfg.min_version == "1.2"
        assert cfg.client_auth is False

    def test_from_dict(self):
        cfg = TLSConfig.from_dict({
            "enabled": True,
            "cert_file": "/certs/cert.pem",
            "key_file": "/certs/key.pem",
            "min_version": "1.3",
        })
        assert cfg.enabled is True
        assert cfg.cert_file == "/certs/cert.pem"
        assert cfg.min_version == "1.3"

    def test_validate_disabled(self):
        """No error when TLS is disabled."""
        cfg = TLSConfig(enabled=False)
        cfg.validate()  # no exception

    def test_validate_missing_cert(self):
        cfg = TLSConfig(enabled=True, key_file="/tmp/key.pem")
        with pytest.raises(ValueError, match="cert_file not set"):
            cfg.validate()

    def test_validate_missing_key(self):
        cfg = TLSConfig(enabled=True, cert_file="/tmp/cert.pem")
        with pytest.raises(ValueError, match="key_file not set"):
            cfg.validate()

    def test_validate_bad_version(self, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("cert")
        key.write_text("key")
        cfg = TLSConfig(enabled=True, cert_file=str(cert), key_file=str(key), min_version="1.0")
        with pytest.raises(ValueError, match="Invalid TLS min_version"):
            cfg.validate()

    def test_env_override(self):
        cfg = TLSConfig()
        with patch.dict(os.environ, {
            "QRDX_TLS_CERT": "/env/cert.pem",
            "QRDX_TLS_KEY": "/env/key.pem",
        }):
            cfg.apply_env()
        assert cfg.cert_file == "/env/cert.pem"
        assert cfg.key_file == "/env/key.pem"


class TestNodeConfig:
    """Tests for the unified NodeConfig."""

    def test_from_file(self, toml_file):
        cfg = NodeConfig.from_file(toml_file)
        assert cfg.node.chain_id == 42
        assert cfg.node.network_name == "qrdx-testnet"
        assert cfg.p2p.listen_port == 30304
        assert cfg.p2p.max_peers == 25
        assert cfg.database.type == "sqlite"
        assert cfg.database.sqlite.path == "/tmp/test.db"
        assert cfg.consensus.mechanism == "pos"
        assert cfg.sync.batch_size == 64
        assert cfg.metrics.enabled is True
        assert cfg.health.path == "/health"

    def test_from_file_missing(self, tmp_path):
        """Missing file returns defaults."""
        cfg = NodeConfig.from_file(str(tmp_path / "nonexistent.toml"))
        assert cfg.node.chain_id == 1
        assert cfg.p2p.listen_port == 30303

    def test_from_file_env_override(self, toml_file):
        """Env vars override TOML values."""
        with patch.dict(os.environ, {"QRDX_CHAIN_ID": "999"}):
            cfg = NodeConfig.from_file(toml_file)
        assert cfg.node.chain_id == 999

    def test_validate_success(self, toml_file):
        cfg = NodeConfig.from_file(toml_file)
        assert cfg.validate() is True

    def test_validate_bad_chain_id(self):
        cfg = NodeConfig()
        cfg.node.chain_id = 0
        with pytest.raises(ValueError, match="chain_id must be >= 1"):
            cfg.validate()

    def test_validate_bad_log_level(self):
        cfg = NodeConfig()
        cfg.node.log_level = "TRACE"
        with pytest.raises(ValueError, match="Invalid log_level"):
            cfg.validate()

    def test_validate_bad_max_peers(self):
        cfg = NodeConfig()
        cfg.p2p.max_peers = 0
        with pytest.raises(ValueError, match="max_peers must be >= 1"):
            cfg.validate()

    def test_validate_bad_db_type(self):
        cfg = NodeConfig()
        cfg.database.type = "postgres"
        with pytest.raises(ValueError, match="Only 'sqlite'"):
            cfg.validate()

    def test_to_dict(self, toml_file):
        cfg = NodeConfig.from_file(toml_file)
        d = cfg.to_dict()
        assert d["node"]["chain_id"] == 42
        assert d["p2p"]["listen_port"] == 30304
        assert d["database"]["type"] == "sqlite"
        assert d["metrics"]["enabled"] is True

    def test_rpc_section_loaded(self, toml_file):
        cfg = NodeConfig.from_file(toml_file)
        assert cfg.rpc is not None
        assert cfg.rpc.http.host == "0.0.0.0"
        assert cfg.rpc.websocket.max_connections == 50
        assert cfg.rpc.modules.eth is True
        assert cfg.rpc.modules.admin is False

    def test_rpc_env_override(self, toml_file):
        with patch.dict(os.environ, {"QRDX_RPC_HTTP_PORT": "9999"}):
            cfg = NodeConfig.from_file(toml_file)
        assert cfg.rpc.http.port == 9999

    def test_load_config_convenience(self, toml_file):
        with patch.dict(os.environ, {"QRDX_CONFIG": toml_file}):
            cfg = load_config()
        assert cfg.node.chain_id == 42


# ===================================================================
# SECTION 2: JSON-RPC 2.0 Server Verification  (Step 11.1)
# ===================================================================

class TestRPCRequest:
    def test_from_dict(self):
        req = RPCRequest.from_dict({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1,
        })
        assert req.method == "eth_blockNumber"
        assert req.id == 1

    def test_is_notification(self):
        req = RPCRequest(jsonrpc="2.0", method="notify", params=None, id=None)
        assert req.is_notification is True

    def test_not_notification(self):
        req = RPCRequest(jsonrpc="2.0", method="call", params=None, id=1)
        assert req.is_notification is False


class TestRPCResponse:
    def test_to_dict_result(self):
        resp = RPCResponse(id=1, result="0x1")
        d = resp.to_dict()
        assert d["result"] == "0x1"
        assert "error" not in d or d["error"] is None

    def test_to_dict_error(self):
        resp = RPCResponse(id=1, error={"code": -32600, "message": "bad"})
        d = resp.to_dict()
        assert d["error"]["code"] == -32600

    def test_to_json(self):
        resp = RPCResponse(id=1, result=42)
        j = json.loads(resp.to_json())
        assert j["result"] == 42


class TestRPCError:
    def test_error_codes(self):
        assert RPCErrorCode.PARSE_ERROR == -32700
        assert RPCErrorCode.METHOD_NOT_FOUND == -32601
        assert RPCErrorCode.INTERNAL_ERROR == -32603

    def test_to_dict(self):
        err = RPCError(RPCErrorCode.INVALID_PARAMS, "bad params")
        d = err.to_dict()
        assert d["code"] == -32602
        assert "bad params" in d["message"]


class TestRPCModule:
    def test_method_discovery(self):
        class TestMod(RPCModule):
            namespace = "test"

            @rpc_method
            async def hello(self):
                return "world"

            async def _private(self):
                return "hidden"

        mod = TestMod()
        methods = mod.get_methods()
        assert "test_hello" in methods
        assert "_private" not in methods


class TestRPCServer:
    @pytest.mark.asyncio
    async def test_handle_single_request(self):
        server = RPCServer()

        async def block_number():
            return "0x10"

        server.register_method("eth_blockNumber", block_number)

        result = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "id": 1,
        })
        parsed = json.loads(result)
        assert parsed["result"] == "0x10"
        assert parsed["id"] == 1

    @pytest.mark.asyncio
    async def test_method_not_found(self):
        server = RPCServer()
        result = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "nonexistent",
            "id": 1,
        })
        parsed = json.loads(result)
        assert parsed["error"]["code"] == RPCErrorCode.METHOD_NOT_FOUND

    @pytest.mark.asyncio
    async def test_parse_error(self):
        server = RPCServer()
        result = await server.handle_request("{invalid json")
        parsed = json.loads(result)
        assert parsed["error"]["code"] == RPCErrorCode.PARSE_ERROR

    @pytest.mark.asyncio
    async def test_batch_request(self):
        server = RPCServer()

        async def echo(*args):
            return args[0] if args else None

        server.register_method("echo", echo)

        result = await server.handle_request([
            {"jsonrpc": "2.0", "method": "echo", "params": ["a"], "id": 1},
            {"jsonrpc": "2.0", "method": "echo", "params": ["b"], "id": 2},
        ])
        parsed = json.loads(result)
        assert len(parsed) == 2
        results = {r["id"]: r["result"] for r in parsed}
        assert results[1] == "a"
        assert results[2] == "b"

    @pytest.mark.asyncio
    async def test_empty_batch(self):
        server = RPCServer()
        result = await server.handle_request([])
        parsed = json.loads(result)
        assert parsed["error"]["code"] == RPCErrorCode.INVALID_REQUEST

    @pytest.mark.asyncio
    async def test_notification_no_response(self):
        called = []

        async def handler():
            called.append(True)

        server = RPCServer()
        server.register_method("notify", handler)

        result = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "notify",
        })
        assert result is None
        assert called == [True]

    @pytest.mark.asyncio
    async def test_register_module(self):
        class TestMod(RPCModule):
            namespace = "test"

            @rpc_method
            async def ping(self):
                return "pong"

        server = RPCServer()
        server.register_module(TestMod())

        result = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "test_ping",
            "id": 1,
        })
        parsed = json.loads(result)
        assert parsed["result"] == "pong"

    @pytest.mark.asyncio
    async def test_unregister_module(self):
        class TestMod(RPCModule):
            namespace = "test"

            @rpc_method
            async def ping(self):
                return "pong"

        server = RPCServer()
        server.register_module(TestMod())
        assert "test_ping" in server.get_methods()

        server.unregister_module("test")
        assert "test_ping" not in server.get_methods()

    @pytest.mark.asyncio
    async def test_kwargs_params(self):
        async def greet(name="world"):
            return f"hello {name}"

        server = RPCServer()
        server.register_method("greet", greet)

        result = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "greet",
            "params": {"name": "qrdx"},
            "id": 1,
        })
        parsed = json.loads(result)
        assert parsed["result"] == "hello qrdx"

    @pytest.mark.asyncio
    async def test_method_exception(self):
        async def fail():
            raise ValueError("boom")

        server = RPCServer()
        server.register_method("fail", fail)

        result = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "fail",
            "id": 1,
        })
        parsed = json.loads(result)
        assert parsed["error"]["code"] == RPCErrorCode.INTERNAL_ERROR


# ===================================================================
# SECTION 3: RPC Config  (Step 11.1)
# ===================================================================

class TestRPCConfig:
    def test_defaults(self):
        cfg = RPCConfig()
        assert cfg.enabled is True
        assert cfg.http.port == 8545
        assert cfg.websocket.port == 8546
        assert cfg.modules.eth is True
        assert cfg.modules.admin is False
        assert cfg.legacy.enabled is False

    def test_from_dict(self):
        cfg = RPCConfig.from_dict({
            "enabled": True,
            "http": {"port": 9545},
            "websocket": {"max_connections": 200},
            "modules": {"admin": True},
            "legacy": {"enabled": True},
        })
        assert cfg.http.port == 9545
        assert cfg.websocket.max_connections == 200
        assert cfg.modules.admin is True
        assert cfg.legacy.enabled is True


# ===================================================================
# SECTION 4: WebSocket Subscriptions  (Step 11.2)
# ===================================================================

class TestSubscriptionType:
    def test_values(self):
        assert SubscriptionType.NEW_HEADS.value == "newHeads"
        assert SubscriptionType.NEW_PENDING_TRANSACTIONS.value == "newPendingTransactions"
        assert SubscriptionType.LOGS.value == "logs"


class TestWSConnection:
    def test_creation(self):
        conn = WSConnection(id="abc123")
        assert conn.id == "abc123"
        assert conn.subscription_count == 0
        assert conn.closed is False


class TestWebSocketManager:
    """Tests for WebSocketManager."""

    def test_connect(self, ws_manager):
        conn = ws_manager.connect()
        assert ws_manager.active_connections == 1
        assert conn.id

    def test_connect_max_exceeded(self, ws_manager):
        for _ in range(5):
            ws_manager.connect()
        with pytest.raises(RPCError, match="Max WebSocket connections"):
            ws_manager.connect()

    def test_disconnect(self, ws_manager):
        conn = ws_manager.connect()
        ws_manager.disconnect(conn.id)
        assert ws_manager.active_connections == 0

    def test_disconnect_nonexistent(self, ws_manager):
        ws_manager.disconnect("nonexistent")  # no error

    def test_subscribe(self, ws_manager):
        conn = ws_manager.connect()
        sub_id = ws_manager.subscribe(conn.id, "newHeads")
        assert sub_id
        assert conn.subscription_count == 1

    def test_subscribe_all_types(self, ws_manager):
        conn = ws_manager.connect()
        ws_manager.subscribe(conn.id, "newHeads")
        ws_manager.subscribe(conn.id, "newPendingTransactions")
        ws_manager.subscribe(conn.id, "logs")
        assert conn.subscription_count == 3

    def test_subscribe_invalid_type(self, ws_manager):
        conn = ws_manager.connect()
        with pytest.raises(RPCError, match="Unknown subscription type"):
            ws_manager.subscribe(conn.id, "invalidType")

    def test_subscribe_max_per_conn(self, ws_manager):
        conn = ws_manager.connect()
        for _ in range(3):
            ws_manager.subscribe(conn.id, "newHeads")
        with pytest.raises(RPCError, match="Max subscriptions per connection"):
            ws_manager.subscribe(conn.id, "newHeads")

    def test_subscribe_nonexistent_conn(self, ws_manager):
        with pytest.raises(RPCError, match="Connection not found"):
            ws_manager.subscribe("nonexistent", "newHeads")

    def test_unsubscribe(self, ws_manager):
        conn = ws_manager.connect()
        sub_id = ws_manager.subscribe(conn.id, "newHeads")
        assert ws_manager.unsubscribe(conn.id, sub_id) is True
        assert conn.subscription_count == 0

    def test_unsubscribe_nonexistent(self, ws_manager):
        conn = ws_manager.connect()
        assert ws_manager.unsubscribe(conn.id, "fake") is False

    def test_unsubscribe_wrong_conn(self, ws_manager):
        assert ws_manager.unsubscribe("nonexistent", "fake") is False

    def test_disconnect_cleans_subscriptions(self, ws_manager):
        conn = ws_manager.connect()
        ws_manager.subscribe(conn.id, "newHeads")
        ws_manager.subscribe(conn.id, "logs")
        ws_manager.disconnect(conn.id)
        assert ws_manager.active_subscriptions == 0

    @pytest.mark.asyncio
    async def test_publish_newheads(self, ws_manager):
        async def mock_send(data):
            pass  # Simulate real WS transport

        conn = ws_manager.connect(send_fn=mock_send)
        ws_manager.subscribe(conn.id, "newHeads")

        sent = await ws_manager.publish(
            SubscriptionType.NEW_HEADS,
            {"number": "0x1", "hash": "0xabc"},
        )
        assert sent == 1

    @pytest.mark.asyncio
    async def test_publish_no_subscribers(self, ws_manager):
        sent = await ws_manager.publish(
            SubscriptionType.NEW_HEADS,
            {"number": "0x1"},
        )
        assert sent == 0

    @pytest.mark.asyncio
    async def test_publish_with_send_fn(self, ws_manager):
        received = []
        send_fn = AsyncMock(side_effect=lambda msg: received.append(json.loads(msg)))

        conn = ws_manager.connect(send_fn=send_fn)
        ws_manager.subscribe(conn.id, "newPendingTransactions")

        await ws_manager.publish(
            SubscriptionType.NEW_PENDING_TRANSACTIONS,
            {"hash": "0xdeadbeef"},
        )

        assert len(received) == 1
        assert received[0]["method"] == "eth_subscription"
        assert received[0]["params"]["result"]["hash"] == "0xdeadbeef"

    @pytest.mark.asyncio
    async def test_publish_failed_send_disconnects(self, ws_manager):
        send_fn = AsyncMock(side_effect=ConnectionError("gone"))
        conn = ws_manager.connect(send_fn=send_fn)
        ws_manager.subscribe(conn.id, "newHeads")

        await ws_manager.publish(SubscriptionType.NEW_HEADS, {"n": 1})
        assert ws_manager.active_connections == 0

    @pytest.mark.asyncio
    async def test_publish_logs_with_filter(self, ws_manager):
        async def mock_send(data): pass
        conn = ws_manager.connect(send_fn=mock_send)
        ws_manager.subscribe(
            conn.id, "logs",
            filter_params={"address": "0xABC"},
        )

        # Matching log
        sent = await ws_manager.publish(
            SubscriptionType.LOGS,
            {"address": "0xabc", "topics": ["0x1"]},
        )
        assert sent == 1

        # Non-matching log
        sent = await ws_manager.publish(
            SubscriptionType.LOGS,
            {"address": "0xDEF", "topics": ["0x1"]},
        )
        assert sent == 0

    @pytest.mark.asyncio
    async def test_publish_logs_topic_filter(self, ws_manager):
        async def mock_send(data): pass
        conn = ws_manager.connect(send_fn=mock_send)
        ws_manager.subscribe(
            conn.id, "logs",
            filter_params={"topics": ["0xTransfer", None, "0xRecipient"]},
        )

        # Match
        sent = await ws_manager.publish(
            SubscriptionType.LOGS,
            {"address": "0x1", "topics": ["0xTransfer", "0xSender", "0xRecipient"]},
        )
        assert sent == 1

        # No match — wrong topic[0]
        sent = await ws_manager.publish(
            SubscriptionType.LOGS,
            {"address": "0x1", "topics": ["0xApprove", "0xSender", "0xRecipient"]},
        )
        assert sent == 0

    @pytest.mark.asyncio
    async def test_publish_logs_topic_or_match(self, ws_manager):
        async def mock_send(data): pass
        conn = ws_manager.connect(send_fn=mock_send)
        ws_manager.subscribe(
            conn.id, "logs",
            filter_params={"topics": [["0xA", "0xB"]]},
        )

        sent = await ws_manager.publish(
            SubscriptionType.LOGS,
            {"address": "0x1", "topics": ["0xB"]},
        )
        assert sent == 1

    def test_get_stats(self, ws_manager):
        conn = ws_manager.connect()
        ws_manager.subscribe(conn.id, "newHeads")

        stats = ws_manager.get_stats()
        assert stats["active_connections"] == 1
        assert stats["active_subscriptions"] == 1
        assert stats["subscriptions_by_type"]["newHeads"] == 1

    def test_stats_tracking(self, ws_manager):
        conn1 = ws_manager.connect()
        conn2 = ws_manager.connect()
        ws_manager.subscribe(conn1.id, "newHeads")
        ws_manager.disconnect(conn2.id)

        assert ws_manager.total_connections_served == 2
        assert ws_manager.total_subscriptions_created == 1

    @pytest.mark.asyncio
    async def test_handle_rpc_subscribe(self, ws_manager):
        conn = ws_manager.connect()
        response = await ws_manager.handle_rpc_message(conn.id, json.dumps({
            "jsonrpc": "2.0",
            "method": "eth_subscribe",
            "params": ["newHeads"],
            "id": 1,
        }))
        parsed = json.loads(response)
        assert "result" in parsed
        assert conn.subscription_count == 1

    @pytest.mark.asyncio
    async def test_handle_rpc_unsubscribe(self, ws_manager):
        conn = ws_manager.connect()
        # Subscribe
        resp1 = await ws_manager.handle_rpc_message(conn.id, json.dumps({
            "jsonrpc": "2.0",
            "method": "eth_subscribe",
            "params": ["newHeads"],
            "id": 1,
        }))
        sub_id = json.loads(resp1)["result"]

        # Unsubscribe
        resp2 = await ws_manager.handle_rpc_message(conn.id, json.dumps({
            "jsonrpc": "2.0",
            "method": "eth_unsubscribe",
            "params": [sub_id],
            "id": 2,
        }))
        assert json.loads(resp2)["result"] is True
        assert conn.subscription_count == 0

    @pytest.mark.asyncio
    async def test_handle_rpc_subscribe_invalid(self, ws_manager):
        conn = ws_manager.connect()
        response = await ws_manager.handle_rpc_message(conn.id, json.dumps({
            "jsonrpc": "2.0",
            "method": "eth_subscribe",
            "params": ["badType"],
            "id": 1,
        }))
        parsed = json.loads(response)
        assert "error" in parsed

    @pytest.mark.asyncio
    async def test_handle_rpc_delegated(self, ws_manager):
        """Non-subscription methods are delegated to RPCServer."""

        async def block_num():
            return "0x42"

        rpc = RPCServer()
        rpc.register_method("eth_blockNumber", block_num)
        ws_manager.rpc_server = rpc

        conn = ws_manager.connect()
        response = await ws_manager.handle_rpc_message(conn.id, json.dumps({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "id": 1,
        }))
        assert json.loads(response)["result"] == "0x42"

    @pytest.mark.asyncio
    async def test_handle_rpc_parse_error(self, ws_manager):
        conn = ws_manager.connect()
        response = await ws_manager.handle_rpc_message(conn.id, "{bad json")
        parsed = json.loads(response)
        assert parsed["error"]["code"] == RPCErrorCode.PARSE_ERROR

    @pytest.mark.asyncio
    async def test_handle_rpc_no_server(self, ws_manager):
        conn = ws_manager.connect()
        response = await ws_manager.handle_rpc_message(conn.id, json.dumps({
            "jsonrpc": "2.0",
            "method": "unknown_method",
            "id": 1,
        }))
        parsed = json.loads(response)
        assert parsed["error"]["code"] == RPCErrorCode.INTERNAL_ERROR


class TestLogFilter:
    """Edge cases for log filtering."""

    def test_no_filter(self):
        assert WebSocketManager._match_log_filter(
            {"address": "0x1", "topics": ["0x2"]},
            {},
        ) is True

    def test_address_list(self):
        assert WebSocketManager._match_log_filter(
            {"address": "0xabc"},
            {"address": ["0xABC", "0xDEF"]},
        ) is True

    def test_topic_too_short(self):
        assert WebSocketManager._match_log_filter(
            {"address": "0x1", "topics": ["0xA"]},
            {"topics": [None, "0xB"]},
        ) is False

    def test_empty_topics(self):
        assert WebSocketManager._match_log_filter(
            {"address": "0x1", "topics": []},
            {"topics": []},
        ) is True


# ===================================================================
# SECTION 5: Prometheus Metrics  (Step 12.3)
# ===================================================================

class TestCounter:
    def test_initial_value(self):
        c = Counter("test_counter")
        assert c.value == 0.0

    def test_increment(self):
        c = Counter("test_counter")
        c.inc()
        assert c.value == 1.0
        c.inc(5)
        assert c.value == 6.0

    def test_negative_increment_raises(self):
        c = Counter("test_counter")
        with pytest.raises(ValueError, match="only be incremented"):
            c.inc(-1)

    def test_expose(self):
        c = Counter("req_total", help="Total requests")
        c.inc(42)
        text = c.expose()
        assert "# HELP req_total Total requests" in text
        assert "# TYPE req_total counter" in text
        assert "req_total 42" in text

    def test_thread_safety(self):
        c = Counter("threaded")
        threads = []
        for _ in range(10):
            t = threading.Thread(target=lambda: [c.inc() for _ in range(100)])
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        assert c.value == 1000.0


class TestGauge:
    def test_initial_value(self):
        g = Gauge("test_gauge")
        assert g.value == 0.0

    def test_set(self):
        g = Gauge("test_gauge")
        g.set(42)
        assert g.value == 42

    def test_inc_dec(self):
        g = Gauge("test_gauge")
        g.inc(10)
        assert g.value == 10
        g.dec(3)
        assert g.value == 7

    def test_expose(self):
        g = Gauge("peer_count", help="Connected peers")
        g.set(25)
        text = g.expose()
        assert "# TYPE peer_count gauge" in text
        assert "peer_count 25" in text

    def test_thread_safety(self):
        g = Gauge("threaded")
        threads = []
        for _ in range(10):
            t = threading.Thread(target=lambda: [g.inc() for _ in range(100)])
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        assert g.value == 1000.0


class TestHistogram:
    def test_empty(self):
        h = Histogram("latency")
        assert h.count == 0
        assert h.sum == 0.0

    def test_observe(self):
        h = Histogram("latency", buckets=(0.1, 0.5, 1.0))
        h.observe(0.05)
        h.observe(0.3)
        h.observe(0.8)
        assert h.count == 3
        assert abs(h.sum - 1.15) < 1e-9

    def test_bucket_counts(self):
        h = Histogram("latency", buckets=(0.1, 0.5, 1.0))
        h.observe(0.05)   # bucket 0.1
        h.observe(0.3)    # bucket 0.5
        h.observe(0.8)    # bucket 1.0
        h.observe(2.0)    # only +Inf

        text = h.expose()
        assert "# TYPE latency histogram" in text
        # Prometheus buckets are cumulative:
        #   le=0.1 → 1 (only 0.05)
        #   le=0.5 → 2 (0.05 + 0.3)
        #   le=1.0 → 3 (0.05 + 0.3 + 0.8)
        #   le=+Inf → 4 (all)
        assert 'latency_bucket{le="0.1"} 1' in text
        assert 'latency_bucket{le="0.5"} 2' in text
        assert 'latency_bucket{le="1.0"} 3' in text
        assert 'latency_bucket{le="+Inf"} 4' in text
        assert "latency_count 4" in text

    def test_expose_format(self):
        h = Histogram("rpc_lat", help="RPC latency", buckets=(1.0,))
        h.observe(0.5)
        text = h.expose()
        assert "# HELP rpc_lat RPC latency" in text
        assert "rpc_lat_sum 0.5" in text
        assert "rpc_lat_count 1" in text

    def test_default_buckets(self):
        h = Histogram("default")
        assert h.buckets == DEFAULT_BUCKETS


class TestMetricsRegistry:
    def test_register(self, registry):
        c = Counter("test")
        registry.register(c)
        assert registry.metric_count == 1

    def test_duplicate_raises(self, registry):
        c = Counter("test")
        registry.register(c)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(Counter("test"))

    def test_unregister(self, registry):
        c = Counter("test")
        registry.register(c)
        registry.unregister("test")
        assert registry.metric_count == 0

    def test_get(self, registry):
        c = Counter("test")
        registry.register(c)
        assert registry.get("test") is c
        assert registry.get("nonexistent") is None

    def test_expose_all(self, registry):
        c = Counter("requests_total", help="Total req")
        g = Gauge("peers", help="Peers")
        c.inc(100)
        g.set(5)
        registry.register(c)
        registry.register(g)

        text = registry.expose()
        assert "requests_total 100" in text
        assert "peers 5" in text
        assert text.endswith("\n")


class TestMetricsCollector:
    def test_all_metrics_registered(self, metrics_collector):
        """All standard metrics should be in the registry."""
        assert metrics_collector.registry.metric_count >= 15

    def test_block_metrics(self, metrics_collector):
        metrics_collector.block_height.set(100)
        metrics_collector.blocks_processed.inc()
        metrics_collector.block_processing_time.observe(0.5)

        assert metrics_collector.block_height.value == 100
        assert metrics_collector.blocks_processed.value == 1.0

    def test_transaction_metrics(self, metrics_collector):
        metrics_collector.transactions_total.inc(50)
        metrics_collector.mempool_size.set(200)

        assert metrics_collector.transactions_total.value == 50
        assert metrics_collector.mempool_size.value == 200

    def test_network_metrics(self, metrics_collector):
        metrics_collector.peer_count.set(12)
        metrics_collector.ws_connections.set(3)

        assert metrics_collector.peer_count.value == 12
        assert metrics_collector.ws_connections.value == 3

    def test_validator_metrics(self, metrics_collector):
        metrics_collector.validator_active.set(1)
        metrics_collector.attestations_sent.inc(10)
        metrics_collector.proposals_made.inc(2)

        assert metrics_collector.validator_active.value == 1
        assert metrics_collector.attestations_sent.value == 10

    def test_rpc_metrics(self, metrics_collector):
        metrics_collector.rpc_requests_total.inc(1000)
        metrics_collector.rpc_errors_total.inc(5)
        metrics_collector.rpc_latency.observe(0.01)

        assert metrics_collector.rpc_requests_total.value == 1000
        assert metrics_collector.rpc_errors_total.value == 5

    def test_consensus_metrics(self, metrics_collector):
        metrics_collector.finalized_epoch.set(42)
        metrics_collector.current_slot.set(1344)

        assert metrics_collector.finalized_epoch.value == 42
        assert metrics_collector.current_slot.value == 1344

    def test_uptime(self, metrics_collector):
        time.sleep(0.05)
        metrics_collector.update_uptime()
        assert metrics_collector.uptime_seconds.value >= 0.04

    def test_expose_prometheus_format(self, metrics_collector):
        metrics_collector.block_height.set(500)
        metrics_collector.peer_count.set(10)

        text = metrics_collector.expose()
        assert "qrdx_block_height 500" in text
        assert "qrdx_peer_count 10" in text
        assert "qrdx_uptime_seconds" in text
        # Verify it's valid Prometheus format
        for line in text.strip().split("\n"):
            if line.startswith("#"):
                assert line.startswith("# HELP") or line.startswith("# TYPE")
            elif line.strip():
                # metric_name value
                parts = line.split()
                assert len(parts) >= 2


# ===================================================================
# SECTION 6: TLS Support  (Step 12.4)
# ===================================================================

class TestTLSContextBuilder:
    def test_validate_no_cert(self):
        builder = TLSContextBuilder(key_file="/tmp/k.pem")
        with pytest.raises(ValueError, match="cert_file is required"):
            builder.validate()

    def test_validate_no_key(self):
        builder = TLSContextBuilder(cert_file="/tmp/c.pem")
        with pytest.raises(ValueError, match="key_file is required"):
            builder.validate()

    def test_validate_file_not_found(self, tmp_path):
        builder = TLSContextBuilder(
            cert_file=str(tmp_path / "nonexistent.pem"),
            key_file=str(tmp_path / "nonexistent.key"),
        )
        with pytest.raises(ValueError, match="not found"):
            builder.validate()

    def test_validate_bad_min_version(self, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("cert")
        key.write_text("key")

        builder = TLSContextBuilder(
            cert_file=str(cert),
            key_file=str(key),
            min_version="1.0",
        )
        with pytest.raises(ValueError, match="Invalid TLS min_version"):
            builder.validate()

    def test_validate_cert_not_file(self, tmp_path):
        # cert_file pointing to a directory
        cert = tmp_path / "certdir"
        cert.mkdir()
        key = tmp_path / "key.pem"
        key.write_text("key")

        builder = TLSContextBuilder(
            cert_file=str(cert),
            key_file=str(key),
        )
        with pytest.raises(ValueError, match="not a file"):
            builder.validate()

    def test_build_server_context_with_real_cert(self, tmp_path):
        """Test with a self-signed cert if cryptography is available."""
        try:
            from qrdx.network.tls import generate_self_signed_cert
            cert_path, key_path = generate_self_signed_cert()

            builder = TLSContextBuilder(
                cert_file=cert_path,
                key_file=key_path,
                min_version="1.2",
            )
            ctx = builder.build_server_context()
            assert isinstance(ctx, ssl.SSLContext)
            assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2

            # Cleanup
            os.unlink(cert_path)
            os.unlink(key_path)
        except ImportError:
            pytest.skip("cryptography package not installed")

    def test_build_server_context_tls13(self, tmp_path):
        """TLS 1.3 minimum version."""
        try:
            from qrdx.network.tls import generate_self_signed_cert
            cert_path, key_path = generate_self_signed_cert()

            builder = TLSContextBuilder(
                cert_file=cert_path,
                key_file=key_path,
                min_version="1.3",
            )
            ctx = builder.build_server_context()
            assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_3

            os.unlink(cert_path)
            os.unlink(key_path)
        except ImportError:
            pytest.skip("cryptography package not installed")

    def test_uvicorn_ssl_params(self, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("cert")
        key.write_text("key")

        builder = TLSContextBuilder(
            cert_file=str(cert),
            key_file=str(key),
        )
        params = builder.get_uvicorn_ssl_params()
        assert params["ssl_keyfile"] == str(key)
        assert params["ssl_certfile"] == str(cert)

    def test_uvicorn_ssl_params_with_ca(self, tmp_path):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        ca = tmp_path / "ca.pem"
        cert.write_text("cert")
        key.write_text("key")
        ca.write_text("ca")

        builder = TLSContextBuilder(
            cert_file=str(cert),
            key_file=str(key),
            ca_file=str(ca),
        )
        params = builder.get_uvicorn_ssl_params()
        assert "ssl_ca_certs" in params


class TestHSTSHeader:
    def test_default(self):
        h = hsts_header()
        assert "max-age=31536000" in h
        assert "includeSubDomains" in h

    def test_custom_max_age(self):
        h = hsts_header(max_age=3600)
        assert "max-age=3600" in h

    def test_no_subdomains(self):
        h = hsts_header(include_subdomains=False)
        assert "includeSubDomains" not in h


class TestSelfSignedCert:
    def test_generate(self):
        try:
            from qrdx.network.tls import generate_self_signed_cert
            cert_path, key_path = generate_self_signed_cert(common_name="test.local")

            assert Path(cert_path).exists()
            assert Path(key_path).exists()
            assert Path(cert_path).stat().st_size > 0
            assert Path(key_path).stat().st_size > 0

            os.unlink(cert_path)
            os.unlink(key_path)
        except ImportError:
            pytest.skip("cryptography package not installed")


# ===================================================================
# SECTION 7: Docker / Production Config Validation  (Step 12.1)
# ===================================================================

class TestDockerConfigs:
    """Validate that production Docker configs exist and are well-formed."""

    def test_prod_compose_exists(self):
        path = Path(__file__).parent.parent / "docker" / "docker-compose.prod.yml"
        assert path.exists(), "docker-compose.prod.yml must exist"

    def test_prod_compose_services(self):
        """Production compose should define 3 services."""
        path = Path(__file__).parent.parent / "docker" / "docker-compose.prod.yml"
        content = path.read_text()
        assert "qrdx-node" in content
        assert "prometheus" in content
        assert "grafana" in content

    def test_prod_compose_volumes(self):
        path = Path(__file__).parent.parent / "docker" / "docker-compose.prod.yml"
        content = path.read_text()
        assert "qrdx-data" in content
        assert "prometheus-data" in content

    def test_prod_compose_resource_limits(self):
        path = Path(__file__).parent.parent / "docker" / "docker-compose.prod.yml"
        content = path.read_text()
        assert "resources:" in content
        assert "limits:" in content

    def test_prod_compose_non_root(self):
        path = Path(__file__).parent.parent / "docker" / "docker-compose.prod.yml"
        content = path.read_text()
        assert 'user:' in content

    def test_prod_compose_security(self):
        path = Path(__file__).parent.parent / "docker" / "docker-compose.prod.yml"
        content = path.read_text()
        assert "no-new-privileges" in content
        assert "read_only: true" in content

    def test_prod_compose_healthcheck(self):
        path = Path(__file__).parent.parent / "docker" / "docker-compose.prod.yml"
        content = path.read_text()
        assert "healthcheck:" in content

    def test_prometheus_config_exists(self):
        path = Path(__file__).parent.parent / "docker" / "prometheus.yml"
        assert path.exists()

    def test_prometheus_scrape_targets(self):
        path = Path(__file__).parent.parent / "docker" / "prometheus.yml"
        content = path.read_text()
        assert "qrdx-node" in content
        assert "/metrics" in content

    def test_alert_rules_exist(self):
        path = Path(__file__).parent.parent / "docker" / "alert-rules.yml"
        assert path.exists()

    def test_alert_rules_content(self):
        path = Path(__file__).parent.parent / "docker" / "alert-rules.yml"
        content = path.read_text()
        assert "ChainStall" in content
        assert "LowPeerCount" in content
        assert "HighRPCErrorRate" in content
        assert "ValidatorInactive" in content
        assert "FinalityStall" in content

    def test_dockerfile_exists(self):
        path = Path(__file__).parent.parent / "docker" / "Dockerfile"
        assert path.exists()

    def test_config_example_exists(self):
        path = Path(__file__).parent.parent / "config.example.toml"
        assert path.exists()


# ===================================================================
# SECTION 8: Integration Helpers  (Step 13.2)
# ===================================================================

class TestConfigIntegration:
    """Integration: config → RPC → metrics → TLS flow."""

    def test_config_to_rpc_config(self, toml_file):
        """NodeConfig properly loads RPC sub-config."""
        cfg = NodeConfig.from_file(toml_file)
        assert isinstance(cfg.rpc, RPCConfig)
        assert cfg.rpc.http.port == 8545
        assert cfg.rpc.websocket.port == 8546

    def test_config_to_metrics(self, toml_file):
        """Metrics config is properly loaded."""
        cfg = NodeConfig.from_file(toml_file)
        assert cfg.metrics.enabled is True
        assert cfg.metrics.port == 9090

    def test_metrics_collector_expose_is_valid(self, metrics_collector):
        """Full collector expose produces valid Prometheus text."""
        metrics_collector.block_height.set(1000)
        metrics_collector.peer_count.set(25)
        metrics_collector.transactions_total.inc(5000)
        metrics_collector.rpc_requests_total.inc(100)
        metrics_collector.rpc_latency.observe(0.01)
        metrics_collector.rpc_latency.observe(0.5)

        text = metrics_collector.expose()

        # Should have all metric types
        assert "# TYPE qrdx_block_height gauge" in text
        assert "# TYPE qrdx_blocks_processed_total counter" in text
        assert "# TYPE qrdx_rpc_latency_seconds histogram" in text

        # Histogram should have buckets
        assert 'qrdx_rpc_latency_seconds_bucket{le=' in text
        assert "qrdx_rpc_latency_seconds_count 2" in text

    @pytest.mark.asyncio
    async def test_ws_manager_full_lifecycle(self):
        """Full lifecycle: connect → subscribe → publish → unsubscribe → disconnect."""
        manager = WebSocketManager(max_connections=10, max_subscriptions_per_conn=5)
        async def mock_send(data): pass

        # Connect
        conn = manager.connect(send_fn=mock_send)
        assert manager.active_connections == 1

        # Subscribe to 2 channels
        sub1 = manager.subscribe(conn.id, "newHeads")
        sub2 = manager.subscribe(conn.id, "newPendingTransactions")
        assert conn.subscription_count == 2

        # Publish events
        sent1 = await manager.publish(SubscriptionType.NEW_HEADS, {"number": "0x1"})
        assert sent1 == 1

        sent2 = await manager.publish(SubscriptionType.NEW_PENDING_TRANSACTIONS, {"hash": "0xabc"})
        assert sent2 == 1

        # Unsubscribe one
        assert manager.unsubscribe(conn.id, sub1) is True
        assert conn.subscription_count == 1

        # Publish again — only sub2 receives
        sent3 = await manager.publish(SubscriptionType.NEW_HEADS, {"number": "0x2"})
        assert sent3 == 0

        sent4 = await manager.publish(SubscriptionType.NEW_PENDING_TRANSACTIONS, {"hash": "0xdef"})
        assert sent4 == 1

        # Disconnect
        manager.disconnect(conn.id)
        assert manager.active_connections == 0
        assert manager.active_subscriptions == 0

    @pytest.mark.asyncio
    async def test_multiple_connections_publish(self):
        """Events are dispatched to all matching subscribers across connections."""
        manager = WebSocketManager(max_connections=10, max_subscriptions_per_conn=5)
        async def mock_send(data): pass

        conn1 = manager.connect(send_fn=mock_send)
        conn2 = manager.connect(send_fn=mock_send)
        conn3 = manager.connect(send_fn=mock_send)

        manager.subscribe(conn1.id, "newHeads")
        manager.subscribe(conn2.id, "newHeads")
        # conn3 does NOT subscribe to newHeads

        sent = await manager.publish(SubscriptionType.NEW_HEADS, {"number": "0x5"})
        assert sent == 2

    def test_rpc_server_list_methods(self):
        """RPCServer lists all registered methods."""
        server = RPCServer()

        async def m1():
            pass

        async def m2():
            pass

        server.register_method("eth_blockNumber", m1)
        server.register_method("eth_chainId", m2)

        methods = server.get_methods()
        assert "eth_blockNumber" in methods
        assert "eth_chainId" in methods
        assert len(methods) == 2
