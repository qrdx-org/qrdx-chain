"""
Tests for QRDX Kademlia DHT integration with the JSON-RPC server.

Verifies that:
1. dht_message RPC method is registered and delegates to KademliaDiscovery
2. dht_getStats RPC method returns DHT statistics
3. dht_getPeers and dht_getRoutingTable RPC methods work
4. DHTModule is always registered (not gated by QRDX_RPC_ENABLED)
5. _init_dht() creates RoutingTable, KademliaDiscovery, DNSSeedDiscovery
6. _init_dht() wires the DHTModule via set_discovery()
7. Shutdown stops DHT and persists routing table
8. _dht_bridge_sync() pushes/pulls peers between DHT and NodesManager
9. discovery.py _send_rpc uses JSON-RPC 2.0 envelope to /rpc
10. /rpc endpoint is always available (not conditional on QRDX_RPC_ENABLED)
"""

import asyncio
import json
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _diverse_ip(i: int) -> str:
    """Generate an IP in a unique /16 subnet for each i."""
    a = 10 + (i % 246)
    b = (i * 7) % 256
    return f'{a}.{b}.0.1'


@pytest.fixture
def pq_keypair():
    """Generate a fresh Dilithium keypair."""
    import oqs
    for algo in ('ML-DSA-65', 'Dilithium3'):
        try:
            signer = oqs.Signature(algo)
            pk = signer.generate_keypair()
            sk = signer.export_secret_key()
            return sk, pk
        except Exception:
            continue
    pytest.skip("No PQ signature algorithm available")


@pytest.fixture
def local_node(pq_keypair):
    """Create a local P2P Node from a generated keypair."""
    from qrdx.p2p.node import Node as P2PNode, Address as P2PAddress
    _, pk = pq_keypair
    return P2PNode(public_key=pk, address=P2PAddress(ip='127.0.0.1', tcp_port=30303))


@pytest.fixture
def routing_table(local_node):
    """Create a fresh RoutingTable."""
    from qrdx.p2p.routing import RoutingTable
    return RoutingTable(local_node.node_id)


@pytest.fixture
def discovery(local_node, routing_table):
    """Create a KademliaDiscovery instance."""
    from qrdx.p2p.discovery import KademliaDiscovery
    return KademliaDiscovery(local_node=local_node, routing_table=routing_table)


@pytest.fixture
def dht_module(discovery):
    """Create a DHTModule wired to a real discovery instance."""
    from qrdx.rpc.modules.dht import DHTModule
    mod = DHTModule()
    mod.set_discovery(discovery)
    return mod


# ============================================================================
# TEST: /rpc endpoint is always registered
# ============================================================================

class TestRPCEndpointAlwaysOn:
    """The /rpc POST route must be registered unconditionally."""

    def test_rpc_route_exists(self):
        """The /rpc POST route must be registered in the FastAPI app."""
        from qrdx.node.main import app
        routes = {r.path for r in app.routes if hasattr(r, 'path')}
        assert '/rpc' in routes, f"/rpc not found in routes: {routes}"

    def test_rpc_route_is_post(self):
        """The /rpc route must accept POST."""
        from qrdx.node.main import app
        for route in app.routes:
            if hasattr(route, 'path') and route.path == '/rpc':
                assert 'POST' in route.methods
                return
        pytest.fail("/rpc route not found")

    def test_legacy_dht_message_route_removed(self):
        """The old /dht/message REST endpoint must NOT exist."""
        from qrdx.node.main import app
        routes = {r.path for r in app.routes if hasattr(r, 'path')}
        assert '/dht/message' not in routes, "/dht/message legacy route still exists"

    def test_legacy_dht_stats_route_removed(self):
        """The old /dht/stats REST endpoint must NOT exist."""
        from qrdx.node.main import app
        routes = {r.path for r in app.routes if hasattr(r, 'path')}
        assert '/dht/stats' not in routes, "/dht/stats legacy route still exists"


# ============================================================================
# TEST: DHTModule RPC method registration
# ============================================================================

class TestDHTModuleRegistration:
    """Verify the DHTModule registers correct RPC methods."""

    def test_dht_module_namespace(self):
        from qrdx.rpc.modules.dht import DHTModule
        mod = DHTModule()
        assert mod.namespace == 'dht'

    def test_dht_module_methods(self):
        """DHTModule must expose message, getStats, getPeers, getRoutingTable."""
        from qrdx.rpc.modules.dht import DHTModule
        mod = DHTModule()
        methods = mod.get_methods()
        assert 'dht_message' in methods
        assert 'dht_getStats' in methods
        assert 'dht_getPeers' in methods
        assert 'dht_getRoutingTable' in methods

    def test_dht_methods_are_rpc_decorated(self):
        """All public methods should have __rpc_method__ attribute."""
        from qrdx.rpc.modules.dht import DHTModule
        mod = DHTModule()
        for name, handler in mod.get_methods().items():
            assert hasattr(handler, '__rpc_method__'), f"{name} missing @rpc_method"


# ============================================================================
# TEST: dht_message RPC method
# ============================================================================

class TestDHTMessageRPC:
    """Verify dht_message delegates to KademliaDiscovery.handle_incoming."""

    @pytest.mark.asyncio
    async def test_dht_message_raises_when_not_initialized(self):
        """dht_message should raise RPCError when discovery is None."""
        from qrdx.rpc.modules.dht import DHTModule
        from qrdx.rpc.server import RPCError
        mod = DHTModule()
        with pytest.raises(RPCError):
            await mod.message({"type": "ping"})

    @pytest.mark.asyncio
    async def test_dht_message_handles_ping(self, dht_module, discovery):
        """dht_message should handle a PING and return PONG."""
        ping_msg = {
            'type': 'ping',
            'sender_id': discovery._local.node_id_hex,
            'sender_host': '127.0.0.1',
            'sender_port': 30303,
            'payload': {},
        }
        result = await dht_module.message(ping_msg)
        assert result['type'] == 'pong'

    @pytest.mark.asyncio
    async def test_dht_message_handles_find_node(self, dht_module, discovery):
        """dht_message should handle a FIND_NODE request."""
        find_msg = {
            'type': 'find_node',
            'sender_id': discovery._local.node_id_hex,
            'sender_host': '127.0.0.1',
            'sender_port': 30303,
            'payload': {'target': discovery._local.node_id_hex},
        }
        result = await dht_module.message(find_msg)
        assert result['type'] == 'find_node_response'


# ============================================================================
# TEST: dht_getStats RPC method
# ============================================================================

class TestDHTGetStatsRPC:
    """Verify dht_getStats returns statistics."""

    @pytest.mark.asyncio
    async def test_get_stats_returns_dict(self, dht_module):
        """dht_getStats should return a dict with running, routing_table, etc."""
        stats = await dht_module.getStats()
        assert 'running' in stats
        assert 'routing_table' in stats
        assert 'local_node_id' in stats

    @pytest.mark.asyncio
    async def test_get_stats_includes_dns_when_set(self, dht_module):
        """dht_getStats should include dns_seeds when DNSSeedDiscovery is set."""
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery
        dns = DNSSeedDiscovery(require_signatures=False)
        dht_module._dns_seeds = dns
        stats = await dht_module.getStats()
        assert 'dns_seeds' in stats


# ============================================================================
# TEST: dht_getPeers RPC method
# ============================================================================

class TestDHTGetPeersRPC:
    """Verify dht_getPeers returns peer list."""

    @pytest.mark.asyncio
    async def test_get_peers_empty(self, dht_module):
        """dht_getPeers should return empty list when no peers."""
        peers = await dht_module.getPeers()
        assert isinstance(peers, list)
        assert len(peers) == 0

    @pytest.mark.asyncio
    async def test_get_peers_returns_entries(self, dht_module, discovery, pq_keypair):
        """dht_getPeers should return peer entries from routing table."""
        import oqs
        from qrdx.p2p.routing import KBucketEntry
        from qrdx.p2p.node import derive_node_id, derive_node_id_hex

        for algo in ('ML-DSA-65', 'Dilithium3'):
            try:
                signer = oqs.Signature(algo)
                peer_pk = signer.generate_keypair()
                break
            except Exception:
                continue

        nid = derive_node_id(peer_pk)
        nid_hex = derive_node_id_hex(peer_pk)
        entry = KBucketEntry(
            node_id=nid, node_id_hex=nid_hex,
            host='10.1.0.1', port=30303,
            public_key_hex=peer_pk.hex(),
            at_schema='', last_seen=time.monotonic(),
            added_at=time.monotonic(), is_inbound=False,
        )
        discovery.routing_table.add_node(entry, is_inbound=False)

        peers = await dht_module.getPeers()
        assert len(peers) >= 1
        assert peers[0]['host'] == '10.1.0.1'


# ============================================================================
# TEST: discovery.py _send_rpc uses JSON-RPC envelope
# ============================================================================

class TestDiscoverySendRPC:
    """Verify KademliaDiscovery._send_rpc sends JSON-RPC 2.0 to /rpc."""

    def test_send_rpc_targets_rpc_endpoint(self):
        """_send_rpc should build URL as http://host:port/rpc."""
        import inspect
        from qrdx.p2p.discovery import KademliaDiscovery
        source = inspect.getsource(KademliaDiscovery._send_rpc)
        # Must target /rpc, not /dht/message
        assert '/rpc' in source
        assert '/dht/message' not in source

    def test_send_rpc_uses_jsonrpc_envelope(self):
        """_send_rpc should wrap messages in JSON-RPC 2.0 format."""
        import inspect
        from qrdx.p2p.discovery import KademliaDiscovery
        source = inspect.getsource(KademliaDiscovery._send_rpc)
        assert '"jsonrpc"' in source
        assert '"method"' in source
        assert 'dht_message' in source

    @pytest.mark.asyncio
    async def test_send_rpc_extracts_result_from_jsonrpc_response(self, discovery):
        """_send_rpc should extract the 'result' from JSON-RPC response."""
        from qrdx.p2p.discovery import DHTMessage, DHTMessageType

        # Create a mock response with JSON-RPC wrapper
        pong = {
            "jsonrpc": "2.0",
            "result": {"type": "pong", "sender_id": "qx" + "00" * 20,
                       "sender_host": "127.0.0.1", "sender_port": 30303, "payload": {}},
            "id": 1,
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = pong

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp

        discovery._client = mock_client

        msg = DHTMessage(
            type=DHTMessageType.PING,
            sender_id=discovery._local.node_id_hex,
            sender_host='127.0.0.1',
            sender_port=30303,
        )
        result = await discovery._send_rpc('127.0.0.1', 30303, msg)
        assert result is not None
        assert result.type == DHTMessageType.PONG

        # Verify it posted to /rpc with JSON-RPC envelope
        call_args = mock_client.post.call_args
        assert '/rpc' in call_args[0][0] or '/rpc' in str(call_args)
        posted_json = call_args[1]['json']
        assert posted_json['jsonrpc'] == '2.0'
        assert posted_json['method'] == 'dht_message'


# ============================================================================
# TEST: _init_dht wires DHTModule
# ============================================================================

class TestInitDHT:
    """Verify _init_dht() creates all DHT components and wires the RPC module."""

    @pytest.mark.asyncio
    async def test_init_dht_creates_discovery(self, pq_keypair, tmp_path):
        """_init_dht should create dht_discovery and wire it into DHTModule."""
        import qrdx.node.main as main_mod

        orig_disc = main_mod.dht_discovery
        orig_dns = main_mod.dht_dns_seeds
        orig_config = main_mod.dht_config
        orig_client = main_mod.http_client
        orig_dht_mod = main_mod.dht_rpc_module

        try:
            import httpx
            main_mod.http_client = httpx.AsyncClient(timeout=5.0)
            main_mod.dht_discovery = None
            main_mod.dht_dns_seeds = None

            from qrdx.p2p.config import DiscoveryConfig
            main_mod.dht_config = DiscoveryConfig(
                routing_table_path=str(tmp_path),
                dns_enabled=True,
                dns_require_signatures=False,
            )

            _, pk = pq_keypair

            # Replace the module-level dht_rpc_module with a fresh one
            from qrdx.rpc.modules.dht import DHTModule
            mock_dht_mod = DHTModule()
            main_mod.dht_rpc_module = mock_dht_mod

            with patch('qrdx.node.main.get_public_key_bytes', return_value=pk), \
                 patch('qrdx.node.main.DENARO_NODE_HOST', '127.0.0.1'), \
                 patch('qrdx.node.main.DENARO_NODE_PORT', '30303'), \
                 patch('qrdx.node.main.BOOTSTRAP_NODES', []):
                await main_mod._init_dht()

            # Verify subsystems were created
            assert main_mod.dht_discovery is not None
            assert isinstance(main_mod.dht_discovery, main_mod.KademliaDiscovery)
            assert main_mod.dht_discovery._running is True

            # Verify the module-level dht_rpc_module was wired
            assert mock_dht_mod._discovery is main_mod.dht_discovery

            # Clean up
            main_mod.dht_discovery.stop()
            await main_mod.http_client.aclose()

        finally:
            main_mod.dht_discovery = orig_disc
            main_mod.dht_dns_seeds = orig_dns
            main_mod.dht_config = orig_config
            main_mod.http_client = orig_client
            main_mod.dht_rpc_module = orig_dht_mod

    @pytest.mark.asyncio
    async def test_init_dht_non_fatal_on_error(self, tmp_path):
        """If _init_dht fails, dht_discovery should be None (non-fatal)."""
        import qrdx.node.main as main_mod

        orig_disc = main_mod.dht_discovery
        orig_dns = main_mod.dht_dns_seeds
        orig_config = main_mod.dht_config

        try:
            main_mod.dht_discovery = None

            from qrdx.p2p.config import DiscoveryConfig
            main_mod.dht_config = DiscoveryConfig(routing_table_path=str(tmp_path))

            with patch('qrdx.node.main.get_public_key_bytes', side_effect=RuntimeError("test error")):
                await main_mod._init_dht()

            assert main_mod.dht_discovery is None

        finally:
            main_mod.dht_discovery = orig_disc
            main_mod.dht_dns_seeds = orig_dns
            main_mod.dht_config = orig_config


# ============================================================================
# TEST: Shutdown stops DHT
# ============================================================================

class TestDHTShutdown:
    """Verify DHT is stopped during node shutdown."""

    def test_dht_stop_persists_routing_table(self, discovery, tmp_path):
        """stop() should persist the routing table to disk."""
        discovery._rt._persist_path = str(tmp_path)
        discovery.start()
        assert discovery._running is True

        discovery.stop()
        assert discovery._running is False
        assert os.path.exists(os.path.join(str(tmp_path), 'routing_table.json'))

    def test_dht_stop_cancels_refresh_task(self, discovery):
        """stop() should cancel the periodic refresh task."""
        discovery.start()
        assert discovery._refresh_task is not None

        discovery.stop()
        assert discovery._refresh_task is None

    def test_shutdown_includes_dht_stop(self):
        """The shutdown handler must call dht_discovery.stop()."""
        import inspect
        from qrdx.node.main import shutdown
        source = inspect.getsource(shutdown)
        assert 'dht_discovery' in source
        assert '.stop()' in source


# ============================================================================
# TEST: DHT ↔ NodesManager bridge
# ============================================================================

class TestDHTBridge:
    """Verify bidirectional peer synchronization."""

    @pytest.mark.asyncio
    async def test_bridge_sync_pushes_peers_to_dht(self, discovery):
        """Peers in NodesManager should be pushed into the DHT routing table."""
        import qrdx.node.main as main_mod

        orig_disc = main_mod.dht_discovery
        orig_self_id = main_mod.self_node_id
        main_mod.dht_discovery = discovery
        main_mod.self_node_id = discovery._local.node_id_hex

        try:
            test_nid = 'qx' + 'ab' * 20
            with patch.object(main_mod.NodesManager, 'peers', {
                test_nid: {'url': 'http://10.1.0.1:30303', 'pubkey': ''}
            }):
                await main_mod._dht_bridge_sync()

            total = discovery.routing_table.total_nodes
            assert total >= 1

        finally:
            main_mod.dht_discovery = orig_disc
            main_mod.self_node_id = orig_self_id

    @pytest.mark.asyncio
    async def test_bridge_sync_noop_when_dht_not_initialized(self):
        """_dht_bridge_sync should be a no-op when dht_discovery is None."""
        import qrdx.node.main as main_mod
        orig = main_mod.dht_discovery
        main_mod.dht_discovery = None
        try:
            await main_mod._dht_bridge_sync()
        finally:
            main_mod.dht_discovery = orig


# ============================================================================
# TEST: P2P imports & globals
# ============================================================================

class TestDHTGlobals:
    """Verify all DHT global variables and functions are importable from main."""

    def test_dht_discovery_importable(self):
        from qrdx.node.main import dht_discovery

    def test_dht_dns_seeds_importable(self):
        from qrdx.node.main import dht_dns_seeds

    def test_dht_config_importable(self):
        from qrdx.node.main import dht_config
        from qrdx.p2p.config import DiscoveryConfig
        assert isinstance(dht_config, DiscoveryConfig)

    def test_init_dht_importable(self):
        from qrdx.node.main import _init_dht
        assert asyncio.iscoroutinefunction(_init_dht)

    def test_dht_bridge_sync_importable(self):
        from qrdx.node.main import _dht_bridge_sync
        assert asyncio.iscoroutinefunction(_dht_bridge_sync)


class TestP2PImports:
    """Verify that main.py imports all required P2P modules."""

    def test_imports_p2p_node(self):
        from qrdx.node.main import P2PNode, P2PAddress, p2p_hex_to_node_id

    def test_imports_routing_table(self):
        from qrdx.node.main import RoutingTable, KBucketEntry

    def test_imports_kademlia_discovery(self):
        from qrdx.node.main import KademliaDiscovery

    def test_imports_dns_seed_discovery(self):
        from qrdx.node.main import DNSSeedDiscovery

    def test_imports_discovery_config(self):
        from qrdx.node.main import DiscoveryConfig

    def test_imports_get_public_key_bytes(self):
        from qrdx.node.main import get_public_key_bytes
        assert callable(get_public_key_bytes)


# ============================================================================
# TEST: Integration completeness (no stubs)
# ============================================================================

class TestDHTIntegrationComplete:
    """Verify the DHT integration is complete with no stubs."""

    def test_dht_module_not_stub(self):
        """DHTModule.message must not be a stub."""
        import inspect
        from qrdx.rpc.modules.dht import DHTModule
        source = inspect.getsource(DHTModule.message)
        assert 'NotImplementedError' not in source
        assert 'handle_incoming' in source

    def test_init_dht_not_stub(self):
        """_init_dht must create real objects, not stubs."""
        import inspect
        from qrdx.node.main import _init_dht
        source = inspect.getsource(_init_dht)
        assert 'KademliaDiscovery' in source
        assert 'RoutingTable' in source
        assert 'dht_rpc_module' in source
        assert 'set_discovery' in source

    def test_bridge_sync_not_stub(self):
        """_dht_bridge_sync must have real logic."""
        import inspect
        from qrdx.node.main import _dht_bridge_sync
        source = inspect.getsource(_dht_bridge_sync)
        assert 'NodesManager' in source
        assert 'routing_table' in source

    def test_send_rpc_uses_jsonrpc(self):
        """discovery.py _send_rpc must use JSON-RPC 2.0, not legacy /dht/message."""
        import inspect
        from qrdx.p2p.discovery import KademliaDiscovery
        source = inspect.getsource(KademliaDiscovery._send_rpc)
        assert '/dht/message' not in source
        assert '/rpc' in source
        assert 'dht_message' in source
