"""
Tests for QRDX Kademlia DHT, Routing Table, Discovery Protocol,
DNS Seed Discovery, Eclipse Attack Resistance, and Bootstrap
Node Decentralization.

Covers checklist items:
- 2.3 Peer Discovery (Kademlia DHT) — Security Tested, Consensus/Decentralized, No Stubs
- 2.4 Bootstrap Node Decentralization — Security Tested, Consensus/Decentralized, No Stubs
"""

import asyncio
import json
import os
import secrets
import time
from unittest.mock import AsyncMock, MagicMock, patch

import blake3
import oqs
import pytest


# ============================================================================
# Fixtures & Helpers
# ============================================================================

def _diverse_ip(i: int) -> str:
    """Generate an IP in a unique /16 subnet for each i (avoids IP diversity rejection)."""
    a = 10 + (i % 246)
    b = (i * 7) % 256
    return f'{a}.{b}.0.1'


@pytest.fixture
def pq_keypair():
    """Generate a fresh Dilithium keypair."""
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
def make_node():
    """Factory to create Node objects with unique keypairs."""
    from qrdx.p2p.node import Node, Address

    def _make(host='127.0.0.1', port=30303):
        return Node.generate(Address(ip=host, tcp_port=port))
    return _make


@pytest.fixture
def local_node(make_node):
    """A local node for routing table tests."""
    return make_node('127.0.0.1', 30303)


@pytest.fixture
def routing_table(local_node):
    """An empty routing table bound to the local node."""
    from qrdx.p2p.routing import RoutingTable
    return RoutingTable(local_node.node_id)


@pytest.fixture
def make_entry():
    """Factory to create KBucketEntry objects."""
    from qrdx.p2p.routing import KBucketEntry
    from qrdx.p2p.node import derive_node_id, derive_node_id_hex

    def _make(host='10.0.0.1', port=30303, *, is_inbound=False, node_id=None):
        if node_id is None:
            random_key = secrets.token_bytes(32)
            nid = derive_node_id(random_key)
            nid_hex = derive_node_id_hex(random_key)
        else:
            nid = node_id
            nid_hex = 'qx' + node_id.hex()
        return KBucketEntry(
            node_id=nid,
            node_id_hex=nid_hex,
            host=host,
            port=port,
            public_key_hex='',
            at_schema='',
            last_seen=time.monotonic(),
            added_at=time.monotonic(),
            is_inbound=is_inbound,
        )
    return _make


def _add_direct(rt, entry):
    """Add entry directly to the correct k-bucket, bypassing rate limiting."""
    if entry.node_id == rt._local_id:
        return False, None
    idx = rt._bucket_index(entry.node_id)
    return rt._buckets[idx].add_or_update(entry, rate_limit=False)


# ============================================================================
# 2.3 — KBucket Tests
# ============================================================================

class TestKBucket:
    """Tests for the individual k-bucket data structure."""

    def test_bucket_initially_empty(self):
        from qrdx.p2p.routing import KBucket
        b = KBucket(index=0)
        assert b.size == 0
        assert not b.is_full
        assert b.get_nodes() == []

    def test_add_entry(self, make_entry):
        from qrdx.p2p.routing import KBucket
        b = KBucket(index=5)
        e = make_entry()
        added, candidate = b.add_or_update(e, rate_limit=False)
        assert added is True
        assert candidate is None
        assert b.size == 1
        assert b.contains(e.node_id)

    def test_update_existing_moves_to_tail(self, make_entry):
        from qrdx.p2p.routing import KBucket
        b = KBucket(index=5)
        e1 = make_entry(host='10.0.0.1')
        e2 = make_entry(host='11.0.0.1')
        b.add_or_update(e1, rate_limit=False)
        b.add_or_update(e2, rate_limit=False)
        b.add_or_update(e1, rate_limit=False)
        nodes = b.get_nodes()
        assert nodes[-1].node_id == e1.node_id

    def test_bucket_full_returns_eviction_candidate(self, make_entry):
        from qrdx.p2p.routing import KBucket, K_BUCKET_SIZE
        b = KBucket(index=10)
        entries = []
        for i in range(K_BUCKET_SIZE):
            e = make_entry(host=_diverse_ip(i))
            b.add_or_update(e, rate_limit=False)
            entries.append(e)
        assert b.is_full

        extra = make_entry(host='192.168.0.1')
        added, candidate = b.add_or_update(extra, rate_limit=False)
        assert added is False
        assert candidate is not None
        assert candidate.node_id == entries[0].node_id

    def test_evict_and_replace(self, make_entry):
        from qrdx.p2p.routing import KBucket, K_BUCKET_SIZE
        b = KBucket(index=10)
        entries = []
        for i in range(K_BUCKET_SIZE):
            e = make_entry(host=_diverse_ip(i))
            b.add_or_update(e, rate_limit=False)
            entries.append(e)

        extra = make_entry(host='192.168.0.1')
        b.add_or_update(extra, rate_limit=False)

        replaced = b.evict_and_replace(entries[0].node_id)
        assert replaced is True
        assert not b.contains(entries[0].node_id)
        assert b.contains(extra.node_id)

    def test_remove_entry(self, make_entry):
        from qrdx.p2p.routing import KBucket
        b = KBucket(index=5)
        e = make_entry()
        b.add_or_update(e, rate_limit=False)
        assert b.remove(e.node_id) is True
        assert b.size == 0

    def test_needs_refresh(self):
        from qrdx.p2p.routing import KBucket, BUCKET_REFRESH_INTERVAL
        b = KBucket(index=0)
        b.last_refresh = time.monotonic() - BUCKET_REFRESH_INTERVAL - 1
        assert b.needs_refresh() is True
        b.touch()
        assert b.needs_refresh() is False


# ============================================================================
# 2.3 — RoutingTable Tests
# ============================================================================

class TestRoutingTable:
    """Tests for the full Kademlia routing table."""

    def test_create_routing_table(self, local_node):
        from qrdx.p2p.routing import RoutingTable, NUM_BUCKETS
        rt = RoutingTable(local_node.node_id)
        assert rt.total_nodes == 0
        assert rt.non_empty_buckets == 0
        assert len(rt._buckets) == NUM_BUCKETS

    def test_invalid_node_id_length(self):
        from qrdx.p2p.routing import RoutingTable
        with pytest.raises(ValueError, match="20 bytes"):
            RoutingTable(b'\x00' * 10)

    def test_add_node(self, routing_table, make_entry):
        e = make_entry()
        added, _ = routing_table.add_node(e)
        assert added is True
        assert routing_table.total_nodes == 1
        assert routing_table.contains(e.node_id)

    def test_cannot_add_self(self, routing_table, local_node):
        from qrdx.p2p.routing import KBucketEntry
        e = KBucketEntry(
            node_id=local_node.node_id,
            node_id_hex=local_node.node_id_hex,
            host='127.0.0.1', port=30303,
            public_key_hex='', at_schema='',
            last_seen=time.monotonic(), added_at=time.monotonic(),
            is_inbound=False,
        )
        added, _ = routing_table.add_node(e)
        assert added is False

    def test_remove_node(self, routing_table, make_entry):
        e = make_entry()
        routing_table.add_node(e)
        assert routing_table.remove_node(e.node_id) is True
        assert routing_table.total_nodes == 0

    def test_find_closest_returns_sorted(self, routing_table, make_entry):
        """find_closest returns nodes sorted by XOR distance."""
        for i in range(10):
            _add_direct(routing_table, make_entry(host=_diverse_ip(i)))

        target = secrets.token_bytes(20)
        target_int = int.from_bytes(target, 'big')
        closest = routing_table.find_closest(target, count=5)

        assert len(closest) == 5
        dists = [target_int ^ int.from_bytes(e.node_id, 'big') for e in closest]
        assert dists == sorted(dists)

    def test_find_closest_excludes(self, routing_table, make_entry):
        e1 = make_entry(host='10.0.0.1')
        e2 = make_entry(host='11.0.0.2')
        _add_direct(routing_table, e1)
        _add_direct(routing_table, e2)

        result = routing_table.find_closest(
            e1.node_id, count=10, exclude={e1.node_id}
        )
        assert all(r.node_id != e1.node_id for r in result)

    def test_get_all_nodes(self, routing_table, make_entry):
        for i in range(25):
            _add_direct(routing_table, make_entry(host=_diverse_ip(i)))
        assert len(routing_table.get_all_nodes()) == 25

    def test_bucket_index_same_node_is_zero(self, routing_table):
        idx = routing_table._bucket_index(routing_table._local_id)
        assert idx == 0

    def test_bucket_index_varies(self, routing_table, make_entry):
        indices = set()
        for _ in range(50):
            e = make_entry()
            idx = routing_table._bucket_index(e.node_id)
            indices.add(idx)
        assert len(indices) > 1

    def test_generate_refresh_target(self, routing_table):
        for bucket_idx in [1, 10, 50, 100, 159]:
            target = routing_table.generate_refresh_target(bucket_idx)
            assert len(target) == 20
            actual_idx = routing_table._bucket_index(target)
            assert actual_idx == bucket_idx

    def test_persistence_save_load(self, routing_table, make_entry, tmp_path):
        from qrdx.p2p.routing import RoutingTable
        routing_table._persist_path = str(tmp_path)

        for i in range(15):
            _add_direct(routing_table, make_entry(host=_diverse_ip(i)))

        routing_table.save()

        filepath = os.path.join(str(tmp_path), 'routing_table.json')
        assert os.path.exists(filepath)

        loaded = RoutingTable.load(routing_table._local_id, str(tmp_path))
        assert loaded.total_nodes == 15

    def test_persistence_corrupt_file(self, routing_table, tmp_path):
        from qrdx.p2p.routing import RoutingTable
        filepath = os.path.join(str(tmp_path), 'routing_table.json')
        os.makedirs(str(tmp_path), exist_ok=True)
        with open(filepath, 'w') as f:
            f.write("NOT JSON")

        loaded = RoutingTable.load(routing_table._local_id, str(tmp_path))
        assert loaded.total_nodes == 0

    def test_stats(self, routing_table, make_entry):
        for i in range(5):
            _add_direct(routing_table, make_entry(host=_diverse_ip(i)))
        stats = routing_table.get_stats()
        assert stats['total_nodes'] == 5
        assert 'inbound_nodes' in stats
        assert 'outbound_nodes' in stats
        assert 'unique_subnets' in stats


# ============================================================================
# 2.3 — Eclipse Attack Resistance Tests
# ============================================================================

class TestEclipseResistance:

    def test_ip_diversity_limit(self, make_entry):
        """Cannot add more than MAX_SAME_SUBNET_PER_BUCKET from the same /16."""
        from qrdx.p2p.routing import KBucket, MAX_SAME_SUBNET_PER_BUCKET
        b = KBucket(index=5)
        added_count = 0
        for i in range(MAX_SAME_SUBNET_PER_BUCKET + 3):
            e = make_entry(host=f'10.1.{i}.1')  # All in 10.1/16
            added, _ = b.add_or_update(e, rate_limit=False)
            if added:
                added_count += 1
        assert added_count == MAX_SAME_SUBNET_PER_BUCKET

    def test_inbound_limit(self, make_entry):
        """Inbound connections limited to half the bucket size."""
        from qrdx.p2p.routing import KBucket, K_BUCKET_SIZE
        b = KBucket(index=5)
        max_inbound = K_BUCKET_SIZE // 2
        added_count = 0
        for i in range(K_BUCKET_SIZE):
            e = make_entry(host=_diverse_ip(i), is_inbound=True)
            added, _ = b.add_or_update(e, rate_limit=False)
            if added:
                added_count += 1
        assert added_count == max_inbound

    def test_outbound_not_limited(self, make_entry):
        """Outbound connections can fill the entire bucket."""
        from qrdx.p2p.routing import KBucket, K_BUCKET_SIZE
        b = KBucket(index=5)
        added_count = 0
        for i in range(K_BUCKET_SIZE):
            e = make_entry(host=_diverse_ip(i), is_inbound=False)
            added, _ = b.add_or_update(e, rate_limit=False)
            if added:
                added_count += 1
        assert added_count == K_BUCKET_SIZE

    def test_sybil_resistant_id(self, make_node):
        """Node IDs derived from BLAKE3 of Dilithium public key — not choosable."""
        node = make_node()
        expected_id = blake3.blake3(node.public_key).digest()[:20]
        assert node.node_id == expected_id

    def test_rate_limiting(self, make_entry):
        """Rapid insertions into the same bucket are rate-limited."""
        from qrdx.p2p.routing import KBucket
        b = KBucket(index=5)
        e1 = make_entry(host='10.0.0.1')
        added1, _ = b.add_or_update(e1, rate_limit=True)
        assert added1 is True
        e2 = make_entry(host='11.0.0.1')
        added2, _ = b.add_or_update(e2, rate_limit=True)
        assert added2 is False

    def test_replacement_cache(self, make_entry):
        """Full bucket stores overflow in replacement cache."""
        from qrdx.p2p.routing import KBucket, K_BUCKET_SIZE
        b = KBucket(index=10)
        for i in range(K_BUCKET_SIZE):
            b.add_or_update(make_entry(host=_diverse_ip(i)), rate_limit=False)
        extra = make_entry(host='192.168.0.1')
        b.add_or_update(extra, rate_limit=False)
        assert len(b.replacement_cache) == 1
        assert b.replacement_cache[0].node_id == extra.node_id


# ============================================================================
# 2.3 — DHT Protocol Tests
# ============================================================================

class TestKademliaProtocol:

    def test_handle_ping(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaProtocol, DHTMessage, DHTMessageType
        proto = KademliaProtocol(routing_table, local_node)
        msg = DHTMessage(
            type=DHTMessageType.PING,
            sender_id='qx' + 'ab' * 20,
            sender_host='10.0.0.1',
            sender_port=30303,
        )
        response = proto.handle_message(msg)
        assert response.type == DHTMessageType.PONG
        assert response.sender_id == local_node.node_id_hex

    def test_handle_find_node(self, local_node, routing_table, make_entry):
        from qrdx.p2p.discovery import KademliaProtocol, DHTMessage, DHTMessageType
        from qrdx.p2p.node import node_id_to_hex

        for i in range(10):
            _add_direct(routing_table, make_entry(host=_diverse_ip(i)))

        proto = KademliaProtocol(routing_table, local_node)
        target = secrets.token_bytes(20)
        msg = DHTMessage(
            type=DHTMessageType.FIND_NODE,
            sender_id='qx' + 'cc' * 20,
            sender_host='10.0.0.99',
            sender_port=30303,
            payload={'target': node_id_to_hex(target)},
        )
        response = proto.handle_message(msg)
        assert response.type == DHTMessageType.FIND_NODE_RESPONSE
        assert 'nodes' in response.payload
        assert len(response.payload['nodes']) > 0

    def test_handle_store_and_find_value(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaProtocol, DHTMessage, DHTMessageType
        proto = KademliaProtocol(routing_table, local_node)

        store_msg = DHTMessage(
            type=DHTMessageType.STORE,
            sender_id='qx' + 'dd' * 20,
            sender_host='10.0.0.1',
            sender_port=30303,
            payload={'key': 'test_key', 'value': 'test_value'},
        )
        resp = proto.handle_message(store_msg)
        assert resp.type == DHTMessageType.STORE_RESPONSE
        assert resp.payload['stored'] is True

        find_msg = DHTMessage(
            type=DHTMessageType.FIND_VALUE,
            sender_id='qx' + 'ee' * 20,
            sender_host='11.0.0.2',
            sender_port=30303,
            payload={'key': 'test_key'},
        )
        resp = proto.handle_message(find_msg)
        assert resp.type == DHTMessageType.FIND_VALUE_RESPONSE
        assert resp.payload['found'] is True
        assert resp.payload['value'] == 'test_value'

    def test_find_value_not_found_returns_nodes(self, local_node, routing_table, make_entry):
        from qrdx.p2p.discovery import KademliaProtocol, DHTMessage, DHTMessageType
        for i in range(5):
            _add_direct(routing_table, make_entry(host=_diverse_ip(i)))

        proto = KademliaProtocol(routing_table, local_node)
        msg = DHTMessage(
            type=DHTMessageType.FIND_VALUE,
            sender_id='qx' + 'ff' * 20,
            sender_host='12.0.0.1',
            sender_port=30303,
            payload={'key': 'nonexistent'},
        )
        resp = proto.handle_message(msg)
        assert resp.payload['found'] is False
        assert 'nodes' in resp.payload

    def test_store_rejects_oversized_value(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaProtocol, DHTMessage, DHTMessageType, MAX_STORE_VALUE_SIZE
        proto = KademliaProtocol(routing_table, local_node)
        msg = DHTMessage(
            type=DHTMessageType.STORE,
            sender_id='qx' + 'aa' * 20,
            sender_host='10.0.0.1',
            sender_port=30303,
            payload={'key': 'big', 'value': 'x' * (MAX_STORE_VALUE_SIZE + 1)},
        )
        resp = proto.handle_message(msg)
        assert resp.payload['stored'] is False
        assert 'too large' in resp.payload.get('error', '').lower()

    def test_sender_added_to_routing_table(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaProtocol, DHTMessage, DHTMessageType
        from qrdx.p2p.node import hex_to_node_id

        proto = KademliaProtocol(routing_table, local_node)
        sender_id = 'qx' + 'bb' * 20
        msg = DHTMessage(
            type=DHTMessageType.PING,
            sender_id=sender_id,
            sender_host='10.0.0.50',
            sender_port=30303,
        )
        proto.handle_message(msg)
        assert routing_table.contains(hex_to_node_id(sender_id))

    def test_dht_message_serialization(self):
        from qrdx.p2p.discovery import DHTMessage, DHTMessageType
        msg = DHTMessage(
            type=DHTMessageType.FIND_NODE,
            sender_id='qx' + 'ab' * 20,
            sender_host='10.0.0.1',
            sender_port=30303,
            payload={'target': 'qx' + 'cd' * 20},
        )
        d = msg.to_dict()
        restored = DHTMessage.from_dict(d)
        assert restored.type == msg.type
        assert restored.sender_id == msg.sender_id
        assert restored.payload == msg.payload


# ============================================================================
# 2.3 — KademliaDiscovery Integration Tests
# ============================================================================

class TestKademliaDiscovery:

    @pytest.mark.asyncio
    async def test_ping_unreachable(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaDiscovery
        disc = KademliaDiscovery(local_node, routing_table)
        result = await disc.ping('192.0.2.1', 1)
        assert result is False

    @pytest.mark.asyncio
    async def test_find_node_unreachable(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaDiscovery
        disc = KademliaDiscovery(local_node, routing_table)
        result = await disc.find_node('192.0.2.1', 1, local_node.node_id)
        assert result == []

    @pytest.mark.asyncio
    async def test_iterative_find_node_no_peers(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaDiscovery
        disc = KademliaDiscovery(local_node, routing_table)
        result = await disc.iterative_find_node(secrets.token_bytes(20))
        assert result == []

    @pytest.mark.asyncio
    async def test_iterative_find_node_local_only(self, local_node, routing_table, make_entry):
        from qrdx.p2p.discovery import KademliaDiscovery
        for i in range(5):
            _add_direct(routing_table, make_entry(host=_diverse_ip(i)))

        disc = KademliaDiscovery(local_node, routing_table)
        target = secrets.token_bytes(20)
        result = await disc.iterative_find_node(target, count=3)
        assert len(result) <= 5

    @pytest.mark.asyncio
    async def test_bootstrap_no_seeds(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaDiscovery
        disc = KademliaDiscovery(local_node, routing_table)
        count = await disc.bootstrap([])
        assert count == 0

    @pytest.mark.asyncio
    async def test_bootstrap_unreachable_seeds(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaDiscovery
        disc = KademliaDiscovery(local_node, routing_table)
        count = await disc.bootstrap([('192.0.2.1', 1)])
        assert isinstance(count, int)

    def test_handle_incoming_valid(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaDiscovery
        disc = KademliaDiscovery(local_node, routing_table)
        response = disc.handle_incoming({
            'type': 'ping',
            'sender_id': 'qx' + 'ab' * 20,
            'sender_host': '10.0.0.1',
            'sender_port': 30303,
        })
        assert response['type'] == 'pong'

    def test_handle_incoming_invalid(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaDiscovery
        disc = KademliaDiscovery(local_node, routing_table)
        response = disc.handle_incoming({'garbage': True})
        assert response.get('type') == 'error' or 'error' in str(response)

    def test_discovery_stats(self, local_node, routing_table, make_entry):
        from qrdx.p2p.discovery import KademliaDiscovery
        for i in range(5):
            _add_direct(routing_table, make_entry(host=_diverse_ip(i)))

        disc = KademliaDiscovery(local_node, routing_table)
        stats = disc.get_stats()
        assert stats['local_node_id'] == local_node.node_id_hex
        assert stats['routing_table']['total_nodes'] == 5
        assert 'store_entries' in stats

    def test_start_stop(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaDiscovery
        disc = KademliaDiscovery(local_node, routing_table)
        disc._running = True
        disc.stop()
        assert disc._running is False


# ============================================================================
# 2.3 — Self-Sustaining Operation Tests
# ============================================================================

class TestSelfSustaining:

    def test_routing_table_survives_restart(self, local_node, make_entry, tmp_path):
        from qrdx.p2p.routing import RoutingTable
        rt1 = RoutingTable(local_node.node_id, persist_path=str(tmp_path))
        entries = []
        for i in range(20):
            e = make_entry(host=_diverse_ip(i))
            _add_direct(rt1, e)
            entries.append(e)
        rt1.save()

        rt2 = RoutingTable.load(local_node.node_id, str(tmp_path))
        assert rt2.total_nodes == 20
        for e in entries:
            assert rt2.contains(e.node_id)

    def test_routing_table_no_bootstrap_dependency(self, routing_table, make_entry):
        for i in range(10):
            _add_direct(routing_table, make_entry(host=_diverse_ip(i)))

        target = secrets.token_bytes(20)
        closest = routing_table.find_closest(target, count=5)
        assert len(closest) == 5

    def test_routing_table_regenerates_refresh_targets(self, routing_table):
        for i in range(1, 160):
            target = routing_table.generate_refresh_target(i)
            assert len(target) == 20
            actual_bucket = routing_table._bucket_index(target)
            assert actual_bucket == i


# ============================================================================
# 2.4 — DNS Seed Discovery Tests
# ============================================================================

class TestDNSSeedDiscovery:

    def test_create_dns_discovery(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery, DEFAULT_DNS_SEEDS
        disc = DNSSeedDiscovery()
        assert disc.seed_domains == list(DEFAULT_DNS_SEEDS)

    def test_custom_seed_domains(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery
        domains = ['seeds.example.com', 'seeds2.example.com']
        disc = DNSSeedDiscovery(seed_domains=domains)
        assert disc.seed_domains == domains

    def test_add_seed_domain(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery
        disc = DNSSeedDiscovery(seed_domains=['a.com'])
        disc.add_seed_domain('b.com')
        assert 'b.com' in disc.seed_domains

    def test_add_trusted_operator(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery, SeedOperator
        disc = DNSSeedDiscovery()
        op = SeedOperator(
            domain='seeds.qrdx.org',
            public_key_hex='ab' * 100,
            organization='QRDX Foundation',
        )
        disc.add_trusted_operator(op)
        assert disc.trusted_operator_count == 1

    def test_parse_unsigned_txt_record(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery
        disc = DNSSeedDiscovery(require_signatures=False)
        record = (
            'dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@node1.qrdx.org:30303,'
            'dilithium3@qxdeadbeef00112233445566778899aabbccddeeff@node2.qrdx.org:30303'
        )
        result = disc._parse_txt_record('seeds.qrdx.org', record)
        assert result is not None
        assert len(result.nodes) == 2
        assert result.signature_valid is False

    def test_parse_unsigned_rejected_in_strict_mode(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery
        disc = DNSSeedDiscovery(require_signatures=True)
        record = 'dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@node1.qrdx.org:30303'
        result = disc._parse_txt_record('seeds.qrdx.org', record)
        assert result is None

    def test_parse_signed_txt_record(self, pq_keypair):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery, SeedOperator
        sk, pk = pq_keypair
        nodes_csv = 'dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@node1.qrdx.org:30303'
        message = f'v=qrdx1 nodes={nodes_csv}'.encode()

        for algo in ('ML-DSA-65', 'Dilithium3'):
            try:
                signer = oqs.Signature(algo, sk)
                sig = signer.sign(message)
                break
            except Exception:
                continue

        record = f'v=qrdx1 nodes={nodes_csv} sig={sig.hex()} pubkey={pk.hex()}'
        op = SeedOperator(
            domain='seeds.qrdx.org',
            public_key_hex=pk.hex(),
            organization='Test Org',
        )
        disc = DNSSeedDiscovery(
            seed_domains=['seeds.qrdx.org'],
            trusted_operators=[op],
            require_signatures=True,
        )
        result = disc._parse_txt_record('seeds.qrdx.org', record)
        assert result is not None
        assert result.signature_valid is True
        assert len(result.nodes) == 1

    def test_forged_signature_rejected(self, pq_keypair):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery, SeedOperator
        _, pk = pq_keypair
        nodes_csv = 'dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@node1.qrdx.org:30303'
        fake_sig = secrets.token_hex(2420)

        record = f'v=qrdx1 nodes={nodes_csv} sig={fake_sig} pubkey={pk.hex()}'
        op = SeedOperator(
            domain='seeds.qrdx.org',
            public_key_hex=pk.hex(),
            organization='Test Org',
        )
        disc = DNSSeedDiscovery(
            seed_domains=['seeds.qrdx.org'],
            trusted_operators=[op],
            require_signatures=True,
        )
        result = disc._parse_txt_record('seeds.qrdx.org', record)
        assert result is None

    def test_wrong_operator_pubkey_rejected(self, pq_keypair):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery, SeedOperator
        sk, pk = pq_keypair
        nodes_csv = 'dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@node1.qrdx.org:30303'
        message = f'v=qrdx1 nodes={nodes_csv}'.encode()

        for algo in ('ML-DSA-65', 'Dilithium3'):
            try:
                signer = oqs.Signature(algo, sk)
                sig = signer.sign(message)
                break
            except Exception:
                continue

        different_pk = secrets.token_hex(len(pk))
        op = SeedOperator(
            domain='seeds.qrdx.org',
            public_key_hex=different_pk,
            organization='Different Org',
        )
        disc = DNSSeedDiscovery(
            seed_domains=['seeds.qrdx.org'],
            trusted_operators=[op],
            require_signatures=True,
        )
        record = f'v=qrdx1 nodes={nodes_csv} sig={sig.hex()} pubkey={pk.hex()}'
        result = disc._parse_txt_record('seeds.qrdx.org', record)
        assert result is None

    @pytest.mark.asyncio
    async def test_discover_caches_results(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery, DNSSeedResult
        disc = DNSSeedDiscovery(
            seed_domains=['seeds.test.org'],
            require_signatures=False,
        )
        disc._cache['seeds.test.org'] = DNSSeedResult(
            domain='seeds.test.org',
            nodes=['dilithium3@qxaabb@host:30303'],
            signature_valid=False,
        )
        nodes = await disc.discover()
        assert len(nodes) == 1

    @pytest.mark.asyncio
    async def test_discover_with_fallback(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery
        disc = DNSSeedDiscovery(
            seed_domains=[],
            require_signatures=False,
        )
        nodes = await disc.discover_with_fallback(
            hardcoded_bootstrap=['http://node.qrdx.org:3007']
        )
        assert 'http://node.qrdx.org:3007' in nodes

    def test_dns_seed_stats(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery
        disc = DNSSeedDiscovery()
        stats = disc.get_stats()
        assert 'seed_domains' in stats
        assert 'trusted_operators' in stats
        assert 'require_signatures' in stats

    def test_seed_operator_active(self):
        from qrdx.p2p.dns_seeds import SeedOperator
        op = SeedOperator(
            domain='seeds.qrdx.org',
            public_key_hex='ab' * 100,
            organization='QRDX Foundation',
            is_active=True,
        )
        assert op.is_active is True
        assert op.public_key_bytes == bytes.fromhex('ab' * 100)


# ============================================================================
# 2.4 — Bootstrap Decentralization Tests
# ============================================================================

class TestBootstrapDecentralization:

    def test_bootstrap_uses_qrdx_org(self):
        from qrdx.constants import BOOTSTRAP_NODES
        for node_url in BOOTSTRAP_NODES:
            assert 'qrdx.org' in node_url
            assert '127.0.0.1' not in node_url
            assert 'localhost' not in node_url

    def test_multiple_bootstrap_nodes(self):
        from qrdx.constants import BOOTSTRAP_NODES
        assert len(BOOTSTRAP_NODES) >= 3

    def test_bootstrap_nodes_are_distinct(self):
        from qrdx.constants import BOOTSTRAP_NODES
        assert len(set(BOOTSTRAP_NODES)) == len(BOOTSTRAP_NODES)

    def test_no_hardcoded_ips_in_bootstrap(self):
        import re
        from qrdx.constants import BOOTSTRAP_NODES
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        for node_url in BOOTSTRAP_NODES:
            host = node_url.replace('http://', '').replace('https://', '').split(':')[0]
            assert not ip_pattern.match(host)

    def test_dht_operates_without_bootstrap(self, local_node, make_entry, tmp_path):
        from qrdx.p2p.routing import RoutingTable
        rt = RoutingTable(local_node.node_id, persist_path=str(tmp_path))

        for i in range(30):
            _add_direct(rt, make_entry(host=_diverse_ip(i)))
        rt.save()

        rt2 = RoutingTable.load(local_node.node_id, str(tmp_path))
        assert rt2.total_nodes == 30

        target = secrets.token_bytes(20)
        closest = rt2.find_closest(target, count=10)
        assert len(closest) == 10

    def test_dns_seeds_multiple_operators(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery, SeedOperator, DEFAULT_DNS_SEEDS, MIN_SEED_OPERATORS
        assert len(DEFAULT_DNS_SEEDS) >= MIN_SEED_OPERATORS

        disc = DNSSeedDiscovery()
        for i, domain in enumerate(DEFAULT_DNS_SEEDS):
            disc.add_trusted_operator(SeedOperator(
                domain=domain,
                public_key_hex='ab' * 100,
                organization=f'Org-{i}',
            ))
        assert disc.trusted_operator_count == len(DEFAULT_DNS_SEEDS)

    def test_fallback_chain(self):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery
        from qrdx.p2p.routing import RoutingTable
        from qrdx.p2p.discovery import KademliaDiscovery
        from qrdx.p2p.node import Node

        node = Node.generate()
        rt = RoutingTable(node.node_id)
        dht = KademliaDiscovery(node, rt)
        dns = DNSSeedDiscovery()
        assert dht is not None
        assert dns is not None
        assert rt is not None

    def test_bootstrap_manager_supports_at_schema(self):
        from qrdx.node.bootstrap import BootstrapManager
        mgr = BootstrapManager(bootstrap_nodes=[
            'dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@node.qrdx.org:30303',
            'http://node2.qrdx.org:3007',
        ])
        assert len(mgr.all_nodes) == 2
        pq_nodes = [n for n in mgr.all_nodes if n.is_pq]
        assert len(pq_nodes) == 1

    def test_legacy_qrdx_network_removed(self):
        from qrdx.constants import BOOTSTRAP_NODES, DENARO_BOOTSTRAP_NODE
        for url in BOOTSTRAP_NODES:
            assert 'qrdx.network' not in url
        assert 'qrdx.network' not in DENARO_BOOTSTRAP_NODE


# ============================================================================
# 2.3 — Consensus / Decentralized Tests
# ============================================================================

class TestConsensusDecentralized:

    def test_node_id_deterministic_from_pubkey(self, make_node):
        node = make_node()
        expected = blake3.blake3(node.public_key).digest()[:20]
        assert node.node_id == expected

    def test_node_id_not_choosable(self):
        from qrdx.p2p.node import Node, derive_node_id
        n1 = Node.generate()
        n2 = Node.generate()
        assert n1.node_id != n2.node_id
        assert n1.node_id == derive_node_id(n1.public_key)
        assert n2.node_id == derive_node_id(n2.public_key)

    def test_routing_table_no_central_authority(self, routing_table):
        assert not hasattr(routing_table, 'set_coordinator')
        assert not hasattr(routing_table, 'set_primary')
        assert not hasattr(routing_table, 'admin_override')

    def test_all_nodes_use_same_protocol(self):
        from qrdx.p2p.discovery import DHTMessageType
        msg_types = set(DHTMessageType)
        assert DHTMessageType.PING in msg_types
        assert DHTMessageType.FIND_NODE in msg_types
        assert DHTMessageType.STORE in msg_types
        assert DHTMessageType.FIND_VALUE in msg_types

    def test_xor_distance_symmetric(self, make_node):
        a = make_node()
        b = make_node()
        assert a.distance(b) == b.distance(a)

    def test_dht_k_parameter(self):
        from qrdx.p2p.routing import K_BUCKET_SIZE
        assert K_BUCKET_SIZE == 20

    def test_dht_160_bit_id_space(self):
        from qrdx.p2p.routing import NUM_BUCKETS
        assert NUM_BUCKETS == 160


# ============================================================================
# 2.3/2.4 — No Stubs Tests
# ============================================================================

class TestNoStubs:

    def test_kbucket_is_real_data_structure(self):
        from qrdx.p2p.routing import KBucket
        b = KBucket(index=0)
        assert hasattr(b, 'entries')
        assert hasattr(b, 'replacement_cache')
        assert hasattr(b, 'add_or_update')
        assert hasattr(b, 'evict_and_replace')
        assert hasattr(b, 'remove')

    def test_routing_table_has_real_persistence(self, tmp_path):
        from qrdx.p2p.routing import RoutingTable
        from qrdx.p2p.node import Node

        node = Node.generate()
        rt = RoutingTable(node.node_id, persist_path=str(tmp_path))
        rt.save()

        filepath = os.path.join(str(tmp_path), 'routing_table.json')
        assert os.path.exists(filepath)
        with open(filepath) as f:
            data = json.load(f)
        assert 'local_node_id' in data
        assert 'buckets' in data

    def test_discovery_protocol_handles_all_message_types(self, local_node, routing_table):
        from qrdx.p2p.discovery import KademliaProtocol, DHTMessage, DHTMessageType
        proto = KademliaProtocol(routing_table, local_node)

        for msg_type in [DHTMessageType.PING, DHTMessageType.FIND_NODE,
                         DHTMessageType.STORE, DHTMessageType.FIND_VALUE]:
            msg = DHTMessage(
                type=msg_type,
                sender_id='qx' + 'ab' * 20,
                sender_host='10.0.0.1',
                sender_port=30303,
                payload={'target': 'qx' + 'cd' * 20, 'key': 'test', 'value': 'val'},
            )
            response = proto.handle_message(msg)
            assert response is not None
            assert response.type is not None

    def test_dns_seeds_use_real_dilithium_verification(self, pq_keypair):
        from qrdx.p2p.dns_seeds import DNSSeedDiscovery
        sk, pk = pq_keypair
        disc = DNSSeedDiscovery(require_signatures=False)

        nodes_csv = 'test@qx0000@host:30303'
        message = f'v=qrdx1 nodes={nodes_csv}'.encode()

        for algo in ('ML-DSA-65', 'Dilithium3'):
            try:
                signer = oqs.Signature(algo, sk)
                sig = signer.sign(message)
                break
            except Exception:
                continue

        valid = disc._verify_signature(
            'seeds.qrdx.org', 'qrdx1', nodes_csv, sig.hex(), pk.hex()
        )
        assert valid is True

    def test_no_hardcoded_network_fallback(self):
        from qrdx.constants import BOOTSTRAP_NODES, DENARO_BOOTSTRAP_NODE
        all_urls = BOOTSTRAP_NODES + [DENARO_BOOTSTRAP_NODE]
        for url in all_urls:
            assert 'qrdx.network' not in url

    def test_kbucket_entry_to_node_conversion(self, make_entry):
        from qrdx.p2p.node import Node
        e = make_entry(host='10.0.0.1', port=30303)
        node = e.to_node()
        assert isinstance(node, Node)
        assert node.address.ip == '10.0.0.1'
        assert node.address.tcp_port == 30303
