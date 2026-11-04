"""
Finding peers: the Kademlia DHT, bootstrap nodes and the periodic discovery loop.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import asyncio
import hashlib
import os
import random
import time
from typing import List, Tuple
from urllib.parse import urlparse

import httpx

from qrdx.constants import (
    BOOTSTRAP_NODES,
    DENARO_DATABASE_PATH,
    DENARO_NODE_HOST,
    DENARO_NODE_PORT,
    DENARO_SELF_URL,
    MAX_PEERS,
)
from qrdx.logger import get_logger
from qrdx.node import main as _node, peers as _peers, sync as _sync
from qrdx.node.identity import get_public_key_bytes
from qrdx.node.nodes_manager import NodeInterface, NodesManager
from qrdx.p2p.discovery import KademliaDiscovery
from qrdx.p2p.dns_seeds import DNSSeedDiscovery
from qrdx.p2p.node import (
    Address as P2PAddress,
    Node as P2PNode,
    hex_to_node_id as p2p_hex_to_node_id,
)
from qrdx.p2p.routing import KBucketEntry, RoutingTable

logger = get_logger(__name__)

# ============================================================================
# KADEMLIA DHT BRIDGE
# ============================================================================


async def _dht_bridge_sync() -> None:
    """
    Bidirectional sync between Kademlia DHT routing table and NodesManager.

    - Push NodesManager peers into the DHT routing table
    - Pull DHT-discovered peers into NodesManager via handshake
    """
    if _node.dht_discovery is None:
        return

    # --- Push: NodesManager → DHT routing table ---
    pushed = 0
    for peer_id, peer_data in list(NodesManager.peers.items()):
        url = peer_data.get("url", "")
        if not url:
            continue
        try:
            parsed = urlparse(url)
            host = parsed.hostname or "localhost"
            port = parsed.port or 30303
            # Derive a node_id from the peer_id string if it looks like qx-hex
            if peer_id.startswith("qx") and len(peer_id) >= 42:
                nid = p2p_hex_to_node_id(peer_id)
            else:
                # Use a hash of the peer_id as a fallback node ID
                nid = hashlib.blake2b(peer_id.encode(), digest_size=20).digest()

            entry = KBucketEntry(
                node_id=nid,
                node_id_hex=peer_id if peer_id.startswith("qx") else "qx" + nid.hex(),
                host=host,
                port=port,
                public_key_hex=peer_data.get("pubkey", ""),
                at_schema="",
                last_seen=time.monotonic(),
                added_at=time.monotonic(),
                is_inbound=False,
            )
            added, _ = _node.dht_discovery.routing_table._buckets[
                _node.dht_discovery.routing_table._bucket_index(nid)
            ].add_or_update(entry, rate_limit=False)
            if added:
                pushed += 1
        except Exception:
            pass  # Skip malformed peers silently

    # --- Pull: DHT routing table → NodesManager ---
    pulled = 0
    for bucket in _node.dht_discovery.routing_table._buckets:
        for entry in bucket.entries:
            entry_node_id = entry.node_id_hex
            if entry_node_id not in NodesManager.peers and entry_node_id != _node.self_node_id:
                if len(NodesManager.peers) < MAX_PEERS and entry.host:
                    peer_url = f"http://{entry.host}:{entry.port}"
                    asyncio.create_task(_peers.do_handshake_with_peer(peer_url))
                    pulled += 1
                    if pulled >= 10:  # Limit handshake burst per sync cycle
                        break
        if pulled >= 10:
            break

    if pushed or pulled:
        logger.debug(
            f"DHT bridge sync: pushed {pushed} peers to DHT, pulled {pulled} for handshake"
        )


async def _periodic_dht_bridge() -> None:
    """Periodically sync DHT routing table with NodesManager."""
    await asyncio.sleep(10)  # Quick DHT start
    while True:
        try:
            await _dht_bridge_sync()
        except Exception as e:
            logger.error(f"DHT bridge sync error: {e}")
        await asyncio.sleep(30)  # DHT sync every 30s


async def _init_dht() -> None:
    """
    Initialize the Kademlia DHT subsystem during node startup.

    - Creates the local P2P Node from the existing identity
    - Loads or creates the routing table (with disk persistence)
    - Initializes DNS seed discovery
    - Bootstraps the DHT from DNS seeds + hardcoded bootstrap nodes
    - Starts the periodic refresh loop
    - Starts the DHT ↔ NodesManager bridge
    """

    try:
        # Build the local P2P Node from existing identity
        pub_key = get_public_key_bytes()
        listen_host = DENARO_NODE_HOST or "0.0.0.0"
        listen_port = int(DENARO_NODE_PORT) if DENARO_NODE_PORT else 30303
        local_addr = P2PAddress(ip=listen_host, tcp_port=listen_port)
        local_node = P2PNode(public_key=pub_key, address=local_addr)

        logger.info(f"DHT local node: {local_node.node_id_hex} @ {listen_host}:{listen_port}")

        # Load or create routing table with disk persistence — in this node's own state
        # directory unless the config names one explicitly.
        persist_dir = _node.dht_config.routing_table_path
        if persist_dir.rstrip("/") == "data":
            persist_dir = _p2p_state_dir()
        os.makedirs(persist_dir, exist_ok=True)

        rt_path = os.path.join(persist_dir, "routing_table.json")
        if os.path.exists(rt_path):
            routing_table = RoutingTable.load(local_node.node_id, persist_dir)
            logger.info(f"Loaded persisted routing table: {routing_table.total_nodes} nodes")
        else:
            routing_table = RoutingTable(local_node.node_id, persist_path=persist_dir)
            logger.info("Created fresh routing table")

        # Create KademliaDiscovery instance
        _node.dht_discovery = KademliaDiscovery(
            local_node=local_node,
            routing_table=routing_table,
            http_client=_node.http_client,
        )

        # Initialize DNS seed discovery
        if _node.dht_config.dns_enabled:
            _node.dht_dns_seeds = DNSSeedDiscovery(
                seed_domains=_node.dht_config.dns_seeds,
                require_signatures=_node.dht_config.dns_require_signatures,
            )
            logger.info(f"DNS seed discovery enabled: {_node.dht_config.dns_seeds}")

        # Collect bootstrap seeds: DNS seeds → hardcoded bootstrap nodes
        seed_nodes: List[Tuple[str, int]] = []

        # Try DNS seeds first
        if _node.dht_dns_seeds is not None:
            try:
                dns_addrs = await _node.dht_dns_seeds.discover_with_fallback(
                    hardcoded_bootstrap=[str(url) for url in BOOTSTRAP_NODES],
                )
                for addr in dns_addrs:
                    # Parse @-schema addresses or HTTP URLs
                    if "@" in addr and addr.count("@") == 2:
                        # @-schema: algo@id@host:port
                        parts = addr.split("@")
                        host_port = parts[2]
                        host, port_str = host_port.rsplit(":", 1)
                        seed_nodes.append((host, int(port_str)))
                    elif "://" in addr:
                        parsed = urlparse(addr)
                        host = parsed.hostname or "localhost"
                        port = parsed.port or 30303
                        seed_nodes.append((host, port))
                logger.info(f"DNS seed discovery returned {len(dns_addrs)} addresses")
            except Exception as e:
                logger.warning(f"DNS seed discovery failed: {e}")

        # Always include hardcoded bootstrap nodes as fallback
        for url in BOOTSTRAP_NODES:
            try:
                parsed = urlparse(str(url).strip().rstrip("/"))
                host = parsed.hostname or "localhost"
                port = parsed.port or 30303
                if (host, port) not in seed_nodes:
                    seed_nodes.append((host, port))
            except Exception:
                pass

        # Bootstrap the DHT
        if seed_nodes:
            discovered = await _node.dht_discovery.bootstrap(seed_nodes)
            logger.info(f"DHT bootstrap discovered {discovered} nodes")
        else:
            logger.warning("No DHT seed nodes available — DHT will rely on incoming connections")

        # Start the periodic refresh loop
        _node.dht_discovery.start()

        # Wire DHT into the module-level RPC module so dht_message / dht_getStats etc. work
        _node.dht_rpc_module.set_discovery(_node.dht_discovery, _node.dht_dns_seeds)
        logger.info("DHT wired into RPC module (dht_* methods live)")

        # Start the bridge sync loop
        asyncio.create_task(_periodic_dht_bridge())

        logger.info("✅ Kademlia DHT subsystem initialized")

    except Exception as e:
        logger.error(f"❌ Failed to initialize DHT subsystem: {e}", exc_info=True)
        # DHT failure is non-fatal — node continues with HTTP gossip only
        _node.dht_discovery = None
        _node.dht_dns_seeds = None


async def bootstrap_from_all_nodes():
    """
    Bootstrap from all configured bootstrap nodes.

    This attempts handshakes with all bootstrap nodes to ensure
    maximum peer discovery at startup.
    """
    logger.info(f"Bootstrapping from {len(BOOTSTRAP_NODES)} configured bootstrap nodes...")

    successful = 0
    for node_url in BOOTSTRAP_NODES:
        node_url = node_url.strip().rstrip("/")
        if not node_url:
            continue

        try:
            logger.info(f"Attempting bootstrap from {node_url}")
            await _peers.do_handshake_with_peer(node_url)
            successful += 1
        except Exception as e:
            logger.warning(f"Failed to bootstrap from {node_url}: {e}")

        # Small delay between bootstrap attempts
        await asyncio.sleep(1)

    logger.info(
        f"Bootstrap complete: {successful}/{len(BOOTSTRAP_NODES)} nodes successful, "
        f"{len(NodesManager.peers)} total peers"
    )
    return successful


async def periodic_peer_discovery():
    """
    Periodically discovers new peers via gossip and verifies them via handshake.
    This version is now resilient to unreachable peers and supports multiple bootstrap nodes.
    """
    await asyncio.sleep(5)  # Start peer discovery quickly

    # Initial bootstrap from all configured nodes
    await bootstrap_from_all_nodes()

    # Immediately check peers for a longer chain after bootstrapping.
    # This prevents newly-started nodes from waiting a full periodic_update_fetcher
    # cycle (8s) before discovering they are behind.
    try:
        all_peers = NodesManager.get_all_peers()
        connectable = [p for p in all_peers if p.get("url")]
        if connectable:
            logger.info(
                f"Post-bootstrap sync check: probing {len(connectable)} peer(s) for longer chain"
            )
            for peer_info in connectable[:3]:
                await _sync.check_peer_and_sync(peer_info)
                await asyncio.sleep(0.5)
    except Exception as e:
        logger.warning(f"Post-bootstrap sync check failed: {e}")
    # The validator may now propose and vote (_validator_wait_reason), once it has caught up.
    try:
        await _sync._catch_up_before_validating()
    except Exception as e:
        logger.warning(f"Catching up before validating failed: {e}")
    _sync._initial_sync_pending = False

    while True:
        await asyncio.sleep(30)  # Refresh peers every 30s
        logger.debug("Running periodic peer discovery...")

        # Peers learned only from their own requests have no URL (a private node does not
        # advertise one), so a node knowing only those cannot sync from anyone.
        if not any(p.get("url") for p in NodesManager.peers.values()):
            logger.info("No connectable peer. Re-bootstrapping from configured nodes.")
            await bootstrap_from_all_nodes()
            continue
        # A configured node that no peer entry reaches (dropped while it was down, then back
        # as a URL-less inbound peer) is handshaken again, which records its URL.
        known_urls = {(p.get("url") or "").rstrip("/") for p in NodesManager.peers.values()}
        for node_url in BOOTSTRAP_NODES:
            node_url = node_url.strip().rstrip("/")
            if node_url and node_url != DENARO_SELF_URL and node_url not in known_urls:
                asyncio.create_task(_peers.do_handshake_with_peer(node_url))

        connectable_peers_tuples = [
            (node_id, peer_data)
            for node_id, peer_data in NodesManager.peers.items()
            if peer_data.get("url")
        ]

        if not connectable_peers_tuples:
            logger.debug(
                "No connectable peers to ask for discovery. Waiting for new inbound connections."
            )
            continue

        # Define peer_id and peer_url here so they are in scope for the entire loop iteration.
        peer_id, peer_data_to_ask = random.choice(connectable_peers_tuples)
        peer_url = peer_data_to_ask["url"]

        logger.debug(f"Asking peer {peer_id} for their peer list")
        try:
            # Use the correctly scoped variables
            interface = NodeInterface(peer_url, client=_node.http_client, db=_node.db)
            peers_resp = await interface.get_peers()

            if not (peers_resp and peers_resp.get("ok")):
                # Peer responded but with an error. This is a minor protocol violation.
                await _node.security.reputation_manager.record_violation(
                    peer_id, "get_peers_failed", 1
                )
                continue

            discovered_peers = peers_resp["result"]["peers"]
            logger.debug(f"Discovered {len(discovered_peers)} peers from {peer_id}.")
            for discovered_peer in discovered_peers:
                if (
                    discovered_peer["node_id"] not in NodesManager.peers
                    and discovered_peer["node_id"] != _node.self_node_id
                ):
                    if len(NodesManager.peers) < MAX_PEERS and discovered_peer.get("url"):
                        logger.info(
                            f"Found new peer {discovered_peer['node_id']} via exchange. Attempting handshake."
                        )
                        asyncio.create_task(_peers.do_handshake_with_peer(discovered_peer["url"]))

        except httpx.RequestError:
            await _peers.handle_unreachable_peer(peer_id, peer_url, "peer discovery")

        except Exception as e:
            # Use the correctly scoped variable in the log message
            logger.error(f"Error during peer discovery with {peer_url}: {e}")

        # Supplement with DHT iterative lookup for our own node ID
        if _node.dht_discovery is not None and len(NodesManager.peers) < MAX_PEERS:
            try:
                from qrdx.p2p.node import derive_node_id as _dni

                local_nid = _dni(get_public_key_bytes())
                dht_found = await _node.dht_discovery.iterative_find_node(local_nid, count=10)
                for entry in dht_found:
                    if (
                        entry.node_id_hex not in NodesManager.peers
                        and entry.node_id_hex != _node.self_node_id
                    ):
                        if len(NodesManager.peers) < MAX_PEERS and entry.host:
                            peer_url_dht = f"http://{entry.host}:{entry.port}"
                            asyncio.create_task(_peers.do_handshake_with_peer(peer_url_dht))
            except Exception as e:
                logger.debug(f"DHT peer discovery supplement error: {e}")


def _p2p_state_dir() -> str:
    """Where this node keeps its peer store and DHT routing table: beside its own database
    (``<database>.p2p/``), or ``QRDX_P2P_STATE_DIR``. They used to be a file inside the package
    (``qrdx/node/nodes.json``) and a ``data/`` directory relative to the working directory —
    shared by every node started from one directory, which is how one testnet came to dial
    another."""
    explicit = os.environ.get("QRDX_P2P_STATE_DIR")
    if explicit:
        return explicit
    db_path = str(DENARO_DATABASE_PATH) if DENARO_DATABASE_PATH else "data/qrdx.db"
    return os.path.splitext(db_path)[0] + ".p2p"
