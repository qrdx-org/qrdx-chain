"""
The node's side of the native peer transport (native/qrdx-native/src/net; docs/NETWORK.md).

Peers' transactions used to reach a node as signed HTTP batches of JSON, and every part of
receiving them ran on the node's one Python thread: the HTTP request, the JSON, the signature
check, and relaying them on. At load that was most of the node's time (docs/PERFORMANCE.md).
With the transport, peers keep an encrypted connection open, and its threads do that work:
reading each transaction, setting duplicates aside, checking signatures, gossip. This module
does what needs the chain's state:

* **Admission.** It admits what the transport hands over (nonces, balances, the mempool),
  through the same ``ExchangeSubmitter`` as every other path. A signature verdict from the
  transport is used only for the exact bytes Python itself would verify: the transaction's
  signed bytes, computed here, must equal the bytes the transport checked.
* **Relaying.** It relays what it admits: a wallet's transaction whole to every peer, a peer's
  announced to the others (``ExchangeSubmitter.use_transport``).
* **Peers.** It keeps the transport's peers to the ones this node admitted (``NodesManager``),
  and not banned, and dials them.
* **Blocks and votes.** A block or vote a peer sends over the transport is taken exactly as one
  sent over HTTP: by the same handlers (``P2PModule.submitCompactBlock`` / ``submitBlock``,
  ``peers._add_remote_attestation``), with the peer the transport authenticated as the
  verified sender (``rpc_caller``). What the node takes it relays, over the transport to the
  peers connected on it and over HTTP to the rest (``peers.propagate``). A compact block's
  operations this node lacks are asked of the peer that sent it (``ask_block_txs``) before
  HTTP.

``QRDX_P2P=0`` turns it off: transactions, blocks and votes then travel over HTTP as before. A peer's transport
listens on its HTTP port plus ``QRDX_P2P_PORT_OFFSET`` (10,000), or on ``QRDX_P2P_PORT``.

The node's state lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``.
"""

import asyncio
import json
import os
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from qrdx.logger import get_logger
from qrdx.node import main as _node

logger = get_logger(__name__)

PORT_OFFSET = int(os.environ.get("QRDX_P2P_PORT_OFFSET", "10000"))
PEER_REFRESH_SECONDS = 2.0
# How long a peer has to answer a request for a block's operations (then HTTP is asked).
ASK_SECONDS = 2.0
ASK_BATCH = 1024  # operations one request names (the transport's bound)

SERVICE: Any = None  # the qrdx_native.NetService, once started
_asked: Dict[int, "asyncio.Future[List[Optional[bytes]]]"] = {}


def enabled() -> bool:
    if os.environ.get("QRDX_P2P", "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    from qrdx import native

    return native.AVAILABLE and hasattr(native._native, "NetService")


def p2p_port(http_port: int) -> int:
    configured = os.environ.get("QRDX_P2P_PORT")
    return int(configured) if configured else int(http_port) + PORT_OFFSET


async def start(chain_id: int, genesis_hash: str, http_port: int) -> bool:
    """Start the transport, if it is available and not turned off. True if it runs."""
    global SERVICE
    if SERVICE is not None or not enabled():
        return SERVICE is not None
    from qrdx import native
    from qrdx.node import identity

    host = os.environ.get("QRDX_P2P_HOST", "0.0.0.0")
    try:
        svc = native._native.NetService(
            f"{host}:{p2p_port(http_port)}",
            identity._secret_key,
            identity._public_key,
            int(chain_id),
            genesis_hash,
            max_peers=int(os.environ.get("QRDX_P2P_MAX_PEERS", "64")),
            threads=int(os.environ.get("QRDX_P2P_THREADS", "4")),
        )
        bound = svc.start()
    except Exception as e:
        logger.warning(f"peer transport not started ({e}); transactions travel over HTTP")
        return False
    asyncio.get_running_loop().add_reader(svc.event_fd(), _on_events)
    SERVICE = svc
    _node._get_exchange_submitter().use_transport(svc.relay)
    asyncio.ensure_future(_keep_peers())
    logger.info(f"peer transport listening on {bound} as {svc.node_id}")
    return True


def stop() -> None:
    global SERVICE
    if SERVICE is None:
        return
    try:
        asyncio.get_running_loop().remove_reader(SERVICE.event_fd())
    except Exception:
        pass
    SERVICE.stop()
    SERVICE = None


def _on_events() -> None:
    if SERVICE is None:
        return
    for event in SERVICE.drain():
        kind = event[0]
        if kind == "txs":
            asyncio.ensure_future(_admit(event[1], event[2]))
        elif kind == "block":
            asyncio.ensure_future(_receive_block(event[1], event[2]))
        elif kind == "votes":
            asyncio.ensure_future(_receive_votes(event[1], event[2]))
        elif kind == "block_txs":
            future = _asked.pop(event[2], None)
            if future is not None and not future.done():
                future.set_result(list(event[3]))
        elif kind == "up":
            logger.debug(f"peer transport: connected to {event[1]} at {event[2]}")
        elif kind == "down":
            logger.debug(f"peer transport: {event[1]} disconnected")


async def _admit(peer: str, items: List[Tuple[bytes, Optional[str], Any, Any, Any]]) -> None:
    """Admit a peer's transactions. A verdict from the transport is taken for the bytes it
    checked only when they are this transaction's signed bytes as Python computes them."""
    from qrdx.constants import SLOT_DURATION
    from qrdx.crypto.pq import dilithium
    from qrdx.exchange.block_processor import verify_exchange_tx
    from qrdx.exchange.submission import parse_exchange_tx

    # Blocks first: reading a batch is event-loop time a block being imported would wait for.
    until_free = getattr(_node.block_processing_lock, "until_free", None)
    if until_free is not None:
        await until_free(SLOT_DURATION)
    txs = []
    verdicts: Dict[Tuple[bytes, bytes, bytes], bool] = {}
    for raw, tx_hash, signed, verdict, _reason in items:
        try:
            tx = parse_exchange_tx(raw)
        except Exception:
            continue
        if signed is not None and verdict is not None and tx.public_key and tx.signature:
            if bytes(signed) == tx.signing_bytes():
                verdicts[(bytes(tx.public_key), bytes(signed), bytes(tx.signature))] = verdict
        # (the transport does not hold what it did not read itself: given with it to relay)
        txs.append((tx, None if tx_hash else bytes(raw)))
    if verdicts:
        with dilithium.precomputed(verdicts):
            for tx, _ in txs:
                verify_exchange_tx(tx)  # (the Python checks, with the transport's verdicts)
    submitter = _node._get_exchange_submitter()
    try:  # (the batch together: one signature batch, one balance read, no wait a transaction)
        await submitter.submit_batch(txs, propagated=True, origin=peer)
    except Exception as e:
        logger.debug(f"peer transport: a batch from {peer[:16]} not admitted: {e}")


async def _receive_block(peer: str, raw: bytes) -> None:
    """A block a peer sent over the transport, taken as one sent over HTTP is: the same handler,
    the peer the transport authenticated as its verified sender."""
    from qrdx.rpc.server import rpc_caller

    try:
        block = json.loads(raw)
    except ValueError:
        return
    if not isinstance(block, dict):
        return
    block.pop("_sender_node_id", None)  # (who sent it is the connection's to say)
    module = _node.p2p_rpc_module
    token = rpc_caller.set(peer)
    try:
        if "exchange_tx_hashes" in block:
            reply = await module.submitCompactBlock(block)
        else:
            reply = await module.submitBlock(block)
        if isinstance(reply, dict) and not reply.get("ok"):
            logger.debug(f"peer transport: block from {peer[:16]} not taken: {reply.get('error')}")
    except Exception as e:
        logger.debug(f"peer transport: block from {peer[:16]} failed: {e}")
    finally:
        rpc_caller.reset(token)


async def _receive_votes(peer: str, raws: List[bytes]) -> None:
    """Votes a peer sent over the transport, taken as gossiped ones are (verified, pooled,
    relayed once)."""
    from qrdx.node import peers

    for raw in raws:
        try:
            vote = json.loads(raw)
        except ValueError:
            continue
        if isinstance(vote, dict):
            vote.pop("_sender_node_id", None)
            await peers._add_remote_attestation(vote, peer)


def send_block(raw: bytes, except_node: Optional[str] = None) -> List[str]:
    """Send a block (its wire form, JSON) to every transport peer but ``except_node``: the
    peers it went to."""
    if SERVICE is None:
        return []
    try:
        return list(SERVICE.send_block(raw, except_node))
    except Exception as e:
        logger.debug(f"peer transport: block not sent: {e}")
        return []


def send_votes(raws: List[bytes], except_node: Optional[str] = None) -> List[str]:
    """Send votes (each its JSON) to every transport peer but ``except_node``: the peers they
    went to."""
    if SERVICE is None:
        return []
    try:
        return list(SERVICE.send_votes(raws, except_node))
    except Exception as e:
        logger.debug(f"peer transport: votes not sent: {e}")
        return []


def _held(item: Any) -> bytes:
    """An operation as the transport hands it to a peer: its binary form (a section item in the
    binary form's text), or its JSON."""
    if isinstance(item, str):
        from qrdx.exchange.wire import from_text

        return from_text(item)
    from qrdx.fastjson import dumps

    return dumps(item).encode()


def hold_section(hashes: List[str], section: List[Any]) -> None:
    """Keep a block's operations where a peer can ask for them (those the pool lacks)."""
    if SERVICE is None or not hashes or len(hashes) != len(section):
        return

    try:
        missing = set(SERVICE.missing(list(hashes)))
        if missing:
            SERVICE.hold(
                [(h, _held(item)) for h, item in zip(hashes, section, strict=True) if h in missing]
            )
    except Exception as e:
        logger.debug(f"peer transport: a block's operations not held: {e}")


async def ask_block_txs(peer: str, hashes: List[str]) -> List[Optional[bytes]]:
    """A block's operations by hash, asked of the peer that sent it: each one's JSON, or None
    where it did not answer (it does not hold it, it is not connected, it took too long)."""
    out: List[Optional[bytes]] = [None] * len(hashes)
    if SERVICE is None or not hashes:
        return out
    loop = asyncio.get_running_loop()
    for at in range(0, len(hashes), ASK_BATCH):
        chunk = hashes[at : at + ASK_BATCH]
        try:
            request = SERVICE.ask_block_txs(peer, chunk)
        except Exception:
            return out
        if request is None:
            return out
        future: "asyncio.Future[List[Optional[bytes]]]" = loop.create_future()
        _asked[request] = future  # (before any event is read: no await since the ask)
        try:
            got = await asyncio.wait_for(future, ASK_SECONDS)
        except asyncio.TimeoutError:
            _asked.pop(request, None)
            return out
        if len(got) != len(chunk):
            return out
        for i, raw in enumerate(got):
            out[at + i] = None if raw is None else bytes(raw)
    return out


def _address(url: str) -> Optional[str]:
    """A peer's transport address, from its HTTP URL."""
    try:
        parsed = urlparse(url)
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            return None
        ip = str(socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0])
        return f"[{ip}]:{p2p_port(port)}" if ":" in ip else f"{ip}:{p2p_port(port)}"
    except (OSError, ValueError, IndexError):
        return None


async def _keep_peers() -> None:
    """Keep the transport's peers to the node's admitted ones, and dial those not connected."""
    from qrdx.node.nodes_manager import NodesManager

    loop = asyncio.get_running_loop()
    while SERVICE is not None:
        try:
            peers = []
            for p in NodesManager.get_propagate_peers():
                node_id = p.get("node_id")
                if node_id and not await _node.security.reputation_manager.is_banned(node_id):
                    peers.append(p)
            SERVICE.allow([p["node_id"] for p in peers])
            connected = {p[0] for p in SERVICE.peers()}
            for p in peers:
                if p["node_id"] in connected or not p.get("url"):
                    continue
                addr = await loop.run_in_executor(None, _address, p["url"])
                if addr:
                    SERVICE.connect(addr, p["node_id"])
        except Exception as e:
            logger.debug(f"peer transport: refreshing peers failed: {e}")
        await asyncio.sleep(PEER_REFRESH_SECONDS)
