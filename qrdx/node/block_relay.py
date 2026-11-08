"""
Compact block relay (docs/PERFORMANCE.md).

A block travelled to every peer whole: each exchange operation in it carries a post-quantum
signature and key, about 10 KB, so a block of 1,000 was 10 MB to encode, send and parse,
peer after peer. Every peer already holds those operations, from gossip. So a block now
travels with its exchange section named by hash (``exchange_tx_hashes``), about 70 bytes each:

* the receiver rebuilds the section from its own mempool, the operations its mempool already
  checked (``block_processor.is_verified``);
* it asks the sender only for what it lacks: over the peer transport by hash when the block came
  over it (qrdx/node/netd.py), then over HTTP (``p2p_getBlockTxs``, by position). A node keeps
  the sections of the blocks it recently sent;
* then the rebuilt block goes through ``p2p_submitBlock`` exactly as a whole one does: its
  body must hash to the ``body_root`` its proposer signed. A rebuilt section that differs in
  any byte is refused, and the receiver fetches the section whole instead.

Nothing changes in consensus. What is relayed is the block its proposer signed, and every
check runs on the section rebuilt in full.

The node's state (the exchange mempool) lives in qrdx.node.main and is read from it at call
time, as ``_node.<name>``.
"""

from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from qrdx.logger import get_logger
from qrdx.node import main as _node

logger = get_logger(__name__)

# The exchange sections of the blocks this node sent lately, by block hash, for peers missing
# some of their operations.
KEEP_BODIES = 256
# The most operations one compact block may name, and one request may fetch.
MAX_COMPACT_TXS = 20_000

_bodies: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()

# The keys of a block's dict that never travel: the decoded operations and their hashes, which a
# node keeps beside a block it handles.
LOCAL_KEYS = ("_exchange_objects", "_exchange_tx_hashes")


def remember(block_hash: Optional[str], section: Optional[List[Dict[str, Any]]]) -> None:
    if not block_hash or not section:
        return
    _bodies[block_hash] = section
    _bodies.move_to_end(block_hash)
    while len(_bodies) > KEEP_BODIES:
        _bodies.popitem(last=False)


def body_txs(block_hash: str, indexes: List[int]) -> Optional[List[Dict[str, Any]]]:
    """The operations at ``indexes`` of a block this node sent lately, or None."""
    section = _bodies.get(block_hash)
    if section is None:
        return None
    if len(indexes) > MAX_COMPACT_TXS or any(
        not isinstance(i, int) or isinstance(i, bool) or not 0 <= i < len(section) for i in indexes
    ):
        return None
    return [section[i] for i in indexes]


def wire_form(data: Dict[str, Any]) -> Dict[str, Any]:
    """The block as it travels whole: without what a node keeps beside it."""
    return {k: v for k, v in data.items() if k not in LOCAL_KEYS}


def compact_form(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The block with its exchange section named by hash, or None when it has none to name."""
    section = data.get("exchange_transactions")
    if not section:
        return None
    hashes = data.get("_exchange_tx_hashes")
    if not hashes or len(hashes) != len(section):
        objects = data.get("_exchange_objects")
        if objects is None or len(objects) != len(section):
            from qrdx.exchange.block_processor import decode_exchange_txs

            objects = decode_exchange_txs(section)
        hashes = [t.tx_hash() for t in objects]
    out = {k: v for k, v in wire_form(data).items() if k != "exchange_transactions"}
    out["exchange_tx_hashes"] = list(hashes)
    return out


def settle(block_data: Dict[str, Any]) -> None:
    """What an applied block consumed leaves this node's mempool: its operations' lanes are
    pruned below their new expected nonces (``ExchangeMempool.prune_lanes``). A whole block
    (rare: compact relay is the rule) is left to the mempool's own sweep."""
    objects = block_data.get("_exchange_objects")
    if objects:
        _node._get_exchange_mempool().prune_lanes(t.nonce_key() for t in objects)


async def rebuild(
    block_data: Dict[str, Any],
    sender_url: Optional[str],
    whole: bool = False,
    sender_node: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], str]:
    """A compact block's whole form (with its operations decoded beside it), or (None, why).
    ``whole``: fetch every operation from the sender (over HTTP, by position) rather than
    reading the mempool. ``sender_node``: the sender's node id, asked over the transport."""
    from qrdx.exchange.transactions import ExchangeTransaction

    hashes = block_data.get("exchange_tx_hashes")
    if not isinstance(hashes, list) or not all(isinstance(h, str) for h in hashes):
        return None, "a compact block names its exchange operations by hash"
    if len(hashes) > MAX_COMPACT_TXS:
        return None, f"a compact block names at most {MAX_COMPACT_TXS} operations"
    mempool = _node._get_exchange_mempool()
    txs: List[Optional[ExchangeTransaction]] = (
        [None] * len(hashes) if whole else [mempool.get(h) for h in hashes]
    )
    missing = [i for i, t in enumerate(txs) if t is None]
    if missing and not whole:
        held = _from_transport([hashes[i] for i in missing])
        for i, tx in zip(missing, held, strict=True):
            txs[i] = tx
        missing = [i for i, t in enumerate(txs) if t is None]
    if missing and not whole and sender_node:
        held = await _from_sender(sender_node, [hashes[i] for i in missing])
        for i, tx in zip(missing, held, strict=True):
            txs[i] = tx
        missing = [i for i, t in enumerate(txs) if t is None]
    if missing:
        fetched = await _fetch(sender_url, block_data.get("block_hash"), missing)
        if fetched is None or len(fetched) != len(missing):
            return None, f"{len(missing)} of the block's exchange operations are unavailable"
        for i, item in zip(missing, fetched, strict=True):
            try:
                tx = ExchangeTransaction.from_any(item)
            except Exception as e:
                return None, f"the sender sent an unreadable operation: {e}"
            if tx.tx_hash() != hashes[i]:
                return None, "the sender sent an operation the block does not name"
            txs[i] = tx
    full = {k: v for k, v in block_data.items() if k != "exchange_tx_hashes"}
    objects = [t for t in txs if t is not None]
    from qrdx.exchange.block_processor import encode_exchange_txs

    height = block_data.get("id")
    full["exchange_transactions"] = encode_exchange_txs(
        objects, int(height) if isinstance(height, int) else None
    )
    full["_exchange_objects"] = objects
    full["_exchange_tx_hashes"] = list(hashes)
    if missing:
        logger.info(
            f"compact block {block_data.get('id')}: fetched {len(missing)} of {len(hashes)} "
            f"operations from its sender"
        )
    return full, ""


def _read(raws: List[Optional[bytes]], hashes: List[str]) -> List[Any]:
    """Each raw operation read, if it is the one named; else None. (The block's import verifies
    its signature, as it does any operation's.)"""
    from qrdx.exchange.submission import parse_exchange_tx

    out: List[Any] = []
    for h, raw in zip(hashes, raws, strict=True):
        tx = None
        if raw is not None:
            try:
                tx = parse_exchange_tx(raw)
                if tx.tx_hash() != h:
                    tx = None
            except Exception:
                tx = None
        out.append(tx)
    return out


async def _from_sender(sender_node: str, hashes: List[str]) -> List[Any]:
    """What the block's sender holds of ``hashes``, asked over the transport."""
    from qrdx.node import netd

    return _read(await netd.ask_block_txs(sender_node, hashes), hashes)


def _from_transport(hashes: List[str]) -> List[Any]:
    """What the peer transport holds of ``hashes`` (qrdx/node/netd.py), read: operations that
    reached this node but are not admitted yet (admission waits while a block is processed), so
    they are not in the mempool. Under latency a block often arrived before its operations were
    admitted, and its whole section was fetched again from the sender, a round trip and a
    megabyte. Each is checked as any operation in a block is: its hash must be the one named,
    and the block's import verifies its signature."""
    from qrdx.node import netd

    service = netd.SERVICE
    if service is None:
        return [None] * len(hashes)
    return _read(list(service.lookup(hashes)), hashes)


async def _fetch(
    sender_url: Optional[str], block_hash: Optional[str], indexes: List[int]
) -> Optional[List[Dict[str, Any]]]:
    if not sender_url or not block_hash:
        return None
    from qrdx.node.nodes_manager import NodeInterface

    ni = NodeInterface(sender_url, client=_node.http_client, db=_node.db)
    found: List[Dict[str, Any]] = []
    for at in range(0, len(indexes), MAX_COMPACT_TXS):
        reply = ni._unwrap(
            await ni._rpc_call("p2p_getBlockTxs", [block_hash, indexes[at : at + MAX_COMPACT_TXS]])
        )
        if not reply or not reply.get("ok") or not isinstance(reply.get("result"), list):
            return None
        found.extend(reply["result"])
    return found
