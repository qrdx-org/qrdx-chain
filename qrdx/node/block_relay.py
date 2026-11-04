"""
Compact block relay (docs/PERFORMANCE.md).

A block travelled to every peer whole: each exchange operation in it carries a post-quantum
signature and key, about 10 KB, so a block of 1,000 was 10 MB to encode, send and parse,
peer after peer. Every peer already holds those operations, from gossip. So a block now
travels with its exchange section named by hash (``exchange_tx_hashes``), about 70 bytes each:

* the receiver rebuilds the section from its own mempool, the operations its mempool already
  checked (``block_processor.is_verified``);
* it asks the sender only for what it lacks (``p2p_getBlockTxs``, by position). A node keeps
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


async def rebuild(
    block_data: Dict[str, Any], sender_url: Optional[str], whole: bool = False
) -> Tuple[Optional[Dict[str, Any]], str]:
    """A compact block's whole form (with its operations decoded beside it), or (None, why).
    ``whole``: fetch every operation from the sender rather than reading the mempool."""
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
    if missing:
        fetched = await _fetch(sender_url, block_data.get("block_hash"), missing)
        if fetched is None or len(fetched) != len(missing):
            return None, f"{len(missing)} of the block's exchange operations are unavailable"
        for i, item in zip(missing, fetched, strict=True):
            try:
                tx = ExchangeTransaction.from_dict(item)
            except Exception as e:
                return None, f"the sender sent an unreadable operation: {e}"
            if tx.tx_hash() != hashes[i]:
                return None, "the sender sent an operation the block does not name"
            txs[i] = tx
    full = {k: v for k, v in block_data.items() if k != "exchange_tx_hashes"}
    objects = [t for t in txs if t is not None]
    full["exchange_transactions"] = [t.to_dict() for t in objects]
    full["_exchange_objects"] = objects
    full["_exchange_tx_hashes"] = list(hashes)
    if missing:
        logger.info(
            f"compact block {block_data.get('id')}: fetched {len(missing)} of {len(hashes)} "
            f"operations from its sender"
        )
    return full, ""


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
