"""
Which chain this database and each peer are on: the chain spec, the genesis block,
passed forks and trusted checkpoints.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import json
import time
from typing import Optional, Tuple

from qrdx import chain_spec as chain_spec_mod
from qrdx.constants import CHAIN_SPEC, CHAIN_SPEC_FILE, NODE_VERSION
from qrdx.logger import get_logger
from qrdx.node import main as _node
from qrdx.node.nodes_manager import NodesManager
from qrdx.node.observability import METRICS

logger = get_logger(__name__)


async def _verify_trusted_checkpoints() -> None:
    """The database must be on the trusted chain (qrdx/checkpoints.py): refuse to start if it
    holds another block at a checkpoint height; warn if it is older than the weak-subjectivity
    period and nothing newer is trusted."""
    from .. import checkpoints
    from ..validator.node_integration import parse_block_timestamp

    error = await checkpoints.startup_error(_node.db)
    if error:
        raise ChainIdentityError(error)
    tip = int(await _node.db.get_next_block_id()) - 1
    block = await _node.db.get_block_by_id(tip) if tip >= 1 else None
    stamp = parse_block_timestamp(block.get("timestamp")) if block else None
    warning = checkpoints.staleness_warning(
        tip, stamp.timestamp() if stamp is not None else None, time.time()
    )
    if warning:
        logger.warning(f"[weak subjectivity] {warning}")
    height, block_hash = checkpoints.describe()
    if height >= 0:
        logger.info(
            f"[weak subjectivity] trusting checkpoint {block_hash[:16]}… at height {height}"
        )


_PASSED_FORKS_KEY = "passed_forks"


class ChainIdentityError(RuntimeError):
    """The database, the chain spec and the environment disagree: the node must not start."""


async def _read_chain_metadata(key: str):
    value = _node.db.get_metadata(key)
    return json.loads(value) if value is not None else None


async def _verify_chain_identity() -> str:
    """
    Refuse to start unless this database belongs to the chain spec the node loaded. Called at
    startup, after genesis is created or found and before anything applies a block.

    * The genesis block records the spec it was created under; it must be ours. A database
      from before chain specs records none and is refused (its parameters are unknowable).
    * A network pinned by this release (chain_spec.PINNED_NETWORKS) must have exactly its
      published genesis block.
    * Forks are append-only. Every fork this chain had passed at the node's previous start must
      still be in the spec, unchanged, and no fork may be scheduled at or below the height the
      chain had then reached — either would re-judge blocks already applied under other rules.

    Returns the genesis block hash. Records the forks passed so far for the next start.
    """
    genesis = await _node.db.get_block_by_id(0)
    if not genesis:
        raise ChainIdentityError("the database has no genesis block")
    genesis_hash = genesis.get("hash") or genesis.get("block_hash")
    content = genesis.get("content") or genesis.get("block_content") or {}
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except ValueError:
            content = {}
    spec_hash = CHAIN_SPEC.genesis_hash()
    recorded = content.get("chain_spec_hash") if isinstance(content, dict) else None
    if not recorded:
        raise ChainIdentityError(
            "this database was created before chain specs existed, so the consensus "
            "parameters it was started with are unknown. Start the node on a new database "
            "(it will sync from the network)."
        )
    if recorded != spec_hash:
        raise ChainIdentityError(
            f"this database was created under chain spec {recorded[:16]}…, but the node loaded "
            f"{spec_hash[:16]}… ({CHAIN_SPEC.network}, "
            f"{CHAIN_SPEC_FILE or 'built-in dev spec from the environment'}). Running it would "
            f"apply different consensus rules to the same chain. Use the network's genesis file "
            f"(and, on a dev network, the environment the database was created with), or start "
            f"on a new database."
        )
    if content.get("chain_id") != CHAIN_SPEC.chain_id:
        raise ChainIdentityError(
            f"genesis records chain id {content.get('chain_id')}, the chain "
            f"spec {CHAIN_SPEC.chain_id}"
        )
    pinned = chain_spec_mod.PINNED_NETWORKS.get(CHAIN_SPEC.network)
    if pinned and pinned.lower() != str(genesis_hash).lower():
        raise ChainIdentityError(
            f"{CHAIN_SPEC.network} is pinned to genesis {pinned[:16]}… by this release, but this "
            f"database holds {str(genesis_hash)[:16]}…"
        )

    tip = await _node.db.get_next_block_id() - 1
    record = await _read_chain_metadata(_PASSED_FORKS_KEY)
    if record:
        spec_forks = {f["name"]: f for f in CHAIN_SPEC.forks}
        for f in record.get("forks", []):
            if spec_forks.get(f["name"]) != f:
                change = "defines it differently" if f["name"] in spec_forks else "omits it"
                raise ChainIdentityError(
                    f"fork {f['name']} (height {f['height']}) has passed on this chain, but the "
                    f"chain spec now {change}. A passed fork can never change: restore the "
                    f"network's chain spec."
                )
        reached = int(record.get("tip", -1))
        for f in CHAIN_SPEC.forks:
            if f["height"] <= reached and f not in record.get("forks", []):
                raise ChainIdentityError(
                    f"the chain spec schedules fork {f['name']} at height {f['height']}, but this "
                    f"chain passed that height (it had reached {reached}) without it. Forks are "
                    f"scheduled ahead of the chain, never behind it."
                )
        tip = max(tip, reached)
    passed = [f for f in CHAIN_SPEC.forks if f["height"] <= tip]
    _node.db.set_metadata(
        _PASSED_FORKS_KEY, json.dumps({"tip": tip, "forks": passed}, sort_keys=True)
    )
    await _node.db.connection.commit()
    return str(genesis_hash)


async def _local_network_identity() -> dict:
    """What this node advertises to peers (handshake, status): its network, genesis, fork id,
    software version and the features its software can execute."""
    if _node.GENESIS_BLOCK_HASH is None:
        raise ChainIdentityError("chain identity is not verified yet")
    tip = max(0, await _node.db.get_next_block_id() - 1)
    return chain_spec_mod.network_identity(CHAIN_SPEC, _node.GENESIS_BLOCK_HASH, tip, NODE_VERSION)


async def _check_peer_identity(remote) -> Tuple[bool, str]:
    """Does a peer advertising ``remote`` follow our chain (same genesis, chain id and fork
    history — chain_spec.check_peer_compatibility)?"""
    if _node.GENESIS_BLOCK_HASH is None:
        return False, "this node's chain identity is not verified yet"
    tip = max(0, await _node.db.get_next_block_id() - 1)
    return chain_spec_mod.check_peer_compatibility(
        CHAIN_SPEC, _node.GENESIS_BLOCK_HASH, tip, remote
    )


async def _drop_if_incompatible(peer_id: Optional[str], remote_identity, context: str) -> bool:
    """Check a peer's advertised identity; forget the peer if it follows another chain (a
    different network, or a fork history ours does not share — e.g. it missed an upgrade).
    Returns True if the peer is compatible."""
    ok, reason = await _check_peer_identity(remote_identity)
    if ok and peer_id and isinstance(remote_identity, dict):
        peer = NodesManager.get_peer(peer_id)
        if peer is not None:
            # In-memory readiness signal for the next fork (/chain_spec, /metrics).
            peer["fork_next"] = int(remote_identity.get("fork_next") or 0)
            peer["node_version"] = str(remote_identity.get("node_version") or "")[:32]
    if not ok:
        METRICS.inc("qrdx_peer_identity_rejections_total")
        logger.warning(f"[chain-spec] {context}: peer {peer_id or '?'} is incompatible — {reason}")
        if peer_id and NodesManager.get_peer(peer_id) is not None:
            NodesManager.remove_peer(peer_id)
    return ok
