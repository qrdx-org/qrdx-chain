"""
Peers: who they are (signed requests, the handshake, validator proofs, admission),
dialing them back, and what we send them (blocks, transactions, attestations).

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import asyncio
import ipaddress
import os
import random
import socket
import time
import traceback
from asyncio import gather
from typing import Any, Dict, Optional, Set
from urllib.parse import urlparse

import httpx
from starlette.requests import Request

from qrdx.constants import BOOTSTRAP_NODES, DENARO_SELF_URL, MAX_PEERS
from qrdx.database_sqlite import DatabaseSQLite as Database
from qrdx.logger import get_logger
from qrdx.node import chain_identity as _identity, main as _node, sync as _sync
from qrdx.node.identity import get_node_id
from qrdx.node.main import app
from qrdx.node.nodes_manager import NodeInterface, NodesManager

logger = get_logger(__name__)

# Attestation gossip. Validators sign one attestation per slot but the broadcast hook
# was never bound, so attestations stayed LOCAL — each proposer could only include its
# OWN attestation, making per-epoch attester coverage = distinct canonical proposers.
# As tip races make production uneven, coverage drops below the 2/3 finality threshold
# and justification stalls (the real cause of the long-run finality lag — NOT a
# block-history fork, which converges). Binding the broadcast fn floods each signed
# attestation to peers so every proposer's pool (and thus every block) carries the whole
# validator set's votes → full per-epoch coverage → finality advances. Additive + signed
# + deduped; no reject path, so no halt risk. Kill-switch, default ON.
_ENABLE_ATTESTATION_GOSSIP = True
# Bounded seen-set for gossip-flood dedup (re-propagate each attestation once).
_SEEN_ATTESTATIONS: set = set()
_SEEN_ATTESTATIONS_MAX = 20000


async def validate_url_for_connection(url: str) -> bool:
    """Validate URL is safe for outbound connections with DNS rebinding protection"""
    if not url:
        return False
    is_valid, resolved_ip = await _node.security.dns_client.validate_and_resolve(url)
    if not is_valid:
        return False
    try:
        ip_obj = ipaddress.ip_address(resolved_ip)
        # Block connections to loopback, link-local, or reserved IPs
        if not ip_obj.is_global and not ip_obj.is_private:
            logger.warning(f"Blocked connection to reserved/loopback/link-local IP: {resolved_ip}")
            return False
        # If the node itself is public, it must not initiate connections to private networks
        if _node.self_is_public and ip_obj.is_private:
            logger.warning(f"Public node blocked connection attempt to private IP: {resolved_ip}")
            return False
        return True
    except Exception as e:
        logger.error(f"Unexpected error while validating Address: {url} - {e}")
        return False


async def propagate(
    path: str, data: dict, ignore_node_id: Optional[str] = None, db: Optional[Database] = None
):
    """Propagates a message with reputation tracking and rate limiting"""
    async with _node.security.propagation_semaphore:
        all_peers = NodesManager.get_propagate_peers()

        # Filter out banned peers
        non_banned_peers = []
        for peer in all_peers:
            if not await _node.security.reputation_manager.is_banned(peer["node_id"]):
                non_banned_peers.append(peer)

        # Limit number of peers
        max_peers_to_propagate = min(len(non_banned_peers), 20)
        if len(non_banned_peers) > max_peers_to_propagate:
            all_peers = random.sample(non_banned_peers, max_peers_to_propagate)
        else:
            all_peers = non_banned_peers

        tasks = []
        # A block is encoded and signed once for every peer (each peer sees the request's nonce
        # once). It travels compact, its exchange operations named by hash, which every peer
        # already holds from gossip (qrdx/node/block_relay.py); whole only to a peer that cannot
        # rebuild it, and then encoded once too.
        prepared = None
        compact = None
        whole_lock = asyncio.Lock()
        if path == "submit_block":
            from qrdx.node import block_relay

            block_relay.remember(data.get("block_hash"), data.get("exchange_transactions"))
            form = block_relay.compact_form(data)
            if form is not None:
                compact = await NodeInterface.prepare_rpc(
                    "p2p_submitCompactBlock", [{**form, "_sender_node_id": get_node_id()}]
                )

        async def whole():
            nonlocal prepared
            async with whole_lock:
                if prepared is None:
                    from qrdx.node import block_relay

                    prepared = await NodeInterface.prepare_rpc(
                        "p2p_submitBlock",
                        [{**block_relay.wire_form(data), "_sender_node_id": get_node_id()}],
                    )
            return prepared

        for peer in all_peers:
            if peer["node_id"] == ignore_node_id:
                continue

            async def communication_task(peer_info: dict, p: str, d: dict):
                peer_id = peer_info.get("node_id", "Unknown")
                peer_url = peer_info.get("url")

                try:
                    ni = NodeInterface(peer_info["url"], client=_node.http_client, db=db)

                    if p == "submit_block" and compact is not None:
                        response = await ni.post_prepared(compact)
                        if response is not None and _cannot_rebuild(response):
                            response = await ni.post_prepared(await whole())
                    elif p == "submit_block":
                        response = await ni.post_prepared(await whole())
                    elif p == "push_tx":
                        response = await ni.push_tx(d["tx_hex"])
                    elif p == "push_attestation":
                        response = await ni.push_attestation(d["attestation"])

                    if response and response.get("error") == "sync_required":
                        if not db:
                            logger.warning(
                                f"Received sync_required from {peer_id} but no DB connection available."
                            )
                            return

                        # Use secure peer sync tracker
                        if await _node.security.peer_sync_tracker.add_peer(peer_id):
                            remote_info = response.get("result", {})
                            next_block_needed = remote_info.get("next_block_expected")

                            if next_block_needed is not None:
                                asyncio.create_task(
                                    _sync._push_sync_to_peer(peer_info, next_block_needed, db, d)
                                )
                        return

                    # Track successful propagation
                    await _node.security.reputation_manager.record_good_behavior(peer_id)
                    logger.debug(f"propagate response from {peer_id}: {response}")

                except httpx.RequestError:
                    # The peer is unreachable (timeout, connection refused, etc.).
                    # This is a network failure, not a protocol violation. Remove them non-punitively.
                    await handle_unreachable_peer(peer_id, peer_url, "propagation")

                except Exception as e:
                    # Track failed propagation
                    await _node.security.reputation_manager.record_violation(
                        peer_id, "propagation_failure", severity=1, details=str(e)
                    )
                    logger.warning(f"propagate EXCEPTION from {peer_id}: {e}")

            tasks.append(communication_task(peer, path, data))

        await gather(*tasks)


def _cannot_rebuild(response: dict) -> bool:
    """A peer that does not take compact blocks, or could not rebuild this one: send it whole."""
    if response.get("ok"):
        return False
    error = str(response.get("error", ""))
    return any(
        why in error
        for why in ("Method not found", "not relayed here", "are unavailable", "names its exchange")
    )


# ---------------------------------------------------------------------------
# Attestation gossip (the missing finality wiring — see _ENABLE_ATTESTATION_GOSSIP)
# ---------------------------------------------------------------------------


def _attestation_seen_key(att_dict: dict) -> str:
    """Dedup key for gossip flooding — one vote per (validator, slot, block)."""
    return (
        f"{att_dict.get('validator_address')}:{att_dict.get('slot')}:{att_dict.get('block_hash')}"
    )


def _mark_attestation_seen(key: str) -> bool:
    """Record an attestation key; return True if it was NEW (first sighting)."""
    if key in _SEEN_ATTESTATIONS:
        return False
    _SEEN_ATTESTATIONS.add(key)
    if len(_SEEN_ATTESTATIONS) > _SEEN_ATTESTATIONS_MAX:
        # Cheap bounded trim (drop ~half); dedup is best-effort, not security-critical.
        for k in list(_SEEN_ATTESTATIONS)[: _SEEN_ATTESTATIONS_MAX // 2]:
            _SEEN_ATTESTATIONS.discard(k)
    return True


async def _broadcast_attestation(attestation) -> None:
    """Broadcast hook bound onto the validator manager: flood a freshly-created,
    signed attestation to peers so every proposer's pool carries the whole validator
    set's votes (→ full per-epoch attester coverage → finality advances). Fire-and-
    forget; failures are non-fatal."""
    if not _ENABLE_ATTESTATION_GOSSIP:
        return
    try:
        att_dict = attestation.to_dict()
        _mark_attestation_seen(_attestation_seen_key(att_dict))  # don't re-accept our own echo
        await propagate("push_attestation", {"attestation": att_dict}, db=_node.db)
    except Exception as e:
        logger.debug(f"attestation broadcast failed: {e}")


async def _add_remote_attestation(att_dict: dict, sender_node_id: Optional[str] = None) -> bool:
    """Receive hook (p2p pushAttestation): verify a gossiped attestation against the
    attester's pubkey from the validators table, add it to this node's attestation pool
    (if this node is a validator → the proposer will include it), and re-gossip it once
    (flood) to peers. Returns True if it was newly accepted (drives re-propagation).
    Best-effort + idempotent; never raises."""
    if not _ENABLE_ATTESTATION_GOSSIP:
        return False
    try:
        key = _attestation_seen_key(att_dict)
        if not _mark_attestation_seen(key):
            return False  # already gossiped through here

        from ..validator.attestation import Attestation
        from ..validator.finality import _validator_stakes_and_keys

        att = Attestation.from_dict(att_dict)

        # Verify the signature against the attester's registered pubkey (same path the
        # block-carried recorder uses). Drop unknown/invalid attesters.
        _stakes, keys = await _validator_stakes_and_keys(_node.db)
        pub = keys.get(att.validator_address)
        if not pub or not att.verify(pub):
            return False

        # Add to the local validator's pool so its next proposed block includes it.
        v = getattr(app.state, "validator", None)
        if v is not None and getattr(v, "manager", None) is not None:
            try:
                v.manager.attestation_pool.register_validator(att.validator_address, pub)
                await v.manager.attestation_pool.add_attestation(att, verify_signature=False)
            except Exception as e:
                logger.debug(f"pool add (remote attestation) skipped: {e}")

        # Re-gossip once to the rest of the mesh (flood), excluding the sender.
        asyncio.create_task(
            propagate(
                "push_attestation",
                {"attestation": att_dict},
                ignore_node_id=sender_node_id,
                db=_node.db,
            )
        )
        return True
    except Exception as e:
        logger.debug(f"remote attestation handling failed: {e}")
        return False


async def get_verified_sender(request: Request):
    """Verifies a request's signature with timestamp validation and reputation tracking"""
    # First check if peer is banned
    is_monitor_request = request.headers.get("x-monitor-request", "false").lower() == "true"

    # 2. Perform standard validation and banning checks for ALL requests.
    node_id = request.headers.get("x-node-id")
    if node_id and await _node.security.reputation_manager.is_banned(node_id):
        await _node.security.security_monitor.log_event(
            "banned_peer_attempt", {"peer_id": node_id, "endpoint": request.url.path}
        )
        return None

    peer_id = await _node.security.auth_validator.validate_request(request)

    if not peer_id:
        return None

    # 3. If it's a monitor request, stop here and return the ID.
    # We have successfully verified them, but we will not treat them as a peer.
    if is_monitor_request:
        if not node_id:  # A monitor must still identify itself
            return None
        # print(f"Verified monitor request from node {node_id}. Skipping peer list update.")
        return peer_id

    # 4. If it's a REGULAR peer request, proceed with the normal logic.
    peer_count = len(NodesManager.peers) if hasattr(NodesManager, "peers") else 0
    if peer_count >= MAX_PEERS:
        NodesManager.update_peer_last_seen(peer_id)
        return peer_id

    peer_url = request.headers.get("x-peer-url")
    pubkey = request.headers.get("x-public-key")

    is_unknown = NodesManager.get_peer(peer_id) is None

    # Only a node on our chain becomes a peer implicitly. Its signed x-denaro-genesis header
    # names its genesis block; anything else stays a one-off caller (the full identity check
    # happens in the handshake).
    if is_unknown and (
        _node.GENESIS_BLOCK_HASH is None
        or (request.headers.get("x-denaro-genesis") or "").lower()
        != _node.GENESIS_BLOCK_HASH.lower()
    ):
        return peer_id

    # An unknown caller on our chain is not admitted for one signed request: anyone can make a
    # key, and the peer table used to fill with whoever asked first (docs/KNOWN_ISSUES.md,
    # "Anyone could fill a node's peer table"). If it advertises a URL, this node dials it back
    # and handshakes: it becomes a peer only by proving its key at the address it gave, under
    # the table's rules (NodesManager.admit_peer).
    if is_unknown and pubkey and peer_url:
        if await validate_url_for_connection(peer_url):
            _dial_back_unknown(peer_url)
        else:
            logger.warning(f"Rejected peer URL {peer_url} due to security validation")
            await _node.security.reputation_manager.record_violation(
                peer_id, "invalid_url", severity=3
            )

    if peer_id in _FORMER_PEER_URLS:
        _dial_back_if_known(peer_id)

    NodesManager.update_peer_last_seen(peer_id)
    await _node.security.reputation_manager.record_good_behavior(peer_id)

    return peer_id


async def _peer_validator(node_id: Optional[str], proof: Any) -> Optional[str]:
    """The validator a handshaking peer proved it runs — ``proof`` is the validator's key over
    ``validator_peer_message(node_id)``, and the address is in the current validator set — or
    None."""
    if not node_id or not isinstance(proof, dict):
        return None
    address, signature = proof.get("address"), proof.get("signature")
    if not isinstance(address, str) or not isinstance(signature, str):
        return None
    try:
        from .. import chain_index
        from ..constants import SLOTS_PER_EPOCH
        from ..crypto.pq.dilithium import PQPublicKey, PQSignature, verify
        from ..rpc.modules.p2p import validator_peer_message
        from ..validator.epoch_state import state_at
        from ..validator.ffg import validator_key

        tip = await _node.db.get_next_block_id() - 1
        key = await validator_key(_node.db, address, tip + 1)
        slot = await chain_index.slot_at(_node.db, tip)
        if key is None or slot is None:
            return None
        members = await state_at(_node.db, int(slot) // SLOTS_PER_EPOCH, tip)
        if address.lower() not in {a.lower() for a in members}:
            return None
        if not verify(
            PQPublicKey.from_bytes(key),
            validator_peer_message(node_id),
            PQSignature.from_bytes(bytes.fromhex(signature)),
        ):
            return None
        return address
    except Exception as e:  # noqa: BLE001 — an unprovable claim is no claim
        logger.debug("validator proof of %s not accepted: %s", node_id, e)
        return None


async def _admit_handshaken_peer(node_id: Optional[str], meta: Any, validator_proof: Any) -> None:
    """A caller that completed our handshake (p2p_handshakeResponse) becomes a peer, under the
    peer table's rules: what it advertised, from where it called, and whether it proved it runs
    a validator."""
    if not node_id or not isinstance(meta, dict) or not meta.get("pubkey"):
        return
    url: Optional[str] = meta.get("url") or None
    if url and not await validate_url_for_connection(url):
        url = None
    is_public = url is not None and not await is_url_local(url)
    validator = await _peer_validator(node_id, validator_proof)
    if NodesManager.admit_peer(
        node_id,
        meta["pubkey"],
        url,
        is_public,
        source_ip=meta.get("ip"),
        validator=validator,
    ):
        logger.info(
            "Handshake: admitted peer %s%s",
            node_id,
            f" (validator {validator})" if validator else "",
        )


# Dial-backs to unknown callers' URLs: at most one per URL every _DIAL_BACK_SECONDS, and at most
# _DIAL_BACK_PENDING in flight, so a stream of fresh keys cannot make this node dial without end.
_DIAL_BACK_SECONDS = 600.0
_DIAL_BACK_PENDING = 8
_dial_backs: Dict[str, float] = {}
_dial_backs_in_flight: Set[str] = set()


def _dial_back_unknown(url: str) -> None:
    now = time.monotonic()
    if now - _dial_backs.get(url, float("-inf")) < _DIAL_BACK_SECONDS:
        return
    if len(_dial_backs_in_flight) >= _DIAL_BACK_PENDING:
        return
    _dial_backs[url] = now
    if len(_dial_backs) > 4096:  # (forget the oldest)
        for old in sorted(_dial_backs, key=_dial_backs.__getitem__)[:1024]:
            del _dial_backs[old]
    _dial_backs_in_flight.add(url)

    async def _go() -> None:
        try:
            await do_handshake_with_peer(url)
        except Exception as e:  # noqa: BLE001
            logger.debug("dial-back to %s failed: %s", url, e)
        finally:
            _dial_backs_in_flight.discard(url)

    asyncio.create_task(_go())


async def do_handshake_with_peer(peer_url_to_connect: str):
    """
    Performs a cryptographic handshake and state negotiation with a peer. This is the
    client-side of the handshake negotiation.
    """
    peer_id = None

    if not peer_url_to_connect or peer_url_to_connect == DENARO_SELF_URL:
        return

    if not await validate_url_for_connection(peer_url_to_connect):
        logger.warning(f"Skipping handshake with unsafe URL: {peer_url_to_connect}")
        return

    if NodesManager.self_is_public and await is_url_local(peer_url_to_connect):
        logger.debug(
            f"Public node skipping handshake attempt to private URL: {peer_url_to_connect}"
        )
        return

    logger.info(f"Attempting handshake with {peer_url_to_connect}")
    try:
        interface = NodeInterface(peer_url_to_connect, client=_node.http_client, db=_node.db)

        # 1. Get Challenge from peer (which includes their chain state), with a fresh nonce the
        # peer must sign: its identity is taken on proof, not on its word.
        client_nonce = os.urandom(32).hex()
        challenge_resp = await interface.handshake_challenge(client_nonce)
        if not (challenge_resp and challenge_resp.get("ok")):
            logger.warning(
                f"Handshake failed: Did not receive challenge from {peer_url_to_connect}."
            )
            return

        challenge_data = challenge_resp["result"]
        challenge = challenge_data.get("challenge")
        peer_id = challenge_data.get("node_id")
        peer_pubkey = challenge_data.get("pubkey")
        peer_is_public = challenge_data.get("is_public")
        peer_advertised_url = challenge_data.get("url")
        peer_height = challenge_data.get("height", -1)

        if not all([challenge, peer_id, peer_pubkey, peer_is_public is not None]):
            logger.warning(
                f"Handshake failed: Incomplete challenge data from {peer_url_to_connect}."
            )
            return

        from qrdx.rpc.modules.p2p import verify_handshake_proof

        proof_problem = verify_handshake_proof(client_nonce, challenge_data)
        if proof_problem:
            logger.warning(
                f"Handshake failed: {peer_url_to_connect} did not prove its identity "
                f"({proof_problem}); not adding it as a peer."
            )
            return

        # Same network and a compatible fork history, or no peering at all — checked before
        # the peer is stored, so a node of another network (or one that missed an upgrade)
        # never enters the peer list, the peer exchange, or a sync.
        if not await _identity._drop_if_incompatible(
            peer_id, challenge_data.get("network"), f"handshake with {peer_url_to_connect}"
        ):
            return

        # Add or update the peer in our manager AS SOON as we have their info.
        # This makes them "known" before we attempt any sync logic.
        url_to_store = (
            peer_advertised_url if peer_is_public and peer_advertised_url else peer_url_to_connect
        )
        if NodesManager.add_or_update_peer(peer_id, peer_pubkey, url_to_store, peer_is_public):
            logger.info(
                f"Handshake Phase 1: Discovered and added new {'public' if peer_is_public else 'private'} peer {peer_id}"
            )
        else:
            logger.debug(
                f"Handshake Phase 1: Discovered and updated {'public' if peer_is_public else 'private'} peer {peer_id}"
            )

        # 2. Respond to Challenge
        response_resp = await interface.handshake_response(challenge)

        if response_resp and response_resp.get("error") == "network_mismatch":
            logger.warning(
                f"[chain-spec] peer {peer_id} refused our handshake: "
                f"{response_resp.get('detail')}"
            )
            NodesManager.remove_peer(peer_id)
            return

        # 3. Handle the peer's response. Now we are guaranteed to find the peer in our manager.

        # Case A: Peer told us that WE are behind ('sync_required'). We must PULL.
        if response_resp and response_resp.get("error") == "sync_required":
            logger.info(f"Peer {peer_id} reported that WE are out of sync. Initiating PULL-sync.")
            await _sync._sync_blockchain(node_id=peer_id)
            return

        # Case B: Peer is behind and REQUESTED that we PUSH blocks to THEM ('sync_requested').
        if response_resp and response_resp.get("result") == "sync_requested":
            logger.info(f"Peer {peer_id} is behind and requested a PUSH-sync from us.")
            sync_details = response_resp.get("detail", {})
            start_block = sync_details.get("start_block")
            target_block = sync_details.get("target_block")
            if start_block is not None and target_block is not None:
                peer_info = NodesManager.get_peer(peer_id)
                if peer_info is None:
                    logger.warning(f"Cannot push-sync unknown peer {peer_id}.")
                    return
                peer_info["node_id"] = peer_id
                trigger_data = {"id": target_block}
                asyncio.create_task(
                    _sync._push_sync_to_peer(peer_info, start_block, _node.db, trigger_data)
                )
            return

        # Case C: Other failure
        if not (response_resp and response_resp.get("ok")):
            logger.warning(
                f"Handshake failed: Peer {peer_id} rejected our response: {response_resp}"
            )
            return

        # Case D: Handshake was successful and no sync instruction was given.
        logger.info(f"Handshake SUCCESS with peer {peer_id}.")

        # Fallback PULL trigger: If peer didn't respond with instructions but we see they are ahead.
        local_height = await _node.db.get_next_block_id() - 1
        if peer_height > local_height:
            logger.info(
                f"Peer {peer_id} has longer chain ({peer_height} > {local_height}). Initiating PULL-sync."
            )
            await _sync._sync_blockchain(node_id=peer_id)

        # 4. Perform peer exchange
        logger.debug(f"Performing peer exchange with {peer_id}")
        peers_resp = await interface.get_peers()
        if peers_resp and peers_resp.get("ok"):
            for discovered_peer in peers_resp["result"]["peers"]:
                if (
                    discovered_peer.get("url")
                    and discovered_peer["node_id"] not in NodesManager.peers
                    and discovered_peer["node_id"] != _node.self_node_id
                ):
                    if len(NodesManager.peers) < MAX_PEERS:
                        logger.info(
                            f"Found node {discovered_peer['node_id']} via exchange. Attempting handshake."
                        )
                        asyncio.create_task(do_handshake_with_peer(discovered_peer["url"]))

    except httpx.RequestError:
        peer_id = NodesManager.find_peer_by_url(peer_url_to_connect)
        if peer_id:
            await handle_unreachable_peer(peer_id, peer_url_to_connect, "handshake")
        else:
            # If we don't know them, we can't remove them, just log it.
            logger.warning(
                f"Failed to connect to unknown or new peer at {peer_url_to_connect} during handshake."
            )

    except Exception as e:
        logger.error(f"Error during handshake with {peer_url_to_connect}: {e}")
        traceback.print_exc()
        await _node.security.security_monitor.log_event(
            "handshake_failure", {"url": peer_url_to_connect, "error": str(e)}
        )


async def is_url_local(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        addr_info = await asyncio.get_event_loop().getaddrinfo(
            hostname, None, family=socket.AF_INET
        )
        ip_obj = ipaddress.ip_address(addr_info[0][4][0])
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except (socket.gaierror, ValueError, IndexError):
        return False


async def check_own_reachability():
    """
    A one-time startup task to determine if the node is publicly reachable.
    Tries multiple bootstrap nodes for verification.
    """
    await asyncio.sleep(3)  # Brief startup delay

    if not DENARO_SELF_URL:
        logger.info("DENARO_SELF_URL not set. Assuming this is a private node.")
        NodesManager.set_public_status(False)
        return

    if await is_url_local(DENARO_SELF_URL):
        logger.info(
            f"DENARO_SELF_URL is a local address ({DENARO_SELF_URL}). Operating as a private node."
        )
        _node.self_is_public = False
        NodesManager.set_public_status(False)
        return

    logger.info(f"Potential public URL is {DENARO_SELF_URL}. Asking bootstrap nodes to verify")

    # Try each bootstrap node until one can verify reachability
    for bootstrap_url in BOOTSTRAP_NODES:
        bootstrap_url = bootstrap_url.strip().rstrip("/")
        if not bootstrap_url:
            continue

        logger.debug(f"Checking reachability via {bootstrap_url}")
        bootstrap_interface = NodeInterface(bootstrap_url, client=_node.http_client, db=_node.db)

        try:
            is_reachable = await bootstrap_interface.check_peer_reachability(DENARO_SELF_URL)
            if is_reachable:
                _node.self_is_public = True
                NodesManager.set_public_status(True)
                logger.info(
                    f"SUCCESS: Node confirmed to be publicly reachable at {DENARO_SELF_URL}"
                )
                return
            else:
                logger.debug(f"Bootstrap node {bootstrap_url} reports us as not reachable")

        except httpx.RequestError:
            logger.debug(f"Bootstrap node at {bootstrap_url} is unreachable, trying next...")
            continue

        except Exception as e:
            logger.debug(f"Error checking reachability via {bootstrap_url}: {e}")
            continue

    # None of the bootstrap nodes could verify us
    _node.self_is_public = False
    NodesManager.set_public_status(False)
    logger.warning(
        f"DENARO_SELF_URL is set to {DENARO_SELF_URL}, but no bootstrap node could verify reachability. "
        f"Operating as a private node."
    )


# Peers dropped as unreachable: node id → the URL they were reached at (verified by the handshake
# it was learned in). A dropped peer that comes back connects in, and a peer that connects in is
# recorded without a URL (a private node advertises none), so this node could then neither push
# blocks to it nor resolve a fork with it. After a validator restarted on the 250 ms testnet the
# network stayed split. get_verified_sender dials the remembered URL back.
_FORMER_PEER_URLS: Dict[str, str] = {}
_FORMER_PEER_URLS_MAX = 256
_DIALBACK_INTERVAL_S = 5.0
_dialback_at: Dict[str, float] = {}


def _dial_back_if_known(peer_id: str) -> None:
    """Re-handshake with a returning peer at the URL it had before it was dropped (at most every
    _DIALBACK_INTERVAL_S per peer), which records that URL again."""
    url = _FORMER_PEER_URLS.get(peer_id)
    if not url or (NodesManager.get_peer(peer_id) or {}).get("url"):
        _FORMER_PEER_URLS.pop(peer_id, None)
        return
    now = time.monotonic()
    if now - _dialback_at.get(peer_id, 0.0) < _DIALBACK_INTERVAL_S:
        return
    _dialback_at[peer_id] = now

    async def dial() -> None:
        try:
            await do_handshake_with_peer(url)
        except Exception as e:
            logger.debug(f"dial-back to {peer_id[:16]} at {url} failed: {e}")
        if (NodesManager.get_peer(peer_id) or {}).get("url"):
            _FORMER_PEER_URLS.pop(peer_id, None)
            logger.info(f"Peer {peer_id[:16]} is back at {url}")

    asyncio.create_task(dial())


async def handle_unreachable_peer(peer_id: str, peer_url: Optional[str], context: str):
    """
    Centralized handler for when a peer is unreachable.
    This action is NOT punitive. It simply removes the peer from the active
    list for this session to prevent wasting resources. The peer can be re-discovered later:
    its URL is remembered, and dialled back when it next connects in.
    """
    logger.warning(
        f"Peer {peer_id} at {peer_url} is unreachable ({context}). Removing from active peer list."
    )
    if peer_url:
        if len(_FORMER_PEER_URLS) >= _FORMER_PEER_URLS_MAX:
            _FORMER_PEER_URLS.pop(next(iter(_FORMER_PEER_URLS)))
        _FORMER_PEER_URLS[peer_id] = peer_url
    NodesManager.remove_peer(peer_id)
