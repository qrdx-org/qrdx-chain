"""
``verifyExternalProof`` (0x…0201): prove an account — and a storage slot of it — on a bridged EVM
chain, against a finalized head QRDX's validators attested (docs/BRIDGE.md "Chain heads"). A
contract can then act on another chain's state: a balance, a lockbox's record, an oracle's slot.

Input (packed)::

    chain id        4   the source chain (as the bridge configures it)
    height          8   an attested head of it (one of the last 64)
    address        20   the account
    account proof   ·   node count 2 · nodes (length 4 · RLP node), from the state root down —
                        what ``eth_getProof`` returns as ``accountProof``
    slot           32   optional: a storage slot of the account …
    storage proof   ·   … and its proof from the account's storage root (``storageProof``)

Output: ``0x00`` if the proof does not hold (or the head is not attested, or the input is
malformed); else ``0x01`` · nonce (32) · balance (32) · storage root (32) · code hash (32), and
with a slot · its value (32). An absent account or slot is proven too: zeros. It never reverts.

Merkle-Patricia proofs are checked by ``trie.HexaryTrie.get_from_proof`` against the attested
state root; the head is read from the exchange's consensus state at that point of the block, so
the result is the same on every node.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

GAS_BASE = 200_000
GAS_PER_NODE = 5_000
MAX_NODES = 64
MAX_NODE_SIZE = 1 << 16
EMPTY_TRIE = bytes.fromhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
EMPTY_CODE = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")


def _nodes(data: bytes, at: int) -> Tuple[List[bytes], int]:
    if at + 2 > len(data):
        raise ValueError("short input")
    count = int.from_bytes(data[at : at + 2], "big")
    at += 2
    if count > MAX_NODES:
        raise ValueError("too many nodes")
    out = []
    for _ in range(count):
        if at + 4 > len(data):
            raise ValueError("short input")
        n = int.from_bytes(data[at : at + 4], "big")
        at += 4
        if n > MAX_NODE_SIZE or at + n > len(data):
            raise ValueError("bad node")
        out.append(data[at : at + n])
        at += n
    return out, at


def parse(data: bytes):
    """(chain, height, address, account nodes, slot or None, storage nodes)."""
    if len(data) < 32:
        raise ValueError("short input")
    chain = int.from_bytes(data[:4], "big")
    height = int.from_bytes(data[4:12], "big")
    address = data[12:32]
    account_nodes, at = _nodes(data, 32)
    slot: Optional[bytes] = None
    storage_nodes: List[bytes] = []
    if at < len(data):
        if at + 32 > len(data):
            raise ValueError("short slot")
        slot = data[at : at + 32]
        storage_nodes, at = _nodes(data, at + 32)
    if at != len(data):
        raise ValueError("trailing input")
    return chain, height, address, account_nodes, slot, storage_nodes


def _get(root: bytes, key: bytes, nodes: List[bytes]) -> bytes:
    import rlp
    from eth_utils import keccak
    from trie import HexaryTrie

    return HexaryTrie.get_from_proof(root, keccak(key), tuple(rlp.decode(n) for n in nodes))


def verify(
    state_root: bytes, address: bytes, account_nodes, slot, storage_nodes
) -> Optional[bytes]:
    """The output for a well-formed proof against ``state_root`` (None if it does not hold)."""
    import rlp

    try:
        raw = _get(state_root, address, account_nodes)
        if raw:
            nonce, balance, storage_root, code_hash = rlp.decode(raw)
            fields = (
                int.from_bytes(nonce, "big").to_bytes(32, "big")
                + int.from_bytes(balance, "big").to_bytes(32, "big")
                + bytes(storage_root).rjust(32, b"\x00")
                + bytes(code_hash).rjust(32, b"\x00")
            )
        else:  # proven absent
            storage_root = EMPTY_TRIE
            fields = bytes(64) + EMPTY_TRIE + EMPTY_CODE
        out = b"\x01" + fields
        if slot is not None:
            value = _get(bytes(storage_root), slot, storage_nodes) if storage_nodes else b""
            if not storage_nodes and bytes(storage_root) != EMPTY_TRIE:
                return None  # a slot of a non-empty storage needs its proof
            out += (
                int.from_bytes(rlp.decode(value), "big").to_bytes(32, "big") if value else bytes(32)
            )
        return out
    except Exception:  # noqa: BLE001 — a malformed or forged proof
        return None


def external_proof_precompile(computation):
    from ..exchange.state_manager import ExchangeStateManager

    data = bytes(computation.msg.data_as_bytes)
    try:
        chain, height, address, account_nodes, slot, storage_nodes = parse(data)
    except ValueError:
        computation.consume_gas(GAS_BASE, reason="verifyExternalProof")
        computation.output = b"\x00"
        return computation
    nodes = len(account_nodes) + len(storage_nodes)
    computation.consume_gas(GAS_BASE + GAS_PER_NODE * nodes, reason="verifyExternalProof")
    head = ExchangeStateManager.get_instance().bridge.head_at(chain, height)
    out = None
    if head is not None:
        out = verify(
            bytes.fromhex(head.state_root[2:]), address, account_nodes, slot, storage_nodes
        )
    computation.output = out if out is not None else b"\x00"
    return computation


def encode(chain: int, height: int, address: bytes, account_proof, slot=None, storage_proof=()):
    """The precompile's input from ``eth_getProof``-style proofs (lists of RLP node bytes)."""

    def nodes(proof):
        out = len(proof).to_bytes(2, "big")
        for n in proof:
            n = bytes.fromhex(n[2:]) if isinstance(n, str) else bytes(n)
            out += len(n).to_bytes(4, "big") + n
        return out

    data = int(chain).to_bytes(4, "big") + int(height).to_bytes(8, "big") + bytes(address)
    data += nodes(account_proof)
    if slot is not None:
        data += bytes(slot).rjust(32, b"\x00") + nodes(storage_proof)
    return data
