"""
A compressed sparse Merkle tree over 256-bit keys (docs/CONSENSUS_ROADMAP.md 8,
docs/STATE_PROOFS.md).

The state roots are LtHash accumulators: cheap to update, but they cannot prove that one entry is
in them. This tree can. Its shape is a function of its entries alone:

* an empty subtree is ``EMPTY`` (32 zero bytes);
* a subtree holding exactly one entry is that entry's leaf, ``H(LEAF | key | value)``, at the
  subtree's top;
* a subtree holding two or more is ``H(NODE | left | right)``.

So an update or a proof costs about log2(entries) hashes, not 256. A proof of ``key`` is the
siblings from the root down to where the walk along the key's bits stops — at the key's leaf
(membership), at another key's leaf, or at an empty subtree (non-membership) — and ``verify``
folds them back up.

Nodes are stored under ``version:depth:path`` (``path``: the first ``depth`` bits of the keys
below, as hex). A version writes only new keys, so a root of an earlier version keeps every node
it reaches until the nodes it replaced (``stale``) are pruned.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

EMPTY = bytes(32)
_LEAF = b"qrdx/smt/leaf/v1\x00"
_NODE = b"qrdx/smt/node/v1\x00"
_VALUE = b"qrdx/smt/value/v1\x00"
_KEY = b"qrdx/smt/key/v1\x00"


def _h(*parts: bytes) -> bytes:
    return hashlib.blake2b(b"".join(parts), digest_size=32).digest()


def leaf_hash(key: bytes, value: bytes) -> bytes:
    return _h(_LEAF, key, value)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(_NODE, left, right)


def value_hash(payload: bytes) -> bytes:
    return _h(_VALUE, payload)


def key_of(identity: bytes) -> bytes:
    return _h(_KEY, identity)


def bit(key: bytes, i: int) -> int:
    return (key[i >> 3] >> (7 - (i & 7))) & 1


@dataclass(frozen=True)
class Ref:
    """A stored node: its hash, where it is stored, and whether it is a leaf."""

    hash: bytes
    nkey: str
    leaf: bool

    def encode(self) -> bytes:
        k = self.nkey.encode()
        return (b"\x02" if self.leaf else b"\x01") + self.hash + bytes([len(k)]) + k

    @staticmethod
    def decode(data: bytes, at: int = 0) -> Tuple[Optional["Ref"], int]:
        flag = data[at]
        if flag == 0:
            return None, at + 1
        h = data[at + 1 : at + 33]
        n = data[at + 33]
        nkey = data[at + 34 : at + 34 + n].decode()
        return Ref(h, nkey, flag == 2), at + 34 + n


def encode_ref(ref: Optional[Ref]) -> bytes:
    return b"\x00" if ref is None else ref.encode()


@dataclass(frozen=True)
class Node:
    key: bytes = b""  # a leaf: its key and its entry (the payload ``value_hash`` hashes)
    payload: bytes = b""
    left: Optional[Ref] = None  # an internal node: its children (None: empty)
    right: Optional[Ref] = None

    @property
    def is_leaf(self) -> bool:
        return bool(self.key)

    @property
    def value(self) -> bytes:
        return value_hash(self.payload)

    def encode(self) -> bytes:
        if self.is_leaf:
            return b"L" + self.key + self.payload
        return b"I" + encode_ref(self.left) + encode_ref(self.right)

    @staticmethod
    def decode(data: bytes) -> "Node":
        if data[:1] == b"L":
            return Node(key=data[1:33], payload=bytes(data[33:]))
        left, at = Ref.decode(data, 1)
        right, _ = Ref.decode(data, at)
        return Node(left=left, right=right)


Loader = Callable[[str], Awaitable[Optional[bytes]]]
Change = Tuple[bytes, Optional[bytes]]  # (key, entry payload), None: removed


class Tree:
    """One version's update of the tree, over a node store read through ``load``. The nodes it
    writes collect in ``writes`` (nkey → bytes); the stored nodes it replaced, in ``stale``."""

    def __init__(self, load: Loader, version: int) -> None:
        self.load = load
        self.version = version
        self.writes: Dict[str, bytes] = {}
        self.stale: List[str] = []

    async def node(self, ref: Ref) -> Node:
        data = self.writes.get(ref.nkey)
        if data is None:
            data = await self.load(ref.nkey)
        if data is None:
            raise KeyError(f"state tree node {ref.nkey} is missing (pruned?)")
        return Node.decode(data)

    def _nkey(self, depth: int, path: int) -> str:
        return f"{self.version}:{depth}:{path:x}"

    def _put(self, depth: int, path: int, node: Node, h: bytes) -> Ref:
        nkey = self._nkey(depth, path)
        self.writes[nkey] = node.encode()
        return Ref(h, nkey, node.is_leaf)

    def _leaf(self, depth: int, path: int, key: bytes, payload: bytes) -> Ref:
        node = Node(key=key, payload=payload)
        return self._put(depth, path, node, leaf_hash(key, node.value))

    def _discard(self, ref: Ref) -> None:
        if ref.nkey in self.writes:  # written by this update, then replaced by it
            del self.writes[ref.nkey]
        else:
            self.stale.append(ref.nkey)

    def _build(self, depth: int, path: int, live: Sequence[Change]) -> Optional[Ref]:
        """The subtree of ``live`` (sorted, distinct keys, all present) below (depth, path)."""
        if not live:
            return None
        if len(live) == 1:
            key, value = live[0]
            assert value is not None
            return self._leaf(depth, path, key, value)
        left = [c for c in live if not bit(c[0], depth)]
        right = [c for c in live if bit(c[0], depth)]
        lref = self._build(depth + 1, path << 1, left)
        rref = self._build(depth + 1, (path << 1) | 1, right)
        return self._internal(depth, path, lref, rref)

    def _internal(
        self, depth: int, path: int, lref: Optional[Ref], rref: Optional[Ref]
    ) -> Optional[Ref]:
        h = node_hash(lref.hash if lref else EMPTY, rref.hash if rref else EMPTY)
        return self._put(depth, path, Node(left=lref, right=rref), h)

    async def update(
        self, ref: Optional[Ref], changes: Sequence[Change], depth: int = 0, path: int = 0
    ) -> Optional[Ref]:
        """The subtree at (depth, path), now ``ref``, with ``changes`` (sorted by key, distinct
        keys) applied. Returns its new ref (None: empty)."""
        if not changes:
            return ref
        if ref is None:
            return self._build(depth, path, [c for c in changes if c[1] is not None])
        node = await self.node(ref)
        if node.is_leaf:
            merged: Dict[bytes, Optional[bytes]] = {node.key: node.payload}
            merged.update(changes)
            live = sorted((k, v) for k, v in merged.items() if v is not None)
            if live == [(node.key, node.payload)]:
                return ref  # unchanged
            self._discard(ref)
            return self._build(depth, path, live)
        left = [c for c in changes if not bit(c[0], depth)]
        right = [c for c in changes if bit(c[0], depth)]
        lref = await self.update(node.left, left, depth + 1, path << 1) if left else node.left
        rref = (
            await self.update(node.right, right, depth + 1, (path << 1) | 1)
            if right
            else node.right
        )
        if lref == node.left and rref == node.right:
            return ref
        self._discard(ref)
        if lref is None and rref is None:
            return None
        lone = rref if lref is None else lref if rref is None else None
        if lone is not None and lone.leaf:  # one entry left below: its leaf rises to here
            leaf = await self.node(lone)
            self._discard(lone)
            return self._leaf(depth, path, leaf.key, leaf.payload)
        return self._internal(depth, path, lref, rref)

    async def prove(
        self, root: Optional[Ref], key: bytes
    ) -> Tuple[List[bytes], Optional[Tuple[bytes, bytes]], Optional[bytes]]:
        """(siblings from the root down, the leaf the walk ends at as (key, value hash) — None
        at an empty subtree — and that leaf's payload)."""
        siblings: List[bytes] = []
        ref, depth = root, 0
        while ref is not None:
            node = await self.node(ref)
            if node.is_leaf:
                return siblings, (node.key, node.value), node.payload
            nxt, other = (node.right, node.left) if bit(key, depth) else (node.left, node.right)
            siblings.append(other.hash if other is not None else EMPTY)
            ref, depth = nxt, depth + 1
        return siblings, None, None


def root_hash(ref: Optional[Ref]) -> bytes:
    return ref.hash if ref is not None else EMPTY


def fold(
    key: bytes,
    value: Optional[bytes],
    siblings: Sequence[bytes],
    terminal: Optional[Tuple[bytes, bytes]],
) -> Optional[bytes]:
    """The root of the tree in which this path shows ``key`` → ``value`` (``value`` None: no
    entry for ``key``) — None if the path is malformed. ``siblings`` and ``terminal`` as
    ``Tree.prove`` returns them (for a held entry ``terminal`` may be None or the entry)."""
    depth = len(siblings)
    if depth > 256 or len(key) != 32 or any(len(s) != 32 for s in siblings):
        return None
    if value is not None:
        if terminal is not None and terminal != (key, value):
            return None
        acc = leaf_hash(key, value)
    elif terminal is None:
        acc = EMPTY
    else:
        other, other_value = terminal
        if other == key or any(bit(other, i) != bit(key, i) for i in range(depth)):
            return None  # it must be another key's leaf, on this key's path
        acc = leaf_hash(other, other_value)
    for i in reversed(range(depth)):
        s = siblings[i]
        acc = node_hash(s, acc) if bit(key, i) else node_hash(acc, s)
    return acc


def verify(
    root: bytes,
    key: bytes,
    value: Optional[bytes],
    siblings: Sequence[bytes],
    terminal: Optional[Tuple[bytes, bytes]],
) -> bool:
    """Does the tree with root ``root`` hold ``key`` → ``value`` (``value`` None: hold no
    entry for ``key``)? ``siblings`` and ``terminal`` as ``Tree.prove`` returns them."""
    if value is not None and terminal != (key, value):
        return False
    return fold(key, value, siblings, terminal) == root


# ── in memory: a persistent tree of immutable nodes ──────────────────────────────────────
#
# For state that lives in memory and is snapshotted by deep copy (the exchange): nodes are
# immutable and shared, so a copy of a tree costs nothing and an update allocates only the
# path it changes; a node no root reaches is freed by Python. Same shape and hashes as the
# stored tree above (``verify`` checks both).


class MNode:
    """A leaf (``key``, ``payload``) or an internal node (``left``, ``right``); immutable."""

    __slots__ = ("hash", "key", "payload", "left", "right")

    def __init__(
        self,
        h: bytes,
        key: bytes = b"",
        payload: bytes = b"",
        left: Optional["MNode"] = None,
        right: Optional["MNode"] = None,
    ) -> None:
        self.hash, self.key, self.payload, self.left, self.right = h, key, payload, left, right

    @property
    def is_leaf(self) -> bool:
        return bool(self.key)

    def __copy__(self) -> "MNode":
        return self

    def __deepcopy__(self, memo) -> "MNode":
        return self

    def __reduce__(self):
        return (MNode, (self.hash, self.key, self.payload, self.left, self.right))


def m_leaf(key: bytes, payload: bytes) -> MNode:
    return MNode(leaf_hash(key, value_hash(payload)), key, payload)


def m_internal(left: Optional[MNode], right: Optional[MNode]) -> MNode:
    h = node_hash(left.hash if left else EMPTY, right.hash if right else EMPTY)
    return MNode(h, left=left, right=right)


def m_build(live: Sequence[Change], depth: int = 0) -> Optional[MNode]:
    """The tree of ``live`` (sorted, distinct keys, all present) below ``depth``."""
    if not live:
        return None
    if len(live) == 1:
        key, payload = live[0]
        assert payload is not None
        return m_leaf(key, payload)
    left = [c for c in live if not bit(c[0], depth)]
    right = [c for c in live if bit(c[0], depth)]
    return m_internal(m_build(left, depth + 1), m_build(right, depth + 1))


def m_update(node: Optional[MNode], changes: Sequence[Change], depth: int = 0) -> Optional[MNode]:
    """``node``'s subtree with ``changes`` (sorted by key, distinct) applied; the original is
    untouched."""
    if not changes:
        return node
    if node is None:
        return m_build([c for c in changes if c[1] is not None], depth)
    if node.is_leaf:
        merged: Dict[bytes, Optional[bytes]] = {node.key: node.payload}
        merged.update(changes)
        live = sorted((k, v) for k, v in merged.items() if v is not None)
        if live == [(node.key, node.payload)]:
            return node
        return m_build(live, depth)
    left = [c for c in changes if not bit(c[0], depth)]
    right = [c for c in changes if bit(c[0], depth)]
    lnode = m_update(node.left, left, depth + 1) if left else node.left
    rnode = m_update(node.right, right, depth + 1) if right else node.right
    if lnode is node.left and rnode is node.right:
        return node
    if lnode is None and rnode is None:
        return None
    lone = rnode if lnode is None else lnode if rnode is None else None
    if lone is not None and lone.is_leaf:  # one entry left below: its leaf rises
        return lone
    return m_internal(lnode, rnode)


def m_prove(
    root: Optional[MNode], key: bytes
) -> Tuple[List[bytes], Optional[Tuple[bytes, bytes]], Optional[bytes]]:
    """As ``Tree.prove``: (siblings, the leaf the walk ends at, its payload)."""
    siblings: List[bytes] = []
    node, depth = root, 0
    while node is not None:
        if node.is_leaf:
            return siblings, (node.key, value_hash(node.payload)), node.payload
        nxt, other = (node.right, node.left) if bit(key, depth) else (node.left, node.right)
        siblings.append(other.hash if other is not None else EMPTY)
        node, depth = nxt, depth + 1
    return siblings, None, None


def m_root(node: Optional[MNode]) -> bytes:
    return node.hash if node is not None else EMPTY


def combine(db_root: bytes, exchange_root: bytes) -> bytes:
    """The proof root: the database tree's root and the exchange tree's, in that order."""
    return _h(b"qrdx/proof-root/v1\x00", db_root, exchange_root)
