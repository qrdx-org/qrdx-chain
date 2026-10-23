"""
The exchange's proof tree (docs/STATE_PROOFS.md): every entry of the in-memory exchange state —
nothing provable only by trusting a node — under one root, the **exchange tree root**, bound into
the signed state root beside the database tree's (``smt.combine``).

Two levels:

* each committed collection keeps its own tree (qrdx/exchange/commitment.py), and so does each
  order book's set of price levels (qrdx/exchange/orderbook.py) — kept where their digests are,
  from the same changes, travelling with every copy and undo of the state;
* the top tree has one leaf per non-empty collection or book, holding its tree's root, and one
  per **part** — a market's, a pool's or a book's own fields, the oracle, the clearinghouse's
  and the components' counters — holding the canonical JSON its commitment covers.

Leaves of the top tree::

    collection  key_of(0x11 | path)   payload 0x11 | root (32) | path
    book levels key_of(0x13 | name)   payload 0x13 | root (32) | name
    part        key_of(0x12 | name)   payload 0x12 | name | 0x00 | canonical JSON

A collection's path is its tag (``ch.accounts``), suffixed with its market, pool or pair when
there is one per market, pool or book (``ch.orders:BTC-QRDX-PERP``). An entry's key in its
collection's tree is ``key_of(0x20 | canonical(key))``; its payload ``canonical([key, encoded])``.
A price level's key is ``key_of(0x21 | side price)`` (``b65000``); its payload the level's orders.

The top tree is kept incrementally: each fold computes every leaf's payload (cheap: collection
roots are kept; a pool's or book's fields are re-encoded only when its digest changed) and
updates the leaves whose payload differs from what the tree holds — a comparison by content, so
it cannot go stale whatever the state was restored from.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from ..crypto import smt
from .commitment import CommittedDict, CommittedSet, canonical_bytes, tracked, tree_key

COLLECTION, PART, BOOK = b"\x11", b"\x12", b"\x13"
HISTORY = 256  # heights whose exchange trees a node keeps for proofs


def collection_key(path: str) -> bytes:
    return smt.key_of(COLLECTION + path.encode())


def book_key(name: str) -> bytes:
    return smt.key_of(BOOK + name.encode())


def part_key(name: str) -> bytes:
    return smt.key_of(PART + name.encode())


def part_payload(name: str, value: Any) -> bytes:
    return PART + name.encode() + b"\x00" + canonical_bytes(value)


def _components(mgr) -> List[Any]:
    return [
        mgr,
        mgr.clearinghouse,
        mgr.trading,
        mgr.tokens,
        mgr.nfts,
        mgr.governance,
        mgr.authority,
        mgr.qns,
        mgr.bridge,
    ]


def collections(mgr) -> List[Tuple[str, Any]]:
    """Every committed collection of the exchange, by path."""
    out: Dict[str, Any] = {}
    for obj in _components(mgr):
        for value in vars(obj).values():
            if isinstance(value, (CommittedDict, CommittedSet)):
                out[value._tag] = value
    ch = mgr.clearinghouse
    for mid in sorted(ch.markets):
        m = ch.markets[mid]
        for coll in (tracked(m.orders), tracked(m.triggers)):
            out[f"{coll._tag}:{mid}"] = coll
        out[f"book.nonces:perp:{mid}"] = m.book._nonces()
    for pid in sorted(mgr.pool_manager._pools):
        st = mgr.pool_manager._pools[pid].state
        for coll in (tracked(st.ticks), tracked(st.positions)):
            out[f"{coll._tag}:{pid}"] = coll
    for pair in sorted(mgr._order_books):
        out[f"book.nonces:{pair}"] = mgr._order_books[pair]._nonces()
    return sorted(out.items())


def books(mgr) -> List[Tuple[str, Any]]:
    """Every order book, by name: the spot books by pair, the perps books by market."""
    out = [(f"spot:{pair}", mgr._order_books[pair]) for pair in sorted(mgr._order_books)]
    ch = mgr.clearinghouse
    out += [(f"perp:{mid}", ch.markets[mid].book) for mid in sorted(ch.markets)]
    return out


def parts(mgr, cache: Dict[str, Tuple[bytes, bytes]]) -> Dict[str, bytes]:
    """Every part's payload. ``cache``: name → (the object's digest, payload), so a pool or a
    book is re-encoded only when its digest changed (a comparison by content)."""
    from .clearinghouse import _market_header

    out: Dict[str, bytes] = {}

    def cached(name: str, digest: bytes, value) -> None:
        hit = cache.get(name)
        if hit is None or hit[0] != digest:
            hit = (digest, part_payload(name, value()))
            cache[name] = hit
        out[name] = hit[1]

    ch = mgr.clearinghouse
    for mid in sorted(ch.markets):
        out[f"market:{mid}"] = part_payload(f"market:{mid}", _market_header(ch.markets[mid]))
    for pid in sorted(mgr.pool_manager._pools):
        pool = mgr.pool_manager._pools[pid]
        cached(f"pool:{pid}", pool.cached_digest(), pool.header)
    for name, book in books(mgr):
        cached(f"bookhdr:{name}", book.cached_digest(), book.header)
    scalars = {
        "clearinghouse": [
            str(ch.vault_total_shares),
            str(ch.holder_balance),
            ch.trigger_seq,
        ],
        "governance": [mgr.governance.next_id, mgr.governance.master_frozen_at],
        "trading": [mgr.trading.seq],
        "authority": [mgr.authority.seq],
        "spot_oracles": {
            pair: [str(o.latest_price or 0), o.observation_count]
            for pair, o in sorted(mgr._oracles.items())
        },
        "oracle": mgr.oracle_state(),
    }
    for name, value in scalars.items():
        out[name] = part_payload(name, value)
    for name in list(cache):
        if name not in out:
            del cache[name]
    return out


def leaves(mgr, cache) -> Tuple[Dict[bytes, bytes], Dict[str, Optional[smt.MNode]]]:
    """The top tree's leaves (key → payload), and each collection's and book's tree by name."""
    out: Dict[bytes, bytes] = {}
    inner: Dict[str, Optional[smt.MNode]] = {}
    for path, coll in collections(mgr):
        t = coll.tree
        inner[path] = t
        if t is not None:
            out[collection_key(path)] = COLLECTION + t.hash + path.encode()
    for name, book in books(mgr):
        t = book.level_tree
        inner[name] = t
        if t is not None:
            out[book_key(name)] = BOOK + t.hash + name.encode()
    for name, payload in parts(mgr, cache).items():
        out[part_key(name)] = payload
    return out, inner


def fold(mgr, height: Optional[int] = None) -> bytes:
    """The exchange tree root now (and, given the block's ``height``, remembered for proofs)."""
    state = mgr.__dict__.setdefault(
        "_proof_tree", {"leaves": {}, "root": None, "parts": {}, "history": OrderedDict()}
    )
    now, inner = leaves(mgr, state["parts"])
    held: Dict[bytes, bytes] = state["leaves"]
    changes: List[smt.Change] = [(k, v) for k, v in now.items() if held.get(k) != v]
    changes += [(k, None) for k in held if k not in now]
    if changes:
        state["root"] = smt.m_update(state["root"], sorted(changes))
        state["leaves"] = now
    root = smt.m_root(state["root"])
    if height is not None:
        history: OrderedDict = state["history"]
        history[int(height)] = (state["root"], inner)
        history.move_to_end(int(height))
        while len(history) > HISTORY:
            history.popitem(last=False)
    return root


def _at(mgr, height: int):
    state = mgr.__dict__.get("_proof_tree")
    if state is None or int(height) not in state["history"]:
        raise ValueError(f"no exchange tree kept for height {height} (only the last {HISTORY})")
    return state["history"][int(height)]


def prove(mgr, height: int, path: str, key: Any) -> Dict[str, Any]:
    """A proof of one entry of the collection (or book, ``spot:…``/``perp:…``, with ``key`` a
    level such as ``"b65000"``) at ``path`` — or of its absence — against the exchange tree root
    of ``height``."""
    top, inner = _at(mgr, height)
    is_book = path.startswith(("spot:", "perp:"))
    if is_book:
        from .orderbook import OrderBook

        k = OrderBook.level_key(str(key)[:1], str(key)[1:])
        outer_key, kind = book_key(path), BOOK
    else:
        k = tree_key(key)
        outer_key, kind = collection_key(path), COLLECTION
    tree = inner.get(path)
    siblings, terminal, payload = smt.m_prove(tree, k)
    member = terminal is not None and terminal[0] == k
    osiblings, oterminal, _opayload = smt.m_prove(top, outer_key)
    held = tree is not None
    return {
        "domain": "exchange",
        "height": int(height),
        "path": path,
        "kind": kind.hex(),
        "inner_key": k.hex(),
        "entry": payload.hex() if member and payload is not None else None,
        "siblings": [s.hex() for s in siblings],
        "terminal": (
            None
            if terminal is None or member
            else {"key": terminal[0].hex(), "value_hash": terminal[1].hex()}
        ),
        "outer_siblings": [s.hex() for s in osiblings],
        "outer_terminal": (
            None
            if oterminal is None or (held and oterminal[0] == outer_key)
            else {"key": oterminal[0].hex(), "value_hash": oterminal[1].hex()}
        ),
        "exchange_tree_root": smt.m_root(top).hex(),
    }


def prove_part(mgr, height: int, name: str) -> Dict[str, Any]:
    top, _inner = _at(mgr, height)
    k = part_key(name)
    siblings, terminal, payload = smt.m_prove(top, k)
    member = terminal is not None and terminal[0] == k
    return {
        "domain": "exchange_part",
        "height": int(height),
        "name": name,
        "entry": payload.hex() if member and payload is not None else None,
        "outer_siblings": [s.hex() for s in siblings],
        "outer_terminal": (
            None
            if terminal is None or member
            else {"key": terminal[0].hex(), "value_hash": terminal[1].hex()}
        ),
        "exchange_tree_root": smt.m_root(top).hex(),
    }


def _terminal(t: Optional[Dict[str, str]]) -> Optional[Tuple[bytes, bytes]]:
    return (bytes.fromhex(t["key"]), bytes.fromhex(t["value_hash"])) if t else None


def exchange_root_of(proof: Dict[str, Any]) -> Optional[bytes]:
    """The exchange tree root an exchange proof folds to (None if it is malformed)."""
    if proof["domain"] == "exchange_part":
        name = str(proof["name"])
        entry = bytes.fromhex(proof["entry"]) if proof.get("entry") else None
        if entry is not None and not entry.startswith(PART + name.encode() + b"\x00"):
            return None
        return smt.fold(
            part_key(name),
            smt.value_hash(entry) if entry is not None else None,
            [bytes.fromhex(s) for s in proof["outer_siblings"]],
            _terminal(proof.get("outer_terminal")),
        )
    kind = bytes.fromhex(proof["kind"])
    path = str(proof["path"])
    k = bytes.fromhex(proof["inner_key"])
    entry = bytes.fromhex(proof["entry"]) if proof.get("entry") else None
    inner_root = smt.fold(
        k,
        smt.value_hash(entry) if entry is not None else None,
        [bytes.fromhex(s) for s in proof["siblings"]],
        _terminal(proof.get("terminal")),
    )
    if inner_root is None or kind not in (COLLECTION, BOOK):
        return None
    outer_key = (collection_key if kind == COLLECTION else book_key)(path)
    leaf = None if inner_root == smt.EMPTY else kind + inner_root + path.encode()
    return smt.fold(
        outer_key,
        smt.value_hash(leaf) if leaf is not None else None,
        [bytes.fromhex(s) for s in proof["outer_siblings"]],
        _terminal(proof.get("outer_terminal")),
    )
