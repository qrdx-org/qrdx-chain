"""
The state proof precompile (docs/STATE_PROOFS.md, docs/CONSENSUS_ROADMAP.md 8).

At ``STATE_PROOF_ADDRESS`` (0x…0300): verify that an entry of QRDX state — an account, a contract
storage slot, a token balance, or any entry of the exchange (a perps account, a QNS record, a
resting order's price level, a market's fields) — held a value, or held none, at an earlier block
of this chain, against that block's signed state root. A contract can then act on state it
cannot read directly.

Input (packed, no padding)::

    height            32   the block whose state is proven (1 ≤ height < this block)
    utxo root         32   the domain roots that block's unified root was made of
    account root      64   (``state_getProof`` returns them)
    exchange root     64
    token root        64
    database tree     32   the two proof trees' roots (combined into the proof root)
    exchange tree     32
    domain            1    0: a database entry; 1: an exchange entry; 2: an exchange part

    domain 0:  entry length 32 · entry (the payload; or only type · identity to prove absence)
               · path
    domain 1:  kind 1 (0x11 collection, 0x13 book levels) · name length 32 · name
               · entry key 32 · entry length 32 · entry (empty: absence) · path · outer path
    domain 2:  entry length 32 · entry (0x12 · name · 0x00 · JSON) · outer path

    path:      sibling count 32 · siblings (32 each, from the root down) · terminal 1 (0, or 1
               then another key's leaf: key 32 · value hash 32)

Output: 32 bytes, 1 if the proof holds, 0 if not (a malformed input included). It never
reverts, so a caller can branch on the result.

The ancestor's root is read from this chain's stored block — the same on every node — and the
height must be below the block being executed, so the result is a function of the chain.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..crypto import smt
from ..crypto.hashing import unified_state_root

GAS_BASE = 50_000  # the ancestor block's root is read from its stored body
GAS_PER_SIBLING = 300

_ROOTS = (
    ("utxo", 32),
    ("account", 64),
    ("exchange", 64),
    ("token", 64),
    ("dtree", 32),
    ("xtree", 32),
)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.at = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.at + n > len(self.data):
            raise ValueError("short input")
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def word(self) -> int:
        return int.from_bytes(self.take(32), "big")

    def blob(self, limit: int = 4096) -> bytes:
        n = self.word()
        if n > limit:
            raise ValueError("too long")
        return self.take(n)

    def path(self):
        count = self.word()
        if count > 256:
            raise ValueError("too many siblings")
        siblings = [self.take(32) for _ in range(count)]
        flag = self.take(1)[0]
        if flag == 0:
            return siblings, None
        if flag != 1:
            raise ValueError("bad terminal flag")
        return siblings, (self.take(32), self.take(32))


def parse(data: bytes) -> Dict[str, Any]:
    """The packed input as a dict; ValueError if malformed."""
    r = _Reader(data)
    out: Dict[str, Any] = {"height": r.word()}
    out["roots"] = {name: r.take(n).hex() for name, n in _ROOTS}
    domain = r.take(1)[0]
    out["domain"] = domain
    if domain == 0:
        out["entry"] = r.blob(256)
        out["siblings"], out["terminal"] = r.path()
    elif domain == 1:
        out["kind"] = r.take(1)
        out["name"] = r.blob(256).decode()
        out["inner_key"] = r.take(32)
        out["entry"] = r.blob()
        out["siblings"], out["terminal"] = r.path()
        out["outer_siblings"], out["outer_terminal"] = r.path()
    elif domain == 2:
        out["entry"] = r.blob()
        out["outer_siblings"], out["outer_terminal"] = r.path()
    else:
        raise ValueError("unknown domain")
    if r.at != len(data):
        raise ValueError("trailing input")
    out["siblings_total"] = len(out.get("siblings", ())) + len(out.get("outer_siblings", ()))
    return out


def _database_root(p: Dict[str, Any]) -> Optional[bytes]:
    from ..state_proofs import _IDENTITY_LENGTH

    entry = p["entry"]
    n = _IDENTITY_LENGTH.get(entry[:1])
    if n is None or len(entry) < 1 + n:
        return None
    key = smt.key_of(entry[: 1 + n])
    member = len(entry) > 1 + n
    return smt.fold(
        key,
        smt.value_hash(entry) if member else None,
        p["siblings"],
        None if member else p["terminal"],
    )


def _exchange_root(p: Dict[str, Any]) -> Optional[bytes]:
    from ..exchange import proofs

    if p["domain"] == 2:
        entry = p["entry"]
        if entry[:1] != proofs.PART or b"\x00" not in entry:
            return None
        name = entry[1 : entry.index(b"\x00")].decode(errors="replace")
        return smt.fold(proofs.part_key(name), smt.value_hash(entry), p["outer_siblings"], None)
    kind, name, entry = p["kind"], p["name"], p["entry"]
    member = len(entry) > 0
    inner = smt.fold(
        p["inner_key"],
        smt.value_hash(entry) if member else None,
        p["siblings"],
        None if member else p["terminal"],
    )
    if inner is None or kind not in (proofs.COLLECTION, proofs.BOOK):
        return None
    outer_key = (proofs.collection_key if kind == proofs.COLLECTION else proofs.book_key)(name)
    leaf = None if inner == smt.EMPTY else kind + inner + name.encode()
    return smt.fold(
        outer_key,
        smt.value_hash(leaf) if leaf is not None else None,
        p["outer_siblings"],
        None if leaf is not None else p["outer_terminal"],
    )


def check(signed_root: Optional[str], p: Dict[str, Any]) -> bool:
    """Does the parsed proof hold against ``signed_root`` (a block's unified state root)?"""
    if not signed_root:
        return False
    roots = p["roots"]
    droot, xroot = bytes.fromhex(roots["dtree"]), bytes.fromhex(roots["xtree"])
    if p["domain"] == 0:
        if _database_root(p) != droot:
            return False
    elif _exchange_root(p) != xroot:
        return False
    proof_root = smt.combine(droot, xroot).hex()
    unified = unified_state_root(
        roots["utxo"], roots["account"], roots["exchange"], roots["token"], proof_root
    )
    return unified == signed_root


def state_proof_precompile(computation):
    data = bytes(computation.msg.data_as_bytes)
    try:
        p = parse(data)
    except (ValueError, IndexError, UnicodeDecodeError):
        computation.consume_gas(GAS_BASE, reason="state proof")
        computation.output = (0).to_bytes(32, "big")
        return computation
    computation.consume_gas(GAS_BASE + GAS_PER_SIBLING * p["siblings_total"], reason="state proof")
    ok = False
    height = p["height"]
    if 1 <= height < int(computation.state.block_number):
        world = getattr(getattr(computation.state, "_account_db", None), "world", None)
        if world is not None:
            if height not in world.header_roots:
                world.need(roots=[height])
            try:
                ok = check(world.header_roots.get(height), p)
            except (ValueError, KeyError):
                ok = False
    computation.output = (1 if ok else 0).to_bytes(32, "big")
    return computation


def _path(siblings, terminal) -> bytes:
    out = len(siblings).to_bytes(32, "big") + b"".join(bytes.fromhex(s) for s in siblings)
    if terminal:
        key, value = bytes.fromhex(terminal["key"]), bytes.fromhex(terminal["value_hash"])
        return out + b"\x01" + key + value
    return out + b"\x00"


def _blob(b: bytes) -> bytes:
    return len(b).to_bytes(32, "big") + b


def encode(proof: Dict[str, Any], entry_override: Optional[bytes] = None) -> bytes:
    """The precompile's input for a proof as ``state_getProof`` returns it."""
    r = proof["roots"]
    out = int(proof["height"]).to_bytes(32, "big")
    out += bytes.fromhex(r["utxo"] or "0" * 64) + bytes.fromhex(r["account"])
    out += bytes.fromhex(r["exchange"]) + bytes.fromhex(r["token"])
    out += bytes.fromhex(proof["database_tree_root"]) + bytes.fromhex(proof["exchange_tree_root"])
    domain = proof.get("domain", "database")

    def entry(default: bytes) -> bytes:
        if entry_override is not None:
            return entry_override
        return bytes.fromhex(proof["entry"]) if proof.get("entry") else default

    if domain == "database":
        out += b"\x00" + _blob(entry(bytes.fromhex(proof["identity"])))
        out += _path(proof["siblings"], proof.get("terminal"))
    elif domain == "exchange":
        out += b"\x01" + bytes.fromhex(proof["kind"]) + _blob(str(proof["path"]).encode())
        out += bytes.fromhex(proof["inner_key"]) + _blob(entry(b""))
        out += _path(proof["siblings"], proof.get("terminal"))
        out += _path(proof["outer_siblings"], proof.get("outer_terminal"))
    else:  # exchange_part (a part exists while its name is one)
        out += b"\x02" + _blob(entry(b"")) + _path(proof["outer_siblings"], None)
    return out
