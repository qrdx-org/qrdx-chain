"""
Native NFTs — collections of unique tokens, defined by data and authorities like the native
fungible tokens (qrdx/exchange/tokens.py), not by contract code (docs/NATIVE_TOKENS.md §8).

The model follows Solana's: a **collection** is a token group (SPL Token-2022's group
extension, Metaplex's collection) — a name, symbol and metadata uri, an optional cap on its
size, royalty information for marketplaces, an **update authority** that may change the
metadata, and a **mint authority** that may add members. Each **NFT** is a member with a supply
of one and no decimals: its token id within the collection, its owner, its own metadata uri and
name. Because only the collection's mint authority can mint into it, every member is a
verified member of its collection.

Owners transfer and burn their NFTs. An owner may approve one account for one NFT, or approve
an operator for all of its NFTs in a collection; either may transfer (and burn) for it. A
collection may be soulbound (``non_transferable``): minted and burned, never moved.

Every collection is an ERC-721 inside the EVM at its own address (with ERC-2981 royalty info),
backed by this registry (qrdx/contracts/nft_evm.py).

The registry is exchange state: replayed from the chain on every path and committed in the
exchange state root (``state_hash``), contributing nothing until the first collection exists.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .tokens import (
    MAX_NAME_LENGTH, MAX_URI_LENGTH, TokenError, _bps, _flag, _name, _symbol, _uri, account,
    optional_address, same,
)

MAX_TOKEN_ID = 2 ** 256 - 1
MAX_OPERATORS_PER_OWNER = 64       # setApprovalForAll grants, across collections


class NftError(TokenError):
    """An NFT operation that cannot execute; nothing has changed."""


def token_id(value: Any) -> int:
    try:
        i = int(str(value), 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        raise NftError(f"token id must be an integer, got {value!r}")
    if not 0 <= i <= MAX_TOKEN_ID:
        raise NftError("token id must be a uint256")
    return i


@dataclass
class Nft:
    owner: str                        # as given; compared by account id
    uri: str = ""
    name: str = ""
    minted_height: int = 0
    approved: Optional[str] = None    # one account approved for this NFT (ERC-721 getApproved)

    def summary(self, collection: str, token_id_: int) -> Dict[str, Any]:
        return {"collection": collection, "token_id": str(token_id_), "owner": self.owner,
                "uri": self.uri, "name": self.name, "approved": self.approved,
                "minted_height": self.minted_height}


@dataclass
class Collection:
    address: str
    name: str
    symbol: str
    creator: str
    uri: str = ""
    max_supply: Optional[int] = None          # None = unlimited
    royalty_bps: int = 0                      # for marketplaces (ERC-2981 / Metaplex)
    royalty_recipient: Optional[str] = None
    update_authority: Optional[str] = None    # None = metadata frozen for good
    mint_authority: Optional[str] = None      # None = no more members, ever
    non_transferable: bool = False
    created_height: int = 0
    minted: int = 0                           # ever minted (burned ones included)
    burned: int = 0
    next_id: int = 1

    @property
    def supply(self) -> int:
        return self.minted - self.burned

    def summary(self) -> Dict[str, Any]:
        return {"collection": self.address, "name": self.name, "symbol": self.symbol,
                "uri": self.uri, "creator": self.creator,
                "max_supply": self.max_supply, "supply": self.supply, "minted": self.minted,
                "burned": self.burned, "royalty_bps": self.royalty_bps,
                "royalty_recipient": self.royalty_recipient,
                "update_authority": self.update_authority, "mint_authority": self.mint_authority,
                "non_transferable": self.non_transferable,
                "created_height": self.created_height}

    def canonical(self) -> List[Any]:
        return [self.name, self.symbol, self.creator, self.uri, self.max_supply,
                self.royalty_bps, self.royalty_recipient, self.update_authority,
                self.mint_authority, self.non_transferable, self.created_height, self.minted,
                self.burned, self.next_id]


class NftRegistry:
    """Collections, their NFTs, approvals and operators. Every method either changes the state
    completely or raises ``NftError`` having changed nothing."""

    def __init__(self) -> None:
        self.collections: Dict[str, Collection] = {}
        self.items: Dict[Tuple[str, int], Nft] = {}
        self.operators: Set[Tuple[str, str, str]] = set()      # (collection, owner, operator)
        # derived indexes (rebuilt with the state, never hashed)
        self.by_owner: Dict[str, Set[Tuple[str, int]]] = {}    # owner id → its NFTs
        self.operator_counts: Dict[str, int] = {}

    # ── lookup ──────────────────────────────────────────────────────────

    def get(self, collection: str) -> Optional[Collection]:
        return self.collections.get(str(collection).lower())

    def require(self, collection: str) -> Collection:
        c = self.get(collection)
        if c is None:
            raise NftError(f"unknown collection {collection}")
        return c

    def item(self, collection: str, tid: Any) -> Nft:
        c = self.require(collection)
        n = self.items.get((c.address, token_id(tid)))
        if n is None:
            raise NftError(f"{c.symbol} #{tid} does not exist")
        return n

    def find(self, collection: str, tid: int) -> Optional[Nft]:
        return self.items.get((str(collection).lower(), tid))

    def balance(self, collection: str, owner: str) -> int:
        c = str(collection).lower()
        return sum(1 for coll, _ in self.by_owner.get(account(owner), ()) if coll == c)

    def owned(self, owner: str, collection: Optional[str] = None) -> List[Tuple[str, int]]:
        keys = self.by_owner.get(account(owner), set())
        if collection is not None:
            c = str(collection).lower()
            keys = {k for k in keys if k[0] == c}
        return sorted(keys)

    def is_operator(self, collection: str, owner: str, operator: str) -> bool:
        return (str(collection).lower(), account(owner), account(operator)) in self.operators

    def may_spend(self, collection: str, tid: int, who: str) -> bool:
        """The owner, the NFT's approved account, or one of the owner's operators."""
        n = self.find(collection, tid)
        if n is None:
            return False
        return (same(n.owner, who) or (n.approved is not None and same(n.approved, who))
                or self.is_operator(collection, n.owner, who))

    # ── lifecycle ───────────────────────────────────────────────────────

    def create(self, address: str, creator: str, height: int, params: Dict[str, Any]) -> Collection:
        address = str(address).lower()
        if address in self.collections:
            raise NftError(f"collection {address} already exists")
        account(creator)
        cap = params.get("max_supply")
        if cap in (None, ""):
            cap = None
        else:
            try:
                cap = int(cap)
            except (TypeError, ValueError):
                raise NftError("max_supply must be an integer")
            if cap < 1:
                raise NftError("max_supply must be at least 1")
        c = Collection(
            address=address, name=_name(params.get("name", "")),
            symbol=_symbol(params.get("symbol", "")), creator=str(creator),
            uri=_uri(params.get("uri")), max_supply=cap,
            royalty_bps=_bps(params.get("royalty_bps", 0)),
            royalty_recipient=(optional_address(params["royalty_recipient"])
                               if "royalty_recipient" in params else str(creator)),
            update_authority=(optional_address(params["update_authority"])
                              if "update_authority" in params else str(creator)),
            mint_authority=(optional_address(params["mint_authority"])
                            if "mint_authority" in params else str(creator)),
            non_transferable=_flag(params.get("non_transferable", False)),
            created_height=int(height))
        if c.royalty_bps and c.royalty_recipient is None:
            raise NftError("royalties need a recipient")
        self.collections[address] = c
        return c

    def mint(self, collection: str, sender: str, to: str, height: int, *, uri: Any = "",
             name: Any = "", tid: Any = None) -> int:
        c = self.require(collection)
        if c.mint_authority is None:
            raise NftError(f"{c.symbol} has no mint authority: it is complete")
        if not same(c.mint_authority, sender):
            raise NftError(f"only {c.symbol}'s mint authority may mint")
        if c.max_supply is not None and c.minted >= c.max_supply:
            raise NftError(f"{c.symbol} is capped at {c.max_supply}")
        account(to)
        i = c.next_id if tid in (None, "") else token_id(tid)
        if (c.address, i) in self.items:
            raise NftError(f"{c.symbol} #{i} already exists")
        name = str(name or "").strip()
        if len(name) > MAX_NAME_LENGTH or not name.isprintable():
            raise NftError(f"an NFT's name must be at most {MAX_NAME_LENGTH} printable characters")
        nft = Nft(owner=str(to), uri=_uri(uri), name=name, minted_height=int(height))
        self.items[(c.address, i)] = nft
        self.by_owner.setdefault(account(to), set()).add((c.address, i))
        c.minted += 1
        if i >= c.next_id:
            c.next_id = i + 1
        return i

    def transfer(self, collection: str, tid: Any, sender: str, frm: str, to: str) -> Nft:
        c = self.require(collection)
        i = token_id(tid)
        n = self.item(c.address, i)
        if c.non_transferable:
            raise NftError(f"{c.symbol} is soulbound: its NFTs cannot be transferred")
        if not same(n.owner, frm):
            raise NftError(f"{c.symbol} #{i} is not owned by {frm}")
        if not self.may_spend(c.address, i, sender):
            raise NftError(f"not approved to transfer {c.symbol} #{i}")
        account(to)
        self.set_owner(c.address, i, str(to))
        return n

    def burn(self, collection: str, tid: Any, sender: str) -> None:
        c = self.require(collection)
        i = token_id(tid)
        self.item(c.address, i)
        if not self.may_spend(c.address, i, sender):
            raise NftError(f"not approved to burn {c.symbol} #{i}")
        self.set_owner(c.address, i, None)

    def approve(self, collection: str, tid: Any, sender: str, spender: Any) -> Optional[str]:
        c = self.require(collection)
        i = token_id(tid)
        n = self.item(c.address, i)
        if not (same(n.owner, sender) or self.is_operator(c.address, n.owner, sender)):
            raise NftError(f"only {c.symbol} #{i}'s owner or its operators may approve")
        spender = optional_address(spender)
        if spender is not None and same(n.owner, spender):
            raise NftError("cannot approve the owner")
        n.approved = spender
        return spender

    def set_operator(self, collection: str, owner: str, operator: str, approved: bool) -> None:
        c = self.require(collection)
        o, op = account(owner), account(operator)
        if o == op:
            raise NftError("cannot approve yourself as an operator")
        key = (c.address, o, op)
        if approved and key not in self.operators:
            if self.operator_counts.get(o, 0) >= MAX_OPERATORS_PER_OWNER:
                raise NftError(f"an account may approve at most {MAX_OPERATORS_PER_OWNER} "
                               "NFT operators")
            self.operators.add(key)
            self.operator_counts[o] = self.operator_counts.get(o, 0) + 1
        elif not approved and key in self.operators:
            self.operators.discard(key)
            n = self.operator_counts.get(o, 0) - 1
            if n > 0:
                self.operator_counts[o] = n
            else:
                self.operator_counts.pop(o, None)

    def set_owner(self, collection: str, tid: int, owner: Optional[str]) -> None:
        """Move an NFT to ``owner`` (None burns it), clearing its approval — the one place
        ownership changes, so the owner index always agrees."""
        key = (str(collection).lower(), tid)
        n = self.items[key]
        held = self.by_owner.get(account(n.owner))
        if held is not None:
            held.discard(key)
            if not held:
                del self.by_owner[account(n.owner)]
        n.approved = None
        if owner is None:
            del self.items[key]
            self.collections[key[0]].burned += 1
            return
        n.owner = owner
        self.by_owner.setdefault(account(owner), set()).add(key)

    def update(self, collection: str, sender: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """The update authority edits the collection (name, symbol, uri, royalties) or, with
        ``token_id``, one NFT's uri and name."""
        c = self.require(collection)
        if c.update_authority is None:
            raise NftError(f"{c.symbol}'s metadata is immutable")
        if not same(c.update_authority, sender):
            raise NftError(f"only {c.symbol}'s update authority may change it")
        if params.get("token_id") not in (None, ""):
            n = self.item(c.address, params["token_id"])
            uri = _uri(params["uri"]) if "uri" in params else n.uri
            name = str(params.get("name", n.name) or "").strip()
            if len(name) > MAX_NAME_LENGTH or not name.isprintable():
                raise NftError(f"an NFT's name must be at most {MAX_NAME_LENGTH} printable "
                               "characters")
            n.uri, n.name = uri, name
            return n.summary(c.address, token_id(params["token_id"]))
        name = _name(params["name"]) if params.get("name") not in (None, "") else c.name
        symbol = _symbol(params["symbol"]) if params.get("symbol") not in (None, "") else c.symbol
        uri = _uri(params["uri"]) if "uri" in params else c.uri
        bps = _bps(params["royalty_bps"]) if "royalty_bps" in params else c.royalty_bps
        recipient = (optional_address(params["royalty_recipient"])
                     if "royalty_recipient" in params else c.royalty_recipient)
        if bps and recipient is None:
            raise NftError("royalties need a recipient")
        c.name, c.symbol, c.uri, c.royalty_bps, c.royalty_recipient = name, symbol, uri, bps, recipient
        return c.summary()

    def set_authority(self, collection: str, sender: str, kind: str, new: Any) -> Optional[str]:
        c = self.require(collection)
        kind = str(kind).lower()
        if kind not in ("update", "mint"):
            raise NftError("authority must be 'update' or 'mint'")
        attr = f"{kind}_authority"
        current = getattr(c, attr)
        if current is None:
            raise NftError(f"{c.symbol} has no {kind} authority (renounced)")
        if not same(current, sender):
            raise NftError(f"only {c.symbol}'s {kind} authority may change it")
        new_address = optional_address(new)
        setattr(c, attr, new_address)
        return new_address

    # ── commitment ──────────────────────────────────────────────────────

    def canonical(self) -> Dict[str, Any]:
        return {
            "collections": {a: c.canonical() for a, c in sorted(self.collections.items())},
            "items": [[c, str(i), n.owner, n.uri, n.name, n.minted_height, n.approved]
                      for (c, i), n in sorted(self.items.items())],
            "operators": [list(k) for k in sorted(self.operators)],
        }

    def state_hash(self) -> bytes:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()
