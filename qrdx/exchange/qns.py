"""
QNS — the QRDX Name Service (docs/QNS.md).

Names are native NFTs (qrdx/exchange/nfts.py) in a protocol collection, so they transfer, approve,
appear in wallets and in the EVM (ERC-721) like any NFT. The protocol is the collection's only
minter: its mint authority is an address no key controls (``QNS_AUTHORITY``), and only QNS
operations mint through it.

* A name is ``label.qrdx``: a label of 3–59 of a-z, 0-9 and hyphen (no leading or trailing
  hyphen). Its NFT's token id is a hash of the name; the NFT's name is the name.
* ``QNS_REGISTER`` mints it to the registrant for 1–QNS_MAX_YEARS years at the chain-spec
  QNS_PRICE_PER_YEAR a year (default 0.0125 QRDX, ~$5 at $400 a QRDX) times the name's length
  factor — 128 for 3 characters, 32 for 4 (``price_factor``) — paid to the treasury. ``QNS_RENEW``: anyone may
  pay to extend it (to at most QNS_MAX_YEARS ahead).
* Its owner — whoever holds the NFT, or an account it approved — sets its records: ``address``
  (what the name resolves to) and text records. ``QNS_SET_PRIMARY``: an account's reverse
  record, valid while the name resolves to that account.
* A name resolves until it expires. After QNS_GRACE_SECONDS more anyone may register it again;
  the old NFT is burned. An owner who burns the NFT gives the name up at once.

Committed (names and primary records here; the NFTs in the NFT registry), absent from the exchange
root until the first name.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from .commitment import Section, committed, encode_value

TLD = "qrdx"
QNS_COLLECTION = "0x" + hashlib.blake2b(b"qns:collection", digest_size=20).hexdigest()
QNS_AUTHORITY = "0xQNSA" + hashlib.blake2b(b"qns:mint-authority", digest_size=18).hexdigest()
YEAR_SECONDS = 365 * 24 * 3600
QNS_MAX_YEARS = 10
QNS_GRACE_SECONDS = 30 * 24 * 3600
MAX_TEXT_RECORDS = 16
MAX_KEY_LENGTH = 32
MAX_VALUE_LENGTH = 256

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{1,57}[a-z0-9])")


def price_factor(name: str) -> int:
    """How many base prices (QNS_PRICE_PER_YEAR) a year of ``name`` costs: short names are the
    scarce ones — 128 for 3 characters, 32 for 4, 1 for 5 or more (ENS's ratios)."""
    label = str(name).split(".", 1)[0]
    return 128 if len(label) <= 3 else 32 if len(label) == 4 else 1


class QnsError(ValueError):
    """A name operation that cannot execute; nothing has changed."""


def normalize(name: Any) -> str:
    """``label.qrdx``, lowercase (the suffix may be left off); QnsError if it is not a name."""
    text = str(name or "").strip().lower()
    label = text[: -len(TLD) - 1] if text.endswith("." + TLD) else text
    if not _LABEL.fullmatch(label):
        raise QnsError(
            "a name is label.qrdx: 3 to 59 of a-z, 0-9 and hyphen, not starting or ending with one"
        )
    return f"{label}.{TLD}"


def name_token_id(name: str) -> int:
    """The name's NFT token id: a hash of the name."""
    return int.from_bytes(hashlib.blake2b(name.encode(), digest_size=32).digest(), "big")


@dataclass(frozen=True)
class NameRecord:
    expires: Decimal  # block time
    target: str  # the address it resolves to ("" none)
    texts: Tuple[Tuple[str, str], ...] = ()


def _encode_record(_name: str, r: NameRecord) -> Any:
    return [str(r.expires), r.target, [list(t) for t in r.texts]]


class NameService:
    names = committed("qns.names", _encode_record, mutable=False)
    primary = committed("qns.primary", encode_value, mutable=False)

    def __init__(self) -> None:
        self.names = {}  # name → NameRecord
        self.primary = {}  # account id → name (its reverse record)

    # ── reading ─────────────────────────────────────────────────────────

    def record(self, name: str) -> Optional[NameRecord]:
        return self.names.peek(name) if len(self.names) else None

    def owner(self, nfts, name: str) -> Optional[str]:
        nft = nfts.items.peek((QNS_COLLECTION, name_token_id(name)))
        return nft.owner if nft is not None else None

    def resolve(self, nfts, name: str, now: Decimal) -> Optional[str]:
        """What ``name`` resolves to now (None: unregistered, expired or no address record)."""
        r = self.record(name)
        if r is None or now >= r.expires or self.owner(nfts, name) is None:
            return None
        return r.target or None

    def reverse(self, nfts, address: str, now: Decimal) -> Optional[str]:
        """``address``'s primary name — while that name still resolves to it."""
        from ..crypto.account_id import to_account_id

        key = to_account_id(address)
        name = self.primary.peek(key) if len(self.primary) else None
        if name is None:
            return None
        target = self.resolve(nfts, name, now)
        return name if target is not None and to_account_id(target) == key else None

    def names_of(self, nfts, address: str) -> List[str]:
        out = []
        for collection, tid in nfts.owned(address, QNS_COLLECTION):
            nft = nfts.items.peek((collection, tid))
            if nft is not None:
                out.append(nft.name)
        return sorted(out)

    def available(self, nfts, name: str, now: Decimal) -> bool:
        r = self.record(name)
        if r is None or self.owner(nfts, name) is None:
            return True
        return now >= r.expires + QNS_GRACE_SECONDS

    # ── commitment ──────────────────────────────────────────────────────

    @property
    def touched(self) -> bool:
        return bool(len(self.names) or len(self.primary))

    def commitment(self) -> bytes:
        return Section("qns").raw(self.names.commitment()).raw(self.primary.commitment()).digest()

    def state_hash(self) -> bytes:
        blob = json.dumps(
            {
                "names": {n: _encode_record(n, r) for n, r in sorted(self.names.peek_items())},
                "primary": dict(sorted(self.primary.peek_items())),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()

    def verify_commitment(self) -> None:
        self.names.verify()
        self.primary.verify()


def summary(svc: NameService, nfts, name: str, now: Decimal) -> Optional[Dict[str, Any]]:
    r = svc.record(name)
    owner = svc.owner(nfts, name)
    if r is None or owner is None:
        return None
    return {
        "name": name,
        "owner": owner,
        "token_id": str(name_token_id(name)),
        "collection": QNS_COLLECTION,
        "expires": str(r.expires),
        "expired": now >= r.expires,
        "available_from": str(r.expires + QNS_GRACE_SECONDS),
        "address": r.target or None,
        "resolves_to": svc.resolve(nfts, name, now),
        "texts": dict(r.texts),
    }
