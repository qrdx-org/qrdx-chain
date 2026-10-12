"""
The consensus bridge (docs/BRIDGE.md): tokens locked on another chain, minted here.

**Deposits.** A user locks a supported token in the lockbox contract on its source chain
(``contracts/bridge/QRDXLockbox.sol``), naming a QRDX recipient. Validators read the lockbox up
to the source chain's *finalized* block (``qrdx/validator/bridge_watcher.py``) and attest each
deposit inside their oracle votes, which already carry their own sequence, travel the mempool's
vote lane and count only committee members not convicted of an offence. Once attestations that
agree on every field of a deposit carry more than two thirds of the committee's stake, the
deposit is minted to the recipient through the bridged token's mint authority — an address no
key controls (``BRIDGE_AUTHORITY``), held by this module alone — and its id is recorded, so a
deposit is minted once however many attestations follow.

**Withdrawals.** ``BRIDGE_WITHDRAW`` burns the bridged token and records a withdrawal: a
sequential id, the source chain, token and recipient, the amount. The lockbox's custodian
releases it on the source chain once the block is final; the lockbox refuses an id twice. The
source chains cannot verify Dilithium signatures, so the release is the custodian's act: the one
trust this design names (docs/BRIDGE.md, "Trust").

The supported assets are a chain-spec parameter (``BRIDGE_ASSETS``), so every node agrees on
them and adding one is a fork. A bridged token is created by the protocol at its first deposit,
at an address derived from its source, with zero supply until then.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .commitment import Section, committed

# The mint authority of every bridged token: a protocol-internal holder (no key controls it;
# qrdx/crypto/account_id.py), so only this module can mint.
BRIDGE_AUTHORITY = "0xBRDG" + hashlib.blake2b(b"bridge:authority", digest_size=18).hexdigest()

MAX_VOTE_DEPOSITS = 16  # deposits one vote may attest
ATTESTATION_MAX_AGE = Decimal(24 * 3600)  # a deposit short of a quorum this long is dropped
MAX_DECIMALS = 18

_HEX20 = re.compile(r"^0x[0-9a-f]{40}$")
_HEX32 = re.compile(r"^0x[0-9a-f]{64}$")


class BridgeError(ValueError):
    """A bridge operation that cannot execute; nothing has changed."""


def token_address(chain: int, source_token: str) -> str:
    """The QRDX address of the token bridged from ``source_token`` on ``chain``."""
    seed = f"bridge:{int(chain)}:{source_token.lower()}".encode()
    return "0x" + hashlib.blake2b(seed, digest_size=20).hexdigest()


@dataclass(frozen=True)
class BridgeAsset:
    symbol: str
    chain: int  # the source chain's EIP-155 id
    source_token: str  # the token's address there, lowercase
    decimals: int

    @property
    def address(self) -> str:
        return token_address(self.chain, self.source_token)

    def summary(self) -> Dict[str, Any]:
        return {
            "symbol": self.symbol,
            "chain": self.chain,
            "source_token": self.source_token,
            "decimals": self.decimals,
            "token_address": self.address,
        }


def parse_assets(entries: Iterable[str]) -> Dict[Tuple[int, str], BridgeAsset]:
    """``BRIDGE_ASSETS`` entries, each ``SYMBOL:CHAIN_ID:SOURCE_TOKEN:DECIMALS`` — for example
    ``USDC:42161:0xaf88d065e77c8cc2239327c5edb3a432268e5831:6``."""
    out: Dict[Tuple[int, str], BridgeAsset] = {}
    for entry in entries:
        parts = [p.strip() for p in str(entry).split(":")]
        if len(parts) != 4:
            raise BridgeError(f"bridge asset {entry!r}: expected SYMBOL:CHAIN_ID:TOKEN:DECIMALS")
        symbol, chain, token, decimals = parts
        token = token.lower()
        if not symbol or not _HEX20.match(token):
            raise BridgeError(f"bridge asset {entry!r}: needs a symbol and a 0x token address")
        try:
            asset = BridgeAsset(symbol, int(chain), token, int(decimals))
        except ValueError as exc:
            raise BridgeError(f"bridge asset {entry!r}: {exc}") from exc
        if asset.chain <= 0 or not 0 <= asset.decimals <= MAX_DECIMALS:
            raise BridgeError(f"bridge asset {entry!r}: bad chain id or decimals")
        if (asset.chain, token) in out:
            raise BridgeError(f"bridge asset {entry!r} is listed twice")
        out[(asset.chain, token)] = asset
    return out


def configured_assets() -> Dict[Tuple[int, str], BridgeAsset]:
    from .. import constants

    return parse_assets(constants.BRIDGE_ASSETS)


def asset_by_token(token: str) -> Optional[BridgeAsset]:
    token = str(token).lower()
    for asset in configured_assets().values():
        if asset.address == token:
            return asset
    return None


@dataclass(frozen=True)
class Deposit:
    """One lock on a source chain, as validators attest it."""

    chain: int
    token: str  # source token, lowercase
    tx: str  # source transaction hash, lowercase
    log: int  # log index in that transaction's block
    to: str  # the QRDX recipient, as the depositor wrote it
    amount: Decimal

    @property
    def id(self) -> str:
        return f"{self.chain}:{self.tx}:{self.log}"

    def canonical(self) -> Dict[str, Any]:
        return {
            "chain": self.chain,
            "token": self.token,
            "tx": self.tx,
            "log": self.log,
            "to": self.to,
            "amount": str(self.amount),
        }

    @property
    def digest(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(blob.encode(), digest_size=16).hexdigest()


def parse_deposit(raw: Any, assets: Dict[Tuple[int, str], BridgeAsset]) -> Deposit:
    """A deposit from a vote, normalized so that every honest validator's copy is identical."""
    from .tokens import TokenError, account as token_account

    if not isinstance(raw, dict):
        raise BridgeError("a deposit is an object")
    try:
        chain = int(raw["chain"])
        token = str(raw["token"]).lower()
        tx = str(raw["tx"]).lower()
        log = int(raw["log"])
        to = str(raw["to"]).strip()
        value = Decimal(str(raw["amount"]))
    except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
        raise BridgeError(f"malformed deposit: {exc}") from exc
    asset = assets.get((chain, token))
    if asset is None:
        raise BridgeError(f"no bridged asset for token {token} on chain {chain}")
    if not _HEX32.match(tx) or log < 0:
        raise BridgeError("a deposit names its source transaction hash and log index")
    try:
        token_account(to)
    except TokenError as exc:
        raise BridgeError(f"deposit recipient: {exc}") from exc
    if not value.is_finite() or value <= 0:
        raise BridgeError("a deposit amount must be positive")
    quantum = Decimal(1).scaleb(-asset.decimals)
    if value != value.quantize(quantum):
        raise BridgeError(f"{asset.symbol} has {asset.decimals} decimals")
    return Deposit(chain, token, tx, log, to, value.quantize(quantum))


def _encode_pending(_key: Any, entry: Any) -> Any:
    return entry


def _encode_withdrawal(_wid: Any, record: Any) -> Any:
    return record


class Bridge:
    """Bridge state: deposits awaiting a quorum, deposits minted, withdrawals recorded. Pure
    and deterministic; the exchange state manager applies the token moves."""

    # Committed entry by entry (qrdx/exchange/commitment.py).
    pending = committed("bridge.pending", _encode_pending, mutable=False)
    done = committed("bridge.done", kind="set")
    withdrawals = committed("bridge.withdrawals", _encode_withdrawal, mutable=False)

    def __init__(self) -> None:
        # "<deposit id>|<digest>" → {"deposit": canonical, "voters": [...], "since": time}
        self.pending = {}
        self.done = set()  # deposit ids minted
        self.withdrawals = {}  # withdrawal id → record
        self.next_withdrawal: int = 1

    # ── deposits ────────────────────────────────────────────────────────

    def attest(
        self, deposit: Deposit, voter: str, now: Decimal, committee: Dict[str, Decimal]
    ) -> bool:
        """Record ``voter``'s attestation. True when the deposit now has a quorum — more than
        two thirds of the committee's stake attesting exactly this deposit: the caller mints
        it, then calls ``complete``. A deposit already minted is ignored."""
        if deposit.id in self.done:
            return False
        key = f"{deposit.id}|{deposit.digest}"
        entry = self.pending.get(key)
        voters = set(entry["voters"]) if entry else set()
        voters.add(voter)
        since = entry["since"] if entry else str(now)
        self.pending[key] = {
            "deposit": deposit.canonical(),
            "voters": sorted(voters),
            "since": since,
        }
        total = sum(committee.values(), Decimal(0))
        weight = sum((committee.get(v, Decimal(0)) for v in voters), Decimal(0))
        return total > 0 and weight * 3 > total * 2

    def complete(self, deposit: Deposit) -> None:
        """The deposit was minted: record it, and drop every attestation of its id."""
        self.done.add(deposit.id)
        for key in [k for k in dict.keys(self.pending) if k.split("|", 1)[0] == deposit.id]:
            del self.pending[key]

    def expire(self, now: Decimal) -> None:
        """Drop deposits that have waited ATTESTATION_MAX_AGE without a quorum (a validator
        still seeing one attests it again)."""
        stale = [
            k
            for k, entry in dict.items(self.pending)
            if now - Decimal(entry["since"]) > ATTESTATION_MAX_AGE
        ]
        for key in stale:
            del self.pending[key]

    def status(self, deposit_id: str) -> Dict[str, Any]:
        attestations = [
            {"deposit": e["deposit"], "voters": e["voters"], "since": e["since"]}
            for k, e in sorted(dict.items(self.pending))
            if k.split("|", 1)[0] == deposit_id
        ]
        return {"id": deposit_id, "minted": deposit_id in self.done, "pending": attestations}

    # ── withdrawals ─────────────────────────────────────────────────────

    def record_withdrawal(self, record: Dict[str, Any]) -> int:
        wid = self.next_withdrawal
        self.withdrawals[wid] = dict(record, id=wid)
        self.next_withdrawal = wid + 1
        return wid

    def list_withdrawals(self, from_id: int = 1, limit: int = 100) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for wid in range(max(1, int(from_id)), self.next_withdrawal):
            if len(out) >= limit:
                break
            record = self.withdrawals.get(wid)
            if record is not None:
                out.append(record)
        return out

    # ── commitment ──────────────────────────────────────────────────────

    @property
    def touched(self) -> bool:
        return bool(self.pending or self.done or self.withdrawals)

    def commitment(self) -> bytes:
        return (
            Section("bridge")
            .value([self.next_withdrawal])
            .raw(self.pending.commitment())
            .raw(self.done.commitment())
            .raw(self.withdrawals.commitment())
            .digest()
        )

    def verify_commitment(self) -> None:
        self.pending.verify()
        self.done.verify()
        self.withdrawals.verify()
