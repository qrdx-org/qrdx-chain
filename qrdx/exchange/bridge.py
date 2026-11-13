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

**The deposit window, and refunds.** Validators attest each deposit with its source block's time.
A deposit counts toward a mint only while it is younger than ``BRIDGE_DEPOSIT_WINDOW`` on QRDX's
clock (7 days by default); after that no attestation counts, so it can never be minted. That is
what makes a refund safe. Once QRDX's *finalized* time is past a deposit's window and it was not
minted, the lockbox's custodian may return it (``refund``). This covers an unlisted token, a
recipient QRDX refuses, or a deposit the validators never reached.

**Guardrails.** ``BRIDGE_MINT_LIMITS`` bounds, per asset, what is minted in a day of QRDX's clock
and the supply. On a real network an asset with no limit mints nothing, so a quorum that is
compromised, or a bug, can mint at most one day's limit. Governance can pause minting
(``bridge_mint_pause``). A deposit over a limit, or while paused, stays attested and mints at a
later vote; if that is past its window, it is refunded instead.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import undo
from .commitment import Section, committed, tracked

# The mint authority of every bridged token: a protocol-internal holder (no key controls it;
# qrdx/crypto/account_id.py), so only this module can mint.
BRIDGE_AUTHORITY = "0xBRDG" + hashlib.blake2b(b"bridge:authority", digest_size=18).hexdigest()

MAX_VOTE_DEPOSITS = 16  # deposits one vote may attest
ATTESTATION_MAX_AGE = Decimal(24 * 3600)  # a deposit short of a quorum this long is dropped
# Attestations short of a quorum one validator may hold at once: past it, its new ones are
# ignored. Real deposits reach a quorum within blocks; this bounds what one validator can make
# the chain hold — and every block expire — with deposits that never happened
# (docs/EXCHANGE_AUDIT.md 10).
MAX_PENDING_PER_VOTER = 1024
# Source chains' finalized heads, attested like deposits (docs/BRIDGE.md "Chain heads"): a vote
# carries up to MAX_VOTE_HEADS; a validator's head vote counts while younger than HEAD_VOTE_MAX_AGE.
MAX_VOTE_HEADS = 8
HEAD_VOTE_MAX_AGE = Decimal(3600)
HEAD_HISTORY = 64  # attested heads kept per chain, for proofs against a recent one
# A deposit's source time may be at most this far ahead of QRDX's clock (clocks differ a little).
DEPOSIT_MAX_FUTURE = Decimal(600)
MINT_PERIOD = 86_400  # the mint limits' day, on QRDX's clock


@dataclass(frozen=True)
class ChainHead:
    """A source chain's finalized block as validators attest it."""

    chain: int
    height: int
    hash: str  # 0x + 64 hex
    state_root: str  # 0x + 64 hex
    timestamp: int

    def canonical(self) -> List[Any]:
        return [self.height, self.hash, self.state_root, self.timestamp]


_HASH = re.compile(r"0x[0-9a-f]{64}")


def parse_head(raw: Any) -> ChainHead:
    """A head as a vote carries it ({chain, height, hash, state_root, timestamp}); BridgeError
    if it is not one (hashes are normalized to lowercase, so honest copies are identical)."""
    if not isinstance(raw, dict):
        raise BridgeError("a chain head is {chain, height, hash, state_root, timestamp}")
    try:
        chain, height, ts = int(raw["chain"]), int(raw["height"]), int(raw["timestamp"])
        h, root = str(raw["hash"]).lower(), str(raw["state_root"]).lower()
    except (KeyError, TypeError, ValueError):
        raise BridgeError("a chain head is {chain, height, hash, state_root, timestamp}") from None
    if not (0 < chain < 1 << 32 and 0 <= height < 1 << 64 and 0 <= ts < 1 << 64):
        raise BridgeError("chain, height or timestamp out of range")
    if not (_HASH.fullmatch(h) and _HASH.fullmatch(root)):
        raise BridgeError("hash and state_root are 32-byte 0x hex")
    return ChainHead(chain, height, h, root, ts)


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
    """One lock on a source chain: the lockbox's record ``deposits[number]``, as validators
    attest it or a storage proof proves it. Its id is the same either way, so it mints once."""

    chain: int
    number: int  # the lockbox's deposit id
    token: str  # source token, lowercase
    sender: str  # the depositor on the source chain, lowercase
    to: str  # the QRDX recipient, exactly as the depositor wrote it
    amount: Decimal
    time: int  # the deposit block's timestamp (seconds): what the deposit window runs from

    @property
    def id(self) -> str:
        return f"{self.chain}:{self.number}"

    def canonical(self) -> Dict[str, Any]:
        return {
            "chain": self.chain,
            "id": self.number,
            "token": self.token,
            "from": self.sender,
            "to": self.to,
            "amount": str(self.amount),
            "time": self.time,
        }

    @property
    def digest(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(blob.encode(), digest_size=16).hexdigest()

    def units(self, asset: "BridgeAsset") -> int:
        """The amount in the token's base units, as the lockbox recorded it."""
        return int(self.amount.scaleb(asset.decimals))

    def record(self, asset: "BridgeAsset") -> bytes:
        """What the lockbox stores for it: keccak256(abi.encode(token, from, amount, recipient,
        time)) — ``QRDXLockbox.depositRecord``."""
        from eth_abi import encode
        from eth_utils import keccak

        return keccak(
            encode(
                ["address", "address", "uint256", "string", "uint256"],
                [self.token, self.sender, self.units(asset), self.to, self.time],
            )
        )


def parse_deposit(raw: Any, assets: Dict[Tuple[int, str], BridgeAsset]) -> Deposit:
    """A deposit from a vote or a proof, normalized so that every honest copy is identical."""
    from .tokens import TokenError, account as token_account

    if not isinstance(raw, dict):
        raise BridgeError("a deposit is an object")
    try:
        chain = int(raw["chain"])
        number = raw["id"]
        if isinstance(number, bool) or not isinstance(number, int) or not 0 < number < 1 << 63:
            raise ValueError("id is the lockbox's deposit id, a positive whole number")
        token = str(raw["token"]).lower()
        sender = str(raw["from"]).lower()
        to = str(raw["to"])
        value = Decimal(str(raw["amount"]))
        when = raw["time"]
        if isinstance(when, bool) or not isinstance(when, int) or not 0 <= when < 1 << 63:
            raise ValueError("time is the deposit block's timestamp, a whole number of seconds")
    except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
        raise BridgeError(f"malformed deposit: {exc}") from exc
    asset = assets.get((chain, token))
    if asset is None:
        raise BridgeError(f"no bridged asset for token {token} on chain {chain}")
    if not _HEX20.match(sender):
        raise BridgeError("a deposit names its depositor, a 0x address")
    try:
        token_account(to)
    except TokenError as exc:
        raise BridgeError(f"deposit recipient: {exc}") from exc
    if not value.is_finite() or value <= 0:
        raise BridgeError("a deposit amount must be positive")
    quantum = Decimal(1).scaleb(-asset.decimals)
    if value != value.quantize(quantum):
        raise BridgeError(f"{asset.symbol} has {asset.decimals} decimals")
    return Deposit(chain, number, token, sender, to, value.quantize(quantum), when)


# ── proofs against attested heads (the trust-minimized path) ─────────────────────────

# Where QRDXLockbox keeps ``deposits`` (its storage layout; tests/test_bridge_proofs.py checks it
# against the compiled contract).
DEPOSITS_SLOT = 4
MAX_PROOF_NODES = 32  # per proof (account, storage): an Ethereum state proof is ~10
MAX_PROOF_NODE_BYTES = 1024  # a Merkle-Patricia node is at most 532 bytes


def deposit_slot(number: int) -> bytes:
    """The storage slot of ``deposits[number]``: keccak256(abi.encode(number, DEPOSITS_SLOT))."""
    from eth_utils import keccak

    return keccak(int(number).to_bytes(32, "big") + DEPOSITS_SLOT.to_bytes(32, "big"))


def parse_lockboxes(entries: Iterable[str]) -> Dict[int, str]:
    """``BRIDGE_LOCKBOXES`` entries, each ``CHAIN_ID:LOCKBOX_ADDRESS``: the one lockbox per chain
    whose records a proof may show."""
    out: Dict[int, str] = {}
    for entry in entries:
        parts = [p.strip() for p in str(entry).split(":")]
        if len(parts) != 2 or not _HEX20.match(parts[1].lower()):
            raise BridgeError(f"bridge lockbox {entry!r}: expected CHAIN_ID:0xADDRESS")
        try:
            chain = int(parts[0])
        except ValueError:
            raise BridgeError(f"bridge lockbox {entry!r}: the chain id is a number") from None
        if chain <= 0 or chain in out:
            raise BridgeError(f"bridge lockbox {entry!r}: bad or repeated chain id")
        out[chain] = parts[1].lower()
    return out


def configured_lockboxes() -> Dict[int, str]:
    from .. import constants

    return parse_lockboxes(constants.BRIDGE_LOCKBOXES)


def _proof_nodes(raw: Any, what: str) -> List[bytes]:
    if not isinstance(raw, list) or not 0 < len(raw) <= MAX_PROOF_NODES:
        raise BridgeError(f"{what} is a list of 1 to {MAX_PROOF_NODES} RLP nodes")
    out = []
    for node in raw:
        try:
            data = bytes.fromhex(str(node).removeprefix("0x"))
        except ValueError:
            raise BridgeError(f"{what}: a node is hex") from None
        if not 0 < len(data) <= MAX_PROOF_NODE_BYTES:
            raise BridgeError(f"{what}: a node is 1 to {MAX_PROOF_NODE_BYTES} bytes")
        out.append(data)
    return out


def verify_deposit_proof(
    deposit: Deposit,
    asset: "BridgeAsset",
    head: Optional[ChainHead],
    lockbox: Optional[str],
    account_proof: Any,
    storage_proof: Any,
) -> Optional[str]:
    """Why the proof does not show the lockbox recording exactly ``deposit``, or None if it
    does: the lockbox's account, then its ``deposits[number]`` slot, proven against the state
    root of a head of the deposit's chain the validators attested."""
    from ..contracts.external_proof_evm import verify

    if lockbox is None:
        return f"chain {deposit.chain} has no lockbox in BRIDGE_LOCKBOXES"
    if head is None:
        return "no attested head of that chain at that height (one of the last 64)"
    account_nodes = _proof_nodes(account_proof, "account_proof")
    storage_nodes = _proof_nodes(storage_proof, "storage_proof")
    out = verify(
        bytes.fromhex(head.state_root[2:]),
        bytes.fromhex(lockbox[2:]),
        account_nodes,
        deposit_slot(deposit.number),
        storage_nodes,
    )
    if out is None:
        return "the proof does not hold against the attested head"
    if out[-32:] != deposit.record(asset):
        return "the lockbox's record is not this deposit"
    return None


@dataclass(frozen=True)
class MintLimit:
    """What may be minted of one bridged asset: per day of QRDX's clock, and in all (0: none)."""

    symbol: str
    per_day: Decimal
    cap: Decimal


def parse_mint_limits(entries: Iterable[str]) -> Dict[str, MintLimit]:
    """``BRIDGE_MINT_LIMITS`` entries, each ``SYMBOL:PER_DAY:CAP`` in the asset's own units —
    for example ``USDC:250000:5000000``; 0 means no limit of that kind."""
    out: Dict[str, MintLimit] = {}
    for entry in entries:
        parts = [p.strip() for p in str(entry).split(":")]
        if len(parts) != 3 or not parts[0]:
            raise BridgeError(f"mint limit {entry!r}: expected SYMBOL:PER_DAY:CAP")
        try:
            per_day, cap = Decimal(parts[1]), Decimal(parts[2])
        except InvalidOperation:
            raise BridgeError(f"mint limit {entry!r}: amounts are numbers") from None
        if not (per_day.is_finite() and cap.is_finite()) or per_day < 0 or cap < 0:
            raise BridgeError(f"mint limit {entry!r}: amounts are 0 or more")
        if parts[0] in out:
            raise BridgeError(f"mint limit {entry!r}: {parts[0]} is limited twice")
        out[parts[0]] = MintLimit(parts[0], per_day, cap)
    return out


def configured_mint_limits() -> Dict[str, MintLimit]:
    from .. import constants

    return parse_mint_limits(constants.BRIDGE_MINT_LIMITS)


def deposit_window() -> Decimal:
    from .. import constants

    return Decimal(int(constants.BRIDGE_DEPOSIT_WINDOW))


def _encode_pending(_key: Any, entry: Any) -> Any:
    return entry


def _encode_withdrawal(_wid: Any, record: Any) -> Any:
    return record


def _encode_tuple(_key: Any, value: Any) -> Any:
    # (A module-level function: committed collections are pickled with their encoder, in the
    # exchange checkpoints a restart resumes from — a lambda cannot be.)
    return list(value)


class Bridge:
    """Bridge state: deposits awaiting a quorum, deposits minted, withdrawals recorded. Pure
    and deterministic; the exchange state manager applies the token moves."""

    # Committed entry by entry (qrdx/exchange/commitment.py).
    pending = committed("bridge.pending", _encode_pending, mutable=False)
    done = committed("bridge.done", kind="set")
    withdrawals = committed("bridge.withdrawals", _encode_withdrawal, mutable=False)
    heads = committed("bridge.heads", _encode_tuple, mutable=False)
    head_votes = committed("bridge.head_votes", _encode_tuple, mutable=False)
    head_history = committed("bridge.head_history", _encode_tuple, mutable=False)
    # Guardrails: per bridged token, (day, amount minted that day); and governance's switches.
    mint_window = committed("bridge.mint_window", _encode_tuple, mutable=False)
    flags = committed("bridge.flags", _encode_withdrawal, mutable=False)

    def __init__(self) -> None:
        # "<deposit id>|<digest>" → {"deposit": canonical, "voters": [...], "since": time}
        self.pending = {}
        self.done = set()  # deposit ids minted
        self.withdrawals = {}  # withdrawal id → record
        self.next_withdrawal: int = 1
        self.heads = {}  # chain id → (height, hash, state_root, timestamp): the attested head
        self.head_votes = {}  # "chain|validator" → (height, hash, state_root, timestamp, since)
        self.head_history = {}  # "chain|height" → the head: the last HEAD_HISTORY per chain
        self.mint_window = {}  # token address → (day, amount minted that day)
        # "mint_paused" → {"paused": bool, "height": the proposal's};
        # "doomsday" → {"time", "height", "cause"}: the Doomsday Protocol triggered (doomsday.py)
        self.flags = {}

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        for name in ("heads", "head_votes", "head_history", "mint_window", "flags"):
            if name not in state:  # (pickled before chain heads / guardrails)
                setattr(self, name, {})

    # ── chain heads ─────────────────────────────────────────────────────

    def attest_head(
        self, head: ChainHead, voter: str, now: Decimal, committee: Dict[str, Decimal]
    ) -> bool:
        """Record ``voter``'s view of a source chain's finalized head (replacing its previous
        one). True when this head — exactly — now has more than two thirds of the committee's
        stake among the votes younger than HEAD_VOTE_MAX_AGE, and is higher than the attested
        one: it becomes the attested head."""
        self.head_votes[f"{head.chain}|{voter}"] = (*head.canonical(), str(now))
        current = self.heads.get(head.chain)
        if current is not None and head.height <= int(current[0]):
            return False
        total = sum(committee.values(), Decimal(0))
        weight = Decimal(0)
        for v in sorted(committee):
            vote = self.head_votes.peek(f"{head.chain}|{v}")
            if (
                vote is not None
                and tuple(vote[:4]) == tuple(head.canonical())
                and now - Decimal(vote[4]) <= HEAD_VOTE_MAX_AGE
            ):
                weight += committee[v]
        if total <= 0 or weight * 3 <= total * 2:
            return False
        self.heads[head.chain] = tuple(head.canonical())
        self.head_history[f"{head.chain}|{head.height}"] = tuple(head.canonical())
        kept = sorted(
            int(k.split("|", 1)[1])
            for k in dict.keys(self.head_history)
            if k.split("|", 1)[0] == str(head.chain)
        )
        for height in kept[:-HEAD_HISTORY]:
            del self.head_history[f"{head.chain}|{height}"]
        return True

    def head_at(self, chain: int, height: int) -> Optional[ChainHead]:
        """An attested head of ``chain`` at ``height`` (one of its last HEAD_HISTORY)."""
        h = (
            self.head_history.peek(f"{int(chain)}|{int(height)}")
            if len(self.head_history)
            else None
        )
        return ChainHead(int(chain), int(h[0]), h[1], h[2], int(h[3])) if h else None

    def head(self, chain: int) -> Optional[ChainHead]:
        h = self.heads.peek(int(chain)) if len(self.heads) else None
        return ChainHead(int(chain), int(h[0]), h[1], h[2], int(h[3])) if h else None

    # ── deposits ────────────────────────────────────────────────────────

    def _pending_index(self) -> Dict[str, Any]:
        """The pending attestations by deposit id, by voter and by the time they were first
        made — derived from ``pending``, never committed, kept up to date from the entries
        changed since (as ``TradingState.due_cancels``)."""
        import bisect

        pending = tracked(self.pending)
        index = self.__dict__.get("_index")
        if index is None or pending.__dict__.get("_index_token") is not index["token"]:
            index = {"token": [], "keys": {}, "by_id": {}, "by_voter": {}, "since": []}
            pending.track_changes()
            pending.take_changes()
            pending.__dict__["_index_token"] = index["token"]
            changed: Iterable[str] = list(dict.keys(pending))
            self.__dict__["_index"] = index
        else:
            changed = pending.take_changes()
        for key in changed:
            dep = key.split("|", 1)[0]
            old = index["keys"].pop(key, None)
            if old is not None:
                since, voters = old
                index["by_id"].get(dep, set()).discard(key)
                for v in voters:
                    index["by_voter"].get(v, set()).discard(key)
                i = bisect.bisect_left(index["since"], (since, key))
                if i < len(index["since"]) and index["since"][i] == (since, key):
                    del index["since"][i]
            entry = pending.peek(key)
            if entry is not None:
                since, voters = Decimal(entry["since"]), tuple(entry["voters"])
                index["keys"][key] = (since, voters)
                index["by_id"].setdefault(dep, set()).add(key)
                for v in voters:
                    index["by_voter"].setdefault(v, set()).add(key)
                bisect.insort(index["since"], (since, key))
        return index

    def attest(
        self, deposit: Deposit, voter: str, now: Decimal, committee: Dict[str, Decimal]
    ) -> bool:
        """Record ``voter``'s attestation. True when the deposit now has a quorum — more than
        two thirds of the committee's stake attesting exactly this deposit: the caller mints
        it, then calls ``complete``. A deposit already minted is ignored, and so is a new
        attestation of a voter that already holds MAX_PENDING_PER_VOTER."""
        if deposit.id in self.done:
            return False
        key = f"{deposit.id}|{deposit.digest}"
        entry = self.pending.get(key)
        voters = set(entry["voters"]) if entry else set()
        if voter not in voters and (
            len(self._pending_index()["by_voter"].get(voter, ())) >= MAX_PENDING_PER_VOTER
        ):
            return False
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

    @staticmethod
    def refusal(deposit: Deposit, now: Decimal) -> Optional[str]:
        """Why an attestation of ``deposit`` cannot count at time ``now``, or None: it is past
        the deposit window (and never will count: it is the custodian's to refund), or its
        source time is ahead of QRDX's clock."""
        if Decimal(deposit.time) > now + DEPOSIT_MAX_FUTURE:
            return "its source time is ahead of QRDX's clock"
        if now - Decimal(deposit.time) > deposit_window():
            return "past the deposit window: it is never minted, and may be refunded"
        return None

    @property
    def mint_paused(self) -> bool:
        flag = self.flags.get("mint_paused") if len(self.flags) else None
        return bool(flag and flag.get("paused"))

    def set_mint_paused(self, paused: bool, height: int) -> None:
        self.flags["mint_paused"] = {"paused": bool(paused), "height": int(height)}

    @property
    def doomsday(self) -> Optional[Dict[str, Any]]:
        """The Doomsday Protocol's trigger ({"time", "height", "cause"}), or None."""
        flag = self.flags.get("doomsday") if len(self.flags) else None
        return dict(flag) if flag else None

    def set_doomsday(self, time: int, height: int, cause: str) -> None:
        self.flags["doomsday"] = {"time": int(time), "height": int(height), "cause": str(cause)}

    def mint_refusal(
        self, asset: BridgeAsset, amount: Decimal, supply: Decimal, now: Decimal, dev: bool
    ) -> Optional[str]:
        """Why a deposit with a quorum cannot mint now (it stays attested and mints at a later
        vote), or None: the Doomsday Protocol triggered, minting is paused, the asset has no
        limit on a real network, or the day's limit or the cap would be exceeded."""
        if self.doomsday:
            return "the Doomsday Protocol stopped minting: the source chain's keys may be broken"
        if self.mint_paused:
            return "minting is paused by governance"
        limit = configured_mint_limits().get(asset.symbol)
        if limit is None:
            return None if dev else f"no mint limit is configured for {asset.symbol}"
        day = int(now // MINT_PERIOD)
        used = self.mint_window.get(asset.address) if len(self.mint_window) else None
        minted_today = Decimal(used[1]) if used and int(used[0]) == day else Decimal(0)
        if limit.per_day and minted_today + amount > limit.per_day:
            return f"{asset.symbol}'s daily mint limit ({limit.per_day}) would be exceeded"
        if limit.cap and supply + amount > limit.cap:
            return f"{asset.symbol}'s supply cap ({limit.cap}) would be exceeded"
        return None

    def record_mint(self, asset: BridgeAsset, amount: Decimal, now: Decimal) -> None:
        day = int(now // MINT_PERIOD)
        used = self.mint_window.get(asset.address) if len(self.mint_window) else None
        today = Decimal(used[1]) if used and int(used[0]) == day else Decimal(0)
        self.mint_window[asset.address] = (day, str(today + amount))

    def complete(self, deposit: Deposit) -> None:
        """The deposit was minted: record it, and drop every attestation of its id."""
        self.done.add(deposit.id)
        for key in sorted(self._pending_index()["by_id"].get(deposit.id, ())):
            del self.pending[key]

    def expire(self, now: Decimal) -> None:
        """Drop deposits that have waited ATTESTATION_MAX_AGE without a quorum (a validator
        still seeing one attests it again)."""
        import bisect

        if len(self.pending):
            ordered = self._pending_index()["since"]
            cutoff = now - ATTESTATION_MAX_AGE  # (older than the age: first made before this)
            for _since, key in ordered[: bisect.bisect_left(ordered, (cutoff, ""))]:
                del self.pending[key]
        if len(self.head_votes):
            old = [
                k
                for k, v in sorted(self.head_votes.peek_items())
                if now - Decimal(v[4]) > HEAD_VOTE_MAX_AGE
            ]
            for key in old:
                del self.head_votes[key]

    def status(self, deposit_id: str) -> Dict[str, Any]:
        attestations = [
            {"deposit": e["deposit"], "voters": e["voters"], "since": e["since"]}
            for k, e in sorted(dict.items(self.pending))
            if k.split("|", 1)[0] == deposit_id
        ]
        return {"id": deposit_id, "minted": deposit_id in self.done, "pending": attestations}

    def guardrails(self) -> Dict[str, Any]:
        """The deposit window, the mint limits and today's use, and whether minting is paused."""
        limits = configured_mint_limits()
        used = (
            {k: list(v) for k, v in sorted(self.mint_window.peek_items())}
            if len(self.mint_window)
            else {}
        )
        return {
            "deposit_window": int(deposit_window()),
            "deposit_max_future": int(DEPOSIT_MAX_FUTURE),
            "mint_period": MINT_PERIOD,
            "mint_paused": self.mint_paused,
            "doomsday": self.doomsday,
            "mint_limits": {
                s: {"per_day": str(m.per_day), "cap": str(m.cap)} for s, m in sorted(limits.items())
            },
            "minted_by_day": used,
        }

    # ── withdrawals ─────────────────────────────────────────────────────

    def record_withdrawal(self, record: Dict[str, Any]) -> int:
        undo.keep(self, ("next_withdrawal",), "bridge")  # (a plain counter: kept for a rollback)
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
        return bool(
            self.pending
            or self.done
            or self.withdrawals
            or len(self.heads)
            or len(self.head_votes)
            or len(self.mint_window)
            or len(self.flags)
        )

    def commitment(self) -> bytes:
        sec = (
            Section("bridge")
            .value([self.next_withdrawal])
            .raw(self.pending.commitment())
            .raw(self.done.commitment())
            .raw(self.withdrawals.commitment())
        )
        if len(self.heads) or len(self.head_votes):  # (absent until the first head vote)
            sec.raw(self.heads.commitment()).raw(self.head_votes.commitment())
            sec.raw(self.head_history.commitment())
        if len(self.mint_window) or len(self.flags):  # (absent until the first limited mint)
            sec.raw(self.mint_window.commitment()).raw(self.flags.commitment())
        return sec.digest()

    def verify_commitment(self) -> None:
        self.pending.verify()
        self.done.verify()
        self.withdrawals.verify()
        self.heads.verify()
        self.head_votes.verify()
        self.head_history.verify()
        self.mint_window.verify()
        self.flags.verify()
