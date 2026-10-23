"""
Account control — who may sign for an account, as consensus state (docs/ACCOUNT_CONTROL.md).

An account's **policy**:

* ``controllers`` — accounts bound to it that may sign **anything** for it: an exchange
  transaction with the account as ``sender`` and the controller as ``signer``, or an EVM
  type-0x51 transaction spending from it (``on_behalf_of``). A controller is a post-quantum
  key (``0xPQ…``) or an m-of-n multisig (``0xPQMS…``): bind a hot wallet to a cold one, or to a
  2-of-3 of your devices, or give an organization's multisig authority over an operating wallet.
* ``own_key`` — whether the account's own key may still sign. Off, the account is controlled
  only by its controllers: a compromised or quantum-weak key loses its power. (Agent keys the
  account approved act only while its own key does.)
* ``delay`` — seconds of block time a change signed by the account's OWN key waits before it
  takes effect (lengthening the delay excepted). Controllers are the root of trust: a change a
  controller signs applies at once, and any controller may cancel a waiting change. So a stolen
  hot key cannot quietly bind a thief as controller: its change waits in the open, and the
  owner's controller cancels it — or turns the stolen key off.

A key whose own account has turned it off signs for nothing: not as a controller, not as an
agent. To need several signers, make the controller a multisig.

**Social recovery** (docs/CONSENSUS_ROADMAP.md 7), for an account whose keys are all lost: its
policy names ``guardians`` and a ``guardian_threshold``. When that many guardians back the same
new controller (``ACCOUNT_RECOVER``), the recovery waits ``recovery_delay`` like any waiting
change — the account's own key or a controller may cancel it — and then binds the new controller
in place of all others and turns the own key off. Setting guardians is a policy change: signed
by the own key it waits out the delay, so a stolen key cannot quietly name its own guardians.

Policies are keyed by canonical account id (qrdx/crypto/account_id.py), so the exchange (which
names accounts as signed) and the EVM (20-byte ids) agree on them. Committed entry by entry, and
absent from the exchange root until first used.
"""

from __future__ import annotations

import bisect
import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import undo
from .commitment import Section, committed, encode_value, tracked

ZERO = Decimal(0)
MAX_CONTROLLERS = 5
MAX_DELAY_SECONDS = 30 * 24 * 3600
MAX_PENDING = 10  # changes waiting, per account
MAX_GUARDIANS = 7
MIN_RECOVERY_DELAY = 24 * 3600
DEFAULT_RECOVERY_DELAY = 7 * 24 * 3600


def account_id(address: str) -> str:
    """The key a policy is filed under: the canonical account id."""
    from ..crypto.account_id import to_account_id

    return to_account_id(str(address))


@dataclass(frozen=True)
class Policy:
    controllers: Tuple[str, ...] = ()  # addresses as given (0xPQ… or 0xPQMS…), sorted
    own_key: bool = True
    delay: int = 0  # seconds of block time a change signed by the own key waits
    guardians: Tuple[str, ...] = ()  # addresses as given, sorted
    guardian_threshold: int = 0
    recovery_delay: int = 0  # seconds of block time a recovery waits

    def controller_ids(self) -> Tuple[str, ...]:
        return tuple(account_id(c) for c in self.controllers)

    def guardian_ids(self) -> Tuple[str, ...]:
        return tuple(account_id(g) for g in self.guardians)


@dataclass(frozen=True)
class Change:
    """A change the account's own key signed, waiting out the account's delay."""

    account: str  # the account's id
    action: str  # "add_controller", "remove_controller", "own_key", "delay", "guardians",
    # or "recover" (queued by the guardians)
    value: str
    due: Decimal  # block time it takes effect
    proposer: str
    seq: int


def _encode_policy(_account: str, p: Policy) -> Any:
    out = [list(p.controllers), p.own_key, p.delay]
    if p.guardians:  # (absent without guardians: earlier policies keep their encoding)
        out += [list(p.guardians), p.guardian_threshold, p.recovery_delay]
    return out


def _encode_change(_cid: str, c: Change) -> Any:
    return [c.account, c.action, c.value, str(c.due), c.proposer, c.seq]


@dataclass(frozen=True)
class Keyset:
    """A multisig's members, as the chain learned them (its address is derived from them)."""

    threshold: int
    members: Tuple[str, ...]  # the members' 0xPQ addresses, in the keyset's order


def _encode_keyset(_address: str, k: Keyset) -> Any:
    return [k.threshold, list(k.members)]


class AccountAuthority:
    """Every account's policy, and the changes waiting."""

    policies = committed("auth.policies", _encode_policy, mutable=False)
    pending = committed("auth.pending", _encode_change, mutable=False)
    keysets = committed("auth.keysets", _encode_keyset, mutable=False)
    recovery_votes = committed("auth.recovery_votes", encode_value, mutable=False)

    def __init__(self) -> None:
        self.policies = {}  # account id → Policy
        self.pending = {}  # change id → Change
        self.keysets = {}  # multisig address (lowercase) → Keyset, once it signed or was published
        self.recovery_votes = {}  # "account id|guardian id" → the new controller it backs
        self.seq = 0

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        if "keysets" not in state:  # (pickled before keysets were recorded)
            self.keysets = {}
        if "recovery_votes" not in state:
            self.recovery_votes = {}

    # ── social recovery ─────────────────────────────────────────────────

    def back_recovery(self, address: str, guardian: str, new_controller: str) -> int:
        """``guardian`` backs ``new_controller`` for ``address`` ("" withdraws its backing).
        Returns how many of the account's guardians now back it."""
        key, gid = account_id(address), account_id(guardian)
        vote = f"{key}|{gid}"
        if not new_controller:
            if vote in self.recovery_votes:
                del self.recovery_votes[vote]
            return 0
        self.recovery_votes[vote] = new_controller
        target = account_id(new_controller)
        return sum(
            1
            for g in self.policy(address).guardian_ids()
            if (v := self.recovery_votes.peek(f"{key}|{g}")) is not None and account_id(v) == target
        )

    def clear_recovery_votes(self, key: str, guardian_ids: Iterable[str]) -> None:
        for g in guardian_ids:
            vote = f"{key}|{g}"
            if vote in self.recovery_votes:
                del self.recovery_votes[vote]

    # ── multisig keysets ────────────────────────────────────────────────

    def record_keyset(self, keyset_material: bytes) -> Optional[str]:
        """Record the multisig keyset a transaction carried (or that was published): its
        threshold and members, under the address they derive. Returns the address (None if the
        material is not a keyset)."""
        from ..crypto.multisig_wire import decode_keyset, is_multisig_material

        if not is_multisig_material(keyset_material):
            return None
        keyset = decode_keyset(keyset_material)
        address = keyset.address.lower()
        if address not in self.keysets:
            members = tuple(pk.to_address() for pk in keyset.public_keys)
            self.keysets[address] = Keyset(threshold=keyset.config.m, members=members)
        return address

    def members_of(self, address: str) -> Optional[Keyset]:
        return self.keysets.peek(str(address).lower()) if len(self.keysets) else None

    def controlled_by(self, address: str) -> List[str]:
        """The accounts (ids) ``address`` is a controller of — a derived index, never
        committed, kept up to date from the policies marked since."""
        index = self._reverse_index()
        try:
            return sorted(index["controls"].get(account_id(address), ()))
        except ValueError:
            return []

    def guardian_of(self, address: str) -> List[str]:
        """The accounts (ids) ``address`` is a guardian of — derived, like ``controlled_by``."""
        index = self._reverse_index()
        try:
            return sorted(index["guards"].get(account_id(address), ()))
        except ValueError:
            return []

    def multisigs_of(self, address: str) -> List[str]:
        index = self._reverse_index()
        return sorted(index["member_of"].get(str(address).lower(), ()))

    def _reverse_index(self) -> Dict[str, Any]:
        policies, keysets = tracked(self.policies), tracked(self.keysets)
        index = self.__dict__.get("_reverse")
        fresh = (
            index is None
            or policies.__dict__.get("_index_token") is not index["token"]
            or keysets.__dict__.get("_index_token") is not index["token"]
        )
        if fresh or index is None:
            index = {
                "token": [],
                "controls": {},
                "member_of": {},
                "pol": {},
                "ks": {},
                "guards": {},
                "gpol": {},
            }
            for d in (policies, keysets):
                d.track_changes()
                d.take_changes()
                d.__dict__["_index_token"] = index["token"]
            changed_p: Iterable[str] = list(dict.keys(policies))
            changed_k: Iterable[str] = list(dict.keys(keysets))
            self.__dict__["_reverse"] = index
        else:
            changed_p, changed_k = policies.take_changes(), keysets.take_changes()
        for acct in changed_p:
            for c in index["pol"].pop(acct, ()):
                index["controls"].get(c, set()).discard(acct)
            for g in index["gpol"].pop(acct, ()):
                index["guards"].get(g, set()).discard(acct)
            p = policies.peek(acct)
            if p is not None:
                ids = p.controller_ids()
                index["pol"][acct] = ids
                for c in ids:
                    index["controls"].setdefault(c, set()).add(acct)
                gids = p.guardian_ids()
                index["gpol"][acct] = gids
                for g in gids:
                    index["guards"].setdefault(g, set()).add(acct)
        for ms in changed_k:
            for member in index["ks"].pop(ms, ()):
                index["member_of"].get(member, set()).discard(ms)
            k = keysets.peek(ms)
            if k is not None:
                members = tuple(m.lower() for m in k.members)
                index["ks"][ms] = members
                for member in members:
                    index["member_of"].setdefault(member, set()).add(ms)
        return index

    # ── reading ─────────────────────────────────────────────────────────

    def policy(self, address: str) -> Policy:
        if not len(self.policies):
            return Policy()
        try:
            return self.policies.peek(account_id(address)) or Policy()
        except ValueError:
            return Policy()

    def may_control(self, account: str, signer: str) -> bool:
        """Is ``signer`` a controller of ``account`` (any address forms)?"""
        if not len(self.policies):
            return False
        try:
            return account_id(signer) in self.policy(account).controller_ids()
        except ValueError:
            return False

    def own_key_enabled(self, address: str) -> bool:
        return self.policy(address).own_key

    def pending_of(self, address: str) -> List[Tuple[str, Change]]:
        key = account_id(address)
        return sorted(
            ((cid, c) for cid, c in self.pending.peek_items() if c.account == key),
            key=lambda x: x[1].seq,
        )

    # ── changing ────────────────────────────────────────────────────────

    def _next_seq(self) -> int:
        undo.keep(self, ("seq",), "authority", shallow=True)
        self.seq += 1
        return self.seq

    def set_policy(self, address: str, policy: Policy) -> None:
        self.store_policy(account_id(address), policy)

    def store_policy(self, key: str, policy: Policy) -> None:
        """File ``policy`` under the account id ``key``; backing from guardians it no longer
        names is dropped."""
        old = self.policies.peek(key) if len(self.policies) else None
        if old is not None and old.guardians:
            kept = set(policy.guardian_ids())
            self.clear_recovery_votes(key, [g for g in old.guardian_ids() if g not in kept])
        if policy == Policy():
            if key in self.policies:
                del self.policies[key]
        else:
            self.policies[key] = policy

    def queue(self, address: str, action: str, value: str, due: Decimal, proposer: str) -> str:
        key = account_id(address)
        if len(self.pending_of(address)) >= MAX_PENDING:
            raise ValueError(f"at most {MAX_PENDING} changes may wait")
        seq = self._next_seq()
        cid = hashlib.blake2b(f"{key}:{seq}".encode(), digest_size=8).hexdigest()
        self.pending[cid] = Change(key, action, value, due, proposer, seq)
        return cid

    def due_changes(self, now: Decimal) -> List[str]:
        """The waiting changes whose time has come, in the order they were proposed."""
        index = self._due_index()
        return [cid for _due, _seq, cid in index[: bisect.bisect_right(index, (now, 1 << 62, "~"))]]

    def _due_index(self) -> List[Tuple[Decimal, int, str]]:
        """The waiting changes sorted by (due, seq, id) — derived, never committed."""
        pending = tracked(self.pending)
        state = self.__dict__.get("_due")
        if state is None or pending.__dict__.get("_index_token") is not state["token"]:
            state = {"token": [], "keys": {}, "list": []}
            pending.track_changes()
            pending.take_changes()
            pending.__dict__["_index_token"] = state["token"]
            changed: Iterable[str] = list(dict.keys(pending))
            self.__dict__["_due"] = state
        else:
            changed = pending.take_changes()
        for cid in changed:
            old = state["keys"].pop(cid, None)
            if old is not None:
                i = bisect.bisect_left(state["list"], old)
                if i < len(state["list"]) and state["list"][i] == old:
                    del state["list"][i]
            c = pending.peek(cid)
            if c is not None:
                key = (c.due, c.seq, cid)
                bisect.insort(state["list"], key)
                state["keys"][cid] = key
        return state["list"]

    # ── commitment ──────────────────────────────────────────────────────

    @property
    def touched(self) -> bool:
        return self.seq > 0 or bool(len(self.policies)) or bool(len(self.keysets))

    def commitment(self) -> bytes:
        sec = (
            Section("authority")
            .value([self.seq])
            .raw(self.policies.commitment())
            .raw(self.pending.commitment())
            .raw(self.keysets.commitment())
        )
        if len(self.recovery_votes):  # (absent until a guardian first backs a recovery)
            sec.raw(self.recovery_votes.commitment())
        return sec.digest()

    def state_hash(self) -> bytes:
        blob = json.dumps(
            {
                "seq": self.seq,
                "policies": {
                    a: _encode_policy(a, p) for a, p in sorted(self.policies.peek_items())
                },
                "pending": {c: _encode_change(c, x) for c, x in sorted(self.pending.peek_items())},
                "keysets": {a: _encode_keyset(a, k) for a, k in sorted(self.keysets.peek_items())},
                **(
                    {"recovery_votes": dict(sorted(self.recovery_votes.peek_items()))}
                    if len(self.recovery_votes)
                    else {}
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()

    def verify_commitment(self) -> None:
        self.policies.verify()
        self.pending.verify()
        self.keysets.verify()
        self.recovery_votes.verify()


def describe(policy: Policy) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "controllers": list(policy.controllers),
        "own_key": policy.own_key,
        "delay": policy.delay,
    }
    if policy.guardians:
        out["guardians"] = {
            "addresses": list(policy.guardians),
            "threshold": policy.guardian_threshold,
            "recovery_delay": policy.recovery_delay,
        }
    return out


__all__ = [
    "AccountAuthority",
    "Change",
    "MAX_CONTROLLERS",
    "MAX_DELAY_SECONDS",
    "Policy",
    "account_id",
    "describe",
]
