"""
QNS, account control (policies, recovery) and referrals.

These are ExchangeStateManager's methods, written as functions of the manager (``self``) and
bound to it under the same names in qrdx/exchange/state_manager.py. They are here only to keep
that file to a size one can read: read them as the class's.
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Any, Dict, List

from ..clearinghouse import ClearinghouseError
from ..nfts import NftError
from ..orderbook import (
    _pinned,
)
from ..tokens import (
    TokenError,
)
from ..transactions import (
    EXCHANGE_GAS_COSTS,
    ExchangeOpType,
    ExchangeTransaction,
)
from .common import (
    ZERO,
    ExchangeExecResult,
    _account_key,
    _apply_policy,
    _default_policy,
    _describe_policy,
    _parse_value,
    _policy_value,
)

if TYPE_CHECKING:
    from ..state_manager import ExchangeStateManager


# ── QNS, the QRDX Name Service (qrdx/exchange/qns.py) ─────────────────────
def qns_authority(self: ExchangeStateManager) -> str:
    from ..qns import QNS_AUTHORITY

    return QNS_AUTHORITY


def _qns_pay(self: ExchangeStateManager, payer: str, years: int, name: str = "") -> Decimal:
    """Take a name's price for ``years`` from ``payer`` for the treasury: QNS_PRICE_PER_YEAR
    a year, times the name's length factor (qns.price_factor)."""
    from ... import constants
    from ..qns import price_factor

    price = Decimal(constants.QNS_PRICE_PER_YEAR) * years * price_factor(name)
    if price <= 0:
        return ZERO
    avail = self.available_balance(payer)  # less this transaction's gas reservation
    if avail is None or avail < price:
        raise ValueError(f"a name costs {price} QRDX; {payer[:16]}… has {avail}")
    self._record_balance_delta(payer, -price)
    self._record_balance_delta(constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"], price)
    return price


def _qns_years(value: Any) -> int:
    from ..qns import QNS_MAX_YEARS

    years = 1 if value is None else value
    if isinstance(years, bool) or not isinstance(years, int) or not 1 <= years <= QNS_MAX_YEARS:
        raise ValueError(f"years must be 1 to {QNS_MAX_YEARS}")
    return years


def _op_qns_register(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Register ``name`` (label.qrdx) for ``years``: its NFT minted to the sender, resolving
    to ``target`` (default: the sender). Refused while it is taken (until its expiry's grace
    period ends — then the old NFT is burned)."""
    from ..qns import (
        QNS_AUTHORITY,
        QNS_COLLECTION,
        YEAR_SECONDS,
        NameRecord,
        QnsError,
        name_token_id,
        normalize,
    )

    p = tx.params
    now = Decimal(str(self._block_clock()))
    try:
        name = normalize(p["name"])
        years = self._qns_years(p.get("years"))
        target = str(p.get("target") or tx.sender)
        from ...crypto.account_id import to_account_id

        to_account_id(target)  # (a real address)
        svc, nfts = self.qns, self.nfts
        if not svc.available(nfts, name, now):
            raise QnsError(f"{name} is registered")
        paid = self._qns_pay(tx.sender, years, name)
        if nfts.get(QNS_COLLECTION) is None:
            nfts.create(
                QNS_COLLECTION,
                QNS_AUTHORITY,
                self._current_block_height,
                {
                    "name": "QRDX Name Service",
                    "symbol": "QNS",
                    "mint_authority": QNS_AUTHORITY,
                    "update_authority": QNS_AUTHORITY,
                },
            )
        tid = name_token_id(name)
        if nfts.items.peek((QNS_COLLECTION, tid)) is not None:  # expired: reclaimed
            nfts.set_owner(QNS_COLLECTION, tid, None)
        nfts.mint(
            QNS_COLLECTION,
            QNS_AUTHORITY,
            tx.sender,
            self._current_block_height,
            uri=f"qns://{name}",
            name=name,
            tid=tid,
        )
        record = NameRecord(expires=now + years * YEAR_SECONDS, target=target, holder=tx.sender)
        svc.names[name] = record  # (a reclaimed name's old records go with it)
    except (ValueError, KeyError, NftError, TokenError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.QNS_REGISTER],
        data={
            "name": name,
            "token_id": str(tid),
            "collection": QNS_COLLECTION,
            "expires": str(record.expires),
            "paid": str(paid),
        },
    )


def _op_qns_renew(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Extend ``name`` by ``years`` from its expiry (anyone may pay), to at most
    QNS_MAX_YEARS ahead; not once its grace period has ended."""
    from dataclasses import replace

    from ..qns import QNS_GRACE_SECONDS, QNS_MAX_YEARS, YEAR_SECONDS, QnsError, normalize

    now = Decimal(str(self._block_clock()))
    try:
        name = normalize(tx.params["name"])
        years = self._qns_years(tx.params.get("years"))
        r = self.qns.record(name)
        if r is None or self.qns.owner(self.nfts, name) is None:
            raise QnsError(f"{name} is not registered")
        if now >= r.expires + QNS_GRACE_SECONDS:
            raise QnsError(f"{name} has lapsed: register it")
        expires = r.expires + years * YEAR_SECONDS
        if expires > now + QNS_MAX_YEARS * YEAR_SECONDS:
            raise QnsError(f"a name is held at most {QNS_MAX_YEARS} years ahead")
        paid = self._qns_pay(tx.sender, years, name)
        self.qns.names[name] = replace(r, expires=expires)
    except (ValueError, KeyError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.QNS_RENEW],
        data={"name": name, "expires": str(expires), "paid": str(paid)},
    )


def _op_qns_set_record(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """The name's owner (or an account it approved for the NFT, or an operator) sets
    ``key``: ``address`` (where it resolves; "" clears) or a text record ("" removes)."""
    from dataclasses import replace

    from ..qns import (
        MAX_KEY_LENGTH,
        MAX_TEXT_RECORDS,
        MAX_VALUE_LENGTH,
        QNS_COLLECTION,
        QnsError,
        name_token_id,
        normalize,
    )

    p = tx.params
    now = Decimal(str(self._block_clock()))
    try:
        name = normalize(p["name"])
        # As its present owner holds them: an earlier owner's are cleared (qns.current).
        r = self.qns.current(self.nfts, name)
        if r is None or now >= r.expires:
            raise QnsError(f"{name} is not registered (or has expired)")
        if not self.nfts.may_spend(QNS_COLLECTION, name_token_id(name), tx.sender):
            raise QnsError(f"only {name}'s owner (or an account it approved) sets its records")
        key, value = str(p["key"]), str(p.get("value", ""))
        if key == "address":
            if value:
                from ...crypto.account_id import to_account_id

                to_account_id(value)
            updated = replace(r, target=value)
        else:
            if not 1 <= len(key) <= MAX_KEY_LENGTH or len(value) > MAX_VALUE_LENGTH:
                raise QnsError(
                    f"a record key is 1 to {MAX_KEY_LENGTH} characters, its value at most "
                    f"{MAX_VALUE_LENGTH}"
                )
            texts = dict(r.texts)
            if value:
                texts[key] = value
            else:
                texts.pop(key, None)
            if len(texts) > MAX_TEXT_RECORDS:
                raise QnsError(f"at most {MAX_TEXT_RECORDS} text records")
            updated = replace(r, texts=tuple(sorted(texts.items())))
        self.qns.names[name] = updated
    except (ValueError, KeyError, NftError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.QNS_SET_RECORD],
        data={"name": name, "key": key, "value": value},
    )


def _op_qns_set_primary(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """The sender's reverse record: ``name`` must resolve to the sender ("" clears it)."""
    from ...crypto.account_id import to_account_id
    from ..qns import QnsError, normalize

    now = Decimal(str(self._block_clock()))
    key = to_account_id(tx.sender)
    try:
        raw = str(tx.params["name"])
        if not raw:
            if key in self.qns.primary:
                del self.qns.primary[key]
            name = ""
        else:
            name = normalize(raw)
            target = self.qns.resolve(self.nfts, name, now)
            if target is None or to_account_id(target) != key:
                raise QnsError(f"{name} does not resolve to {tx.sender[:16]}…")
            self.qns.primary[key] = name
    except (ValueError, KeyError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.QNS_SET_PRIMARY],
        data={"primary": name or None},
    )


# ── account control (qrdx/exchange/authority.py) ─────────────────────────
def _op_account_policy(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Change who may sign for the sender (docs/ACCOUNT_CONTROL.md). ``action``:
    ``add_controller`` / ``remove_controller`` {controller}, ``own_key`` {enabled},
    ``delay`` {seconds}, ``cancel`` {change_id}. Signed by a controller it applies at once;
    by the account's own key it waits out the delay (lengthening it excepted)."""
    p = tx.params
    account, action = tx.sender, str(p["action"])
    auth = self.authority
    by_controller = bool(tx.signer) and auth.may_control(account, tx.signer)
    now = Decimal(str(self._block_clock()))
    try:
        if action == "publish_keyset":  # public information: anyone may record a keyset
            from ...crypto.multisig_wire import encode_keyset, keyset_of

            ks = p["keyset"]
            if not isinstance(ks, dict) or not isinstance(ks.get("public_keys"), list):
                raise ValueError("keyset is {m, public_keys}")
            from ...crypto.pq.dilithium import PQPublicKey

            keyset = keyset_of([PQPublicKey.from_hex(h) for h in ks["public_keys"]], int(ks["m"]))
            address = auth.record_keyset(encode_keyset(keyset))
            return ExchangeExecResult(
                success=True,
                gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ACCOUNT_POLICY],
                data={"multisig": address},
            )
        if tx.signer and not by_controller:
            raise ValueError("only the account itself or its controllers change its policy")
        if action == "cancel":
            change = auth.pending.peek(str(p["change_id"]))
            if change is None or change.account != _account_key(account):
                raise ValueError(f"no waiting change {p['change_id']}")
            del auth.pending[str(p["change_id"])]
            return ExchangeExecResult(
                success=True,
                gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ACCOUNT_POLICY],
                data={"cancelled": str(p["change_id"])},
            )
        value = _policy_value(action, p)
        current = auth.policy(account)
        changed = _apply_policy(current, action, value, account)  # (checks it)
        immediate = (
            by_controller
            or current.delay == 0
            or (action == "delay" and int(value) > current.delay)
        )
        if immediate:
            auth.set_policy(account, changed)
            data: Dict[str, Any] = {"applied": True, **_describe_policy(changed)}
        else:
            cid = auth.queue(account, action, str(value), now + current.delay, "own_key")
            data = {"applied": False, "change_id": cid, "due": str(now + current.delay)}
    except (ValueError, KeyError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ACCOUNT_POLICY], data=data
    )


def _op_account_recover(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """A guardian of ``account`` backs ``new_controller`` ("" withdraws its backing). When
    the account's threshold of guardians back the same one, the recovery is queued: after
    the account's recovery delay it binds that controller in place of all others and turns
    the own key off — unless the own key or a controller cancels it first (ACCOUNT_POLICY
    cancel)."""
    p = tx.params
    account, new = str(p["account"]), str(p.get("new_controller", ""))
    auth = self.authority
    now = Decimal(str(self._block_clock()))
    try:
        policy = auth.policy(account)
        key = _account_key(account)
        if _account_key(tx.sender) not in policy.guardian_ids():
            raise ValueError(f"{tx.sender[:16]}… is not a guardian of {account[:16]}…")
        if new:
            _apply_policy(policy, "recover", new, account)  # (checks the address)
            target = _account_key(new)
            for _cid, c in auth.pending_of(account):
                if c.action == "recover" and _account_key(c.value) == target:
                    raise ValueError(f"a recovery to {new[:16]}… is already waiting")
        backing = auth.back_recovery(account, tx.sender, new)
        data: Dict[str, Any] = {"account": key, "new_controller": new, "backing": backing}
        if new and backing >= policy.guardian_threshold:
            due = now + policy.recovery_delay
            data["change_id"] = auth.queue(account, "recover", new, due, "guardians")
            data["due"] = str(due)
            auth.clear_recovery_votes(
                key,
                [
                    g
                    for g in policy.guardian_ids()
                    if (v := auth.recovery_votes.peek(f"{key}|{g}")) is not None
                    and _account_key(v) == _account_key(new)
                ],
            )
    except (ValueError, KeyError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ACCOUNT_RECOVER], data=data
    )


@_pinned
def apply_policy_changes(self: ExchangeStateManager, now: Decimal) -> List[Dict[str, Any]]:
    """The block's tick for account control: changes the own key signed whose delay has
    passed take effect — unless the own key was turned off meanwhile, or the change no
    longer fits the policy (it is dropped)."""
    auth = self.authority
    if not len(auth.pending):
        return []
    events = []
    for cid in auth.due_changes(now):
        change = auth.pending.peek(cid)
        del auth.pending[cid]
        policy = auth.policies.peek(change.account) or _default_policy()
        event = {"change_id": cid, "account": change.account, "action": change.action}
        try:
            if not policy.own_key and change.action != "recover":
                raise ValueError("the own key that signed it was turned off")
            updated = _apply_policy(policy, change.action, _parse_value(change), change.account)
        except ValueError as e:
            events.append({"type": "policy_change_dropped", **event, "reason": str(e)})
            continue
        if change.action == "recover":  # done: the guardians' backing is spent
            auth.clear_recovery_votes(change.account, policy.guardian_ids())
        auth.store_policy(change.account, updated)
        events.append({"type": "policy_change_applied", **event})
    return events


def _op_referral(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """REFERRAL_REGISTER: take ``code``. REFERRAL_JOIN: join ``code``'s referrer."""
    code = str(tx.params["code"])
    try:
        if tx.op_type == ExchangeOpType.REFERRAL_REGISTER:
            self.clearinghouse.register_referral_code(tx.sender, code)
            data = {"code": code}
        else:
            data = {"code": code, "referrer": self.clearinghouse.join_referral(tx.sender, code)}
    except (ClearinghouseError, ValueError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(success=True, gas_used=EXCHANGE_GAS_COSTS[tx.op_type], data=data)
