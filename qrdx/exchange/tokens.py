"""
The native token standard — one fungible-token model for the whole chain.

Every token on QRDX is a native token: an entry in this registry plus balances in the consensus
token ledger (``token_balances``, committed by the token root). Like an SPL mint or a
Hyperliquid HIP-1 token, a token is defined by data and authorities, not by contract code:

* **mint authority** — may mint new supply (never above ``max_supply``); none = the supply is
  fixed forever;
* **freeze authority** — may freeze and thaw one account's balance of the token; none = no
  account can ever be frozen;
* **holders** transfer, burn their own balance, and approve spenders, who move tokens for them
  with ``transfer_from`` up to the approved amount.

An authority can be handed to another account or renounced; renouncing is irreversible.

A frozen account cannot move its balance — no transfer, burn, swap, order, deposit or any other
debit — but can still receive. Tokens it had already committed elsewhere (a resting order's
escrow, a liquidity position, perps collateral) are no longer its balance: the freeze does not
reach them, and whatever they pay back lands in the frozen balance.

Amounts carry at most 18 decimal places (the ledger's unit, as for the AMM); ``decimals`` is how
wallets display the token.

The registry, the allowances and the frozen accounts are exchange state: replayed from the chain
on every path (forward, restart, reorg rebuild) and committed in the exchange state root
(``state_hash``). The balances stay in the token ledger.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional, Set, Tuple

ZERO = Decimal(0)
AMOUNT_QUANTUM = Decimal("1e-18")
MAX_DECIMALS = 18
MAX_NAME_LENGTH = 64
MAX_SYMBOL_LENGTH = 16
# Non-zero allowances one owner may hold across all tokens: approvals are state every node
# carries, so they are bounded like resting orders are.
MAX_ALLOWANCES_PER_OWNER = 256


class TokenError(ValueError):
    """A token operation that cannot execute; nothing has changed."""


def account(address: Any) -> str:
    """The account id a token authority, allowance or freeze is keyed by — the same key the
    token ledger uses for balances, so every address form of one account is one holder."""
    from ..crypto.account_id import to_account_id
    try:
        return to_account_id(str(address))
    except ValueError as e:
        raise TokenError(f"invalid address {address!r}: {e}") from e


def optional_address(value: Any) -> Optional[str]:
    """An authority parameter: an address — kept as given, for display, once it is known to
    name an account — or empty / None for no authority."""
    if value is None or (isinstance(value, str) and value.strip().lower() in ("", "none")):
        return None
    account(value)
    return str(value).strip()


def same(a: Optional[str], b: Any) -> bool:
    """Do two address forms name the same account?"""
    return a is not None and account(a) == account(b)


def amount(value: Any, what: str = "amount", allow_zero: bool = False) -> Decimal:
    """A token amount: a finite decimal with at most 18 places, positive (or zero if allowed)."""
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise TokenError(f"{what} is not a number: {value!r}")
    if not d.is_finite():
        raise TokenError(f"{what} must be finite")
    if d < 0 or (d == 0 and not allow_zero):
        raise TokenError(f"{what} must be {'non-negative' if allow_zero else 'positive'}")
    if d != d.quantize(AMOUNT_QUANTUM):
        raise TokenError(f"{what} has more than 18 decimal places")
    return d


@dataclass
class NativeToken:
    address: str
    name: str
    symbol: str
    decimals: int
    creator: str                           # addresses are kept as given and compared by
    supply: Decimal = ZERO                 # account id (any form of one account matches)
    max_supply: Optional[Decimal] = None   # None = uncapped (only matters with a mint authority)
    mint_authority: Optional[str] = None   # None = fixed supply
    freeze_authority: Optional[str] = None # None = never freezable
    created_height: int = 0

    def summary(self) -> Dict[str, Any]:
        return {
            "token_address": self.address, "name": self.name, "symbol": self.symbol,
            "decimals": self.decimals, "total_supply": str(self.supply),
            "max_supply": None if self.max_supply is None else str(self.max_supply),
            "mint_authority": self.mint_authority, "freeze_authority": self.freeze_authority,
            "creator": self.creator, "created_height": self.created_height,
        }


class TokenRegistry:
    """Native tokens, allowances and frozen accounts. Pure, deterministic state: every method
    either changes it completely or raises ``TokenError`` having changed nothing."""

    def __init__(self) -> None:
        self.tokens: Dict[str, NativeToken] = {}
        self.allowances: Dict[Tuple[str, str, str], Decimal] = {}   # (token, owner, spender)
        self.frozen: Set[Tuple[str, str]] = set()                    # (token, holder)
        self.allowance_counts: Dict[str, int] = {}   # owner → non-zero allowances (derived)
        self.changed: Set[str] = set()       # tokens changed this block (the DB mirror)

    # ── lookup ──────────────────────────────────────────────────────────

    def get(self, token: str) -> Optional[NativeToken]:
        return self.tokens.get(str(token).lower())

    def require(self, token: str) -> NativeToken:
        t = self.get(token)
        if t is None:
            raise TokenError(f"unknown token {token}")
        return t

    def is_frozen(self, token: str, holder: str) -> bool:
        if not self.frozen:
            return False
        try:
            return (str(token).lower(), account(holder)) in self.frozen
        except TokenError:
            return False

    def allowance(self, token: str, owner: str, spender: str) -> Decimal:
        return self.allowances.get((str(token).lower(), account(owner), account(spender)), ZERO)

    # ── lifecycle ───────────────────────────────────────────────────────

    def deploy(self, address: str, creator: str, height: int, *, name: Any, symbol: Any,
               decimals: Any = MAX_DECIMALS, initial_supply: Any = 0, max_supply: Any = None,
               mint_authority: Any = None, freeze_authority: Any = None) -> NativeToken:
        address = str(address).lower()
        if address in self.tokens:
            raise TokenError(f"token {address} already exists")
        name, symbol = str(name).strip(), str(symbol).strip()
        if not 1 <= len(name) <= MAX_NAME_LENGTH:
            raise TokenError(f"name must be 1-{MAX_NAME_LENGTH} characters")
        if not 1 <= len(symbol) <= MAX_SYMBOL_LENGTH or not symbol.isprintable() \
                or any(c in symbol for c in ": "):
            raise TokenError(f"symbol must be 1-{MAX_SYMBOL_LENGTH} printable characters "
                             "without spaces or ':'")
        try:
            decimals = int(decimals)
        except (TypeError, ValueError):
            raise TokenError(f"decimals must be an integer, got {decimals!r}")
        if not 0 <= decimals <= MAX_DECIMALS:
            raise TokenError(f"decimals must be 0-{MAX_DECIMALS}")
        supply = amount(initial_supply, "initial supply", allow_zero=True)
        cap = None if max_supply in (None, "") else amount(max_supply, "max_supply")
        if cap is not None and supply > cap:
            raise TokenError("initial supply exceeds max_supply")
        minter = optional_address(mint_authority)
        if supply == 0 and minter is None:
            raise TokenError("a token needs an initial supply or a mint authority")
        account(creator)
        token = NativeToken(address=address, name=name, symbol=symbol, decimals=decimals,
                            creator=str(creator), supply=supply, max_supply=cap,
                            mint_authority=minter,
                            freeze_authority=optional_address(freeze_authority),
                            created_height=int(height))
        self.tokens[address] = token
        self.changed.add(address)
        return token

    def mint(self, token: str, sender: str, value: Any) -> Decimal:
        t = self.require(token)
        if t.mint_authority is None:
            raise TokenError(f"{t.symbol} has no mint authority: its supply is fixed")
        if not same(t.mint_authority, sender):
            raise TokenError(f"only {t.symbol}'s mint authority may mint")
        v = amount(value)
        if t.max_supply is not None and t.supply + v > t.max_supply:
            raise TokenError(f"minting {v} would exceed {t.symbol}'s max supply {t.max_supply}")
        t.supply += v
        self.changed.add(t.address)
        return v

    def burn(self, token: str, value: Any) -> Decimal:
        """Reduce the supply (the caller debits the burner's balance)."""
        t = self.require(token)
        v = amount(value)
        if v > t.supply:
            raise TokenError("cannot burn more than the supply")
        t.supply -= v
        self.changed.add(t.address)
        return v

    def set_authority(self, token: str, sender: str, kind: str, new: Any) -> Optional[str]:
        t = self.require(token)
        kind = str(kind).lower()
        if kind not in ("mint", "freeze"):
            raise TokenError("authority must be 'mint' or 'freeze'")
        attr = f"{kind}_authority"
        current = getattr(t, attr)
        if current is None:
            raise TokenError(f"{t.symbol} has no {kind} authority (renounced or never set)")
        if not same(current, sender):
            raise TokenError(f"only {t.symbol}'s {kind} authority may change it")
        new_address = optional_address(new)
        setattr(t, attr, new_address)
        self.changed.add(t.address)
        return new_address

    def freeze(self, token: str, sender: str, holder: str, frozen: bool) -> None:
        t = self.require(token)
        if t.freeze_authority is None:
            raise TokenError(f"{t.symbol} has no freeze authority")
        if not same(t.freeze_authority, sender):
            raise TokenError(f"only {t.symbol}'s freeze authority may freeze or thaw")
        key = (t.address, account(holder))
        if frozen:
            self.frozen.add(key)
        else:
            self.frozen.discard(key)

    # ── allowances ──────────────────────────────────────────────────────

    def approve(self, token: str, owner: str, spender: str, value: Any) -> Decimal:
        t = self.require(token)
        owner_id, spender_id = account(owner), account(spender)
        if owner_id == spender_id:
            raise TokenError("cannot approve yourself")
        v = amount(value, allow_zero=True)
        key = (t.address, owner_id, spender_id)
        if v == 0:
            if self.allowances.pop(key, None) is not None:
                self._count(owner_id, -1)
            return v
        if key not in self.allowances:
            if self.allowance_counts.get(owner_id, 0) >= MAX_ALLOWANCES_PER_OWNER:
                raise TokenError(f"an account may hold at most {MAX_ALLOWANCES_PER_OWNER} "
                                 "allowances; revoke one first")
            self._count(owner_id, +1)
        self.allowances[key] = v
        return v

    def _count(self, owner_id: str, delta: int) -> None:
        n = self.allowance_counts.get(owner_id, 0) + delta
        if n > 0:
            self.allowance_counts[owner_id] = n
        else:
            self.allowance_counts.pop(owner_id, None)

    def set_allowance(self, token: str, owner: str, spender: str, value: Decimal) -> None:
        """Set an allowance the EVM interface already validated (its ``approve`` /
        ``transferFrom``, when the block's EVM section is accepted)."""
        key = (str(token).lower(), account(owner), account(spender))
        existed = key in self.allowances
        if value:
            self.allowances[key] = Decimal(value)
            if not existed:
                self._count(key[1], +1)
        elif existed:
            del self.allowances[key]
            self._count(key[1], -1)

    def spend_allowance(self, token: str, owner: str, spender: str, value: Decimal) -> Decimal:
        key = (str(token).lower(), account(owner), account(spender))
        have = self.allowances.get(key, ZERO)
        if have < value:
            raise TokenError(f"allowance {have} is less than {value}")
        left = have - value
        if left == 0:
            del self.allowances[key]
            self._count(key[1], -1)
        else:
            self.allowances[key] = left
        return left

    # ── commitment ──────────────────────────────────────────────────────

    def canonical(self) -> Dict[str, Any]:
        return {
            "tokens": {a: [t.name, t.symbol, t.decimals, t.creator, str(t.supply),
                           None if t.max_supply is None else str(t.max_supply),
                           t.mint_authority, t.freeze_authority, t.created_height]
                       for a, t in sorted(self.tokens.items())},
            "allowances": [[t, o, s, str(v)] for (t, o, s), v in sorted(self.allowances.items())],
            "frozen": [list(k) for k in sorted(self.frozen)],
        }

    def state_hash(self) -> bytes:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()
