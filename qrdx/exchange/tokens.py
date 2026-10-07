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

**Extensions** — like SPL Token-2022, a token opts into more behaviour when it is deployed
(docs/NATIVE_TOKENS.md §7):

* **metadata** — a ``uri`` and up to 16 extra ``fields``, with a metadata (update) authority
  that may change the name, symbol, uri and fields;
* **transfer fee** — ``transfer_fee_bps`` of every holder-to-holder transfer, capped at
  ``max_transfer_fee``, withheld from the amount and held by the token's own address until the
  withdraw authority withdraws it; the fee authority may change the rate, which takes effect
  ``FEE_UPDATE_DELAY_BLOCKS`` later so nobody is surprised mid-transfer;
* **non-transferable** — soulbound: minted and burned, never moved between holders;
* **default-frozen** — every account starts frozen until the freeze authority thaws it (KYC'd
  assets); the deployer starts thawed;
* **permanent delegate** — an account that may transfer or burn anyone's balance (a
  regulated issuer's clawback), without an allowance;
* **pausable** — a pause authority may stop every transfer, mint and burn of the token;
* **operators** (ERC-777) — a holder may authorize operators that move its balance without an
  allowance; ``default_operators`` set at deployment are operators for every holder until that
  holder revokes them.

Transfer-fee and non-transferable tokens cannot be pooled or traded on an order book (spot
moves are exact; a fee would break the pool's accounting).

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
from dataclasses import dataclass, field
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Set, Tuple

ZERO = Decimal(0)
AMOUNT_QUANTUM = Decimal("1e-18")
MAX_DECIMALS = 18
MAX_NAME_LENGTH = 64
MAX_SYMBOL_LENGTH = 16
# Non-zero allowances one owner may hold across all tokens: approvals are state every node
# carries, so they are bounded like resting orders are.
MAX_ALLOWANCES_PER_OWNER = 256
MAX_OPERATORS_PER_HOLDER = 64        # authorized operators, across all tokens
MAX_DEFAULT_OPERATORS = 8
MAX_URI_LENGTH = 256
MAX_METADATA_FIELDS = 16
MAX_FIELD_KEY_LENGTH = 32
MAX_FIELD_VALUE_LENGTH = 256
MAX_MEMO_BYTES = 256
MAX_FEE_BPS = 10_000
FEE_UPDATE_DELAY_BLOCKS = 100        # a new transfer-fee rate applies this many blocks later
AUTHORITIES = ("mint", "freeze", "metadata", "fee", "withdraw", "pause", "permanent_delegate")


NATIVE_ASSET = "QRDX"          # native QRDX, as spot names it (pools, books, swaps)


def is_native_asset(asset: Any) -> bool:
    return isinstance(asset, str) and asset.strip().upper() == NATIVE_ASSET


def canonical_asset(value: Any, registry: "TokenRegistry" = None) -> str:
    """How spot names an asset: "QRDX" for native QRDX (any casing), a registered token's
    canonical lowercase address, anything else as given."""
    text = str(value).strip()
    if text.upper() == NATIVE_ASSET:
        return NATIVE_ASSET
    if registry is not None:
        token = registry.get(text)
        if token is not None:
            return token.address
    return text


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
    # ── extensions (none set = a plain token, hashed exactly as before they existed) ──
    uri: str = ""
    fields: Dict[str, str] = field(default_factory=dict)
    metadata_authority: Optional[str] = None
    fee_enabled: bool = False              # the transfer-fee extension
    fee_bps: int = 0
    max_fee: Optional[Decimal] = None      # None = uncapped
    pending_fee: Optional[Tuple[int, Optional[Decimal], int]] = None  # (bps, max, from height)
    fee_authority: Optional[str] = None
    withdraw_authority: Optional[str] = None
    non_transferable: bool = False
    default_frozen: bool = False
    permanent_delegate: Optional[str] = None
    pausable: bool = False
    pause_authority: Optional[str] = None
    paused: bool = False
    default_operators: Tuple[str, ...] = ()

    def fee_config(self, height: int) -> Tuple[int, Optional[Decimal]]:
        """The transfer-fee rate and cap in force at ``height``."""
        if self.pending_fee is not None and height >= self.pending_fee[2]:
            return self.pending_fee[0], self.pending_fee[1]
        return self.fee_bps, self.max_fee

    def transfer_fee(self, value: Decimal, height: int) -> Decimal:
        """What a transfer of ``value`` at ``height`` withholds (rounded up to the ledger's
        unit, then capped)."""
        if not self.fee_enabled:
            return ZERO
        bps, cap = self.fee_config(height)
        if not bps or value <= 0:
            return ZERO
        fee = (value * bps / MAX_FEE_BPS).quantize(AMOUNT_QUANTUM, rounding=ROUND_CEILING)
        if cap is not None:
            fee = min(fee, cap)
        return _trim(min(fee, value))

    def extensions(self) -> Dict[str, Any]:
        """The extensions this token has, JSON-safe."""
        ext: Dict[str, Any] = {}
        if self.uri or self.fields or self.metadata_authority:
            ext["metadata"] = {"uri": self.uri, "fields": dict(sorted(self.fields.items())),
                               "update_authority": self.metadata_authority}
        if self.fee_enabled:
            ext["transfer_fee"] = {
                "bps": self.fee_bps, "max_fee": None if self.max_fee is None else str(self.max_fee),
                "pending": None if self.pending_fee is None else {
                    "bps": self.pending_fee[0],
                    "max_fee": None if self.pending_fee[1] is None else str(self.pending_fee[1]),
                    "from_height": self.pending_fee[2]},
                "fee_authority": self.fee_authority,
                "withdraw_authority": self.withdraw_authority,
                "withheld_at": self.address}
        if self.non_transferable:
            ext["non_transferable"] = True
        if self.default_frozen:
            ext["default_frozen"] = True
        if self.permanent_delegate:
            ext["permanent_delegate"] = self.permanent_delegate
        if self.pausable:
            ext["pausable"] = {"pause_authority": self.pause_authority, "paused": self.paused}
        if self.default_operators:
            ext["default_operators"] = list(self.default_operators)
        return ext

    def summary(self) -> Dict[str, Any]:
        return {
            "token_address": self.address, "name": self.name, "symbol": self.symbol,
            "decimals": self.decimals, "total_supply": str(self.supply),
            "max_supply": None if self.max_supply is None else str(self.max_supply),
            "mint_authority": self.mint_authority, "freeze_authority": self.freeze_authority,
            "creator": self.creator, "created_height": self.created_height,
            "extensions": self.extensions(),
        }

    def canonical_extensions(self) -> Optional[List[Any]]:
        ext = self.extensions()
        if not ext:
            return None
        if "transfer_fee" in ext:
            ext["transfer_fee"].pop("withheld_at")
        return [ext]


class TokenRegistry:
    """Native tokens, allowances and frozen accounts. Pure, deterministic state: every method
    either changes it completely or raises ``TokenError`` having changed nothing."""

    def __init__(self) -> None:
        self.tokens: Dict[str, NativeToken] = {}
        self.allowances: Dict[Tuple[str, str, str], Decimal] = {}   # (token, owner, spender)
        self.frozen: Set[Tuple[str, str]] = set()                    # (token, holder)
        self.thawed: Set[Tuple[str, str]] = set()     # (token, holder) of default-frozen tokens
        self.operators: Set[Tuple[str, str, str]] = set()          # (token, holder, operator)
        self.revoked_defaults: Set[Tuple[str, str, str]] = set()   # default operators revoked
        self.allowance_counts: Dict[str, int] = {}   # owner → non-zero allowances (derived)
        self.operator_counts: Dict[str, int] = {}    # holder → authorized operators (derived)
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
        token = str(token).lower()
        t = self.tokens.get(token)
        default_frozen = t is not None and t.default_frozen
        if not self.frozen and not default_frozen:
            return False
        try:
            key = (token, account(holder))
        except TokenError:
            return False
        if key in self.frozen:
            return True
        # (the token's own address holds its withheld fees: never frozen by default)
        return default_frozen and key not in self.thawed and key[1] != token

    def is_operator(self, token: str, holder: str, operator: str) -> bool:
        """May ``operator`` move ``holder``'s balance of ``token`` (ERC-777): an authorized
        operator, or a default operator the holder has not revoked. A holder is its own."""
        token = str(token).lower()
        h, o = account(holder), account(operator)
        if h == o or (token, h, o) in self.operators:
            return True
        t = self.tokens.get(token)
        return (t is not None and o in {account(d) for d in t.default_operators}
                and (token, h, o) not in self.revoked_defaults)

    def is_permanent_delegate(self, token: str, who: str) -> bool:
        t = self.get(token)
        return t is not None and t.permanent_delegate is not None and same(t.permanent_delegate, who)

    def check_transfer(self, token: str, frm: str, height: int, value: Decimal) -> Decimal:
        """May ``frm`` transfer ``value`` of ``token`` to another holder now? Returns the fee
        it withholds; raises TokenError if the token is paused or non-transferable or the
        sender is frozen."""
        t = self.require(token)
        if t.paused:
            raise TokenError(f"{t.symbol} is paused")
        if t.non_transferable:
            raise TokenError(f"{t.symbol} is non-transferable")
        if value and self.is_frozen(t.address, frm):
            raise TokenError(f"the sender's {t.symbol} balance is frozen")
        return t.transfer_fee(value, height)

    def allowance(self, token: str, owner: str, spender: str) -> Decimal:
        return self.allowances.get((str(token).lower(), account(owner), account(spender)), ZERO)

    # ── lifecycle ───────────────────────────────────────────────────────

    def deploy(self, address: str, creator: str, height: int, *, name: Any, symbol: Any,
               decimals: Any = MAX_DECIMALS, initial_supply: Any = 0, max_supply: Any = None,
               mint_authority: Any = None, freeze_authority: Any = None,
               extensions: Optional[Dict[str, Any]] = None) -> NativeToken:
        address = str(address).lower()
        if address in self.tokens:
            raise TokenError(f"token {address} already exists")
        name, symbol = _name(name), _symbol(symbol)
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
        _apply_extensions(token, dict(extensions or {}), str(creator))
        self.tokens[address] = token
        if token.default_frozen:
            self.thawed.add((address, account(creator)))     # the deployer starts thawed
        self.changed.add(address)
        return token

    def _live(self, token: str, what: str) -> NativeToken:
        t = self.require(token)
        if t.paused:
            raise TokenError(f"{t.symbol} is paused: no {what}")
        return t

    def mint(self, token: str, sender: str, value: Any) -> Decimal:
        t = self._live(token, "minting")
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
        t = self._live(token, "burning")
        v = amount(value)
        if v > t.supply:
            raise TokenError("cannot burn more than the supply")
        t.supply -= v
        self.changed.add(t.address)
        return v

    def set_authority(self, token: str, sender: str, kind: str, new: Any) -> Optional[str]:
        t = self.require(token)
        kind = str(kind).lower()
        if kind not in AUTHORITIES:
            raise TokenError(f"authority must be one of {', '.join(AUTHORITIES)}")
        attr = kind if kind == "permanent_delegate" else f"{kind}_authority"
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
            self.thawed.discard(key)
        else:
            self.frozen.discard(key)
            if t.default_frozen:
                self.thawed.add(key)

    # ── extensions ──────────────────────────────────────────────────────

    def update_metadata(self, token: str, sender: str, params: Dict[str, Any]) -> NativeToken:
        """The metadata authority changes the name, symbol, uri and/or fields (a field set to
        None or "" is removed)."""
        t = self.require(token)
        if t.metadata_authority is None:
            raise TokenError(f"{t.symbol}'s metadata is immutable")
        if not same(t.metadata_authority, sender):
            raise TokenError(f"only {t.symbol}'s metadata authority may update it")
        name = _name(params["name"]) if params.get("name") not in (None, "") else t.name
        symbol = _symbol(params["symbol"]) if params.get("symbol") not in (None, "") else t.symbol
        uri = _uri(params["uri"]) if "uri" in params else t.uri
        fields = dict(t.fields)
        for k, v in dict(params.get("fields") or {}).items():
            if v is None or v == "":
                fields.pop(str(k), None)
            else:
                fields[str(k)] = str(v)
        t.name, t.symbol, t.uri, t.fields = name, symbol, uri, _fields(fields)
        self.changed.add(t.address)
        return t

    def set_transfer_fee(self, token: str, sender: str, height: int, bps: Any,
                         max_fee: Any = None) -> Tuple[int, Optional[Decimal], int]:
        """The fee authority sets a new rate and cap; it applies FEE_UPDATE_DELAY_BLOCKS
        later (until then the current one does)."""
        t = self.require(token)
        if not t.fee_enabled:
            raise TokenError(f"{t.symbol} has no transfer fee")
        if t.fee_authority is None or not same(t.fee_authority, sender):
            raise TokenError(f"only {t.symbol}'s fee authority may change its fee")
        t.fee_bps, t.max_fee = t.fee_config(height)          # a due pending rate is now current
        pending = (_bps(bps), _cap(max_fee), int(height) + FEE_UPDATE_DELAY_BLOCKS)
        t.pending_fee = pending
        self.changed.add(t.address)
        return pending

    def check_withdraw_authority(self, token: str, sender: str) -> NativeToken:
        t = self.require(token)
        if not t.fee_enabled:
            raise TokenError(f"{t.symbol} has no transfer fee")
        if t.withdraw_authority is None or not same(t.withdraw_authority, sender):
            raise TokenError(f"only {t.symbol}'s withdraw authority may withdraw its fees")
        return t

    def set_paused(self, token: str, sender: str, paused: bool) -> None:
        t = self.require(token)
        if not t.pausable:
            raise TokenError(f"{t.symbol} is not pausable")
        if t.pause_authority is None or not same(t.pause_authority, sender):
            raise TokenError(f"only {t.symbol}'s pause authority may pause or resume it")
        if t.paused == paused:
            raise TokenError(f"{t.symbol} is already {'paused' if paused else 'running'}")
        t.paused = paused
        self.changed.add(t.address)

    def set_operator(self, token: str, holder: str, operator: str, authorized: bool) -> None:
        """ERC-777 ``authorizeOperator`` / ``revokeOperator``."""
        t = self.require(token)
        h, o = account(holder), account(operator)
        if h == o:
            raise TokenError("a holder is always its own operator")
        key = (t.address, h, o)
        is_default = o in {account(d) for d in t.default_operators}
        if authorized:
            if is_default:
                self.revoked_defaults.discard(key)
            elif key not in self.operators:
                if self.operator_counts.get(h, 0) >= MAX_OPERATORS_PER_HOLDER:
                    raise TokenError(f"an account may authorize at most "
                                     f"{MAX_OPERATORS_PER_HOLDER} operators")
                self.operators.add(key)
                self.operator_counts[h] = self.operator_counts.get(h, 0) + 1
        else:
            if is_default:
                self.revoked_defaults.add(key)
            if key in self.operators:
                self.operators.discard(key)
                n = self.operator_counts.get(h, 0) - 1
                if n > 0:
                    self.operator_counts[h] = n
                else:
                    self.operator_counts.pop(h, None)

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
        # Extensions and the newer sets appear only when used, so a chain that uses none of
        # them commits exactly what it did before they existed.
        out = {
            "tokens": {a: [t.name, t.symbol, t.decimals, t.creator, str(t.supply),
                           None if t.max_supply is None else str(t.max_supply),
                           t.mint_authority, t.freeze_authority, t.created_height]
                       + (t.canonical_extensions() or [])
                       for a, t in sorted(self.tokens.items())},
            "allowances": [[t, o, s, str(v)] for (t, o, s), v in sorted(self.allowances.items())],
            "frozen": [list(k) for k in sorted(self.frozen)],
        }
        if self.thawed:
            out["thawed"] = [list(k) for k in sorted(self.thawed)]
        if self.operators:
            out["operators"] = [list(k) for k in sorted(self.operators)]
        if self.revoked_defaults:
            out["revoked_defaults"] = [list(k) for k in sorted(self.revoked_defaults)]
        return out

    def state_hash(self) -> bytes:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()


# ── parameter checks shared by deploy and the extension updates ───────────

def _trim(d: Decimal) -> Decimal:
    """``d`` without trailing zeros (and never in exponent form)."""
    n = d.normalize()
    return n if n.as_tuple().exponent <= 0 else n.quantize(Decimal(1))


def _name(value: Any) -> str:
    name = str(value).strip()
    if not 1 <= len(name) <= MAX_NAME_LENGTH:
        raise TokenError(f"name must be 1-{MAX_NAME_LENGTH} characters")
    return name


def _symbol(value: Any) -> str:
    symbol = str(value).strip()
    if not 1 <= len(symbol) <= MAX_SYMBOL_LENGTH or not symbol.isprintable() \
            or any(c in symbol for c in ": "):
        raise TokenError(f"symbol must be 1-{MAX_SYMBOL_LENGTH} printable characters "
                         "without spaces or ':'")
    return symbol


def _uri(value: Any) -> str:
    uri = "" if value is None else str(value).strip()
    if len(uri) > MAX_URI_LENGTH or not uri.isprintable():
        raise TokenError(f"uri must be at most {MAX_URI_LENGTH} printable characters")
    return uri


def _fields(fields: Dict[str, Any]) -> Dict[str, str]:
    if len(fields) > MAX_METADATA_FIELDS:
        raise TokenError(f"at most {MAX_METADATA_FIELDS} metadata fields")
    out = {}
    for k, v in fields.items():
        k, v = str(k).strip(), str(v)
        if not 1 <= len(k) <= MAX_FIELD_KEY_LENGTH or not k.isprintable():
            raise TokenError(f"metadata field names must be 1-{MAX_FIELD_KEY_LENGTH} printable "
                             "characters")
        if len(v) > MAX_FIELD_VALUE_LENGTH or not v.isprintable():
            raise TokenError(f"metadata field values must be at most {MAX_FIELD_VALUE_LENGTH} "
                             "printable characters")
        out[k] = v
    return dict(sorted(out.items()))


def _bps(value: Any) -> int:
    try:
        bps = int(value)
    except (TypeError, ValueError):
        raise TokenError(f"transfer_fee_bps must be an integer, got {value!r}")
    if not 0 <= bps <= MAX_FEE_BPS:
        raise TokenError(f"transfer_fee_bps must be 0-{MAX_FEE_BPS}")
    return bps


def _cap(value: Any) -> Optional[Decimal]:
    return None if value in (None, "") else amount(value, "max_transfer_fee", allow_zero=True)


def _flag(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _authority(params: Dict[str, Any], key: str, default: str) -> Optional[str]:
    """An extension's authority: as given (empty = none), or the deployer when not given."""
    return optional_address(params[key]) if key in params else default


def memo(value: Any) -> Optional[str]:
    """A transfer's memo (Solidity's ``data``): at most MAX_MEMO_BYTES of UTF-8."""
    if value in (None, ""):
        return None
    text = str(value)
    if len(text.encode("utf-8")) > MAX_MEMO_BYTES:
        raise TokenError(f"memo must be at most {MAX_MEMO_BYTES} bytes")
    return text


def _apply_extensions(t: NativeToken, p: Dict[str, Any], creator: str) -> None:
    """Set a new token's extensions from its deploy parameters (docs/NATIVE_TOKENS.md §7)."""
    if any(k in p for k in ("uri", "metadata", "metadata_authority")):
        t.uri = _uri(p.get("uri"))
        t.fields = _fields(dict(p.get("metadata") or {}))
        t.metadata_authority = _authority(p, "metadata_authority", creator)
    if "transfer_fee_bps" in p:
        t.fee_enabled = True
        t.fee_bps = _bps(p["transfer_fee_bps"])
        t.max_fee = _cap(p.get("max_transfer_fee"))
        t.fee_authority = _authority(p, "fee_authority", creator)
        t.withdraw_authority = _authority(p, "withdraw_authority", creator)
    t.non_transferable = _flag(p.get("non_transferable", False))
    if t.non_transferable and t.fee_enabled:
        raise TokenError("a non-transferable token cannot charge a transfer fee")
    t.default_frozen = _flag(p.get("default_frozen", False))
    if t.default_frozen and t.freeze_authority is None:
        raise TokenError("a default-frozen token needs a freeze authority to thaw accounts")
    t.permanent_delegate = optional_address(p.get("permanent_delegate"))
    t.pausable = _flag(p.get("pausable", False))
    if t.pausable:
        t.pause_authority = _authority(p, "pause_authority", creator)
    ops = p.get("default_operators") or []
    if isinstance(ops, str):
        ops = [o for o in ops.split(",") if o.strip()]
    if len(ops) > MAX_DEFAULT_OPERATORS:
        raise TokenError(f"at most {MAX_DEFAULT_OPERATORS} default operators")
    seen, out = set(), []
    for o in ops:
        o = optional_address(o)
        if o is None or account(o) in seen:
            continue
        seen.add(account(o))
        out.append(o)
    t.default_operators = tuple(out)
