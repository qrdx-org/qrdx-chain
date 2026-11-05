"""
Native tokens (deploy, transfers, mint and burn, authorities and extensions) and native NFTs,
and the protocol's holder addresses.

These are ExchangeStateManager's methods, written as functions of the manager (``self``) and
bound to it under the same names in qrdx/exchange/state_manager.py. They are here only to keep
that file to a size one can read: read them as the class's.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Dict, List, Tuple

from ..nfts import NftError, token_id as nft_token_id
from ..tokens import (
    TokenError,
    account as token_account,
    amount as token_amount,
    is_native_asset,
    memo as token_memo,
)
from ..transactions import (
    EXCHANGE_GAS_COSTS,
    ExchangeOpType,
    ExchangeTransaction,
)
from .common import (
    ZERO,
    ExchangeExecResult,
    logger,
)

if TYPE_CHECKING:
    from ..state_manager import ExchangeStateManager


def derive_token_address(sender: str, nonce: int, symbol: str) -> str:
    """Deterministic QRC-20 token address from the deploy tx (consensus-stable:
    every node derives the same address from the same tx)."""
    seed = f"{sender}:{int(nonce)}:{symbol}".encode()
    return "0x" + hashlib.blake2b(seed, digest_size=20).hexdigest()


def pool_holder_address(pool_id: str) -> str:
    """Deterministic token-ledger holder address for an AMM pool's reserves
    (Phase E spot). Liquidity providers' tokens move INTO this holder; swap
    outputs move OUT of it — so pool reserves are real, conserved token balances."""
    return "0xPOOL" + hashlib.blake2b(f"pool:{pool_id}".encode(), digest_size=18).hexdigest()


def orderbook_escrow_address(pair: str) -> str:
    """Deterministic token-ledger holder for a CLOB book's RESTING-order funds
    (Phase E spot). A placed limit order's funds move INTO this holder; matched
    fills + cancels move OUT — so resting orders are backed by real, conserved
    token balances (the same pattern as ``pool_holder_address`` for AMM reserves)."""
    return "0xCLOB" + hashlib.blake2b(f"book:{pair}".encode(), digest_size=18).hexdigest()


def _settle_token_move(
    self: ExchangeStateManager,
    frm: str,
    to: str,
    token: str,
    amount: Decimal,
    *,
    covered: bool = False,
    release: bool = False,
) -> None:
    """Phase E spot: record a token move frm→to as paired deltas (no-op for 0). Raises if
    ``frm`` — a trader, a pool's holder or a book's escrow — cannot cover it, so the
    enclosing operation fails whole (see ``_atomic``) instead of the ledger flush clamping a
    debit while its credit lands, which would mint the difference.

    ``covered``: ``frm`` is a protocol holder paying out what its own records say it holds
    — a book's escrow what an order escrowed there, a pool's holder its reserves — in the
    block's tick (a fired trigger, a TWAP slice). That record is its cover, not a balance
    loaded for the block: the tick runs on blocks for which no balance is loaded, so a check
    of one would judge the same move differently on different paths.

    ``release``: funds a protocol holder of many accounts' funds hands back to their owner (a
    liquidity withdrawal, an escrow's refund). A paused token still goes back — a pause stops
    trading, not exits; otherwise one token's issuer could lock a pool's other token."""
    if amount and amount > ZERO:
        if not is_native_asset(token):
            if self.tokens.is_frozen(token, frm):
                raise ValueError(f"{frm[:16]}…'s {token[:12]}… balance is frozen")
            t = self.tokens.peek(token)
            if t is not None and t.paused and not release:
                raise ValueError(f"{t.symbol} is paused")
        avail = None if covered else self.available_token_balance(frm, token)
        if covered:
            pass
        elif avail is None:
            # Every debit's balance is loaded with its block (block_processor.
            # preload_token_balances). One that was not is a gap in that list: refuse it
            # rather than let an unchecked debit overdraw the ledger.
            if self.enforce_spot_settlement:
                raise ValueError(
                    f"{frm[:16]}…'s {token[:12]}… balance was not loaded " "for this block"
                )
        elif avail < amount:
            # The protocol's holders (pool reserves, book escrow, the perps clearinghouse)
            # are always held to it; a trader only once spot settlement is enforced (in
            # observe mode their overdraft is logged by the flush, not refused).
            from ...crypto.account_id import is_synthetic_holder

            if self.enforce_spot_settlement or is_synthetic_holder(frm):
                raise ValueError(
                    f"{frm[:16]}… cannot cover {amount} of {token[:12]}… " f"(holds {avail})"
                )
        if is_native_asset(token):
            # Native QRDX lives in account_state: the move rides the balance flush.
            self._record_balance_delta(frm, -amount)
            self._record_balance_delta(to, amount)
        else:
            self._record_token_delta(frm, token, -amount)
            self._record_token_delta(to, token, amount)


def _op_token_deploy(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Deploy a native token (qrdx/exchange/tokens.py): its registry entry — name, symbol,
    display decimals, optional supply cap, mint and freeze authorities — and its initial
    supply, credited to the deployer. The address derives from the deploy transaction, so
    every node agrees on it. A token with no initial supply needs a mint authority (a
    bridge's stablecoin starts at zero and is minted as deposits arrive)."""
    p = tx.params
    symbol = str(p.get("symbol", ""))
    address = self.derive_token_address(tx.sender, tx.nonce, symbol)
    try:
        token = self.tokens.deploy(
            address,
            tx.sender,
            self._current_block_height,
            name=p.get("name", ""),
            symbol=symbol,
            decimals=p.get("decimals", 18),
            initial_supply=p.get("initial_supply", p.get("total_supply", 0)),
            max_supply=p.get("max_supply"),
            mint_authority=p.get("mint_authority"),
            freeze_authority=p.get("freeze_authority"),
            extensions=p,
        )
    except TokenError as e:
        return ExchangeExecResult(success=False, error=f"TOKEN_DEPLOY: {e}")
    if token.supply > 0:
        self._record_token_delta(tx.sender, token.address, token.supply)
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_DEPLOY],
        data={
            "token_address": token.address,
            "symbol": token.symbol,
            "total_supply": str(token.supply),
            "decimals": token.decimals,
            "mint_authority": token.mint_authority,
            "freeze_authority": token.freeze_authority,
            "extensions": token.extensions(),
        },
    )


def _token_move(
    self: ExchangeStateManager, op: str, token: str, frm: str, to: str, value
) -> Tuple[Any, Decimal, Decimal]:
    """Validate a holder-to-holder move of a registered token: the token, the amount, a
    keyable recipient (an unkeyable one would have its credit dropped while the debit
    applied — burning the tokens), the token's transfer rules (paused, non-transferable,
    a frozen sender) and the sender's balance. Returns the token, the amount and the
    transfer fee it withholds. Raises TokenError."""
    t = self.tokens.require(token)
    v = token_amount(value)
    token_account(to)
    fee = self.tokens.check_transfer(t.address, frm, self._current_block_height, v)
    avail = self.available_token_balance(frm, t.address)
    if avail is not None and avail < v:
        if self.enforce_spot_settlement:
            raise TokenError(f"insufficient token balance: need {v}, available {avail}")
        logger.warning(
            "[Phase E observe] %s by %s: amount %s exceeds available %s — would "
            "REJECT once spot settlement is enforced",
            op,
            frm[:20],
            v,
            avail,
        )
    return t, v, fee


def _transfer_with_fee(
    self: ExchangeStateManager, frm: str, to: str, t, v: Decimal, fee: Decimal
) -> None:
    """``to`` receives ``v`` less the fee; the fee is withheld at the token's own address
    (the withdraw authority collects it with TOKEN_WITHDRAW_FEES)."""
    self._settle_token_move(frm, to, t.address, v - fee)
    if fee > ZERO:
        self._settle_token_move(frm, t.address, t.address, fee)


def _op_token_transfer(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Move tokens from the sender to ``to`` in the token ledger (less any transfer fee),
    with an optional ``memo``. ``token_address`` "QRDX" moves native QRDX: how an account
    whose own key is off (or an ECDSA account after the Doomsday Protocol) moves its QRDX,
    signed by its controller."""
    p = tx.params
    to = str(p["to"])
    if is_native_asset(p["token_address"]):
        try:
            note = token_memo(p.get("memo"))
            v = token_amount(p["amount"])
            token_account(to)
            avail = self.available_token_balance(tx.sender, "QRDX")
            if avail is None or avail < v:
                raise ValueError(f"insufficient QRDX: need {v}, available {avail}")
            self._settle_token_move(tx.sender, to, "QRDX", v)
        except (TokenError, ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=f"TOKEN_TRANSFER: {e}")
        data = {"token_address": "QRDX", "to": to, "amount": str(v)}
        if note:
            data["memo"] = note
        return ExchangeExecResult(
            success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_TRANSFER], data=data
        )
    try:
        note = token_memo(p.get("memo"))
        t, v, fee = self._token_move(
            "token_transfer", str(p["token_address"]), tx.sender, to, p["amount"]
        )
        self._transfer_with_fee(tx.sender, to, t, v, fee)
    except (TokenError, ValueError) as e:
        return ExchangeExecResult(success=False, error=f"TOKEN_TRANSFER: {e}")
    data = {"token_address": t.address, "to": to, "amount": str(v)}
    if fee:
        data.update(fee=str(fee), received=str(v - fee))
    if note:
        data["memo"] = note
    return ExchangeExecResult(
        success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_TRANSFER], data=data
    )


def _spend_authority(self: ExchangeStateManager, t, owner: str, spender: str, v: Decimal) -> str:
    """How ``spender`` may move ``owner``'s tokens: as the permanent delegate, as an
    operator (ERC-777), or within an allowance. Raises TokenError if none — and always for
    a protocol holder of many accounts' funds (``holds_pooled_funds``): no one moves those
    but the protocol."""
    from ...crypto.account_id import holds_pooled_funds

    if holds_pooled_funds(owner):
        raise TokenError("tokens the protocol holds for many accounts move only by its rules")
    if self.tokens.is_permanent_delegate(t.address, spender):
        return "permanent_delegate"
    if self.tokens.is_operator(t.address, owner, spender):
        return "operator"
    have = self.tokens.allowance(t.address, owner, spender)
    if have < v:
        raise TokenError(f"allowance {have} is less than {v}")
    return "allowance"


def _op_token_transfer_from(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """The sender moves ``from``'s tokens to ``to``: within the allowance ``from``
    approved (which it consumes), as one of ``from``'s operators, or as the token's
    permanent delegate."""
    p = tx.params
    owner, to = str(p["from"]), str(p["to"])
    try:
        note = token_memo(p.get("memo"))
        t, v, fee = self._token_move(
            "token_transfer_from", str(p["token_address"]), owner, to, p["amount"]
        )
        via = self._spend_authority(t, owner, tx.sender, v)
        self._transfer_with_fee(owner, to, t, v, fee)
    except (TokenError, ValueError) as e:
        return ExchangeExecResult(success=False, error=f"TOKEN_TRANSFER_FROM: {e}")
    data = {"token_address": t.address, "from": owner, "to": to, "amount": str(v), "via": via}
    if via == "allowance":
        data["allowance_left"] = str(self.tokens.spend_allowance(t.address, owner, tx.sender, v))
    if fee:
        data.update(fee=str(fee), received=str(v - fee))
    if note:
        data["memo"] = note
    return ExchangeExecResult(
        success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_TRANSFER_FROM], data=data
    )


def _op_token_mint(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """The mint authority mints ``amount`` to ``to`` (default: itself), within any cap."""
    p = tx.params
    to = str(p.get("to") or tx.sender)
    try:
        token_account(to)
        t = self.tokens.require(str(p["token_address"]))
        v = self.tokens.mint(t.address, tx.sender, p["amount"])
    except TokenError as e:
        return ExchangeExecResult(success=False, error=f"TOKEN_MINT: {e}")
    self._record_token_delta(to, t.address, v)
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_MINT],
        data={
            "token_address": t.address,
            "to": to,
            "amount": str(v),
            "total_supply": str(t.supply),
        },
    )


def _op_token_burn(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """A holder burns ``amount`` of its own balance — or, naming ``from``, an operator or
    the permanent delegate burns another holder's; the supply falls by as much."""
    p = tx.params
    holder = str(p.get("from") or tx.sender)
    try:
        t = self.tokens.require(str(p["token_address"]))
        v = token_amount(p["amount"])
        via = "holder"
        from ...crypto.account_id import holds_pooled_funds

        if holds_pooled_funds(holder):
            raise TokenError("tokens the protocol holds for many accounts move only by its rules")
        if token_account(holder) != token_account(tx.sender):
            if self.tokens.is_permanent_delegate(t.address, tx.sender):
                via = "permanent_delegate"
            elif self.tokens.is_operator(t.address, holder, tx.sender):
                via = "operator"
            else:
                raise TokenError(
                    "only the holder, its operators or the permanent delegate "
                    "may burn its balance"
                )
        if self.tokens.is_frozen(t.address, holder):
            raise TokenError("the holder's balance is frozen")
        avail = self.available_token_balance(holder, t.address)
        if self.enforce_spot_settlement and (avail is None or avail < v):
            raise TokenError(f"insufficient token balance: need {v}, available {avail}")
        self.tokens.burn(t.address, v)
    except TokenError as e:
        return ExchangeExecResult(success=False, error=f"TOKEN_BURN: {e}")
    self._record_token_delta(holder, t.address, -v)
    data = {"token_address": t.address, "amount": str(v), "total_supply": str(t.supply)}
    if via != "holder":
        data.update(**{"from": holder, "via": via})
    return ExchangeExecResult(
        success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_BURN], data=data
    )


def _op_token_approve(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Set ``spender``'s allowance over the sender's tokens to ``amount`` (0 revokes)."""
    p = tx.params
    try:
        t = self.tokens.require(str(p["token_address"]))
        v = self.tokens.approve(t.address, tx.sender, str(p["spender"]), p["amount"])
    except TokenError as e:
        return ExchangeExecResult(success=False, error=f"TOKEN_APPROVE: {e}")
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_APPROVE],
        data={"token_address": t.address, "spender": str(p["spender"]), "amount": str(v)},
    )


def _op_token_set_authority(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """Hand the mint or freeze authority to ``new_authority``, or renounce it (empty) —
    irreversibly."""
    p = tx.params
    try:
        t = self.tokens.require(str(p["token_address"]))
        new = self.tokens.set_authority(
            t.address, tx.sender, str(p["authority"]), p.get("new_authority")
        )
    except TokenError as e:
        return ExchangeExecResult(success=False, error=f"TOKEN_SET_AUTHORITY: {e}")
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_SET_AUTHORITY],
        data={
            "token_address": t.address,
            "authority": str(p["authority"]).lower(),
            "new_authority": new,
        },
    )


def _op_token_freeze(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """TOKEN_FREEZE / TOKEN_THAW: the freeze authority stops (or lets again) ``account``
    moving its balance of the token."""
    p = tx.params
    frozen = tx.op_type == ExchangeOpType.TOKEN_FREEZE
    try:
        t = self.tokens.require(str(p["token_address"]))
        self.tokens.freeze(t.address, tx.sender, str(p["account"]), frozen)
    except TokenError as e:
        return ExchangeExecResult(success=False, error=f"{tx.op_type.name}: {e}")
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[tx.op_type],
        data={"token_address": t.address, "account": str(p["account"]), "frozen": frozen},
    )


def _op_token_update_metadata(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """The metadata authority edits the token's name, symbol, uri and extra fields."""
    p = tx.params
    try:
        ticker = self.ticker_of(str(p.get("token_address", "")))
        if (
            ticker is not None
            and p.get("symbol") not in (None, "")
            and str(p["symbol"]).strip().upper() != ticker
        ):
            # A ticker's token keeps its symbol: renamed, it would show one asset's symbol
            # under another's ticker (docs/HYPERLIQUID_PARITY.md 11).
            raise TokenError(f"the token holds the ticker {ticker}: its symbol stays")
        t = self.tokens.update_metadata(str(p["token_address"]), tx.sender, p)
    except (TokenError, KeyError) as e:
        return ExchangeExecResult(success=False, error=f"TOKEN_UPDATE_METADATA: {e}")
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_UPDATE_METADATA],
        data={
            "token_address": t.address,
            "name": t.name,
            "symbol": t.symbol,
            "uri": t.uri,
            "fields": dict(t.fields),
        },
    )


def _op_token_set_transfer_fee(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """The fee authority sets a new transfer-fee rate and cap, effective
    FEE_UPDATE_DELAY_BLOCKS later."""
    p = tx.params
    try:
        bps, cap, height = self.tokens.set_transfer_fee(
            str(p["token_address"]),
            tx.sender,
            self._current_block_height,
            p["transfer_fee_bps"],
            p.get("max_transfer_fee"),
        )
    except TokenError as e:
        return ExchangeExecResult(success=False, error=f"TOKEN_SET_TRANSFER_FEE: {e}")
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_SET_TRANSFER_FEE],
        data={
            "token_address": str(p["token_address"]).lower(),
            "transfer_fee_bps": bps,
            "max_transfer_fee": None if cap is None else str(cap),
            "from_height": height,
        },
    )


def _op_token_withdraw_fees(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """The withdraw authority moves every withheld transfer fee to ``to`` (default: itself)."""
    p = tx.params
    to = str(p.get("to") or tx.sender)
    try:
        token_account(to)
        t = self.tokens.check_withdraw_authority(str(p["token_address"]), tx.sender)
        withheld = self.available_token_balance(t.address, t.address)
        if withheld is None:
            raise TokenError("the withheld balance was not loaded for this block")
        if withheld > ZERO:
            self._settle_token_move(t.address, to, t.address, withheld)
    except (TokenError, ValueError) as e:
        return ExchangeExecResult(success=False, error=f"TOKEN_WITHDRAW_FEES: {e}")
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_WITHDRAW_FEES],
        data={"token_address": t.address, "to": to, "amount": str(withheld)},
    )


def _op_token_pause(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """TOKEN_PAUSE / TOKEN_RESUME: the pause authority stops (or restarts) every transfer,
    mint and burn of the token — spot and perps moves of it included."""
    p = tx.params
    paused = tx.op_type == ExchangeOpType.TOKEN_PAUSE
    try:
        self.tokens.set_paused(str(p["token_address"]), tx.sender, paused)
    except TokenError as e:
        return ExchangeExecResult(success=False, error=f"{tx.op_type.name}: {e}")
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[tx.op_type],
        data={"token_address": str(p["token_address"]).lower(), "paused": paused},
    )


def _op_token_operator(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """TOKEN_AUTHORIZE_OPERATOR / TOKEN_REVOKE_OPERATOR (ERC-777): the sender lets
    ``operator`` move (and burn) its balance of the token without an allowance — or stops
    it, a default operator included."""
    p = tx.params
    authorized = tx.op_type == ExchangeOpType.TOKEN_AUTHORIZE_OPERATOR
    try:
        self.tokens.set_operator(str(p["token_address"]), tx.sender, str(p["operator"]), authorized)
    except TokenError as e:
        return ExchangeExecResult(success=False, error=f"{tx.op_type.name}: {e}")
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[tx.op_type],
        data={
            "token_address": str(p["token_address"]).lower(),
            "operator": str(p["operator"]),
            "authorized": authorized,
        },
    )


# ── native NFTs (qrdx/exchange/nfts.py) ─────────────────────────────
def derive_collection_address(sender: str, nonce: int, symbol: str) -> str:
    """Deterministic NFT collection address from the creating transaction (a different
    domain from token addresses, so the two never collide)."""
    seed = f"nft-collection:{sender}:{int(nonce)}:{symbol}".encode()
    return "0x" + hashlib.blake2b(seed, digest_size=20).hexdigest()


def _nft(self: ExchangeStateManager, tx: ExchangeTransaction, fn) -> ExchangeExecResult:
    try:
        data = fn(tx.params)
    except (NftError, TokenError) as e:
        return ExchangeExecResult(success=False, error=f"{tx.op_type.name}: {e}")
    return ExchangeExecResult(success=True, gas_used=EXCHANGE_GAS_COSTS[tx.op_type], data=data)


def _op_nft_create_collection(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """Create an NFT collection: name, symbol, uri, optional size cap, royalties, update and
    mint authorities (both the creator unless given), optionally soulbound."""

    def go(p):
        address = self.derive_collection_address(tx.sender, tx.nonce, str(p.get("symbol", "")))
        if self.tokens.get(address) is not None:
            raise NftError(f"{address} is a token")
        return self.nfts.create(address, tx.sender, self._current_block_height, p).summary()

    return self._nft(tx, go)


def _op_nft_mint(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """The collection's mint authority mints the next NFT (or ``token_id``) to ``to``
    (default: itself), with its own uri and name."""

    def go(p):
        to = str(p.get("to") or tx.sender)
        i = self.nfts.mint(
            str(p["collection"]),
            tx.sender,
            to,
            self._current_block_height,
            uri=p.get("uri", ""),
            name=p.get("name", ""),
            tid=p.get("token_id"),
        )
        return {"collection": str(p["collection"]).lower(), "token_id": str(i), "to": to}

    return self._nft(tx, go)


def _op_nft_transfer(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Move an NFT to ``to``: by its owner, its approved account or an operator of the
    owner's (``from`` names the owner when the sender is not it)."""

    def go(p):
        note = token_memo(p.get("memo"))
        frm = str(p.get("from") or tx.sender)
        self.nfts.transfer(str(p["collection"]), p["token_id"], tx.sender, frm, str(p["to"]))
        out = {
            "collection": str(p["collection"]).lower(),
            "token_id": str(nft_token_id(p["token_id"])),
            "from": frm,
            "to": str(p["to"]),
        }
        if note:
            out["memo"] = note
        return out

    return self._nft(tx, go)


def _op_nft_burn(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    def go(p):
        owner = self.nfts.item(str(p["collection"]), p["token_id"]).owner
        self.nfts.burn(str(p["collection"]), p["token_id"], tx.sender)
        return {
            "collection": str(p["collection"]).lower(),
            "token_id": str(nft_token_id(p["token_id"])),
            "owner": owner,
        }

    return self._nft(tx, go)


def _op_nft_approve(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """The owner (or an operator) approves one account for one NFT ("" clears it)."""

    def go(p):
        spender = self.nfts.approve(
            str(p["collection"]), p["token_id"], tx.sender, p.get("spender")
        )
        return {
            "collection": str(p["collection"]).lower(),
            "token_id": str(nft_token_id(p["token_id"])),
            "spender": spender,
        }

    return self._nft(tx, go)


def _op_nft_set_approval_for_all(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """The sender approves (``approved``, default true) or revokes an operator for all its
    NFTs in the collection."""

    def go(p):
        approved = p.get("approved", True)
        approved = (
            str(approved).lower() in ("1", "true", "yes")
            if isinstance(approved, str)
            else bool(approved)
        )
        self.nfts.set_operator(str(p["collection"]), tx.sender, str(p["operator"]), approved)
        return {
            "collection": str(p["collection"]).lower(),
            "operator": str(p["operator"]),
            "approved": approved,
        }

    return self._nft(tx, go)


def _op_nft_update(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    return self._nft(tx, lambda p: self.nfts.update(str(p["collection"]), tx.sender, p))


def _op_nft_set_authority(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    def go(p):
        new = self.nfts.set_authority(
            str(p["collection"]), tx.sender, str(p["authority"]), p.get("new_authority")
        )
        return {
            "collection": str(p["collection"]).lower(),
            "authority": str(p["authority"]).lower(),
            "new_authority": new,
        }

    return self._nft(tx, go)


def token_registry_ops(self: ExchangeStateManager) -> List[Dict[str, Any]]:
    """The registry rows of the tokens this block deployed or changed (supply,
    authorities), for the DB mirror (``token_registry``)."""
    return [
        self.tokens.tokens[a].summary()
        for a in sorted(self.tokens.changed)
        if a in self.tokens.tokens
    ]
