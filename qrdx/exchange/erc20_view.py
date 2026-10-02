"""
Native tokens as ERC-20s for web3 wallets — the read view (docs/NATIVE_TOKENS.md §6).

A wallet that adds a token by its address calls ``name()``, ``symbol()``, ``decimals()``,
``totalSupply()``, ``balanceOf(owner)`` and ``allowance(owner, spender)`` with ``eth_call``. For
a native token's address, ``eth_call`` answers them here — from the token registry and the token
ledger, the state the exchange moves — rather than by running EVM code (there is none there).

* Read-only and RPC-only: a contract cannot call it, and an EVM transaction sent to a native
  token's address is refused at admission (it would run as a no-op and still cost gas). Native
  tokens move with exchange transactions (``TOKEN_TRANSFER``, ``TOKEN_APPROVE``, …).
* ``decimals()`` is the token's declared decimals and amounts are in its base units
  (10^-decimals), rounded down: the ledger counts 1e-18 for every token, so dust below a
  token's decimals is not shown.
"""
from __future__ import annotations

from decimal import ROUND_FLOOR, Decimal
from typing import Optional

SELECTORS = {
    "06fdde03": "name",
    "95d89b41": "symbol",
    "313ce567": "decimals",
    "18160ddd": "totalSupply",
    "70a08231": "balanceOf",
    "dd62ed3e": "allowance",
}
WRITE_SELECTORS = {
    "a9059cbb": "transfer",
    "095ea7b3": "approve",
    "23b872dd": "transferFrom",
}
MOVE_HINT = ("native tokens move with exchange transactions (TOKEN_TRANSFER, TOKEN_APPROVE, "
             "TOKEN_TRANSFER_FROM — `qrdx-wallet token`), not EVM calls")


class NativeTokenCallError(Exception):
    """An eth_call to a native token that cannot be answered — it reverts with this reason."""


def native_token(address) -> Optional[object]:
    """The registered native token at ``address`` (any case), or None."""
    if not address:
        return None
    from .state_manager import ExchangeStateManager
    if isinstance(address, (bytes, bytearray)):
        address = "0x" + bytes(address).hex()
    return ExchangeStateManager.get_instance().tokens.get(str(address))


def _uint(value: int) -> bytes:
    return int(value).to_bytes(32, "big")


def _string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uint(32) + _uint(len(raw)) + raw + b"\0" * ((-len(raw)) % 32)


def revert_data(reason: str) -> bytes:
    """``Error(string)`` — what Solidity's ``revert(reason)`` returns."""
    return bytes.fromhex("08c379a0") + _string(reason)


def base_units(amount: Decimal, decimals: int) -> int:
    """An amount in the token's base units, rounded down (never negative)."""
    if amount <= 0:
        return 0
    return int((Decimal(amount) * (Decimal(10) ** decimals)).to_integral_value(rounding=ROUND_FLOOR))


def _address(args: bytes, index: int) -> str:
    word = args[32 * index:32 * (index + 1)]
    if len(word) != 32 or any(word[:12]):
        raise NativeTokenCallError("malformed address argument")
    return "0x" + word[12:].hex()


async def call(db, to, data: bytes) -> Optional[bytes]:
    """The ABI-encoded answer to an ``eth_call`` of ``data`` on a native token at ``to`` —
    or None when ``to`` is not a native token (run the EVM as usual). Raises
    NativeTokenCallError for a write or an unknown function."""
    token = native_token(to)
    if token is None:
        return None
    data = bytes(data or b"")
    selector, args = data[:4].hex(), data[4:]
    fn = SELECTORS.get(selector)
    if fn is None:
        if selector in WRITE_SELECTORS:
            raise NativeTokenCallError(f"{WRITE_SELECTORS[selector]}: {MOVE_HINT}")
        raise NativeTokenCallError(f"{token.symbol} is a native token; it answers name, "
                                   "symbol, decimals, totalSupply, balanceOf and allowance")
    if fn == "name":
        return _string(token.name)
    if fn == "symbol":
        return _string(token.symbol)
    if fn == "decimals":
        return _uint(token.decimals)
    if fn == "totalSupply":
        return _uint(base_units(token.supply, token.decimals))
    if fn == "balanceOf":
        holder = _address(args, 0)
        balance = await db.get_token_balance(token.address, holder)
        return _uint(base_units(Decimal(balance), token.decimals))
    from .state_manager import ExchangeStateManager
    registry = ExchangeStateManager.get_instance().tokens
    allowance = registry.allowance(token.address, _address(args, 0), _address(args, 1))
    return _uint(base_units(allowance, token.decimals))


def refuse_transaction_to(to) -> Optional[str]:
    """Why an EVM transaction to ``to`` must not be admitted, or None. A native token's
    address has no EVM code: a wallet's "send token" there would run as a no-op that still
    costs gas, while the tokens never move."""
    token = native_token(to)
    if token is None:
        return None
    return (f"{to} is the native token {token.symbol}: an EVM transaction cannot move it — "
            f"{MOVE_HINT}")
