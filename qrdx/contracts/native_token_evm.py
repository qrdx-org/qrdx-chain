"""
Native tokens inside the EVM: every native token (qrdx/exchange/tokens.py) is an ERC-20 at its
own address, backed by the one native ledger (docs/NATIVE_TOKENS.md §6).

A call to a native token's address runs ``native_token_precompile``: ``name``, ``symbol``,
``decimals``, ``totalSupply``, ``balanceOf``, ``allowance`` read the registry and the ledger;
``transfer``, ``approve`` and ``transferFrom`` move the same balances and set the same
allowances the exchange's TOKEN_* operations do, with ERC-20 ``Transfer`` / ``Approval`` logs.
A wallet's "send token" therefore just works, and contracts can hold and move native tokens.

Amounts are in the token's base units, 10^-decimals (the ledger counts 1e-18 for every token,
so ``balanceOf`` rounds down: dust below a token's decimals is not shown or movable from here).
A frozen account cannot send, as everywhere. Tokens have no EVM code: ``extcodesize`` is 0 —
call them with the standard interface (which expects return data).

Consistency: a transaction's token moves are journaled on its state (``WorldState``), so a
reverted call frame undoes them; a transaction's net moves join its block's ``EvmSection``
overlay, which later transactions in the block read through, and which is written to the token
ledger (and allowances to the registry) only when the block's EVM section is accepted — a
section that is dropped or rejected leaves nothing behind.
"""
from __future__ import annotations

import contextvars
from decimal import ROUND_FLOOR, Decimal
from typing import Dict, Iterable, Optional, Tuple

from eth.exceptions import Revert
from eth_utils import keccak

from ..crypto.account_id import to_account_id

ZERO = Decimal(0)
MAX_UINT256 = 2 ** 256 - 1

SELECTORS = {
    "06fdde03": "name",
    "95d89b41": "symbol",
    "313ce567": "decimals",
    "18160ddd": "totalSupply",
    "70a08231": "balanceOf",
    "dd62ed3e": "allowance",
    "a9059cbb": "transfer",
    "095ea7b3": "approve",
    "23b872dd": "transferFrom",
}
WRITES = {"transfer", "approve", "transferFrom"}
GAS = {"name": 2_600, "symbol": 2_600, "decimals": 2_600, "totalSupply": 2_600,
       "balanceOf": 2_600, "allowance": 2_600, "transfer": 30_000, "approve": 25_000,
       "transferFrom": 35_000}
GAS_UNKNOWN = 2_600
TRANSFER_TOPIC = int.from_bytes(keccak(text="Transfer(address,address,uint256)"), "big")
APPROVAL_TOPIC = int.from_bytes(keccak(text="Approval(address,address,uint256)"), "big")

# The EVM section being executed (set by evm_block_apply around a block's EVM section).
CURRENT_SECTION: contextvars.ContextVar[Optional["EvmSection"]] = contextvars.ContextVar(
    "qrdx_evm_token_section", default=None)


def _registry():
    from ..exchange.state_manager import ExchangeStateManager
    return ExchangeStateManager.get_instance().tokens


def _uint(value: int) -> bytes:
    return int(value).to_bytes(32, "big")


def _string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uint(32) + _uint(len(raw)) + raw + b"\0" * ((-len(raw)) % 32)


def revert_data(reason: str) -> bytes:
    """``Error(string)`` — what Solidity's ``revert(reason)`` returns."""
    return bytes.fromhex("08c379a0") + _string(reason)


def base_units(amount: Decimal, decimals: int) -> int:
    if amount <= 0:
        return 0
    return int((amount * (Decimal(10) ** decimals)).to_integral_value(rounding=ROUND_FLOOR))


class EvmSection:
    """One block's EVM section, pending until it is accepted: its native token moves and
    approvals, and the receipts (with logs) of its transactions."""

    def __init__(self):
        self.deltas: Dict[Tuple[str, str], Decimal] = {}
        self.allowances: Dict[Tuple[str, str, str], Decimal] = {}
        self.receipts: list = []

    def record(self, **receipt) -> None:
        """A transaction's receipt, as ``eth_getTransactionReceipt`` serves it (status, gas,
        created contract, logs); its index is its position in the section."""
        receipt["tx_index"] = len(self.receipts)
        self.receipts.append(receipt)

    def delta(self, key: Tuple[str, str]) -> Decimal:
        return self.deltas.get(key, ZERO)

    def absorb(self, journal) -> None:
        """A successful transaction's surviving journal entries."""
        for entry in journal:
            if entry[0] == "bal":
                _, token, holder, amount = entry
                key = (token, holder)
                self.deltas[key] = self.deltas.get(key, ZERO) + amount
            else:
                _, token, owner, spender, value = entry
                self.allowances[(token, owner, spender)] = value

    async def commit(self, db) -> None:
        """Write the section's moves to the token ledger and its approvals to the registry."""
        for (token, holder), amount in sorted(self.deltas.items()):
            if amount:
                await db.apply_token_balance_delta(token, holder, amount)
        registry = _registry()
        for (token, owner, spender), value in sorted(self.allowances.items()):
            registry.set_allowance(token, owner, spender, value)
        for r in self.receipts:
            try:
                await _write_receipt(db, r)
            except Exception as e:      # the receipt index is not consensus: never block on it
                import logging
                logging.getLogger(__name__).error("[RECEIPT] %s not recorded: %s",
                                                  r.get("tx_hash"), e)
        self.deltas.clear()
        self.allowances.clear()
        self.receipts.clear()


def _hex32(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).rjust(32, b"\0").hex()
    return "0x" + int(value).to_bytes(32, "big").hex()


async def _write_receipt(db, r) -> None:
    """Receipt and logs into the tables eth_getTransactionReceipt / eth_getLogs read (a node's
    query index, rebuilt with the chain — not consensus state)."""
    conn = db.connection
    await conn.execute("DELETE FROM contract_logs WHERE tx_hash = ?", (r["tx_hash"],))
    await conn.execute(
        "INSERT OR REPLACE INTO contract_transactions "
        "(tx_hash, block_number, tx_index, from_address, to_address, value, gas_limit, "
        "gas_used, gas_price, nonce, input_data, contract_address, status, error_message, "
        "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (r["tx_hash"], int(r["block_number"]), r["tx_index"], r["from"], r.get("to"),
         str(r["value"]), int(r["gas_limit"]), int(r["gas_used"]), str(r["gas_price"]),
         int(r["nonce"]), r.get("data") or b"", r.get("contract_address"),
         1 if r["success"] else 0, r.get("error"), int(r.get("timestamp") or 0)))
    for i, (address, topics, data) in enumerate(r.get("logs") or []):
        topics = list(topics) + [None] * (4 - len(topics))
        await conn.execute(
            "INSERT OR REPLACE INTO contract_logs (tx_hash, block_number, log_index, "
            "contract_address, topic0, topic1, topic2, topic3, data, removed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (r["tx_hash"], int(r["block_number"]), i, "0x" + bytes(address).hex(),
             *[None if t is None else _hex32(t) for t in topics[:4]], bytes(data or b"")))


class TokenWorld:
    """The native tokens one EVM execution sees: the registry (metadata, freezes, allowances),
    the ledger balances it has loaded, and its block's pending section changes."""

    def __init__(self, db, section: Optional[EvmSection] = None, registry=None):
        self.db = db
        self.section = section
        self.registry = registry if registry is not None else _registry()
        self.loaded: Dict[Tuple[str, str], Decimal] = {}

    def token(self, address: bytes):
        return self.registry.get("0x" + bytes(address).hex())

    def is_token(self, address: bytes) -> bool:
        return self.token(address) is not None

    async def load(self, keys: Iterable[Tuple[str, str]]) -> None:
        for token, holder in sorted(keys):
            if (token, holder) not in self.loaded:
                base = Decimal(await self.db.get_token_balance(token, holder))
                pending = self.section.delta((token, holder)) if self.section else ZERO
                self.loaded[(token, holder)] = base + pending

    def balance(self, state, token: str, holder: str) -> Decimal:
        from .evm_world import StateMiss
        key = (token, holder)
        if key not in self.loaded:
            raise StateMiss(tokens=[key])
        value = self.loaded[key]
        for entry in state.token_journal:
            if entry[0] == "bal" and entry[1] == token and entry[2] == holder:
                value += entry[3]
        return value

    def allowance(self, state, token: str, owner: str, spender: str) -> Decimal:
        for entry in reversed(state.token_journal):
            if entry[0] == "allow" and entry[1:4] == (token, owner, spender):
                return entry[4]
        if self.section is not None and (token, owner, spender) in self.section.allowances:
            return self.section.allowances[(token, owner, spender)]
        return self.registry.allowance(token, owner, spender)

    def allowance_slots_used(self, state, owner: str) -> int:
        """Non-zero allowances ``owner`` holds, counting this block's pending approvals."""
        keys = {k for k, v in self.registry.allowances.items() if k[1] == owner and v}
        pending = dict(self.section.allowances) if self.section else {}
        for entry in state.token_journal:
            if entry[0] == "allow":
                pending[entry[1:4]] = entry[4]
        for key, value in pending.items():
            if key[1] != owner:
                continue
            if value:
                keys.add(key)
            else:
                keys.discard(key)
        return len(keys)


def _address_word(data: bytes, index: int) -> bytes:
    word = data[32 * index:32 * (index + 1)]
    if len(word) != 32 or any(word[:12]):
        raise ValueError("malformed address argument")
    return word[12:]


def _uint_word(data: bytes, index: int) -> int:
    word = data[32 * index:32 * (index + 1)]
    if len(word) != 32:
        raise ValueError("missing argument")
    return int.from_bytes(word, "big")


def native_token_precompile(computation):
    """The ERC-20 interface of the native token at the called address."""
    state = computation.state
    tokens: TokenWorld = state.native_tokens
    msg = computation.msg
    token = tokens.token(msg.code_address)
    data = bytes(msg.data_as_bytes)
    fn = SELECTORS.get(data[:4].hex())

    def fail(reason: str):
        computation.output = revert_data(reason)
        raise Revert(reason)

    computation.consume_gas(GAS.get(fn, GAS_UNKNOWN), reason=f"native token {fn or 'call'}")
    if fn is None:
        fail(f"{token.symbol} is a native token: it implements the ERC-20 interface only")
    if msg.storage_address != msg.code_address:
        fail("a native token cannot be called with DELEGATECALL or CALLCODE")
    if msg.value:
        fail("native tokens do not accept QRDX")
    if fn in WRITES and msg.is_static:
        fail("a native token transfer or approval cannot run in a static call")

    address = token.address
    scale = Decimal(10) ** token.decimals
    args = data[4:]
    try:
        if fn == "name":
            computation.output = _string(token.name)
        elif fn == "symbol":
            computation.output = _string(token.symbol)
        elif fn == "decimals":
            computation.output = _uint(token.decimals)
        elif fn == "totalSupply":
            computation.output = _uint(base_units(token.supply, token.decimals))
        elif fn == "balanceOf":
            holder = to_account_id(_address_word(args, 0))
            computation.output = _uint(base_units(tokens.balance(state, address, holder),
                                                  token.decimals))
        elif fn == "allowance":
            owner = to_account_id(_address_word(args, 0))
            spender = to_account_id(_address_word(args, 1))
            computation.output = _uint(min(MAX_UINT256, base_units(
                tokens.allowance(state, address, owner, spender), token.decimals)))
        elif fn == "approve":
            owner = to_account_id(msg.sender)
            spender_raw = _address_word(args, 0)
            spender = to_account_id(spender_raw)
            units = _uint_word(args, 1)
            value = Decimal(units) / scale
            if spender == owner:
                fail("cannot approve yourself")
            current = tokens.allowance(state, address, owner, spender)
            if value and not current:
                from ..exchange.tokens import MAX_ALLOWANCES_PER_OWNER
                if tokens.allowance_slots_used(state, owner) >= MAX_ALLOWANCES_PER_OWNER:
                    fail(f"an account may hold at most {MAX_ALLOWANCES_PER_OWNER} allowances")
            state.token_journal.append(("allow", address, owner, spender, value))
            computation.add_log_entry(msg.code_address, [APPROVAL_TOPIC,
                                                         int.from_bytes(msg.sender, "big"),
                                                         int.from_bytes(spender_raw, "big")],
                                      _uint(units))
            computation.output = _uint(1)
        else:   # transfer / transferFrom
            if fn == "transfer":
                frm_raw, to_raw, units = bytes(msg.sender), _address_word(args, 0), _uint_word(args, 1)
            else:
                frm_raw, to_raw, units = _address_word(args, 0), _address_word(args, 1), _uint_word(args, 2)
            if not any(to_raw):
                fail("transfer to the zero address")
            frm, to = to_account_id(frm_raw), to_account_id(to_raw)
            amount = Decimal(units) / scale
            if fn == "transferFrom":
                spender = to_account_id(msg.sender)
                have = tokens.allowance(state, address, frm, spender)
                if have < amount:
                    fail("insufficient allowance")
            if amount and tokens.registry.is_frozen(address, frm):
                fail(f"the sender's {token.symbol} balance is frozen")
            if tokens.balance(state, address, frm) < amount:
                fail("transfer amount exceeds balance")
            tokens.balance(state, address, to)            # loaded before it is credited
            if fn == "transferFrom":
                state.token_journal.append(("allow", address, frm, spender, have - amount))
            if amount:
                state.token_journal.append(("bal", address, frm, -amount))
                state.token_journal.append(("bal", address, to, amount))
            computation.add_log_entry(msg.code_address, [TRANSFER_TOPIC,
                                                         int.from_bytes(frm_raw, "big"),
                                                         int.from_bytes(to_raw, "big")],
                                      _uint(units))
            computation.output = _uint(1)
    except ValueError as e:
        fail(str(e))
    return computation
