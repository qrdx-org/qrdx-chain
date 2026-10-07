"""
Native tokens inside the EVM: every native token (qrdx/exchange/tokens.py) is an ERC-20 at its
own address, backed by the one native ledger (docs/NATIVE_TOKENS.md §6).

A call to a native token's address runs ``native_token_precompile``: ``name``, ``symbol``,
``decimals``, ``totalSupply``, ``balanceOf``, ``allowance`` read the registry and the ledger;
``transfer``, ``approve`` and ``transferFrom`` move the same balances and set the same
allowances the exchange's TOKEN_* operations do, with ERC-20 ``Transfer`` / ``Approval`` logs.
A wallet's "send token" therefore just works, and contracts can hold and move native tokens.

Every native token is also an ERC-777 token (operators: ``authorizeOperator``,
``revokeOperator``, ``isOperatorFor``, ``defaultOperators``; ``send`` / ``operatorSend`` with
data; ``burn`` / ``operatorBurn``; ``granularity``; ``Sent`` / ``Burned`` /
``AuthorizedOperator`` / ``RevokedOperator`` events — no ``tokensReceived`` hooks), and
reports its metadata uri as ERC-1046's ``tokenURI()`` and its pause state as ``paused()``.
The token's extensions hold here as everywhere (docs/NATIVE_TOKENS.md §7): a paused or
non-transferable token does not move, a transfer fee is withheld at the token's own address
(a second ``Transfer`` log shows it), ``transferFrom`` also accepts the holder's operators and
the token's permanent delegate.

Amounts are in the token's base units, 10^-decimals (the ledger counts 1e-18 for every token,
so ``balanceOf`` rounds down: dust below a token's decimals is not shown or movable from here).
A frozen account cannot send, as everywhere. Tokens have no EVM code; inside the EVM their
address reports a one-byte stub, so Solidity's ``extcodesize`` check passes (``eth_getCode``
still returns empty).

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

def _selector(signature: str) -> str:
    return keccak(text=signature)[:4].hex()


SIGNATURES = {
    "name": "name()", "symbol": "symbol()", "decimals": "decimals()",
    "totalSupply": "totalSupply()", "balanceOf": "balanceOf(address)",
    "allowance": "allowance(address,address)", "transfer": "transfer(address,uint256)",
    "approve": "approve(address,uint256)",
    "transferFrom": "transferFrom(address,address,uint256)",
    # ERC-777
    "granularity": "granularity()", "defaultOperators": "defaultOperators()",
    "isOperatorFor": "isOperatorFor(address,address)",
    "authorizeOperator": "authorizeOperator(address)",
    "revokeOperator": "revokeOperator(address)",
    "send": "send(address,uint256,bytes)",
    "operatorSend": "operatorSend(address,address,uint256,bytes,bytes)",
    "burn": "burn(uint256,bytes)",
    "operatorBurn": "operatorBurn(address,uint256,bytes,bytes)",
    # ERC-1046 metadata, pause state
    "tokenURI": "tokenURI()", "paused": "paused()",
}
SELECTORS = {_selector(sig): fn for fn, sig in SIGNATURES.items()}
WRITES = {"transfer", "approve", "transferFrom", "authorizeOperator", "revokeOperator", "send",
          "operatorSend", "burn", "operatorBurn"}
GAS = {"transfer": 30_000, "approve": 25_000, "transferFrom": 35_000, "send": 30_000,
       "operatorSend": 35_000, "burn": 30_000, "operatorBurn": 35_000,
       "authorizeOperator": 25_000, "revokeOperator": 25_000}
GAS_UNKNOWN = 2_600            # reads, and an unknown selector before it reverts
TRANSFER_TOPIC = int.from_bytes(keccak(text="Transfer(address,address,uint256)"), "big")
APPROVAL_TOPIC = int.from_bytes(keccak(text="Approval(address,address,uint256)"), "big")
SENT_TOPIC = int.from_bytes(keccak(
    text="Sent(address,address,address,uint256,bytes,bytes)"), "big")
BURNED_TOPIC = int.from_bytes(keccak(text="Burned(address,address,uint256,bytes,bytes)"), "big")
AUTHORIZED_TOPIC = int.from_bytes(keccak(text="AuthorizedOperator(address,address)"), "big")
REVOKED_TOPIC = int.from_bytes(keccak(text="RevokedOperator(address,address)"), "big")

# The EVM section being executed (set by evm_block_apply around a block's EVM section).
CURRENT_SECTION: contextvars.ContextVar[Optional["EvmSection"]] = contextvars.ContextVar(
    "qrdx_evm_token_section", default=None)


def _registry():
    from ..exchange.state_manager import ExchangeStateManager
    return ExchangeStateManager.get_instance().tokens


def _nft_registry():
    from ..exchange.state_manager import ExchangeStateManager
    return ExchangeStateManager.get_instance().nfts


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
    """One block's EVM section, pending until it is accepted: its native token moves,
    approvals, operator changes and burns, and the receipts (with logs) of its transactions."""

    def __init__(self):
        self.deltas: Dict[Tuple[str, str], Decimal] = {}
        self.allowances: Dict[Tuple[str, str, str], Decimal] = {}
        self.operators: Dict[Tuple[str, str, str], bool] = {}
        self.burns: Dict[str, Decimal] = {}
        # native NFTs (qrdx/contracts/nft_evm.py)
        self.nft_owners: Dict[Tuple[str, int], Optional[str]] = {}
        self.nft_approvals: Dict[Tuple[str, int], Optional[str]] = {}
        self.nft_operators: Dict[Tuple[str, str, str], bool] = {}
        self.nft_balances: Dict[Tuple[str, str], int] = {}
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
            elif entry[0] == "allow":
                _, token, owner, spender, value = entry
                self.allowances[(token, owner, spender)] = value
            elif entry[0] == "op":
                _, token, holder, operator, authorized = entry
                self.operators[(token, holder, operator)] = authorized
            elif entry[0] == "burn":
                _, token, amount = entry
                self.burns[token] = self.burns.get(token, ZERO) + amount
            elif entry[0] == "nft_own":
                self.nft_owners[(entry[1], entry[2])] = entry[3]
            elif entry[0] == "nft_appr":
                self.nft_approvals[(entry[1], entry[2])] = entry[3]
            elif entry[0] == "nft_op":
                self.nft_operators[(entry[1], entry[2], entry[3])] = entry[4]
            elif entry[0] == "nft_bal":
                key = (entry[1], entry[2])
                self.nft_balances[key] = self.nft_balances.get(key, 0) + entry[3]

    async def commit(self, db) -> None:
        """Write the section's moves to the token ledger and its approvals to the registry."""
        for (token, holder), amount in sorted(self.deltas.items()):
            if amount:
                await db.apply_token_balance_delta(token, holder, amount)
        registry = _registry()
        for (token, owner, spender), value in sorted(self.allowances.items()):
            registry.set_allowance(token, owner, spender, value)
        for (token, holder, operator), authorized in sorted(self.operators.items()):
            try:
                registry.set_operator(token, holder, operator, authorized)
            except Exception as e:      # validated when it ran; never fail an accepted section
                import logging
                logging.getLogger(__name__).error("[TOKENS] operator change dropped: %s", e)
        for token, amount in sorted(self.burns.items()):
            t = registry.get(token)
            if t is not None and amount:
                t.supply -= amount
                registry.changed.add(t.address)
                await db.apply_token_registry_op(t.summary())
        nfts = _nft_registry()
        for (collection, tid), owner in sorted(self.nft_owners.items()):
            if nfts.find(collection, tid) is not None:
                nfts.set_owner(collection, tid, owner)
        for (collection, tid), spender in sorted(self.nft_approvals.items()):
            item = nfts.find(collection, tid)
            if item is not None:
                item.approved = spender
        for (collection, owner, operator), approved in sorted(self.nft_operators.items()):
            try:
                nfts.set_operator(collection, owner, operator, approved)
            except Exception as e:      # validated when it ran; never fail an accepted section
                import logging
                logging.getLogger(__name__).error("[NFT] operator change dropped: %s", e)
        for r in self.receipts:
            try:
                await _write_receipt(db, r)
            except Exception as e:      # the receipt index is not consensus: never block on it
                import logging
                logging.getLogger(__name__).error("[RECEIPT] %s not recorded: %s",
                                                  r.get("tx_hash"), e)
        self.deltas.clear()
        self.allowances.clear()
        self.operators.clear()
        self.burns.clear()
        self.nft_owners.clear()
        self.nft_approvals.clear()
        self.nft_operators.clear()
        self.nft_balances.clear()
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

    def __init__(self, db, section: Optional[EvmSection] = None, registry=None,
                 height: Optional[int] = None, nfts=None):
        self.db = db
        self.section = section
        self.registry = registry if registry is not None else _registry()
        self.nfts = nfts if nfts is not None else _nft_registry()
        self.loaded: Dict[Tuple[str, str], Decimal] = {}
        if height is None:                     # a read-only call: the latest block's rules
            from ..exchange.state_manager import ExchangeStateManager
            height = ExchangeStateManager.get_instance()._current_block_height
        self.height = int(height)

    def token(self, address: bytes):
        return self.registry.get("0x" + bytes(address).hex())

    def is_token(self, address: bytes) -> bool:
        return self.token(address) is not None

    # ── native NFTs: the registry, under the block's and this transaction's changes ──

    def collection(self, address: bytes):
        return self.nfts.get("0x" + bytes(address).hex())

    def is_collection(self, address: bytes) -> bool:
        return self.collection(address) is not None

    def _overlay(self, state, kind: str, key, pending: dict):
        for entry in reversed(state.token_journal):
            if entry[0] == kind and entry[1:1 + len(key)] == key:
                return True, entry[1 + len(key)]
        if key in pending:
            return True, pending[key]
        return False, None

    def nft_owner(self, state, collection: str, tid: int) -> Optional[str]:
        """The owner's account id, or None if the NFT does not exist."""
        found, owner = self._overlay(state, "nft_own", (collection, tid),
                                     self.section.nft_owners if self.section else {})
        if found:
            return owner
        item = self.nfts.find(collection, tid)
        return None if item is None else to_account_id(item.owner)

    def nft_approved(self, state, collection: str, tid: int) -> Optional[str]:
        found, spender = self._overlay(state, "nft_appr", (collection, tid),
                                       self.section.nft_approvals if self.section else {})
        if found:
            return spender
        item = self.nfts.find(collection, tid)
        return None if item is None or item.approved is None else to_account_id(item.approved)

    def nft_operator(self, state, collection: str, owner: str, operator: str) -> bool:
        found, approved = self._overlay(state, "nft_op", (collection, owner, operator),
                                        self.section.nft_operators if self.section else {})
        if found:
            return approved
        return self.nfts.is_operator(collection, owner, operator)

    def nft_balance(self, state, collection: str, owner: str) -> int:
        n = self.nfts.balance(collection, owner)
        if self.section is not None:
            n += self.section.nft_balances.get((collection, owner), 0)
        for entry in state.token_journal:
            if entry[0] == "nft_bal" and entry[1] == collection and entry[2] == owner:
                n += entry[3]
        return n

    def nft_uri(self, collection: str, tid: int) -> str:
        item = self.nfts.find(collection, tid)
        return "" if item is None else item.uri

    def nft_operator_slots_used(self, state, owner: str) -> int:
        keys = {k for k in self.nfts.operators if k[1] == owner}
        pending = dict(self.section.nft_operators) if self.section else {}
        for entry in state.token_journal:
            if entry[0] == "nft_op":
                pending[entry[1:4]] = entry[4]
        for key, approved in pending.items():
            if key[1] != owner:
                continue
            if approved:
                keys.add(key)
            else:
                keys.discard(key)
        return len(keys)

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

    def is_operator(self, state, token: str, holder: str, operator: str) -> bool:
        if holder == operator:
            return True
        for entry in reversed(state.token_journal):
            if entry[0] == "op" and entry[1:4] == (token, holder, operator):
                return entry[4]
        if self.section is not None and (token, holder, operator) in self.section.operators:
            return self.section.operators[(token, holder, operator)]
        return self.registry.is_operator(token, holder, operator)

    def operator_slots_used(self, state, holder: str) -> int:
        """Operators ``holder`` has authorized (not counting default operators), with this
        block's pending changes."""
        keys = {k for k in self.registry.operators if k[1] == holder}
        pending = dict(self.section.operators) if self.section else {}
        for entry in state.token_journal:
            if entry[0] == "op":
                pending[entry[1:4]] = entry[4]
        for key, authorized in pending.items():
            if key[1] != holder:
                continue
            if authorized:
                keys.add(key)
            else:
                keys.discard(key)
        return len(keys)

    def burned(self, state, token: str) -> Decimal:
        """This block's and this transaction's pending burns of ``token``."""
        total = self.section.burns.get(token, ZERO) if self.section else ZERO
        for entry in state.token_journal:
            if entry[0] == "burn" and entry[1] == token:
                total += entry[2]
        return total

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


def _bytes_arg(data: bytes, index: int) -> bytes:
    """A dynamic ``bytes`` argument (its head word is an offset into the arguments)."""
    offset = _uint_word(data, index)
    if offset + 32 > len(data):
        raise ValueError("malformed bytes argument")
    length = int.from_bytes(data[offset:offset + 32], "big")
    if offset + 32 + length > len(data):
        raise ValueError("malformed bytes argument")
    return data[offset + 32:offset + 32 + length]


def _addresses(values) -> bytes:
    out = _uint(32) + _uint(len(values))
    for v in values:
        out += bytes(12) + bytes.fromhex(v[2:])
    return out


def native_token_precompile(computation):
    """The ERC-20 / ERC-777 interface of the native token at the called address."""
    from ..exchange.tokens import TokenError
    state = computation.state
    tokens: TokenWorld = state.native_tokens
    registry = tokens.registry
    msg = computation.msg
    token = tokens.token(msg.code_address)
    data = bytes(msg.data_as_bytes)
    fn = SELECTORS.get(data[:4].hex())

    def fail(reason: str):
        computation.output = revert_data(reason)
        raise Revert(reason)

    computation.consume_gas(GAS.get(fn, GAS_UNKNOWN), reason=f"native token {fn or 'call'}")
    if fn is None:
        fail(f"{token.symbol} is a native token: it implements the ERC-20 and ERC-777 "
             "interfaces only")
    if msg.storage_address != msg.code_address:
        fail("a native token cannot be called with DELEGATECALL or CALLCODE")
    if msg.value:
        fail("native tokens do not accept QRDX")
    if fn in WRITES and msg.is_static:
        fail("a native token transfer or approval cannot run in a static call")

    address = token.address
    scale = Decimal(10) ** token.decimals
    args = data[4:]
    caller_raw = bytes(msg.sender)

    def move(frm_raw: bytes, to_raw: bytes, units: int, operator_raw: Optional[bytes],
             sent: Optional[Tuple[bytes, bytes]] = None) -> None:
        """One transfer, every rule applied: the recipient, the token's transfer rules (and
        fee), the spender's authority when it is not the holder, the balance."""
        if not any(to_raw):
            fail("transfer to the zero address")
        frm, to = to_account_id(frm_raw), to_account_id(to_raw)
        amount = Decimal(units) / scale
        try:
            fee = registry.check_transfer(address, frm, tokens.height, amount)
        except TokenError as e:
            fail(str(e))
        if operator_raw is not None:
            spender = to_account_id(operator_raw)
            if registry.is_permanent_delegate(address, spender) \
                    or tokens.is_operator(state, address, frm, spender):
                pass
            elif sent is not None:                       # ERC-777 operatorSend
                fail("the caller is not an operator for the holder")
            else:
                have = tokens.allowance(state, address, frm, spender)
                if have < amount:
                    fail("insufficient allowance")
                state.token_journal.append(("allow", address, frm, spender, have - amount))
        if tokens.balance(state, address, frm) < amount:
            fail("transfer amount exceeds balance")
        tokens.balance(state, address, to)            # loaded before it is credited
        if fee:
            tokens.balance(state, address, address)    # the fee vault, likewise
        if amount:
            state.token_journal.append(("bal", address, frm, -amount))
            state.token_journal.append(("bal", address, to, amount - fee))
            if fee:
                state.token_journal.append(("bal", address, address, fee))
        net_units = units - (base_units(fee, token.decimals) if fee else 0)
        frm_word, to_word = int.from_bytes(frm_raw, "big"), int.from_bytes(to_raw, "big")
        if sent is not None:
            computation.add_log_entry(msg.code_address, [
                SENT_TOPIC, int.from_bytes(caller_raw, "big"), frm_word, to_word],
                _uint(units) + _sent_tail(sent))
        computation.add_log_entry(msg.code_address, [TRANSFER_TOPIC, frm_word, to_word],
                                  _uint(net_units))
        if fee:
            computation.add_log_entry(msg.code_address, [
                TRANSFER_TOPIC, frm_word, int.from_bytes(msg.code_address, "big")],
                _uint(units - net_units))

    def burn(holder_raw: bytes, units: int, operator: bool, data_: bytes, op_data: bytes) -> None:
        holder = to_account_id(holder_raw)
        amount = Decimal(units) / scale
        if operator:
            spender = to_account_id(caller_raw)
            if not (registry.is_permanent_delegate(address, spender)
                    or tokens.is_operator(state, address, holder, spender)):
                fail("the caller is not an operator for the holder")
        if token.paused:
            fail(f"{token.symbol} is paused")
        if amount and registry.is_frozen(address, holder):
            fail(f"the holder's {token.symbol} balance is frozen")
        if tokens.balance(state, address, holder) < amount:
            fail("burn amount exceeds balance")
        if amount:
            state.token_journal.append(("bal", address, holder, -amount))
            state.token_journal.append(("burn", address, amount))
        holder_word = int.from_bytes(holder_raw, "big")
        computation.add_log_entry(msg.code_address, [
            BURNED_TOPIC, int.from_bytes(caller_raw, "big"), holder_word],
            _uint(units) + _sent_tail((data_, op_data)))
        computation.add_log_entry(msg.code_address, [TRANSFER_TOPIC, holder_word, 0], _uint(units))

    try:
        if fn == "name":
            computation.output = _string(token.name)
        elif fn == "symbol":
            computation.output = _string(token.symbol)
        elif fn == "decimals":
            computation.output = _uint(token.decimals)
        elif fn == "totalSupply":
            supply = token.supply - tokens.burned(state, address)
            computation.output = _uint(base_units(supply, token.decimals))
        elif fn == "balanceOf":
            holder = to_account_id(_address_word(args, 0))
            computation.output = _uint(base_units(tokens.balance(state, address, holder),
                                                  token.decimals))
        elif fn == "allowance":
            owner = to_account_id(_address_word(args, 0))
            spender = to_account_id(_address_word(args, 1))
            computation.output = _uint(min(MAX_UINT256, base_units(
                tokens.allowance(state, address, owner, spender), token.decimals)))
        elif fn == "granularity":
            computation.output = _uint(1)
        elif fn == "defaultOperators":
            computation.output = _addresses([to_account_id(o) for o in token.default_operators])
        elif fn == "isOperatorFor":
            operator = to_account_id(_address_word(args, 0))
            holder = to_account_id(_address_word(args, 1))
            ok = (tokens.is_operator(state, address, holder, operator)
                  or registry.is_permanent_delegate(address, operator))
            computation.output = _uint(1 if ok else 0)
        elif fn == "tokenURI":
            computation.output = _string(token.uri)
        elif fn == "paused":
            computation.output = _uint(1 if token.paused else 0)
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
        elif fn in ("authorizeOperator", "revokeOperator"):
            operator_raw = _address_word(args, 0)
            holder, operator = to_account_id(caller_raw), to_account_id(operator_raw)
            if holder == operator:
                fail("a holder is always its own operator")
            authorize = fn == "authorizeOperator"
            is_default = operator in {to_account_id(o) for o in token.default_operators}
            if authorize and not is_default \
                    and not tokens.is_operator(state, address, holder, operator):
                from ..exchange.tokens import MAX_OPERATORS_PER_HOLDER
                if tokens.operator_slots_used(state, holder) >= MAX_OPERATORS_PER_HOLDER:
                    fail(f"an account may authorize at most {MAX_OPERATORS_PER_HOLDER} operators")
            state.token_journal.append(("op", address, holder, operator, authorize))
            computation.add_log_entry(msg.code_address, [
                AUTHORIZED_TOPIC if authorize else REVOKED_TOPIC,
                int.from_bytes(operator_raw, "big"), int.from_bytes(caller_raw, "big")], b"")
            computation.output = b""
        elif fn == "transfer":
            move(caller_raw, _address_word(args, 0), _uint_word(args, 1), None)
            computation.output = _uint(1)
        elif fn == "transferFrom":
            move(_address_word(args, 0), _address_word(args, 1), _uint_word(args, 2), caller_raw)
            computation.output = _uint(1)
        elif fn == "send":
            move(caller_raw, _address_word(args, 0), _uint_word(args, 1), None,
                 sent=(_bytes_arg(args, 2), b""))
            computation.output = b""
        elif fn == "operatorSend":
            move(_address_word(args, 0), _address_word(args, 1), _uint_word(args, 2), caller_raw,
                 sent=(_bytes_arg(args, 3), _bytes_arg(args, 4)))
            computation.output = b""
        elif fn == "burn":
            burn(caller_raw, _uint_word(args, 0), False, _bytes_arg(args, 1), b"")
            computation.output = b""
        elif fn == "operatorBurn":
            burn(_address_word(args, 0), _uint_word(args, 1), True, _bytes_arg(args, 2),
                 _bytes_arg(args, 3))
            computation.output = b""
    except ValueError as e:
        fail(str(e))
    return computation


def _sent_tail(parts: Tuple[bytes, bytes]) -> bytes:
    """The (bytes data, bytes operatorData) part of a Sent / Burned event's data, after its
    uint256 amount: offsets counted from the start of the data (three head words)."""
    head, tail = b"", b""
    for part in parts:
        head += _uint(96 + len(tail))
        tail += _uint(len(part)) + part + b"\0" * ((-len(part)) % 32)
    return head + tail
