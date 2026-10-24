"""
The EVM's way into the exchange (docs/HYPERLIQUID_PARITY.md, Hyperliquid's HyperEVM ↔ HyperCore):

* **Read** (``EXCHANGE_READ_ADDRESS``, 0x…0400): a contract reads live exchange state — a market's
  mark and oracle price, a perps position, an account's equity and withdrawable collateral, a QNS
  name's address — as of this point of the block, the same on every node.
* **Write** (``EXCHANGE_WRITE_ADDRESS``, 0x…0401, Hyperliquid's CoreWriter): a contract sends an
  exchange action — an order, a cancel, a deposit, a withdrawal, a vault or staking move — as its
  own account (its address, ``0x`` + 40 hex). The action is journaled with the call (a revert
  drops it), queued in the exchange's committed state when the block's EVM section is accepted,
  and executed at the start of the next block's exchange processing, before its transactions —
  authorized by the EVM execution itself (no signature; its gas was paid in the EVM).

Read ABI (Solidity)::

    function markPrice(string market) returns (uint256 price1e18)
    function oraclePrice(string market) returns (uint256 price1e18)
    function position(address account, string market)
        returns (int256 size1e18, uint256 entry1e18, uint256 isolatedMargin1e18)
    function positionOf(string account, string market) returns (int256, uint256, uint256)
    function perpAccount(address account) returns (int256 equity1e18, uint256 withdrawable1e18)
    function resolve(string name) returns (address)            // QNS; 0 if it resolves nowhere

Write ABI::

    function sendAction(string actionJson)   // {"op": "PERP_ORDER", "params": {...}, "gas": n}

``gas`` is the action's exchange gas limit, as a signed transaction's: what bounds its work (an
order visits no more resting orders than it pays for). Default: the operation's base gas, at most
MAX_ACTION_GAS. The call pays WRITE_GAS plus one EVM gas per EXCHANGE_GAS_PER_EVM_GAS of it — the
exchange runs its gas about that much faster than the EVM, so a block's EVM gas cannot queue more
exchange work than about half a block's exchange budget.

An unknown selector, a malformed input or an action outside EVM_ACTION_OPS reverts.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any, Dict, Tuple

from eth_abi import decode, encode
from eth_utils import keccak

READ_GAS = 5_000
WRITE_GAS = 25_000  # plus the action's exchange gas, converted
EXCHANGE_GAS_PER_EVM_GAS = 10
MAX_ACTION_GAS = 2_000_000
MAX_ACTION_BYTES = 4096
SCALE = Decimal(10) ** 18

# What a contract may do on the exchange: trading, its margin, vaults, delegation, deploying.
EVM_ACTION_OPS = frozenset(
    {
        "PERP_DEPOSIT",
        "PERP_WITHDRAW",
        "PERP_SET_LEVERAGE",
        "PERP_ORDER",
        "PERP_CANCEL",
        "PERP_TRIGGER",
        "PERP_MODIFY",
        "PERP_ISOLATED_MARGIN",
        "CANCEL_ALL",
        "PLACE_ORDER",
        "CANCEL_ORDER",
        "MODIFY_ORDER",
        "SWAP",
        "VAULT_DEPOSIT",
        "VAULT_WITHDRAW",
        "STAKE_DELEGATE",
        "STAKE_UNDELEGATE",
        "SCHEDULE_CANCEL",
        # A contract may be a market deployer (docs/HYPERLIQUID_PARITY.md): bond, list, run the
        # oracle — an on-chain oracle aggregator, say — and settle.
        "DEPLOYER_BOND",
        "DEPLOYER_UNBOND",
        "CREATE_MARKET",
        "DEPLOYER_SET_ORACLE",
        "DEPLOYER_HALT",
    }
)


def _selector(signature: str) -> bytes:
    return keccak(signature.encode())[:4]


_READS: Dict[bytes, Tuple[str, Tuple[str, ...]]] = {
    _selector("markPrice(string)"): ("mark", ("string",)),
    _selector("oraclePrice(string)"): ("oracle", ("string",)),
    _selector("position(address,string)"): ("position", ("address", "string")),
    _selector("positionOf(string,string)"): ("position", ("string", "string")),
    _selector("perpAccount(address)"): ("account", ("address",)),
    _selector("resolve(string)"): ("resolve", ("string",)),
}
SEND_ACTION = _selector("sendAction(string)")


def _fail(computation, reason: str):
    from eth.exceptions import Revert

    from .native_token_evm import revert_data

    computation.output = revert_data(reason)
    raise Revert(reason)


def _u(value: Decimal) -> int:
    return max(0, int((Decimal(value) * SCALE).to_integral_value()))


def _i(value: Decimal) -> int:
    return int((Decimal(value) * SCALE).to_integral_value())


def _account_key(raw: Any) -> str:
    """The exchange account an argument names: an EVM address as ``0x`` + 40 lowercase hex (a
    contract's or an EVM user's), a string as given (a ``0xPQ…`` address)."""
    if isinstance(raw, (bytes, bytearray)):
        return "0x" + bytes(raw).hex()
    s = str(raw)
    return s.lower() if s.startswith("0x") and len(s) == 42 else s


def exchange_read_precompile(computation):
    from ..exchange.state_manager import ExchangeStateManager

    data = bytes(computation.msg.data_as_bytes)
    computation.consume_gas(READ_GAS, reason="exchange read")
    if computation.msg.value:
        _fail(computation, "the exchange precompile does not accept QRDX")
    entry = _READS.get(data[:4])
    if entry is None:
        _fail(computation, "unknown exchange read")
    kind, types = entry
    try:
        args = decode(list(types), data[4:])
    except Exception:
        _fail(computation, "malformed exchange read")
    mgr = ExchangeStateManager.get_instance()
    ch = mgr.clearinghouse
    if kind in ("mark", "oracle"):
        m = ch.markets.get(str(args[0]))
        price = Decimal(0) if m is None else (m.mark_price if kind == "mark" else m.oracle_price)
        computation.output = encode(["uint256"], [_u(price)])
    elif kind == "position":
        acct = ch.accounts.peek(_account_key(args[0]))
        pos = acct.positions.get(str(args[1])) if acct is not None else None
        if pos is None:
            computation.output = encode(["int256", "uint256", "uint256"], [0, 0, 0])
        else:
            computation.output = encode(
                ["int256", "uint256", "uint256"],
                [_i(pos.size), _u(pos.entry_price), _u(pos.isolated_margin)],
            )
    elif kind == "account":
        key = _account_key(args[0])
        if ch.accounts.peek(key) is None:
            computation.output = encode(["int256", "uint256"], [0, 0])
        else:
            computation.output = encode(
                ["int256", "uint256"], [_i(ch.cross_equity(key)), _u(ch.withdrawable(key))]
            )
    else:  # resolve
        from ..crypto.account_id import to_account_id
        from ..exchange.qns import QnsError, normalize

        target = None
        try:
            now = Decimal(str(mgr._block_clock()))
            target = mgr.qns.resolve(mgr.nfts, normalize(str(args[0])), now)
        except (QnsError, ValueError):
            target = None
        address = bytes(20)
        if target:
            try:
                address = bytes.fromhex(to_account_id(target)[2:])
            except ValueError:
                address = bytes(20)
        computation.output = encode(["address"], ["0x" + address.hex()])
    return computation


def parse_action(raw: str) -> Tuple[str, Dict[str, Any], int]:
    """(operation name, params, exchange gas limit) of an action's JSON; ValueError if it is not
    one a contract may send, or its parameters are not the operation's."""
    from ..exchange.transactions import EXCHANGE_GAS_COSTS, ExchangeOpType, ExchangeTransaction

    if len(raw.encode()) > MAX_ACTION_BYTES:
        raise ValueError(f"an action is at most {MAX_ACTION_BYTES} bytes")
    obj = json.loads(raw)
    if not isinstance(obj, dict) or not isinstance(obj.get("params", {}), dict):
        raise ValueError('an action is {"op": name, "params": {...}}')
    op = str(obj.get("op", ""))
    if op not in EVM_ACTION_OPS:
        raise ValueError(f"a contract may not send {op or 'that'}")
    params = obj.get("params", {})
    base = EXCHANGE_GAS_COSTS.get(ExchangeOpType[op], 100_000)
    gas = obj.get("gas", base)
    if isinstance(gas, bool) or not isinstance(gas, int) or not base <= gas <= MAX_ACTION_GAS:
        raise ValueError(f"gas is a whole number from {base} to {MAX_ACTION_GAS}")
    probe = ExchangeTransaction(
        op_type=ExchangeOpType[op],
        sender="0x" + "00" * 20,
        nonce=0,
        params=params,
        gas_limit=gas,
        gas_price=1,
        timestamp=1.0,
    )
    probe.validate_basic()
    return op, params, gas


def exchange_write_precompile(computation):
    msg = computation.msg
    data = bytes(msg.data_as_bytes)
    if msg.storage_address != msg.code_address:
        # A DELEGATECALL runs with the delegating frame's caller as ``msg.sender``: a contract
        # anyone calls could otherwise send actions as whoever called it (as a CALLCODE could as
        # itself, by surprise). Only a plain CALL acts — as the calling contract.
        computation.consume_gas(WRITE_GAS, reason="exchange write")
        _fail(computation, "the exchange cannot be called with DELEGATECALL or CALLCODE")
    if msg.value:
        computation.consume_gas(WRITE_GAS, reason="exchange write")
        _fail(computation, "the exchange precompile does not accept QRDX")
    if data[:4] != SEND_ACTION:
        computation.consume_gas(WRITE_GAS, reason="exchange write")
        _fail(computation, "unknown exchange write")
    if msg.is_static:
        computation.consume_gas(WRITE_GAS, reason="exchange write")
        _fail(computation, "an exchange action cannot be sent in a static call")
    try:
        (raw,) = decode(["string"], data[4:])
        op, params, gas = parse_action(raw)
    except Exception as e:  # noqa: BLE001 — any malformed action reverts
        computation.consume_gas(WRITE_GAS, reason="exchange write")
        _fail(computation, f"bad exchange action: {e}")
    computation.consume_gas(
        WRITE_GAS + -(-gas // EXCHANGE_GAS_PER_EVM_GAS), reason="exchange write"
    )
    sender = "0x" + bytes(computation.msg.sender).hex()
    computation.state.token_journal.append(
        ("xact", sender, op, json.dumps(params, sort_keys=True), gas)
    )
    return computation
