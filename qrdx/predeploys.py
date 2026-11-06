"""
Contracts present from genesis (chain-spec parameter ``EVM_PREDEPLOYS``; docs/PQ_SMART_ACCOUNTS.md).

Some contracts cost more gas to deploy than a block holds: the PQ smart account's implementation
takes about 1.2M gas against a block's 1M of EVM gas. They are part of the network's genesis
instead. Each entry is ``ADDRESS:CODE[:SLOT=VALUE...]``: an address at or above ``0x…0600``
(below it are the precompiles), the runtime code, and the storage slots it starts with. The
default is the PQ smart account's implementation (locked: its owner key has no preimage, as its
constructor would leave it) at ``0x…0600`` and its factory at ``0x…0601``.

The code is in the chain spec, which the genesis block commits to, so a network's genesis file
pins it: a later release with other bytecode cannot build another genesis from the same file.
Genesis writes each as a block-0 record (``genesis_contract``) beside the allocations, and every
rebuild seeds it from there (``DatabaseSQLite.seed_genesis_contract``).
"""

from __future__ import annotations

import re
from typing import Dict, List, NamedTuple

from . import predeploy_code

IMPLEMENTATION_ADDRESS = "0x" + "00" * 18 + "0600"
FACTORY_ADDRESS = "0x" + "00" * 18 + "0601"
FIRST_ADDRESS = 0x0600  # below: precompiles (0x01-0x0c, 0x0200-0x0501)
MAX_CODE_BYTES = 24_576  # EIP-170

_HEX = re.compile(r"(0x)?[0-9a-fA-F]*")


class Predeploy(NamedTuple):
    address: str  # 0x + 40 lowercase hex
    code: bytes
    storage: Dict[str, str]  # 32-byte slot -> 32-byte value, lowercase hex without 0x


def _keccak(data: bytes) -> bytes:
    from eth_utils import keccak

    return keccak(data)


def _word(raw: str, what: str) -> str:
    if not _HEX.fullmatch(raw) or len(raw.removeprefix("0x")) > 64:
        raise ValueError(f"{what} {raw!r} is not a 32-byte hex word")
    return raw.removeprefix("0x").lower().rjust(64, "0")


def parse(entry: str) -> Predeploy:
    """An ``EVM_PREDEPLOYS`` entry. Raises ValueError."""
    parts = str(entry).split(":")
    if len(parts) < 2:
        raise ValueError(f"{str(entry)[:40]}… is not ADDRESS:CODE[:SLOT=VALUE...]")
    address, code_hex = parts[0].lower(), parts[1]
    if not re.fullmatch(r"0x[0-9a-f]{40}", address):
        raise ValueError(f"{parts[0]!r} is not a 20-byte address")
    if int(address, 16) < FIRST_ADDRESS:
        raise ValueError(f"{address} is reserved for precompiles (predeploys start at 0x…0600)")
    if not _HEX.fullmatch(code_hex) or len(code_hex.removeprefix("0x")) % 2:
        raise ValueError(f"{address}: the code is not hex")
    code = bytes.fromhex(code_hex.removeprefix("0x"))
    if not code or len(code) > MAX_CODE_BYTES:
        raise ValueError(f"{address}: code of {len(code)} bytes (1 to {MAX_CODE_BYTES})")
    storage: Dict[str, str] = {}
    for item in parts[2:]:
        slot, sep, value = item.partition("=")
        if not sep:
            raise ValueError(f"{address}: storage {item!r} is not SLOT=VALUE")
        key = _word(slot, "slot")
        if key in storage:
            raise ValueError(f"{address}: slot {slot} given twice")
        word = _word(value, "value")
        if int(word, 16):  # (a zero slot is no slot)
            storage[key] = word
    return Predeploy(address, code, storage)


def check(entries: List[str]) -> List[Predeploy]:
    """Every entry parsed, no address twice. Raises ValueError."""
    out = [parse(e) for e in entries]
    addresses = [p.address for p in out]
    if len(set(addresses)) != len(addresses):
        raise ValueError("an address is listed twice")
    return out


def _push32_zero_offsets(code: bytes) -> List[int]:
    """Where ``code`` pushes a 32-byte zero: how solc leaves an immutable to be filled in at
    deployment (the optimizer never pushes a literal zero that way). Walks the instructions, so
    push data is never read as an opcode."""
    out, i = [], 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7F:
            width = op - 0x5F
            if op == 0x7F and code[i + 1 : i + 33] == bytes(32):
                out.append(i + 1)
            i += 1 + width
        else:
            i += 1
    return out


def factory_code(implementation: str = IMPLEMENTATION_ADDRESS) -> bytes:
    """The factory's runtime code for ``implementation``: what its constructor would deploy."""
    code = bytearray(bytes.fromhex(predeploy_code.PQ_ACCOUNT_FACTORY_RUNTIME))
    word = bytes(12) + bytes.fromhex(implementation.removeprefix("0x"))
    offsets = _push32_zero_offsets(bytes(code))
    if not offsets:
        raise ValueError("the factory's code has no immutable to fill")
    for offset in offsets:
        code[offset : offset + 32] = word
    return bytes(code)


# The implementation's constructor sets its owner key to a hash without a known preimage, so the
# implementation itself can never be initialized and used (accounts are proxies of it).
IMPLEMENTATION_LOCK = _keccak(b"PQSmartAccount: implementation, no owner").hex()


def default_entries() -> List[str]:
    implementation = predeploy_code.PQ_SMART_ACCOUNT_RUNTIME
    return [
        f"{IMPLEMENTATION_ADDRESS}:0x{implementation}:0x0=0x{IMPLEMENTATION_LOCK}",
        f"{FACTORY_ADDRESS}:0x{factory_code().hex()}",
    ]


def genesis_record(p: Predeploy) -> Dict[str, object]:
    """The block-0 record of a predeploy (``transactions``, type ``genesis_contract``)."""
    return {
        "type": "genesis_contract",
        "address": p.address,
        "code": p.code.hex(),
        "code_hash": _keccak(p.code).hex(),
        "storage": dict(sorted(p.storage.items())),
    }
