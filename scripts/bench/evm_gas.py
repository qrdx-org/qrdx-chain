#!/usr/bin/env python3
"""
Calibrate the block gas limit for this machine (docs/BLOCK_LIMITS.md).

Runs the EVM's slowest workloads per unit of gas — its cheapest instruction in a loop, each
precompile in a loop, reads of accounts that are not loaded — through the node's own executor,
and prints the gas per second of each and how long a block full of the slowest would take to
execute here at the configured ``BLOCK_GAS_LIMIT``. A network's limit should keep that well
within its slot time on the slowest hardware its validators run.

    python scripts/bench/evm_gas.py [gas per run, default and at most BLOCK_GAS_LIMIT]
"""

import asyncio
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from qrdx.constants import BLOCK_GAS_LIMIT, SLOT_DURATION  # noqa: E402
from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor  # noqa: E402
from qrdx.contracts.evm_world import EvmWorld, run  # noqa: E402
from qrdx.contracts.state import ContractStateManager  # noqa: E402
from qrdx.database_sqlite import DatabaseSQLite  # noqa: E402

SENDER = bytes.fromhex("a1" * 20)


def push(n, width=None):
    width = width or max(1, (n.bit_length() + 7) // 8)
    return bytes([0x5F + width]) + n.to_bytes(width, "big")


def precompile_loop(index, data):
    """Copy ``data`` to memory, then STATICCALL precompile ``index`` with it until out of gas."""
    address = bytes(19) + bytes([index])
    loop = (
        b"\x5b" + push(64) + push(len(data), 2) + push(len(data), 2) + push(0)
        + b"\x73" + address + b"\x5a\xfa\x50" + push(9, 2) + b"\x56"
    )
    return push(len(data), 2) + push(9 + len(loop), 2) + push(0) + b"\x39" + loop + data


G1 = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
G2 = bytes.fromhex(
    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
)
NEG_G1 = (1).to_bytes(32, "big") + (
    21888242871839275222246405745257275088696311157297823662689037894645226208581
).to_bytes(32, "big")
ECRECOVER = bytes.fromhex(
    "456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"
    "000000000000000000000000000000000000000000000000000000000000001c"
    "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"
    "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"
)
WORKLOADS = [
    ("JUMPDEST (1 gas)", b"\x5b" * 201 + push(0) + b"\x56"),
    ("BALANCE of new accounts", push(0) + bytes.fromhex("5b8031506001016002") + b"\x56"),
    ("ecrecover", precompile_loop(1, ECRECOVER)),
    ("sha256 4 KB", precompile_loop(2, bytes(4096))),
    ("identity 4 KB", precompile_loop(4, bytes(4096))),
    ("bn128 add", precompile_loop(6, G1 + G1)),
    ("bn128 mul", precompile_loop(7, G1 + (2**255 - 19).to_bytes(32, "big"))),
    ("bn128 pairing x2", precompile_loop(8, G1 + G2 + NEG_G1 + G2)),
]


async def main(gas: int) -> None:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(db_path=path)
    try:
        sm = ContractStateManager(db)
        ex = QRDXEVMExecutor(sm)
        sm.set_balance_sync("0x" + SENDER.hex(), 10**24)
        print(f"{'workload':26s} {'Mgas/s':>8s}   a full block ({BLOCK_GAS_LIMIT:,} gas)")
        slowest = None
        for i, (name, code) in enumerate(WORKLOADS):
            target = bytes(18) + b"\xbe" + bytes([i])
            sm.set_code_sync("0x" + target.hex(), code)
            await sm.commit(1)
            rate = float("inf")
            for _ in range(2):  # cold, then warm: the slower counts
                world = EvmWorld(sm)
                t = time.perf_counter()
                r = await run(world, lambda w=world: ex.call(SENDER, target, b"", gas=gas, world=w),
                              preload=[SENDER, target])
                rate = min(rate, r.gas_used / (time.perf_counter() - t))
            block_s = BLOCK_GAS_LIMIT / rate
            slowest = max(slowest or 0.0, block_s)
            print(f"{name:26s} {rate / 1e6:8.2f}   {block_s * 1000:7.0f} ms")
        slots = slowest / float(SLOT_DURATION)
        print(f"\nslowest full block: {slowest * 1000:.0f} ms = {slots:.1f} slots of "
              f"{float(SLOT_DURATION) * 1000:.0f} ms")
    finally:
        await db.close()
        for p in (path, path + "-wal", path + "-shm"):
            if os.path.exists(p):
                os.remove(p)


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else BLOCK_GAS_LIMIT))
