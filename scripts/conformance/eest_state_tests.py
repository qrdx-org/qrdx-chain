#!/usr/bin/env python3
"""
Ethereum's state tests run through QRDX's EVM (docs/MAINNET_READINESS.md §4, "Fuzzing and
conformance").

QRDX executes contracts on py-evm, but through its own world: accounts and storage load on
demand from the state manager (qrdx/contracts/evm_world.py), the executor applies the message
itself (qrdx/contracts/evm_executor_v2.py) and writes every change back. Each state test of the
execution-spec-tests release gives a pre-state, a transaction and the post-state Ethereum
reaches; this runs the transaction through QRDX's executor over that pre-state and compares
every account the test expects.

What is not compared, because QRDX decides it differently on purpose:

* the sender's balance and nonce: QRDX charges a transaction's gas and consumes its nonce in the
  node's transaction path (qrdx/node/main.py), around the executor this drives;
* the block's coinbase: QRDX burns fees, it pays no tips;
* transactions Ethereum refuses before running (``expectException``): QRDX's admission rules
  are its own.

The block context (coinbase, number, time, gas limit, PREVRANDAO, base fee, chain id) is the
test's, so the comparison is of the EVM, not of QRDX's choice of context.

    python scripts/conformance/fetch_eest.sh            # the pinned fixtures release
    python scripts/conformance/eest_state_tests.py FIXTURES_DIR [--fork Shanghai] [-k NAME]

Exit status 1 if any compared value differs, other than where QRDX differs on purpose (``KNOWN``).
"""

from __future__ import annotations

import argparse
import asyncio
import glob
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

FORKS = ("Shanghai",)  # QRDX's EVM is Shanghai's (py-evm/eth/vm/forks/qrdx)

# Where QRDX differs on purpose, or where the test's state cannot arise on QRDX: (test file,
# a part of the case's name) → why. Any other difference fails the run.
KNOWN: Dict[Tuple[str, str], str] = {
    ("tests/frontier/precompiles/test_precompile_absence.py", ""): (
        "0x0100–0x0104 are reserved: the retired exchange precompiles revert"
    ),
    ("tests/byzantium/eip196_ec_add_mul/test_gas.py", "ecmul"): (
        "bn128 multiplication costs 12,000 gas more, as py-evm runs it (docs/BLOCK_LIMITS.md)"
    ),
    ("tests/paris/eip7610_create_collision/test_initcollision.py", "non-empty-balance"): (
        "EIP-7610: a creation onto an account with storage but no code or nonce. Such an account "
        "cannot arise in QRDX's state (storage is only ever written by code, and goes with it), "
        "so the EVM's world does not look for it"
    ),
}


def known(name: str) -> Optional[str]:
    path = name.split("::")[0]
    for (file, part), why in KNOWN.items():
        if path == file and part in name:
            return why
    return None


def _int(v: Any) -> int:
    return int(v, 16) if isinstance(v, str) else int(v)


def _bytes(v: str) -> bytes:
    return bytes.fromhex(v[2:] if v.startswith("0x") else v)


def intrinsic_gas(data: bytes, create: bool, access_list: List[Dict[str, Any]]) -> int:
    """Shanghai's: 21,000; 32,000 more to create; 4 a zero byte and 16 any other; 2,400 an
    access-list address and 1,900 a key (EIP-2930). (The 2 a word of a creation's init code,
    EIP-3860, py-evm charges as the creation starts.)"""
    gas = 21_000 + sum(4 if b == 0 else 16 for b in data)
    if create:
        gas += 32_000
    for entry in access_list:
        gas += 2_400 + 1_900 * len(entry.get("storageKeys", ()))
    return gas


@dataclass
class Case:
    name: str
    fork: str
    env: Dict[str, Any]
    pre: Dict[str, Any]
    tx: Dict[str, Any]
    post: Dict[str, Any]
    indexes: Dict[str, int]


@dataclass
class Outcome:
    case: Case
    diffs: List[str] = field(default_factory=list)
    error: str = ""


def load_cases(fixtures: str, forks=FORKS, match: str = "") -> List[Case]:
    cases = []
    for path in sorted(glob.glob(os.path.join(fixtures, "**", "*.json"), recursive=True)):
        if os.sep + "state_tests" + os.sep not in path:
            continue
        with open(path) as f:
            tests = json.load(f)
        for name, test in tests.items():
            if match and match not in name:
                continue
            for fork in forks:
                for i, entry in enumerate(test["post"].get(fork, ())):
                    if entry.get("expectException"):
                        continue
                    cases.append(
                        Case(
                            f"{name}#{i}",
                            fork,
                            test["env"],
                            test["pre"],
                            test["transaction"],
                            entry["state"],
                            entry["indexes"],
                        )
                    )
    return cases


class Runner:
    """One database, wiped between cases; the executor's block context is each test's."""

    def __init__(self, mode: str = "node") -> None:
        self.path = tempfile.mktemp(suffix=".db")
        self.db = None
        self.mode = mode

    async def __aenter__(self):
        from qrdx.database_sqlite import DatabaseSQLite

        self.db = await DatabaseSQLite.create(db_path=self.path)
        return self

    async def __aexit__(self, *exc):
        await self.db.close()
        for p in (self.path, self.path + "-lck"):
            if os.path.exists(p):
                os.remove(p)

    async def _wipe(self) -> None:
        for table in ("account_state", "contract_storage", "contract_code"):
            self.db.store[table].delete_prefix()
        await self.db.connection.commit()

    async def run(self, case: Case) -> Outcome:
        from eth.vm.execution_context import ExecutionContext
        from eth_utils import keccak

        from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
        from qrdx.contracts.evm_world import EvmWorld, run
        from qrdx.contracts.native_token_evm import EvmSection, TokenWorld
        from qrdx.contracts.state import ContractStateManager
        from qrdx.exchange import ExchangeStateManager

        out = Outcome(case)
        await self._wipe()
        ExchangeStateManager.reset_instance()
        sm = ContractStateManager(self.db)
        self.db.account_write_listeners = [sm.invalidate]
        for address, acct in case.pre.items():
            await sm.set_balance(address, _int(acct["balance"]))
            await sm.set_nonce(address, _int(acct["nonce"]))
            code = _bytes(acct["code"])
            if code:
                await sm.set_code(address, code, 0, address)
            for key, value in acct["storage"].items():
                await sm.set_storage(
                    address, _int(key).to_bytes(32, "big"), _int(value).to_bytes(32, "big")
                )
        await sm.commit(0)
        await self.db.connection.commit()

        env, tx, ix = case.env, case.tx, case.indexes
        number = _int(env["currentNumber"])
        base_fee = _int(env.get("currentBaseFee", "0x0"))

        def context(block_number, timestamp):
            return ExecutionContext(
                coinbase=_bytes(env["currentCoinbase"]),
                timestamp=_int(env["currentTimestamp"]),
                block_number=number,
                difficulty=_int(env.get("currentDifficulty", "0x0")),
                mix_hash=_bytes(env.get("currentRandom", "0x" + "00" * 32)),
                gas_limit=_int(env["currentGasLimit"]),
                prev_hashes=[
                    keccak(str(n).encode()) for n in range(number - 1, max(-1, number - 257), -1)
                ],
                chain_id=1,
                base_fee_per_gas=base_fee,
            )

        ex = QRDXEVMExecutor(sm)
        ex._execution_context = context  # (an instance attribute: this runner's only)
        sender = _bytes(tx["sender"])
        to = _bytes(tx["to"]) if tx.get("to") else None
        data = _bytes(tx["data"][ix["data"]])
        gas = _int(tx["gasLimit"][ix["gas"]])
        value = _int(tx["value"][ix["value"]])
        access = (tx.get("accessLists") or [None] * (ix["data"] + 1))[ix["data"]] or []
        if "gasPrice" in tx:
            price = _int(tx["gasPrice"])
        else:
            price = min(_int(tx["maxFeePerGas"]), base_fee + _int(tx["maxPriorityFeePerGas"]))
        intrinsic = intrinsic_gas(data, to is None, access)
        access_list = [
            (_bytes(e["address"]), [_bytes(k) for k in e.get("storageKeys", ())]) for e in access
        ]
        if self.mode == "ethereum":
            # Ethereum's transaction around the message: the gas limit bought up front, the
            # intrinsic gas taken from it, and the sender and recipient warm (EIP-2929).
            await sm.set_balance(tx["sender"], await sm.get_balance(tx["sender"]) - gas * price)
            run_gas, run_price, run_intrinsic = gas - intrinsic, 0, 0
            access_list = [(sender, []), *([(to, [])] if to else []), *access_list]
        else:  # as the node's transaction path calls it (qrdx/node/main.py)
            run_gas, run_price, run_intrinsic = gas, price, intrinsic

        section = EvmSection()
        world = EvmWorld(sm, tokens=TokenWorld(self.db, section))
        try:
            await run(
                world,
                lambda: ex.execute(
                    sender,
                    to,
                    value,
                    data,
                    run_gas,
                    run_price,
                    origin=sender,
                    intrinsic_gas=run_intrinsic,
                    block_number=number,
                    world=world,
                    payer=sender,
                    access_list=access_list,
                ),
                preload=[sender, to] if to else [sender],
            )
        except Exception as e:  # a crash is a finding too
            out.error = f"{type(e).__name__}: {e}"
            return out
        await self._compare(case, sm, out)
        return out

    async def _compare(self, case: Case, sm, out: Outcome) -> None:
        coinbase = case.env["currentCoinbase"].lower()
        sender = case.tx["sender"].lower()
        for address, want in case.post.items():
            a = address.lower()
            if a == coinbase:
                continue
            got_code = await sm.get_code(address)
            if got_code != _bytes(want["code"]):
                out.diffs.append(f"{a} code {got_code.hex()[:16]}… ≠ {want['code'][:18]}…")
            if a != sender:
                for what, getter in (("balance", sm.get_balance), ("nonce", sm.get_nonce)):
                    got, exp = await getter(address), _int(want[what])
                    if got != exp:
                        out.diffs.append(f"{a} {what} {got} ≠ {exp}")
            want_storage = {_int(k): _int(v) for k, v in want["storage"].items() if _int(v)}
            got_storage = {
                int.from_bytes(k, "big"): int.from_bytes(v, "big")
                for k, v in (await sm.get_all_storage(address)).items()
                if any(v)
            }
            if got_storage != want_storage:
                missing = {k: v for k, v in want_storage.items() if got_storage.get(k) != v}
                extra = {k: v for k, v in got_storage.items() if k not in want_storage}
                out.diffs.append(
                    f"{a} storage: expected {dict(list(missing.items())[:3])}, "
                    f"unexpected {dict(list(extra.items())[:3])}"
                )
        for address in case.pre:
            if address not in case.post and address.lower() != coinbase:
                if await sm.get_code(address) or await sm.get_balance(address):
                    out.diffs.append(f"{address.lower()} should no longer exist")


async def main_async(args) -> int:
    cases = load_cases(args.fixtures, tuple(args.fork), args.k)
    if args.limit:
        cases = cases[: args.limit]
    failed: List[Outcome] = []
    expected: List[Outcome] = []
    start = time.time()
    async with Runner(args.mode) as runner:
        for i, case in enumerate(cases):
            outcome = await runner.run(case)
            if outcome.diffs or outcome.error:
                if known(case.name) and not outcome.error:
                    expected.append(outcome)
                    continue
                failed.append(outcome)
                if args.verbose:
                    print(f"FAIL {case.name}: {outcome.error or '; '.join(outcome.diffs[:3])}")
            if not args.quiet and (i + 1) % 100 == 0:
                print(f"  {i + 1}/{len(cases)} ({len(failed)} differ, {time.time() - start:.0f}s)")
    agree = len(cases) - len(failed) - len(expected)
    print(
        f"{len(cases)} state tests: {agree} agree with Ethereum, {len(expected)} differ where "
        f"QRDX does on purpose, {len(failed)} differ ({time.time() - start:.0f}s)"
    )
    for why in sorted({known(o.case.name) for o in expected}):
        print(f"  on purpose: {why}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                [{"name": o.case.name, "error": o.error, "diffs": o.diffs} for o in failed],
                f,
                indent=1,
            )
    return 1 if failed else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("fixtures", help="the extracted fixtures directory (fetch_eest.sh)")
    p.add_argument("--fork", action="append", default=None, help="Shanghai (default)")
    p.add_argument("-k", default="", help="only tests whose name contains this")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument(
        "--mode",
        choices=("node", "ethereum"),
        default="node",
        help="node: the executor called as the node calls it (the default); "
        "ethereum: inside Ethereum's transaction rules, to isolate the EVM itself",
    )
    p.add_argument("--json", help="write the differing cases here")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    args = p.parse_args()
    args.fork = args.fork or list(FORKS)
    import logging

    logging.disable(logging.WARNING)
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
