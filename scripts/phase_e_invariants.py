"""
Phase E economic-invariant checker. Reads every node's DB (+ logs) after an
integration run and asserts the cross-node economic invariants that Phase E claims:

  1. Token-supply CONSERVATION — per token, the sum of all holder balances equals the
     registry total_supply (deploy mints supply; transfer/swap/liquidity only MOVE it,
     never mint/burn). A drift means an op leaked or printed value.
  2. Token-ledger CONVERGENCE — get_token_balances_root() is byte-identical on every
     node (the 4th unified-root domain; eligibility/E-D4 enforce off it).
  3. account_state (QRDX) CONVERGENCE — the unified QRDX ledger (perp margin/PnL +
     genesis) is identical per address across nodes.
  4. No NEGATIVE balances anywhere (clamp-at-0 invariant).
  5. E-D4 held — 0 "unified state root mismatch" rejections in the node logs.

This is the in-repo, automatable slice of the Phase E soak gate (the real gate is a
≥30-day multi-validator run). Run it after `python -m integration_tests.run_scenarios`.
Exits non-zero on any violation.
"""

import asyncio
import glob
import sys
from collections import defaultdict
from decimal import Decimal
from pathlib import Path

from qrdx.database_sqlite import DatabaseSQLite

DB_GLOB = "testnet/databases/node*.db"
LOG_GLOB = "testnet/logs/node*/node.log"


async def _node_snapshot(path: str) -> dict:
    db = await DatabaseSQLite.create(path)
    try:
        reg = await db.connection.execute(
            "SELECT token_address, symbol, total_supply FROM token_registry")
        registry = {r[0]: {"symbol": r[1], "supply": Decimal(str(r[2]))} for r in await reg.fetchall()}
        bal = await db.connection.execute(
            "SELECT token_address, holder_address, balance FROM token_balances")
        token_bals = [(r[0], r[1], Decimal(str(r[2]))) for r in await bal.fetchall()]
        acct = await db.connection.execute("SELECT address, balance FROM account_state")
        account = {r[0]: Decimal(str(r[1])) for r in await acct.fetchall()}
        token_root = await db.get_token_balances_root()
        return {"registry": registry, "token_bals": token_bals,
                "account": account, "token_root": token_root}
    finally:
        await db.connection.close()


def _check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' — ' + detail) if detail else ''}")
    return ok


async def main() -> int:
    db_paths = sorted(glob.glob(DB_GLOB))
    if not db_paths:
        print("no node DBs found — run an integration suite first")
        return 2
    snaps = {Path(p).stem: await _node_snapshot(p) for p in db_paths}
    names = list(snaps)
    print(f"\n[phase-e] checking economic invariants across {len(names)} nodes: {names}\n")
    ok = True

    # 1. Token-supply conservation (per node, per token).
    print("1. Token-supply conservation (sum of balances == total_supply)")
    any_token = False
    for name, s in snaps.items():
        sums = defaultdict(Decimal)
        for token, _holder, b in s["token_bals"]:
            sums[token] += b
        for token, meta in s["registry"].items():
            any_token = True
            held = sums.get(token, Decimal(0))
            ok &= _check(f"{name} {meta['symbol']} {token[:10]}",
                         held == meta["supply"], f"held={held} supply={meta['supply']}")
    if not any_token:
        print("  (no tokens deployed in this run)")

    # 2. Token-ledger root convergence.
    print("2. Token-ledger root convergence")
    roots = {name: s["token_root"] for name, s in snaps.items()}
    ok &= _check("identical token root on all nodes", len(set(roots.values())) == 1,
                 f"{ {n: r[:12] for n, r in roots.items()} }")

    # 3. account_state convergence (per address).
    print("3. account_state (QRDX) convergence")
    ref_name = names[0]
    ref_acct = snaps[ref_name]["account"]
    conv = True
    for name in names[1:]:
        other = snaps[name]["account"]
        diffs = {a: (ref_acct.get(a), other.get(a))
                 for a in set(ref_acct) | set(other)
                 if ref_acct.get(a, Decimal(0)) != other.get(a, Decimal(0))}
        if diffs:
            conv = False
            sample = dict(list(diffs.items())[:3])
            _check(f"{name} matches {ref_name}", False, f"{len(diffs)} divergent addr(s) e.g. {sample}")
    ok &= _check("account_state identical across nodes", conv)

    # 4. No negative balances.
    print("4. No negative balances")
    neg = []
    for name, s in snaps.items():
        neg += [f"{name} token {h[:8]}" for _t, h, b in s["token_bals"] if b < 0]
        neg += [f"{name} acct {a[:8]}" for a, b in s["account"].items() if b < 0]
    ok &= _check("all balances >= 0", not neg, f"{len(neg)} negative" if neg else "")

    # 5. E-D4 held (no unified-root rejections).
    print("5. E-D4 unified-state-root integrity (log scan)")
    total_mismatch = 0
    for lp in glob.glob(LOG_GLOB):
        try:
            txt = Path(lp).read_text(errors="ignore")
            total_mismatch += txt.count("unified state root mismatch")
        except OSError:
            pass
    ok &= _check("0 unified-state-root mismatches in logs", total_mismatch == 0,
                 f"{total_mismatch} found" if total_mismatch else "")

    print(f"\n==== PHASE E INVARIANTS: {'ALL HOLD' if ok else 'VIOLATION(S) FOUND'} ====")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
