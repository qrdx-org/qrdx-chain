"""
Long-run finality soak. Starts the integration testnet and samples, over ~8 minutes,
the chain epoch vs the finalized/justified epoch and per-epoch attester coverage —
validating that attestation gossip keeps finality tracking the tip PAST the original
stall point (finalized froze at ~8 while the chain reached ~29). Reads node DBs
directly (read-only) while nodes run. Prints a table + verdict, then stops the nodes.
"""

import asyncio
import sqlite3
import time
from pathlib import Path

from integration_tests.orchestrator import TestnetOrchestrator

DB_DIR = Path("testnet/databases")
SAMPLE_EVERY = 40       # seconds between samples
SOAK_SECONDS = 480      # ~8 min → chain should pass epoch ~29


def _q1(con, sql):
    try:
        r = con.execute(sql).fetchone()
        return r[0] if r and r[0] is not None else -1
    except Exception:
        return -1


def sample_node(db_path: Path) -> dict:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
    try:
        cur_epoch = _q1(con, "SELECT MAX(target_epoch) FROM attestation_votes")
        justified = _q1(con, "SELECT MAX(epoch) FROM epochs WHERE justified=1")
        finalized = _q1(con, "SELECT MAX(epoch) FROM epochs WHERE finalized=1")
        # coverage of the last 4 fully-past epochs (exclude the in-progress tip epoch)
        cov = con.execute(
            "SELECT target_epoch, COUNT(DISTINCT validator_address) FROM attestation_votes "
            "WHERE target_epoch < ? GROUP BY target_epoch ORDER BY target_epoch DESC LIMIT 4",
            (cur_epoch,)).fetchall()
        return {"epoch": cur_epoch, "justified": justified, "finalized": finalized,
                "coverage": [(e, c) for e, c in cov]}
    finally:
        con.close()


async def main():
    orch = TestnetOrchestrator(force_regenerate=True)
    await orch.setup()
    await orch.start_all_nodes()
    await orch.wait_network_ready()
    print("\n[soak] network ready; sampling finality vs chain epoch\n")
    print(f"{'t(s)':>5} | {'chain_ep':>8} | {'justified':>9} | {'finalized':>9} | {'lag':>4} | recent coverage (epoch:attesters)")
    print("-" * 95)

    start = time.time()
    min_coverage = 99
    worst_lag = 0
    samples = 0
    try:
        while time.time() - start < SOAK_SECONDS:
            await asyncio.sleep(SAMPLE_EVERY)
            dbs = sorted(DB_DIR.glob("node*.db"))
            snaps = [sample_node(p) for p in dbs]
            # node0 is the reference; chain epoch = max across nodes
            chain_ep = max(s["epoch"] for s in snaps)
            fin = max(s["finalized"] for s in snaps)
            jus = max(s["justified"] for s in snaps)
            cov0 = snaps[0]["coverage"]
            lag = chain_ep - fin if fin >= 0 else -1
            for _e, c in cov0:
                min_coverage = min(min_coverage, c)
            if lag >= 0:
                worst_lag = max(worst_lag, lag)
            samples += 1
            cov_str = " ".join(f"{e}:{c}" for e, c in cov0)
            print(f"{int(time.time()-start):>5} | {chain_ep:>8} | {jus:>9} | {fin:>9} | {lag:>4} | {cov_str}")
    finally:
        print("\n[soak] stopping nodes...")
        await orch.stop_all_nodes()

    print("\n==== VERDICT ====")
    print(f"samples={samples} worst_finality_lag={worst_lag} min_recent_coverage={min_coverage}")
    healthy = worst_lag >= 0 and worst_lag <= 6 and min_coverage >= 3
    print("RESULT:", "HEALTHY — finality tracks the tip past the old stall point"
          if healthy else "DEGRADED — investigate")


if __name__ == "__main__":
    asyncio.run(main())
