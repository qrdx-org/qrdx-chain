"""
Upgrade rehearsal — a scheduled protocol fork on a live multi-node testnet.

    python -m integration_tests.upgrade_rehearsal [--fork-height 40] [--past 30]

What it does (docs/PROTOCOL_UPGRADES.md §8):

  1. Writes a testnet genesis whose chain spec schedules the ``randao`` fork (RANDAO proposer
     selection) at ``--fork-height``. Like every fork on a real network it needs on-chain
     approval: the validators propose and approve it through governance, and it executes at
     least GOV_FORK_APPROVAL_LEAD_BLOCKS before the fork.
  2. Starts every node on that spec — except the last (a full node), which is started on a
     STALE copy of the same genesis whose spec omits the fork: an operator who did not upgrade.
     Same genesis block, so the two kinds of node peer happily until the fork.
  3. Lets the chain run ``--past`` blocks beyond the fork, and checks:
       * the fork is approved on chain in time (the stale node records the approval too —
         approvals never depend on a node's own spec);
       * every upgraded node reports the fork scheduled, then active, and one shared fork id;
       * the upgraded nodes keep producing blocks across the fork and agree on every block
         hash around it;
       * the upgraded nodes refuse the stale node once they pass the fork (EIP-2124), and the
         stale node refuses them — instead of anyone silently following a different chain.

Exit code 0 when every check holds. Uses the larger-slot RANDAO configuration
(QRDX_SLOT_DURATION=6, QRDX_SLOTS_PER_EPOCH=4) unless the environment says otherwise — RANDAO on
a 3-validator, 2-second-slot testnet churns (docs/KNOWN_ISSUES.md, RANDAO entry), which would
blur the result.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time

import httpx

logger = logging.getLogger("upgrade-rehearsal")


async def _get(client, url, path):
    try:
        r = await client.get(f"{url}{path}", timeout=5.0)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


async def _rpc(client, url, method, params=None):
    try:
        r = await client.post(f"{url}/rpc", timeout=5.0,
                              json={"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1})
        return r.json().get("result")
    except Exception:
        return None


def _log_count(log_dir, needle):
    """Occurrences of ``needle`` in a node's logs. The console handler wraps long lines, so
    both are compared with all whitespace removed."""
    needle = re.sub(r"\s+", "", needle)
    total = 0
    try:
        for name in os.listdir(log_dir):
            with open(os.path.join(log_dir, name), errors="replace") as fh:
                total += re.sub(r"\s+", "", fh.read()).count(needle)
    except OSError:
        pass
    return total


async def _approve_fork_on_chain(client, urls, wallets, fork, check) -> bool:
    """Validator 0 proposes approving ``fork`` (its exact definition, from the node's spec), all
    three validators vote yes (2/3 of three equal stakes needs all three), and once the timelock
    ends validator 0 executes it. Each validator submits to its own node."""
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.exchange import ExchangeOpType, ExchangeTransaction
    from integration_tests.config import CHAIN_ID

    async def send(i, op, params):
        w = wallets[f"Validator {i}"]
        key = PQPrivateKey.from_hex(w["private_key"], w["public_key"])
        for _ in range(4):
            nonce = int(await _rpc(client, urls[i], "exchange_getNonce", [w["address"]]))
            tx = ExchangeTransaction(chain_id=CHAIN_ID, op_type=op, sender=w["address"], nonce=nonce,
                                     params=params, gas_limit=2_000_000, gas_price=10 ** 9)
            tx.public_key = key.public_key.to_bytes()
            tx.signature = key.sign(tx.signing_bytes()).to_bytes()
            tx_hash = await _rpc(client, urls[i], "exchange_sendTransaction", [tx.to_dict()])
            for _ in range(60):
                rec = await _rpc(client, urls[i], "exchange_getTransactionReceipt", [tx_hash])
                if rec:
                    if not rec["success"] and "Invalid nonce" in (rec.get("error") or ""):
                        break
                    return rec
                await asyncio.sleep(2)
        return None

    params = await _rpc(client, urls[0], "governance_getForkApprovalParams", [fork])
    approve_by = params.pop("approve_by")
    rec = await send(0, ExchangeOpType.GOV_PROPOSE, {**params, "memo": "upgrade rehearsal"})
    if not (rec and rec["success"]):
        check(False, f"approval proposed ({rec and rec['error']})")
        return False
    pid = rec["data"]["proposal_id"]
    for i in range(3):
        rec = await send(i, ExchangeOpType.GOV_VOTE, {"proposal_id": pid, "support": True})
        check(bool(rec) and rec["success"], f"validator {i} approves ({rec and rec['error']})")
    proposal = await _rpc(client, urls[0], "governance_getProposal", [pid])
    for _ in range(120):
        status = await _rpc(client, urls[0], "governance_getStatus")
        if status and status["height"] >= proposal["timelock_ends"]:
            break
        await asyncio.sleep(2)
    rec = await send(0, ExchangeOpType.GOV_EXECUTE, {"proposal_id": pid})
    check(bool(rec) and rec["success"], f"approval executed ({rec and rec['error']})")
    approved_at = (rec or {}).get("data", {}).get("approved_at")
    check(approved_at is not None and approved_at <= approve_by,
          f"approved at block {approved_at}, in time for the fork (by {approve_by})")
    return bool(rec and rec["success"])


async def main(args) -> int:
    os.environ["QRDX_TESTNET_RANDAO_FORK_HEIGHT"] = str(args.fork_height)
    os.environ.setdefault("QRDX_SLOT_DURATION", "6")
    os.environ.setdefault("QRDX_SLOTS_PER_EPOCH", "4")

    from integration_tests.config import CONFIGS_DIR, GENESIS_FILE, TESTNET_DIR
    from integration_tests.orchestrator import TestnetOrchestrator

    orch = TestnetOrchestrator(force_regenerate=False)
    failures = []

    def check(ok, what):
        logger.info("  %s %s", "✓" if ok else "✗", what)
        if not ok:
            failures.append(what)

    try:
        await orch.setup()
        H = args.fork_height

        # The operator who did not upgrade: the same genesis, a spec without the fork.
        stale = orch.node_specs[-1]
        assert not stale.is_validator, "the stale node must be a full node"
        data = json.load(open(GENESIS_FILE))
        assert data["chain_spec"]["forks"], "the genesis does not schedule the fork"
        data["chain_spec"]["forks"] = []
        stale_genesis = TESTNET_DIR / "genesis_stale_no_fork.json"
        json.dump(data, open(stale_genesis, "w"), indent=2)
        env_path = CONFIGS_DIR / f"node{stale.node_id}.env"
        lines = [l for l in open(env_path).read().splitlines() if not l.startswith("QRDX_GENESIS_FILE=")]
        lines.append(f"QRDX_GENESIS_FILE={stale_genesis}")
        open(env_path, "w").write("\n".join(lines) + "\n")
        logger.info("Fork 'randao' at height %d; node %d runs the stale spec (%s)",
                    H, stale.node_id, stale_genesis.name)

        await orch.start_all_nodes()
        if not await orch.wait_network_ready():
            check(False, "network became ready")
            return 1

        urls = [p.url for p in orch.node_processes]
        upgraded = [u for s, u in zip(orch.node_specs, urls) if s.node_id != stale.node_id]
        stale_url = urls[[s.node_id for s in orch.node_specs].index(stale.node_id)]

        async with httpx.AsyncClient() as client:
            stale_id = ((await _rpc(client, stale_url, "p2p_getStatus")) or {}).get("node_id")
            before = [await _get(client, u, "/chain_spec") for u in upgraded]
            check(all(b and b["next_fork"] and b["next_fork"]["height"] == H for b in before),
                  f"every upgraded node schedules the fork at {H} before it")
            pre_stale = await _get(client, stale_url, "/chain_spec")
            check(bool(pre_stale) and pre_stale["next_fork"] is None and pre_stale["genesis_block_hash"]
                  == before[0]["genesis_block_hash"],
                  "the stale node shares the genesis block but schedules no fork")

            from integration_tests.config import WALLETS_DIR
            wallets = {}
            for i in range(3):
                wallets[f"Validator {i}"] = json.load(open(WALLETS_DIR / f"validator_{i}.json"))
            await _approve_fork_on_chain(client, urls, wallets, "randao", check)
            upgraded_reports = [await _get(client, u, "/chain_spec") for u in upgraded]
            check(all(r and r["forks"][0]["approval"]["approved"] for r in upgraded_reports),
                  "every upgraded node sees the fork approved")
            stale_gov = await _rpc(client, stale_url, "governance_getStatus")
            check(bool(stale_gov) and len(stale_gov["fork_approvals"]) == 1,
                  "the stale node recorded the approval too (identical governance state)")

            target = H + args.past
            deadline = time.time() + args.timeout
            heads = []
            while time.time() < deadline:
                reports = [await _get(client, u, "/chain_spec") for u in upgraded]
                heads = [r["head"] if r else -1 for r in reports]
                logger.info("  heads %s (target %d)", heads, target)
                if min(heads) >= target:
                    break
                await asyncio.sleep(6)
            check(min(heads) >= target, f"the upgraded chain advanced past the fork to {target}")

            after = [await _get(client, u, "/chain_spec") for u in upgraded]
            check(all(a and a["forks"][0]["status"] == "active" and "randao_selection"
                      in a["active_features"] for a in after),
                  "every upgraded node reports the fork active")
            check(len({a["fork_id"]["hash"] for a in after if a}) == 1 and
                  after[0]["fork_id"]["hash"] != before[0]["fork_id"]["hash"],
                  "upgraded nodes share one post-fork fork id, different from the pre-fork one")

            agree = True
            for h in range(max(1, H - 3), min(heads) + 1):
                hashes = set()
                for u in upgraded:
                    b = await _get(client, u, f"/get_block?block={h}")
                    blk = ((b or {}).get("result") or {}).get("block") or {}
                    hashes.add(blk.get("hash") or blk.get("block_hash"))
                if len(hashes) != 1 or None in hashes:
                    agree = False
                    logger.info("    height %d: %s", h, hashes)
            check(agree, f"upgraded nodes agree on every block hash from {H - 3} to {min(heads)}")

            stale_report = await _get(client, stale_url, "/chain_spec")
            stale_head = stale_report["head"] if stale_report else -1
            logger.info("  stale node head %d (upgraded %d)", stale_head, min(heads))

        # Refusals, from the nodes' own logs (main._drop_if_incompatible / the handshake).
        refusals = sum(_log_count(s.log_dir, f"peer {stale_id} is incompatible")
                       for s in orch.node_specs if s.node_id != stale.node_id) if stale_id else 0
        stale_refusals = (_log_count(stale.log_dir, "is incompatible")
                          + _log_count(stale.log_dir, "refused our handshake"))
        check(refusals > 0, f"upgraded nodes refused the stale node after the fork "
                            f"({refusals} refusals logged)")
        check(stale_refusals > 0, f"the stale node refused the upgraded nodes "
                                  f"({stale_refusals} refusals logged)")
    finally:
        if not args.keep:
            await orch.stop_all_nodes()

    logger.info("")
    logger.info("UPGRADE REHEARSAL: %s", "PASSED" if not failures else f"FAILED ({len(failures)})")
    for f in failures:
        logger.info("  failed: %s", f)
    return 0 if not failures else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fork-height", type=int, default=50)
    parser.add_argument("--past", type=int, default=30, help="blocks to run beyond the fork")
    parser.add_argument("--timeout", type=float, default=900.0, help="seconds to wait for the chain")
    parser.add_argument("--keep", action="store_true", help="leave the nodes running")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%H:%M:%S")
    sys.exit(asyncio.run(main(parser.parse_args())))
