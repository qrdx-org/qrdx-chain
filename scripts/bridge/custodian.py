#!/usr/bin/env python3
"""
The lockbox custodian's tool (docs/BRIDGE.md, "Run the custodian's side").

QRDX burns a withdrawal and records it; the custodian, a multisig on the source chain, releases
it from the lockbox. This tool plans and checks that work. It never holds the multisig's keys:
the signers review and sign the batch it writes in the Safe app.

    # Every signer runs this against their OWN QRDX node(s) and compares the batch hash:
    python scripts/bridge/custodian.py plan --qrdx-rpc http://my-node:3007/rpc \\
        --rpc https://arb1.example/rpc --chain-id 42161 --lockbox 0xLockbox --safe 0xSafe \\
        --batch releases.json

    python scripts/bridge/custodian.py reconcile ... --from-block <deployment block>
    python scripts/bridge/custodian.py deposits  ... --from-block <deployment block>
    python scripts/bridge/custodian.py refunds   ... --from-block <deployment block> --batch r.json
    python scripts/bridge/custodian.py status    ...

Commands:
  plan       the finalized withdrawals not yet released: a summary, the batch hash, and the
             Safe Transaction Builder batch (--batch). Refuses if the QRDX nodes named disagree.
  reconcile  every Released event against QRDX's records: paid exactly, once, and only a
             finalized withdrawal; and every Refunded event: a whole deposit back to its
             depositor, never minted, after its window closed. Exits 1 on any alarm.
  deposits   every Deposit event against QRDX: minted, waiting, or not attested.
  refunds    the deposits QRDX will never mint (an unlisted token, a recipient QRDX refuses, no
             quorum within the deposit window): QRDX's finalized time is past their window and
             no node reports them minted. A summary, the batch hash and the Safe batch
             (--batch); each refund goes back to its depositor.
  status     the lockbox's custodian, whether deposits are paused, and each asset's backing:
             tokens locked against QRDX's supply plus what is waiting to be released.
  release    TEST NETWORKS ONLY: a single-key custodian sends the planned releases itself.
  refund     TEST NETWORKS ONLY: a single-key custodian sends the planned refunds itself.
"""

from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from qrdx.bridge import lockbox as L  # noqa: E402


def _common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--qrdx-rpc",
        action="append",
        required=True,
        help="a QRDX node's /rpc URL; repeat it: every node must agree",
    )
    ap.add_argument("--rpc", required=True, help="the source chain's JSON-RPC URL")
    ap.add_argument("--chain-id", required=True, type=int, help="the source chain's id")
    ap.add_argument("--lockbox", required=True, help="the lockbox's address there")


def _setup(args):
    rpc = L.JsonRpc(args.rpc)
    if L.chain_id(rpc) != args.chain_id:
        raise L.LockboxError(f"{args.rpc} is not chain {args.chain_id}")
    view = L.agreed_view([L.JsonRpc(u) for u in args.qrdx_rpc], getattr(args, "from_id", 1))
    return rpc, view


def cmd_plan(args) -> int:
    rpc, view = _setup(args)
    mine = [int(w["id"]) for w in view.withdrawals if int(w["chain"]) == args.chain_id]
    plan = L.plan_releases(view, args.chain_id, L.released_ids(rpc, args.lockbox, mine), args.max)
    print(
        f"QRDX finalized height {view.finalized}; {len(mine)} withdrawals to chain "
        f"{args.chain_id} ({len(plan.released)} released, {len(plan.waiting)} waiting)"
    )
    for r in plan.releases:
        print(
            f"  #{r.withdrawal_id}  {r.amount} ({r.units} units) of {r.token} -> {r.to}  "
            f"[QRDX block {r.height}]"
        )
    if not plan.releases:
        print("nothing to release")
        return 0
    print(f"batch hash {plan.batch_hash()}  (every signer must get the same from their own node)")
    for token in {r.token for r in plan.releases}:
        need = sum(r.units for r in plan.releases if r.token == token)
        have = L.token_balance(rpc, token, args.lockbox)
        if have < need:
            raise L.LockboxError(
                f"the lockbox holds {have} units of {token}; the batch pays {need}"
            )
    if args.batch:
        Path(args.batch).write_text(
            json.dumps(L.safe_batch(args.chain_id, args.safe or "", args.lockbox, plan), indent=1)
            + "\n"
        )
        print(f"Safe Transaction Builder batch written to {args.batch}")
    return 0


def cmd_release(args) -> int:
    rpc, view = _setup(args)
    mine = [int(w["id"]) for w in view.withdrawals if int(w["chain"]) == args.chain_id]
    plan = L.plan_releases(view, args.chain_id, L.released_ids(rpc, args.lockbox, mine), args.max)
    account = L.load_account(args.keystore, args.password, "QRDX_CUSTODIAN_KEY")
    if L.custodian_of(rpc, args.lockbox) != account.address:
        raise L.LockboxError(f"{account.address} is not the lockbox's custodian")
    print("WARNING: a single-key custodian is for test networks; mainnet uses a multisig")
    for r in plan.releases:
        tx = L.build_tx(
            rpc, account.address, args.chain_id, args.lockbox, r.calldata(), legacy=args.legacy
        )
        receipt = L.send(rpc, account, tx)
        if not L.is_released(rpc, args.lockbox, r.withdrawal_id):
            raise L.LockboxError(f"withdrawal {r.withdrawal_id} is not marked released")
        print(f"released #{r.withdrawal_id}: {r.amount} to {r.to} ({receipt['transactionHash']})")
    if not plan.releases:
        print("nothing to release")
    return 0


def cmd_reconcile(args) -> int:
    rpc, view = _setup(args)
    head = int(rpc.call("eth_blockNumber"), 16)
    events = L.released_events(rpc, args.lockbox, args.from_block, head)
    rec = L.reconcile(view, args.chain_id, events)
    print(
        f"{len(rec.matched)} releases match QRDX's records; {len(rec.pending)} finalized "
        f"withdrawals await release {rec.pending[:20]}; {len(rec.waiting)} await QRDX finality"
    )
    deposits, refund_view, _refunded = _refund_inputs(args, rpc)
    refunds = L.refunded_events(rpc, args.lockbox, args.from_block, head)
    alarms = rec.alarms + L.reconcile_refunds(deposits, refund_view, refunds)
    print(f"{len(refunds)} refunds checked against QRDX")
    for alarm in alarms:
        print(f"ALARM {alarm}")
    return 1 if alarms else 0


def _refund_inputs(args, rpc):
    """The lockbox's deposits up to its chain's finalized block, what the QRDX nodes agree on
    for them (with the source chain's time and the lockbox's refund delay), and the ones the
    lockbox has refunded."""
    import dataclasses

    finalized = L.finalized_block(rpc)
    deposits = L.deposit_events(rpc, args.chain_id, args.lockbox, args.from_block, finalized)
    nodes = [L.JsonRpc(u) for u in args.qrdx_rpc]
    view = L.agreed_refund_view(nodes, [d.deposit_id for d in deposits])
    view = dataclasses.replace(
        view,
        source_time=L.block_time(rpc, int(rpc.call("eth_blockNumber"), 16)),
        refund_delay=L.refund_delay(rpc, args.lockbox),
    )
    refunded = {
        d.deposit_id
        for d in deposits
        if d.deposit_id not in view.minted and L.is_refunded(rpc, args.lockbox, d.number)
    }
    return deposits, view, refunded


def _refund_plan(args):
    rpc, _view = _setup(args)
    deposits, view, refunded = _refund_inputs(args, rpc)
    plan = L.plan_refunds(deposits, view, refunded, args.max)
    print(
        f"QRDX finalized time {view.finalized_time}, deposit window {view.window} s: "
        f"{len(deposits)} deposits ({len(plan.minted)} minted, {len(plan.refunded)} refunded, "
        f"{len(plan.window_open)} still mintable)"
    )
    for r in plan.refunds:
        d = r.deposit
        print(f"  {r.deposit_id}  {d.units} units of {d.token} back to {d.sender}")
    return rpc, plan


def cmd_refunds(args) -> int:
    _rpc, plan = _refund_plan(args)
    if not plan.refunds:
        print("nothing to refund")
        return 0
    print(f"batch hash {plan.batch_hash()}  (every signer must get the same from their own node)")
    if args.batch:
        batch = L.safe_batch(
            args.chain_id, args.safe or "", args.lockbox, plan, "QRDX bridge refunds"
        )
        Path(args.batch).write_text(json.dumps(batch, indent=1) + "\n")
        print(f"Safe Transaction Builder batch written to {args.batch}")
    return 0


def cmd_refund(args) -> int:
    rpc, plan = _refund_plan(args)
    account = L.load_account(args.keystore, args.password, "QRDX_CUSTODIAN_KEY")
    if L.custodian_of(rpc, args.lockbox) != account.address:
        raise L.LockboxError(f"{account.address} is not the lockbox's custodian")
    print("WARNING: a single-key custodian is for test networks; mainnet uses a multisig")
    for r in plan.refunds:
        tx = L.build_tx(
            rpc, account.address, args.chain_id, args.lockbox, r.calldata(), legacy=args.legacy
        )
        receipt = L.send(rpc, account, tx)
        if not L.is_refunded(rpc, args.lockbox, r.deposit.number):
            raise L.LockboxError(f"deposit {r.deposit_id} is not marked refunded")
        print(
            f"refunded {r.deposit_id}: {r.deposit.units} units to {r.deposit.sender} "
            f"({receipt['transactionHash']})"
        )
    if not plan.refunds:
        print("nothing to refund")
    return 0


def cmd_deposits(args) -> int:
    rpc, view = _setup(args)
    nodes = [L.JsonRpc(u) for u in args.qrdx_rpc]
    finalized = L.finalized_block(rpc)
    events = L.deposit_events(rpc, args.chain_id, args.lockbox, args.from_block, finalized)
    minted, pending, unseen = 0, [], []
    for e in events:
        status = nodes[0].call("bridge_getDeposit", e.deposit_id)
        if status.get("minted"):
            minted += 1
        elif status.get("pending"):
            pending.append(e.deposit_id)
        else:
            unseen.append(e.deposit_id)
    print(
        f"{len(events)} deposits up to finalized block {finalized}: {minted} minted, "
        f"{len(pending)} attested and not minted, {len(unseen)} not attested yet"
    )
    for d in pending[:20]:
        print(
            f"  attested, not minted (short of a quorum, or held by a guardrail: bridge_getGuardrails): {d}"
        )
    for d in unseen[:20]:
        print(f"  not attested: {d} (is the token listed? are the validators' watchers running?)")
    return 0


def cmd_status(args) -> int:
    rpc, view = _setup(args)
    print(f"lockbox {L.to_checksum_address(args.lockbox)} on chain {args.chain_id}")
    print(
        f"  custodian {L.custodian_of(rpc, args.lockbox)}; deposits paused: "
        f"{L.deposits_paused(rpc, args.lockbox)}"
    )
    mine = [w for w in view.withdrawals if int(w["chain"]) == args.chain_id]
    released = L.released_ids(rpc, args.lockbox, [int(w["id"]) for w in mine])
    status = 0
    for asset in view.assets:
        if int(asset["chain"]) != args.chain_id:
            continue
        token, dec = L.to_checksum_address(asset["source_token"]), int(asset["decimals"])
        locked = Decimal(L.token_balance(rpc, token, args.lockbox)).scaleb(-dec)
        supply = Decimal(str(asset["supply"]))
        owed = sum(
            (
                Decimal(w["amount"])
                for w in mine
                if int(w["id"]) not in released and str(w["token"]).lower() == token.lower()
            ),
            Decimal(0),
        )
        backed = locked >= supply + owed
        print(
            f"  {asset['symbol']}: locked {locked}; QRDX supply {supply} + unreleased "
            f"withdrawals {owed} = {supply + owed}  {'BACKED' if backed else 'SHORT'}"
        )
        status |= 0 if backed else 1
    return status


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, help_ in (
        ("plan", "plan the releases and write the Safe batch"),
        ("release", "TEST NETWORKS ONLY: send the releases with a single key"),
        ("reconcile", "check every release and refund against QRDX"),
        ("deposits", "check every deposit against QRDX"),
        ("refunds", "plan the refunds of deposits QRDX will never mint"),
        ("refund", "TEST NETWORKS ONLY: send the refunds with a single key"),
        ("status", "the lockbox and each asset's backing"),
    ):
        p = sub.add_parser(name, help=help_)
        _common(p)
        if name in ("plan", "release", "refunds", "refund"):
            p.add_argument("--max", type=int, help="at most this many")
        if name in ("plan", "release"):
            p.add_argument("--from-id", type=int, default=1, help="QRDX withdrawals from this id")
        if name in ("plan", "refunds"):
            p.add_argument("--safe", help="the custodian Safe's address (for the batch's metadata)")
            p.add_argument("--batch", help="write the Safe Transaction Builder batch here")
        if name in ("release", "refund"):
            p.add_argument("--keystore", help="the custodian's keystore (else QRDX_CUSTODIAN_KEY)")
            p.add_argument("--password")
            p.add_argument("--legacy", action="store_true")
        if name in ("reconcile", "deposits", "refunds", "refund"):
            p.add_argument(
                "--from-block", type=int, required=True, help="the lockbox's deployment block"
            )
    args = ap.parse_args(argv)
    try:
        return {
            "plan": cmd_plan,
            "release": cmd_release,
            "reconcile": cmd_reconcile,
            "deposits": cmd_deposits,
            "refunds": cmd_refunds,
            "refund": cmd_refund,
            "status": cmd_status,
        }[args.cmd](args)
    except L.LockboxError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
