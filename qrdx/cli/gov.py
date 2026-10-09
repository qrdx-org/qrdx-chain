"""
``qrdx-wallet gov …`` — on-chain governance from the command line (docs/GOVERNANCE.md).

Validators propose and vote (weighted by their stake); any holder may veto a passed proposal
during its timelock by locking QRDX; anyone may execute it once the timelock has ended. Writes
are exchange transactions signed with the wallet's post-quantum key.

    qrdx-wallet gov status
    qrdx-wallet gov list [--status open]
    qrdx-wallet gov show 3
    qrdx-wallet gov propose-spend validator.json 0x…0008 0xPQ… 250000 --memo "Q3 grants"
    qrdx-wallet gov propose-freeze validator.json
    qrdx-wallet gov propose-fork validator.json randao
    qrdx-wallet gov vote validator.json 3 yes
    qrdx-wallet gov veto holder.json 3 50000
    qrdx-wallet gov execute any.json 3
"""
from __future__ import annotations

import json
from decimal import Decimal

import click

from .perp import _send, json_option, node_option, rpc

wait_option = click.option("--wait", is_flag=True, help="Wait for the receipt")
yes_option = click.option("--yes", "-y", is_flag=True, help="Do not ask for confirmation")
memo_option = click.option("--memo", default="", help="Why (stored with the proposal, ≤ 280 chars)")


def _show(p) -> None:
    click.echo(f"#{p['id']}  {p['status'].upper():9}  {p['action']}  {json.dumps(p['params'])}")
    click.echo(f"    by {p['proposer']}  created {p['created_at']}  voting until {p['voting_ends']}")
    total = Decimal(p["total_weight"])
    if total:
        click.echo(f"    yes {p['yes']} / no {p['no']} of {p['total_weight']} stake "
                   f"(needs {p['threshold_bps'] / 100:.2f}%)")
    if p.get("timelock_ends") is not None:
        click.echo(f"    passed {p['passed_at']}: vetoable until {p['timelock_ends']}, "
                   f"executable until {p['execute_by']}; vetoes {p['veto_total']} QRDX")
    if p.get("memo"):
        click.echo(f"    memo: {p['memo']}")


@click.group("gov")
def gov():
    """On-chain governance: system-wallet spends, freezing the master controller, approving forks."""


@gov.command("status")
@node_option
@json_option
def status_cmd(node, as_json):
    """Parameters, the master controller's authority, fork approvals."""
    s = rpc(node, "governance_getStatus")
    if as_json:
        click.echo(json.dumps(s, indent=2))
        return
    m = s["master_controller"]
    click.echo(f"height {s['height']}  open proposals {s['open_proposals']}")
    click.echo("master controller: " + ("has authority" if m["authority"] else m["reason"]))
    click.echo(f"  sunset at block {m['sunset_height']}; frozen at {m['frozen_at']}")
    for f in s["scheduled_forks"]:
        a = f["approval"]
        state = (f"approved at {a['approved_at']}" if a["approved"]
                 else f"needs approval by block {a['approve_by']}")
        click.echo(f"fork {f['name']} @ {f['height']} ({', '.join(f['features'])}): {state}")
    for k, v in s["params"].items():
        click.echo(f"  {k} = {v}")


@gov.command("list")
@click.option("--status", default=None, help="open, voting, passed, rejected, vetoed, executed, expired")
@click.option("--limit", default=20, show_default=True)
@node_option
@json_option
def list_cmd(status, limit, node, as_json):
    """Proposals, newest first."""
    rows = rpc(node, "governance_getProposals", [status, limit])
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    for p in rows:
        _show(p)
    if not rows:
        click.echo("No proposals.")


@gov.command("show")
@click.argument("proposal_id", type=int)
@node_option
@json_option
def show_cmd(proposal_id, node, as_json):
    """One proposal: votes, timelock, vetoes."""
    p = rpc(node, "governance_getProposal", [proposal_id])
    if as_json:
        click.echo(json.dumps(p, indent=2))
    else:
        _show(p)


@gov.command("propose-spend")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("system_wallet")
@click.argument("to")
@click.argument("amount")
@memo_option
@node_option
@wait_option
@yes_option
def propose_spend_cmd(wallet_file, system_wallet, to, amount, memo, node, wait, yes):
    """Propose moving AMOUNT QRDX from SYSTEM_WALLET to TO (validators only)."""
    _send(node, wallet_file, "GOV_PROPOSE",
          {"action": "system_spend", "wallet": system_wallet, "to": to,
           "amount": str(Decimal(amount)), "memo": memo},
          f"Propose: spend {amount} QRDX from {system_wallet} to {to}", wait, yes, group="gov")


@gov.command("propose-freeze")
@click.argument("wallet_file", type=click.Path(exists=True))
@memo_option
@node_option
@wait_option
@yes_option
def propose_freeze_cmd(wallet_file, memo, node, wait, yes):
    """Propose ending the master controller's authority over the system wallets now."""
    _send(node, wallet_file, "GOV_PROPOSE", {"action": "freeze_master", "memo": memo},
          "Propose: freeze the master controller", wait, yes, group="gov")


@gov.command("propose-fork")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("fork")
@memo_option
@node_option
@wait_option
@yes_option
def propose_fork_cmd(wallet_file, fork, memo, node, wait, yes):
    """Propose approving FORK, as scheduled in the node's chain spec (its exact definition)."""
    params = rpc(node, "governance_getForkApprovalParams", [fork])
    approve_by = params.pop("approve_by")
    params["memo"] = memo
    _send(node, wallet_file, "GOV_PROPOSE", params,
          f"Propose: approve fork {fork} at height {params['height']} "
          f"(definition {params['definition_hash'][:16]}…; must execute by block {approve_by})",
          wait, yes, group="gov")


@gov.command("vote")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("proposal_id", type=int)
@click.argument("choice", type=click.Choice(["yes", "no"]))
@node_option
@wait_option
@yes_option
def vote_cmd(wallet_file, proposal_id, choice, node, wait, yes):
    """Vote on a proposal (validators in its stake snapshot; votes are final)."""
    _send(node, wallet_file, "GOV_VOTE", {"proposal_id": proposal_id, "support": choice == "yes"},
          f"Vote {choice} on proposal #{proposal_id}", wait, yes, group="gov")


@gov.command("veto")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("proposal_id", type=int)
@click.argument("amount")
@node_option
@wait_option
@yes_option
def veto_cmd(wallet_file, proposal_id, amount, node, wait, yes):
    """Lock AMOUNT QRDX against a passed proposal during its timelock. It comes back when the
    proposal is vetoed, executed or expires."""
    _send(node, wallet_file, "GOV_VETO", {"proposal_id": proposal_id, "amount": str(Decimal(amount))},
          f"Veto proposal #{proposal_id}, locking {amount} QRDX", wait, yes, group="gov")


@gov.command("execute")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("proposal_id", type=int)
@node_option
@wait_option
@yes_option
def execute_cmd(wallet_file, proposal_id, node, wait, yes):
    """Execute a passed proposal whose timelock has ended (anyone may)."""
    _send(node, wallet_file, "GOV_EXECUTE", {"proposal_id": proposal_id},
          f"Execute proposal #{proposal_id}", wait, yes, group="gov")
