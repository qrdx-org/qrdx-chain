"""
``qrdx-wallet bridge …`` — the consensus bridge from the command line (docs/BRIDGE.md).

Deposits are made on the source chain, into its lockbox (``deposit(token, amount, recipient)``),
and minted here once validators holding two thirds of the stake attest them. A withdrawal burns
the bridged token here; the lockbox's custodian releases it on the source chain.

    qrdx-wallet bridge assets
    qrdx-wallet bridge deposit 42161:0x…:7
    qrdx-wallet bridge withdrawals [--from 1]
    qrdx-wallet bridge withdraw wallet.json USDC 250 0x…recipient-on-the-source-chain
"""

from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation

import click

from .perp import _send, json_option, node_option, receipt_cmd, rpc

wait_option = click.option("--wait", is_flag=True, help="Wait for the receipt")
yes_option = click.option("--yes", "-y", is_flag=True, help="Do not ask for confirmation")


@click.group("bridge")
def bridge():
    """The consensus bridge: bridged assets, deposits, withdrawals."""


@bridge.command("assets")
@node_option
@json_option
def assets_cmd(node, as_json):
    """The tokens the bridge carries."""
    rows = rpc(node, "bridge_getAssets")
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    for a in rows:
        click.echo(
            f"{a['symbol']:8} chain {a['chain']} token {a['source_token']} "
            f"({a['decimals']} decimals) → {a['token_address']}  minted {a['supply']}"
        )
    if not rows:
        click.echo("This network bridges no assets.")


@bridge.command("deposit")
@click.argument("deposit_id")
@node_option
@json_option
def deposit_cmd(deposit_id, node, as_json):
    """A deposit's status: DEPOSIT_ID is <chain id>:<transaction hash>:<log index>."""
    d = rpc(node, "bridge_getDeposit", [deposit_id])
    if as_json:
        click.echo(json.dumps(d, indent=2))
        return
    if d["minted"]:
        click.echo(click.style("✓ minted", fg="green") + f"  {d['id']}")
    elif d["pending"]:
        for p in d["pending"]:
            dep = p["deposit"]
            click.echo(
                f"attested by {len(p['voters'])} validator(s) since {p['since']}: "
                f"{dep['amount']} to {dep['to']}"
            )
    else:
        click.echo("Not attested yet (validators attest deposits once their block is final).")


@bridge.command("withdrawals")
@click.option("--from", "from_id", default=1, show_default=True, help="First withdrawal id")
@click.option("--limit", default=50, show_default=True)
@node_option
@json_option
def withdrawals_cmd(from_id, limit, node, as_json):
    """Recorded withdrawals, oldest first: what the custodian releases."""
    rows = rpc(node, "bridge_getWithdrawals", [from_id, limit])
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    for w in rows:
        click.echo(
            f"#{w['id']}  {w['amount']} of {w['token']} to {w['to']} on chain {w['chain']}"
            f"  (block {w['height']})"
        )
    if not rows:
        click.echo("No withdrawals.")


@bridge.command("withdraw")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("asset")
@click.argument("amount")
@click.argument("to")
@node_option
@wait_option
@yes_option
def withdraw_cmd(wallet_file, asset, amount, to, node, wait, yes):
    """Burn AMOUNT of a bridged ASSET (its symbol or QRDX token address) for TO on its source
    chain."""
    try:
        value = Decimal(amount)
    except InvalidOperation as e:
        raise click.ClickException(f"not an amount: {amount}") from e
    assets = rpc(node, "bridge_getAssets") or []
    match = [
        a for a in assets if asset.lower() in (a["token_address"].lower(), a["symbol"].lower())
    ]
    if len(match) != 1:
        known = ", ".join(a["symbol"] for a in assets) or "none"
        raise click.ClickException(f"{asset} is not one bridged asset (bridged: {known})")
    a = match[0]
    _send(
        node,
        wallet_file,
        "BRIDGE_WITHDRAW",
        {"token_address": a["token_address"], "amount": str(value), "to": to},
        f"Withdraw {value} {a['symbol']} to {to} on chain {a['chain']} (burned here)",
        wait,
        yes,
        group="bridge",
    )


bridge.add_command(receipt_cmd, "receipt")
