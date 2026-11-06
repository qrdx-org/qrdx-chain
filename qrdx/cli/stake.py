"""
``qrdx-wallet stake …`` — staking from the command line (docs/STAKING.md).

Running a validator: ``deposit`` locks QRDX from the wallet and registers it (pending until its
activation epoch); ``exit`` starts the exit, and the principal comes back in a block
``WITHDRAWAL_DELAY_EPOCHS`` after the exit epoch, less anything slashed meanwhile.
``commission`` sets the validator's cut of its pool's rewards.

Staking without running one: ``delegate`` locks QRDX in a validator's pool; its shares earn the
staking rate less the validator's commission, compounding. ``undelegate`` redeems them, paid
after the unbonding period. ``pools`` and ``delegations`` show what is staked where.

    qrdx-wallet stake status [0xPQ…]
    qrdx-wallet stake deposit validator.json 100000
    qrdx-wallet stake exit validator.json
    qrdx-wallet stake commission validator.json 800
    qrdx-wallet stake pools
    qrdx-wallet stake delegate wallet.json 0xPQ…validator 2500
    qrdx-wallet stake delegations 0xPQ…
    qrdx-wallet stake undelegate wallet.json 0xPQ…validator [--shares 100]
    qrdx-wallet stake receipt <tx_hash>
"""

from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional

import click

from .perp import _send, json_option, node_option, receipt_cmd, rpc

wait_option = click.option("--wait", is_flag=True, help="Wait for the receipt")
yes_option = click.option("--yes", "-y", is_flag=True, help="Do not ask for confirmation")


def _validators(node: str) -> List[Dict[str, Any]]:
    import httpx

    try:
        resp = httpx.get(f"{node.rstrip('/')}/get_validators", timeout=20.0)
    except Exception as e:
        raise click.ClickException(f"cannot reach {node}: {e}") from e
    if resp.status_code != 200:
        raise click.ClickException(f"/get_validators failed (HTTP {resp.status_code})")
    return list(resp.json().get("validators") or [])


def _principal_epoch(v: Dict[str, Any]) -> Optional[int]:
    """The epoch from which an exiting validator's principal is paid."""
    from qrdx.constants import WITHDRAWAL_DELAY_EPOCHS

    exit_epoch = v.get("exit_epoch")
    if exit_epoch is None:
        return None
    return int(exit_epoch) + int(WITHDRAWAL_DELAY_EPOCHS)


def _show(v: Dict[str, Any]) -> None:
    status = str(v.get("status", "")).lower()
    flag = click.style(" SLASHED", fg="red") if v.get("slashed") else ""
    click.echo(f"{v['address']}  {status.upper()}{flag}")
    click.echo(f"    stake {v.get('stake')}  effective {v.get('effective_stake')}")
    if v.get("activation_epoch") is not None:
        click.echo(f"    activation epoch {v['activation_epoch']}")
    if v.get("exit_epoch") is not None:
        click.echo(
            f"    exit epoch {v['exit_epoch']}; principal paid from epoch {_principal_epoch(v)}"
        )


@click.group("stake")
def stake():
    """Validator staking: deposit, exit, status."""


@stake.command("status")
@click.argument("address", required=False)
@node_option
@json_option
def status_cmd(address, node, as_json):
    """The validator set, or one validator (ADDRESS)."""
    rows = _validators(node)
    if address:
        rows = [v for v in rows if str(v.get("address", "")).lower() == address.lower()]
        if not rows:
            raise click.ClickException(f"{address} is not a validator")
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    for v in rows:
        _show(v)
    if not rows:
        click.echo("No validators.")


@stake.command("deposit")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("amount")
@node_option
@wait_option
@yes_option
def deposit_cmd(wallet_file, amount, node, wait, yes):
    """Lock AMOUNT QRDX and register the wallet as a validator."""
    from qrdx.constants import MIN_VALIDATOR_STAKE

    try:
        stake_amount = Decimal(amount)
    except InvalidOperation as e:
        raise click.ClickException(f"not an amount: {amount}") from e
    if stake_amount < MIN_VALIDATOR_STAKE:
        raise click.ClickException(
            f"a validator stakes at least {MIN_VALIDATOR_STAKE} QRDX (got {stake_amount})"
        )
    _send(
        node,
        wallet_file,
        "STAKE_DEPOSIT",
        lambda signer: {
            "stake_amount": str(stake_amount),
            "validator_public_key": signer.public_key.hex(),
        },
        f"Stake {stake_amount} QRDX as a validator (locked until exit + withdrawal delay)",
        wait,
        yes,
        group="stake",
    )


@stake.command("exit")
@click.argument("wallet_file", type=click.Path(exists=True))
@node_option
@wait_option
@yes_option
def exit_cmd(wallet_file, node, wait, yes):
    """Start the validator's exit (also how an ejected validator claims its principal)."""
    _send(
        node,
        wallet_file,
        "STAKE_EXIT",
        {},
        "Exit as a validator: the principal is paid after the withdrawal delay",
        wait,
        yes,
        group="stake",
    )


@stake.command("commission")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("basis_points", type=int)
@node_option
@wait_option
@yes_option
def commission_cmd(wallet_file, basis_points, node, wait, yes):
    """Set the validator's commission on its pool's rewards (basis points; 800 = 8 %)."""
    if not 0 <= basis_points <= 10_000:
        raise click.ClickException("0 to 10,000 basis points")
    _send(
        node,
        wallet_file,
        "STAKE_SET_COMMISSION",
        {"commission_bps": basis_points},
        f"Set the pool commission to {basis_points / 100:.2f} % (from the next epoch)",
        wait,
        yes,
        group="stake",
    )


@stake.command("pools")
@node_option
@json_option
def pools_cmd(node, as_json):
    """Every validator's delegation pool."""
    rows = rpc(node, "staking_getPools")
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    for p in rows:
        click.echo(
            f"{p['validator']}  commission {p['commission_bps'] / 100:.2f} %  "
            f"value {p['value']} QRDX  {p['delegators']} delegator(s)  "
            f"share {p['share_price']}  warming up {p['warming_up']}"
        )
    if not rows:
        click.echo("No pools yet: the first delegation to a validator opens one.")


@stake.command("delegate")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("validator")
@click.argument("amount")
@node_option
@wait_option
@yes_option
def delegate_cmd(wallet_file, validator, amount, node, wait, yes):
    """Lock AMOUNT QRDX in VALIDATOR's pool."""
    from qrdx.constants import STAKE_MIN_DELEGATION

    try:
        value = Decimal(amount)
    except InvalidOperation as e:
        raise click.ClickException(f"not an amount: {amount}") from e
    if value < STAKE_MIN_DELEGATION:
        raise click.ClickException(f"delegate at least {STAKE_MIN_DELEGATION} QRDX")
    _send(
        node,
        wallet_file,
        "STAKE_DELEGATE",
        {"validator": validator, "amount": str(value)},
        f"Delegate {value} QRDX to {validator} (earning once it has warmed up)",
        wait,
        yes,
        group="stake",
    )


@stake.command("undelegate")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("validator")
@click.option("--shares", default="all", show_default=True, help="Shares to redeem")
@node_option
@wait_option
@yes_option
def undelegate_cmd(wallet_file, validator, shares, node, wait, yes):
    """Redeem shares of VALIDATOR's pool: paid after the unbonding period."""
    _send(
        node,
        wallet_file,
        "STAKE_UNDELEGATE",
        {"validator": validator, "shares": shares},
        f"Undelegate {shares} share(s) from {validator} (paid after unbonding)",
        wait,
        yes,
        group="stake",
    )


@stake.command("delegations")
@click.argument("address")
@node_option
@json_option
def delegations_cmd(address, node, as_json):
    """ADDRESS's stake in each pool, and the payouts owed to it."""
    d = rpc(node, "staking_getDelegations", [address])
    if as_json:
        click.echo(json.dumps(d, indent=2))
        return
    for s in d["stakes"]:
        click.echo(f"{s['validator']}  {s['shares']} share(s) worth {s['value']} QRDX")
        for w in s["warming_up"]:
            click.echo(
                f"    warming up: {w['amount']} QRDX, earning from epoch {w['active_from_epoch']}"
            )
    for p in d["payouts"]:
        click.echo(f"owed: {p['amount']} QRDX ({p['kind']}), paid from epoch {p['due_epoch']}")
    if not d["stakes"] and not d["payouts"]:
        click.echo("Nothing staked.")


stake.add_command(receipt_cmd, "receipt")
