"""
``qrdx-wallet token …`` — native tokens from the command line (docs/NATIVE_TOKENS.md).

Reads need only a node. Writes are exchange transactions signed with the wallet's
post-quantum key and gossiped to every node (see ``qrdx-wallet perp``); ``--wait`` prints the
receipt once a block includes them.

    qrdx-wallet token list
    qrdx-wallet token info 0x…
    qrdx-wallet token balance 0x… 0xPQ…
    qrdx-wallet token deploy wallet.json "Bridged USD" qUSD --decimals 6 --mint-authority self
    qrdx-wallet token mint wallet.json 0x… 1000 --to 0xPQ…
    qrdx-wallet token transfer wallet.json 0x… 0xPQ… 25
    qrdx-wallet token approve wallet.json 0x… <spender> 100
    qrdx-wallet token set-authority wallet.json 0x… mint none     # renounce, for good

Extensions (docs/NATIVE_TOKENS.md §7) are chosen at deploy — ``--uri``, ``--field k=v``,
``--transfer-fee-bps``, ``--non-transferable``, ``--default-frozen``, ``--permanent-delegate``,
``--pausable``, ``--default-operator`` — and managed with ``metadata``, ``set-fee``,
``withdraw-fees``, ``pause`` / ``resume`` and ``operator`` / ``revoke-operator``.
"""
from __future__ import annotations

import json

import click

from .perp import _print_receipt, _send, json_option, node_option, rpc

wait_option = click.option("--wait", is_flag=True, help="Wait for the receipt")
yes_option = click.option("--yes", "-y", is_flag=True, help="Do not ask for confirmation")
wallet_arg = click.argument("wallet_file", type=click.Path(exists=True))


def _authority(value, signer):
    """``self`` → the signing wallet, ``none`` / empty → no authority, else an address."""
    if value is None or str(value).lower() in ("", "none"):
        return ""
    return signer.address if str(value).lower() == "self" else str(value)


def _show_token(t) -> None:
    click.echo(click.style(f"{t['symbol']}", bold=True) + f"  {t['name']}  {t['token_address']}")
    cap = t.get("max_supply") or "uncapped"
    click.echo(f"  supply {t['total_supply']} (max {cap}), {t['decimals']} decimals")
    click.echo(f"  mint authority:   {t.get('mint_authority') or 'none (fixed supply)'}")
    click.echo(f"  freeze authority: {t.get('freeze_authority') or 'none'}")
    ext = t.get("extensions") or {}
    if "metadata" in ext:
        m = ext["metadata"]
        click.echo(f"  metadata: {m['uri'] or '(no uri)'}"
                   + "".join(f"  {k}={v}" for k, v in m["fields"].items())
                   + f"  (update authority: {m['update_authority'] or 'none — immutable'})")
    if "transfer_fee" in ext:
        f = ext["transfer_fee"]
        click.echo(f"  transfer fee: {f['bps']} bps (max {f['max_fee'] or 'uncapped'}), "
                   f"withheld at {f['withheld_at']}")
        if f.get("pending"):
            click.echo(f"    → {f['pending']['bps']} bps from block {f['pending']['from_height']}")
    for flag, text in (("non_transferable", "non-transferable"),
                       ("default_frozen", "accounts start frozen")):
        if ext.get(flag):
            click.echo(f"  {text}")
    if ext.get("permanent_delegate"):
        click.echo(f"  permanent delegate: {ext['permanent_delegate']}")
    if "pausable" in ext:
        click.echo(f"  pausable ({'PAUSED' if ext['pausable']['paused'] else 'running'})")
    if ext.get("default_operators"):
        click.echo(f"  default operators: {', '.join(ext['default_operators'])}")


@click.group("token")
def token():
    """Native tokens: deploy, mint, burn, transfer, approve, freeze."""


# ── reads ──────────────────────────────────────────────────────────────────

@token.command("list")
@node_option
@json_option
def list_cmd(node, as_json):
    """Every native token."""
    rows = rpc(node, "exchange_getTokens")
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("No tokens yet.")
    for t in rows:
        _show_token(t)


@token.command("info")
@click.argument("token_address")
@node_option
@json_option
def info_cmd(token_address, node, as_json):
    """One token: supply, decimals, authorities."""
    t = rpc(node, "exchange_getToken", [token_address])
    click.echo(json.dumps(t, indent=2)) if as_json else _show_token(t)


@token.command("balance")
@click.argument("token_address")
@click.argument("address")
@node_option
@json_option
def balance_cmd(token_address, address, node, as_json):
    """A holder's balance (and whether it is frozen)."""
    acct = rpc(node, "exchange_getTokenAccount", [token_address, address])
    if as_json:
        click.echo(json.dumps(acct, indent=2))
        return
    click.echo(f"{acct['balance']}" + (click.style("  (frozen)", fg="red") if acct["frozen"] else ""))


@token.command("allowance")
@click.argument("token_address")
@click.argument("owner")
@click.argument("spender")
@node_option
def allowance_cmd(token_address, owner, spender, node):
    """How much of OWNER's tokens SPENDER may move."""
    click.echo(rpc(node, "exchange_getAllowance", [token_address, owner, spender])["allowance"])


@token.command("receipt")
@click.argument("tx_hash")
@node_option
@json_option
def receipt_cmd(tx_hash, node, as_json):
    """The result of a submitted transaction."""
    r = rpc(node, "exchange_getTransactionReceipt", [tx_hash])
    if r is None:
        click.echo("Pending (not in a block yet), or unknown.")
    elif as_json:
        click.echo(json.dumps(r, indent=2))
    else:
        _print_receipt(r)


# ── writes ─────────────────────────────────────────────────────────────────

@token.command("deploy")
@wallet_arg
@click.argument("name")
@click.argument("symbol")
@click.option("--supply", default="0", show_default=True, help="Initial supply, to you")
@click.option("--decimals", default=18, show_default=True, type=int)
@click.option("--max-supply", default=None, help="Cap on minting (default: uncapped)")
@click.option("--mint-authority", default=None,
              help="Who may mint: an address, 'self', or omitted for a fixed supply")
@click.option("--freeze-authority", default=None,
              help="Who may freeze accounts: an address, 'self', or omitted for never")
@click.option("--uri", default=None, help="Metadata URI (you hold the update authority)")
@click.option("--field", "fields", multiple=True, help="Extra metadata, key=value (repeatable)")
@click.option("--transfer-fee-bps", default=None, type=int,
              help="Transfer fee in basis points, withheld for you to withdraw")
@click.option("--max-transfer-fee", default=None, help="Cap on one transfer's fee")
@click.option("--non-transferable", is_flag=True, help="Soulbound: minted and burned only")
@click.option("--default-frozen", is_flag=True,
              help="Accounts start frozen until the freeze authority thaws them")
@click.option("--permanent-delegate", default=None,
              help="An address (or 'self') that may move or burn anyone's balance")
@click.option("--pausable", is_flag=True, help="You may pause every transfer, mint and burn")
@click.option("--default-operator", "default_operators", multiple=True,
              help="An ERC-777 default operator for every holder (repeatable)")
@node_option
@wait_option
@yes_option
def deploy_cmd(wallet_file, name, symbol, supply, decimals, max_supply, mint_authority,
               freeze_authority, uri, fields, transfer_fee_bps, max_transfer_fee,
               non_transferable, default_frozen, permanent_delegate, pausable,
               default_operators, node, wait, yes):
    """Create a token."""
    def params(signer):
        p = {"name": name, "symbol": symbol, "decimals": decimals, "total_supply": supply,
             "mint_authority": _authority(mint_authority, signer),
             "freeze_authority": _authority(freeze_authority, signer)}
        if max_supply:
            p["max_supply"] = max_supply
        if uri is not None or fields:
            p["uri"] = uri or ""
            p["metadata"] = dict(f.split("=", 1) for f in fields)
        if transfer_fee_bps is not None:
            p["transfer_fee_bps"] = transfer_fee_bps
            if max_transfer_fee:
                p["max_transfer_fee"] = max_transfer_fee
        if non_transferable:
            p["non_transferable"] = True
        if default_frozen:
            p["default_frozen"] = True
        if permanent_delegate:
            p["permanent_delegate"] = _authority(permanent_delegate, signer)
        if pausable:
            p["pausable"] = True
        if default_operators:
            p["default_operators"] = [_authority(o, signer) for o in default_operators]
        return p
    _send(node, wallet_file, "TOKEN_DEPLOY", params,
          f"Deploy {symbol} ({name}), supply {supply}", wait, yes, group="token")


@token.command("mint")
@wallet_arg
@click.argument("token_address")
@click.argument("amount")
@click.option("--to", "to", default=None, help="Recipient (default: you)")
@node_option
@wait_option
@yes_option
def mint_cmd(wallet_file, token_address, amount, to, node, wait, yes):
    """Mint new supply (the mint authority only)."""
    params = {"token_address": token_address, "amount": amount}
    if to:
        params["to"] = to
    _send(node, wallet_file, "TOKEN_MINT", params, f"Mint {amount} of {token_address}",
          wait, yes, group="token")


@token.command("burn")
@wallet_arg
@click.argument("token_address")
@click.argument("amount")
@node_option
@wait_option
@yes_option
def burn_cmd(wallet_file, token_address, amount, node, wait, yes):
    """Burn some of your balance."""
    _send(node, wallet_file, "TOKEN_BURN", {"token_address": token_address, "amount": amount},
          f"Burn {amount} of {token_address}", wait, yes, group="token")


@token.command("transfer")
@wallet_arg
@click.argument("token_address")
@click.argument("to")
@click.argument("amount")
@click.option("--memo", default=None, help="A note for the recipient (at most 256 bytes)")
@node_option
@wait_option
@yes_option
def transfer_cmd(wallet_file, token_address, to, amount, memo, node, wait, yes):
    """Send tokens."""
    params = {"token_address": token_address, "to": to, "amount": amount}
    if memo:
        params["memo"] = memo
    _send(node, wallet_file, "TOKEN_TRANSFER", params,
          f"Send {amount} of {token_address} to {to}", wait, yes, group="token")


@token.command("approve")
@wallet_arg
@click.argument("token_address")
@click.argument("spender")
@click.argument("amount")
@node_option
@wait_option
@yes_option
def approve_cmd(wallet_file, token_address, spender, amount, node, wait, yes):
    """Let SPENDER move up to AMOUNT of your tokens (0 revokes)."""
    _send(node, wallet_file, "TOKEN_APPROVE",
          {"token_address": token_address, "spender": spender, "amount": amount},
          f"Approve {spender} for {amount} of {token_address}", wait, yes, group="token")


@token.command("transfer-from")
@wallet_arg
@click.argument("token_address")
@click.argument("owner")
@click.argument("to")
@click.argument("amount")
@node_option
@wait_option
@yes_option
def transfer_from_cmd(wallet_file, token_address, owner, to, amount, node, wait, yes):
    """Move OWNER's tokens within the allowance OWNER gave you."""
    _send(node, wallet_file, "TOKEN_TRANSFER_FROM",
          {"token_address": token_address, "from": owner, "to": to, "amount": amount},
          f"Move {amount} of {token_address} from {owner} to {to}", wait, yes, group="token")


@token.command("set-authority")
@wallet_arg
@click.argument("token_address")
@click.argument("authority", type=click.Choice(["mint", "freeze", "metadata", "fee", "withdraw",
                                                "pause", "permanent_delegate"]))
@click.argument("new_authority")
@node_option
@wait_option
@yes_option
def set_authority_cmd(wallet_file, token_address, authority, new_authority, node, wait, yes):
    """Hand an authority to NEW_AUTHORITY, or 'none' to renounce it for good."""
    renounce = new_authority.lower() in ("none", "")
    if renounce:
        click.echo(click.style(f"Renouncing the {authority} authority cannot be undone.",
                               fg="yellow"))
    _send(node, wallet_file, "TOKEN_SET_AUTHORITY",
          lambda signer: {"token_address": token_address, "authority": authority,
                          "new_authority": _authority(new_authority, signer)},
          f"{'Renounce' if renounce else 'Hand over'} the {authority} authority of "
          f"{token_address}", wait, yes, group="token")


@token.command("metadata")
@wallet_arg
@click.argument("token_address")
@click.option("--name", default=None)
@click.option("--symbol", default=None)
@click.option("--uri", default=None)
@click.option("--field", "fields", multiple=True, help="key=value, or key= to remove")
@node_option
@wait_option
@yes_option
def metadata_cmd(wallet_file, token_address, name, symbol, uri, fields, node, wait, yes):
    """Update the name, symbol, uri or fields (the metadata authority only)."""
    params = {"token_address": token_address}
    for key, value in (("name", name), ("symbol", symbol), ("uri", uri)):
        if value is not None:
            params[key] = value
    if fields:
        params["fields"] = {k: (v or None) for k, v in (f.split("=", 1) for f in fields)}
    _send(node, wallet_file, "TOKEN_UPDATE_METADATA", params,
          f"Update the metadata of {token_address}", wait, yes, group="token")


@token.command("set-fee")
@wallet_arg
@click.argument("token_address")
@click.argument("bps", type=int)
@click.option("--max-fee", default=None, help="Cap on one transfer's fee")
@node_option
@wait_option
@yes_option
def set_fee_cmd(wallet_file, token_address, bps, max_fee, node, wait, yes):
    """Set a new transfer-fee rate (the fee authority only); it applies after a delay."""
    params = {"token_address": token_address, "transfer_fee_bps": bps}
    if max_fee:
        params["max_transfer_fee"] = max_fee
    _send(node, wallet_file, "TOKEN_SET_TRANSFER_FEE", params,
          f"Set {token_address}'s transfer fee to {bps} bps", wait, yes, group="token")


@token.command("withdraw-fees")
@wallet_arg
@click.argument("token_address")
@click.option("--to", "to", default=None, help="Recipient (default: you)")
@node_option
@wait_option
@yes_option
def withdraw_fees_cmd(wallet_file, token_address, to, node, wait, yes):
    """Collect the withheld transfer fees (the withdraw authority only)."""
    params = {"token_address": token_address}
    if to:
        params["to"] = to
    _send(node, wallet_file, "TOKEN_WITHDRAW_FEES", params,
          f"Withdraw {token_address}'s withheld fees", wait, yes, group="token")


def _token_only(op, verb):
    @wallet_arg
    @click.argument("token_address")
    @node_option
    @wait_option
    @yes_option
    def cmd(wallet_file, token_address, node, wait, yes):
        _send(node, wallet_file, op, {"token_address": token_address},
              f"{verb} {token_address}", wait, yes, group="token")
    return cmd


token.command("pause", help="Stop every transfer, mint and burn (the pause authority only).")(
    _token_only("TOKEN_PAUSE", "Pause"))
token.command("resume", help="Let a paused token move again.")(
    _token_only("TOKEN_RESUME", "Resume"))


def _operator(op, verb):
    @wallet_arg
    @click.argument("token_address")
    @click.argument("operator")
    @node_option
    @wait_option
    @yes_option
    def cmd(wallet_file, token_address, operator, node, wait, yes):
        _send(node, wallet_file, op, {"token_address": token_address, "operator": operator},
              f"{verb} {operator} for your {token_address}", wait, yes, group="token")
    return cmd


token.command("operator", help="Let OPERATOR move your balance without an allowance (ERC-777).")(
    _operator("TOKEN_AUTHORIZE_OPERATOR", "Authorize"))
token.command("revoke-operator", help="Stop OPERATOR moving your balance.")(
    _operator("TOKEN_REVOKE_OPERATOR", "Revoke"))


def _freeze(op, verb):
    @wallet_arg
    @click.argument("token_address")
    @click.argument("account")
    @node_option
    @wait_option
    @yes_option
    def cmd(wallet_file, token_address, account, node, wait, yes):
        _send(node, wallet_file, op, {"token_address": token_address, "account": account},
              f"{verb} {account}'s {token_address}", wait, yes, group="token")
    return cmd


token.command("freeze", help="Stop ACCOUNT moving its balance (the freeze authority only).")(
    _freeze("TOKEN_FREEZE", "Freeze"))
token.command("thaw", help="Let a frozen ACCOUNT move its balance again.")(
    _freeze("TOKEN_THAW", "Thaw"))
