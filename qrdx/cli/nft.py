"""
``qrdx-wallet nft …`` — native NFT collections from the command line (docs/NATIVE_TOKENS.md §8).

    qrdx-wallet nft collections
    qrdx-wallet nft info 0x…                       # a collection
    qrdx-wallet nft show 0x… 7                     # one NFT
    qrdx-wallet nft owned 0xPQ…                    # an owner's NFTs
    qrdx-wallet nft create wallet.json "Quantum Art" QART --uri ipfs://… --royalty-bps 500
    qrdx-wallet nft mint wallet.json 0x… --to 0xPQ… --uri ipfs://…/7.json
    qrdx-wallet nft transfer wallet.json 0x… 7 0xPQ…
    qrdx-wallet nft approve-all wallet.json 0x… <operator>
"""
from __future__ import annotations

import json

import click

from .perp import _send, json_option, node_option, rpc
from .token import _authority, wait_option, wallet_arg, yes_option


def _show_collection(c) -> None:
    cap = c.get("max_supply") or "unlimited"
    click.echo(click.style(c["symbol"], bold=True) + f"  {c['name']}  {c['collection']}")
    click.echo(f"  {c['supply']} NFTs (cap {cap}), royalties {c['royalty_bps']} bps"
               + (f" to {c['royalty_recipient']}" if c.get("royalty_recipient") else ""))
    click.echo(f"  uri: {c['uri'] or '(none)'}")
    click.echo(f"  update authority: {c.get('update_authority') or 'none — immutable'}")
    click.echo(f"  mint authority:   {c.get('mint_authority') or 'none — complete'}")
    if c.get("non_transferable"):
        click.echo("  soulbound (non-transferable)")


def _show_nft(n) -> None:
    click.echo(click.style(f"{n.get('symbol', '')} #{n['token_id']}", bold=True)
               + (f"  {n['name']}" if n.get("name") else ""))
    click.echo(f"  owner: {n['owner']}")
    click.echo(f"  uri:   {n['uri'] or '(none)'}")
    if n.get("approved"):
        click.echo(f"  approved: {n['approved']}")


@click.group("nft")
def nft():
    """Native NFTs: collections, mint, transfer, approve, burn."""


@nft.command("collections")
@node_option
@json_option
def collections_cmd(node, as_json):
    """Every NFT collection."""
    rows = rpc(node, "exchange_getNftCollections")
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("No collections yet.")
    for c in rows:
        _show_collection(c)


@nft.command("info")
@click.argument("collection")
@node_option
@json_option
def info_cmd(collection, node, as_json):
    """One collection."""
    c = rpc(node, "exchange_getNftCollection", [collection])
    click.echo(json.dumps(c, indent=2)) if as_json else _show_collection(c)


@nft.command("show")
@click.argument("collection")
@click.argument("token_id")
@node_option
@json_option
def show_cmd(collection, token_id, node, as_json):
    """One NFT."""
    n = rpc(node, "exchange_getNft", [collection, token_id])
    click.echo(json.dumps(n, indent=2)) if as_json else _show_nft(n)


@nft.command("owned")
@click.argument("owner")
@click.option("--collection", default=None)
@node_option
@json_option
def owned_cmd(owner, collection, node, as_json):
    """An owner's NFTs."""
    rows = rpc(node, "exchange_getNftsOf", [owner, collection])
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("No NFTs.")
    for n in rows:
        _show_nft(n)


@nft.command("create")
@wallet_arg
@click.argument("name")
@click.argument("symbol")
@click.option("--uri", default="", help="Collection metadata URI")
@click.option("--max-supply", default=None, type=int, help="Cap on the collection's size")
@click.option("--royalty-bps", default=0, type=int, show_default=True)
@click.option("--royalty-recipient", default=None, help="Default: you")
@click.option("--soulbound", is_flag=True, help="Its NFTs can never be transferred")
@node_option
@wait_option
@yes_option
def create_cmd(wallet_file, name, symbol, uri, max_supply, royalty_bps, royalty_recipient,
               soulbound, node, wait, yes):
    """Create a collection (you hold its update and mint authorities)."""
    def params(signer):
        p = {"name": name, "symbol": symbol, "uri": uri, "royalty_bps": royalty_bps}
        if max_supply:
            p["max_supply"] = max_supply
        if royalty_recipient:
            p["royalty_recipient"] = _authority(royalty_recipient, signer)
        if soulbound:
            p["non_transferable"] = True
        return p
    _send(node, wallet_file, "NFT_CREATE_COLLECTION", params,
          f"Create the {symbol} collection ({name})", wait, yes, group="token")


@nft.command("mint")
@wallet_arg
@click.argument("collection")
@click.option("--to", "to", default=None, help="Owner (default: you)")
@click.option("--uri", default="", help="The NFT's metadata URI")
@click.option("--name", default="", help="The NFT's name")
@click.option("--token-id", default=None, help="Default: the next id")
@node_option
@wait_option
@yes_option
def mint_cmd(wallet_file, collection, to, uri, name, token_id, node, wait, yes):
    """Mint an NFT into a collection (its mint authority only)."""
    p = {"collection": collection, "uri": uri, "name": name}
    if to:
        p["to"] = to
    if token_id is not None:
        p["token_id"] = token_id
    _send(node, wallet_file, "NFT_MINT", p, f"Mint into {collection}", wait, yes, group="token")


@nft.command("transfer")
@wallet_arg
@click.argument("collection")
@click.argument("token_id")
@click.argument("to")
@click.option("--from", "frm", default=None, help="The owner, when you are its approved account "
                                                   "or operator")
@click.option("--memo", default=None)
@node_option
@wait_option
@yes_option
def transfer_cmd(wallet_file, collection, token_id, to, frm, memo, node, wait, yes):
    """Send an NFT."""
    p = {"collection": collection, "token_id": token_id, "to": to}
    if frm:
        p["from"] = frm
    if memo:
        p["memo"] = memo
    _send(node, wallet_file, "NFT_TRANSFER", p, f"Send {collection} #{token_id} to {to}",
          wait, yes, group="token")


@nft.command("burn")
@wallet_arg
@click.argument("collection")
@click.argument("token_id")
@node_option
@wait_option
@yes_option
def burn_cmd(wallet_file, collection, token_id, node, wait, yes):
    """Burn an NFT."""
    _send(node, wallet_file, "NFT_BURN", {"collection": collection, "token_id": token_id},
          f"Burn {collection} #{token_id}", wait, yes, group="token")


@nft.command("approve")
@wallet_arg
@click.argument("collection")
@click.argument("token_id")
@click.argument("spender")
@node_option
@wait_option
@yes_option
def approve_cmd(wallet_file, collection, token_id, spender, node, wait, yes):
    """Let SPENDER transfer one NFT ('none' clears it)."""
    _send(node, wallet_file, "NFT_APPROVE",
          {"collection": collection, "token_id": token_id,
           "spender": "" if spender.lower() == "none" else spender},
          f"Approve {spender} for {collection} #{token_id}", wait, yes, group="token")


@nft.command("approve-all")
@wallet_arg
@click.argument("collection")
@click.argument("operator")
@click.option("--revoke", is_flag=True)
@node_option
@wait_option
@yes_option
def approve_all_cmd(wallet_file, collection, operator, revoke, node, wait, yes):
    """Let OPERATOR transfer all your NFTs in the collection (or --revoke)."""
    _send(node, wallet_file, "NFT_SET_APPROVAL_FOR_ALL",
          {"collection": collection, "operator": operator, "approved": not revoke},
          f"{'Revoke' if revoke else 'Approve'} {operator} for all your {collection}",
          wait, yes, group="token")


@nft.command("update")
@wallet_arg
@click.argument("collection")
@click.option("--token-id", default=None, help="Update one NFT instead of the collection")
@click.option("--name", default=None)
@click.option("--symbol", default=None)
@click.option("--uri", default=None)
@click.option("--royalty-bps", default=None, type=int)
@node_option
@wait_option
@yes_option
def update_cmd(wallet_file, collection, token_id, name, symbol, uri, royalty_bps, node, wait, yes):
    """Edit the collection's or an NFT's metadata (the update authority only)."""
    p = {"collection": collection}
    for key, value in (("token_id", token_id), ("name", name), ("symbol", symbol), ("uri", uri),
                       ("royalty_bps", royalty_bps)):
        if value is not None:
            p[key] = value
    _send(node, wallet_file, "NFT_UPDATE", p, f"Update {collection}", wait, yes, group="token")


@nft.command("set-authority")
@wallet_arg
@click.argument("collection")
@click.argument("authority", type=click.Choice(["update", "mint"]))
@click.argument("new_authority")
@node_option
@wait_option
@yes_option
def set_authority_cmd(wallet_file, collection, authority, new_authority, node, wait, yes):
    """Hand the update or mint authority to NEW_AUTHORITY, or 'none' to renounce it for good."""
    _send(node, wallet_file, "NFT_SET_AUTHORITY",
          lambda signer: {"collection": collection, "authority": authority,
                          "new_authority": _authority(new_authority, signer)},
          f"Set the {authority} authority of {collection}", wait, yes, group="token")
