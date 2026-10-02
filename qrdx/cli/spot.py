"""
``qrdx-wallet spot …`` — swap, provide liquidity and trade the spot order books
(docs/PERPS_API.md §7).

Reads need only a node. Writes are exchange transactions signed with the wallet's post-quantum
key and gossiped to every node (see ``qrdx-wallet perp``); ``--wait`` prints the receipt.

    qrdx-wallet spot pools
    qrdx-wallet spot quote 0xIN… 0xOUT… 100
    qrdx-wallet spot swap wallet.json 0xIN… 0xOUT… 100 --slippage 0.5 --wait
    qrdx-wallet spot add-liquidity wallet.json <pool_id> -6000 6000 --amount0 10 --amount1 10
    qrdx-wallet spot positions 0xPQ…
    qrdx-wallet spot remove-liquidity wallet.json <pool_id> <position_id>
    qrdx-wallet spot order wallet.json 0xBASE… 0xQUOTE… buy 1.5 100
"""
from __future__ import annotations

import json
from decimal import ROUND_FLOOR, Decimal

import click

from .perp import _print_receipt, _send, json_option, node_option, rpc

wait_option = click.option("--wait", is_flag=True, help="Wait for the receipt")
yes_option = click.option("--yes", "-y", is_flag=True, help="Do not ask for confirmation")
wallet_arg = click.argument("wallet_file", type=click.Path(exists=True))


@click.group("spot")
def spot():
    """Spot: AMM swaps, liquidity positions, order books."""


# ── reads ──────────────────────────────────────────────────────────────────

@spot.command("pools")
@click.option("--pair", nargs=2, default=None, help="Only this pair's pools: TOKEN_A TOKEN_B")
@node_option
@json_option
def pools_cmd(pair, node, as_json):
    """AMM pools: price, liquidity, fee tier."""
    rows = rpc(node, "exchange_getPools", list(pair) if pair else [])
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("No pools.")
    for p in rows:
        click.echo(click.style(p["pool_id"], bold=True) +
                   f"  {p['token0']} / {p['token1']}  price {p['price']}  "
                   f"liquidity {p['liquidity']}  fee {Decimal(p['fee_rate']) * 100}%  "
                   f"{p['positions']} position(s)")


@spot.command("quote")
@click.argument("token_in")
@click.argument("token_out")
@click.argument("amount_in")
@click.option("--venue", type=click.Choice(["auto", "amm", "clob"]), default="auto",
              show_default=True)
@click.option("--sender", default="", help="Your address (the quote stops at your own orders)")
@node_option
@json_option
def quote_cmd(token_in, token_out, amount_in, venue, sender, node, as_json):
    """What a swap would get right now."""
    q = rpc(node, "exchange_quoteSwap", [token_in, token_out, amount_in, sender, None, venue])
    if as_json:
        click.echo(json.dumps(q, indent=2))
        return
    click.echo(f"{q['amount_in']} in → {q['amount_out']} out  via {q['source']}"
               f"{' pool ' + q['pool_id'] if q.get('pool_id') else ''}  fee {q['fee']}")
    if q.get("price_impact") is not None:
        click.echo(f"  price {q['price_before']} → {q['price_after']}  "
                   f"(impact {Decimal(q['price_impact']) * 100:.4f}%)")


@spot.command("positions")
@click.argument("address")
@node_option
@json_option
def positions_cmd(address, node, as_json):
    """An address's liquidity positions and what removing each would pay."""
    rows = rpc(node, "exchange_getPositions", [address])
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("No positions.")
    for p in rows:
        state = click.style("in range", fg="green") if p["in_range"] else "out of range"
        click.echo(click.style(p["position_id"], bold=True) +
                   f"  pool {p['pool_id']}  ticks [{p['tick_lower']}, {p['tick_upper']})  {state}")
        click.echo(f"  worth {p['amount0']} + {p['amount1']}, fees {p['fees0']} + {p['fees1']}")


@spot.command("book")
@click.argument("token_a")
@click.argument("token_b")
@click.option("--depth", default=10, show_default=True)
@node_option
@json_option
def book_cmd(token_a, token_b, depth, node, as_json):
    """A pair's order book (either token order)."""
    b = rpc(node, "exchange_getOrderBook", [f"{token_a}:{token_b}", depth])
    if as_json:
        click.echo(json.dumps(b, indent=2))
        return
    click.echo(f"{b['base']} / {b['quote']}")
    for price, size in reversed(b["asks"]):
        click.echo(click.style(f"  {price:>18}  {size}", fg="red"))
    click.echo("  " + "-" * 30)
    for price, size in b["bids"]:
        click.echo(click.style(f"  {price:>18}  {size}", fg="green"))


@spot.command("orders")
@click.argument("address")
@node_option
@json_option
def orders_cmd(address, node, as_json):
    """An address's resting spot orders."""
    rows = rpc(node, "exchange_getOpenOrders", [address])
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("No open orders.")
    for o in rows:
        click.echo(f"{o['order_id']}  {o['pair']}  {o['side']} {o['remaining']} @ {o['price']}")


@spot.command("receipt")
@click.argument("tx_hash")
@node_option
def receipt_cmd(tx_hash, node):
    """The result of a submitted transaction."""
    r = rpc(node, "exchange_getTransactionReceipt", [tx_hash])
    click.echo("Pending (not in a block yet), or unknown.") if r is None else _print_receipt(r)


# ── writes ─────────────────────────────────────────────────────────────────

@spot.command("swap")
@wallet_arg
@click.argument("token_in")
@click.argument("token_out")
@click.argument("amount_in")
@click.option("--slippage", default="0.5", show_default=True,
              help="Tolerance, percent below the quote")
@click.option("--min-out", default=None, help="An explicit minimum instead of --slippage")
@click.option("--venue", type=click.Choice(["auto", "amm", "clob"]), default="auto",
              show_default=True)
@node_option
@wait_option
@yes_option
def swap_cmd(wallet_file, token_in, token_out, amount_in, slippage, min_out, venue, node, wait,
             yes):
    """Swap AMOUNT_IN of TOKEN_IN for TOKEN_OUT at the best venue, refusing less than the
    quote minus your slippage tolerance."""
    def params(signer):
        floor = min_out
        if floor is None:
            q = rpc(node, "exchange_quoteSwap",
                    [token_in, token_out, amount_in, signer.address, None, venue])
            keep = Decimal(1) - Decimal(slippage) / 100
            floor = str((Decimal(q["amount_out"]) * keep).quantize(Decimal("1e-18"),
                                                                    rounding=ROUND_FLOOR))
            click.echo(f"Quote: {q['amount_out']} via {q['source']}; minimum {floor}")
        return {"token_in": token_in, "token_out": token_out, "amount_in": amount_in,
                "min_amount_out": floor, "venue": venue}
    _send(node, wallet_file, "SWAP", params, f"Swap {amount_in} of {token_in} for {token_out}",
          wait, yes, group="spot")


@spot.command("add-liquidity", context_settings={"ignore_unknown_options": True})
@wallet_arg
@click.argument("pool_id")
@click.argument("tick_lower", type=int)
@click.argument("tick_upper", type=int)
@click.option("--amount0", default=None, help="Most of token0 to deposit")
@click.option("--amount1", default=None, help="Most of token1 to deposit")
@click.option("--liquidity", default=None, help="Exact liquidity L instead of amounts")
@node_option
@wait_option
@yes_option
def add_liquidity_cmd(wallet_file, pool_id, tick_lower, tick_upper, amount0, amount1, liquidity,
                      node, wait, yes):
    """Provide liquidity in [TICK_LOWER, TICK_UPPER) — the most your amounts buy."""
    if liquidity is None and amount0 is None and amount1 is None:
        raise click.UsageError("give --amount0 and/or --amount1, or --liquidity")
    q = rpc(node, "exchange_quoteLiquidity",
            [pool_id, tick_lower, tick_upper, liquidity, amount0, amount1])
    _send(node, wallet_file, "ADD_LIQUIDITY",
          {"pool_id": pool_id, "tick_lower": tick_lower, "tick_upper": tick_upper,
           "amount": q["liquidity"]},
          f"Add liquidity {q['liquidity']} to {pool_id}: deposits {q['amount0']} "
          f"{q['token0']} + {q['amount1']} {q['token1']}", wait, yes, group="spot")


@spot.command("remove-liquidity")
@wallet_arg
@click.argument("pool_id")
@click.argument("position_id")
@click.option("--amount", default=None, help="Liquidity to remove (default: all; 0 collects fees)")
@node_option
@wait_option
@yes_option
def remove_liquidity_cmd(wallet_file, pool_id, position_id, amount, node, wait, yes):
    """Withdraw a position (principal + fees)."""
    params = {"pool_id": pool_id, "position_id": position_id}
    if amount is not None:
        params["amount"] = amount
    _send(node, wallet_file, "REMOVE_LIQUIDITY", params,
          f"Remove {'all' if amount is None else amount} of position {position_id}", wait, yes,
          group="spot")


@spot.command("order")
@wallet_arg
@click.argument("base")
@click.argument("quote")
@click.argument("side", type=click.Choice(["buy", "sell"]))
@click.argument("price")
@click.argument("amount")
@node_option
@wait_option
@yes_option
def order_cmd(wallet_file, base, quote, side, price, amount, node, wait, yes):
    """A limit order: SIDE AMOUNT of BASE at PRICE (in QUOTE per BASE). The book's base is the
    lower token address; the order is escrowed while it rests."""
    _send(node, wallet_file, "PLACE_ORDER",
          {"pair": f"{base}:{quote}", "side": side, "order_type": "limit", "price": price,
           "amount": amount},
          f"{side.capitalize()} {amount} {base} @ {price} {quote}", wait, yes, group="spot")


@spot.command("cancel")
@wallet_arg
@click.argument("token_a")
@click.argument("token_b")
@click.argument("order_id")
@node_option
@wait_option
@yes_option
def cancel_cmd(wallet_file, token_a, token_b, order_id, node, wait, yes):
    """Cancel a resting order (its escrow is refunded)."""
    _send(node, wallet_file, "CANCEL_ORDER", {"pair": f"{token_a}:{token_b}", "order_id": order_id},
          f"Cancel order {order_id}", wait, yes, group="spot")


@spot.command("create-pool")
@wallet_arg
@click.argument("token0")
@click.argument("token1")
@click.option("--fee", type=click.Choice(["100", "500", "3000", "10000"]), default="3000",
              show_default=True, help="Fee tier in hundredths of a basis point")
@click.option("--price", required=True, help="Initial price: token1 per token0 of the sorted pair")
@click.option("--stake", default="10000", show_default=True, help="QRDX staked by the creator")
@node_option
@wait_option
@yes_option
def create_pool_cmd(wallet_file, token0, token1, fee, price, stake, node, wait, yes):
    """Create an AMM pool (the creator stakes QRDX, refunded on REMOVE_POOL)."""
    _send(node, wallet_file, "CREATE_POOL",
          {"token0": token0, "token1": token1, "fee_tier": int(fee), "pool_type": "STANDARD",
           "initial_price": price, "stake_amount": stake},
          f"Create a {token0}/{token1} pool at {price}, fee tier {fee}", wait, yes, group="spot")
