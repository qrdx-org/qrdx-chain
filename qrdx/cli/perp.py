"""
``qrdx-wallet perp …`` — trade perpetuals from the command line (docs/PERPS_CLEARINGHOUSE.md).

Reads need only a node; writes are exchange transactions signed with the wallet's post-quantum
key (exchange operations are PQ-only), submitted with ``exchange_sendTransaction`` and gossiped
to every node, so any node will do. ``--wait`` polls the receipt until a block includes it.

    qrdx-wallet perp markets
    qrdx-wallet perp book BTC-USD-PERP
    qrdx-wallet perp account 0xPQ…
    qrdx-wallet perp deposit wallet.json 1000 --wait
    qrdx-wallet perp order wallet.json BTC-USD-PERP buy 0.1 65000 --wait
    qrdx-wallet perp cancel wallet.json BTC-USD-PERP 3f9a…
    qrdx-wallet perp withdraw wallet.json all
"""
from __future__ import annotations

import json
import time
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Optional

import click

DEFAULT_NODE = "http://localhost:3007"
node_option = click.option("--node", "-n", default=DEFAULT_NODE, show_default=True,
                           help="Node URL (its JSON-RPC endpoint is <node>/rpc)")
json_option = click.option("--json", "as_json", is_flag=True, help="Print raw JSON")


def rpc(node: str, method: str, params: Any = None, timeout: float = 20.0) -> Any:
    import httpx
    try:
        resp = httpx.post(f"{node.rstrip('/')}/rpc", timeout=timeout,
                          json={"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1})
    except Exception as e:
        raise click.ClickException(f"cannot reach {node}: {e}")
    if resp.status_code != 200:
        raise click.ClickException(f"{method} failed (HTTP {resp.status_code})")
    body = resp.json()
    if body.get("error"):
        err = body["error"]
        raise click.ClickException(f"{method}: {err.get('message', err) if isinstance(err, dict) else err}")
    return body.get("result")


def _signer(wallet_file: str):
    """The wallet's post-quantum key — exchange transactions are signed with Dilithium."""
    from qrdx.wallet_v2 import PQWallet, UnifiedWallet, WalletDecryptionError, load_wallet
    from .wallet import get_password
    password = get_password(prompt="Enter wallet password: ")
    try:
        wallet = load_wallet(Path(wallet_file), password)
    except WalletDecryptionError:
        raise click.ClickException("Invalid password")
    except Exception as e:
        raise click.ClickException(f"Failed to load wallet: {e}")
    if isinstance(wallet, UnifiedWallet):
        wallet = wallet.pq
    if not isinstance(wallet, PQWallet):
        raise click.ClickException(
            "Exchange transactions (perps, spot, tokens) are signed with Dilithium: use a "
            "post-quantum (0xPQ) wallet. Create one with: qrdx-wallet create --type pq")
    return wallet


def build_tx(signer, op_name: str, params: Dict[str, Any], nonce: int):
    from qrdx.exchange import ExchangeOpType, ExchangeTransaction
    tx = ExchangeTransaction(op_type=ExchangeOpType[op_name], sender=signer.address, nonce=nonce,
                             params=params, gas_limit=1_000_000, gas_price=Decimal("1"))
    tx.public_key = signer.public_key
    tx.signature = signer.sign(tx.signing_bytes())
    return tx


def _send(node: str, wallet_file: str, op_name: str, params: Any, summary: str,
          wait: bool, yes: bool, group: str = "perp") -> Optional[Dict[str, Any]]:
    """Sign and submit one exchange transaction. ``params`` may be a function of the signer
    (for parameters that name the wallet itself)."""
    signer = _signer(wallet_file)
    if callable(params):
        params = params(signer)
    click.echo(f"{summary}\n  from {signer.address}")
    if not yes and not click.confirm("Submit?", default=True):
        click.echo("Cancelled.")
        return None
    nonce = int(rpc(node, "exchange_getNonce", [signer.address]))
    tx = build_tx(signer, op_name, params, nonce)
    tx_hash = rpc(node, "exchange_sendTransaction", [tx.to_dict()])
    click.echo(click.style("✓ Submitted", fg="green") + f"  tx {tx_hash}  (nonce {nonce})")
    if not wait:
        click.echo(f"Track it: qrdx-wallet {group} receipt {tx_hash} --node {node}")
        return None
    for _ in range(45):
        receipt = rpc(node, "exchange_getTransactionReceipt", [tx_hash])
        if receipt:
            _print_receipt(receipt)
            return receipt
        time.sleep(2)
    click.echo(click.style("⚠ Not included yet — it may still be pending.", fg="yellow"))
    return None


def _print_receipt(r: Dict[str, Any]) -> None:
    status = (click.style("✓ executed", fg="green") if r.get("success")
              else click.style("✗ failed", fg="red"))
    click.echo(f"{status} in block {r.get('block_height')}: {r.get('op')}")
    if r.get("error"):
        click.echo(f"  error: {r['error']}")
    data = r.get("data") or {}
    if data.get("order_id"):
        click.echo(f"  order {data['order_id']}  "
                   f"{'resting' if data.get('resting') else 'not resting'}")
    for f in data.get("fills", []):
        click.echo(f"  filled {f['amount']} @ {f['price']}")
    for key in ("collateral", "shares", "value", "token_address", "amount", "total_supply",
                "allowance_left", "new_authority", "frozen", "position_id", "amount_out"):
        if key in data:
            click.echo(f"  {key}: {data[key]}")


@click.group("perp")
def perp():
    """Trade perpetual futures (order-book matched, settled in the USD stablecoin)."""


# ── reads ──────────────────────────────────────────────────────────────────

@perp.command("markets")
@node_option
@json_option
def markets_cmd(node: str, as_json: bool):
    """List markets: oracle / mark price, open interest, top of book, funding."""
    rows = rpc(node, "perp_getMarkets")
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("No perp markets yet.")
    for m in rows:
        click.echo(click.style(m["market_id"], bold=True) +
                   f"  oracle {m['oracle_price']}  mark {m['mark_price']}  "
                   f"last {m['last_trade_price']}  OI {m['open_interest']}  "
                   f"bid {m['best_bid']} / ask {m['best_ask']}  funding {m['funding_rate']}")


@perp.command("book")
@click.argument("market_id")
@click.option("--depth", default=10, show_default=True)
@node_option
@json_option
def book_cmd(market_id: str, depth: int, node: str, as_json: bool):
    """Show a market's order book."""
    book = rpc(node, "perp_getOrderBook", [market_id, depth])
    if as_json:
        click.echo(json.dumps(book, indent=2))
        return
    click.echo(click.style(f"{market_id}  mark {book['mark_price']}", bold=True))
    for price, size in reversed(book["asks"]):
        click.echo(click.style(f"  ask {price:>20} {size:>14}", fg="red"))
    for price, size in book["bids"]:
        click.echo(click.style(f"  bid {price:>20} {size:>14}", fg="green"))


@perp.command("account")
@click.argument("address")
@node_option
@json_option
def account_cmd(address: str, node: str, as_json: bool):
    """Show an account: collateral, margin, positions, open orders."""
    a = rpc(node, "perp_getAccount", [address])
    if as_json:
        click.echo(json.dumps(a, indent=2))
        return
    click.echo(click.style(address, bold=True))
    click.echo(f"  collateral {a['collateral']}   withdrawable {a['withdrawable']}   "
               f"equity {a['equity']}")
    click.echo(f"  maintenance {a['maintenance_margin']}   initial {a['initial_margin']}   "
               f"exchange nonce {a['exchange_nonce']}")
    for mid, p in a["positions"].items():
        mode = "isolated" if p["isolated"] else "cross"
        click.echo(f"  {mid}: {p['size']} @ {p['entry_price']}  mark {p['mark_price']}  "
                   f"uPnL {p['unrealized_pnl']}  liq {p['liquidation_price']}  ({mode} "
                   f"{p['leverage']}x)")
    for o in a["orders"]:
        click.echo(f"  order {o['order_id']}: {o['side']} {o['remaining']}/{o['size']} "
                   f"{o['market_id']} @ {o['price']}{'  reduce-only' if o['reduce_only'] else ''}")
    if Decimal(a.get("vault_shares", "0")) > 0:
        click.echo(f"  vault shares {a['vault_shares']} (unlock {a['vault_unlock_time']})")


@perp.command("receipt")
@click.argument("tx_hash")
@node_option
@json_option
def receipt_cmd(tx_hash: str, node: str, as_json: bool):
    """Show an exchange transaction's result (null while pending)."""
    r = rpc(node, "exchange_getTransactionReceipt", [tx_hash])
    if as_json:
        click.echo(json.dumps(r, indent=2))
    elif r is None:
        click.echo("Pending (or unknown to this node).")
    else:
        _print_receipt(r)


# ── writes ─────────────────────────────────────────────────────────────────

wait_option = click.option("--wait", "-w", is_flag=True, help="Wait for the receipt")
yes_option = click.option("--yes", "-y", is_flag=True, help="Do not ask for confirmation")


@perp.command("deposit")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("amount")
@node_option
@wait_option
@yes_option
def deposit_cmd(wallet_file, amount, node, wait, yes):
    """Move collateral (the stablecoin) from the wallet into the perps clearinghouse."""
    _send(node, wallet_file, "PERP_DEPOSIT", {"amount": str(Decimal(amount))},
          f"Deposit {amount} perps collateral", wait, yes)


@perp.command("withdraw")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("amount")
@node_option
@wait_option
@yes_option
def withdraw_cmd(wallet_file, amount, node, wait, yes):
    """Move collateral back to the wallet. AMOUNT may be "all" (everything withdrawable)."""
    if amount.lower() == "all":
        signer = _signer(wallet_file)
        amount = rpc(node, "perp_getAccount", [signer.address])["withdrawable"]
        if Decimal(amount) <= 0:
            raise click.ClickException("Nothing is withdrawable.")
    _send(node, wallet_file, "PERP_WITHDRAW", {"amount": str(Decimal(amount))},
          f"Withdraw {amount} perps collateral", wait, yes)


@perp.command("leverage")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("market_id")
@click.argument("leverage")
@click.option("--isolated", is_flag=True, help="Isolated margin (default: cross)")
@node_option
@wait_option
@yes_option
def leverage_cmd(wallet_file, market_id, leverage, isolated, node, wait, yes):
    """Set leverage and margin mode for a market."""
    mode = "isolated" if isolated else "cross"
    _send(node, wallet_file, "PERP_SET_LEVERAGE",
          {"market_id": market_id, "leverage": str(Decimal(leverage)), "mode": mode},
          f"Set {market_id} to {leverage}x {mode}", wait, yes)


@perp.command("order")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("market_id")
@click.argument("side", type=click.Choice(["buy", "sell"]))
@click.argument("size")
@click.argument("price")
@click.option("--reduce-only", is_flag=True, help="Only reduce an open position")
@click.option("--ioc", is_flag=True, help="Immediate-or-cancel: never rest on the book")
@node_option
@wait_option
@yes_option
def order_cmd(wallet_file, market_id, side, size, price, reduce_only, ioc, node, wait, yes):
    """Place a limit order. A "market" order is --ioc at an aggressive price."""
    params = {"market_id": market_id, "side": side, "size": str(Decimal(size)),
              "price": str(Decimal(price))}
    if reduce_only:
        params["reduce_only"] = True
    if ioc:
        params["tif"] = "ioc"
    flags = "".join((" reduce-only" if reduce_only else "", " IOC" if ioc else ""))
    _send(node, wallet_file, "PERP_ORDER", params,
          f"{side.upper()} {size} {market_id} @ {price}{flags}", wait, yes)


@perp.command("cancel")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("market_id")
@click.argument("order_id")
@node_option
@wait_option
@yes_option
def cancel_cmd(wallet_file, market_id, order_id, node, wait, yes):
    """Cancel a resting order (its id is the first 16 characters of the order's tx hash)."""
    _send(node, wallet_file, "PERP_CANCEL", {"market_id": market_id, "order_id": order_id},
          f"Cancel order {order_id} on {market_id}", wait, yes)


@perp.command("vault-deposit")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("amount")
@node_option
@wait_option
@yes_option
def vault_deposit_cmd(wallet_file, amount, node, wait, yes):
    """Put free collateral into the liquidation backstop vault for shares (locked a while)."""
    _send(node, wallet_file, "VAULT_DEPOSIT", {"amount": str(Decimal(amount))},
          f"Deposit {amount} into the backstop vault", wait, yes)


@perp.command("vault-withdraw")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("shares")
@node_option
@wait_option
@yes_option
def vault_withdraw_cmd(wallet_file, shares, node, wait, yes):
    """Redeem vault shares at the vault's current value."""
    _send(node, wallet_file, "VAULT_WITHDRAW", {"shares": str(Decimal(shares))},
          f"Redeem {shares} vault shares", wait, yes)


@perp.command("create-market")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("base")
@click.option("--max-leverage", default=None, help="Default 20")
@node_option
@wait_option
@yes_option
def create_market_cmd(wallet_file, base, max_leverage, node, wait, yes):
    """Open a market for BASE, such as BTC. It trades once validators price it."""
    params = {"base_token": base}
    if max_leverage:
        params["max_leverage"] = str(Decimal(max_leverage))
    _send(node, wallet_file, "CREATE_MARKET", params, f"Create the {base} perp market",
          wait, yes)
