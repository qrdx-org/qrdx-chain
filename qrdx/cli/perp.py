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
node_option = click.option(
    "--node",
    "-n",
    default=DEFAULT_NODE,
    show_default=True,
    help="Node URL (its JSON-RPC endpoint is <node>/rpc)",
)
json_option = click.option("--json", "as_json", is_flag=True, help="Print raw JSON")


def rpc(node: str, method: str, params: Any = None, timeout: float = 20.0) -> Any:
    import httpx

    try:
        resp = httpx.post(
            f"{node.rstrip('/')}/rpc",
            timeout=timeout,
            json={"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1},
        )
    except Exception as e:
        raise click.ClickException(f"cannot reach {node}: {e}") from e
    if resp.status_code != 200:
        raise click.ClickException(f"{method} failed (HTTP {resp.status_code})")
    body = resp.json()
    if body.get("error"):
        err = body["error"]
        raise click.ClickException(
            f"{method}: {err.get('message', err) if isinstance(err, dict) else err}"
        )
    return body.get("result")


def _signer(wallet_file: str):
    """The wallet's post-quantum key — exchange transactions are signed with Dilithium."""
    from qrdx.wallet_v2 import PQWallet, UnifiedWallet, WalletDecryptionError, load_wallet

    from .wallet import get_password

    password = get_password(prompt="Enter wallet password: ")
    try:
        wallet = load_wallet(Path(wallet_file), password)
    except WalletDecryptionError as exc:
        raise click.ClickException("Invalid password") from exc
    except Exception as e:
        raise click.ClickException(f"Failed to load wallet: {e}") from e
    if isinstance(wallet, UnifiedWallet):
        wallet = wallet.pq
    if not isinstance(wallet, PQWallet):
        raise click.ClickException(
            "Exchange transactions (perps, spot, tokens) are signed with Dilithium: use a "
            "post-quantum (0xPQ) wallet. Create one with: qrdx-wallet create --type pq"
        )
    return wallet


def build_tx(
    signer,
    op_name: str,
    params: Dict[str, Any],
    nonce: int,
    gas_price: Optional[int] = None,
    chain_id: Optional[int] = None,
    gas_limit: int = 1_000_000,
):
    from qrdx.exchange import ExchangeOpType, ExchangeTransaction

    price: Dict[str, Any] = {} if gas_price is None else {"gas_price": int(gas_price)}  # wei/gas
    chain: Dict[str, Any] = {} if chain_id is None else {"chain_id": int(chain_id)}
    tx = ExchangeTransaction(
        op_type=ExchangeOpType[op_name],
        sender=signer.address,
        nonce=nonce,
        params=params,
        gas_limit=int(gas_limit),
        **price,
        **chain,
    )
    tx.public_key = signer.public_key
    tx.signature = signer.sign(tx.signing_bytes())
    return tx


def _chain_id(node: str) -> int:
    """The chain id of the network ``node`` follows. Every exchange transaction is signed for
    one network; signing with this process's own default would produce a transaction that
    network refuses (or, worse, one valid on a different network)."""
    status = rpc(node, "p2p_getStatus") or {}
    try:
        return int(status["network"]["chain_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise click.ClickException(
            f"{node} did not report its network's chain id "
            f"(p2p_getStatus); refusing to guess which chain to sign for"
        ) from exc


def _gas_price(node: str, op_name: str = "", address: str = "") -> Optional[int]:
    """The exchange gas price to offer (wei per gas): 0 for a trading operation the account may
    send free now (the free lane, docs/TOKENOMICS.md); otherwise the node's; None — the built-in
    floor — if it cannot say (an older node)."""
    from qrdx.exchange.transactions import AGENT_SCOPE, ExchangeOpType

    if address and ExchangeOpType[op_name] in AGENT_SCOPE:
        try:
            if (rpc(node, "exchange_getFreeActions", [address]) or {}).get("free_now"):
                return 0
        except Exception:
            pass
    try:
        return int(rpc(node, "exchange_gasPrice"))
    except Exception:
        return None


def _send(
    node: str,
    wallet_file: str,
    op_name: str,
    params: Any,
    summary: str,
    wait: bool,
    yes: bool,
    group: str = "perp",
    gas_limit: int = 1_000_000,
) -> Optional[Dict[str, Any]]:
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
    tx = build_tx(
        signer,
        op_name,
        params,
        nonce,
        gas_price=_gas_price(node, op_name, signer.address),
        chain_id=_chain_id(node),
        gas_limit=gas_limit,
    )
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
    status = (
        click.style("✓ executed", fg="green")
        if r.get("success")
        else click.style("✗ failed", fg="red")
    )
    click.echo(f"{status} in block {r.get('block_height')}: {r.get('op')}")
    if r.get("error"):
        click.echo(f"  error: {r['error']}")
    data = r.get("data") or {}
    if data.get("order_id"):
        click.echo(
            f"  order {data['order_id']}  " f"{'resting' if data.get('resting') else 'not resting'}"
        )
    for f in data.get("fills", []):
        click.echo(f"  filled {f['amount']} @ {f['price']}")
    for key in (
        "collateral",
        "shares",
        "value",
        "token_address",
        "amount",
        "total_supply",
        "allowance_left",
        "new_authority",
        "frozen",
        "position_id",
        "amount_out",
    ):
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
        click.echo(
            click.style(m["market_id"], bold=True)
            + f"  oracle {m['oracle_price']}  mark {m['mark_price']}  "
            f"last {m['last_trade_price']}  OI {m['open_interest']}  "
            f"bid {m['best_bid']} / ask {m['best_ask']}  funding {m['funding_rate']}"
        )


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
    click.echo(
        f"  collateral {a['collateral']}   withdrawable {a['withdrawable']}   "
        f"equity {a['equity']}"
    )
    click.echo(
        f"  maintenance {a['maintenance_margin']}   initial {a['initial_margin']}   "
        f"exchange nonce {a['exchange_nonce']}"
    )
    for mid, p in a["positions"].items():
        mode = "isolated" if p["isolated"] else "cross"
        click.echo(
            f"  {mid}: {p['size']} @ {p['entry_price']}  mark {p['mark_price']}  "
            f"uPnL {p['unrealized_pnl']}  liq {p['liquidation_price']}  ({mode} "
            f"{p['leverage']}x)"
        )
    for o in a["orders"]:
        click.echo(
            f"  order {o['order_id']}: {o['side']} {o['remaining']}/{o['size']} "
            f"{o['market_id']} @ {o['price']}{'  reduce-only' if o['reduce_only'] else ''}"
        )
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
    _send(
        node,
        wallet_file,
        "PERP_DEPOSIT",
        {"amount": str(Decimal(amount))},
        f"Deposit {amount} perps collateral",
        wait,
        yes,
    )


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
    _send(
        node,
        wallet_file,
        "PERP_WITHDRAW",
        {"amount": str(Decimal(amount))},
        f"Withdraw {amount} perps collateral",
        wait,
        yes,
    )


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
    _send(
        node,
        wallet_file,
        "PERP_SET_LEVERAGE",
        {"market_id": market_id, "leverage": str(Decimal(leverage)), "mode": mode},
        f"Set {market_id} to {leverage}x {mode}",
        wait,
        yes,
    )


@perp.command("order")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("market_id")
@click.argument("side", type=click.Choice(["buy", "sell"]))
@click.argument("size")
@click.argument("price")
@click.option("--reduce-only", is_flag=True, help="Only reduce an open position")
@click.option("--ioc", is_flag=True, help="Immediate-or-cancel: never rest on the book")
@click.option(
    "--tif",
    type=click.Choice(["gtc", "ioc", "fok", "alo"]),
    default=None,
    help="Time in force: gtc, ioc, fok (fill whole or not at all), alo (post-only)",
)
@click.option("--hidden", is_flag=True, help="Rest without showing in the book's depth")
@click.option("--display-size", default=None, help="An iceberg: show this much at a time")
@click.option(
    "--leverage", default=None, help="This trade's leverage (the market's setting becomes it)"
)
@click.option(
    "--margin-mode",
    type=click.Choice(["cross", "isolated"]),
    default=None,
    help="This trade's margin mode (with no position or order in the market)",
)
@node_option
@wait_option
@yes_option
def order_cmd(
    wallet_file,
    market_id,
    side,
    size,
    price,
    reduce_only,
    ioc,
    tif,
    hidden,
    display_size,
    leverage,
    margin_mode,
    node,
    wait,
    yes,
):
    """Place a limit order. A "market" order is --ioc at an aggressive price."""
    params: Dict[str, Any] = {
        "market_id": market_id,
        "side": side,
        "size": str(Decimal(size)),
        "price": str(Decimal(price)),
    }
    if reduce_only:
        params["reduce_only"] = True
    tif = "ioc" if ioc else tif
    if tif:
        params["tif"] = tif
    if hidden:
        params["hidden"] = True
    if display_size:
        params["display_size"] = str(Decimal(display_size))
    if leverage:
        params["leverage"] = str(Decimal(leverage))
    if margin_mode:
        params["margin_mode"] = margin_mode
    flags = "".join(
        (
            " reduce-only" if reduce_only else "",
            f" {tif.upper()}" if tif else "",
            " hidden" if hidden else "",
            f" iceberg {display_size}" if display_size else "",
            f" {Decimal(leverage)}x" if leverage else "",
            f" {margin_mode}" if margin_mode else "",
        )
    )
    _send(
        node,
        wallet_file,
        "PERP_ORDER",
        params,
        f"{side.upper()} {size} {market_id} @ {price}{flags}",
        wait,
        yes,
    )


@perp.command("cancel")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("market_id")
@click.argument("order_id")
@node_option
@wait_option
@yes_option
def cancel_cmd(wallet_file, market_id, order_id, node, wait, yes):
    """Cancel a resting order (its id is the first 16 characters of the order's tx hash)."""
    _send(
        node,
        wallet_file,
        "PERP_CANCEL",
        {"market_id": market_id, "order_id": order_id},
        f"Cancel order {order_id} on {market_id}",
        wait,
        yes,
    )


@perp.command("trigger")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("market_id")
@click.argument("side", type=click.Choice(["buy", "sell"]))
@click.argument("kind", type=click.Choice(["sl", "tp"]))
@click.argument("trigger_price")
@click.option("--size", default=None, help="Size (omit with --position)")
@click.option("--limit", "limit_price", default=None, help="Limit price (default: market)")
@click.option("--position", is_flag=True, help="The position's TP/SL: closes it whole")
@click.option("--reduce-only", is_flag=True, help="Only reduce an open position")
@click.option("--max-makers", default=20, show_default=True, help="Matching paid for up front")
@node_option
@wait_option
@yes_option
def trigger_cmd(
    wallet_file,
    market_id,
    side,
    kind,
    trigger_price,
    size,
    limit_price,
    position,
    reduce_only,
    max_makers,
    node,
    wait,
    yes,
):
    """A stop-loss (sl) or take-profit (tp) that fires when the mark reaches TRIGGER_PRICE."""
    params: Dict[str, Any] = {
        "market_id": market_id,
        "side": side,
        "kind": kind,
        "trigger_price": str(Decimal(trigger_price)),
        "max_makers": int(max_makers),
    }
    if position:
        params["position"] = True
    elif size:
        params["size"] = str(Decimal(size))
    else:
        raise click.UsageError("give --size, or --position for the position's TP/SL")
    if limit_price:
        params["limit_price"] = str(Decimal(limit_price))
    if reduce_only:
        params["reduce_only"] = True
    _send(
        node,
        wallet_file,
        "PERP_TRIGGER",
        params,
        f"{kind.upper()} {side.upper()} {'position' if position else size} {market_id} "
        f"at mark {trigger_price}" + (f", limit {limit_price}" if limit_price else ", market"),
        wait,
        yes,
        gas_limit=40_000 + int(max_makers) * 10_000,
    )


@perp.command("modify")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("market_id")
@click.argument("order_id")
@click.option("--size", default=None, help="What is left of it")
@click.option("--price", default=None)
@click.option("--trigger-price", default=None, help="A trigger order's")
@click.option("--limit", "limit_price", default=None, help="A trigger order's limit")
@node_option
@wait_option
@yes_option
def modify_cmd(
    wallet_file, market_id, order_id, size, price, trigger_price, limit_price, node, wait, yes
):
    """Change an open order (or trigger) in one step."""
    params: Dict[str, Any] = {"market_id": market_id, "order_id": order_id}
    for key, value in (
        ("size", size),
        ("price", price),
        ("trigger_price", trigger_price),
        ("limit_price", limit_price),
    ):
        if value is not None:
            params[key] = str(Decimal(value))
    _send(node, wallet_file, "PERP_MODIFY", params, f"Modify {order_id}", wait, yes)


@perp.command("cancel-all")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.option("--market", default=None, help="Only this market (a perp id or a spot pair)")
@click.option("--scope", type=click.Choice(["all", "spot", "perps"]), default="all")
@node_option
@wait_option
@yes_option
def cancel_all_cmd(wallet_file, market, scope, node, wait, yes):
    """Cancel every open order, trigger and TWAP."""
    params: Dict[str, Any] = {"scope": scope}
    if market:
        params["market"] = market
    _send(
        node,
        wallet_file,
        "CANCEL_ALL",
        params,
        f"Cancel all ({scope}{', ' + market if market else ''})",
        wait,
        yes,
        gas_limit=2_000_000,
    )


@perp.command("twap")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("market_id")
@click.argument("side", type=click.Choice(["buy", "sell"]))
@click.argument("size")
@click.argument("duration", type=int)
@click.option("--slices", type=int, default=None, help="Default: one every 30 s (at most 60)")
@click.option("--max-slippage", default="0.03", show_default=True)
@click.option("--max-makers", default=5, show_default=True, help="Per slice, paid up front")
@click.option("--reduce-only", is_flag=True)
@node_option
@wait_option
@yes_option
def twap_cmd(
    wallet_file,
    market_id,
    side,
    size,
    duration,
    slices,
    max_slippage,
    max_makers,
    reduce_only,
    node,
    wait,
    yes,
):
    """Work SIZE into the market over DURATION seconds, in slices — unattended."""
    count = slices or min(60, duration // 30)
    params: Dict[str, Any] = {
        "market_id": market_id,
        "side": side,
        "size": str(Decimal(size)),
        "duration": int(duration),
        "slices": int(count),
        "max_slippage": str(Decimal(max_slippage)),
        "max_makers": int(max_makers),
    }
    if reduce_only:
        params["reduce_only"] = True
    _send(
        node,
        wallet_file,
        "TWAP_ORDER",
        params,
        f"TWAP {side.upper()} {size} {market_id} over {duration} s in {count} slices",
        wait,
        yes,
        gas_limit=40_000 + count * (10_000 + int(max_makers) * 10_000),
    )


@perp.command("twap-cancel")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("twap_id")
@node_option
@wait_option
@yes_option
def twap_cancel_cmd(wallet_file, twap_id, node, wait, yes):
    _send(node, wallet_file, "TWAP_CANCEL", {"twap_id": twap_id}, f"Stop TWAP {twap_id}", wait, yes)


@perp.command("vault-deposit")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("amount")
@node_option
@wait_option
@yes_option
def vault_deposit_cmd(wallet_file, amount, node, wait, yes):
    """Put free collateral into the liquidation backstop vault for shares (locked a while)."""
    _send(
        node,
        wallet_file,
        "VAULT_DEPOSIT",
        {"amount": str(Decimal(amount))},
        f"Deposit {amount} into the backstop vault",
        wait,
        yes,
    )


@perp.command("vault-withdraw")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("shares")
@node_option
@wait_option
@yes_option
def vault_withdraw_cmd(wallet_file, shares, node, wait, yes):
    """Redeem vault shares at the vault's current value."""
    _send(
        node,
        wallet_file,
        "VAULT_WITHDRAW",
        {"shares": str(Decimal(shares))},
        f"Redeem {shares} vault shares",
        wait,
        yes,
    )


@perp.command("create-market")
@click.argument("wallet_file", type=click.Path(exists=True))
@click.argument("base")
@click.option("--max-leverage", default=None, help="Default 20")
@node_option
@wait_option
@yes_option
def create_market_cmd(wallet_file, base, max_leverage, node, wait, yes):
    """Open a market for BASE, such as BTC. It trades once validators price it. Listing burns
    the network's market listing fee (PERP_MARKET_LISTING_FEE QRDX). Only where the network
    allows open listing (PERP_OPEN_LISTING, a dev network's setting): elsewhere validator-priced
    markets are listed by governance (``list_market``), and a bonded deployer lists its own as
    ``dex:ASSET`` (docs/HYPERLIQUID_PARITY.md)."""
    from ..constants import PERP_MARKET_LISTING_FEE

    params = {"base_token": base}
    if max_leverage:
        params["max_leverage"] = str(Decimal(max_leverage))
    what = f"Create the {base} perp market (burns {PERP_MARKET_LISTING_FEE} QRDX)"
    _send(node, wallet_file, "CREATE_MARKET", params, what, wait, yes)
