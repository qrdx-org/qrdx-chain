# Perps & exchange API — for wallets and apps

How a wallet or app trades QRDX perpetuals: the transaction format, the REST endpoints, the
JSON-RPC methods, the realtime streams, and the `qrdx-wallet perp` CLI. How the perps engine
works (matching, margin, liquidations, funding, the oracle) is in
[PERPS_CLEARINGHOUSE.md](PERPS_CLEARINGHOUSE.md). Spot — swaps, liquidity, the spot order
books — uses the same transactions and submission path; its operations and reads are in §7.

Every surface reads through one set of views (`qrdx/exchange/views.py`) and writes through one
path (`qrdx/exchange/submission.py`), so they always agree. Any node serves all of it: exchange
transactions are gossiped, so the node you submit to does not have to be a validator.

---

## 1. Transactions

Every perps action is an **exchange transaction**: a JSON object signed with the sender's
post-quantum (Dilithium / ML-DSA-65) key. A traditional `0x` key cannot sign one.

```jsonc
{
  "op_type": 21,                     // or "PERP_ORDER"
  "sender": "0xPQ…",
  "nonce": 4,                        // the sender's next EXCHANGE nonce (not its account nonce)
  "params": {"market_id": "BTC-USD-PERP", "side": "buy", "size": "0.5", "price": "65000"},
  "gas_limit": 1000000,
  "gas_price": "1000000000",         // WEI per gas: at least the floor (exchange_gasPrice)
  "public_key": "<hex>",             // must derive to sender
  "signature": "<hex>"               // over the signing bytes below
}
```

| op | # | params |
|---|---|---|
| `PERP_DEPOSIT` | 18 | `amount` — collateral (the stablecoin) moved from the wallet into the clearinghouse |
| `PERP_WITHDRAW` | 19 | `amount` — at most `withdrawable` |
| `PERP_SET_LEVERAGE` | 20 | `market_id`, `leverage`, `mode` (`cross` \| `isolated`) |
| `PERP_ORDER` | 21 | `market_id`, `side` (`buy` \| `sell`), `size`, `price`, optional `reduce_only` (bool), `tif` (`gtc` default \| `ioc`) |
| `PERP_CANCEL` | 22 | `market_id`, `order_id` |
| `VAULT_DEPOSIT` | 23 | `amount` — free collateral into the backstop vault, for shares |
| `VAULT_WITHDRAW` | 24 | `shares` |
| `CREATE_MARKET` | 12 | `base_token` (e.g. `BTC`), optional `max_leverage` (default 20) |

Amounts, sizes and prices are decimal strings. There are only limit orders; a "market order" is
`tif: "ioc"` at an aggressive price. An order's id is the first 16 characters of its
transaction hash (the receipt also returns it).

**Nonce.** `GET /get_exchange_nonce?address=` or `exchange_getNonce`. A transaction that
executes consumes its nonce whether it succeeds or fails (e.g. an order refused for margin); one
rejected before execution (bad signature, wrong nonce, under-priced, unaffordable gas) does not.

**Fees.** Gas is priced in wei (1 QRDX = 10^18 wei), at least the floor `exchange_gasPrice`
returns (1 gwei). Every executed transaction — success or failure — pays its operation's gas ×
`gas_price` in QRDX, burned (about 0.00004–0.00015 QRDX); the sender needs QRDX for
`gas_limit × gas_price`, reserved while it runs. The receipt reports `fee` and `gas_price`.

**Signing bytes** — what the signature covers, concatenated:

| field | encoding |
|---|---|
| `op_type` | 1 byte |
| `sender` | UTF-8 |
| `nonce` | 8 bytes, big-endian |
| `params` | Python `json.dumps(params, sort_keys=True, default=str)` (note the `", "` / `": "` separators) |
| `gas_limit` | 8 bytes, big-endian |
| `gas_price` | the integer wei amount as a decimal string, UTF-8 (`"1000000000"`) |

The transaction hash is BLAKE2b-256 of the same bytes, in hex. Reproducing the params rendering
outside Python is error-prone, so the node serves it: **`POST /exchange_signing_payload`** (or
`exchange_getSigningPayload`) takes the unsigned fields and returns `signing_bytes` (hex),
`tx_hash`, and the normalized `tx` to which you add `signature` and `public_key`.

**Submit** — `POST /submit_exchange_tx` with `{"tx": {…}}` (or the legacy
`{"tx_hex": "<the JSON string>"}`), or `exchange_sendTransaction(tx)`. Admission checks the
signature, sender binding, nonce window and capacity, then the node gossips the transaction to
its peers and any validator can include it. It **executes only in a block**: poll the receipt.

**Receipt** — `GET /get_exchange_receipt?tx_hash=` / `exchange_getTransactionReceipt`:

```json
{"tx_hash": "…", "block_height": 812, "block_time": 1790898900.0, "op": "PERP_ORDER",
 "sender": "0xPQ…", "nonce": 4, "success": true, "error": "", "gas_used": 60000,
 "data": {"order_id": "3f9a…", "resting": false,
          "fills": [{"market": "BTC-USD-PERP", "price": "65000", "amount": "0.5",
                     "buyer": "0xPQ…", "seller": "0xPQ…", "maker": "0xPQ…", "realized": {…}}]}}
```

`null` means pending (or aged out — each node keeps the latest 50,000 receipts and rebuilds them
from the chain on restart).

---

## 2. REST

All responses are `{"ok": true, "result": …}` or `{"ok": false, "error": "…"}`.

| endpoint | what |
|---|---|
| `GET /get_perp_markets` | every market: oracle / mark / last price, open interest, best bid / ask, funding rate, next funding time |
| `GET /get_perp_market?market_id=` | one market |
| `GET /get_perp_orderbook?market_id=&depth=20` | price levels, best first: `bids` / `asks` as `[price, size]` |
| `GET /get_perp_account?address=` | collateral, withdrawable, equity, maintenance / initial margin, positions (size, entry, mark, uPnL, notional, leverage, mode, **estimated liquidation price**), open orders, vault shares, the collateral token |
| `GET /get_perp_orders?address=` | resting orders, every market |
| `GET /get_perp_vault` | the backstop vault: NAV, shares, share value, positions it carries, lockup |
| `GET /get_perp_trades?market_id=&limit=50` | recent fills, oldest first (liquidation fills flagged) |
| `GET /get_perp_events?market_id=&address=&types=fill,liquidation,funding&since=&limit=` | the event feed; `since` is a sequence number, `last_seq` the newest |
| `GET /get_exchange_receipt?tx_hash=` | a transaction's result |
| `GET /get_exchange_nonce?address=` | the next exchange nonce |
| `GET /get_token_balance?token_address=&address=` | a QRC-20 balance (e.g. the stablecoin) |
| `POST /exchange_signing_payload` | the bytes to sign (§1) |
| `POST /submit_exchange_tx` | submit (§1) |

The liquidation price is an estimate: the mark at which the position reaches maintenance,
holding the account's other positions at their current marks.

---

## 3. JSON-RPC (`POST /rpc`)

Always enabled, on every node.

| method | params |
|---|---|
| `exchange_sendTransaction` | `tx` (object or JSON string) → tx hash |
| `exchange_getSigningPayload` | `tx` (unsigned fields) |
| `exchange_getTransactionReceipt` | `tx_hash` |
| `exchange_getNonce` | `address` |
| `exchange_getTokenBalance` | `token_address`, `address` |
| `exchange_getStateRoot` | — |
| `perp_getMarkets` | — |
| `perp_getMarket` | `market_id` (unknown → error −32001) |
| `perp_getOrderBook` | `market_id`, `depth` = 20 |
| `perp_getAccount` | `address` |
| `perp_getOpenOrders` | `address` |
| `perp_getVault` | — |
| `perp_getTrades` | `market_id`, `limit` = 50 |
| `perp_getEvents` | `market_id`, `address`, `types`, `since`, `limit` (all optional) |

A rejected submission is error −32003 with the reason (`nonce too low: …`, `invalid
signature`, …).

---

## 4. Streams — `/ws` (WebSocket) and `/stream` (SSE)

Enabled per node with `QRDX_ENABLE_STREAMING=1`. A client receives the block feed by default and
chooses other channels:

* WebSocket: send `{"op": "subscribe" | "unsubscribe" | "set", "channels": [...]}` (reply
  `{"type": "subscribed", "channels": [...]}`), or `{"op": "channels"}`; or connect to
  `/ws?channels=a,b`.
* SSE: `GET /stream?channels=a,b`.

| channel | events |
|---|---|
| `blocks` | `{"type": "block", "height", "finalized_epoch"}` — the default |
| `perp_markets` / `perp_markets:<id>` | `{"type": "perp_market", "market": <as GET /get_perp_market>}` when it changes |
| `perp_book:<id>` | `{"type": "perp_book", "book": <as GET /get_perp_orderbook>}` when it changes |
| `perp_events` / `perp_events:<id>` | `{"type": "perp_event", "event": <a fill, liquidation or funding event>}` as blocks commit |
| `perp_account:<address>` | `{"type": "perp_account", "account": <as GET /get_perp_account>}` when it changes (live PnL included) |
| `spot_pools` / `spot_pools:<pool_id>` | `{"type": "spot_pool", "pool": <as GET /get_pools>}` when it changes |
| `spot_book:<tokenA>:<tokenB>` | `{"type": "spot_book", "book": <as GET /get_spot_orderbook>}` when it changes (either token order) |
| `spot_account:<address>` | `{"type": "spot_account", "account": {"positions": …, "orders": …}}` — liquidity positions (with uncollected fees) and resting spot orders |
| `tokens` / `tokens:<token>` | `{"type": "token", "token": <as GET /get_token>}` when supply or authorities change |
| `orderbook:<market>` | `{"type": "orderbook", "book": <as GET /get_orderbook, level 2>}` when it changes — any market: a spot pair (either order, QRDX by name) or a perps market (§8) |
| `trades` / `trades:<market>` | `{"type": "trade", "trade": <as one of GET /get_trades>}` for every trade as its block commits — book fills, pool swaps, perps fills |
| `tickers` / `tickers:<market>` | `{"type": "ticker", "ticker": <as GET /get_ticker>}` when it changes |

Each perps, spot or token subscription starts with a snapshot of the current state
(`"snapshot": true`). At most
64 channels per client. The stream is a display feed: a reading can catch a block mid-way, so a
wallet confirms with the receipt and re-reads over REST / RPC after reconnecting.

```js
const ws = new WebSocket("ws://node:3007/ws");
ws.onopen = () => ws.send(JSON.stringify({op: "subscribe",
  channels: ["perp_markets", "perp_book:BTC-USD-PERP", `perp_account:${address}`]}));
ws.onmessage = (m) => render(JSON.parse(m.data));
```

---

## 5. CLI — `qrdx-wallet perp`

```
qrdx-wallet perp markets                         [--node URL] [--json]
qrdx-wallet perp book BTC-USD-PERP [--depth 10]
qrdx-wallet perp account 0xPQ…
qrdx-wallet perp receipt <tx_hash>
qrdx-wallet perp deposit  wallet.json 1000              [--wait] [--yes]
qrdx-wallet perp leverage wallet.json BTC-USD-PERP 5 [--isolated]
qrdx-wallet perp order    wallet.json BTC-USD-PERP buy 0.1 65000 [--reduce-only] [--ioc]
qrdx-wallet perp cancel   wallet.json BTC-USD-PERP <order_id>
qrdx-wallet perp withdraw wallet.json all
qrdx-wallet perp vault-deposit / vault-withdraw / create-market …
```

Writes ask for the wallet password, sign with its post-quantum key (a unified wallet uses its PQ
half), submit over JSON-RPC, and with `--wait` print the receipt (fills, order id, error).

---

## 6. Example — a wallet that does not run this codebase

```python
import httpx
node = "http://node:3007"
fields = {"op_type": "PERP_ORDER", "sender": addr, "nonce": nonce,
          "params": {"market_id": "BTC-USD-PERP", "side": "buy", "size": "0.1", "price": "65000"}}
p = httpx.post(f"{node}/exchange_signing_payload", json={"tx": fields}).json()["result"]
signature = dilithium_sign(secret_key, bytes.fromhex(p["signing_bytes"]))   # ML-DSA-65
tx = dict(p["tx"], signature=signature.hex(), public_key=public_key.hex())
httpx.post(f"{node}/submit_exchange_tx", json={"tx": tx})
# … then poll GET /get_exchange_receipt?tx_hash=<p["tx_hash"]>
```

---

## 7. Spot — swaps, liquidity, spot order books

Spot trades native tokens (addressed by token address) **and native QRDX** (named `QRDX`, any
casing — no wrapping: its side settles in account balances) through two venues: AMM pools
(concentrated liquidity, Uniswap-V3 mathematics) and a limit order book per pair. A pair is
always the **sorted** pair: `token0` is the lower name, and `QRDX` sorts after every `0x…`
address, so a QRDX pair is priced in QRDX; a pool's price is token1 per token0, and a book's
base is token0, priced in token1. Every operation is all-or-nothing — one that fails
(slippage, an unaffordable deposit, someone else's position) changes nothing. Transfer-fee and
non-transferable tokens cannot be pooled ([NATIVE_TOKENS.md §7](NATIVE_TOKENS.md)).

| op | # | params |
|---|---|---|
| `SWAP` | 4 | `token_in`, `token_out`, `amount_in`, `min_amount_out`, optional `deadline` (block time), `venue` (`auto` \| `amm` \| `clob`), `pool_id` |
| `ADD_LIQUIDITY` | 2 | `pool_id` (or `token0` + `token1` [+ `fee_tier`]), `tick_lower`, `tick_upper` (multiples of the pool's tick spacing), `amount` — the liquidity L |
| `REMOVE_LIQUIDITY` | 3 | `pool_id`, `position_id`, optional `amount` (L; default all, `0` collects fees only). Owner only; pays principal + fees |
| `PLACE_ORDER` | 5 | `pair` (`tokenA:tokenB`, either order), `side`, `order_type` `limit`, `price`, `amount` (base) — escrowed while it rests |
| `CANCEL_ORDER` | 6 | `order_id`, `pair` — refunds the escrow |
| `CREATE_POOL` | 1 | `token0`, `token1`, `fee_tier` (100 \| 500 \| 3000 \| 10000), `pool_type`, `initial_price` (token1 per token0 of the sorted pair), `stake_amount` (QRDX) |
| `REMOVE_POOL` | 17 | `pool_id` — the creator, once no position remains; refunds the stake, pays out protocol fees |
| `TOKEN_DEPLOY` / `TOKEN_TRANSFER` | 13 / 14 | `name`, `symbol`, `total_supply`, `decimals`, … / `token_address`, `to`, `amount` — and mint, burn, approvals, authorities and freezing: [NATIVE_TOKENS.md](NATIVE_TOKENS.md) |

**A swap** goes to the venue that pays the most for `amount_in`: any of the pair's pools, or the
book (walking the bids when selling the base, the asks when buying it; it stops at the sender's
own orders). It settles with that venue — the pool's holder, or the matched makers' escrow. Get
the quote first and set `min_amount_out` from it, less your slippage tolerance: if nothing trades
in between, the swap gets exactly the quote. Fees: 70 % of a pool's fee goes to its in-range LPs,
30 % to the protocol.

**Adding liquidity**: pick a range, then ask `/get_liquidity_quote` with the token amounts you
want to put in — it returns the most liquidity they buy and the exact deposit; send that
`liquidity` as ADD_LIQUIDITY's `amount`. The receipt carries the `position_id`. A position earns
fees only while the price is inside its range.

| REST | JSON-RPC | what |
|---|---|---|
| `GET /get_pools?token_a=&token_b=` | `exchange_getPools` | pools (all, or a pair's): price, tick, active liquidity, fee tier, tick spacing, protocol fees, volume, `holder_address` |
| `GET /get_pool?pool_id=&twap_window=` | `exchange_getPool` | one pool + its initialized ticks + positions; `twap_window` (seconds) adds the time-weighted price |
| `GET /get_swap_quote?token_in=&token_out=&amount_in=&sender=&venue=&pool_id=` | `exchange_quoteSwap` | the exact fill: `source`, `pool_id`, `amount_in` used, `amount_out`, `fee`, `execution_price` (in per out), `price_before` / `price_after` / `price_impact` (pools) |
| `GET /get_liquidity_quote?pool_id=&tick_lower=&tick_upper=&amount0=&amount1=` (or `&liquidity=`) | `exchange_quoteLiquidity` | liquidity and its exact deposit |
| `GET /get_lp_positions?address=` | `exchange_getPositions` | an address's positions: range, liquidity, in range?, and what removing it pays now (`amount0/1` principal + `fees0/1`) |
| `GET /get_spot_orderbook?pair=&depth=20` | `exchange_getOrderBook` | price levels (quote per base), best first, and the escrow address |
| `GET /get_spot_orders?address=` | `exchange_getOpenOrders` | resting spot orders, every pair |
| `GET /get_token_balance?token_address=&address=` | `exchange_getTokenBalance` | a token balance |

CLI: `qrdx-wallet spot pools | quote | positions | book | orders | receipt` to read;
`swap` (quotes first and refuses less than the quote minus `--slippage`), `add-liquidity`
(`--amount0` / `--amount1`, through the liquidity quote), `remove-liquidity`, `order`, `cancel`,
`create-pool` to write.

```python
q = httpx.get(f"{node}/get_swap_quote", params={"token_in": A, "token_out": B,
              "amount_in": "100", "sender": addr}).json()["result"]
min_out = Decimal(q["amount_out"]) * Decimal("0.995")          # 0.5 % tolerance
fields = {"op_type": "SWAP", "sender": addr, "nonce": nonce,
          "params": {"token_in": A, "token_out": B, "amount_in": "100",
                     "min_amount_out": str(min_out)}}
# sign and submit as in §6
```

---

## 8. Market data — one shape for every market

For interfaces: every market — a spot pair (book and/or pools) or a perps market — answers the
same endpoints in the same shape (`qrdx/exchange/views.py`, `qrdx/exchange/market_data.py`).
A `market` is a spot pair `base:quote` (`/` also accepted; token addresses, a token's symbol
when it is unique, or `QRDX`; either order) or a perps market id. Prices are quote per base,
amounts are base units. Trades, candles and 24-hour statistics come from the blocks as they
commit (by **block time**) — every node that imported the same blocks serves the same data.

| REST | JSON-RPC | what |
|---|---|---|
| `GET /get_markets?kind=spot\|perp` | `market_getMarkets(kind)` | every market's ticker |
| `GET /get_ticker?market=` | `market_getTicker` | best bid/ask, mid, last price, 24h open/high/low/change/%/volume/quote volume/trades; a spot pair adds its deepest pool's price and pool count, a perps market its mark, oracle, funding and open interest |
| `GET /get_orderbook?market=&depth=50&level=2\|3` | `market_getOrderBook(market, depth, level)` | level 2: price levels with running `total` (base) and `notional_total` (quote) and order counts; level 3: every resting order (id, owner, remaining) per level in time priority. Plus best bid/ask, `spread`, `spread_bps`, `mid`, `last_price`, the `block_height` it reflects, and for a spot pair its AMM pools (`amm`) |
| `GET /get_trades?market=&limit=&since=` | `market_getTrades(market, limit, since)` | recent trades, oldest first: `seq`, `price`, `amount`, `quote_amount`, the taker's `side`, `venue` (`clob` \| `amm` \| `perp`), `maker`, `taker`, `pool_id`, `tx_hash`, block height and time. `since` (a `seq`) returns only newer ones; `last_seq` is the newest |
| `GET /get_candles?market=&interval=1m&limit=&end=` | `market_getCandles` | OHLCV by block time — `1m 5m 15m 1h 4h 1d` — with quote volume and trade count |

The streams carry the same shapes live: `orderbook:<market>`, `trades[:<market>]`,
`tickers[:<market>]` (§4). Bounded: the newest 1000 trades and 1500 candles per interval per
market; rebuilt with the exchange state after a restart or reorg.

## 9. Transaction history — what a wallet did, and what the chain did

Every canonical block's transactions are indexed (`qrdx/tx_index.py`) — legacy transfers
(`genesis`, `transfer`, `coinbase`), exchange operations (`exchange`: token moves and mints,
swaps, orders, pools, perps, NFTs, staking) and EVM transactions (`evm`: QRDX transfers,
contract calls and deployments, with every ERC-20 / ERC-721 `Transfer` they emitted) — under
**every account each one touched**, with that account's roles: `sender`; `to`, `from`,
`spender`, `operator`, `account`; `maker` (an order of yours that someone else's transaction
filled); `token_from` / `token_to`; `created`. An account's `0x` and `0xPQ` addresses share one
history.

| REST | JSON-RPC | what |
|---|---|---|
| `GET /get_address_history?address=&limit=50&cursor=&kinds=` | `tx_getHistory(address, limit, cursor, kinds)` | newest first: `tx_hash`, `kind`, `op`, block height and time, `sender`, `target`, `asset`, `amount`, `status` (`success` \| `failed` \| `unknown`), `fee` (QRDX), `error`, `detail` (parameters and what it did), `roles`. Page with `cursor` = the previous page's `next_cursor`; `kinds` filters (comma-separated) |
| `GET /get_latest_transactions?limit=&cursor=&kinds=` | `tx_getRecent` | the chain's latest transactions, every kind |
| `GET /get_indexed_transaction?tx_hash=` | `tx_getTransaction` | one transaction and every account it touched, with roles |

The index follows the tip in the background (a block appears within about a second of being
applied) and follows reorgs: blocks that leave the chain leave the index. `indexed_height` in
each answer is how far it has got. Node-local and derived — never consensus; disable with
`QRDX_TX_INDEX=0`.
