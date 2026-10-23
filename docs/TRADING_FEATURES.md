# Trading features — order types, triggers, TWAP, agents, vaults, fees, history

What the exchange offers beyond a plain limit order, how each feature is enforced in consensus,
and how a wallet or app uses it. Transactions, signing and submission are as in
[PERPS_API.md](PERPS_API.md) §1; the perps engine is in
[PERPS_CLEARINGHOUSE.md](PERPS_CLEARINGHOUSE.md); block and gas limits are in
[BLOCK_LIMITS.md](BLOCK_LIMITS.md).

Everything here is consensus state: committed in the exchange state root, executed identically by
every node, undone exactly when an operation fails (below). The defaults marked *default* are
starting values for review, not settled economics.

| Code | What |
|---|---|
| `qrdx/exchange/undo.py` | All-or-nothing operations (undo scopes) |
| `qrdx/exchange/orderbook.py` | Time in force, hidden and iceberg orders, in-place size reduction |
| `qrdx/exchange/clearinghouse.py` | Perps triggers, modify, cancel-all, user vaults, fee tiers, referrals, portfolio margin |
| `qrdx/exchange/trading.py` | Spot triggers, TWAPs, agents, sub-accounts |
| `qrdx/exchange/state_manager.py` | The operations, the batch, multi-hop swaps, the tick's spot work |
| `qrdx/trading_history.py` | The trading history (database) |
| Tests | `tests/test_order_types.py`, `test_trading_ops.py`, `test_acting_for_accounts.py`, `test_portfolio_margin.py`, `test_trading_history.py`, `test_undo_scopes.py` |

---

## 1. Every operation is all or nothing

An exchange operation that fails changes nothing: it pays its gas and consumes its nonce, and
that is all. Inside an undo scope (`undo.atomic()`), each piece of exchange state records what it
was the first time the operation touches it — a committed entry, an order book's price level, a
clearinghouse market's fields — and a failure puts exactly those back. The cost follows what the
operation touched, not the size of the state. (A spot order used to deep-copy its whole book
first; a perp order that matched and then could not rest kept the makers' fills without the
trades.) That is what makes fill-or-kill, modify, batches and multi-hop swaps safe to offer.

An operation that fails after matching pays for the resting orders it visited
(`EXCHANGE_GAS_PER_MAKER` each), exactly as it would have had it succeeded: a fill-or-kill order
cannot sweep the book and fail for its base gas.

---

## 2. Order types

### Time in force — spot `PLACE_ORDER` and `PERP_ORDER`, param `tif`

| `tif` | |
|---|---|
| `gtc` (default) | What does not fill rests on the book |
| `ioc` | What does not fill is cancelled |
| `fok` | Fills whole, or the operation fails and changes nothing |
| `alo` | Post-only: refused, changing nothing, if any resting order (a hidden one included) would match it |

An unknown value is refused. Spot `MARKET` orders are allowed now: they take what the book has,
each fill paid live from the sender's balance (one it cannot cover fails the order whole), and
never rest or escrow.

### Hidden and iceberg orders — params `hidden` (true/false), `display_size`

A **hidden** order matches like any other but shows nothing in the book's depth. An **iceberg**
shows `display_size` at a time; the rest is hidden. Only a resting limit order (`gtc` or `alo`)
can be either. Neither is private: the order's parameters are in its transaction on the chain.

Priority within a price level has two tiers: every displayed quantity in time order (an iceberg's
current slice), then every hidden quantity in time order (an iceberg's reserve, a hidden order).
An iceberg whose slice runs out shows its next slice from the back of the level. Depth, best
bid/ask and everything priced from the book — the mark price, the funding premium, the impact
price — read displayed quantities only. The router quotes in the same two-tier order, so a quote
is still exactly what executes (fuzz-tested over thousands of random books).

`yes/no` params are JSON booleans: a string `"false"` is refused, never read as true.

---

## 3. Trigger orders — stop-loss and take-profit

### Perps — `PERP_TRIGGER` (56)

| param | |
|---|---|
| `market_id`, `side` | |
| `kind` | `sl` (stop) or `tp` (take-profit) |
| `trigger_price` | Judged on the **mark price** |
| `size` | Or `position: true` — the position's TP/SL: it closes the whole position, whatever it is when it fires, and is cancelled once there is no position on that side |
| `limit_price` | Optional: the order it becomes is a limit order there (`tif` `gtc` or `ioc`); without one it is a market order at most `TRIGGER_SLIPPAGE` (10 %) through the mark |
| `reduce_only` | Clamped to the position when it fires |
| `max_makers` | The matching it may do when it fires, **paid now**: 1–100, default 20; gas = 40,000 + `max_makers` × 10,000 |

A buy stop and a sell take-profit fire as the mark rises to the trigger; a sell stop and a buy
take-profit as it falls. A trigger the mark has already reached is refused (place an order
instead). At most 50 per account per market.

### Spot — `PLACE_ORDER` with `order_type` `stop_loss` or `take_profit`

`trigger_price` (or `stop_price`), `amount`, optional `price` (the limit; without one, a market
order paying at most 10 % above the trigger for a buy, taking at least 10 % below it for a sell),
`tif` `gtc`/`ioc`, `max_makers`. `order_type` `oco` is both at once over one escrow — a stop leg
(`trigger_price`, `price`) and a take-profit leg (`tp_price`, `tp_limit`); the first the price
reaches fires. Judged on the pair's **last order-book trade price**. Its funds
are **escrowed when placed** (the base for a sell, `amount` × its highest price of quote for a
buy) in the pair's book escrow. When it fires it settles entirely out of that escrow; what it did
not use comes back. Cancel with `CANCEL_ORDER` (full refund). At most 50 per account per pair.

The order book's own stop orders triggered inside whichever trade moved the price, unbounded, and
settled nothing; operations no longer place them.

### Attached to an order — a TP and SL that protect what it buys

**Perps:** `PERP_ORDER` with `tp` and/or `sl`, each `{trigger_price, limit_price?, max_makers?}`,
places reduce-only triggers on the other side, sized to the order, in a group: the first to fire
cancels the other. They go with the order if it is cancelled before it fills, and once it is done
and there is no position left for them to reduce. A TP/SL the mark has already reached refuses the
whole order. Each costs what a `PERP_TRIGGER` costs; the order's matching gets what is left of the
gas limit.

**Spot:** `PLACE_ORDER` of a **buy** with `tp` and/or `sl`, each `{trigger_price, price?}`
(`tp_sl_max_makers`, `tp_sl_tif` optional), places one sell trigger — an oco with both — that
starts **empty**: each fill of the order, whenever and however it happens (as taker now, as a
maker later, against a fired trigger or a swap), puts the base it bought (after its fee) into the
trigger's escrow instead of the buyer's balance. It protects exactly what was bought. If the order
is cancelled before it buys anything the trigger goes too; one holding base stays. A modify that
replaces the order carries the trigger over to the new order.

### Firing

Triggers fire in the tick at the end of every block (after its transactions), as orders of their
owner: risk-reducing ones first, then those the price passed furthest, then the first placed. A
block fires at most 64 of each kind, visiting at most 1,000 resting orders between them; the rest
fire in the next blocks. One that cannot be placed (margin, a book limit) is cancelled with the
reason; it changes nothing else. While a market's oracle is stale only risk-reducing perps
triggers fire. A spot pair whose token is paused fires nothing until it resumes. A liquidation
cancels the account's perps triggers.

Events: `trigger_fired` / `trigger_cancelled` (perps), `spot_trigger_fired` /
`spot_trigger_cancelled` / `spot_trigger_waiting`.

---

## 4. Changing orders in one step

| op | # | params |
|---|---|---|
| `PERP_MODIFY` | 58 | `market_id`, `order_id`, `size` (what should be left), `price` — or for a trigger `trigger_price`, `limit_price`, `size` |
| `MODIFY_ORDER` | 59 | `pair`, `order_id`, `amount` (what should be left), `price` |
| `CANCEL_ALL` | 57 | optional `scope` (`all` \| `spot` \| `perps`), `market` (a pair or a perp market id) |

A smaller size at the same price **keeps the order's place in the queue** (spot: the escrow it
no longer needs comes back). Any other change cancels it and places a new order (a new id,
returned) — matched and margined like any order, all or nothing; hidden, iceberg and post-only
carry over. `CANCEL_ALL` cancels every resting order, trigger and TWAP of the sender in scope,
refunding spot escrow; it costs 20,000 gas plus 5,000 per order cancelled (a gas limit too low
for them all cancels none).

## 5. Batches — `BATCH` (60)

`{"actions": [{"op": "PERP_ORDER", "params": {…}}, …]}` — 1 to 20 actions, each one of
`PLACE_ORDER`, `CANCEL_ORDER`, `MODIFY_ORDER`, `SWAP`, `PERP_DEPOSIT`, `PERP_WITHDRAW`,
`PERP_SET_LEVERAGE`, `PERP_ORDER`, `PERP_CANCEL`, `PERP_TRIGGER`, `PERP_MODIFY`, `CANCEL_ALL`,
`TWAP_ORDER`, `TWAP_CANCEL`. They run in order as the sender, **all or nothing**: the first that
fails fails the batch (its error names the action), and nothing before it stays. One nonce; gas
is 10,000 plus each action's, within the batch's gas limit. Each action's order id derives from
the batch's hash and the action's place, so identical actions get distinct ids (returned in
`results`). A malformed batch is refused at admission.

## 6. Multi-hop swaps — `SWAP` with `path`

`{"path": ["A", "B", "C"], "amount_in": "…", "min_amount_out": "…"}` — up to 4 hops, each
through its pair's best venue (AMM pools or order book), each spending exactly what the hop
before it bought. `min_amount_out` bounds the last hop; short of it, the whole swap is undone.

A swap through an order book now pays for the resting orders it visits, as an order does: SWAP's
65,000 gas per hop plus 10,000 a resting order, and the router quotes the book within what the
gas limit pays for (a swap used to sweep any number of makers for its flat base gas).

## 7. TWAP — `TWAP_ORDER` (61), `TWAP_CANCEL` (62)

A size worked into the market unattended, in equal slices over `duration` seconds (60 s – 24 h).

| param | |
|---|---|
| perps | `market_id`, `side`, `size`, optional `reduce_only` |
| spot | `token_in`, `token_out`, `amount_in` — escrowed now, swapped slice by slice through the best venue |
| `slices` | Default one every 30 s, at most 60; at least 30 s apart |
| `max_slippage` | Each slice an IOC at most this far from the price (perps: the mark; spot: the marginal price of a thousandth of the slice); default 3 %, at most 10 % |
| `max_makers` | Per slice, 1–20, default 5 |

Gas, paid when placed: 40,000 + `slices` × (10,000 + `max_makers` × 10,000) — a 60-slice TWAP at
5 makers is 3.64M gas. The first slice runs in the same block's tick. Each slice is the remainder
over the slices left, so a slice that misses (no liquidity, beyond its slippage) is made up after.
A block runs at most 64 slices and 640 resting-order visits; the rest run next block. A liquidation
stops the account's perps TWAPs; a reduce-only TWAP stops when the position is gone. Cancelling a
spot TWAP returns the unspent escrow. At most 10 per account. Events `twap_slice`, `twap_finished`.

---

## 8. Acting for an account

(Binding wallets as controllers, turning an account's own key off, and multisig keys:
[ACCOUNT_CONTROL.md](ACCOUNT_CONTROL.md).)

### Agent keys — `AGENT_APPROVE` (63), `AGENT_REVOKE` (64)

A transaction may carry **`signer`**: the key that signed it when that is not `sender`. The
signature then binds to the signer's key; execution requires the account to have authorized it,
and refuses anything else **before** it consumes a nonce or gas. `signer` is part of the signed
bytes (`\x00signer:<address>` appended — only when present, so every other transaction keeps its
bytes and hash).

`AGENT_APPROVE` `{agent, valid_until, name}`: the agent (a `0xPQ` address) may sign **trading
operations** for the account — the orders, cancels, modifies, triggers, TWAPs, swaps,
`PERP_SET_LEVERAGE`, `CANCEL_ALL`, and batches of those — until `valid_until` (block time; 0:
until revoked). Never withdrawals, deposits, transfers, approvals, staking or governance. At most
10 per account. Revoked by the account, or by the agent itself. A bot holds an agent key; the
wallet never signs its orders.

**Trust.** An agent cannot move funds out, but trading can lose them: a stolen or dishonest agent
key can trade the account's balances at bad prices against a counterparty its holder controls
(an order, or a swap through a pool it seeded). Approve agent keys as you would an exchange API
key with trading rights — and give them an expiry.

**Nonces.** A signer's transactions take their nonces from their own lane: `sender|signer`
(`exchange_getNonce(address, signer)`). A bot and its owner's wallet never race for one nonce.
The mempool queues and orders each lane separately. Gas is paid by the account.

### Sub-accounts — `SUBACCOUNT_CREATE` (65), `SUBACCOUNT_TRANSFER` (66)

A sub-account is its own balances, margin account and orders, at an address no key controls
(`0xSUBA…`, derived from the master and its number; at most 20). The master signs for it
(`sender` the sub-account, `signer` the master) — any operation; the master's agents may trade
for it too. `SUBACCOUNT_TRANSFER` `{subaccount, asset, amount, direction: to_sub | from_sub}`
moves QRDX or a token between them.

---

## 9. User vaults — copy trading

`VAULT_CREATE` (67) `{amount, profit_share, name}`: a margin account (`0xUVLT…`) its leader
trades by signing for it (`sender` the vault, `signer` the leader or the leader's agent) —
trading operations only. Others join with `VAULT_DEPOSIT {vault, amount}`: their free collateral
for shares at NAV (the vault's equity at mark), locked for 1 day. `VAULT_WITHDRAW {vault,
shares}` pays the shares out at NAV, less the leader's `profit_share` (default 10 %, at most 50 %)
of what they gained over what they cost; refused while locked or beyond what the vault can release
without dropping below margin on its positions. The leader starts it with at least 100 and holds
at least 5 % of the shares while anyone else holds any. At most 5 per leader. The leader pays the
vault's gas.

**Trust.** Depositors trust the leader's trading. The protocol bounds the worst of it: a vault's
order may be no more than 10 % worse than the mark when placed, so a leader cannot hand an
account it controls the vault's equity in one fill. Within that band a dishonest leader can still
lose depositors' money to a counterparty it controls, a little at a time — as on any exchange
with vaults.

---

## 10. Fees — tiers, maker rebates, referrals

An account's rates follow its perps volume (notional, as buyer or seller) over the last 14 days
of block time (*default* tiers):

| 14-day volume | taker | maker |
|---|---|---|
| < 5M | 0.050 % | 0.020 % |
| 5M | 0.045 % | 0.016 % |
| 25M | 0.040 % | 0.012 % |
| 100M | 0.035 % | 0.008 % |
| 500M | 0.030 % | 0.004 % |
| 2B | 0.028 % | 0 |
| 7B | 0.026 % | −0.002 % (a rebate) |

A rebate is paid out of the fee the same trade's taker pays: every taker rate is above every
rebate, so no trade costs the backstop vault, which collects the fees.

**Referrals** — `REFERRAL_REGISTER` (68) `{code}` (3–16 of a-z, 0-9, _; one per account),
`REFERRAL_JOIN` (69) `{code}` (once, before 10,000 of volume). A referee pays 4 % less on its
first 25M of volume; its referrer earns 10 % of the fees it pays, out of the vault's share.

Each fill reports both sides' fees (`fees`).

**Spot order books** charge the same tiers. Each side pays out of what it **receives** — the
buyer in base, the seller in quote — so nothing changes for escrow and receiving less can never
fail. A spot maker pays no less than zero (its fee and the taker's are in different assets, so
there is no rebate to fund). Fees go to the treasury (`TREASURY_MULTISIG`), less a referrer's
share. Spot volume counts toward an account's tier when the pair is quoted in the perps
settlement asset. The router quotes a swap net of the taker's fee, fill by fill, with the same
rounding as settlement, so a quote is exact. Rates are taken as they stood when the operation
began; its volume counts only after all its fills settle. AMM pools charge their pool fee, as
before.

---

## 11. Portfolio margin — tokens as perps margin

Tokens listed in the chain-spec parameter `PERP_PORTFOLIO_ASSETS` (`TOKEN:MARKET_ID:HAIRCUT`;
**none by default** — the feature is inert until assets are chosen) can be held as perps margin
beside the settlement token: `PERP_DEPOSIT` / `PERP_WITHDRAW` with `asset`. Each is valued at that
perp market's oracle price less its haircut, and counts toward cross equity — margin for
positions and orders. A deposit is worth at least 100.

Every amount is clearinghouse state: tokens move on the ledger only on deposit, withdrawal and the
vault's sales, so margin never depends on a balance loaded for a block. A token leaves only if
what is left carries the account — its positions and orders, and what it owes in settlement token
(losses and fees can take its settlement balance below zero; that debt counts against it).

An account liquidated hands its tokens to the backstop vault at the value they counted for (its
equity unchanged), before the book close; one with a debt and no positions is taken over once the
debt exceeds its tokens' haircut value (the vault absorbs what they do not cover). The vault sells
what it takes back into the settlement token, a slice every 30 s, through the spot venues, never
more than 2 % under the oracle (else it waits). Accounts holding tokens are checked every block
(their margin moves with the tokens' prices too).

**Before listing an asset:** it needs a perp market whose oracle prices it, spot liquidity against
the settlement token for the vault to sell into, and a haircut that covers a move over the time
the vault takes to sell — a risk decision.

---

## 12. History and reads

### Trading history — `history_*` (JSON-RPC)

Every trade (every venue and kind: trades, liquidations, triggers, TWAP slices, vault unwinds and
asset sales, with both sides' order ids, fees and realized PnL), every order's life (placed or
refused, modified, cancelled, triggered, finished, liquidated), every funding settlement, and each
perp market's mark, oracle, open interest and funding rate once a minute — written to the node's
database as blocks commit (`qrdx/trading_history.py`), kept for good, cut back with the chain on a
reorg. Node-local, never hashed; `QRDX_TRADING_HISTORY=0` turns it off.

| method | params |
|---|---|
| `history_getTrades` | `address` and/or `market`, `limit`, `cursor` |
| `history_getOrders` | `address` or `order_id`, `market`, `limit`, `cursor` |
| `history_getFunding` | `market`, `limit`, `cursor` |
| `history_getMarketSamples` | `market`, `since`, `until`, `limit` (oldest first) |
| `history_getLeaderboard` | `window` (`day` \| `week` \| `month` \| `all`), `metric` (`pnl` \| `volume`), `limit` |
| `history_getRecentTrades` | `address`, `limit` — from the node's memory (no database) |

Pages are newest first; pass `next_cursor` back as `cursor`. The leaderboard ranks perps accounts
by realized PnL net of fees, or by volume.

### State

| method | |
|---|---|
| `perp_getAccount` | Now also `triggers`, `twaps`, `assets` (portfolio margin), `fees` (volume, rates, referral) |
| `perp_getTriggers(address)` | Waiting triggers, perps and spot |
| `perp_getTwaps(address)` | TWAPs in progress |
| `perp_getFeeSchedule(address?)` | The tiers, and an address's volume and rates |
| `perp_getUserVaults(leader?)`, `perp_getUserVault(vault, holder?)` | User vaults: NAV, shares, share value, positions, a holder's shares, cost and value |
| `exchange_getAgents(address)`, `exchange_getSubaccounts(address)` | |
| `exchange_getNonce(address, signer?)` | A signer's lane |

Book depth (`market_getOrderBook`, `perp_getOrderBook`, `exchange_getOrderBook`) shows displayed
quantities; an owner's own open orders show `hidden` / `display_size`.

### CLI

`qrdx-wallet perp order … --tif fok|alo --hidden --display-size`, `perp trigger`, `perp modify`,
`perp cancel-all`, `perp twap`, `perp twap-cancel`.

---

## 13. Operation numbers and gas

| op | # | base gas |
|---|---|---|
| `PERP_TRIGGER` | 56 | 40,000 + prepaid matching |
| `CANCEL_ALL` | 57 | 20,000 + 5,000 per cancelled |
| `PERP_MODIFY` | 58 | 60,000 + matching |
| `MODIFY_ORDER` | 59 | 40,000 + matching |
| `BATCH` | 60 | 10,000 + each action's |
| `TWAP_ORDER` | 61 | 40,000 + slices × (10,000 + makers × 10,000) |
| `TWAP_CANCEL` | 62 | 25,000 |
| `AGENT_APPROVE` | 63 | 30,000 |
| `AGENT_REVOKE` | 64 | 20,000 |
| `SUBACCOUNT_CREATE` | 65 | 50,000 |
| `SUBACCOUNT_TRANSFER` | 66 | 40,000 |
| `VAULT_CREATE` | 67 | 100,000 |
| `REFERRAL_REGISTER` | 68 | 30,000 |
| `REFERRAL_JOIN` | 69 | 30,000 |
| `ACCOUNT_POLICY` | 70 | 40,000 — see [ACCOUNT_CONTROL.md](ACCOUNT_CONTROL.md) |

New op numbers and state are a consensus change: a network runs them from a fresh genesis (or a
fork that activates them).

---

## 14. Market liquidity — a listing comes with a book

`CREATE_MARKET` takes `liquidity`: at least the chain-spec `PERP_MARKET_MIN_LIQUIDITY` (*default*
10,000, in the settlement unit) of the creator's free perps collateral. It goes into the market's
**liquidity vault** (`0xUVLT…`, `market_maker_address`), and the protocol quotes that vault on the
market's book in every tick:

- every 5 s, or as soon as the mark moves 0.25 %: 5 post-only orders a side, 0.1 % from the mark
  and 0.1 % apart;
- each side worth 1 × the vault's equity in all, scaled down on the side its position already
  leans to — none once that position reaches 3 × equity;
- pulled while the market's oracle is stale; a level that would cross the book is skipped, so it
  never takes;
- at most 8 markets re-quoted a block.

No one signs for the vault — its creator included. It is a user vault (§9): anyone may add
liquidity at NAV (`VAULT_DEPOSIT {vault}`) and share its PnL and fees. The creator's shares are
locked for the chain-spec `PERP_MARKET_LIQUIDITY_LOCKUP_SECONDS` (*default* 30 days), and the
creator takes `liquidity_profit_share` (*default* 10 %) of others' gains. The vault's orders are
margined like anyone's and it can be liquidated like anyone. The inventory limit and the 10 %
vault order band keep it from being drained quickly, but a market maker can lose money. Markets
show their vault as `liquidity_vault`.
