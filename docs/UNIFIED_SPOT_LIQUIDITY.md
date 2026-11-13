# Unified spot liquidity: one market per pair

A spot pair trades in two places: its order book, and up to four AMM pools (one per fee tier).
Until 2026-10-26 they were separate markets. This change joins them into one: every trade on a
pair takes the best prices across the book and every pool, in price order. It also routes swaps
through a third token when that pays more, and lets spot stops and take-profits see trades in the
pools.

All of it is consensus: every node runs it identically on every path (proposer, importers and
both rebuilds). A network needs a fresh genesis for it.

## What was wrong

| # | Problem | Who lost |
|---|---|---|
| 1 | A swap from A to B used only the A/B pools and book. It never went through another token, even when A→C→B paid more. | The swapper. A bot that closed the gap kept the difference. |
| 2 | A swap sent all of its input to the one venue that quoted best (one pool, or the book). It never split. | The swapper, on any sizeable swap. |
| 3 | A spot limit order only matched the book. A buy at 2.10 rested on the book while a pool sold at 2.00. | The order's owner. Anyone could buy from the pool at 2.00 and sell to it at 2.10. |
| 4 | A swap could push a pool's price straight past resting orders without filling them. A buy at 1.90 stayed unfilled while the pool traded at 1.80. | The order's owner: the order never filled. |
| 5 | Spot stops and take-profits watched only the book's last trade. Pool trades never moved it, so on a pair that trades in its pools a stop-loss never fired. | The trigger's owner. |
| 6 | A trigger fired only if the price was past it at the end of a block. A move through it and back within a block (250 ms) did not count. | The trigger's owner. |

Perps did not have these problems: each perp market has one book, and its triggers watch the
mark price, as on Hyperliquid. Nothing here changes perps.

## 1. One market per pair

Every taker on a spot pair walks one combined market (`UnifiedRouter.plan_fill`). The takers are:
- a swap;
- a limit or market order;
- a fired stop or take-profit;
- a TWAP slice;
- the protocol's own sales (the stakers' fee conversion, the backstop vault's unwinds).

**Order of fills: best price first.** Prices are compared after each venue's fee:
- A book level at price *p* costs a buyer *p* / (1 − *taker fee*) per unit of base received, and pays a seller *p* × (1 − *taker fee*).
- A pool at price *p* with fee tier *f* costs a buyer *p* / (1 − *f*) at the margin, and pays a seller *p* × (1 − *f*).

**Ties go to resting orders.** They were there first, and a resting order is a quote the pools
must not trade through.

**Pools are split, not filled one at a time.** When two or more pools are the best price, they
move together. The amount is split so that they end at the same marginal price, which is the
cheapest split there is. With one pool the split is exact. With several, the common price is
found by bisection (40 steps), and the deepest pool takes the exact remainder.

**Planned, then executed exactly.** The walk is read-only. It returns the legs:
- one order-book leg: a size, the worst level it takes, and the resting orders it visits;
- at most one plan per pool.

Execution then does exactly what was planned:
- every check runs on the plan, before anything changes;
- the order-book leg executes as an immediate-or-cancel order, and must fill exactly its planned size;
- each pool applies its plan;
- if anything fails, the whole operation is undone.

**Stopping rules:**
- **Your own resting order:** the book closes to the walk there (self-trade prevention), as matching closes it. The pools may still fill the rest, so the walk passes only your own order. That order would then rest crossed with the pool, so the pair is queued and the next tick fills it from the pools (section 4).
- **Out of resting-order budget:** the walk stops entirely (`MatchBudget`, paid for by the transaction's gas). It never passes other people's orders it did not visit.
- **Limit:** a pool trades only while its marginal price, fee included, is within the limit. A book level trades only if its price is within the limit, as before (the exchange's taker fee is charged on top, as on any exchange).

**All or nothing.** A failed operation puts every pool back too. Before this change it did not
(see "A failed operation left a pool's price moved" below).

## 2. Swaps: the best path, split across venues

A `SWAP` with `token_in` and `token_out` (no `path`) now chooses its path:
- **Candidates:** the direct pair, and two hops through each routing hub. The hubs are QRDX and the perps settlement asset; a hub that is the swap's own input or output is skipped.
- **Choice:** the router plans every candidate (each hop through its pair's combined market, per section 1) and takes the one with the most output. On a tie the direct pair wins, then the hubs in order.
- **Gas:** a two-hop candidate is considered only if the transaction's gas limit covers two hops.

The result shows the path taken (`path`, `hops`).

| Parameter | Meaning |
|---|---|
| `path` | As before: exactly these tokens, each hop through its pair's combined market. |
| `pool_id` | Restricts the pools of a direct swap to that one pool. Resting orders at better prices still fill first: no swap trades through a resting order. |
| `venue: "clob"` | Book only. |
| `venue: "amm"` | Pools only, except that resting orders at better prices still fill first, as with `pool_id`. |
| `min_amount_out` | Bounds the final output, whatever the path. |

**Gas:**
- `SWAP`'s base gas for each hop;
- `EXCHANGE_GAS_PER_MAKER` for each resting order visited;
- `EXCHANGE_GAS_PER_MAKER` for each pool used beyond the first in a hop.

The block's balance preloads include the hubs, so the intermediate token a two-hop swap receives
and spends is always loaded.

## 3. Limit orders take from the pools first

`PLACE_ORDER` (a limit or market order) walks the combined market up to its limit. Only what is
left rests on the book.

**Limit price:**
- **Pool fills:** fee included, never worse than the limit. Each pool fill is at or better than the limit.
- **Book fills:** the level price is within the limit and the taker fee is charged on top, as before.

**Time in force:**
- **Post-only (`alo`):** refused if it would take from a pool, as it is refused if it would match a resting order. A post-only order never rests crossed with a pool.
- **Fill-or-kill:** the book and the pools together must fill it whole.

**What a pool fill pays:**
- **Exchange fees:** none. A pool fill pays its pool's fee (which already carries the protocol's share), not the exchange's spot taker fee.
- **Attached TP/SL (bracket):** the base a pool fill buys goes into the bracket's escrow, as a book fill's does.
- **Builder fee:** charged on pool fills too, at its rate of what the order received.

The order's `filled` counts pool fills. Its result lists every fill, with `venue` "amm" or "clob".

## 4. Resting orders fill when a pool reaches them

There are two ways a pool's price can reach a resting order.

**A taker pushes it.** This is now impossible without filling the order. A walk takes a resting
order before any pool price beyond it, so a swap that would push a pool past a resting bid sells
to the bid first.

**Liquidity appears at a price beyond the order.** This happens when liquidity is added to a pool
whose price is past resting orders. For example, a new pool opens at 1.50 while a bid rests at
1.90. It also happens when a trader's own swap passes their own resting order (section 1).
- `ADD_LIQUIDITY`, and such a swap, queue the pair (`trading.uncross`, committed in the state root).
- At the block's tick, each crossed resting order takes from the pools as a taker, best order first.
- It pays the pool's price, which is better than its limit, out of its own escrow, and gets the difference back. A buy with an attached TP/SL puts what it buys into the bracket, as any fill does.
- It stops at its limit. Whatever is unfilled keeps resting.
- At most `SPOT_UNCROSS_ORDERS_PER_BLOCK` (32) orders per block. The pair stays queued until the tick gets through its orders, so the rest fill in the next blocks.

A resting buy at 1.90 therefore fills whenever the market sells at or below 1.90, wherever the
market is. Its owner keeps any better price.

## 5. Stops and take-profits watch the pair's real price

**The pair's last price includes pool trades.** A pool fill counts as a trade at the pool's price
after it (its marginal price, without the fee). A taker's walk leaves the last price at the worst
price it reached.

**Reached means reached, even mid-block.** Every price a trade reaches is checked against the
pair's triggers:
- an upward-firing trigger is reached when a trade's price is at or above it;
- a downward-firing one when it is at or below.

Only trades after the trigger was placed count. A reached trigger is marked (`reached`, committed
with it). An OCO records which leg was reached first.

**Firing:**
- Marked triggers fire at the block's tick, through the combined market, along with any whose leg the last price is past.
- A trigger the block's firing limits defer stays marked and fires in a later block, even if the price has moved back.

**A stop never disappears unfilled** (the user's choice, 2026-10-27). A trigger with no limit
price fills within 10 % of its trigger (`TRIGGER_SLIPPAGE`). Before, if the price jumped past
that band, it fired, filled nothing and was gone. Now:
- what it cannot fill within the band waits, with its escrow (`waiting`);
- it fires again at each tick the pair's price is back within the band, until it fills or its
  owner cancels it;
- waiting triggers queue behind triggers firing for the first time, so stuck ones cannot use up
  a block's firing limits.

Perps market triggers work the same way, against 10 % of the mark: what finds no book within the
band waits and fires again at the next tick the mark is still past it. Its take-profit or
stop-loss partner stays until part of it fills.

A waiting perps trigger that **opens** a position fills only within 10 % of its own trigger, as a
spot trigger does. A breakout buy at 103 that the price gapped past to 130 waits for an ask by
113.3; it never buys near 130. A trigger that reduces a position still gets out within 10 % of
the mark: getting out is the point.

A trigger with a limit price is unchanged: when it fires, its order rests on the book (or, sent
as immediate-or-cancel, takes what it can and is gone).

**Stop hunting.** A trade can now reach a trigger within a block even if the price moves back by
the end of the block. Pushing a pool through stops costs the pusher the pools' fees both ways and
the price impact. The stopped orders fill at the tick at the market's price then, not at the
pushed price. A trader who wants no fill below a price sets a limit price on the stop.

Placing a trigger whose leg the pair's price has already reached is refused, as before. The
"price" is now the pair's last trade, pools included. A pair that has never traded uses its
deepest pool's price.

## Where it is

| Piece | Code | Tests |
|---|---|---|
| Pool swaps to a price limit, exact output, continuing a plan | `ConcentratedLiquidityPool.quote(…, sqrt_limit, exact_out, start)` | `tests/test_unified_spot.py` |
| The combined walk | `UnifiedRouter.plan_fill` | `tests/test_unified_spot.py` |
| Swap path choice | `ExchangeStateManager._plan_swap` | `tests/test_unified_spot.py` |
| Limit orders through pools | `_op_place_order`, `_take_spot` | `tests/test_unified_spot.py` |
| Uncrossing at the tick | `uncross_spot_books`, `trading.uncross`, `_flag_self_pass` | `tests/test_unified_spot.py` |
| A failed operation puts its pools back | `ExchangeStateManager._atomic` | `tests/test_unified_spot.py` |
| Triggers on the pair's price | `_record_spot_prices`, `SpotTrigger.reached`, `fire_spot_triggers` | `tests/test_unified_spot.py` |

## Verified (2026-10-27)

- **Tests:** `tests/test_unified_spot.py`, 29 tests, one per defect above, plus random trading
  that checks escrow stays whole, the book ends uncrossed and every LP can withdraw.
  `test_reorg_rebuild_equivalence.py::test_rebuild_equivalence_unified_spot` runs each new path
  on a real database and requires the rebuild to reproduce the forward account, token and
  exchange roots.
- **Live, 4 nodes:**
  - **Hub routing:** a swap went through QRDX for 198 against 49.8 direct, exactly its quote.
  - **Limit through a pool:** a buy limited at 1.5 filled from the pool at 0.50.
  - **Uncross:** a bid at 0.9 filled from a pool that opened at 0.5.
  - **Stop through a pool:** a stop-loss a pool trade reached fired and sold into the pool.
  - **Restart:** a restarted node replayed 837 blocks.
  - **Agreement:** every node agreed on block hashes, exchange roots, pools, the book, balances
    and open orders.

## Defaults awaiting review

| Setting | Default | Where |
|---|---|---|
| Routing hubs | QRDX and the perps settlement asset | `ExchangeStateManager.routing_hubs` |
| Bisection steps for a split | 40 | `router.SPLIT_STEPS` |
| Crossed orders filled per block | 32 | `trading.SPOT_UNCROSS_ORDERS_PER_BLOCK` |

## A failed operation left a pool's price moved

Found while building this, and reproduced on the code before it. An operation is all or nothing:
a failure undoes everything it did. A pool's state was the exception. Its snapshot was restored
only if the failure came inside the step that moved the pool, so a failure after that step undid
every balance but left the pool at the swap's price. Its curve then no longer matched what its
holder held. Two cases:
- a `BATCH` whose swap succeeded and whose next action failed;
- a two-hop swap that missed its `min_amount_out`.

Anyone could move a pool's price for free with a batch built to fail, then trade against the moved
price at the liquidity providers' expense. The snapshot now belongs to the operation's undo
scope, so any failure puts the pool back.
