# The native exchange engine

The exchange (qrdx/exchange, about 28,000 lines of Python) runs every operation in Python. A
plain transfer now runs natively (docs/NATIVE.md, the transfer lane), but a spot order costs
185–210 µs (2026-11-05, `scripts/bench/exchange_block.py --workload orders`): at four blocks a
second, an order-heavy block fills its slot at about a fifth of the transfer rate. This page is
the plan for moving the exchange into Rust, and what is done.

## Principles

* **Python stays the reference.** Each native component computes exactly what the Python it
  replaces computes — results, state, events, errors, commitments — and is tested against it on
  random inputs, as every native piece is (docs/NATIVE.md). A node without the module, or with
  `QRDX_NATIVE=0`, runs Python and agrees byte for byte.
* **Refuse rather than guess.** What a native component would not reproduce exactly, it hands
  to Python whole (the operation, not half of it).
* **One owner per piece of state.** A collection is held either by Python or natively, never
  mirrored; the other side reaches it through an interface that marks, undoes and commits as
  the Python one did.
* **Consensus formats may change** while the testnet is regenerated (2026-11-05): a component
  may define its own commitment if Python computes the same one.

## Phases

| | Component | What it takes over | Status |
|---|---|---|---|
| E0 | Reference speed-ups | Sorted book sides (no sort per read), read-only token lookups, copy-free undo where nothing changes | done: orders 260–290 → 185–210 µs |
| E1 | Exact decimal (`src/dec.rs`) | Python's `Decimal` — add, subtract, multiply, divide, quantize, compare, `str` — under any context, every rounding | done: held to `decimal` on 116,000 random cases |
| E2 | Order book | Price levels, orders, matching (limit, market, iceberg, hidden, stop, expiry, self-trade), fees, trades, the book's digest and level tree, undo and snapshots | done: held to Python on 16,800 random operations; found a consensus bug (one price in two spellings) |
| E3a | Spot books held natively | Every spot pair's book is a native one behind the Python book's interface: the router, handlers, triggers, views, undo, snapshots and proofs run unchanged | done (2026-11-08): the exchange with native books is the exchange with Python's, block for block; found a snapshot bug (proof trees) |
| E3b | Spot settlement | Escrow, token and QRDX moves, fees, the journal's fills: a run of plain limit orders and cancels executed natively end to end | done (2026-11-08): 210 → 72 µs an order on a block's path |
| E4 | Ledger | Token balances and nonces held natively, the database written behind the block | |
| E5 | Router and pools | Unified liquidity (`plan_fill`): the AMM's tick math and the book together | done (2026-11-08): orders that reach a pool and swaps (hub routing too) run natively; 240 → 113 µs an order, 331 → 155 with swaps |
| E6 | Perps | The clearinghouse: margin, funding, liquidation | |

Each phase is wired in only when its differential tests hold, and measured live.

## E2: the order book

The book (`qrdx/exchange/orderbook.py`) is reached from more than its methods. The router
plans unified fills by reading levels and their queues (`level_prices`, `fill_queue`,
`_orders`); the spot handler executes a plan maker by maker (`fill_resting`) and reads and sets
order fields; the views read levels; undo scopes record levels and orders the first time they
change; snapshots deep-copy books every block. So the native book keeps that interface:

* the book's state in Rust: each side an ordered map of price to level, a level's orders in
  time order, the order index, stop orders, owner counts and nonces, the trade sequence;
* `Order` objects for Python that read and write the native order, so the router and the
  handlers run unchanged;
* undo: the first change to a level or order in a scope is recorded natively, and the scope's
  restore puts it back;
* copies: the state is persistent (structurally shared), so a snapshot is a pointer copy;
* the digest and level tree computed natively from the same payloads (`_level_payload`).

Its test drives a Python book and a native book with the same random operations — limit and
market orders, icebergs, hidden and stop orders, expiries, self-trades, cancels, reductions,
fills by plan, undone scopes, snapshots — and compares every trade, order, level, error and
digest.

### Where E2 stands (2026-11-05)

`src/book.rs` (`NativeBook`) is the Python book, operation for operation: the same trades, the
order as it ended, the same refusals word for word, every level's queue, the totals and the
digest, after each of 16,800 random operations (`tests/test_native_book.py`; a fee rate changed
by one basis point is caught). Its state is persistent, so a copy and a failed placement's
rollback are pointer copies. Porting it found a consensus bug in the Python book, now fixed
(docs/KNOWN_ISSUES.md: one price written two ways).

It was not wired into the node then (E3a wired it in), and on its own it would not make the
exchange faster:

* matching is about 11 µs of a spot order's ~190 in Python; the rest is the operation around
  it (settlement, fees, undo bookkeeping, the journal), which is E3;
* through its test interface (an order as a dict of 16 fields, in and out) it costs 10 µs a
  resting order to Python's 11, and 32 µs an order that fills. Most of that is the conversion
  and the per-level sums Python's book does too. Its decimals keep a 128-bit coefficient while a
  value fits (`dec.rs`), and its ids, owners and orders are shared, so the savepoint every
  operation takes costs reference counts, not copies;
* its full digest is twice as fast as Python's (11 ms to 23 at 10,600 resting orders).

## E3a: the spot books held natively (2026-11-08)

Every spot pair's book is now a native one (`qrdx/exchange/native_book.py`, `NativeSpotBook`),
wherever the module is present; `QRDX_NATIVE_BOOK=0` (or `QRDX_NATIVE=0`) keeps Python's. It
puts the Python book's interface over `NativeBook`, so nothing that reaches a book changed:

* **Orders handed out** (`get_order`, `_orders`, a level's queue, `cancel_order`…) are `Order`
  objects kept current: each native call reports the orders it changed and the objects handed
  out are updated in place. A placed order is the object its caller passed.
* **Trades handed out** write the fees settlement charges on them back into the book's display
  history, as a Python book's trade objects are its history's own (the history is never
  committed, but the two kinds of book show the same).
* **Views** (`_orders`, `_stop_orders`, `_bids`, `_asks`, `_owner_order_count`) are read-only
  mappings over the native state.
* **Undo**: an operation's first change records the native state (a pointer copy) and a failed
  scope puts it back. A failed native call changes nothing and records nothing.
* **Nonces** stay a Python committed dict, so they stay provable as before; the digest composes
  the native header and levels with their commitment.
* **Snapshots and checkpoints**: a copy is a pointer copy; a pickle is the book's data
  (`export`), which a node without native books loads as the same Python book, and a Python
  book restored on a node with them becomes native (`as_spot_book`). A perps book stays Python:
  it runs a Python callback inside matching (`maker_guard`), which a native book refuses.

Tests: `tests/test_native_book.py` drives both kinds of book through the Python interface (four
self-trade rules, 10,000 random operations, failed scopes, copies, pickles loaded both ways, the
per-block limit across a conversion) and compares every result, view, digest, level tree and
handed-out order. `tests/test_native_spot_equivalence.py` runs the same spot traffic through
`process_transaction` with each kind (orders of every type and time in force, cancels,
modifications, swaps across book and pool, each block's uncross and triggers) and compares every
result, tick event, root, balance change and book history, block by block, including across a checkpoint
written with one kind and loaded with the other. Changing the self-trade rule or the per-owner
cap of the native books only is caught. The full suite passes in both modes.

Porting found a pre-existing bug: a published snapshot of a network with proof trees could not be
loaded (docs/KNOWN_ISSUES.md).

It is not faster yet: a spot order costs 241 µs with native books against 203 with Python's
(`scripts/bench/exchange_block.py --workload orders`). Matching is a small part of an order; the
rest is the Python around it, which now also converts each order it hands across. That is E3b.

## E3b: plain orders natively, end to end (2026-11-08)

A block's runs of plain spot limit orders and cancels run in Rust over the native books
(`native/qrdx-native/src/order_lane.rs`, `qrdx/exchange/order_lane.py`; docs/NATIVE.md). What
an operation does is Python's `process_transaction` around `_op_place_order` /
`_op_cancel_order`, step for step: the nonce; then all or nothing — the block's start for the
book, the balance check, matching, each fill's settlement (base and quote moved, each side's fee
by its tier, staking discount and referral, the referrer's reward, the stakers' part, the
treasury's), the trades' fees into the book's history, the remainder into the escrow, or a
cancelled order's escrow back; on a pair quoted in the perps' settlement asset, each fill's
notional toward both sides' fee tiers, lifetime volume and referral volume (`_record_volume`:
the fee tier and the referee's discount move with it mid-run); then the gas and the
reservation's rest. Errors are Python's, word for word.

Python keeps what decides anything else, once a transaction or once a run: parsing and its
checks (`prepare`; the same checks let the section be judged natively, with plain transfers),
and per pair where its pools start to fill, where its waiting triggers fire (the lowest price a
rising one waits for, the highest a falling one waits for), which orders have brackets, paused
tokens, freezing tokens' senders, each sender's payer, each trader's fee inputs (staking
discount, volume by day, referral). The run
stops before the first operation it would not reproduce exactly; Python runs that one and the
run goes on. The ledger stays Python's: entries are read from its dicts when first needed and
written back through them with the same undo records, keys entering in the same order.

What is still Python's: fills that reach a waiting trigger's price (they mark it) or a bracketed
order, trigger orders, brackets, builder fees, modifications, an agent's or a multisig's
signature, the free lane, a book with stop orders. (Orders that reach a pool, market orders and
swaps run natively since E5, below.)

Tests: `tests/test_order_lane.py` runs random blocks both ways — plain orders in every time in
force (hidden, iceberg, too large, too small, from an account whose balance was not loaded) and
cancels (one's own, another's, unknown), on a pair with pool liquidity, two with triggers waiting
near the price, one quoted in QRDX (on half the seeds the settlement asset), among what only
Python runs; traders with fee tiers (one crossing a floor mid-run, with a day past the window),
a negative maker rate, staking discounts, referrals capped, uncapped and crossing the cap — and
compares every result and field, nonce,
delta and balance (with the order keys entered), the fees, staker fees and fee tokens, the books
and their history, the root, and takes every block back out by its undo record; and judges
random sections with refusals both ways. Breaking it is caught: a referrer's reward not paid, a
move's two sides recorded in the other order, a negative maker rate not floored, the history's
fees not written, the write-back reordered or missing a dict, the volume not recorded, a
trigger's price ignored, the staking discount ignored, old volume days kept.

Measured (`scripts/bench/exchange_block.py --workload orders`, a block's section as a node runs
it — judged, run, its root — 500 operations a block, 30% cancels, 30% crossing, 40% resting):

| | µs an operation |
|---|---:|
| Python's books | 210 |
| native books, through the Python interface (E3a) | 260 |
| native books and the order lane | 72 |

Of the 72: the native run about 25 (matching, settlement, reading Python's dicts, building the
results), Python's preparation about 12 plus hashing each new transaction for its order id (a
node has hashed it on admission already), and the rest the section's judgment, its fee
reservations and the exchange root.

## E5: pools and the router natively (2026-11-08)

`native/qrdx-native/src/router.rs` is the pools' swap math and the router's walk of a pair's
combined market, step for step: `ConcentratedLiquidityPool.quote` (partial, continuing a plan),
`_swap_step` / `_swap_step_out` and the amount and √price functions under their own rounding
contexts (ceiling, floor, half-even), `liquid_sqrt`, `SwapPlan.then`, and `Router.plan_fill`
(the book maker by maker, the pools at one price moving together, a split by bisection, the
rest to the deepest pool, self-trade, budget and dust stops), exact-out for an order and
exact-in for a swap. Three values are Python's own, asked for: the tick at a √price (a
logarithm), a limit's square root, a pool's end price (a power) — exactly what Python computes,
rather than a port of `decimal`'s transcendental functions. Values keep Python's spelling where
it travels on (`min` takes the first of equal values, sorts are stable).

The order lane uses it for limit and market orders that reach a pool — each pool's leg applied
and paid (taker into the pool's holder, the pool out to the taker), the book matching the rest,
the pair's last price from fills and pools together, `_flag_self_pass` — and for swaps: the
pair, or two hops through a routing hub when that pays more (`choose_swap_path`), each hop
planned within the gas and executed (the book's leg as the router's immediate-or-cancel order,
its id from the router's sequence, which a failed swap does not take back, as Python's does
not). Each stretch hands the native run every candidate pool with its initialized ticks (read
unmarked); the plans applied come back and Python applies them with the pool's own `apply`
(its oracle observation, the crossed ticks' fee growth), after keeping the pool for the undo
scope as `_atomic` does.

Tests: `tests/test_order_lane.py` now trades on two pools of one pair (two fee tiers, five
positions, so fills cross ticks and split between pools), a pair with liquidity only above its
price, and hub pairs (A:QRDX, USD:QRDX) through which a swap may go; market orders, swaps with
minimums, deadlines, amounts too large and too small, tight gas. Over four seeds: 252 orders
filled by pools natively (43 split between two), 118 plans crossing ticks, 186 swaps (33 through
QRDX), each identical to Python. Breaking it is caught: one bisection step fewer, a pool fee
rounded half-even, the deepest pool reversed, self-trade ignored, the LP fee growth rounded
half-even, the pool's price not recorded, the self-pass not flagged, pools beyond the first not
charged, the exact-in bound not rounded down, the router's sequence taken back on failure, the
first path taken instead of the best.

Measured (`scripts/bench/exchange_block.py --workload orders`, a block's section, µs an
operation):

| | Python's books | native books and lanes |
|---|---:|---:|
| orders, the pool without liquidity | 204 | 75 |
| orders, `--liquidity` (crossing orders reach the pool) | 240 | 113 |
| orders and swaps, `--liquidity --swaps 0.3` | 331 | 155 |

## What remains outside the engine

* **A binary transaction format** (a fork): a transfer is about 10.5 KB of hex JSON. Binary
  halves it, and a key named by its address (the registry the chain already has) saves 1.95 KB
  more. Every block hashes, stores and relays less.
* **Execution deferred a second block** (a fork): the next proposer would not wait for its
  parent's run either; the inclusion rule then needs a fee reserve.
