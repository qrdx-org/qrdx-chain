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
| E2 | Order book | Price levels, orders, matching (limit, market, iceberg, hidden, stop, expiry, self-trade), fees, trades, the book's digest and level tree, undo and snapshots | core done, not wired: held to Python on 16,800 random operations; found a consensus bug (one price in two spellings) |
| E3 | Spot settlement | Escrow, token and QRDX moves, fees, the journal's fills: a plain limit order or cancel run natively end to end | |
| E4 | Ledger | Token balances and nonces held natively, the database written behind the block | |
| E5 | Router and pools | Unified liquidity (`plan_fill`): the AMM's tick math and the book together | |
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

It is not wired into the node, and on its own it would not make the exchange faster:

* matching is about 11 µs of a spot order's ~190 in Python; the rest is the operation around
  it (settlement, fees, undo bookkeeping, the journal), which is E3;
* through its test interface (an order as a dict of 16 fields, in and out) it costs 20 µs an
  order to Python's 11. Its decimals allocate every coefficient (`num-bigint`), where Python's
  C `decimal` is fast on small values. The next step is a fast path in `dec.rs` — a 128-bit
  coefficient while a value fits, big integers beyond — held to the same tests;
* its full digest is twice as fast as Python's (11 ms to 23 at 10,600 resting orders).

The book becomes the node's when E3 runs a plain limit order or cancel natively end to end, with
the book behind the same interface the router and handlers use.

## What remains outside the engine

* **A binary transaction format** (a fork): a transfer is about 10.5 KB of hex JSON. Binary
  halves it, and a key named by its address (the registry the chain already has) saves 1.95 KB
  more. Every block hashes, stores and relays less.
* **Execution deferred a second block** (a fork): the next proposer would not wait for its
  parent's run either; the inclusion rule then needs a fee reserve.
