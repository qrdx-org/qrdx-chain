# Perpetuals Clearinghouse — design

Status: **Phases 1–5 done** (October 2026): zero-sum core, mark price, liquidations and the
backstop vault, funding, USD-stablecoin settlement and the validator price oracle. Replaces the
counterparty-less `PerpEngine` (see docs/KNOWN_ISSUES.md). Modelled on Hyperliquid. Code:
`qrdx/exchange/clearinghouse.py` (the engine), `qrdx/exchange/state_manager.py` (ops, oracle),
`qrdx/validator/price_feed.py` (what validators vote). Ops `PERP_DEPOSIT`, `PERP_WITHDRAW`,
`PERP_SET_LEVERAGE`, `PERP_ORDER`, `PERP_CANCEL`, `VAULT_DEPOSIT`, `VAULT_WITHDRAW`,
`ORACLE_VOTE` (the old house ops 7–10 are retired and refused). **Wallet / app access — REST,
JSON-RPC (`exchange_*`, `perp_*`), realtime streams, the `qrdx-wallet perp` CLI, the transaction
format and signing — is documented in [PERPS_API.md](PERPS_API.md).**

Decisions taken with the project owner:

| Question | Decision |
|---|---|
| Oracle (index) source | **Validator price votes** — stake-weighted median of prices validators observe on external exchanges |
| Liquidation backstop | **Treasury seed + user deposits** (HLP-style vault with shares) |
| Margin mode | **Both** — cross by default, isolated selectable per market |
| Collateral / settlement asset | **A USD stablecoin** (Hyperliquid's USDC model): the bridged stablecoin's QRC-20 token on mainnet; markets quoted in USD. Native QRDX remains a configuration for development and tests |

---

## 1. Why the old engine was wrong

`PerpEngine.open_position` recorded a position with nobody on the other side. Closing paid
margin + PnL into the owner's real balance and debited no one, so the engine was a "house"
with no balance: it minted QRDX on every winning trade and burned it on every losing one
(one 1 BTC long at 30,000: BTC to 33,000 created 3,000 QRDX; BTC to 27,000 destroyed 3,000).

## 2. The model

* Every perp trade is a **fill on an order book** between a buyer and a seller. Both accounts'
  positions change by equal and opposite amounts at the fill price, so in every market the
  sum of all position sizes is always zero.
* All perp collateral lives in **one clearinghouse holder** (`0xPERP…`). The collateral is the
  token named by `QRDX_PERP_COLLATERAL_TOKEN` — the USD stablecoin, held in the consensus QRC-20
  ledger — or native QRDX in `account_state` when that is set to `QRDX`; unset, deposits are
  refused. It moves only on `PERP_DEPOSIT` (trader → holder) and `PERP_WITHDRAW` (holder →
  trader). Vault deposits, trading, realized PnL, fees, funding and liquidations move value
  **between internal account records** — never in or out of the holder. A token deposit is
  always checked against the trader's token balance: the token flush is not gated, so an
  unchecked deposit would credit the holder while the debit could not land.
* Markets are quoted in `QRDX_PERP_QUOTE` (default `USD`): `BTC-USD-PERP`, priced by oracle pair
  `BTC:USD`. Prices, PnL, fees and funding are all in that unit — which validators can observe on
  any exchange.
* Realized PnL settles into the trader's collateral record against its own entry price.
  The counterparty's side of that value is its unrealized PnL, which it realizes later.

## 3. Invariants (tested on every phase)

1. **Real conservation.** No perp operation changes the sum of all `account_state` balances.
   Deposits and withdrawals are transfers between a trader and the holder.
2. **Matched exposure.** For every market, Σ signed position sizes = 0.
3. **Clearinghouse identity.** Let *H* be the holder's real balance, *C* the sum of every
   internal collateral record (cross collateral, isolated margins, vault, fee pool), and
   *s<sub>i</sub>*, *E<sub>i</sub>* each position's signed size and average entry price. Then
   **H = C − Σ s<sub>i</sub>·E<sub>i</sub>** at all times. (Because Σ s<sub>i</sub> = 0, the
   total unrealized PnL at any price X equals −Σ s<sub>i</sub>·E<sub>i</sub>: the identity says
   the holder holds exactly what all accounts are worth.)
4. **Determinism.** Everything is a function of the canonical chain: prices from on-chain
   votes and fills, time from block timestamps — never the wall clock.
5. **No withdrawal exceeds the holder.** Bad debt is absorbed internally (vault, then
   auto-deleveraging) so a withdrawal can never draw on value the holder does not have.

## 4. Prices

| Price | Definition | Used for |
|---|---|---|
| Trade | The order book's fill price | Entry, exit, realized PnL |
| Oracle (index) | Stake-weighted median of the validator committee's fresh price votes (§8). A configured reporter's `UPDATE_ORACLE` also sets it — development and tests only; production configures none | Funding notional and premium; mark price input |
| Impact bid / ask | Average price to sell / buy 1,000 QRDX of notional on the book (none if the book is shallower) | Funding premium |
| External perp | Stake-weighted median of the committee's votes for other venues' perp price (`"BTC:perp"`, §8); fresh for 120 s of block time | Mark price input |
| Mark | Median of: oracle + 150 s EMA(book mid − oracle); median(best bid, best ask, last trade); the external perp price while fresh, else the 30 s EMA of that book median — held within ±5 % of the oracle. With two inputs (no book), their mean | Margin, liquidation triggers, unrealized PnL |

Liquidations trigger on mark, not the last trade: a single large trade or a spoofed order on a
thin book cannot then liquidate everyone on the other side. The liquidation itself still
executes on the book.

**Block time, every block.** The EMAs are Hyperliquid's time-weighted form
(num ← num·e^(−dt/τ) + sample·dt, den likewise) with dt from block timestamps. They must
advance on *every* block, not only on blocks that carry exchange transactions, so the
exchange runs a per-block tick (`block_processor.run_exchange_tick`) on every path: the
proposer, the p2p / sync / REST importers, and both rebuilds. A quiet block still moves the
mark; skipping it would split nodes (pinned by `tests/test_clearinghouse_mark_price.py`).

**What a manipulator can do.** Hyperliquid's third mark input is the median of other venues'
perp prices. Validators vote it with their oracle prices (§8); while no vote is fresh, the 30 s
EMA of the book median stands in, and the ±5 % band is added on top either way. With the
external price, a squeeze of the local book moves the mark only at the pace of the 150 s premium
EMA: a book held 10 % over a flat oracle takes ~54 s to move the mark 3 % (~12 s through the
book EMA alone) and ~104 s to reach the band (~22 s) — time for arbitrage with the other venues
to close the gap. A deep book remains the first defence
(`tests/test_validator_oracle.py::test_the_external_price_slows_a_squeeze_of_the_local_book`).

**The book never crosses.** Self-trade prevention used to skip the sender's own resting
order and rest the remainder across it — a crossed book that moved the mid, and so the mark,
at no cost. Both consensus books (perps and the spot CLOB) now use `CANCEL_TAKER`: an order
that reaches its own resting order stops there and its remainder is cancelled; fills already
made against others stand, resting orders are untouched (so no escrow moves).

## 5. Margin

* Leverage and mode (cross / isolated) are set per account per market (`PERP_SET_LEVERAGE`).
* Initial margin = |size| × price / leverage. Maintenance margin = half the initial margin at the
  market's maximum leverage.
* Cross: one collateral record backs all cross positions; equity = collateral + Σ unrealized PnL
  at mark. Isolated: margin is moved from cross collateral into the position when it grows and
  released (with its PnL) when it shrinks; equity is per position.
* An order is accepted only if the account could carry both worst cases at initial margin: a
  full fill now, at its limit, and resting whole (the margin it reserves at its own price, and any
  it shifts onto the account's other orders).
* Resting orders reserve margin for the part that would open exposure. Per market, the position's
  size is closing capacity, used by the orders on the closing side in the order they would fill;
  a take-profit reserves nothing. Reduce-only orders never reserve.
* When a position changes, the account's resting orders there are re-checked: a reduce-only order
  that would now open is cancelled, and so are opening orders the account can no longer carry,
  the least likely to fill first. At match time, a maker whose fill would open exposure is
  cancelled instead if it is reduce-only or neither its reservation nor the free margin covers
  it (Hyperliquid's `reduceOnlyCanceled` / `marginCanceled`). Cancellations are reported in the
  order's receipt (`cancelled`) or, from the tick, as `order_cancelled` events.
* Withdrawals are limited to realized collateral that is not needed as margin.

## 6. Liquidations and the backstop vault (Phase 3)

Every block's tick, after the marks move, checks every account at mark — isolated positions one
by one, then each cross account as a whole — in owner order:

1. **Book first.** Below maintenance margin: cancel the account's resting orders (in that market
   only, for an isolated position) and send a reduce-only IOC for each position, limited to its
   **bankruptcy price** — the price at which closing it, taker fee included, leaves exactly zero.
   No book fill can therefore create bad debt; whatever margin is left stays with the trader.
   A position above 100,000 of notional is sent in **slices** (Hyperliquid): 20 % of it, then
   it cools down for 30 s of block time, during which only the backstop acts.
2. **Backstop.** Still below ⅔ of maintenance (or the book could not take it): the vault takes the
   positions over **at mark** together with the margin that backed them — all cross collateral
   for a cross account, only that position's margin for an isolated one (the trader's cross
   collateral is never touched). The leftover margin is the vault's compensation; a negative
   balance is the vault's loss.
3. **Auto-deleveraging.** If the vault cannot cover a negative balance, the account's positions
   are closed against the opposite side ranked by (mark/entry for longs, entry/mark for shorts) ×
   notional / account value — most profitable and most leveraged first — at prices that return the
   account to zero. The deficit is split across its positions by notional; the counterparties give
   up exactly that much unrealized profit. Prices round in the bankrupt account's favour, so it
   ends at zero or a hair above.

ADL closes counterparties at a worse price than mark, which can push one already checked under,
so passes repeat (at most four) until one changes nothing. Liquidation orders bypass the owner's
per-block rate limit and nonce sequence (`OrderBook.place_order(protocol=True)`): a liquidation
cannot fail because the account traded heavily that block. The vault is liquidated like any
account (book, then ADL) but never backstopped into itself.

**The vault unwinds what it takes over.** Every 30 s of block time per market (the first one 30 s
after the takeover, since the book had just failed to absorb it), it sends a slice of its
position — as for a liquidation — to the book as a reduce-only IOC at most 0.5 % through mark. It
never dumps through a thin book: an attempt that finds no bid or ask within the limit fills
nothing and waits for the next interval (`vault_unwind` events).

**The vault** is the margin account `@vault`. Trading fees accrue to it. `VAULT_DEPOSIT` moves free
collateral in for shares at NAV (collateral + unrealized PnL at mark); `VAULT_WITHDRAW` redeems at
NAV after a lockup of `QRDX_PERP_VAULT_LOCKUP_SECONDS` of block time (default 4 days, as
Hyperliquid's HLP), and never more than the vault can release while its positions still need
margin. Value that accrued before anyone held a share belongs to the protocol (`@protocol`), not
to the first depositor. **Treasury seed:** a deposit from an address in `QRDX_PERP_VAULT_SEEDERS`
mints protocol-owned shares that never unlock — the treasury multisig cannot sign exchange
transactions (they are PQ-only), so a designated PQ key seeds on its behalf. If the vault is
wiped out (shares outstanding, NAV ≤ 0), the old shares are written off and it reopens.

## 7. Funding (Phase 4)

Peer to peer, as Hyperliquid: every block samples the premium
(max(0, impact bid − oracle) − max(0, oracle − impact ask)) / oracle, weighted by the block time
it stood for. At each boundary of `QRDX_PERP_FUNDING_INTERVAL_SECONDS` of block time (default one
hour), F = average premium + clamp(0.01 % − premium, ±0.05 %) is the 8-hour rate and the
interval's share of it is paid, capped at 4 % per hour. Each position pays
size × oracle × rate — longs to shorts when positive; isolated positions from their own margin.
Each payment is rounded to wei and the vault takes the few wei left over, so the payments sum to
exactly zero. After a halt spanning several intervals, the interval the premium samples cover is
paid at its rate and each interval with no block in it at the interest-only rate (dYdX's rule: a
position held through a halt kept its exposure, and pays its carry). Funding runs before liquidations in the tick, so a payment that pushes an
account under is acted on in the same block. The legacy `PerpEngine` funding duty is removed.

## 8. The validator oracle (Phase 5)

Settled in USD, an oracle price is something every validator can observe (BTC/USD on any
exchange), so the chain takes it from them:

* **Committee.** The validator set in force at the block's parent
  (`qrdx/validator/epoch_state.py`, [STAKING.md](STAKING.md)): active and exiting validators,
  each weighted by its effective stake plus what is delegated to it. Every path sets it before
  every block, section and tick alike (`block_processor.ensure_oracle_committee`), so every node
  judges each block by the same committee. A pending validator votes once it activates; an
  ejected or exited one stops. It is not hashed into the state root, since it is a function of
  the chain, but the votes are.
* **Votes.** `ORACLE_VOTE {"prices": {"BTC": "65000.5", "BTC:perp": "65020", …}}`, signed like
  every exchange transaction, from a committee member, for existing markets only (1–64 prices).
  `"<base>"` keys are the oracle; `"<base>:perp"` keys are other venues' perp price, the mark's
  third input. A vote's nonce is its own sequence (the slot it was made in), not the account's
  exchange nonce, so voting never moves the validator's other transactions. Each validator votes
  from a background loop — on a price change, and at least every quarter of the vote lifetime —
  through the mempool, which keeps each voter's newest vote and gossips it like any exchange
  transaction; whoever proposes next includes it, votes first. Prices come from the feed
  (`QRDX_ORACLE_FEED`: `exchanges` = the median of public USD spot prices — and of USDT-margined
  perp prices on Binance, Bybit and OKX for the `:perp` keys — refreshed in the background;
  `file:<path>` = the testnet's scripted feed; `static:BTC=…,BTC:perp=…`). With more prices than a
  vote carries, successive votes rotate through them. A vote is an input like any transaction: a
  node whose feed fails simply does not vote.
* **Aggregation.** Every block, before the clearinghouse tick, each voted market's oracle becomes
  the stake-weighted (lower) median of the committee's votes no older than
  `QRDX_PERP_ORACLE_VOTE_MAX_AGE` (60 s of block time) — only if those votes carry a strict
  majority of the committee's stake. A minority cannot set the price at all, and within a
  majority the median ignores outliers. Expired votes are dropped. The `:perp` votes set each
  market's external perp price the same way.
* **Convictions.** A member convicted by slashing evidence on the chain below the block leaves the
  committee: its votes stop counting and the majority is of the rest
  (`chain_index.offenders_before`, refreshed before every section on every path).
* **Staleness.** A market whose oracle has not been set for `QRDX_PERP_ORACLE_STALE_SECONDS`
  (300 s) refuses orders that add exposure; reduce-only orders still work, and liquidations run.

**Known limits.** The median tolerates a minority of bad voters.

**Listing.** `CREATE_MARKET` burns `PERP_MARKET_LISTING_FEE` QRDX (a chain-spec parameter, 1,000 by
default) with the fee gate on: every market costs every node work in every block and a place in
the validators' votes, so listing one must not be nearly free. A market trades only once
validators price it.

## 9. Phases

| Phase | Scope | Exit criteria |
|---|---|---|
| **1. Zero-sum core** ✅ | Clearinghouse holder; deposit/withdraw; per-market order books; fills net into positions (increase / reduce / flip); realized PnL to collateral; cross + isolated margin; pre-trade and withdrawal margin checks; maker/taker fees to the vault; canonical state hashing, snapshot/revert; old house ops retired | Invariants 1–3 hold under randomized sequences; forward ≡ rebuild; soak — **met** (`tests/test_clearinghouse.py`, `test_perps_manager.py`, `test_reorg_rebuild_equivalence.py`; cross-node scenario s13: positions and balances identical on all nodes, holder keeps exactly the fees) |
| **2. Mark price** ✅ | Mark per §4 from oracle + book; per-block tick on every path; margin checks and PnL at mark; self-trade prevention that cannot cross the book | Manipulation bound tested; forward-with-ticks ≡ rebuild over quiet blocks — **met** (`tests/test_clearinghouse_mark_price.py`) |
| **3. Liquidations** ✅ | Book-first liquidation in the per-block tick; backstop vault (treasury seed + user shares); auto-deleveraging | No account ends negative; invariants hold through crashes; soak with forced liquidations — **met** (`tests/test_clearinghouse_liquidation.py`: each stage pinned to exact numbers; 16 randomized runs with crashes, spikes and thin books — with a funded vault and an empty one — keep the identity exact, net size zero and no account below −1e-6 after every block; forward ≡ rebuild with a liquidation inside a block's tick; cross-node scenario s19) |
| **4. Funding** ✅ | Interval boundaries of block time, premium + clamped interest, capped; peer-to-peer on oracle notional | Σ funding payments = 0 per market per interval — **met** (`tests/test_clearinghouse_funding.py`: exact zero-sum with uneven sizes, direction, clamp, cap, cadence, isolated margin; forward ≡ rebuild across several settlements) |
| **5. Stablecoin + validator oracle** ✅ | USD-stablecoin settlement (token deposits/withdrawals, USD markets); committee = the chain-derived validator set; signed `ORACLE_VOTE`s in blocks; stake-weighted median with a majority quorum per block; staleness halt; price feeds in validators; scripted feed for the testnet | Votes verified on import; median identical on all nodes; stale/absent votes handled — **met** (`tests/test_perps_stablecoin.py`: the stablecoin conserved end to end, QRDX untouched, refusals, forward ≡ rebuild with a liquidation; `tests/test_validator_oracle.py`: committee, admission, weighted median, quorum, expiry, departures, staleness, signed proposer votes, forward ≡ rebuild with the committee loaded at different heights; cross-node scenarios s13/s19 with prices set only by validator votes) |
