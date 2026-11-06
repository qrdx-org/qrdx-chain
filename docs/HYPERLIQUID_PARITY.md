# Hyperliquid parity — the protocol features added to match it

The protocol features Hyperliquid has that QRDX lacked after the trading set
(docs/TRADING_FEATURES.md) and the consensus roadmap (docs/CONSENSUS_ROADMAP.md). Each is
consensus state or a consensus rule:
- executed identically by every node;
- committed in the state root and provable (docs/STATE_PROOFS.md);
- replayed on every path: proposer, importers, and both rebuilds.

Nothing here lives only in a node's memory.

| # | Feature (Hyperliquid's name) | Status | Code · tests |
|---|---|---|---|
| 1 | Action expiry (`expiresAfter`) | built | `ExchangeTransaction.expires_at` · `test_trading_controls.py` |
| 2 | Isolated margin added and removed (`updateIsolatedMargin`) | built | `PERP_ISOLATED_MARGIN` · `test_trading_controls.py` |
| 3 | Dead man's switch (`scheduleCancel`) | built | `SCHEDULE_CANCEL` · `test_trading_controls.py` |
| 4 | Builder codes (`approveBuilderFee`, an order's `builder`) | built | `APPROVE_BUILDER_FEE` · `test_trading_controls.py`, `test_spot_fees.py` |
| 5 | Order grid (`szDecimals`, 5 significant figures, minimum order value) | built | `Clearinghouse._check_grid` · `test_order_grid.py` |
| 6 | Staking fee discounts | built | `Clearinghouse.stake_discount` · `test_stake_fee_discount.py` |
| 7 | EVM ↔ exchange (HyperEVM read precompiles, CoreWriter) | built | `contracts/exchange_evm.py` · `test_evm_exchange.py` |
| 8 | Where perp markets come from: genesis majors, governance listings (HIP-3's deployer markets: **not adopted**) | built | `PERP_GENESIS_MARKETS`, `list_market` · `test_perp_markets.py` |
| 9 | Leverage per trade, per market (`updateLeverage` in the order ticket) | built | an order's `leverage` / `margin_mode` · `test_perps_listing_and_leverage.py` |
| 10 | Perps settings no outside actor chooses | built | `list_market`, `PERP_MARKET_MAX_LEVERAGE` · `test_perps_listing_and_leverage.py` |
| 11 | Unique tickers by Dutch auction (HIP-1's deploy auction) | built | `TICKER_CLAIM` · `test_tickers.py` |
| 12 | Big blocks (HyperEVM's two block sizes) | built | `BIG_BLOCK_*`, `block_limits.evm_gas_limit_at` · `test_big_blocks.py` |
| 13 | Token perps: any on-chain token's perp, by its address, priced off its own spot market | built | `CREATE_MARKET {token}`, `spot_reading`, `update_spot_oracles` · `test_token_perps.py`, `test_token_perps_adversarial.py` |
| — | Batch auctions (frequent batch auctions) | **skipped** | the decision of 2026-10-22 |

A network needs a fresh genesis for the new operations and state. Every default below is a
chain-spec parameter or a module constant and **awaits review** before mainnet
(docs/KNOWN_ISSUES.md, "Defaults awaiting review").

Where this differs from Hyperliquid:
- **A stop-market that finds nothing within 10 % waits.** On Hyperliquid it is cancelled. Here
  the unfilled part waits and fires again at later ticks, so a stop the price gapped past still
  executes once the market comes back (the user's choice, 2026-10-27;
  docs/UNIFIED_SPOT_LIQUIDITY.md 5).
- **Big blocks** run inline with the 250 ms slots, not on a clock of their own as HyperEVM's
  do. A big block's slowest possible work is about 1.8 s of execution (section 12).
- **No deployer markets.** A HIP-3 deployer sets its own markets' oracle. Here no single key
  prices any market: the validators' stake-weighted votes price the markets of off-chain
  assets, and a token perp's own spot market prices it (sections 8 and 13). Deployer markets
  were built and then removed (2026-10-26), as was `UPDATE_ORACLE`, a configured reporter's
  price.

---

## 1. Action expiry

Any exchange transaction may carry `expires_at`, a block time in seconds. A block whose time is
past it cannot include the transaction: it is refused before its nonce or any gas, as if it had
never been sent. A wallet signs an order valid for the next few seconds, and it can never fill
later at a stale price. A malformed value is refused at admission.

## 2. Isolated margin added and removed

`PERP_ISOLATED_MARGIN {market_id, amount}` moves collateral into an isolated position's margin
(a negative `amount` takes it out). A removal must leave the position at its initial margin.
Only an isolated position takes margin. An agent may sign it: the value moves only within the
account.

## 3. Dead man's switch

`SCHEDULE_CANCEL {time}` cancels every order, trigger and TWAP of the account at that block time.
Sending it without `time` clears the switch.

When it fires: in the block's tick, before triggers and TWAPs.

Limits:
- `time` is at least `CANCEL_MIN_DELAY` (5 s) ahead;
- it fires at most `CANCEL_TRIGGERS_PER_DAY` (10) times per account per block day;
- at most `CANCELS_PER_BLOCK` (50) accounts fire per block; the rest fire in the next block.

State: `trading.cancel_at`, plus a derived index of the armed switches (never committed).

## 4. Builder codes

`APPROVE_BUILDER_FEE {builder, max_fee_rate}` lets a front-end charge up to that rate on orders
it routes (`0` revokes). Only the account itself signs it; an agent cannot.

An order carries `builder: {b, f}`. The builder earns rate `f` of the notional of the fills the
order *takes*:
- **Perps:** paid out of the taker's free margin, into the builder's margin account.
- **Spot:** paid out of what the taker received, in that asset. A spot order with an attached
  take-profit or stop-loss cannot carry a builder.

Caps:

| Market | Cap | Constant |
|---|---|---|
| Perps | 0.1 % | `BUILDER_FEE_MAX_PERP` |
| Spot | 1 % | `BUILDER_FEE_MAX_SPOT` |

An order above its approval, or above the cap, is refused. State: `trading.builder_approvals`.

## 5. Order grid

A market lists sizes in whole lots of `sz_decimals` decimals.
- Default: `PERP_DEFAULT_SZ_DECIMALS` (4). `CREATE_MARKET {sz_decimals}` sets it per market;
  -1 means no grid.
- Prices have at most `PRICE_SIG_FIGS` (5) significant figures and `6 − sz_decimals` decimals.
  An integer price always fits.
- An order that is not reduce-only is worth at least `PERP_MIN_ORDER_VALUE` (10).

The grid is checked wherever a user's order enters a book: orders, triggers, and both kinds of
modify.

## 6. Staking fee discounts

An account's QRDX at stake earns a discount on its perps and spot trading fees. Its stake is its
own validator principal plus its delegations at their pool's price, read from the validator set
at the block's parent (`epoch_state.stakes_for_block`, set each block by every path).

| Staked QRDX | Discount |
|---|---|
| 10 | 5 % |
| 100 | 10 % |
| 1,000 | 15 % |
| 10,000 | 20 % |
| 100,000 | 30 % |
| 500,000 | 40 % |

These are `STAKE_FEE_DISCOUNTS`. A maker rebate is kept whole.

---

## 7. EVM ↔ exchange

Contracts reach the exchange the way HyperEVM contracts reach HyperCore
(`qrdx/contracts/exchange_evm.py`).

### Reading: `0x…0400`

A contract reads live exchange state as of its point in the block. Every node reads the same
state, because the EVM section runs after the exchange's.

```solidity
function markPrice(string market) returns (uint256 price1e18)
function oraclePrice(string market) returns (uint256 price1e18)
function position(address account, string market)
    returns (int256 size1e18, uint256 entry1e18, uint256 isolatedMargin1e18)
function positionOf(string account, string market) returns (int256, uint256, uint256)  // 0xPQ…
function perpAccount(address account) returns (int256 equity1e18, uint256 withdrawable1e18)
function resolve(string name) returns (address)   // QNS; 0 if it resolves nowhere
```

A read costs 5,000 gas. An unknown selector or malformed input reverts. A native token's balance
is read through the token's own ERC-20 precompile (docs/NATIVE_TOKENS.md).

### Writing: `0x…0401`

This is Hyperliquid's CoreWriter.

```solidity
function sendAction(string actionJson)  // {"op": "PERP_ORDER", "params": {...}, "gas": n}
```

The action runs **as the contract's own exchange account**, keyed by its address as `0x` plus 40
lowercase hex. Allowed operations:
- trading: perps and spot orders, cancels, modifies, triggers, leverage, isolated margin,
  cancel-all, the dead man's switch, swaps;
- margin: deposits and withdrawals;
- user vaults and staking delegation;
- deploying a market (section 8).

Anything else reverts: token administration, governance, account control, oracle votes. So does
a malformed action, which is checked when the action is sent.

**Lifecycle.**
1. The action is journaled with the call, so a revert anywhere above it drops it.
2. It is queued in the exchange's committed state (`trading.evm_actions`) when the block's EVM
   section is accepted.
3. It runs at the **start of the next block's exchange processing**, before that block's own
   transactions, on every path. That includes a block without exchange transactions: the tick
   runs the queue.

**Execution.**
- It is authorized by the EVM execution that sent it: no signature, no nonce, and no exchange
  fee, because its gas was paid in the EVM.
- It runs all or nothing. A failing action changes nothing and leaves the queue.
- At most `EVM_ACTIONS_PER_BLOCK` (256) run per block; the rest run in the next.
- Each has a hash derived from its place in the queue, so two identical actions place two
  orders.
- Its receipt, fills and order history go to the node's journal under that hash.
- The contract's QRDX and token balances are preloaded like a sender's, so a deposit is judged
  against what the contract holds.

**Gas.** `gas` is the action's exchange gas limit, like a signed transaction's.
- Default: the operation's base gas. Maximum: `MAX_ACTION_GAS` (2,000,000).
- It bounds the action's work: an order visits only the resting orders its gas pays for.
- The call pays `WRITE_GAS` (25,000) plus one EVM gas per `EXCHANGE_GAS_PER_EVM_GAS` (10)
  exchange gas, so a block's EVM gas queues at most about half a block's exchange budget.

A static call cannot send an action. Neither can a DELEGATECALL or CALLCODE: a DELEGATECALL keeps
its caller's `msg.sender`, so through one any contract a victim called could otherwise trade or
withdraw the victim's exchange account (the native token and NFT precompiles refuse them for the
same reason). Only a plain CALL acts, as the calling contract. The precompiles take no QRDX.

---

## 8. Where perp markets come from

Three kinds of market, and no other way to make one:

| Market | Made by | Priced by | Named |
|---|---|---|---|
| The genesis majors | the chain spec: `PERP_GENESIS_MARKETS`, made by the first block | the validators' votes | `BTC-USD-PERP` |
| Any other off-chain asset | governance: `list_market {base_token, max_leverage?, sz_decimals?}` | the validators' votes | `AVAX-USD-PERP` |
| An on-chain token | anyone: `CREATE_MARKET {token, liquidity, …}` (section 13) | its own spot market | `0x…-USD-PERP`, by the token's address |

**The genesis majors** are Hyperliquid's settings for each (`BASE:MAX_LEVERAGE:SZ_DECIMALS`):

| Market | Maximum leverage | Size decimals |
|---|---|---|
| BTC | 40 | 5 |
| ETH | 25 | 4 |
| SOL | 20 | 2 |

Every block path (the proposer, the importers, both rebuilds) runs the same block function, which
makes any genesis market not yet there before the block's transactions. So a node rebuilding from
genesis makes them where the network did. A market is never removed: a delisted one stays,
settled, and is not made again. Their bases are reserved tickers (section 11), so no token can
call itself BTC.

**A validator-priced base** is an off-chain asset's symbol: a letter, then up to 15 letters and
digits. It is never `QRDX` or an address: a perp on anything on chain is a token perp, and its
price comes from the chain itself.

**No one else prices a market.** The only operation that sets a validator-priced market's price
is `ORACLE_VOTE`, aggregated by stake (a majority, at least `ORACLE_MIN_VOTERS`, at most
`ORACLE_MAX_STEP_BPS` a second). Operations 11 (`UPDATE_ORACLE`) and 79–82 (the deployer
markets') are retired: a transaction naming one does not decode.

---

## 9. Leverage per trade

Every market's position has its own leverage and margin mode, and each trade can set them:
`PERP_ORDER`, `PERP_TRIGGER` and a perps `TWAP_ORDER` take

| Param | Meaning |
|---|---|
| `leverage` | 1 to the market's maximum |
| `margin_mode` | `cross` or `isolated` |

The market's setting for the account becomes them **inside the operation**, as
`PERP_SET_LEVERAGE` would make it: if the order is refused, the setting stays as it was. Without
them, the market's current setting applies. A TWAP's slices trade at it; a trigger fires at the
market's setting then. The CLI takes `--leverage` and `--margin-mode`.

- **Positions:** BTC at 20× cross and ETH at 3× isolated in one account are independent. Each
  cross position's initial margin is at its own market's leverage.
- **Orders:** a resting order keeps the leverage it was placed at. Its reservation, and the
  margin it moves into an isolated position when it fills, use it. A modify keeps it.
- **An open isolated position** may change leverage. Raising it moves nothing (take margin out
  with `PERP_ISOLATED_MARGIN`). Lowering it needs the position to hold its initial margin at the
  new leverage: what it lacks moves in from free cross margin, and the change is refused if there
  is not enough. `PERP_SET_LEVERAGE` returns `margin_moved`.
- **The margin mode** changes only with no position or order in the market.
- Two positions in one market at different leverage are two accounts: sub-accounts
  (docs/TRADING_FEATURES.md).

## 10. Perps settings no outside actor chooses

Who may change what:

| Setting | Who changes it |
|---|---|
| An account's leverage, mode, orders, margin, withdrawals | the account; its controllers; an agent it approved (trading only, within its limits); a sub-account's master; a vault's leader (trading only) |
| A validator-priced market's existence and settings (name, maximum leverage, grid) | governance: `list_market` |
| A validator-priced market's oracle | the validators: a stake majority, at most `ORACLE_MAX_STEP_BPS` a second |
| Delisting a validator-priced market | governance: `delist_market` |
| A token perp's oracle | no one: its token's spot market, read the same by every node (section 13) |
| Listing a token perp | anyone, once per token, while the token has a spot market deep enough |
| Fee rates, margin tiers, funding caps, the price band, the circuit breaker | the protocol (chain-spec parameters and code): only a fork changes them, and governance approves it |

What changed to make it so:
- **Listing by governance.** Whoever listed a validator-priced market chose its maximum leverage
  and its grid, and took its name for good. Anyone could squat `ETH-USD-PERP` with settings that
  made it unusable or unsafe. The governance action `list_market {base_token, max_leverage,
  sz_decimals}` lists them now, after the genesis majors (section 8). `CREATE_MARKET` lists
  only token perps (section 13).
- **A bounded maximum leverage.** A market's maintenance margin is half its initial margin at
  maximum leverage, and there was no upper bound: a 10,000× market would liquidate far too late,
  and the shared backstop would pay. `PERP_MARKET_MAX_LEVERAGE` (50) bounds it.
- **Vault shares at everything the vault holds.** A user vault's shares were priced at its cross
  equity, which leaves out isolated positions. A leader could move margin into one to lower the
  price, join cheaply, and take it out again at the other holders' expense. Shares are now priced
  at `Clearinghouse.total_equity`, cross and isolated together; so are the market liquidity
  vaults' quotes and open-interest caps.
- **No reused order ids.** An order id already live in a market is refused. Ids are
  transaction hashes, so this needs a collision, but two live orders sharing an id would share
  metadata.
- **No reporter.** `UPDATE_ORACLE`, a configured reporter's price, is retired: one key could
  move every market it reported.
- **Contracts act only as themselves** (section 7).

---

## 11. Unique tickers

Anyone may deploy a token called USDC, so a symbol alone proves nothing. A **ticker** is unique:
one token holds it, for good. Hyperliquid sells spot tickers in a gas auction (HIP-1); here:

- `TICKER_CLAIM {token_address, max_price?}`. The token's creator buys its symbol, upper-cased,
  as its ticker: 1 to 12 letters and digits. The price is the ticker auction's, burned.
  `max_price` guards against the price moving before the block.
- **The auction** is one continuous Dutch auction:

  | Phase | Price |
  |---|---|
  | Before the first sale | `TICKER_OPENING_PRICE` (250 QRDX, ~$100,000) |
  | Right after a sale at P | 2 × P, opening the next auction |
  | Then | falls linearly to `TICKER_MIN_PRICE` (25 QRDX, ~$10,000) over `TICKER_AUCTION_SECONDS` (31 h) |

  Every node prices it at the block's time.
- **Reserved:** `QRDX`, the perps quote (`USD`), the genesis markets' bases (`BTC`, `ETH`,
  `SOL`) and every bridged asset's symbol. A bridged
  token takes its own ticker when the bridge creates it, so the bridged USDC holds `USDC`.
- **A ticker's token keeps its symbol.** Its metadata authority may rename it, but not change
  its symbol to another one: the ticker and the symbol always agree.
- **State:** `trading.tickers` (TICKER → token) and `trading.ticker_auction` (the last sale),
  committed and provable.
- **API:** `exchange_getTicker(ticker)`, `exchange_getTickerAuction()`; `exchange_getTokens` /
  `getToken` and market data show each token's `ticker`.

## 12. Big blocks

HyperEVM has small fast blocks and a big block a minute, for what does not fit the small ones:
contract deployments, above all. The same here. Every `BIG_BLOCK_INTERVAL`-th block (240: once a
minute at 250 ms slots), by height, may carry `BIG_BLOCK_GAS_LIMIT` (3,000,000) of EVM gas
instead of `BLOCK_GAS_LIMIT` (1,000,000). A contract typically needs 0.6–1.2M gas to deploy, so
the larger ones did not fit any block before.

- **Admission:** a transaction may declare up to the big limit. One above the ordinary limit
  waits for a big block, and the proposer fills each block to its own limit.
- **Validity:** every import path checks the section against the limit at its height. The EVM's
  GASLIMIT opcode reads the block's own limit. `eth_call` and gas estimation may use the big
  limit.
- **Fees:** big blocks are priced on an EVM fee track of their own. A big block's base fee is set
  by the big block before it, an ordinary block's by the ordinary block before it, so neither
  kind moves the other's price. The big track moves up to 1/2 per big block, not 1/8: twenty
  full big blocks (twenty minutes) multiply its price about 3,300 times.
- **The cost:** blocks execute inline with the slot clock. A big block of the EVM's slowest work
  (~1.7 Mgas/s) takes about 1.8 s, so blocks come more slowly for a moment once a minute, as a
  full ordinary block does for 0.6 s. Its price makes doing that on purpose expensive within
  minutes. `BIG_BLOCK_INTERVAL` 0 turns big blocks off.

## 13. Token perps

A perp on an on-chain token: a native token (one bridged in included) or QRDX itself. No
validator votes its price, since it has no price outside this chain. The market reads the
token's own spot market instead, and nothing else can move its oracle.

**Listing.** Anyone lists one with `CREATE_MARKET {token, liquidity, max_leverage?,
sz_decimals?, liquidity_profit_share?}`:
- `token` is the token's **address** ("QRDX" for QRDX). A symbol is refused, since anyone can
  deploy a token with any symbol. The market id is `<address>-USD-PERP`, and the market shows
  the token's ticker if it holds one (section 11). No ticker is needed.
- One market per token.
- The token needs a spot market to read: a path of pools to the settlement asset, each with
  `SPOT_ORACLE_TWAP_SECONDS` of price history, and `SPOT_ORACLE_MIN_DEPTH` of depth.
- The maximum leverage is at most, and by default, `PERP_SPOT_MAX_LEVERAGE` (10).
- As for any listing: the listing fee is burned, and `liquidity` seeds the market's liquidity
  vault (docs/TRADING_FEATURES.md §14).
- Not the settlement asset itself: settling in QRDX, QRDX has no price in itself.
- A contract may list one through the write precompile (section 7).

**The path.** No one chooses the pools, not even the lister. Each block, the market reads every
path from the token to the settlement asset: a pool between the two, or two through QRDX. It
takes the deepest path that has a price.
- A new pool counts only once it has a TWAP's history.
- Outweighing the others takes real capital, held near the price for as long as it should count.
- So a perp listed while its token traded thinly follows the token to deeper pools. A squatter
  cannot pin it to a pool of its own.

The path last read is shown as `spot_pools`.

**The oracle**, each block before the clearinghouse's tick (`update_spot_oracles`):
- **Price:** the geometric-mean TWAP over `SPOT_ORACLE_TWAP_SECONDS` (600), multiplied hop by
  hop into the settlement asset. Pools keep checkpoints of their tick cumulatives 15 seconds
  apart, so the TWAP is exact over its span, and a swap cannot move it within a block. It moves
  at most `ORACLE_MAX_STEP_BPS` a second, as the validators' does.
- **Depth** is what moving each pool's price `SPOT_ORACLE_DEPTH_BAND_BPS` (2 %) up or down
  takes (`ConcentratedLiquidityPool.band_depth`), by walking the liquidity in between. The
  smaller side counts, valued in the settlement asset, and the path's least pool sets it.
  - Liquidity concentrated at the price counts as the capital it actually holds within the band.
    The pool's virtual reserves, the measure before, counted a narrow range as if it spread over
    every price: over 20× its capital in the test.
  - The market's depth rises at most doubling every `SPOT_ORACLE_TWAP_SECONDS` from
    `SPOT_ORACLE_MIN_DEPTH`, and falls at once. Liquidity added for a moment raises it by a
    sliver.
- **No price without depth.** While the depth is under `SPOT_ORACLE_MIN_DEPTH` (10,000 of the
  settlement asset), the oracle is not updated. It goes stale, and the market takes only
  reduce-only orders.

**Open interest** is capped at the depth × `SPOT_OI_DEPTH_BPS` (10×). Moving the TWAP 2 % for its
window costs more than the depth, and gains 2 % of the open interest: at most 20 % of that
cost. A large swap moves the pool at once but the oracle by a sliver: the test moves the pool
30 % and the oracle under 2 %.

**Contained:**
- isolated margin only;
- the shared backstop vault never takes it over, so a loss the book cannot absorb is
  auto-deleveraged inside the market;
- it never prices anyone's margin;
- validators' votes for it are skipped;
- no funding premium is sampled while its oracle is stale.

`test_token_perps_adversarial.py` plays the attacks out block by block:
- the token's creator dumps it 30 %, and only that market's isolated positions are reached;
- a push held for one block moves the oracle under 1 %;
- a squatter's thin pool is replaced by a deeper one;
- votes cannot price it.

**State:** each market's `spot_token`, `spot_pools`, `spot_depth` and `spot_time`
(`header.spot`), committed and provable. `perp_getMarkets` shows `oracle_source` (`validators`
or `spot`), the token, its ticker, the path and the depth.
