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
| 8 | Deployer markets (HIP-3, builder-deployed perps) | built | `DEPLOYER_*`, `slash_deployer` · `test_deployer_markets.py` |
| — | Batch auctions (frequent batch auctions) | **skipped** | the decision of 2026-10-22 |

A network needs a fresh genesis for the new operations and state. Every default below is a
chain-spec parameter or a module constant and **awaits review** before mainnet
(docs/KNOWN_ISSUES.md, "Defaults awaiting review").

What Hyperliquid has that this does not, beyond batch auctions:
- a Dutch auction for spot tickers (HIP-1's deploy auction). A native token's symbol is first
  come, first served at its deploy fee;
- HyperEVM's two block sizes. The EVM has one gas limit per block, `BLOCK_GAS_LIMIT`.

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

A static call cannot send an action.

---

## 8. Deployer markets (HIP-3)

A **deployer** bonds QRDX under a namespace of its own and lists perp markets there. It runs
their oracle and takes a share of the protocol's fees on them. Validators can stop a deployer
fast, and governance can slash its bond. Hyperliquid's builder-deployed perps work the same way.

### Bond and namespace

`DEPLOYER_BOND {dex, amount}`. The first bond names the namespace: 1 to 8 lowercase letters and
digits, starting with a letter. It is first come, first served, and stays the deployer's for
good.

The bond is real QRDX, held by the protocol holder `0xDBND…` (`deployer_bond_address`).

`DEPLOYER_UNBOND {amount}` starts unbonding:
- The amount is claimable `DEPLOYER_UNBOND_SECONDS` (14 days) after the latest start, with
  `DEPLOYER_UNBOND {claim: true}`.
- It stays slashable until then. The delay is longer than a governance proposal's voting period
  plus its timelock, so a deployer cannot unbond ahead of a slash.
- A deployer running markets keeps `DEPLOYER_MIN_BOND` (100,000 QRDX) bonded.

### Listing

`CREATE_MARKET {base_token: "dex:ASSET", oracle_price, fee_share_bps, liquidity, …}`. Only the
namespace's deployer may list in it, and only with at least `DEPLOYER_MIN_BOND` bonded and fewer
than `DEPLOYER_MAX_MARKETS` (10) live markets.
- The market id is `dex:ASSET-USD-PERP`.
- It starts at the deployer's `oracle_price`.
- The deployer takes `fee_share_bps` of what the protocol keeps on the market's fees, at most
  `DEPLOYER_MAX_FEE_SHARE_BPS` (50 %), paid to its margin account. The stakers' share comes
  first; the backstop vault keeps the rest.
- The listing fee, the seeded liquidity vault, the grid, leverage tiers, the price band, the
  circuit breaker and the open-interest cap apply as on any market.

A base containing `:` is reserved for deployers. This keeps their markets apart from
validator-priced ones: a deployer cannot list a market that validators already vote on.

### The deployer's oracle

`DEPLOYER_SET_ORACLE {market_id, price}` sets the price at most once per block time. The price
moves at most `DEPLOYER_ORACLE_MAX_STEP_BPS` (1 %) per second since the last update, counting at
most 10 seconds. A price further away is applied at the bound.

An agent key may sign it, so the deployer's oracle bot need not hold the main key. A contract
may be the deployer, through the write precompile: an on-chain oracle aggregator, for example.

Validators' price votes for a deployer market are skipped, not refused, while it is not frozen.

### Settling

`DEPLOYER_HALT {market_id}` settles the deployer's market for good at its oracle price, as a
passed `delist_market` does. Every position closes and the result is zero-sum.

### The validators' freeze

An `ORACLE_VOTE` may carry `freeze: [market_id, …]`, at most 16 entries. Operators set it with
`QRDX_ORACLE_FREEZE`.

While fresh freeze votes hold more than two thirds of the committee's stake, the market is
frozen. Frozen means:
- it takes only reduce-only orders;
- the deployer can neither set its oracle nor settle it;
- **its oracle is the validators'**: their price votes apply as on any market.

The freeze lasts until one vote window (`PERP_ORACLE_VOTE_MAX_AGE`) after the last block with a
quorum. Stale votes, non-members' votes, and votes for settled markets are dropped.

### Slashing

The governance action `slash_deployer {deployer, bps, halt}` burns `bps` of the deployer's bond,
including what is unbonding. With `halt`, it also settles every market the deployer runs at its
oracle price, which is the validators' while frozen.

The intended sequence is: freeze at once, then slash and settle by proposal.

### State and API

- **Committed:** `trading.deployers`, `trading.freeze_votes`, and each market's
  `deployer`, `deployer_fee_share` and `frozen_until` (`header.dep`, `header.frozen`).
- **RPC:** `perp_getDeployer(address | dex)`. `perp_getMarkets` shows each market's deployer,
  fee share and freeze.
