# Known Issues

Open defects and accepted limitations, most severe first. Each entry states the
mechanism, the blast radius, and what closing it requires — so none of them survives
only as a comment in a diff.

Companions: [UNIFIED_ACCOUNT_IDENTITY.md](UNIFIED_ACCOUNT_IDENTITY.md),
[EXCHANGE_AND_VALIDATOR_STAKE_AUDIT.md](EXCHANGE_AND_VALIDATOR_STAKE_AUDIT.md),
[CONSENSUS_REMAINING_WORK.md](CONSENSUS_REMAINING_WORK.md),
[PROTOCOL_UPGRADES.md](PROTOCOL_UPGRADES.md) (chain specs, forks, network identity).

---

# Open defects

## OPEN — Perpetuals: rebuilt on a zero-sum clearinghouse; mainnet needs its bridge deployed

**Severity: critical (design) → being closed in phases.** Design and status:
docs/PERPS_CLEARINGHOUSE.md.

**The defect.** `PerpEngine.open_position` recorded a position with nobody on the other side.
Closing paid margin + PnL into the owner's real balance and debited no one, so the engine was a
"house" with no balance: it **minted** QRDX whenever a trader won and **burned** it whenever one
lost. Measured at honest oracle prices (one 1 BTC long, 10x, entry 30,000):

| BTC moves to | net QRDX created across all accounts |
|---|---|
| 33,000 | **+3,000** |
| 27,000 | **−3,000** |

**Phase 1 — done: the zero-sum core.** Perps now trade on an order book per market
(`qrdx/exchange/clearinghouse.py`): every fill has a buyer and a seller with equal and opposite
position changes; all collateral sits in one clearinghouse holder (`0xPERP…`); real QRDX moves
only on `PERP_DEPOSIT` / `PERP_WITHDRAW`; realized PnL, fees (to the vault) and isolated margin
move between internal records. Cross and isolated margin, pre-trade initial-margin checks with
resting-order reservations, reduce-only orders, IOC. The house ops (`OPEN_POSITION`,
`CLOSE_POSITION`, `PARTIAL_CLOSE`, `ADD_MARGIN`) are retired. The clearinghouse identity
*holder = Σ collateral − Σ size × entry* holds **exactly** — entry prices are stored quantized and
the residual is charged to the account, and every internal transfer is a whole number of wei.
Read-only view: `GET /get_perp_account?address=`.

Tests: `tests/test_clearinghouse.py` (18, incl. 600 randomized steps across two markets with
mixed cross/isolated accounts — identity exact and net size zero after every step),
`tests/test_perps_manager.py` (total `account_state` QRDX unchanged end to end through deposits,
a trade, a 10 % rally, closes and withdrawals), `tests/test_perp_price_integrity.py` (the original
attack is refused; two colluding accounts trading at 1e9 only move value between themselves),
rebuild equivalence and restart replay with order-book trades. S13 now runs two traders on the
book cross-node and checks winner + loser + holder = 0. First soak: positions and final
balances identical on all four nodes, and the holder kept exactly the 44.1 QRDX of fees — the
scenario's one failure was its own balance read (below).

**Phase 2 — done: mark price and a per-block tick.** Mark = median(oracle + 150 s premium EMA,
median of best bid / best ask / last trade, 30 s EMA of that median), held within ±5 % of the
oracle. The EMAs run on block time, so the exchange now ticks on **every** block on every path
(proposer, p2p / sync / REST importers, both rebuilds) — before, exchange duties ran only in
blocks carrying exchange transactions. Tests: `tests/test_clearinghouse_mark_price.py` (a 50 %
thin-book squeeze moves the mark ~3 % in one block and never past the band; it decays once the
honest book returns; forward-with-ticks ≡ rebuild over 37 quiet blocks, and skipping them is
proven to diverge). Two defects found on the way, both fixed:
* **The order book could cross.** Self-trade prevention (`REJECT`) skipped the sender's own
  resting order and rested the remainder across it — a 30,290 bid above the same trader's
  30,010 ask — moving the mid, and with it the mark, at no cost. It affected the spot CLOB too.
  Both consensus books now use a new `CANCEL_TAKER` mode: the order stops at its own resting
  order and the remainder is cancelled (never escrowed); fills against others stand. The old
  `CANCEL_BOTH` mode had the same flaw (a cancelled taker could still rest) — fixed in the
  matching loop.
* **Protocol holders were unreadable over RPC.** `/get_address_info` refused `0xPOOL` /
  `0xCLOB` / `0xPERP` addresses (the transaction address pattern), and the client read the
  400 as a balance of 0 — which is how S13's conservation check saw +0 at the holder while every
  node's `account_state` held 44.1. Read-only queries now accept them
  (`account_id.is_synthetic_holder`); transactions still cannot name them.

**Phase 3 — done: liquidations and the backstop vault.** In every block's tick, at mark: book
first (reduce-only IOC limited to the bankruptcy price, so no fill creates bad debt), then the
vault takes over below ⅔ of maintenance (at mark, with the remaining margin — only the position's
own margin when isolated), then auto-deleveraging against the most profitable, most leveraged
opposite positions at prices that return the account to exactly zero. The vault is an HLP-style
account with shares at NAV (`VAULT_DEPOSIT` / `VAULT_WITHDRAW`, 4-day lockup), fees accrue to it,
and a configured treasury seeder's deposits are protocol-owned and never unlock. Tests:
`tests/test_clearinghouse_liquidation.py` — every stage to exact numbers, 16 randomized crash
runs (funded and empty vault; every stage exercised) with the identity exact, net size zero and
no account below −1e-6 after every block, and forward ≡ rebuild with a liquidation inside a
block's tick. Found on the way: **a fresh market's first book set its mark outright** — the mark
EMAs seeded from their first sample, so a trader's own far-apart quotes could prop up the mark
and dodge liquidation. They now start anchored to the oracle with a full timescale of weight.
The legacy `PerpEngine` liquidation duty, which still credited real balances, is removed.

**Phase 4 — done: funding.** Hyperliquid's formula on block time: premium from the impact
bid/ask, F = premium + clamp(0.01 % − premium, ±0.05 %) per 8 h, the interval's share paid,
capped at 4 %/h; size × oracle × rate, longs to shorts when positive. Exactly zero-sum (rounding
dust to the vault). Tests: `tests/test_clearinghouse_funding.py`. Cross-node: scenario S19 (a
forced liquidation into the vault, a depositor redeeming above cost, funding state identical on
every node, QRDX conserved).

**Phase 5 — done: USD-stablecoin settlement and the validator oracle.** Per the project's
decision (Hyperliquid's USDC model), perps settle in a configured QRC-20 USD stablecoin
(`QRDX_PERP_COLLATERAL_TOKEN`; markets `BTC-USD-PERP`) — so an oracle price is a plain USD price
every validator can observe. The oracle is the stake-weighted median of the validator committee's
fresh `ORACLE_VOTE`s, set only when they carry a majority of the committee's stake; proposers
attach their own signed votes from a price feed; a market whose oracle goes stale refuses new
exposure. The committee starts from the validator set the genesis block now records and follows
staking. Tests: `tests/test_perps_stablecoin.py`, `tests/test_validator_oracle.py`. Cross-node:
S13/S19 settle in a testnet stablecoin with prices set only by validator votes — no reporter.
Found on the way: **`PERP_FUNDING_INTERVAL_SECONDS` was defined twice in `constants.py`**; the
later, legacy 8-hour line silently replaced the env-driven one, so a testnet configured for 60 s
funding paid none (caught by S19's funding check). The duplicate is gone and
`tests/test_constants_single_definition.py` now fails on any name assigned twice there.

**Still open:**
* **The bridge is built; mainnet still has to deploy it.** The consensus bridge
  ([BRIDGE.md](BRIDGE.md)) mints a listed source-chain token once validators holding two thirds
  of the stake attest its lockbox deposit, through a mint authority no key controls, and records
  burns for the lockbox's custodian to release. What remains is not code: the lockbox
  (`contracts/bridge/QRDXLockbox.sol`) audited and deployed, a custodian chosen (a multisig —
  the source chains cannot verify Dilithium, so releases are its act), and mainnet's chain spec
  listing the asset (`BRIDGE_ASSETS`) and settling perps in it (`PERP_COLLATERAL_TOKEN`). Until
  then the default (unset) collateral refuses deposits; the testnet deploys a test token.
  Native-QRDX settlement remains for development only. The older bridge scaffolding in
  `qrdx/bridge/` is not part of it and could not have been: its `BridgeMinter`
  (`qrdx/bridge/shielding.py`) only tallies totals in memory, and its Ethereum lock-event scan
  matches a sha256 topic (Ethereum uses keccak) and never decodes the amount or recipient. It
  remains for the Doomsday Protocol's reads only.

**Fixed (2026-10-12):**
* **Oracle votes are gossiped and have their own sequence.** A vote used to ride only in its
  voter's own blocks, so on a large validator set it refreshed only as often as the voter
  proposed, and each one consumed the validator's exchange nonce, so its own transactions signed
  elsewhere went stale. Validators now vote from a background loop through the mempool (a vote
  lane that keeps each voter's newest vote, gossiped and included votes-first); a vote's nonce is
  the slot it was made in, checked against the voter's last applied vote, never the account nonce.
* **Convicted validators leave the oracle committee.** Slashing evidence on the chain below the
  block excludes the offender (only `STAKE_EXIT` used to remove a member).
* **Mark-price robustness.** Validators vote other venues' perp prices (`"BTC:perp"`; the
  exchanges feed reads Binance, Bybit and OKX perps), aggregated like the oracle. While fresh it is
  the mark's third input in place of the 30 s book EMA, so a squeeze of the local book moves the
  mark ~5× slower (a 10 % squeeze: ~54 s to move it 3 %, not ~12 s).
* **Margin for closing orders.** A resting order that only closes the position reserves nothing
  (it reserved as if it opened, unless flagged reduce-only). Orders are re-checked when the
  position changes and at match time, so one left opening by a smaller position cannot fill
  unmargined. Found on the way: **a resting order far from mark reserved nothing at placement**
  — the check valued it as filled now, at the gap to mark — so a sell at twice the mark rested
  against almost no collateral. Placement now also checks the order resting whole.
* **Large liquidations in 20 % slices** with a 30 s cooldown above 100,000 of notional
  (Hyperliquid); the backstop still acts during the cooldown.
* **The vault unwinds what it takes over**, a slice every 30 s per market, never more than 0.5 %
  through mark (it held the positions until it fell under maintenance itself).
* **Funding after a halt** pays every interval the halt spanned, those with no block in them at
  the interest-only rate (one interval used to be paid).
* **Market listing is not free:** `CREATE_MARKET` burns `PERP_MARKET_LISTING_FEE` QRDX (a
  chain-spec parameter, default 1,000). Every market costs every node work in every block and a
  place in the validators' votes; it cost only gas.
* Found on the way: **placing a perp order walked every resting order in the market** to prune
  finished ones (most of its cost: 1.9 ms at 10,000 orders, now 0.3 ms), and derived indexes
  re-read every change since the last commitment on each sync. Both now touch only what changed.

Tests: `tests/test_validator_oracle.py`, `tests/test_clearinghouse_order_reservations.py`,
`tests/test_clearinghouse_liquidation_slices.py`, `tests/test_clearinghouse_funding.py`,
`tests/test_exchange_fees.py`.

## OPEN — The first release needs maintainer keys

**Severity: high (blocks every release).** Signed releases and reproducible builds are in place
([RELEASES.md](RELEASES.md)). `release/allowed_signers` is empty on purpose, so nothing
verifies until maintainers register.

**To close:**

1. At least `maintainer_threshold` (2) maintainers add their keys with
   `scripts/release/release.py add-signer`
   ([RELEASES.md §5](RELEASES.md#5-cutting-a-release-maintainers)).
2. Apply the GitHub settings listed there: branch protection, a `v*` tag ruleset, and a public
   GHCR package.

Two other blockers are resolved, pending your next commit:

- **The `dvm` gitlink.** An undeclared submodule broke every fresh clone. Its removal and the
  `.gitignore` entry are staged.
- **The py-evm change.** The change the tests ran against is committed as py-evm `ffe59501` and
  pushed to `qrdx-org/py-evm` (`denaro`). The new submodule pointer is staged.

A CI simulation (a fresh clone of a commit of the current tree, py-evm fetched from GitHub)
reproduced the following:

- the image build from the commit;
- the unit suite inside the image.

## OPEN — QRDX's chain ids are not registered yet

**Severity: low (process).** Mainnet is chain id **762** (`qrdx-mainnet`) and the testnet
**7620** (`qrdx-testnet`). Both were unassigned in ethereum-lists/chains and chainid.network on
2026-10-09. The code reserves them: only those networks' specs may use them, and a dev node
can't (`chain_spec.QRDX_NETWORKS`). But an id is only "ours" once it is registered. Every
signed transaction is bound to it, so another chain taking 762 would make keys used on both
replayable.

**To close:** submit `eip155-762.json` and `eip155-7620.json` to ethereum-lists/chains.

## OPEN — New trading features await review of their defaults and an audit

**Severity: medium (process).** docs/TRADING_FEATURES.md, docs/ACCOUNT_CONTROL.md. Built and
tested, but their economics and limits are starting values: the fee tiers and rebate (perps and
spot), the referral terms, the trigger and TWAP per-block budgets, the vault profit-share bounds,
the leader's minimum share and the vault order band, the market-liquidity minimum (10,000), its
lockup (30 days) and the protocol's quoting (levels, spread, depth, inventory limit). Account
control (controllers, the own key, multisig signing in exchange and EVM transactions) is
security-critical and needs the audit first. Portfolio margin is **inert** until `PERP_PORTFOLIO_ASSETS` lists an asset, which needs a
pricing market, spot liquidity for the vault to sell into and a haircut that covers the time it
takes. A user-vault leader can still lose depositors' money to a counterparty it controls within
the 10 % band (as with vaults anywhere). Hidden and iceberg orders hide only from the book's depth:
their parameters are on the chain. All of it needs
the soak and external audit the rest of the exchange does. New op types and state need a fresh
genesis (or a fork that activates them).

The consensus features of docs/CONSENSUS_ROADMAP.md add starting values too: the price band
(20 %), the circuit breaker (10 % in 300 s, 60 s cooldown), the open-interest multiple (50 × the
liquidity vault's equity) and floor (0), the leverage tiers (1M / 10M), the oracle's minimum
voters (3), step bound (5 % a second) and outlier band (2 %), the stakers' fee share (20 %) and
its conversion (once a minute a token, 2 % under a 10-minute TWAP), the guardian limits (7,
recovery delay 1–30 days, default 7) and QNS's price (now 0.0125 QRDX a year, ~$5). Frequent batch auctions
(fair ordering step 2) were skipped (decision of 2026-10-22). Social recovery and agent
spending limits are account control: audit first.

The Hyperliquid-parity features (docs/HYPERLIQUID_PARITY.md) add their own:
- **Dead man's switch:** at least 5 s ahead, 10 fires per account per day, 50 accounts per block.
- **Builder fees:** capped at 0.1 % perps and 1 % spot.
- **Order grid:** 4 size decimals, 5 significant figures, a minimum order of 10.
- **Staking fee discounts:** 5 % at 10 QRDX staked up to 40 % at 500,000.
- **Contract actions:** 25,000 EVM gas each plus 1 per 10 exchange gas, at most 2,000,000
  exchange gas, 256 run per block.
- **Tickers:** opening price 250 QRDX, floor 25, 31 h auctions.
- **Native-token perps:** at most 10× leverage, a 600 s TWAP, a minimum depth of 10,000 of the
  settlement asset, open interest at most 1× the depth (rising at most 2× per window).
- **Token economics at ~$400 a QRDX:** every QRDX amount in docs/TOKENOMICS.md — a 10M supply,
  system wallets of $100k–$1M each, the free trading lane's budget (10,000 actions, 1 per unit
  traded, one per 10 s past it, 64 an account a block, a $10 holding, closed above 2× the base
  fee floor).
- **Big blocks:** every 240th block, 3,000,000 EVM gas, a fee track moving up to 1/2 per big
  block.
- **Perps listing:** maximum leverage at most 50 (`PERP_MARKET_MAX_LEVERAGE`); validator-priced
  markets listed by governance (`PERP_OPEN_LISTING` off).
- **Deployer markets:** a 1,250 QRDX (~$500,000) bond, 14-day unbonding, 10 markets per deployer, a fee
  share of at most 50 %, an oracle step of 1 % a second (10 s at most per update), a freeze at
  more than 2/3 of stake for one vote window.

Deployer markets put a deployer's oracle in charge of real positions. The bounds, the circuit
breaker, the validators' freeze and the slashable bond limit the damage, and they need the
audit too.

## FIXED — Isolated orders crossing the spread were refused; pool TWAPs had 16 s of history

Found building native-token perps (2026-10-23):
- **Every isolated order filling a tick worse than mark was refused.** The pre-check required
  the position's equity at mark after the fill to cover its full initial margin. But its margin
  is sized at the fill price, so crossing the spread was always short by the spread: an
  isolated taker could not buy above mark or sell below it, on any market. It now must not open
  already liquidatable (equity at mark above maintenance), as on Hyperliquid.
  Test: `test_perps_listing_and_leverage.py::test_an_isolated_order_may_cross_the_spread_but_not_open_liquidatable`.
- **An AMM pool kept 64 observations, one per block that changed it**: 16 seconds at 250 ms
  slots. A TWAP longer than that had no history to read on an active pool. The stakers' fee
  conversion (a 10-minute TWAP bound) silently skipped busy pools. Pools now keep checkpoints
  15 seconds apart, the newest moving with each change: 128 hold about 32 minutes. A TWAP runs
  from the newest checkpoint at or before its window's start, exact over that span.

## FIXED — Funding on a deployer's untrusted price; a ticker's token renamed

Found by playing out a malicious deployer block by block (`tests/test_deployer_adversarial.py`,
2026-10-23):
- **Funding kept running on a frozen or abandoned deployer market's price.** The funding
  premium (book against oracle) was sampled every block, frozen or not. The validators' freeze
  stopped the deployer's oracle, but not funding at up to 4 % an hour on the price it left
  behind. The same held for an oracle its deployer stopped updating. Neither samples a premium
  now: such an interval pays the interest rate alone.
- **A ticker's token could change its symbol** (its metadata authority). It would then show one
  asset's symbol under another's ticker. A token holding a ticker now keeps its symbol.

## OPEN — A deployer can extract funding until the validators freeze its market

**Severity: medium (design, bounded).** docs/HYPERLIQUID_PARITY.md 8. A deployer that holds its
oracle away from the book collects funding from the other side, at most 4 % of open interest an
hour, until the validators freeze the market (`QRDX_ORACLE_FREEZE`) and governance slashes the
bond. It can also walk the oracle 1 % a second to liquidate that side. Only that market's
isolated positions are reachable. The bond (1,250 QRDX, ~$500,000) should exceed what a deployer market's
open interest could yield in the time the validators take to react: review the bond and the
open-interest caps together. Monitoring deployer markets for an oracle off the book is
operators' work.

## FIXED — Perps settings an outside actor could choose, and paths around the perps rules

**Severity: critical (the first) to high.** Found in a perps audit on 2026-10-23
(docs/HYPERLIQUID_PARITY.md 10). None was ever committed; a fresh genesis carries the fixes.

- **A contract could send exchange actions as whoever called it.** The exchange write
  precompile (`0x…0401`, from the day before) took `msg.sender` as the account, and a
  DELEGATECALL keeps its caller's. Any contract a victim called could trade or withdraw the
  victim's exchange account. It now refuses DELEGATECALL and CALLCODE, as the native token and
  NFT precompiles always had, and refuses QRDX sent to it.
  Test: `test_evm_exchange.py::test_a_contract_cannot_send_actions_as_its_caller`.
- **A market's maximum leverage had no upper bound.** Its maintenance margin is half its initial
  margin at maximum leverage. A market listed at 10,000× liquidates far too late, and the shared
  backstop vault pays. Now at most `PERP_MARKET_MAX_LEVERAGE` (50).
  The constant this was first added as, `PERP_MAX_LEVERAGE`, was silently replaced by the
  retired engine's constant of the same name later in `constants.py`
  (tests/test_constants_single_definition.py caught it).
- **Whoever listed a validator-priced market first chose its settings.** That included its
  maximum leverage and grid, and it took the canonical name for good. These markets are now
  listed by governance (`list_market`). `CREATE_MARKET` lists deployer markets only, unless the
  chain spec sets `PERP_OPEN_LISTING` (a dev network's setting).
- **A deployer's oracle could reach accounts outside its market.**
  - Cross margin mixed a deployer market with an account's other positions.
  - The shared backstop vault took over its liquidations.
  - A portfolio-margin asset could be priced by it.
  - A configured reporter could set its price.

  Now it is isolated-margin only, auto-deleveraged within itself, never a collateral price
  source, and closed to reporters. Reporters also walk at the validators' step bound now.
- **Vault shares were priced at cross equity only.** A leader could move a vault's margin into
  an isolated position, join at the depressed price, and take value from the other holders when
  the margin came back. A test reproduced 518 of 10,000 taken. Shares, liquidity-vault quotes and
  open-interest caps now use `Clearinghouse.total_equity`.
- **A live order id could be reused** (it would need a hash collision). Now refused.

Tests: `tests/test_perps_listing_and_leverage.py`, `tests/test_evm_exchange.py`.

## FIXED — Trading state outside the exchange root when only newer collections held entries

The exchange root takes the trading state (`TradingState`) only once it is `touched`. That
flag looked only at the trigger/TWAP counter, agents and sub-accounts. An account whose only
trading state was a scheduled cancel, a builder approval or (now) a contract's queued action
left all of it out of `exchange_state_root`.

Its proof leaves were still in the proof root, which is part of the signed unified root, so no
node could have held different state under one root. But the exchange root alone did not bind
it.

Found while building contract actions (docs/HYPERLIQUID_PARITY.md 7). `touched` now covers every
collection the trading state commits, and the pre-incremental serialization covers them too.
Test: `tests/test_evm_exchange.py` (a queued action changes the root).

## FIXED — Blocks were judged by their slot where their height was meant

A PoS block's signed `number` is its **slot** (the proposer sets `number=slot`), which runs ahead
of its height after any skipped slot — by 24 within minutes on a 4-node testnet with one node
restarted. Several importer checks read it as the height: the E-D4 unified-root check chose each
domain's rules by it (`_verify_unified_state_root`), proposer eligibility judged the block on the
chain ending at `number − 1` instead of its parent, and RANDAO selection's activation was decided
by it — while the proposer decides by height. Every rule so far is a genesis feature, so nothing
diverged yet; at a height-gated fork, importers would have switched rules up to (slot − height)
blocks before the proposer and refused its blocks. It surfaced in a live run as state-proof roots
filed under slot numbers on importers (`state_root_parts`). Every import path now passes the
height it applies the block at; otherwise it is the parent's stored height + 1
(`block_verification.block_height_of`). Tests: `tests/test_protocol_upgrade_activation.py`
(`…by_its_height_never_its_slot`), `tests/test_sync_ed4_enforcement.py` (`…not_its_slot`). (The
RANDAO *reveal* requirement is keyed by the slot on both sides — consistent, and a reveal is
required whenever height-based selection needs one, since slot ≥ height.)

## FIXED — A restarted node credited staker fee payouts from nothing

Fee payouts are paid out of the fee holder (`withdrawals._payout_moves`), but the derived-state
rebuild — a restart, a reorg's replay — re-applied every staking payout as a plain credit: the
holder kept the income it had paid out, and a `fee_pooled` row (addressed to the holder) was even
credited to it. A node restarted after its first epoch of fee income computed an account root no
block carried, and stalled. Found in a live 4-node run (restart of one node); the rebuild now
applies the same moves as the forward path. Tests: `tests/test_interleaved_rebuild_equivalence.py`
(`test_fee_payouts_rebuild_like_forward`, and a sensitivity test showing the old replay diverges).

## FIXED — An agent's orders were refused once its owner's nonce passed the agent's lane

Exchange transactions are numbered per nonce lane (the account's own, and one per agent, master
or leader signing for it), but a spot or perps order also carried its transaction's nonce into
the book's own per-owner check, which wants it strictly increasing across all of the owner's
orders. Once the owner had placed more orders than its agent (or the reverse), the other's next
order failed "Nonce replay". An order signed in another lane now carries 0 into the book, which
it does not check — the lane's nonce already refuses a replay. Test:
`tests/test_recovery_and_agent_limits.py` (`…in_any_interleaving`, which fails on the old code).

## FIXED — Each account-balance write scanned the account table

`DatabaseSQLite.apply_account_balance_delta` finds the row with `WHERE LOWER(address) =
LOWER(?)` (case-insensitive: genesis may store a checksummed address), which could not use the
primary key: every balance write was a full scan of `account_state` — ~1.4 ms a write at 20,000
accounts, growing with the state, in the block path. An index on `LOWER(address)` serves the
same query: same rows, same semantics, a lookup. Test: `tests/test_state_proofs.py`
(`…finds_its_row_by_index`).

## FIXED — A block at an orphan's height could inherit the orphan's staker fee income

Each block logs the stakers' fee income it took in (`staker_fee_income`), and the epoch
transition shares it. The log was written only for blocks that took something in, and cut above
the tip only after the reorg's rebuild (and only with the deposit-undo gate on): a block of the
new branch at an orphan's height that took in nothing left the orphan's row in place, paying
stakers fees that never happened. Every path now writes each block's row — removing it for
nothing. Test: `tests/test_staker_fees.py` (`…clears_an_orphans_row…`).

## FIXED — The state-proof tree missed rows written without its triggers

The tree is kept from TEMP triggers on the node's own connection; a row written by another
connection (a tool) never reached it, and that node's proof root — so its state root — would
disagree with the network's. The LtHash accumulators already repaired themselves at startup in
that case; now a domain they repair makes the tree rebuild itself from the rows (a deleted row's
leaf included). Test: `tests/test_state_proofs.py` (`…without_the_triggers…`, which fails with
the repair disabled).

## FIXED — An order-book swap swept any number of resting orders for its base gas

A `SWAP` routed through an order book visited every maker its size reached for SWAP's flat 65,000
gas — the cost PLACE_ORDER and PERP_ORDER stopped paying when matching was metered
(docs/BLOCK_LIMITS.md). Now the router quotes the book within what the gas limit pays for at
`EXCHANGE_GAS_PER_MAKER` a resting order, executes on exactly that budget, and the swap pays for
the visits. Likewise an order that fails after matching (fill-or-kill, a settlement it cannot
cover) pays for what it visited, not only its base gas. Tests: `tests/test_trading_ops.py`.

## FIXED — A perp order that could not rest kept its makers' fills without the trades

A `PERP_ORDER` that matched and then could not rest its remainder (the account already rested
the most a book allows) raised after the book had filled the makers: the makers lost their orders
and got no position. Every exchange operation now runs in an undo scope (`qrdx/exchange/undo.py`)
and changes nothing if it fails; the same mechanism made spot orders stop deep-copying their whole
book before matching. Tests: `tests/test_undo_scopes.py` (random books, clearinghouses and nested
scopes rolled back field for field, then behaving identically to a twin).

## FIXED — The tick's ledger moves were dropped in blocks without exchange transactions

New tick-time work settles real tokens (a fired spot trigger, a spot TWAP slice, the vault's
sale of margin tokens). A block that carries exchange transactions flushes its section's deltas,
the tick's included; one that carries none ticked through `run_exchange_tick` and flushed
nothing, so those moves would have vanished at the next block. Every path now ticks such a block
through `block_processor.tick_and_flush`. Test: `tests/test_trading_ops.py`
(`…reaches_the_ledger`). Tick-time debits are covered by the protocol's own records (a book's
escrow, a pool's reserves), never by a balance loaded for the block — the tick runs on blocks for
which none is loaded, so a check of one would judge the same move differently on different paths.

## FIXED — A block's body was not signed, and its hash was taken as sent

**Severity: critical (consensus).** The proposer signed only header fields: number, parent hash,
state root, transactions root, timestamp, slot, epoch, RANDAO reveal. The votes a block
carried, its slashing proofs, and its exchange and EVM sections were covered by nothing.

- **Votes and evidence could be rewritten in transit.** Anyone relaying or serving a block
  could strip or swap the valid votes and slashing proofs it carried, under the same hash.
  Those inputs decide finality, rewards and the validator set. Nodes holding different copies
  of one block therefore derived different validator sets from it, and so different verdicts on
  who may propose next: a split. A syncing node could be served history with its votes stripped.
- **The block hash was not checked.** The p2p path took a block's hash as sent: it only checked
  that it was hex. So one sender could store an honest block under a hash of its choosing, and
  fork choice prefers the lowest. The hash covered only some header fields anyway.

**Fixed:**

- The header carries `body_root`, signed. It is a hash of the block's votes, slashing proofs,
  graffiti and both sections, exactly as they travel (`block_verification.body_root`).
- The header also signs the proposer's address and the base fees.
- A block's hash is its signing root.
- Every import path recomputes both before anything else and refuses a mismatch
  (`block_integrity_error` in `_verify_chain_rules`).
- Fork-choice scoring and the equal-height tie-break ignore blocks sent under hashes that are
  not theirs. The tie-break also used to roll back the tip before validating the incoming block.
  It is off by default (`_ENFORCE_EQUAL_HEIGHT_TIEBREAK`), and can no longer be pointed at a
  forged hash.

A block format change: existing networks need a new genesis. Tests:
`tests/test_block_body_commitment.py`.

## FIXED — A transaction could stall every node

**Severity: critical (liveness).** EVM state is loaded on demand. On every read of something
not yet loaded, the execution started over from the beginning, on a py-evm state rebuilt and
re-hashed from everything loaded so far. A transaction touching n new accounts did O(n²) work.
Measured: 200,000 gas of BALANCE calls on new addresses took 0.35 s, 400,000 took 0.85 s, and
800,000 took 2.8 s. The 10,000,000 gas a transaction could carry, about 0.01 QRDX at 1 gwei,
meant minutes on every node.

**Fixed:**

- Execution runs in a greenlet and switches out to load what it misses. Each account and slot is
  loaded once, where the execution stopped for it (`evm_world.run`). 800,000 gas of the same
  calls now takes 49 ms.
- The state is a journaled dictionary store with py-evm's semantics (`WorldAccountDB`), where
  the trie seeded per restart used to be.
- A differential test runs random contracts on both stores and requires identical results, gas,
  logs and state roots (`tests/test_evm_world_equivalence.py`). Planted bugs in the new store
  fail it.

## FIXED — Blocks had no bound on execution, and gas no price

**Severity: high (liveness).** A block was bounded only by its size in bytes:
- 1.9 MB of EVM transactions with any gas limits;
- as many exchange operations as fit;
- any number of votes, each a Dilithium signature to verify.

Gas had no price: EVM transactions had no floor at all (a gas price of 0 executed for free),
and exchange gas cost the floor however full blocks were. An order paid its base gas however
many resting orders it swept: 1,600 makers took 38 ms for 60,000 gas. py-evm runs bn128 in pure
Python, so a block of pairings at Ethereum's prices took ~6 s. Nodes without coincurve recovered
every EVM sender in pure Python: ~15 ms each.

**Fixed** (docs/BLOCK_LIMITS.md):

- **Limits:** per-block limits on EVM gas (1,000,000) and exchange gas (20,000,000), both
  chain-spec parameters, plus caps on votes (128) and slashing proofs (16). Every import path
  checks them before anything runs. The proposer packs to them, and the mempools refuse what no
  block could carry. `eth_call` and estimation are capped too.
- **Base fees:** EIP-1559-style base fees in the signed header, one per kind of gas, with an EVM
  floor (`EVM_MIN_GAS_PRICE_WEI`). Validators' oracle votes are exempt.
- **Per-maker gas:** matching costs 10,000 gas per resting order visited, within the order's own
  gas limit.
- **Precompiles:** bn128 is surcharged to the cheapest instruction's speed.
- **Dependencies:** coincurve is in the release lock, and a node without it logs an error.

Calibrate with `scripts/bench/evm_gas.py`. Tests: `tests/test_block_limits.py`,
`tests/test_match_budget.py`, `tests/test_fee_market.py`.

**Consequence:** a zk-SNARK verification (3–4 pairings, 1.4M gas here) does not fit a block until
a native pairing backend replaces py_ecc.

## FIXED — The validator cap was never enforced

**Severity: medium (scalability).** `MAX_VALIDATORS` (150) was declared and never read, so any
number of validators could join. Each adds a 3.3 KB vote every epoch that every node verifies and
stores: at 150 validators that is ~5 GB a day. Past a few thousand, honest votes no longer fit
the blocks of their inclusion window, and their validators are penalized for votes they cast.

**Fixed:** `MAX_VALIDATORS` is a chain-spec parameter and an activation queue
(`epoch_state.transition`, step 4). Past the cap, validators that are due wait in order: by when
they became due, then by address. One activates when another's exit completes. A queued validator
can leave at once. Startup refuses a cap above what an epoch's blocks can carry (128 votes × 32
slots). Tests: `tests/test_epoch_state.py`.

## FIXED — A syncing node could follow a long-range fork

**Severity: high (consensus, new nodes).** A running node never reorganizes below finality. A
node syncing from genesis had nothing to hold on to. Validators that left long ago can sign
another history from an old block onward, finality included: their stake is withdrawn and
nothing is slashable. A new node would follow whichever history it was shown.

**Fixed** (docs/WEAK_SUBJECTIVITY.md): trusted checkpoints, from the chain spec (appended by each
signed release) and from the operator (`QRDX_TRUSTED_CHECKPOINT`).
- A block at a checkpoint's height must be the checkpoint, on every import path.
- No reorganization goes below the highest checkpoint held, or below finality.
- A node whose database contradicts a checkpoint refuses to start.
- A node offline longer than the weak-subjectivity period (~3.9 days) is warned.
- `qrdx_weakSubjectivityCheckpoint` gives operators a checkpoint to hand to new nodes.

Tests: `tests/test_trusted_checkpoints.py`.

**Still open:** checkpoint sync. A new node still replays from genesis.

## FIXED — A second, unused token class remained

**Severity: low.** This was what remained of the 2026-10-02 spot exchange audit.
`qrdx/tokens/qrc20.py` was an in-memory token class (approvals, permits, bridge mint/burn,
freeze) that no consensus path used. The Doomsday trading hook (Whitepaper §9.2) read its
per-token flag, and integration scenarios S05/S06 drove it on a scratch database.

**Fixed:** native tokens carry the Doomsday flag as an extension, `post_doomsday_trade`, set at
`TOKEN_DEPLOY`. A plain token is committed exactly as before. The hook evaluates native tokens.
`qrc20.py`, its persistence layer, its constants and S05/S06 are removed. S14, S15 and S20 cover
the native standard and the AMM through consensus. The suite is now 21 scenarios.

---

# Accepted limitations

## FIXED — Historical proposer eligibility could not be re-checked (and refused deposits became validators)

**Severity: critical (consensus).** A block's proposer must be the validator selected for its
slot. The set it was selected from was this node's live `validators` table, which the epoch
loop rebuilt each time *this node's* finality advanced. Three consequences:

- A block judged long after its slot was judged against a different set: during a sync, or on
  a branch fork choice adopted. So sync and adoption trust-replayed eligibility, and a branch of
  out-of-turn blocks could win on height between justified checkpoints.
- Live import and the proposer could disagree for a moment whenever one had processed a
  finalized epoch the other had not.
- Casper FFG weighed votes by that same live table, so finality depended on node-local timing.

**Found on the way: refused deposits became validators.** The rebuild took its stake inputs
from the per-block index, which records every `STAKE_DEPOSIT` a block carries. That includes
deposits the exchange **refused**: a failed transaction is still included, because it pays its
gas.

- **Measured:** an account holding 1 QRDX submitted a deposit naming 1,000,000 of stake. The
  exchange refused it and debited nothing, yet the rebuild registered an **active validator with
  ~1,000,000 effective stake**. Against three 100,000 genesis validators that is ~77 % of all
  stake, enough to finalize on its own.
- **Second bug:** a pending validator that exited became "exiting", a proposing status, so it
  gained proposal rights without ever activating.

**Fixed:** the validator set is a pure function of the chain (`qrdx/validator/epoch_state.py`,
[STAKING.md](STAKING.md)).

- `S_E`, the set at the start of epoch `E`, comes from an epoch-by-epoch transition from the
  genesis set over the chain's blocks: executed stake operations, votes within the inclusion
  window, slashing proofs. Finality and node timing are not inputs.
- Stake operations are read only from the logs block application writes for operations that
  executed, which rollback reverses.
- States are cached per (epoch, checkpoint hash), so a reorg never reuses one.
- Every block is judged against `S_E` of its own parent chain, on every path. Sync and
  fork-choice adoption now enforce eligibility.
- The proposer selects from the same function, and FFG weighs a vote for target `t` by `S_t`.
- Pending validators no longer propose before they activate, and a pending exit leaves at once.
- The `validators` table is now a display copy that the epoch loop writes. The finality-gated
  reconstruction, its snapshots and the index's unfiltered stake-op table are removed.

**Verification:**

- `tests/test_epoch_state.py`:
  - the transition rules;
  - refused deposits;
  - identical states across different import histories;
  - historical judgement of a block after the chain moved on;
  - every path enforcing;
  - FFG weights;
  - caching across reorgs;
  - restarts;
  - cost per epoch.
- The integration suite: all scenarios, S16's deposit, activation and exit included, with no
  eligibility rejections in any node log.

## FIXED — The exchange kept a second validator set

**Severity: medium (consensus).** Oracle prices, bridge attestations and governance votes are
weighted by a validator "committee" the exchange kept as its own record: the genesis set, plus
executed deposits, minus exits. That was a second definition of the validator set, and it
disagreed with the first:

- a validator voted prices, attested bridge deposits and proposed governance while still
  **pending**;
- one **ejected** for inactivity kept voting until it filed an exit itself;
- delegated stake did not count;
- weights were principal, not effective stake.

**Found on the way.** The members a slashing proof convicts were read below the node's tip,
not below the block being applied. A rebuild of history therefore excluded a validator from
blocks before its conviction, and its earlier votes counted differently.

**Fixed:** the committee for block `h` is the chain-derived validator set in force at its parent
(`epoch_state.committee_for_block`): active and exiting validators, weighted like everywhere else.
Convictions below `h` are excluded, for governance proposals too. Every path sets it before every
block, section and tick alike, for that block's own height (`block_processor.ensure_oracle_committee`).
Stake operations no longer edit it, and the validators' vote loop reads it without touching the
exchange's. Tests: `tests/test_validator_oracle.py`
(`test_the_committee_is_the_validator_set_in_force_at_the_parent`,
`test_every_path_sets_the_committee_before_each_block`, the conviction height).

## FIXED — Restarts replayed derived state from genesis (and fast reorgs kept orphaned history)

**Severity: medium (scaling).** Reorgs no longer replayed the chain, but a restart still did: the
exchange state lives only in memory, and the reorg checkpoints were in-memory copies. A starting
node rebuilt every derived domain from genesis, at about 26 µs per block plus the blocks that
carry transactions. That is ~2 s at 75,000 blocks and ~9 s per day of 250 ms blocks.

Found on the way: **the fast reorg path left the exchange journal behind.** It restored the
exchange state from a checkpoint but not the journal (receipts, perps events, trades, candles).
Receipts and trades of orphaned blocks stayed, and the replayed blocks were journaled a second
time.

**Fixed:**

- **The journal follows reorgs.** `ExchangeJournal.rollback_to` and `MarketData.rollback_to`
  undo every block above a height: receipts, events, trades, candle updates, last prices.
  Sequence numbers are never reused, so stream subscribers see the new branch as new. A replay
  records only the blocks above the journal's height.
- **Restarts start from a persisted checkpoint.** Every 1,024 blocks of finality
  (`PERSIST_INTERVAL_BLOCKS`), the base checkpoint (the exchange state after a finalized block)
  and the journal are pickled, compressed and stored in `exchange_checkpoint`. The undo journal
  is kept back to that checkpoint. A starting node loads it if its block is still on the chain
  and takes the reorg fast path: undo the database to it, restore the exchange, replay the
  blocks above. Otherwise it falls back to the full replay.
- **The equivalence check still runs.** Every restart compares the rebuilt account and token
  roots with the durable ones, as before. `QRDX_STARTUP_FULL_REBUILD=1` forces the replay from
  genesis, which is the reference the checkpoint path is checked against.

Live: a node restarted at tip 545 replayed 514 blocks from its checkpoint, matched its durable
state and rejoined. Tests: `tests/test_fast_reorg_rebuild.py`. The fast path equals the full
rebuild, journal included, across reorgs and across a restart from the persisted checkpoint;
without the journal rollback the reorg cases fail.

## FIXED — Exchange duties cost O(state) per block

**Severity: medium (scaling; it decided how far sub-second blocks scale).** The state roots no
longer grew with the state, but four per-block exchange costs still did. At 250 ms slots they
were what a busy node would run out of first:

| Duty | Cost before |
|---|---|
| The liquidation scan: equity of every account with a position | 3 µs an account; 29 ms at 10,000, 148 ms (now measured 305 ms) at 50,000 |
| The per-block revert snapshot: a deep copy of the whole exchange for a block with transactions | 11 µs an account; 115 ms at 10,000 |
| Order-book digests: a touched book re-digested whole | 6 ms at 4,000 resting orders |
| Top-of-book reads in the tick: every level's orders summed | 4.3 ms a tick at 4,000 resting orders |

**Fixed:**

- **Liquidation index** (`clearinghouse._LiquidationIndex`). Equity and maintenance are linear in
  the mark, so a position whose margin covers one market (isolated, or an account's only cross
  market) has an exact liquidation price. Those prices are kept sorted per market, and a tick
  checks only the owners whose price the new mark crossed, plus every account with cross
  positions in several markets. It is kept current from the accounts the commitment tracking
  marks. During a pass, owners that a liquidation pushes under join the pass, so the result is
  exactly the full scan's, in the same order. With `QRDX_VERIFY_STATE_COMMITMENTS` (tests, the
  harness) every pass is compared with the full scan on a copy. **8 µs** a tick at 50,000
  accounts.
- **No per-block revert snapshot.** Live paths that see a section fail or mismatch restore
  through the reorg fast path (`main._restore_after_rejected_block`; the proposer through an
  injected hook). Only replays, which must undo a failed section exactly where forward
  application did, still take one.
- **Order books are committed per price level.** Each level's digest is kept, the book holds
  their LtHash, and the entry points mark the levels they change. Owner nonces are a committed
  dict.
- **Top-of-book reads are lazy and best-first** (`OrderBook.iter_levels`): the impact price and
  best bid/ask stop at what they need. A tick: **0.09 ms** at 4,000 resting orders.

Found on the way: **two stop orders could make an exchange section fail.** A triggered stop is
matched as a market order whose fills re-check the triggers. The inner check removed stops the
outer one still listed, and the outer `pop` raised `KeyError` out of the order book, which fails
the whole section.

Tests: `tests/test_liquidation_index.py`, `tests/test_orderbook_digest.py`,
`tests/test_fast_reorg_rebuild.py` (a rejected section undone by the fast path).

## FIXED — Live streams arrived in bursts, not as blocks landed

**Severity: medium (interfaces).** The `/ws` and `/stream` publishers polled: the chain poller
every 2 s, the perps and market-data pollers every 1 s. At 250 ms slots a subscriber got eight
`block` events at once every two seconds, and trades, book changes and marks up to a second
late. A reorg at equal height was never announced: the poller only looked for a taller tip.

**Fixed:** the publishers are event-driven. `block_processing_lock` is a `SignallingLock` that
raises `CHAIN_CHANGED` (`qrdx/node/observability.py`) each time it is released, which is when a
block was applied, proposed or rolled back. The pollers wake on it, with their old interval left
only as a fallback. `block` events carry the block hash. A tip whose hash changed at a height
already announced is published as a `reorg` event (ancestor, its hash, the orphaned hashes),
followed by the new branch's blocks. Measured on the local 250 ms testnet: the median gap between
`block` events is 250 ms, as the blocks are produced. Tests: `tests/test_observability.py`
(signal, latency, reorg detection, the exchange stream waking on a block).

## OPEN — Each block still carries a 3.3 KB signature (was: the chain grew 7 GB a day)

**Severity: low (operations).** At 250 ms slots a node grew by 21.8 KB a block, about 7.5 GB a
day. Three hex fields made most of each 17.8 KB body:

| Part | Size |
|---|---|
| Proposer signature | 6.6 KB |
| RANDAO reveal | 6.6 KB |
| Proposer public key | 3.9 KB |

Vote history kept a second copy of every vote's signature besides.

**Fixed:**

- **Bodies are stored compressed** (`qrdx/block_codec.py`). Hex holds 4 bits a character, so
  zlib recovers about the raw size. Every reader sees the same text, signed and sent unchanged.
- **The proposer's public key is gone from the body.** Importers take it from the chain's key
  registry (`block_verification.verify_block_proposer`), as FFG votes already did. DOUBLE_SIGN
  evidence carries it instead, and a wrong key fails because it must derive to the address.
- **A RANDAO reveal is carried only from 256 blocks before RANDAO selection activates.** Before
  that nothing reads the mix. The reveal is now also verified as the proposer's signature of the
  slot's reveal message: it used to be taken unchecked, so a proposer could have chosen the
  bytes folded into the mix.
- **Vote history is pruned** 256 epochs below finality (`prune_attestation_votes`).

Measured on the local testnet: 7.25 KB a block before the vote-history pruning (about 0.5 KB
less after it), about 2.3 GB a day at 250 ms.

**What remains** is the proposer's Dilithium signature, about 3.4 KB stored, roughly 1.2 GB a
day. Going lower needs one of two choices:

- **Prune finalized signatures on non-archive nodes.** New nodes would then sync history from
  archive nodes, or verify it against finality proofs.
- **Produce no block for an empty slot.** Inclusion latency is unchanged, but votes, oracle
  updates and exchange ticks would have to ride the next block, or a periodic one.

## FIXED — An EVM precompile read a node-local table

The QRDX fork's `getChainState` precompile (0x0200, `py-evm/eth/vm/forks/qrdx/precompiles.py`)
answered from `_oracle_chain_states`, a module-level dictionary. Nothing in the node wrote it, so
it answered zeros everywhere — but anything that ever filled it from a node's own observations
would have made contracts see different values on different nodes: a split. Validators now attest
each bridged chain's finalized head in their oracle votes (two thirds of the stake, heads only
forward: docs/BRIDGE.md "Chain heads"), and the node's EVM answers 0x0200 from that consensus
state, ahead of the fork's table (`evm_world.chain_state_precompile`). Test:
`tests/test_chain_heads.py` (the table is filled with a node's own view, and ignored).

## ACCEPTED — Oracle reporters are trusted (development override only)

Production prices come from the validator oracle (docs/PERPS_CLEARINGHOUSE.md §8). Addresses in
`QRDX_ORACLE_REPORTERS` (a consensus parameter; empty by default) may still set a market's oracle
directly with `UPDATE_ORACLE` — trusted outright, no aggregation — which unit tests and
development setups use. No production network should configure one; the integration testnet no
longer does.

## FIXED — A finality stall longer than the withdrawability delay reopened the slashing window

An exiting validator stayed eligible until the **finalized** epoch reached its `exit_epoch`,
while its principal was paid at head epoch `exit_epoch + WITHDRAWAL_DELAY_EPOCHS`. If finality
stalled for longer than the delay, it could still be eligible when paid, and an offence after
that point would be slashed from a stake already returned.

Fixed with the chain-derived validator set (see "Historical proposer eligibility" above):
eligibility no longer follows finality. A validator leaves the set when the *chain's* epoch
reaches its exit epoch, so it is out a full withdrawal delay before its principal is paid,
however long finality stalls. The delay remains the window for evidence of its earlier offences
to reach a block.

## FIXED — Ejected validators had to claim their principal manually

The stake-floor ejection happened in the asynchronous reconstruction, so it wrote no exit record
on the chain and nothing paid the validator's principal. It had to submit a `STAKE_EXIT` of its
own. The ejection is now part of the validator set's transition, a function of the chain, so
the in-block withdrawals read it and pay the principal like any exit
(`withdrawals._ejected`; `tests/test_validator_withdrawals.py`).

Staking had no wallet support: `STAKE_DEPOSIT` and `STAKE_EXIT` were posted by hand to
`/submit_exchange_tx`. **Fixed (2026-10-12):** `qrdx-wallet stake` now covers it:

- `deposit`, `exit`, `status` and `receipt` (`qrdx/cli/stake.py`): signed with the wallet's PQ
  key for the node's network; a deposit under the minimum is refused before signing; `status`
  shows each validator and the epoch its principal is paid from (`tests/test_stake_cli.py`);
- `commission`, `pools`, `delegate`, `undelegate` and `delegations` for delegation pools
  ([STAKING.md](STAKING.md)).

## ACCEPTED — 20-byte account ids give ~80-bit collision resistance

Deliberate and documented. Grinding two Dilithium keypairs to the same account id is
~2^80 classical work, versus ~2^128 for the 32-byte `0xPQ` form. **This is exactly
Ethereum's own bound** and is the unavoidable price of EVM compatibility: a 32-byte
account cannot be named by a contract, be `msg.sender`, or fit an RLP `to` field.

It does not weaken the post-quantum property that motivates the PQ credential — that is
about *signature forgery* (Shor breaking secp256k1 key recovery), and a Dilithium
signature still authorises every spend. Second-preimage against a *specific existing*
account is ~2^160.

**Do not "fix" this by widening to 32 bytes** — that re-partitions the ledger and undoes
the unification. See [UNIFIED_ACCOUNT_IDENTITY.md §2](UNIFIED_ACCOUNT_IDENTITY.md).

---

## ACCEPTED — Exchange operations are PQ-only senders

`ExchangeTransaction.verify()` binds to a Dilithium key, so a traditional `0x` account
cannot open a perp position, place a CLOB order, or deploy a QRC-20. Native transfers and
contract calls are symmetric between the two account families; exchange operations are
not.

**To close (if wanted):** a secp256k1-signed exchange envelope, or route exchange
operations through contracts so the EVM's own authentication covers them.

---

## ACCEPTED — RANDAO proposer selection is off on small validator sets

RANDAO selection is the chain-spec feature `randao_selection`, off unless a network's spec
schedules it (`QRDX_ENFORCE_RANDAO` survives only as a dev-network override). Safe when
enabled (no halt, no divergence, 0 eligibility rejects) but not cleanly passable on a
3-validator/2-second-slot testnet: K=1 dips on missed slots and K=2 churns on competing
blocks. A small-N, short-slot artifact rather than a consensus bug — schedule it on a
production-scale set or a larger slot ([PROTOCOL_UPGRADES.md](PROTOCOL_UPGRADES.md)).

---

## ACCEPTED — The legacy UTXO ledger is vestigial

`unspent_outputs` is still read as a fallback in `get_address_balance`, but nothing writes
to it: genesis funds every allocation, system wallets included, in `account_state`. Until
2026-10-09 the system wallets were the exception, and that fallback is what hid a
value-creation bug ([below](#fixed-system-wallet-balances-lived-only-in-the-legacy-utxo-ledger)).

`qrdx/transactions/transaction_output.py` cannot represent `0x` or `0xPQ` addresses at all
(it needs base58 secp256k1 curve points). Kept only for legacy reads. Removing the fallback
would make any future gap fail loudly rather than read as a balance.

---

# Test-coverage gaps worth knowing

These are not defects, but they are the reason two real bugs survived a green suite.

* **The integration suite asserts success and convergence, not conservation.** Scenarios
  s06/s15/s17/s18 verify that operations succeed and that state roots agree across nodes.
  A *deterministic* value loss satisfies both — every node loses identically, so no root
  diverges. The `0xPOOL`/`0xCLOB` holder break burned every pool deposit and escrowed
  order through a **19/19 green run**. Conservation assertions are the only thing that
  catches that class: `tests/test_synthetic_holder_accounts.py`,
  `tests/test_evm_value_transfer_conservation.py`, and `scripts/phase_e_invariants.py`
  (post-run, not part of the suite).
* **"Balance decreased" is not an amount check.** `s04` asserted only that the sender's
  balance went down and the recipient's went up, so it passed for years while every
  native transfer moved **twice** the value.
* **An equivalence test with a stand-in executor proves the orchestration, not the
  execution.** Every EVM rebuild-equivalence test replaced the executor with a few lines that
  moved a balance, so nothing exercised contract storage — which the real executor never wrote
  to the database at all. `tests/test_evm_native_token_rebuild.py` drives the real one.
* **A unit test of an RPC module may not test what the node serves.** `qrdx/node/main.py`
  registers its own `eth_call` and `eth_sendRawTransaction` handlers over `EthModule`'s, so
  module tests passed while the node's `eth_call` refused every standard call. Test what
  `main.rpc_server` dispatches, or drive the method over a live node (S20 does).
* **Per-item `try/except` around a value-bearing write hides loss.** Both flushes now log
  at ERROR with a `[VALUE-LOST]` marker, so a log scan or soak surfaces a dropped delta
  instead of it blending into warning noise.
* **An equivalence test passes when nothing happens.** The "rich honest chain" in
  `tests/test_reorg_rebuild_equivalence.py` carried a `CREATE_MARKET` without its required
  `base_token` and an `ADD_LIQUIDITY` without `pool_id`. Both failed non-critically on
  *both* paths, the roots matched, and perp margin and liquidity went untested behind a
  green result. The test now asserts the position and the liquidity actually landed;
  every equivalence chain should assert its operations took effect, and each new one
  here ships with a sensitivity test showing the old code diverges on it.
* **Synthetic fixtures miss real formats.** The interleaved rebuild passed every unit test
  and crashed on the first real chain, because real genesis stores a `datetime` timestamp
  and the fixtures used integers. Replaying a soak node's database offline with the real
  executor is cheap (seconds) and caught it; do it before wiring anything that rewrites
  derived state.
* **Soak database snapshots must include `-wal` and `-shm`.** Nodes run SQLite in WAL
  mode; copying only `nodeN.db` captures the last checkpoint, not the node's state. One
  such snapshot showed an empty `account_state` on a node that was in fact byte-identical
  to its peers.

---

# Recently fixed (for orientation)

| Issue | Where |
|---|---|
| Exchange duties cost O(state) per block (liquidation scan, revert snapshot, book digests, top-of-book reads); two stop orders could fail a section | [below](#fixed-exchange-duties-cost-ostate-per-block) |
| Restarts replayed derived state from genesis, and fast reorgs kept orphaned exchange history | [below](#fixed-restarts-replayed-derived-state-from-genesis-and-fast-reorgs-kept-orphaned-history) |
| Each block carried 17 KB of hex (key, unused RANDAO reveal, signature); the chain grew 7.5 GB a day | [below](#open-each-block-still-carries-a-33-kb-signature-was-the-chain-grew-7-gb-a-day) |
| A proposer could build on an all-zero parent during a reorg | [below](#fixed-a-proposer-could-build-on-an-all-zero-parent-during-a-reorg) |
| Fork choice let a branch carrying the votes for a shared checkpoint beat a taller one (a lone validator never rejoined) | [below](#fixed-fork-choice-let-a-branch-carrying-the-votes-for-a-shared-checkpoint-beat-a-taller-one) |
| A peer that dropped out came back without a URL, so the network stayed split after a validator restart | [below](#fixed-a-peer-that-dropped-out-came-back-without-a-url-and-the-network-stayed-split) |
| A sync aborted as "fatal", and penalized its peer, over blocks pushed while it ran | [below](#fixed-a-sync-aborted-as-fatal-and-penalized-its-peer-over-blocks-pushed-meanwhile) |
| The local testnet forked at 250 ms: nodes could not push blocks to each other (one bootstrap peer, staggered start) | [below](#fixed-the-local-testnet-forked-at-250-ms-its-nodes-could-not-push-blocks-to-each-other) |
| A validator proposed and voted before its first sync (a restarted validator forked the chain) | [below](#fixed-a-validator-proposed-and-voted-before-its-first-sync) |
| Validator rewards and penalties accrued per epoch, so 8 s epochs would have run them 8 times as fast | [below](#fixed-validator-rewards-and-penalties-accrued-per-epoch-not-per-unit-of-time) |
| Finality was not bound to a branch: two forks could both finalize (now Casper FFG) | [below](#fixed-finality-was-not-bound-to-a-branch-two-forks-could-both-finalize) |
| Forks were resolved only every 8 s, under two rules that disagreed | [below](#fixed-forks-were-resolved-only-every-8-s-under-two-rules-that-disagreed) |
| A reorg replayed derived state from genesis (now an undo journal) | [below](#fixed-a-reorg-replayed-derived-state-from-genesis) |
| The proposer selected from a validator set frozen at startup | [below](#fixed-the-proposer-selected-from-a-validator-set-frozen-at-startup) |
| State roots were recomputed from all state every block (now incremental) | [below](#fixed-state-roots-were-recomputed-from-all-state-every-block) |
| Block time grew with the chain (2 s → 14.5 s on the testnet): consensus helpers re-read history every call | [below](#fixed-block-time-grew-with-the-chain) |
| A genesis validator's top-up deposit was re-applied at every rebuild (its stake grew each finalized epoch) | [below](#fixed-a-genesis-validators-top-up-was-re-applied-at-every-rebuild) |
| The peer RPC transport was unauthenticated (any peer could claim any identity) | [below](#fixed-the-peer-rpc-transport-was-unauthenticated) |
| CI's lint and type checks had never passed, and hid real bugs; shipped dependencies had known vulnerabilities | [below](#fixed-cis-static-checks-had-never-passed-and-hid-real-bugs) |
| Release images were neither reproducible nor signed, and never ran the tested dependency versions | [below](#fixed-release-images-were-neither-reproducible-nor-signed) |
| Locally built images could contain the node's private key | [below](#fixed-locally-built-images-could-contain-the-nodes-private-key) |
| System-wallet balances lived only in the legacy UTXO ledger (a debit through the balance flush was dropped) | [below](#fixed-system-wallet-balances-lived-only-in-the-legacy-utxo-ledger) |
| Governance was not connected to consensus; one key controlled the system wallets forever | [below](#fixed-governance-was-not-connected-to-consensus) |
| No way to change a consensus rule after launch; consensus parameters set per node by environment | [below](#fixed-there-was-no-way-to-change-a-consensus-rule-after-launch) |
| Consensus signatures were not bound to a network (cross-network slashing replay) | [below](#fixed-consensus-signatures-were-not-bound-to-a-network) |
| Transactions signed for any chain (or none) executed here | [below](#fixed-transactions-signed-for-any-chain-executed-here) |
| Genesis did not identify the network (accounts uncommitted, random RANDAO seed, silent fallback genesis) | [below](#fixed-genesis-did-not-identify-the-network) |
| Native transfers moved 2× the value | [UNIFIED_ACCOUNT_IDENTITY.md §5](UNIFIED_ACCOUNT_IDENTITY.md) |
| Plain transfers were free (no gas charged) | same |
| Account nonce never advanced → web3 clients broke on their 2nd tx | same |
| `0x` ↔ `0xPQ` transfers impossible | [UNIFIED_ACCOUNT_IDENTITY.md](UNIFIED_ACCOUNT_IDENTITY.md) |
| Validator stake never checked or debited (consensus capture from a zero balance) | [EXCHANGE_AND_VALIDATOR_STAKE_AUDIT.md §3](EXCHANGE_AND_VALIDATOR_STAKE_AUDIT.md) |
| Orphaned deposit kept its registration and stake weight | same, §3.6 |
| The proposer built blocks in the middle of a derived-state rebuild | [below](#fixed-the-proposer-built-blocks-in-the-middle-of-a-derived-state-rebuild) |
| `eth_sendTransaction` executed outside consensus | [below](#fixed-eth_sendtransaction-executed-outside-consensus) |
| The EVM saw a constant block context (`block.timestamp` = `block.number` = 1) | [below](#fixed-the-evm-saw-a-constant-block-context) |
| E-D4 bound nothing: a block rejected live re-entered through sync | [below](#fixed-e-d4-bound-nothing-a-block-rejected-live-re-entered-through-sync) |
| Fork-choice reconciliation failed on 24 of 41 attempts | [below](#fixed-fork-choice-reconciliation-failed-on-24-of-41-attempts) |
| Any user could mint unlimited QRDX through perp positions | [below](#fixed-any-user-could-mint-unlimited-qrdx-through-perp-positions) |
| Exchange rules judged time by the node's wall clock | [below](#fixed-exchange-rules-judged-time-by-the-nodes-wall-clock) |
| Any validator could get any other validator slashed | [below](#fixed-any-validator-could-get-any-other-validator-slashed) |
| Stake forfeiture read node-local state; principal was paid while still eligible | [below](#fixed-stake-forfeiture-read-node-local-state-principal-was-paid-while-still-eligible) |
| A restarted node replayed exchange history with every enforcement gate off | [below](#fixed-a-restart-replayed-exchange-state-without-enforcement) |
| The rollback rebuild replayed state domains out of forward order | [below](#fixed-the-rollback-rebuild-replayed-state-domains-out-of-forward-order) |
| E-D4 rejected a bad block but kept its effects | [below](#fixed-e-d4-rejected-a-bad-block-but-kept-its-effects) |
| Block history did not converge — nodes on genuinely different chains | [below](#fixed-block-history-did-not-converge) |
| EVM state lived in a per-node trie (storage never persisted, third-party payments lost) | [below](#fixed-evm-state-lived-in-a-per-node-trie) |
| Exchange operations were free | [below](#fixed-exchange-operations-were-free) |
| `eth_call` failed for every standard web3 client | [below](#fixed-eth_call-failed-for-every-standard-web3-client) |
| Nodes started from one directory shared peer and DHT state | [below](#fixed-nodes-started-from-the-same-directory-shared-peer-and-dht-state) |
| Spot exchange: liquidity could be stolen or lost, pools moved for free, replays diverged | [below](#fixed-spot-exchange-liquidity-could-be-stolen-or-lost-pools-moved-for-free-replays-diverged) |
| Staked principal never returned on exit (and three bugs behind it) | [below](#fixed-staked-principal-never-returned-on-exit) |
| `--from-system-wallet` sends had no working path | [below](#fixed-system-wallet-sends) |
| `eth_estimateGas` under-reported for PQ transactions (every PQ tx refused) | [below](#fixed-estimategas-ignored-the-pq-intrinsic-floor) |
| Failed transactions were free and infinitely retryable at one nonce | [below](#fixed-failed-transactions-cost-nothing) |
| No maintenance stake threshold — validators could decay to zero and keep their slot | [below](#fixed-no-maintenance-stake-threshold) |
| Transaction replay after a node restart (double-spend) | [below](#fixed-transaction-replay-after-a-node-restart) |
| Pool reserves + CLOB escrow silently burned every token moved into them | same, §1.3(b) |
| Malformed `TOKEN_TRANSFER` recipient burned tokens | same, §1.3(a) |

---

## FIXED — A proposer could build on an all-zero parent during a reorg

**Severity: medium (liveness).** The proposer read the next height and then the tip block, in two
steps before taking the block-processing lock. Under the lock it re-checked only the height. A
reorg in between could remove the tip and apply another block at the same height, so the
height still matched, but the tip had been read as missing. The block was then built on an
all-zero parent, stored, and broadcast, and every peer refused it. Seen once in the 250 ms
integration run.

**Fixed:** under the lock the proposer re-reads the tip, and skips the slot unless it is exactly
the parent the block is built on. Tests: `tests/test_proposer_production_lock.py`.

## FIXED — Fork choice let a branch carrying the votes for a shared checkpoint beat a taller one

**Severity: high (liveness).** Fork choice first compared each branch's latest justified epoch,
computed from the votes that branch's own blocks carry. A checkpoint below the fork is in both
chains, but its votes ride whichever blocks included them. On the 250 ms integration run, one
validator was briefly cut off and ended on its own branch. That branch carried all three
validators' votes for epoch 14's checkpoint (height 331, below the fork at 338); the network's
branch was missing that validator's vote. The lone branch therefore scored "justified 14"
against "justified 9" and never rejoined the network, 162 blocks taller. With three equal
validators, justification needs all three votes, so finality stopped.

**Fixed:** a justified checkpoint decides only if it is above the fork, in one chain alone
(`ffg.prefer(candidate, current, ancestor)`; scores now carry the justified checkpoint's
height). A checkpoint below the fork is held by both chains and decides nothing, so height does.
The node then re-includes its orphaned votes on the chain it joins. Replaying the stuck node's
database with the new rule picks the network's branch. Tests: `tests/test_fork_resolution.py`.

## FIXED — A peer that dropped out came back without a URL, and the network stayed split

**Severity: high (liveness).** A node drops a peer it cannot reach. When the peer came back it
connected in, and a peer that connects in is recorded without a URL, because a private node
advertises none. The node could then neither push blocks to it nor resolve a fork with it (the
resolver fetches from the peer's URL). It never re-learned the URL either: it re-bootstrapped
only when it had no connectable peer at all. On the 250 ms testnet, a validator restarted for
10 s ended up on its own branch for good, and finality stopped, because each of the two
validators voted for its own branch's checkpoint.

**Fixed:**

- A dropped peer's URL, verified by the handshake it was learned in, is remembered (up to 256
  peers). When that peer next connects in, it is dialled back (`main._dial_back_if_known`, at
  most every 5 s), which records the URL again. Measured: all three peers restored it within
  3 s of the restart, and finality resumed.
- The 30 s discovery pass also re-handshakes any configured bootstrap node that no peer entry
  reaches.

Tests: `tests/test_peer_dialback.py`.

## FIXED — A sync aborted as "fatal", and penalized its peer, over blocks pushed meanwhile

**Severity: medium (liveness, peer reputation).** At 250 ms slots, blocks pushed by peers keep
arriving while a sync fetches a batch, so the batch's first blocks were often already here when
it was applied. The sync tried to apply them again and failed on the height. It then aborted
with "FATAL ERROR", and recorded a severity-8 violation against the honest peer it was syncing
from.

**Fixed:** a block the node already holds is skipped. A different block at a height the node
holds stops the sync without a penalty and hands the decision to fork choice. So does a next
block whose parent is not the node's tip, which happens when the peer reorgs between the sync's
check and its batch. Tests: `tests/test_sync_race.py`.

## FIXED — The local testnet forked at 250 ms: its nodes could not push blocks to each other

**Severity: high (testnet liveness).** `scripts/testnet.sh` gave every node node 0 as its only
bootstrap peer, and started the nodes 5 s apart. A node records a peer that only connects in
without a URL (a node advertises one only when public), and pushes blocks only to peers with a
URL. So validator 1's blocks never reached validator 0 by push, and validator 0's reached
validator 1 over three hops. Each validator then proposed in the other's slots as the backup,
on its own branch:

- fork choice repaired the split every few seconds, with rollbacks of about 30 blocks;
- FFG justified almost nothing, because each validator voted for its own branch's checkpoint;
- a validator that started 9 s after genesis forked off at height 1.

Peer and routing state from earlier runs (`databases/node<i>.p2p`) also survived a restart.

**Fixed (in the script):**

- Every node lists every other node as a bootstrap peer, a full mesh as in the integration
  harness.
- All nodes start together, and genesis is set 15 s plus 1 s per node ahead, so the mesh has
  formed before the first slot.
- Each start wipes the per-node database and peer state.
- The slot is a `--slot-ms` option (default 250), written into the genesis chain spec.

Measured with 4 nodes and 2 validators: 120 blocks in 30.0 s (0.250 s per block, no missed
slots), no fork switches, and every node finalizing together about 12 s behind the tip.

**Still true of the node:** a peer that only connects in is never pushed to. A public network is
unaffected, because its nodes advertise URLs, but a private node relies on its configured
bootstrap list.

## FIXED — A validator proposed and voted before its first sync

**Severity: medium (liveness).** A validator started producing as soon as it booted. One that
joined late, or restarted behind the network, built blocks on its stale tip (seconds of them at
250 ms). They forked the network until fork choice undid them, and the validator spent its one
FFG vote of the epoch on a checkpoint of that stale chain.

**Fixed:** the validator node's guard (`main._validator_wait_reason`) holds proposals and votes
until the post-bootstrap sync check has run, and until any sync it started has finished. With
no reachable peer there is nothing to wait for, and the wait never exceeds 120 s. A vote held
back is cast in a later slot of the same epoch. Tests: `tests/test_fork_choice_adoption.py`.

## FIXED — Validator rewards and penalties accrued per epoch, not per unit of time

**Severity: medium (economics).** Each finalized epoch moved every active validator's effective
stake by 0.01%. At 250 ms slots an epoch is 8 s instead of 64 s, so stake would have moved 8
times as fast per day. An offline validator would have lost half its stake, and been ejected,
after about 15 hours instead of 5 days.

**Fixed:** the rate is 0.01% per 64 s of chain time, so each 8 s epoch carries an eighth
(`epoch_rewards.reward_quotient`, integer arithmetic from the chain spec). The other parameters
with a duration are sized for 250 ms slots in `chain_spec.PARAMS`:

| Parameter | Standard value | Wall-clock time |
|---|---|---|
| Governance voting period | 2,419,200 blocks | 7 days |
| Governance timelock | 691,200 blocks | 2 days |
| Governance execution window | 2,419,200 blocks | 7 days |
| Unbonding period | 40,320 epochs | ~3.7 days |
| Withdrawal delay | 2,048 epochs | ~4.6 hours |
| Master-controller sunset | height 800,000 | ~2.3 days |

Activation delay and the fork-approval lead stay depths (4 epochs, 256 blocks). Tests:
`tests/test_epoch_rewards.py`.

## FIXED — Finality was not bound to a branch: two forks could both finalize

**Severity: critical (safety).** Finality justified epoch *E* once ⅔ of the stake had voted
for *E*, whichever branch the voted block was on, and validators voted every slot for whatever
head they saw. A validator that switched forks therefore supported both branches, legitimately.
When a fork outlived the finality lag, both branches finalized different blocks at the same
height, and the reorg guard made the split permanent.

At 250 ms slots, within 30 s of an idle run, nodes {0, 1} and {2, 3} had each finalized their
own branch: 31 refused reorgs and a 47-block spread. At 2 s a network partition of about 30 s
would have done the same.

**Fixed: Casper FFG** (`qrdx/validator/ffg.py`):

- **Checkpoint-bound votes.** A vote names a source and a target checkpoint (epoch and block
  hash), both signed. A validator casts one vote per epoch, at a fixed point in it
  (`vote_slot`). Its signing record (`SigningRecord`, persisted) refuses a second, different
  vote for one target, or a surrounding one, even across restarts. Both are slashable
  (`slashing_block.attestation_equivocation`).
- **Votes validated on import.** A block is accepted only if every carried vote checks out
  (`verify_block_votes`): the key from the chain-derived registry, a valid signature, and a
  target that is this chain's checkpoint. Every import path runs the check. The proposer
  includes only votes valid for, and not already on, its own chain, so a vote that rode an
  orphaned block is included again.
- **Justification from canonical votes.** A checkpoint is justified when ⅔ of the voting stake
  voted for it from a source justified on the same chain. *t−1* is finalized when ⅔ voted the
  link *t−1 → t* exactly. Every input comes from the chain index, so every node holding the
  chain computes the same finality. The computation resumes from the stored finalized
  checkpoint.

Two branches can now finalize conflicting checkpoints only if ⅓ of the stake signs slashable
votes. A side effect: blocks carry about 0.3 votes instead of one per validator per slot.

**A bug found while building it:** each node's vote store did not keep the new roots, so seeing
an honest vote a second time (re-included after a reorg) looked like a double vote. All three
testnet validators were slashed within minutes. The store keeps the roots now, votes without
roots are never compared, and the detector records only evidence that verifies
(`tests/test_surround_vote_detection.py`). Tests: `tests/test_finality_compute.py` (14),
including two branches with honest validators that cannot both finalize.

## FIXED — Forks were resolved only every 8 s, under two rules that disagreed

**Severity: high (liveness).** A node on a losing branch stayed there until a periodic pass,
about every 8 s. Sync took the longer chain, while the pass took the lower hash at the first
divergent height, so the two rules could move nodes in opposite directions. Sync and the pass
also rolled back before fetching the competing branch, so a branch with a bad block left the
node on a partial chain.

**Fixed:** one fork-choice rule (`ffg.prefer`), Casper FFG's and then the longest chain. A
chain holding the newest justified checkpoint is never left for one that does not hold it. When
both chains hold it, because it lies below the fork, the taller chain wins, then the lower tip
hash. One resolver applies it (`main.resolve_fork_with_peer`):

1. Find the common ancestor in one exchange of block hashes (`p2p_getBlockHashes`). It is never
   searched for below the finalized checkpoint.
2. Fetch the peer's branch and score it from its own blocks. A peer's claims are never trusted.
3. Roll back and apply only if the branch wins. If one of its blocks is refused, restore our
   own branch. The tip check, rollback, apply and restore all happen under one hold of the
   block-processing lock. The 250 ms suite caught a block pushed over p2p landing between the
   rollback and the apply: the branch then no longer fit on the tip, and our own branch could
   not be restored either. If the chain moved while the branch was being scored, the switch is
   abandoned, and the next competing block triggers it again.

It runs at once when a peer sends a block that does not extend our tip, and the periodic pass
stays as a backstop. Tests: `tests/test_fork_resolution.py`.

## FIXED — A reorg replayed derived state from genesis

**Severity: high (scaling).** Every reorg, and every rejected block, rebuilt all derived state by
replaying the whole chain: ~26 µs a block, about 9 s after one day of 250 ms blocks.

**Fixed:**

- **Undo journal.** SQLite triggers record every change a block makes to the derived tables,
  under its height (`qrdx/undo_journal.py`).
- **Exchange checkpoints.** The exchange state is checkpointed when a block opens an epoch.
- **The fast path** (`derived_state_rebuild.rebuild_to_tip`). A rollback undoes the journal to
  the newest checkpoint at or below the new tip, restores the exchange from it, and replays only
  the blocks above. The cost is the changes since that checkpoint plus less than an epoch of
  blocks, not the chain.
- **Safety net.** Every block-application path records its writes. A write to those tables
  outside any block is recorded as unattributed, and while one exists the full rebuild is used
  instead. The journal is pruned below the finalized checkpoint.

Tests: `tests/test_fast_reorg_rebuild.py` checks that the fast path equals the full rebuild —
every row, the state commitments and both exchange roots — across successive reorgs onto
different branches.

## FIXED — A proposer could fill several heights from one slot

**Severity: medium (consensus).** Eligibility bound a proposer to a slot, but nothing compared
the slot with the chain. One eligible proposer could sign a run of blocks all claiming its slot,
or claim future slots.

**Fixed:** every import path refuses a block whose slot is not later than its parent's, or that
is more than about a second ahead of the clock (`verify_slot_progression`). The proposer skips a
slot that is not after its tip's. Tests: `tests/test_slot_progression.py`.

## FIXED — The proposer selected from a validator set frozen at startup

**Severity: high (liveness).** The proposer's validator set was built once, when the node
started. Importers check eligibility against the validators table as it is. Every finalized
epoch changes the table (rewards and penalties move stakes; validators join and exit), so the
proposer chose from a set its peers no longer used. It proposed in slots they assigned to
someone else, its blocks were refused, and the chain forked. This was the main cause of
sub-second instability, and after a validator joined the testnet it split the 2 s network too.

**Fixed:** the set is rebuilt from the table every slot, exactly as importers build it
(`ValidatorNode._refresh_validator_set`; `tests/test_proposer_validator_set.py`). With this and
the fixes above, an idle 250 ms testnet ran 482 consecutive slots at exactly 0.250 s: no missed
slot, no reorg, nodes within one block. Before, the same run had 218 missed slots, a 47-block
split and 31 finality conflicts.

## FIXED — State roots were recomputed from all state every block

**Severity: high (scaling).** Every block hashed every entry of every state domain, in order.
The proposer and each importer did this at least twice per block (the EVM section's account
root, then the unified root):

| Domain | Cost before |
|---|---|
| Account/contract-storage root | ~1.4 µs per account: 74 ms at 50,000 |
| Exchange root | 42 ms at 10,000 perp accounts and nonces; 296 ms at 50,000 |
| Token root, UTXO hash | likewise |

The exchange root was the worst: one JSON document of every account, order, LP position,
allowance and nonce.

**Fixed (chain-spec feature `incremental_state_root`, on from genesis for networks this release
creates):** every domain commits to its state with an LtHash accumulator (`qrdx/crypto/lthash.py`;
1024 × 16-bit lanes, BLAKE3 output, the construction Solana uses for its accounts). Adding an
entry adds its vector and removing one subtracts it, so a root costs what changed:

- **Database domains** (`qrdx/state_commitment.py`). SQLite triggers fold every
  `account_state`, `contract_storage`, `token_balances` and `unspent_outputs` change into the
  domain's accumulator, inside the writing statement's transaction, so a rollback takes the
  change with it and no write path can bypass it. Startup recomputes each accumulator from its
  rows and repairs any that disagree.
- **Exchange** (`qrdx/exchange/commitment.py`). Keyed collections are `CommittedDict` /
  `CommittedSet`. Each keeps a 32-byte digest per entry and re-digests only entries that may
  have changed. That covers clearinghouse accounts and the vault, nonces, tokens, allowances,
  frozen sets, NFTs, proposals, and pool ticks and positions. Tracking is conservative: a write
  marks its key, and handing out a mutable value marks it too. Only explicit `peek` reads (the
  liquidation scan, the invariant sums) leave a value unmarked, so a missed conversion costs
  time, never correctness. Order books and pools keep a digest that their own mutating entry
  points invalidate.

After: at 10,000 or at 50,000 accounts, a block that changes nothing costs 0.2 ms of exchange
root, and one that changes 40 entries about 1 ms. An account-root update plus the root takes
under 10 ms at 20,000 accounts in a test bound.

**How it is checked:**

- `QRDX_VERIFY_STATE_COMMITMENTS=1` checks every incremental exchange root against a
  from-scratch recomputation. The test suite runs that way, about 700 checks over real exchange
  states. It caught one test that edits a book's private fields, which is exactly what it is
  for.
- `tests/test_state_commitment.py`: the triggers equal the rows across randomized writes,
  rollbacks, REPLACE, upserts and clears; roots are independent of write order; startup repair.
- `tests/test_exchange_commitment.py`: marking rules, copies, order independence, a quiet block
  re-digests no account, gating by height.

## FIXED — Block time grew with the chain

**Severity: critical.** On test.qrdx.org the block time drifted from 2.0 s at genesis to 14.7 s
at height 74,600. By then two of every three slots were missed. Only one validator was
proposing, so this was not competition: every block cost the node more work than the one
before. Several consensus helpers recomputed their answer from genesis on every call:

| What | How often | Cost per call |
|---|---|---|
| RANDAO mix (`compute_randao_mix`) | twice per fork-choice pass (~10 s); per slot and per import once RANDAO selection is on | every block body fetched and parsed |
| Validator reconstruction | every finalized epoch | two such walks, then every epoch replayed from genesis |
| `update_finality` | every imported block, and every 2 s | every epoch since genesis re-evaluated and rewritten, one commit each |
| `finalized_block_height` | every import, every fork-choice pass | every vote ever, plus one query per distinct block |
| `slashed_on_chain` | per exit payout | `LIKE` over every block body |

A block body is ~60 KB (Dilithium signatures). One walk at 75,000 blocks parses ~4.5 GB with
`ast.literal_eval`, ~0.6 ms per block, on the event loop. That starved block production.

**Fixed:**

- **Chain index** (`qrdx/chain_index.py`). Each block is parsed once into compact rows: slot,
  epoch, running RANDAO mix, stake ops, votes, and the offenders its verified slashing proofs
  convict. It is extended lazily and is reorg-safe: a block's hash commits to its ancestry,
  so the index is trusted up to the highest height whose hash still matches. Index writes
  join the current transaction. It is brought up to date at startup, before the validator
  runs.
- **Validator reconstruction** resumes from per-epoch snapshots. It restores the latest one,
  or an earlier one when newly finalized blocks add an attester to an epoch already processed,
  when slashing evidence for such an epoch was recorded, or when the chain changed below a
  snapshot. The result equals the full rebuild exactly, checked at every finality step on
  randomized histories with late votes, late evidence, reorgs and restarts.
- **Finality** is monotonic, so it is computed only from the latest finalized epoch or height
  onward, and only changed rows are written.
- **Slot clock.** The proposer and attester loops slept a fixed slot *after* their work, so
  each iteration took the slot plus the work: a lone validator's block time was 2 s plus
  everything above, and grew with it. The loops now wake at slot boundaries computed from the
  genesis time (attestations at a third of the slot), so work that fits in a slot no longer
  lengthens it (`tests/test_validator_slot_clock.py`).
- **Derived-state rebuild** (every reorg and every restart) read every block body and probed
  both section tables per height to find the few blocks that carry transactions: 0.42 ms per
  block, ~32 s at 75,000 blocks. It now reads hashes and timestamps in one query and the set
  of blocks with sections in one more: 0.026 ms per block, ~2 s at 75,000. What is replayed
  is unchanged. The rebuild is still linear in the chain; see the open entry below.
- **The transaction indexer held the block-processing lock** while it re-read the last 64
  blocks in full, about 45 KB of signatures each, every second, only to compare their hashes.
  That was ~100 ms a second during which the proposer could not build. It now reads the
  window's hashes in one query (`get_block_hashes`). The parent check on import, the
  fork-choice window, the attestation loop and the proposer read headers only
  (`get_block_header`).
- **Smaller costs.** Every signed peer request rewrote the peer store (`nodes.json`) to record
  the peer's `last_seen`, a third of an idle node's event-loop time; it is now written at most
  once a minute (`tests/test_nodes_manager_last_seen.py`). Observe-only RANDAO logging in the
  fork-choice pass is removed. HTTP access logs moved to DEBUG (two INFO lines per request
  through the rich console were a measurable share of the event loop).

Steady-state costs at 2,000 and 16,000 blocks: the RANDAO mix 1 ms, selection 2 ms, finality
2 ms and 1 ms, reconstruction 8 ms per epoch. Each was linear in the chain before. On the
4-node, 3-validator integration testnet, all 23 scenarios pass, and once they finish every
block lands exactly one 2 s slot after the last, with no missed slots. The event loop is about
11% busy. With 1-second slots (`SLOT_DURATION_MS: 1000` in the chain spec, or
`QRDX_SLOT_DURATION_MS=1000` for the harness) the suite also passes. Blocks then land exactly 1.00 s
apart at about 8% event-loop load; that is after the peer-store fix, and the 2 s figure was
measured before it. This run exposed the push-sync defect below. Tests:

- `tests/test_chain_index.py`: every indexed answer equals the original walk, across reorgs
  and a rollback;
- `tests/test_validator_reconstruction_incremental.py`.

## FIXED — Push-sync never delivered a PoS block, and stranded the node it targeted

**Severity: high (liveness of joining nodes).** When a node falls behind, a peer that is ahead
pushes the missing blocks to it (`_push_sync_to_peer` → `p2p_submitBlocks`). Three defects
combined:

1. The pushed items carried no block hash, proposer or timestamp. `p2p_submitBlocks` routes a
   block to the PoS import path only when both the hash and the proposer are set, so it handed
   every pushed block to the legacy PoW parser, which failed on it. A push of a PoS chain never
   delivered a block.
2. The pusher counted each refused push as a violation by the receiver (−30). After four, the
   receiver was banned, and a banned node's handshake is refused.
3. Peers learned only from their own requests are private and have no URL. A node knowing only
   such peers never re-bootstrapped: that happened only when the peer list was empty.

Together, a node that started a few blocks behind was pushed to, banned by every validator,
and left at height 0 with no peer it could pull from. With 2-second slots, a joining node
usually completed its handshakes before the validators pushed to it, which hid the problem.
With 1-second slots it lost that race on the first start.

**Fixed:** pushed items carry the hash, proposer and timestamp, and the receiver imports them
with live enforcement (slot eligibility included), so a push cannot bypass a check that a
broadcast faces. A refused push is logged, not held against the receiver. A node with no
connectable peer re-bootstraps from its configured nodes every 30 s.
`tests/test_push_sync.py` covers each defect and fails on the old code.

## FIXED — A genesis validator's top-up was re-applied at every rebuild

**Severity: high (consensus divergence).** The validator reconstruction reset to a "genesis
base" it read from the live table (`activation_epoch = 0` rows). `register_pending_validator`
tops up any existing row, so a genesis validator that deposited more stake had that deposit in
its base. Every rebuild, one per finalized epoch, applied it again on top. Its stake grew every
epoch, and by a different amount on each node, depending on how many rebuilds each had run.

**Fixed:** genesis initialisation records the genesis set immutably (`chain_metadata`
`genesis_validators`), and the reset reads that record. A database from before the record
existed derives the set once and records it. Found by the incremental-reconstruction
equivalence test.

## FIXED — The peer RPC transport was unauthenticated

**Severity: medium.** Node-to-node JSON-RPC carried no signature.

- **Handshake.** `p2p_handshakeResponse` consumed a challenge without checking who answered it.
  The answering node's id and public key were taken on its word, and it was added as a peer.
- **Signed REST requests.** The node id they claimed (`x-node-id`) was never checked against
  the key that signed them, so a peer could sign with its own key and claim any node's id.
- **Pushed blocks.** A block named the node the receiver should follow-up-sync from
  (`_sender_node_id`).

**Fixed:**

- **Signed calls.** Every call a node makes to a peer is signed with its Dilithium identity
  over the exact bytes sent, a timestamp and a nonce (`NodeInterface._rpc_call`).
- **Verified at the endpoint.** `/rpc` (`node/main.py rpc_endpoint`) verifies the signature,
  the replay and timestamp window, and the ban list. It accepts a node id only if it is the
  BLAKE3 of the presented key, which also closes the REST gap. A forged, tampered or replayed
  signature is refused on any call.
- **Peer-only methods.** Methods marked `@peer_only` are refused without a verified caller:
  block and block-batch submission, transaction and attestation push, and both handshake steps.
  The RPC server enforces this itself, so no transport can bypass it. Reads stay open, because
  what they return is verified by whoever uses it.
- **The verified caller.** It reaches RPC methods as `rpc_caller`. Follow-up sync uses it,
  never a node named in the payload.
- **Mutual handshake.** A challenge can be answered only by the node it was issued to. The
  answering node proves its identity by signing the caller's fresh nonce together with the
  challenge and every claim it makes (id, key, URL, network), under a per-network signing
  domain (`p2p-handshake`). The caller adds a peer only on a valid proof.
- **REST handshake removed.** The REST pair (`/handshake/challenge`, `/handshake/response`)
  is gone, rather than left as a weaker second way in.

Tests: `tests/test_peer_rpc_authentication.py`.

## FIXED — CI's static checks had never passed, and hid real bugs

**Severity: high.** The Lint, Type check and Security jobs had failed on every run, and the test
jobs behind them never ran.

- **Lint.** 4,393 ruff findings; black would have reformatted 150 of 163 files.
- **Type check.** mypy reported 722 errors, and the job never even installed mypy
  (`pip install -e .[dev] --no-deps`).
- **Security.** `gitleaks-action@v2` needed a paid license for organisation repositories (the
  secret scan has since been removed), and `pip-audit` audited `requirements.txt` (not what ships)
  and ended in `|| true`.

**Real bugs found while clearing them:**

- **Endpoints that always failed.** `/get_recent_transactions` and `/get_recent_blocks`
  raised `TypeError` on every SQLite call (missing `offset`).
- **`InsufficientStakeError` was unreachable.** It was raised with a keyword it did not
  accept, so callers got `TypeError` instead.
- **`qrdx_submitBlock`.** Its fallback path would have reported success for a block nothing
  validated or stored. It now refuses.
- **The state checkpoint.** It called `bytes.fromhex` on bytes (`TypeError`).
- **Bridge scanners.** `BridgeRecord` was built without its operation, and the ETH and SOL
  scanners crashed on undecoded amounts.
- **Signing.** `ContractTransaction.sign` and `verify_signature` called the signing helpers
  with the wrong arguments. `transactions/validation.py` called a `PublicKey.from_bytes` that
  does not exist.
- **Missing APIs.** `PQWallet.from_seed` called an API that was deliberately removed.
  `compute_contract_address` imported from the wrong module.
- **Handshake crashes.** The handshake state machine crashed on out-of-order messages.
- **Discovery.** A cancelled lookup (`BaseException`) was iterated as a result.

Other fixes:

- **Formatting.** The code base is black/isort formatted, and ruff and isort agree on import
  grouping.
- **Exceptions.** Raised exceptions chain their cause (B904).
- **Dead code.** 259 unused imports were removed, checked against every cross-module import.
- **mypy.** mypy is clean against the dependency versions the image ships.

CI (`.github/workflows/ci.yml`) now runs as follows:

- **Pinned tools.** It installs every tool from a hashed lock (`release/lint-requirements.lock`)
  and type-checks against the shipped dependencies.
- **pip-audit.** It audits `release/requirements.lock`, and a finding fails the build.
- **Tests.** It runs the unit suite, and the integration suite for pull requests to main,
  **inside the node image built from the commit**.

The pytest integration wrapper (`tests/test_testnet_integration.py`) could never have passed.
It ran each scenario through a fresh runner, so every scenario after the first was skipped for
"unmet dependencies", and it covered only 13 of the 23 scenarios. It now runs the canonical
suite once and reports each scenario. Inside the image it passed 24/24: the testnet came up
ready and all 23 scenarios passed.

**The audit found nine vulnerable packages in the lock:** cryptography, urllib3, starlette,
requests, anyio, idna, pygments, python-dotenv and fastecdsa. All are upgraded. fastecdsa is
held to the 2.3 line, because 3.0 rejects the `str` messages `transaction_input.py` verifies.
The unit suite passes inside an image built with the upgraded set.

## FIXED — Release images were neither reproducible nor signed

**Severity: critical for mainnet.**

- **Unverifiable.** No two builds of the image were the same, and nothing was signed. An
  operator could not tell a genuine image from a modified one.
- **Not the tested versions.** The image ran dependency versions nobody had tested. The
  Dockerfile ran `pip wheel -r requirements-v3.txt`, which takes the newest version each range
  allows on the day of the build. The base image was a moving tag (`python:3.11-slim`), apt
  installed whatever Debian served that day, and pip, setuptools and wheel were upgraded to
  the latest at build time.
- **Release tags pushed unverified images.** CI's `docker-build` job published every `v*` tag
  to Docker Hub as an unsigned image under the release's own version. It also checked out
  without submodules, so it had no `py-evm` to build.

**Fixed** ([RELEASES.md](RELEASES.md)):

- **Reproducible build.** Every input is pinned: the base image by digest, Debian by snapshot,
  liboqs by commit, and every Python package by sha256 (`release/*.lock`, the tested
  versions). Time, modes and ownership are normalised. Two builds of a commit give the same
  image, and the CI build, a perturbed checkout and an operator's rebuild were all verified
  bit-identical.
- **Release workflow** (`.github/workflows/release.yml`), from a maintainer-signed tag: it
  builds twice and compares, tests inside the image, and pushes by digest. It then
  cosign-signs the image and attaches an SBOM and SLSA provenance, Sigstore-signs a manifest
  of every artifact, and opens a draft release. The release is published only after k-of-n
  maintainers have reproduced it and signed it (`sign-release.sh`).
- **Operator check.** Operators verify with `verify-release.sh` against their own trusted
  policy and run the image by digest.
- **CI.** `ci.yml` no longer publishes tags, and it fails when a lock is stale.

Tests: `tests/test_release_tooling.py`, plus the unit suite run inside the built image
(`scripts/release/test-image.sh`: 2925 passed, 0 failed, in an image built from a tag).

## FIXED — Locally built images could contain the node's private key

**Severity: high.** `.dockerignore` listed key and state files with root-only patterns
(`*.priv`, `nodes.json`). A node started from a checkout writes its identity key to
`qrdx/node/node_key.priv` and its peers to `qrdx/node/nodes.json`, and both were copied into
any image built from that checkout. **Fixed:** the patterns are recursive (`**/`), and release
images are built from a clean export of a commit, so untracked files cannot reach them at all.
**If an image built locally before this fix was ever pushed or shared, rotate the node identity
key of the checkout it was built from.**

## FIXED — System-wallet balances lived only in the legacy UTXO ledger

**Severity: critical (value creation), found by the live governance scenario (S22).** Genesis
funded the ten system wallets as UTXO outputs, not in `account_state`. Reads hid it, because
`get_address_balance` falls back to the UTXO table when an account has no row, so the developer
fund showed its 10M. But a debit through the exchange balance flush
(`apply_account_balance_delta`) on an account without a row did nothing and reported nothing,
while its paired credit created the recipient's row.

The first governance treasury spend credited the recipient 1,234.5 QRDX on all four nodes and
debited the fund nothing: QRDX created from nothing. Every node did it identically, so no state
root diverged. This is the conservation blind spot in "Test-coverage gaps worth knowing" again.

**Fixed:**

- Genesis funds system wallets in `account_state` like every other allocation, and
  `seed_genesis_account_state` restores them after a reorg.
- The flush logs any debit that finds no row as `[VALUE-LOST]`.

Test: `tests/test_governance.py::test_a_system_spend_debits_the_wallet_in_the_ledger_and_conserves_value`
drives a spend through genesis, preload, execution and the flush, and asserts the ledger
amounts.

## FIXED — Governance was not connected to consensus

**Severity: high for mainnet.** `qrdx/governance/` was imported by nothing outside itself: state
in memory, wall-clock timelocks, and a `PROTOCOL_UPGRADE` that only recorded a version string.
QRDX_IMPLEMENTATION_CHECKLIST §10.1 claimed otherwise. Meanwhile the genesis master controller,
a single key, controlled all ten system wallets (75M QRDX) with no way to remove it.

**Fixed** ([GOVERNANCE.md](GOVERNANCE.md)):

- **Governance is consensus state.** It runs as four exchange operations (`GOV_PROPOSE`,
  `GOV_VOTE`, `GOV_VETO`, `GOV_EXECUTE`), replayed on every path and committed in the state
  root.
- **Validators decide; holders can veto.** Validators propose and decide by stake (2/3). Holders
  veto by locking real QRDX during a timelock, which is refunded when the proposal resolves.
- **System-wallet spends need a proposal.**
- **The master controller's authority ends automatically** at block 100,000, or earlier by vote.
  It is enforced at admission, at the proposer and at block import.
- **Forks need validator approval** to activate (PROTOCOL_UPGRADES.md §4a).

Tests: `tests/test_governance.py`; live: `integration_tests/scenarios/s22_governance.py`. The old
`qrdx/governance/` library remains, unused.

## FIXED — There was no way to change a consensus rule after launch

**Severity: critical for mainnet.** Every consensus rule was a module-level boolean or an
environment variable with no activation height, and every node replays the whole chain under its
current code on restart (`derived_state_rebuild.py`, which keeps the replayed state when it
differs). Any rule change shipped after launch would have rewritten history on the upgraded
nodes and split them from the rest. The one fork schedule in the code (`consensus.py`'s
`ConsensusSchedule`) had a single entry and was read only by legacy checks. Fifteen consensus
parameters (slot length, epoch length, staking delays, perps settings, the gas floor) and six
consensus A/B switches were read from each node's environment, so one operator's typo forked
their node off silently — the class of bug behind the two-epoch-definitions incident. Peers on
other networks or other rules were accepted as long as they answered.

**Fixed** — design and operator procedure in [PROTOCOL_UPGRADES.md](PROTOCOL_UPGRADES.md):
a chain spec in the genesis file defines the network (chain id, every parameter, an append-only
fork schedule); rules switch on at fork heights (`chain_spec.is_active(feature, height)`, each
block judged under its own height's rules); peers compare EIP-2124 fork ids and drop each other
at a fork one of them missed; on a non-dev network the environment cannot change consensus
(startup error); a node refuses a database created under another spec, a changed or removed
passed fork, or a fork inserted behind the chain. RANDAO proposer selection is the first rule on
the schedule. Tests: `tests/test_chain_spec.py`, `tests/test_chain_identity_startup.py`,
`tests/test_protocol_upgrade_activation.py`.

## FIXED — Consensus signatures were not bound to a network

**Severity: high.** Block signing roots, attestation signing roots, RANDAO reveals and
exchange-transaction signing bytes carried no chain id or genesis domain. A validator using one
key on two networks could have two of its headers (or attestations) from one network submitted
on the other as DOUBLE_SIGN (or surround-vote) evidence, and be slashed there. An exchange
transaction signed on a testnet verified on any network where its sender's nonce lined up.
Ethereum prevents both with a signing domain.

**Fixed** ([PROTOCOL_UPGRADES.md §7](PROTOCOL_UPGRADES.md)):

- Node signatures are taken over `chain_spec.signing_domain(purpose)`, a hash of purpose, chain
  id and chain-spec hash, plus the fields. There is one definition each:
  `reconstruct_signing_root` (the legacy `manager.py` copy now calls it),
  `Attestation.signing_root` and `randao.randao_reveal_message` (the proposer and
  `consensus.py` used to build the reveal message separately).
- Exchange transactions carry a signed `chain_id`, checked in `verify_exchange_tx`. A missing
  one is never defaulted.

Tests: `tests/test_signing_domains.py`, including that another network's headers are not
slashing evidence here.

## FIXED — Transactions signed for any chain executed here

**Severity: critical.** The EIP-155 chain id was parsed out of every legacy transaction and
never compared, the PQ envelope's chain id was never checked, and pre-EIP-155 transactions (no
chain id) were accepted. Any transaction signed on another network — another QRDX network, or
Ethereum itself for a key used there — executed here once its nonce lined up. The chain id the
node reported was a hardcoded `88888` (another chain's) in five places, independent of the
genesis.

**Fixed:** the chain id comes from the chain spec (`constants.CHAIN_ID`: `eth_chainId`, the
EVM's `CHAINID`), and the shared transaction parser refuses any other id and unprotected
legacy transactions (`contracts/evm_mempool._require_chain_id`) — so admission, execution and
block import all apply it. 17 test files had been signing for chain id 1 and passing.
Tests: `tests/test_chain_id_replay_protection.py`.

## FIXED — Genesis did not identify the network

**Severity: high.** The genesis state root covered validator stakes and system wallets but not
the prefunded accounts, so two genesis files funding different accounts produced the same
genesis block. `GenesisCreator` drew a random RANDAO seed on every node. A genesis file that
failed to load fell back to a built-in genesis with placeholder allocations — and a failure to
create genesis returned `False`, which startup logged as "genesis already exists". The
initializer counted every prefunded account twice in the state it hashed (harmless only because
the root ignored accounts), and genesis metadata was written into the package directory, shared
by every node started from one checkout.

**Fixed:** the root (`QRDX_GENESIS_STATE_V2`) commits to the chain spec and every allocation in
integer wei; the RANDAO seed is derived; a node recomputes genesis from its file and refuses
unless it reproduces the file's recorded block hash; every failure raises; metadata lives in the
node's own `chain_metadata` table. Tests: `tests/test_genesis_chain_spec.py`.

## FIXED — A rolled-back block's EVM receipts outlived it

**Severity: medium (wrong answers to wallets, not consensus).** `remove_blocks` dropped the
removed blocks and their exchange / EVM sections but left their rows in `contract_transactions`
and `contract_logs`. A transaction that existed only on the abandoned branch kept answering
`eth_getTransactionReceipt` and `eth_getLogs` as if it had executed; one included again at a
different height on the new branch had its receipt overwritten, but the orphan's logs could
linger.

**Fixed (2026-10-06):** `remove_blocks` deletes the receipts and logs at and above the cut
height, and cuts the new transaction index (`qrdx/tx_index.py`) with them; a block applied on
the new branch writes its own. The index additionally re-checks the block hashes it indexed
near the tip, so a branch switch that did not go through `remove_blocks` re-indexes too
(`tests/test_tx_index.py::test_a_reorg_cuts_the_index_and_reindexes`).

---

## FIXED — EVM state lived in a per-node trie

**Severity: critical.** The executor kept its own in-memory state trie. Before a transaction it
copied in only the sender and the recipient; afterwards it copied back only their balances and
nonces. So:
* **contract storage never reached the database** — it lived in that trie, which a restart
  emptied and a reorg rebuild never cleared (an orphaned block's storage survived);
* **the account root did not cover storage**: two nodes whose contracts held different storage
  agreed on it;
* **a contract's payment to any other account was lost** — the trie held it, the database did
  not, and the next time that account transacted its stale database balance was copied over it;
* code a contract created (a factory's child) was not saved, and the account row of a
  deployed contract held its code hash while the code bytes themselves were never written;
* the state manager's synchronous reads returned 0 or empty code for anything not cached;
* SELFDESTRUCT never deleted the account (the executor skips py-evm's transaction
  finalization, which does that);
* a delegated (system-wallet) spend charged gas and consumed the nonce of the *source*, not of
  the signer who authorised it, contrary to its own documented design;
* **no transaction included through a block had a receipt or logs**: `eth_getTransactionReceipt`
  and `eth_getLogs` read tables only a legacy RPC path wrote (with topics stored as decimal
  integers), so a wallet waiting on a receipt waited forever. Found by S20's live EVM transfer.

**Fixed** (`qrdx/contracts/evm_world.py`): every execution — a block's transactions,
`eth_call`, gas estimation — runs on a fresh state built from what the state manager holds
(pending block changes over the database). A read of anything not loaded raises `StateMiss`;
the caller loads it (a contract's whole storage at once when small, otherwise slot by slot)
and runs again from the start, so the result is what it would have been with everything
loaded. Afterwards every account and slot the execution touched is written back; commit writes
storage, code bytes, and deletes a destroyed account's every slot; the account root hashes
contract storage. Writers that change balances in the database directly (the exchange flush,
withdrawals) invalidate the cached account, and each EVM section starts from fresh reads.
Self-destructed accounts are deleted; the signer pays a delegated spend's gas. Each section
records its transactions' receipts and logs (topics as 32-byte hex) when it is accepted —
rewritten by a rebuild, orphaned ones cleared with the rest of the EVM state.

**Native tokens are ERC-20s inside the EVM** (`qrdx/contracts/native_token_evm.py`): a call to
a native token's address runs a precompile over the one native ledger — `balanceOf`, `transfer`,
`approve`, `transferFrom`, … with `Transfer` / `Approval` logs — so a wallet's "send" works and
contracts can hold and move native tokens. A transaction's token moves are journaled on its
state (a reverted frame undoes them), join its block's section overlay (later transactions in
the block read through it), and reach the token ledger only when the section is accepted. This
replaces the RPC-only read view and the refusal of EVM transactions to token addresses.

**Verified:** `tests/test_evm_world.py` (storage persists and survives a restart, a contract
writing another's storage, a payment to a third account kept when that account transacts,
slot-by-slot loading, SELFDESTRUCT, a reverted transaction writes nothing, a direct database
write is not shadowed; native tokens read and sent by a wallet, held and moved by a contract,
undone by a reverting frame, refused when frozen or short, approve/transferFrom through a
contract, a dropped section moves nothing, a later transaction in a section spends an earlier
one's delivery); `tests/test_evm_native_token_rebuild.py` drives the node's real executor
forward and then through the rebuild — token root, account root (with storage), exchange root
and the receipts (statuses, indexes, created contract, Transfer log) identical. Until now every
EVM rebuild-equivalence test used a stand-in executor. Live: S20 sends a native token from a 0x
wallet as an ordinary EVM transaction, gets its receipt, and all four nodes show the move
natively and through `balanceOf`; 21/21 scenarios, then the fault-injecting soak (a killed node
re-synced to the tip) — SOAK PASS, no root mismatch, failed execution or receipt error in any
node's log.

## FIXED — Exchange operations were free

**Severity: medium (spam vector; no fee market).** `process_transaction` computed
`gas_used × gas_price` and only logged it; nothing was debited, so any account could fill blocks
with exchange operations at no cost. `gas_price` was a Decimal in QRDX per gas that every caller
set to 1 — charging it as-is would have cost 50,000 QRDX for a 50,000-gas operation.

**Fixed:** exchange gas is priced like EVM gas, in **wei** per gas (1 QRDX = 10^18 wei), at no
less than `EXCHANGE_MIN_GAS_PRICE_WEI` (1 gwei, `eth_gasPrice`'s answer; `exchange_gasPrice`
returns it). Every executed operation — success or failure — pays `gas_used × gas_price` in
QRDX, **burned** as EVM gas is (about 0.00004–0.00015 QRDX per operation). `gas_limit ×
gas_price` is reserved before the operation runs, so it cannot spend its own gas, and the rest
is refunded. An operation priced below the floor or not whole wei, or whose sender cannot cover
the reservation, is refused before it executes and consumes nothing, nonce included; the
mempool refuses an under-priced one at admission. Receipts carry `fee` and `gas_price`.
`tests/test_exchange_fees.py`; soaked with every scenario now paying gas (21/21, SOAK PASS).

**Found on the way: the enforcement gates were set in four places.** The proposer, the
importer and both rebuilds each set every `enforce_*` gate by hand, and several tests kept their
own copies of the list — the structure behind this codebase's most repeated divergence (a gate
on one path and not another makes a rebuild accept what the network refused). They now all call
one `block_processor.apply_enforcement`, and
`tests/test_reorg_rebuild_equivalence.py::test_every_path_sets_the_gates_through_one_function`
requires every path to call it, none to set a gate itself, and the function to cover every gate
the manager has.

**Already fixed earlier — replay of a failed operation.** The exchange nonce advanced only on
success, so one signed failing operation could be re-submitted indefinitely; it now advances
once an operation executes (`tests/test_exchange_nonce_on_failure.py`).

## FIXED — `eth_call` failed for every standard web3 client

**Severity: high for usability.** The node registers its own `eth_call` handler (it runs the
call against the tip block's number and timestamp), and that handler took the transaction object
alone. Every web3 library — MetaMask, ethers, web3.py — sends `[transaction, block]`, so every
`eth_call` against a QRDX node failed with an internal error ("takes 1 positional argument but 2
were given"): no contract read, no token balance, no `decimals()`. Unit tests drove the
`EthModule` method, which the node's handler overrides, so they never saw it. Found by S20's
live ERC-20 read of a native token.

**Fixed:** the handler takes the standard `[transaction, block]` (calls run against the latest
state). `tests/test_native_tokens.py::test_the_nodes_eth_call_accepts_the_standard_block_tag`;
S20 reads `decimals()` and `balanceOf()` over `eth_call` on every node.

## FIXED — Nodes started from the same directory shared peer and DHT state

**Severity: low (operational), but it caused cross-testnet contact.** The peer store was a fixed
file inside the package (`qrdx/node/nodes.json`) and the DHT routing table defaulted to `data/`
relative to the working directory, so every node launched from one directory — the
orchestrator's four, or several testnets on one host — read and wrote the same two files. A
soak run from a copy of the tree inherited another running testnet's peers this way and dialled
it.

**Fixed:** each node keeps both in its own state directory beside its database
(`<database>.p2p/`, e.g. `testnet/databases/node0.p2p/`), or where `QRDX_P2P_STATE_DIR` says; a
routing-table path set explicitly in the DHT config is still honoured. The peer store is cleared
at startup as before, now the node's own (`tests/test_node_state_paths.py`). In the soak each
node kept its own `nodeN.p2p/` (peer store + routing table), no shared `data/` appeared, and the
peer mesh formed as before (S02 9/9). The first attempt shipped an `UnboundLocalError` — a later
`import os` inside `startup()` made `os` local to the whole function — which only a node start
showed; `test_no_function_in_the_node_shadows_os` now checks the symbol table.

## FIXED — Spot exchange: liquidity could be stolen or lost, pools moved for free, replays diverged

**Severity: critical.** Found by an audit of the spot exchange (AMM, router, spot oracles, order
book) on 2026-10-02, each defect reproduced at the manager level. What the integration soaks
covered — deploy and transfer tokens, add liquidity, one AMM swap, resting / matching /
cancelling CLOB orders — worked and conserved; the defects were on the paths they never took.

| Defect (reproduced) | Now |
|---|---|
| Anyone could remove anyone's liquidity — `REMOVE_LIQUIDITY` never checked the owner and paid the sender | Owner-only |
| Removing liquidity returned only the fees, never the principal (an LP deposited 29,553 of each token and got back 0, 0) | The principal at the current price, rounded down, plus every fee the position earned |
| Failed operations kept their effects: five swaps that failed their own `min_amount_out` moved a pool to 0.25× for free; a failed book-routed swap consumed part of a maker's order | Every operation is all-or-nothing: the router quotes exactly, every check runs on the quote, and an operation that raises restores each pool, book and ledger delta it touched |
| Every pool worked in one direction only — both directions' reciprocal prices went into one pair oracle, whose outlier rule then refused the other direction | Pools carry their own oracle (Uniswap-V3 tick cumulatives); swaps record nothing into the pair oracle |
| Book-routed swaps settled against the AMM's reserves (makers never paid, escrow stranded); the router's book side was inverted and sized in the wrong token | A swap settles with the venue that filled it — the pool's holder, or the matched makers' escrow; selling the base walks the bids |
| Restarts and rebuilds diverged after any swap (oracle stamped with the wall clock, merged per timestamp, count hashed) | The pool oracle runs on block time and replays identically |
| The token ledger minted on any over-debit (clamped a negative balance at 0 while the credit landed) | A protocol holder that cannot cover a payout refuses the operation; the ledger applies an overdraft in full and logs `[TOKEN-OVERDRAFT]` instead of clamping |

**The AMM is now Uniswap-V3 mathematics in exact Decimal** (qrdx/exchange/amm.py): swaps cross
ticks through `liquidity_net`, positions earn fees only inside their range (`fee_growth_outside`
flips), every rounding is directed in the pool's favour, and a swap is a `quote` → `apply` plan,
so what the router quoted is what executes. Fees: 70 % to LPs through fee growth, 30 % to the
protocol, paid out at `REMOVE_POOL` — half to the pool's creator, half to the treasury (the
validators' 5-point share has no per-validator distribution yet, so it goes to the treasury).

**Found while closing it:**
* **The state root did not commit the order books' contents** — only (trades, volume, bid
  levels, ask levels), so nodes could hold different resting orders, owners or time priority
  under one root. `OrderBook.state_digest()` now commits every resting order in priority order,
  parked stop orders, order nonces and the last trade price, for spot books and (inside the
  clearinghouse's canonical form) perps books.
* **Every book kept its whole trade history in memory, and each order deep-copied it** (the
  all-or-nothing wrapper, and the per-block snapshot), so a long-running node grew without bound
  and each trade made the next slower. The history is bounded (`MAX_RECENT_TRADES`) and display-
  only — the stop trigger reads `last_price` — and the book snapshots copy it shallowly.
* **Book expiry read the wall clock.** No operation sets an expiry yet, so it never fired; it is
  now judged by the block time `new_block` receives.
* **Book, router and manager arithmetic ran in the caller's Decimal context** (prec 78 only
  because importing the AMM module set it). They are now pinned, like the AMM and the
  clearinghouse.
* **Spot had no read API.** Pools, liquidity positions (with their exact current value), swap
  quotes (exactly what the swap gets) and spot books are now served over REST and `exchange_*`
  JSON-RPC from the same views ([PERPS_API.md](PERPS_API.md), "Spot").
* Pool prices were displayed to 8 decimal places, so a 1e-10 price showed as 0; now 18
  significant digits.

**Verified:** `tests/test_spot_amm.py` (one test per defect, plus randomized solvency: after any
mix of swaps, adds, removes and failed operations, each pool's holder holds at least what its
positions and protocol fees can claim), `tests/test_orderbook_determinism.py`,
`tests/test_spot_api.py`; S15 on the live chain — the reverse swap executes at exactly the quote
the node served, a swap below its minimum fails and moves nothing, a stranger cannot remove the
LP's position, the withdrawal pays exactly the position's served value, and the emptied pool
holds only the protocol's fees. Soaked: 20/20 scenarios (S15 31/31), then the fault-injecting
soak (a node killed and restarted re-synced to the tip) — SOAK PASS, and no token overdraft,
lost value or root mismatch in any node's log.

## FIXED — Exchange transactions reached a block only through the node they were sent to

**Severity: high for usability; a censorship lever.** `POST /submit_exchange_tx` admitted a
transaction to that node's mempool and stopped there — exchange transactions were never
gossiped (EVM transactions were). Only that node's validator could include it, so a wallet
talking to a non-validator node never saw its order execute, and any one validator could sit on
what it was sent. There was also no receipt: the result of an included transaction (an order's
fills, a margin refusal) was visible only in node logs.

**Fixed** (qrdx/exchange/submission.py): one write path for REST, JSON-RPC and the CLI admits,
then floods newly admitted transactions to peers over `exchange_sendTransaction`; echoes stop at
mempool dedup or a consumed nonce (`tests/test_perps_api.py` floods a 3-node mesh: each pool
holds the transaction once). Because every node now holds copies that another validator may
include, the mempool drops a sender's stale copies on admission and prunes globally when full —
otherwise a busy sender, then the whole pool, would have been locked out by its own history. A
node-local journal records a receipt per executed transaction and a feed of fills,
liquidations and funding (rebuilt with the exchange state; never consensus). The perps API is
in docs/PERPS_API.md: REST, always-on `exchange_*` / `perp_*` JSON-RPC, channel subscriptions on
`/ws` and `/stream`, and `qrdx-wallet perp`. Cross-node: S13 submits one trader's transactions
only through the non-validator node, checks open orders and receipts on every node, and watches
the fill arrive on a WebSocket subscription.

## FIXED — The proposer built blocks in the middle of a derived-state rebuild

**Severity was: high (wrong declared roots; a block's sections could land mid-replay).** This
was the "transient E-D4 mismatch after heavy reorgs" previously under observation.

Every import path and the reorg rebuild hold `block_processing_lock`; the block production
loop never took it. The rebuild yields at every database await, so a proposer selected while
its node was rebuilding computed the unified root over half-rebuilt state. Caught in a
preserved soak: node2 began a sync-triggered rebuild at 01:49:11, proposed block 123 in the
same second — between the rebuild's reset and its completion — and declared `369ea204…`;
every importer computed `63e7b01c…` (block 122's root: block 123 changed nothing), and node2's
own next block declared `63e7b01c…` again. The importers all agreeing with each other, and not
with the proposer, is the signature. A block carrying sections could equally have been applied
in the middle of a replay, out of order.

**Diagnosis history.** The by-domain rebuild order was the first suspect; replaying the final
chain offline ruled it out, and the mismatch recurred (2, 2, 1 across nodes) on the first soak
with the interleaved rebuild — which is what pointed at concurrency rather than replay.

### Fixed

The production loop holds the node's `block_processing_lock` from the tip re-check through
storing the block (sections, withdrawals, unified root, `propose_block`, `add_block`, finality
recording); main.py shares it via `set_block_processing_lock`. Broadcasting and the slot sleep
run outside it, so a slow peer never holds up imports. The block is also stamped with the
timestamp its sections executed at (see "Exchange rules judged time by the node's wall clock").

**Soak:** zero E-D4 observe mismatches on all four nodes (previous soak: 2, 2, 1); all four
nodes ended at the same tip (232) with identical account and token roots; node 3's restart
matched durable state. **Tests:** `tests/test_proposer_production_lock.py` (four fail without
the fix).

---

## FIXED — `eth_sendTransaction` executed outside consensus

**Severity was: high (any RPC client could diverge a node's state).**

`EthModule.sendTransaction` correctly refuses and points callers at
`eth_sendRawTransaction` — but main.py registered its own `eth_sendTransaction` handler after
the module, silently replacing it. That handler accepted any validly signed `r, s, v` params
and executed them straight against the EVM state manager: no block, no mempool, no nonce
check. The writes sat in the manager's cache as dirty entries and the next block's EVM flush
committed them, so a single RPC call pushed off-chain effects into that node's
`account_state` — diverging it from the network — and the same params could be replayed
indefinitely.

**Fixed:** the handler and its registration are removed; `eth_sendRawTransaction` (mempool →
block) is the only write path. `EthModule.sendRawTransaction` also executes directly, but
main.py overrides it with the mempool-admission handler, so it is not reachable. **Test:**
`test_there_is_one_write_path` in `tests/test_evm_block_context.py`.

---

## FIXED — The EVM saw a constant block context

**Severity was: medium for dapps, none for consensus.**

`evm_executor_v2.execute` built its block context from constants — `TIMESTAMP` = 1,
`NUMBER` = 1 — so every contract with a timelock, vesting schedule, auction window or router
deadline behaved as if the chain never advanced. Deterministic, so nodes agreed; just wrong.

**Fixed:** `execute` and `call` take `block_number` and `timestamp`. Every consensus path
passes the block being executed — the proposer (whose block now carries the timestamp it
executed at), the sync, REST and p2p importers (the block's own timestamp), and the rebuild
(the stored copy of the same value) — and `eth_call` passes the latest block, as geth does.
The fork is fixed (QRDXVM extends Shanghai), so real block numbers cannot switch rules.
`CHAINID` was already right (88888, as `eth_chainId` reports). Still constant: `COINBASE`
(zero) and `BLOCKHASH` history (zero) — no contract in the suite depends on them.

**Tests:** `tests/test_evm_block_context.py` — a contract returning `TIMESTAMP` / `NUMBER`
sees the block's values; every consensus execution and `eth_call` pass their block; genesis's
datetime timestamp maps safely.

**Soak (with the `eth_sendTransaction` removal):** 19/19 scenarios; all four nodes at the same
tip (240) with identical account and token roots; zero E-D4 observe mismatches; the staking
round-trip (deposit → exit → 100,000 repaid in block 155) identical on every node; node 3's
restart matched durable state.

---

## FIXED — E-D4 bound nothing: a block rejected live re-entered through sync

**Severity was: high (block validity depended on how a block arrived).**

E-D4 rejected a bad unified root on the live-broadcast paths, but the bulk-sync path only
*observed* at the tip (it enforced only at finalized heights, which almost never fires). So a
block the live paths rejected re-entered through sync: its proposer builds on it, the next live
block makes each importer sync from that proposer, and the sync path accepted the bad block with
an `[E-D4 observe]` warning. That is exactly how the proposer-mid-rebuild bug's wrong roots got
into every node's chain.

The tip had been left observe-only because "a catching-up node legitimately holds different
state mid-reorg". That stopped being true once every rollback rebuilt derived state from the
canonical prefix in forward order, the proposer stopped building over half-finished rebuilds,
and the exchange stopped reading the wall clock — two fault-injecting soaks with those fixes had
logged zero observe mismatches.

**Fixed:** `_ED4_ENFORCE_SYNC_TIP` (main.py, default on; `QRDX_ED4_ENFORCE_SYNC=0` for A/B only)
makes the sync path reject a mismatched unified root at any height. A node whose own state is at
fault is not stranded: the rejection rebuilds derived state from the chain
(`_restore_after_rejected_block`), and the next sync attempt re-applies the block on clean state.
**Tests:** `tests/test_sync_ed4_enforcement.py` — the enforcement decision under every gate
combination, and the root check against a real database (match accepted, mismatch rejected when
enforced, logged when observing).

**Soak (enforced, fault-injecting):** 19/19 scenarios; zero sync-path E-D4 rejections and zero
observe mismatches on all four nodes — no false rejection of honest blocks; all four nodes ended
at the same tip (256) with identical account and token roots.

---

## FIXED — Fork-choice reconciliation failed on 24 of 41 attempts

**Severity was: medium (forks lingered; the resolver sometimes re-created them).** Counted across
three fault-injecting soaks by un-wrapping the node logs (the 80-column wrapping had hidden the
outcome lines from earlier greps).

* **18 failures — the ancestor search started above the peer's chain.** Reconciliation passed
  the LOCAL tip as the search start, but the peer holding the canonical (lowest-hash) block can
  be shorter. It was asked for a block it did not have and the reorg aborted ("Could not get
  remote block at height N"). `handle_reorganization` now takes `search_from`; reconciliation
  passes the divergence height, while orphan collection still runs to the local tip.
* **Most of the rest — the node's own proposer slipped into the adoption.** Rollback and each
  applied batch hold the block-processing lock, but the network fetches between them cannot.
  The proposer built a fresh block on the just-rolled-back tip ("Block 130 added" by itself,
  then "height 130 != expected 131"), so the adoption failed on the height it had just taken —
  seen even after the proposer started taking the lock. Both adoption paths (longest-chain sync
  and reconciliation) now mark rollback-through-apply (`_adopting_peer_chain`), and the proposer
  skips its slot while one is in flight (checked under the lock).

**Tests:** `tests/test_fork_choice_adoption.py` — a shorter canonical peer aborts the old search
and succeeds from the divergence height (real database, fake peer); the adoption marker is
balanced even on error; both paths mark rollback through apply; the proposer's guard sits under
the lock, before any section executes.

**Soak:** 10 reconciliation attempts, **10 converged** — none declined, none rejected mid-adoption
(before: 41 attempts, 17 converged). The guard fired 8 times: the proposer skipped its slot
while its node adopted a peer chain, exactly where it used to create a new competing block.

---

## FIXED — Any user could mint unlimited QRDX through perp positions

**Severity was: critical.** Found while reviewing the exchange readiness doc (oracle scheduling,
item E3).

Closing a perp position settles its realized PnL into the owner's real balance (Phase E). The
close price came straight from the transaction's own `price` param, unbounded:

```
open  1 BTC long, 10x, "price" 30,000          → margin 3,000 debited
close the same position, "price" 1,000,000,000 → +999,973,000 QRDX credited
```

Reproduced exactly before the fix (the balance delta that flushes into `account_state`).
Three further holes made the obvious fixes insufficient on their own:

* **Anyone could set the oracle.** `UPDATE_ORACLE` — documented as a "validator duty" — had no
  authorization at all, so executing at the oracle price instead would just have moved the
  attack one transaction earlier.
* **Anyone could close anyone's position**, at a price ruinous to its owner.
* **The open price was the trader's too**, so a position could be opened below the market.

### Fixed — and then superseded

The interim fix below closed the arbitrary-price mint, but the engine still had no counterparty
and so still minted and burned QRDX at honest prices. It has since been replaced by the
order-book clearinghouse — see "Perpetuals: rebuilt on a zero-sum clearinghouse" under open
defects. Kept from the interim fix: the oracle-reporter authorization. The original attack is
still a regression test (`tests/test_perp_price_integrity.py`).

What the interim fix did (qrdx/exchange/state_manager.py, since removed):

* Opens, closes and partial closes execute at the market's **oracle mark price**. The trader's
  `price` is a slippage limit: a buy (open long / close short) refuses to execute above it, a
  sell below it. A market with no oracle price, or a stale one (block time — see "Exchange rules
  judged time by the node's wall clock"), refuses to trade.
* `UPDATE_ORACLE` is accepted only from `constants.ORACLE_REPORTERS`
  (`QRDX_ORACLE_REPORTERS`, a consensus parameter; empty by default, which disables perps until
  configured). The trust this places in reporters is listed under accepted limitations.
* Only a position's owner may close it.
* The integration testnet configures an "Oracle Reporter" wallet, and S13 prices its market
  through it before trading — S13 passed in the soak with the reporter-priced market.

**Tests:** `tests/test_perp_price_integrity.py` — the exact attack refuses and the honest close
returns only the margin; unauthorized and unconfigured oracle updates refuse; opens execute at
the oracle price within the limit; non-owner closes refuse; a stale price refuses; real profit
when the oracle moves. 37 existing tests that opened positions with no price, set prices as
arbitrary senders, or "closed at a profit" by naming the price were updated to price the market
first (`tests/exchange_prices.py`) — several of them were testing the exploit as a feature.

---

## FIXED — Exchange rules judged time by the node's wall clock

**Severity was: high (consensus nondeterminism, amplified by every replay).** Found while
checking the final soak.

Three consensus rules read `time.time()` inside block processing:

* **Oracle staleness** — `OPEN_POSITION` is rejected if the market's oracle is older than
  120 s. `ORACLE_UPDATE` stamped `last_price_update` with the wall clock and the check
  compared against the wall clock. A position opened more than two minutes after the last
  update was rejected live but **accepted** by any fast replay — a catching-up sync, a reorg
  rebuild, and (with the startup rebuild) every restart: a margin debit on one side only.
* **Swap deadline** — `SWAP`'s `deadline` param was compared with the wall clock, so any later
  replay **rejected** swaps the network had accepted: token-ledger divergence.
* **Funding cadence** — funding settles at most every 8 wall-clock hours, so a fast replay
  skipped settlements forward application had made: different position margins, which reach
  `account_state` when positions close.

### Fixed

`PerpEngine` and `UnifiedRouter` take a `clock`; `ExchangeStateManager` points both at the
timestamp of the block being processed (`begin_block` sets it). The oracle's `record()`
already did this; the perp engine and router never had. A standalone engine keeps the wall
clock. Order expiry also reads the wall clock but is unreachable from consensus —
`PLACE_ORDER` never sets `expire_time` — so orders are good-till-cancelled.

That made one pre-existing gap consequential: the proposer executed the sections at `now()`
and then stamped the block with a *later* `time.time()` inside `propose_block`, while
importers execute at the block's timestamp. The proposer now passes the timestamp it
executed at into `propose_block`, so the block carries exactly that value.

Also fixed: every successful funding settlement logged `Funding settlement failed` at ERROR
(its debug line read `snapshot.funding_rate`; the field is `rate`).

**Tests:** `tests/test_exchange_block_clock.py` — staleness, swap deadline and funding cadence
each decided by block time with the wall clock pinned to a misleading value (four fail
without the fix); no false funding error; standalone engines keep the wall clock.

---

## FIXED — Any validator could get any other validator slashed

**Severity was: critical.** Found while making withdrawal forfeiture chain-derived.

Slashing evidence rides in block bodies and self-verifies: a DOUBLE_SIGN proof carries two
conflicting headers signed by one proposer, an attestation proof two conflicting
attestations plus the key that signed them. Both verifiers check exactly that. But the
recorder took the **offender** from the proof's top-level `proposer` field, which neither
verifier looks at:

```python
proposer = ev.get("proposer") or (ev.get("header_a") or {}).get("proposer_address")
```

So any validator could sign two conflicting headers with its **own** key, set `proposer` to
an honest validator, and include the proof in its block. It verified, the honest validator
was recorded as the offender, and the finalized-epoch penalty cut its stake by half and
ejected it. The attacker lost nothing. Reproduced directly before the fix: the recorded
offender was the victim.

### Fixed

`slashing_block.verified_offence` returns `(offender, condition, slot, epoch)` taken only
from verified content: the proposer both headers are signed by (whose key
`verify_pos_block_proposer` binds to that address), or the validator both attestations are
signed by (key bound by `verify_attestation_evidence`). The epoch is derived from the slot
rather than a free field, so it cannot be pushed out to delay a penalty, and the recorded
condition is canonical. `record_block_slashing_evidence` records only what it returns.

**Tests:** `tests/test_slashing_offender_binding.py` — a forged name convicts the signer,
not the victim, for both proof kinds; the epoch ignores a forged field; a mislabelled
condition does not verify. The existing slashing tests (56 selected by `-k slash`) pass
unchanged.

---

## FIXED — Stake forfeiture read node-local state; principal was paid while still eligible

**Severity was: high (a latent consensus split, and a slashing-evasion window).** Both in
the in-block withdrawal design below; found while re-auditing it.

**Forfeiture.** A slashed validator forfeits its principal. The check read
`slashing_events` — but that table also holds offences a node detected **locally** from
gossip, plus chain evidence the finality pass records **asynchronously**. At the payout
block two nodes could disagree on it: one pays, the other does not, and their account roots
split. Honest soaks never slash, so it never showed.

**Timing.** Principal was paid at the first block whose head epoch reached `exit_epoch`. An
exiting validator stays eligible until the **finalized** epoch reaches it, about two epochs
later — so it could still propose and attest after its stake had left, and any offence in
that window was slashed from nothing.

### Fixed (qrdx/validator/withdrawals.py)

* Forfeiture reads only verified evidence carried in canonical blocks **before** the paying
  block (`slashed_on_chain`), the same rule as every other withdrawal input — identical on
  every node. A forfeit is settled with a zero-amount ledger row so the scan runs once; both
  ledger re-credit paths skip zero rows, so a forfeit never touches `account_state`.
* The scan is kept cheap: it runs only for an exit that would actually pay something, and
  every block carries an (almost always empty) `slashing_evidence` key, so blocks whose list
  is empty are excluded in SQL before any ~100 KB block body is parsed.
* Payout waits `WITHDRAWAL_DELAY_EPOCHS` beyond the exit epoch — 256 in production
  (Ethereum's `MIN_VALIDATOR_WITHDRAWABILITY_DELAY`), 4 on the fast testnet. The constant
  already existed for the legacy lifecycle classes; it is now env-overridable and enforced
  on the live path. What it does not cover is listed under accepted limitations.

**Tests:** `tests/test_withdrawal_delay_and_forfeit.py` — the delay boundary; chain evidence
before the block forfeits, once; evidence in the paying block or later does not count;
evidence against someone else (including a forged name) does not forfeit; a zero row never
touches `account_state`; an ejected validator claims with `STAKE_EXIT`; only blocks with
evidence are parsed; an exit that pays nothing triggers no scan. In
`tests/test_validator_withdrawals.py` the old slashing test is replaced by one asserting
that a **locally** recorded offence does not forfeit.

**Soak (delay 4 on testnet):** s16's staker exited in epoch 17 (exit epoch 19) and was repaid
its 100,000 in block 142 — the first block of epoch 23 = 19 + 4; blocks 140–141 (epoch 22)
correctly paid nothing. Deposit, exit, withdrawal row, balance, validator status, account and
token roots were identical on all four nodes.

---

## FIXED — A restart replayed exchange state without enforcement

**Severity was: high.** Found while fixing the rollback order below; pre-existing since the
exchange enforcement gates were introduced.

Exchange state (pools, order books, perp markets, nonces) lives only in memory, so startup
replayed it from the chain with `rebuild_exchange_state_from_chain(db)`. That call runs the
exchange sections **alone**: every enforcement gate at its default (off), and no sender
balances loaded. An op the network had **rejected** — an under-collateralised position, an
unaffordable pool, an over-spending swap — was **accepted** on replay.

Reproduced directly: a 10-QRDX account opens a position needing 3,000 margin. Forward
rejects it; the restart replay accepts it. Exchange roots: forward `d34a2875…`, restarted
`dcb41a03…`.

A restarted node therefore held a different exchange state from the network after any
chain containing a single rejected exchange op — routine under reorg churn — and from then
on rejected every valid block carrying an exchange section on the strict import path, and
proposed exchange roots the network rejected.

### Why it needed the whole rebuild

Turning the gates on is not enough. Each op is accepted or rejected against the sender's
balance **at that block**, and the durable `account_state` holds only tip balances. The
only way to reproduce the network's decisions is to recompute each block's balances while
replaying — which is exactly the interleaved rebuild below.

### Fixed

* `_rebuild_derived_state_on_startup` (qrdx/node/main.py) runs the interleaved rebuild at
  startup: exchange in memory, `account_state` and the token ledger, block by block.
* The contract system (EVM executor + account-state manager) is now initialised **before**
  the rebuild and before the validator, epoch loop and chain poller start. It used to be
  created only when the RPC modules registered, after block production and sync had
  already started — a window in which an EVM section could be imported with EVM
  uninitialised. The RPC modules now share that one instance.
* **Every restart is an equivalence check.** The rebuilt account and token roots are
  compared with the durable ones; a difference logs `[RESTART-REBUILD]` at ERROR and the
  chain-derived state is kept, since every reorg would produce it.
* Cost: a replay of the chain at every startup. On the real soak chain (173 blocks, 5 EVM
  sections, 19 exchange sections) the whole offline check — Python start-up, both rebuilds
  — took 4.5 seconds. Replay is linear in chain length; checkpointing is the optimisation
  when that matters.
* A/B override: `QRDX_STARTUP_REBUILD=0` restores the old exchange-only replay.
* **Live check:** in the fault-injecting soak, node 3 was killed and restarted at tip 136;
  its startup rebuild reported `matches durable state` and it re-synced to the network tip.
* **Crash recovery.** A rebuild commits its reset (cleared `account_state` and token ledger)
  before replaying. In a later soak the orchestrator stopped node 3 one second into a reorg
  rebuild, leaving genesis balances and an empty token ledger on disk — under the old startup
  that state would have been permanent. Running the real startup hook on that snapshot
  logged `[RESTART-REBUILD]` and restored exactly the account and token roots the other three
  nodes held. Regression test:
  `test_a_rebuild_interrupted_by_a_crash_is_repaired_at_the_next_start`.

### The bug the real chain caught

The first version parsed every block's timestamp as an integer. Genesis stores a
`datetime`, so on any real chain the rebuild raised at height 0 — **after** clearing
`account_state`. On startup that would have left every restarted node with genesis-only
balances. The unit tests passed because their blocks all used integer timestamps; it was
found only by replaying a real soak node's database with the real EVM executor. The
timestamp is now read only where a section uses it, with the forward path's own
conversion, and the tests' genesis blocks use the real `datetime` format.

**Tests:** `tests/test_startup_rebuild.py` — restart reproduces the forward exchange,
account and token roots on a chain with a rejected position; the old replay diverges on
the same chain (sensitivity); durable drift is reported and repaired; and startup
ordering (EVM initialised → rebuild → validator / epoch loop / chain poller; one shared
`ContractStateManager`).

---

## FIXED — The rollback rebuild replayed state domains out of forward order

**Severity was: low-medium (an equal-tip divergence when hit).**

Forward import applies each block as exchange section → EVM section → withdrawals, then
the next block. `_rebuild_derived_state_after_rollback` instead replayed **all** EVM
sections across the chain, then **all** exchange sections, then **all** withdrawals. Any
transaction whose outcome depended on an earlier block's effect in another domain replayed
differently:

```
forward:  block 1  STAKE_DEPOSIT 100k        balance 150k → 50k
          block 2  EVM send of 120k           → fails
by-domain:EVM pass  block 2's send            balance 150k → SUCCEEDS (30k left)
          exchange pass  block 1's deposit     → REJECTED, 30k < 100k
```

The rebuilt node ends up with the spent funds and **no stake** — the network has the stake
and the funds unspent. Withdrawals had the same problem in reverse: they were re-credited
after every EVM section had already run, so a spend funded by a withdrawal failed on
rebuild.

### Fixed

`qrdx/derived_state_rebuild.py::rebuild_derived_state_interleaved` replays each canonical
block exactly as an importer applies it — exchange section (preload → process → flush),
then EVM section, then the withdrawals that block paid — so rebuilt state equals forward
state by construction. It sets the forward path's exact enforce-flag set; the flag guard
test now reads that set **from the forward importer's source** and checks both rebuild
functions against it, so a gate added only to the forward path fails immediately.

Wiring: the rollback trims orphaned exit/withdrawal logs **before** the rebuild (it
re-credits every ledger row that remains), then runs the interleaved rebuild on EVM and
EVM-less nodes alike. The same function serves reorgs, the equal-height tie-break, the
rejected-block restore and startup. A/B override: `QRDX_INTERLEAVED_REBUILD=0` restores the
old path, kept as `_rebuild_derived_state_by_domain`.

**Tests:** `tests/test_interleaved_rebuild_equivalence.py` — two cross-domain chains
(stake → EVM spend, withdrawal → EVM spend), each with a **sensitivity test proving the
old rebuild diverges on it**; idempotence; the EVM-less ordering (withdrawal → stake
deposit); and the real rollback hook, which fails with `QRDX_INTERLEAVED_REBUILD=0`
(110,000 instead of 10,000: the deposit rejected on rebuild). The EVM executor in these
tests loads balances through the real `sync_address_to_evm`, so it sees exactly the
`account_state` an importer's EVM would.

**Real-chain check:** a soak node's final database (tip 173), replayed offline with the
real EVM executor, rebuilds to the network's converged account and token roots exactly.

**Soak (interleaved rebuild + startup rebuild, fault-injecting):** 19/19 scenarios, SOAK
PASS; 22 interleaved reorg rebuilds across the four nodes with no failure and no
`[VALUE-LOST]`; zero E-D4 observe mismatches in that run; all four nodes ended with identical
account and token roots. (The mismatches recurred in the next soak — they had a separate
cause, fixed in "The proposer built blocks in the middle of a derived-state rebuild".)

---

## FIXED — E-D4 rejected a bad block but kept its effects

**Severity was: medium.**

Every import path applies a block's sections before its final checks, and those sections
do not roll back on their own: `apply_block_evm_section` commits on success (committing the
exchange deltas flushed before it), the in-memory `ExchangeStateManager` has already been
mutated, and withdrawal credits sit in the open transaction for the next commit. A block
rejected by a **later** check — the EVM section's own root, or E-D4 — left its effects in a
node whose chain does not contain it.

### Fixed

`_restore_after_rejected_block` (qrdx/node/main.py) rolls back the open transaction and
rebuilds derived state from the canonical chain, which the rejected block never joined —
restoring the exact pre-block state in every domain, in memory included. It is called on
EVM-section and E-D4 rejection on the sync, REST and p2p paths (p2p through the
`restore_after_rejected_block` hook).

The rebuild also now resets the mempool's nonce expectations
(`_reset_evm_pending_nonces`). Without that, a transaction from an orphaned or rejected
block could never be re-admitted: the mempool still expected the post-orphan nonce while
the account had rolled back. That affected **every** reorg, not only rejections.

Cost: a rebuild is O(chain). Acceptable because it fires only when a block that already
passed signature, eligibility and parent-continuity checks then fails a state check —
which only an eligible proposer can cause, once per slot it owns.

**Tests:** `tests/test_rejected_block_restore.py` (8) — the restore is wired on EVM and
E-D4 rejection on the sync, REST and p2p paths (source checks) and the p2p hook is
injected; behaviourally, a rejected block's uncommitted credit is undone and the rebuild
resets mempool nonce expectations to the rebuilt accounts.

**Soak:** 19/19 scenarios, SOAK PASS, 19 reorgs, all four nodes byte-identical at the end.
No block was rejected during that run, so the restore itself was exercised only by the
tests, not live.

---

## FIXED — Transaction replay after a node restart

Kept in full because the design choice inside it is non-obvious and will be questioned.

**Was: high (double-spend).** The mempool's expected-nonce came from `EVM_PENDING_NONCE`,
an in-memory dict lost on restart and never rehydrated; the `EVM_TX_CACHE` dedup was
in-memory too; and **nothing compared a transaction's nonce to the sender's account nonce
during execution**. So after a restart an already-executed signed transaction could be
re-submitted, re-admitted (expected nonce back to 0), re-included, and **re-executed**.

*Why it survived:* the account nonce only started advancing for plain transfers recently
(see [UNIFIED_ACCOUNT_IDENTITY.md §5](UNIFIED_ACCOUNT_IDENTITY.md)) — before that there was
no account-state nonce to validate against, so the check was not implementable.

**Two defences:**

1. **`_ENFORCE_TX_NONCE` in the shared execution path** — authoritative. The nonce must
   equal the sender's **durable account nonce**, so it holds across restarts and is
   identical on every node replaying the same chain. It lives in `_execute_evm_raw_tx`,
   which the RPC, proposer and every importer share, so all three agree.
2. **`_rehydrate_evm_pending_nonces()` at startup** — restores the mempool's per-sender
   expectations from the durable nonces, so a replay is refused at admission rather than
   after it has been gossiped and possibly selected by a proposer. Best-effort;
   correctness rests on defence 1.

**Why the transaction is rejected, not its block.** Ethereum treats an invalid-nonce
transaction as making its block invalid, which is stricter. Here a mismatch rejects only
the transaction, as a no-op, because rejecting the block would turn any nonce disagreement
into an **import halt**, and would make a poisoned mempool entry a **griefing vector**
(`produce_block_evm_section` drops its whole EVM section on a transaction that cannot
execute, so one bad transaction would block all EVM activity). State is untouched either
way, identically on every node, so roots still agree and the replay is still impossible —
which is the security property. The cost is that a wrong-nonce transaction can occupy block
space as a no-op; mempool admission is what keeps that from being cheap.

Tests: `tests/test_tx_nonce_replay_protection.py` (12) — replay refused, stale and future
nonces refused, the correct sequence still executes, independent per-sender sequences,
rehydration restores expectations without ever lowering a live one, and a rejection still
reports its tx hash so the block imports.

---

## FIXED — No maintenance stake threshold

**Was: medium.** Also a **corrected diagnosis** — worth reading, because the first
framing of this issue was wrong and would have produced a harmful fix.

### The original framing, and why it was wrong

It was first written up as *"`effective_stake` can drift below `MIN_VALIDATOR_STAKE`
without ejection"*, prompted by a live observation: a joined validator sat at
`effective_stake = 99840.12` against a 100,000 floor, still `active` and still weighted in
proposer selection.

That is **not a defect.** `MIN_VALIDATOR_STAKE` is an *activation* threshold, and in
Ethereum a validator with 31 ETH keeps validating perfectly normally. Ejecting at the
activation floor would have churned the validator set on ordinary missed attestations — on
a small set, repeatedly losing proposers, and in the worst case emptying the set and
halting the chain. The "fix" would have been worse than the bug.

### The actual defect

There was **no maintenance threshold at all**. `grep` for an ejection threshold returned
nothing: `MIN_VALIDATOR_STAKE` was checked at deposit
(`ExchangeStateManager._op_stake_deposit`) and at activation (`epoch_processing.py`), and
nowhere else. So under sustained inactivity penalties a validator's `effective_stake` could
decay toward **zero** while it kept its slot and its full stake-weighted influence over
proposer selection and fork-choice attesting weight.

### Fixed

`VALIDATOR_EJECTION_STAKE = MIN_VALIDATOR_STAKE / 2` (50,000 QRDX) — half the activation
floor, mirroring Ethereum's 16 ETH ejection vs 32 ETH activation. The hysteresis is the
design: a validator must have lost **half** its stake before losing its slot, so ordinary
penalty drift never triggers it. The live-observed 99,840 case is correctly left alone.

`epoch_loop._eject_validators_below_stake_floor` sweeps the active set after each finalized
epoch's rewards and penalties are applied, so it reads settled stake. Deterministic — a
pure function of the validators table (which every node agrees on at a finalized epoch)
plus a constant.

Ejection is an **exit, not a removal**: the validator moves to `exiting` with a
deterministic `exit_epoch` and stays eligible through unbonding, like a voluntary
`STAKE_EXIT`. Its principal is not paid automatically — it claims it by submitting a
`STAKE_EXIT` (see accepted limitations). It was inactive, not dishonest — a slashed
validator is already ejected by `apply_epoch_slashings` and never reaches this sweep.

**Liveness backstop.** The sweep is skipped entirely if it would leave fewer than
`_MIN_ACTIVE_AFTER_EJECTION` (3) active validators, and is otherwise capped at that bound.
If every honest validator has decayed together, keeping them is strictly better than
halting the chain. When the cap binds, candidates are taken in canonical
lowest-stake-then-address order so every node ejects the same subset.

Tests: `tests/test_stake_floor_ejection.py` (19) — hysteresis (the 99,840 case kept, at-floor
kept, below-floor ejected), exit-through-unbonding with the right exit epoch, only `active`
rows swept, the backstop skipping and capping, cross-node agreement on a capped ejection
via `validators_table_hash`, and idempotence.

---

---


### Addendum — the first wiring was dead

As first shipped, the ejection lived only in the epoch loop's incremental path, which the
live configuration never reaches (reconstruction is on — see §2). It ran in unit tests and
nowhere else; the soak's "zero ejections" was true but would have been zero regardless.
It now runs per-epoch inside `reconstruct_validators_state`, the live single writer.
Verified by `test_the_reconstruction_walk_ejects_a_decayed_validator` — which **fails with
the fix reverted** — and live: reconstruction ran 26 times on one node in a soak with the
validator set byte-identical across all four.

## FIXED — Failed transactions cost nothing

**Was: low-medium (spam vector), and it contradicted the code's own assumption.**

**Was: low-medium (spam vector), and it contradicted the code's own assumption.**

On failure `ExecutionContext.finalize_execution` reverts the EVM snapshot. That revert is
what makes a failure safe — no state changes survive — but it also rolled back the **gas
charge** and the **nonce increment** that `execute()` had applied. Only the state changes
should roll back.

Three consequences:

* **free failed execution** — an attacker makes every node do the work and pays nothing;
* **infinite retry at one nonce** — nothing advanced, so the same transaction was
  resubmittable forever;
* it contradicted `apply_block_evm_section`'s own documented assumption, which states that
  a reverted transaction "is still validly included and still mutates state (nonce/gas)" —
  untrue until now.

### Fixed

`_charge_failed_tx` re-applies the cost *after* the revert, gated by
`_ENFORCE_FAILED_TX_COSTS`:

* **gas** = `min(gas_limit, max(consumed, intrinsic))` — the same rule the success path
  uses, so a failure is never cheaper than the floor and never exceeds what the sender
  authorised. A sender who cannot cover it is clamped to zero rather than going negative:
  the affordability check belongs at admission, and clamping keeps this deterministic
  instead of raising mid-block.
* **nonce** advances to `tx_nonce + 1` regardless of gas price — cost can legitimately be
  zero, but replayability must not be. This composes with the replay check: the retry of a
  failed transaction is now refused as an invalid nonce.

Both the revert branch and the **exception** branch charge (out of gas, insufficient funds
mid-execution, a VM error) — otherwise the cheapest way to spam the network would be to
make execution throw. The exception path charges the full gas limit, as Ethereum does for
out-of-gas.

Deterministic: every node takes the same branch for the same transaction with the same gas
figure, so the account root still agrees — asserted directly by
`test_two_nodes_charge_a_failure_identically`, which compares `account_state_root` across
two independent nodes after the same failure.

Tests: `tests/test_failed_tx_costs.py` (12) — an overspend still pays gas and moves no
value, the nonce is consumed, the retry is refused, the intrinsic floor is respected, the
gas limit is a ceiling, balances clamp rather than go negative, zero-gas-price failures
still consume the nonce, successes are unaffected, the sender can continue at the next
nonce, and the charge is identical across nodes.

### A gate decision that was made, reversed, and why

Worth recording, because the reasoning is the useful part.

The first two soaks with this enabled came in at 20-21 reorgs and failed CLOB convergence
scenarios, against 9-16 reorgs on earlier passing runs. That looked like the charge might be
amplifying churn — plausibly, since a failed transaction now mutates `account_state`, so
more blocks carry state changes and there are more chances for a root mismatch to reject a
block. On that suspicion the flag was defaulted **off**.

A controlled A/B refuted it:

| soak | flag | reorgs | differing block hashes (node0 vs node2) | result |
|---|---|---|---|---|
| replay-check | off | 14 | — | pass |
| stake-ejection | off | 10 | — | pass |
| control | off | 9 | 9 (token ledgers agreed) | pass |
| failed-tx | **on** | 20 | 10, two-way token split | fail |
| failed-tx repeat | **on** | 21 | 10, two-way token split | fail |
| verification | off | **20** | **19, THREE-way token split** | fail |

The flag-OFF run at the same churn level diverged **worse** than either flag-ON run. So
failures track reorg count, not this flag, and the cause is §1's pre-existing fork — which
reproduces with the charge disabled.

The gate was therefore restored to **on**. The general lesson: §1 breaks any 20+-reorg soak
regardless of what else changed, so "wait for a clean high-churn soak" is an unmeetable bar
for *every* change until §1 is fixed. Gating decisions in the meantime have to rest on a
change's own merits — determinism, unit coverage including cross-node root agreement, and
whether it is implicated in an observed failure — not on a soak that cannot currently pass.

---

## FIXED — estimateGas ignored the PQ intrinsic floor

**Was: low (wallet UX, but fatal in practice).**

`QRDXEVMExecutor.estimate_gas` binary-searches execution with `intrinsic_gas=0`, so it
knows nothing about a type-0x51 transaction's ~5.3KB ML-DSA-65 authentication envelope. It
therefore under-reported — and because a transaction below its intrinsic floor is
**invalid** (rejected outright, not merely reverting), a wallet trusting the estimate would
have *every* PQ transaction refused.

### Fixed — two surfaces

* **`eth_estimateGas` honours the standard EIP-2718 `type` field.** Pass `type: "0x51"`
  and it returns the PQ floor directly rather than binary-searching execution that cannot
  account for the envelope.
* **`qrdx_getIntrinsicGas(envelope, data, is_create)`** answers explicitly, for callers
  that would rather ask than set a type field. Purely computational — no state access, so
  it answers for an address that has never been funded.

```
legacy  transfer  →  21,000        pq  transfer  → 145,176
legacy  create    →  53,000        pq  create    → 177,232
```

### The assertion that matters

The quoted floor must equal what the node **enforces**, or wallets break the moment they
drift apart. `test_the_quoted_pq_floor_matches_what_a_real_transaction_requires` signs a
transaction funded with exactly the quoted floor and asserts the parser accepts it, then
signs one funded a single gas below and asserts it is refused with `intrinsic gas too low`.

Tests: `tests/test_intrinsic_gas_rpc.py` (15) — both envelopes, creation surcharge,
per-byte calldata pricing, zero-vs-non-zero byte cost, envelope aliases, malformed input
rejection, and agreement with the parser for both legacy and PQ.

---

## FIXED — System-wallet sends
**Severity: low (a CLI path that could never work), but it needs a consensus change.**

`qrdx-wallet send --from-system-wallet` built a legacy UTXO transaction carrying
`system_wallet_source` + `controller_address` + `controller_signature`. The UTXO set is
empty from genesis onward, so it could only ever fail with "No UTXOs found". It now fails
with an explicit message rather than an obscure one.

### Why it is not a CLI fix

A system wallet is spent by its **controller** — a PQ address or an m-of-n multisig — and
has no key of its own (`SystemWalletManager`). But a type-0x51 PQ transaction derives its
sender *from the signing key*, deliberately: there is no sender field on the wire, so
nothing can be forged. A controller therefore cannot sign a transaction that spends from a
different address.

`SystemWalletManager` already has the authorization primitives — `can_spend_from` and
`verify_multisig_spend` — but **no consensus path calls them**: grepping
`system_wallet_source|controller_signature` outside `qrdx/cli/` returns nothing. The
authorization model exists only in the CLI's dead UTXO payload.

### Fixed — a delegated source inside the signed envelope

```
0x51 ‖ rlp([chain_id, nonce, gas_price, gas_limit, to, value, data,
            on_behalf_of, public_key, signature])
```

* `on_behalf_of` is a 20-byte account id (empty for an ordinary transaction) and sits
  **inside the signing hash**, so it cannot be redirected in flight.
* The **signer** still pays gas and consumes its own nonce — it submitted and it pays.
  Only the value leaves the delegated source. The EVM runs with the source as its sender
  and `origin` kept as the real signer, so a contract still sees who authorised it.
* `SystemWalletManager` had held `can_spend_from` since the UTXO days, but grepping
  `system_wallet_source|controller_signature` outside `qrdx/cli/` returned nothing — the
  authorisation model existed only in a dead CLI payload. `verify_delegated_spend` is
  that missing call site, reading the genesis-registered `system_wallets` table.

**Authorised at BOTH choke points** — mempool admission *and* `apply_block_evm_section`.
Checking only at submission would let a proposer smuggle an unauthorised delegated spend
into a block, the same hole the PQ signature check sits there to close. Neither path
trusts the other.

**Deliberately async and db-backed, not a module-level cache.** A cache has a load-order
failure mode, and because this check **fails closed** an unloaded cache would silently
refuse every delegated spend — the same class of bug as the in-memory nonce state that
caused the replay hole.

Tests: `tests/test_delegated_system_wallet_spend.py` (13) — the source is signature-covered
and tamper-evident, signer and source stay distinct, the controller may spend, a
non-controller may not, an ordinary account is not delegable, authorisation fails closed on
an unreadable registry, ordinary transactions pass unconditionally, and both choke points
are asserted to run the check.

---

## FIXED — Staked principal never returned on exit

**Was: medium (staked principal locked forever).** Also includes a correction and three
pre-existing bugs that had to be fixed first.

### Correction

This was first written up as *"Validators table is not reconstructed on reorg"*, citing
`node/main.py::_ENFORCE_VALIDATOR_RECONSTRUCTION = False`. That was wrong: that flag is a
superseded hook. Since commit `2f0a296` the epoch loop has been the single writer, rebuilding
the validators table from the finalized canonical chain every epoch
(`epoch_loop._RECONSTRUCT_VALIDATORS = True`).

With reconstruction on, the loop never reaches the incremental path — where this session had
put both stake-floor ejection and the exit refund. Neither ever ran. Their unit tests called
the helpers directly and passed anyway. Ejection moved into the reconstruction walk; the
refund could not simply move (below).

### Why the refund needed in-block withdrawals

A refund credits `account_state`, which is bound into the E-D4 unified root. The epoch loop
runs asynchronously, so crediting from it makes nodes disagree on the root depending on
whether their loop has run yet. The refund therefore has to happen **inside block
application**, like Ethereum's EIP-4895 withdrawals.

`qrdx/validator/withdrawals.py` computes, for each block, the withdrawals that have become
payable and credits them as part of that block's state transition — after the EVM section
(so the section's own declared root is untouched on both sides) and before the unified root
(so E-D4 binds the credits). The proposer and all three import paths (sync, REST, p2p) run
the same computation at the same point.

**It reads only chain-derived records** — a deposit log and an exit log written during block
application and reversed on rollback, the paid-withdrawal ledger, and chain-carried slashing
evidence — and never the asynchronously rebuilt validators table. An exit is payable once its
`exit_epoch` is reached, it has not been paid, and the validator was never slashed. The
amount is deposits minus prior withdrawals, so staking is exactly supply-neutral.

On rollback, exit and withdrawal records from orphaned blocks are discarded and every
canonical withdrawal is re-credited onto the rebuilt `account_state` (a withdrawal is neither
an EVM nor an exchange transaction, so the rebuild alone would drop it).

### The three bugs the soaks exposed

The first withdrawal soak paid on two nodes and not the other two. From identical blocks,
node0 scheduled the exit for epoch 11 and node2 for epoch 4. Root causes:

1. **Two definitions of an epoch.** `qrdx/validator/config.py` hardcoded
   `SLOTS_PER_EPOCH = 32` (and `SLOT_DURATION = 2`, `UNBONDING_PERIOD_EPOCHS = 9450`) while
   `qrdx.constants` reads the environment — 8 on the testnet. `propose_block` stamped every
   block's `epoch` at 32-slot granularity; the node loop, finality, RANDAO, block
   verification and slashing all used 8. So proposer and importers scheduled validator
   lifecycle ops in different epochs, and reconstruction — walking in finality's 8-slot
   epochs — read op epochs about 4× too early. Production defaults (32/32) agreed by
   coincidence, which is why it hid. Now one source of truth.
2. **`epoch_from_block` missed the sync path.** It read `block_content` (the p2p/REST
   envelope) but not `content` (the stored-row key the sync path uses), so every block
   imported via sync — bulk sync and every post-reorg re-fetch — scheduled its lifecycle ops
   with no epoch at all.
3. **A pending validator's exit was silently dropped.** `mark_validator_exiting` moved only
   `active` rows, and reconstruction applies an epoch's STAKE ops before that epoch's
   activations — so an exit landing in the activation epoch no-op'd and the validator was then
   activated and stayed active forever. With withdrawals that is an exploit (refunded *and*
   still stake-weighted). A pending validator now exits without ever activating. The exit
   log cannot be gated on whether the table moved, because the table is rebuilt asynchronously.

Each has a regression test that **fails with the fix reverted**.

### Verified

Three consecutive soaks at shipped defaults, 19/19 each: s16's real deposit → exit
round-trip returned the 100,000 stake on all four nodes, with the exit logged at the same
block and epoch everywhere, the withdrawal paid at the same block, the validator `exited`
on every node, and `account_state` byte-identical across nodes.

**Residual:** a validator ejected for inactivity by the stake-floor sweep has no exit
*operation* on chain (the ejection is derived inside the asynchronous reconstruction), so its
principal is not returned automatically; it claims it with a `STAKE_EXIT` (see accepted
limitations). Two further defects in this design were fixed later — see "Stake forfeiture
read node-local state; principal was paid while still eligible".

Tests: `tests/test_validator_withdrawals.py` (22), `tests/test_single_epoch_definition.py` (6),
plus the updated `tests/test_validator_membership.py`.

---

## FIXED — Block history did not converge

**Was: high — nodes sat on genuinely different chains, and the derived state split with
them (a pool and two tokens existing on some nodes only).**

### Resolution

Three changes, each found by measurement rather than assumed:

1. **One definition of an epoch** (see the staked-principal entry): blocks were stamped with
   32-slot epochs while finality, attestation targets and the node loop used 8-slot epochs
   on the testnet. Fixing it cut reorgs from 9–29 to about 3 per soak and worst divergence
   from 7–22 to 3–6.
2. **Parent continuity enforced on every path.** Stored chains held blocks whose parent the
   node did not have, so each height's block was effectively chosen independently. The flag
   existed but was off — and even when on, the p2p path (live broadcast, where most blocks
   arrive) called the checker without `enforce` and got a silent `False`. The checker now
   defaults to the gate.
3. **Equal-height reconciliation actually implemented.** Its enforce branch was a stub. It
   now rolls back via `handle_reorganization` and then fetches the canonical (min-hash)
   chain — neither `handle_reorganization` (rollback only) nor `_sync_blockchain` (refuses
   any peer that is not strictly longer) does both.

Neither 2 nor 3 converged alone. Together, in an interleaved A/B of three fault-injecting
soaks per arm:

| | worst pairwise block divergence | broken parent links | derived state | soaks |
|---|---|---|---|---|
| observe | 4, 4, 5 | 3, 3, 4 | converged 3/3 | PASS ×3 |
| **enforced** | **0, 0, 0** | **0, 0, 0** | converged 3/3 | PASS ×3 |

Liveness was unchanged (tips 182–225 vs 184–237; tip spread 6–7 vs 6–15). Reorgs rise to
6–10 per soak because reconciliation actively moves losing nodes onto the canonical chain —
the intended cost. A final soak at pure shipped defaults: divergence 0, broken links 0,
derived state identical, 19/19, soak PASS.

**Ruled out along the way** (controlled A/Bs, no effect): reconciliation alone; a proposer
propagation-grace wait. The proposer's tip re-check was also made unconditional (it applied
only to backup proposers).

Tests: `tests/test_fork_choice_enforcement.py` (6, including the p2p call shape, which fails
with the old default), `tests/test_single_epoch_definition.py`,
`tests/test_proposer_tip_recheck.py`.

### Investigation history


**Severity: high (persistent fork ⇒ nodes disagree about what happened).**

Under fault injection (~20 reorgs in a 180s soak) the four nodes end up on **genuinely
different chains**, and stay there. Measured from preserved node databases after a run
where nodes 0 and 2 were both at tip 214:

```
heights in common: 215      differing block hashes: 10   (first at height 1)

height   1: 529df10f→nodes[0,3]  f1c55d80→node[1]  dabc2c01→node[2]   ← three-way
height  77: f1050180→nodes[0,1,3]                  8988d5c5→node[2]
height 146: aaebc707→node[0]                       ea509db4→nodes[1,2,3]
```

The groupings differ *per height*, so this is not one node trailing — it is several
partial histories that fork choice never reconciles.

**It is not cosmetic.** The derived state differs accordingly, which means the nodes
disagree about real activity:

```
token_balances (non-zero rows):  nodes 0,1 → 8 rows    nodes 2,3 → 6 rows
  extra on nodes 0,1:  two tokens × 1,000,000 held by 0x63318a60…  (two TOKEN_DEPLOYs)
account_state at EQUAL TIP 214:
  0x63318a60…  node0 = 990,000 QRDX    node2 = 1,000,000 QRDX   (a 10,000 CREATE_POOL stake)
```

So a liquidity pool and two QRC-20 tokens exist on two nodes and not on the other two.

**Why the existing guards do not catch it.** E-D4 compares a block's declared roots against
what the importing node computes for *that block*; a node on its own fork validates its own
chain consistently, so zero root mismatches are logged (confirmed: 0 across the run). A
persistent fork is fork-choice's job, not the root check's. This is also why the
integration suite's convergence assertions pass in quiet runs and only fail under churn —
`s17_clob_settlement` fails its cancel-refund convergence check because the nodes really are
on different ledgers, not because it polled too briefly.

**Relationship to the previously-noted issue.** This was recorded as "equivalent-state block
forks persist (different block hash per height) though state roots converge". That
understates it: the state does **not** converge here. The earlier observation was from
quieter runs where the forked blocks happened to carry equivalent activity.

**Independent of any recent change.** Measured with the failed-transaction-cost gate
disabled at the same churn level, the fork is *worse*: **19 differing block hashes of 198
common**, and a three-way token split (nodes 0,3 → 11 rows; node 1 → 12; node 2 → 10). The
low-churn control (9 reorgs) still shows 9 differing hashes but converged ledgers. So the
fork is always present; whether it surfaces as state divergence depends on whether real
activity happens to land on only one fork, which becomes likely around 20 reorgs.

**Reproduction:** `python -m integration_tests.run_scenarios --force --soak 180
--fault-inject`, then compare `block_hash` per height and `token_balances` across
`testnet/databases/node*.db`. Expect ~89% scenario pass (s17 + s18 fail) and a
finality-convergence soak violation (finalized-epoch spread of 7 against a tolerance of 2).
A run without `--fault-inject` passes 19/19, so churn is the trigger.

#### Progress (2026-09-28) — root cause found, enforce path implemented, not yet converged

**Root cause, from preserved soak databases.** Competing blocks at one height share a
PARENT but come from **adjacent slots**:

```
height | node0                       | node2
    66 | slot 73, proposer eC7FcA…   | slot 72, proposer 88aa1a…
    73 | slot 80, proposer d3d3C0…   | slot 81, proposer 88aa1a…
```

Both blocks are **valid**: RANDAO is off, so eligibility is strict (one proposer per slot),
and each block was signed by its own slot's rightful proposer. With a 2-second slot the
next proposer routinely builds before the previous block propagates, so two valid blocks
appear at the same height off the same parent. Eligibility cannot reject either, and
nothing else broke the tie — hence a permanent fork.

**The enforce path is now implemented.** `_ENFORCE_FORK_CHOICE_RECONCILE`'s enforce branch
was a stub ("intentionally not wired yet"), so flipping the flag did nothing. It now rolls
back via `handle_reorganization` (keeping its finality guard and depth cap) and then
**fetches the winner's chain** from the common ancestor forward.

Neither existing primitive does this alone, which cost two attempts to discover:

* `handle_reorganization` only ROLLS BACK — its caller in `_sync_blockchain` runs the
  fetch loop. Calling it alone leaves the node short with nothing re-fetched, so ordinary
  sync later pulls from an arbitrary peer and re-establishes the fork.
* `_sync_blockchain` refuses any peer that is not strictly LONGER
  (`"Local chain is at or ahead of remote. No sync needed."`). Equal-height reconciliation
  is exactly the case it declines — 204 enforce lines, nothing converged.

**Results so far — improving, not solved:**

| soak | reorgs | worst pairwise block divergence | derived state | scenarios |
|---|---|---|---|---|
| baseline (observe) | 20 | **19** | 3-way split | 95% FAIL |
| rollback only | 29 | 12 | node1 wrecked | 100% pass |
| via `_sync_blockchain` (no-op) | 10 | 22 | converged | 100% pass |
| rollback + fetch | 25 | **7** | converged | 89% FAIL |

Divergence improves 19 → 7 at comparable churn and **derived state converges on all four
nodes** — the economically harmful half. But no soak with enforce enabled has been clean,
and reorg counts swing between 10 and 29 across runs, so the scenario failures cannot be
separated from churn. The flag therefore stays **observe by default**
(`QRDX_ENFORCE_FORK_CHOICE_RECONCILE=1` to enable).

**A ceiling worth knowing:** divergence is observed at heights 1 and 2, far below the
finalized height. The finality guard correctly refuses to reorg below finality, and the
reconcile window is only `_FORK_CHOICE_WINDOW = 24` blocks from the tip. So historical
forks are **permanently unreconcilable by design** — this approach can only converge forks
while they are recent and unfinalized. Any complete fix must also prevent forks from
finalizing divergently in the first place, not just repair them afterwards.

#### Controlled A/B verdict: reconciliation does NOT fix this

Six runs, three per arm, **no fault injection** (it was the dominant variance source —
reorg counts swung 10-29 and swamped the signal):

| arm | run | worst pairwise divergence | derived state converged | scenarios |
|---|---|---|---|---|
| observe | 1 | 6 | no | 100% |
| observe | 2 | 10 | no | 89% |
| observe | 3 | 3 | no | 100% |
| **enforce** | 1 | 6 | **yes** | 89% |
| **enforce** | 2 | 4 | no | 100% |
| **enforce** | 3 | 7 | **yes** | 89% |

Block divergence: **6.3 vs 5.7** — ranges [3,10] and [4,7] overlap heavily at N=3. That is
not a difference. Derived-state convergence is the only signal in favour (2/3 enforce
versus 0/3 observe), and 2/3 is not convergence. **The flag stays observe by default.**

**This also corrects an earlier reading in this document.** A single quiet control run had
converged ledgers, which was taken as "the fork is harmless at low churn". These three
observe runs show derived state failing to converge with **no fault injection at all** —
that run was lucky, not representative. The fork corrupts state in ordinary operation, not
only under stress, which raises the practical severity.

#### Prevention attempt: proposer propagation grace — also no effect

If a proposer's tip is not from the immediately previous slot at slot N, the slot N-1
block may simply be in flight; the proposer now optionally waits half a slot so it can
arrive and be built on rather than raced (`QRDX_PROPOSER_PROPAGATION_GRACE`, behaviour-only,
cannot invalidate a block). Interleaved A/B, three runs per arm, no fault injection:

| arm | worst pairwise divergence | derived state converged |
|---|---|---|
| grace off | 7, 7, 5 (mean 6.3) | 1/3 |
| grace on | 7, 9, 2 (mean 6.0) | 2/3 |

No meaningful difference. It stays **off**. Together with the reconciliation A/B this rules
out both cheap levers — repair after the fact, and a short proposer wait. The race is not
won by waiting a fraction of a 2-second slot. The remaining candidates are structural:
**wire the existing, unused LMD-GHOST `ForkChoice`** (`qrdx/validator/fork_choice.py` —
attestation-weighted head selection is implemented but nothing calls `get_head()`), or run
with a slot duration comfortably above block propagation time.

#### The epoch fix substantially reduced it

Fixing the two epoch definitions (see the FIXED entry on staked principal) changed the soak
numbers sharply and consistently:

| | reorgs per soak | worst pairwise block divergence |
|---|---|---|
| every fault-injecting soak before the fix | 9–29 | 7–22 |
| three consecutive soaks after it | **3, 3, 3** | **3, 5, 6** |

Blocks had been stamped with 32-slot epochs while finality, attestation targets and the node
loop used 8-slot epochs, so the chain was disagreeing with itself about which epoch a block
belonged to. It is a major contributor, not the whole cause: divergence is still non-zero.

#### Parent links are broken on stored chains

Checking `parent_hash` from block content against the stored previous block shows nodes
holding blocks whose parent they do not have — at height 129, three nodes accepted a block
built on a block 128 none of them stored. (`blocks.prev_block_hash` is NULL for every row, so
the column cannot be used for this.) That is how forks can differ height by height:
`_ENFORCE_PARENT_CONTINUITY = False` lets a block onto a mismatched parent.

Earlier work found enforcing continuity **safe (6/6 soak) but insufficient alone**, and
concluded it must be enforced *together with* the equal-height tie-break. The tie-break's
enforce path was a stub until now, so **that combination has never been tested**. It is the
next experiment.

**Next steps for whoever picks this up:**
1. ~~Run the A/B at a controlled churn level~~ — done, see the table above: no
   meaningful effect on block divergence. Repair-after-the-fact is not the answer.
2. Investigate the "rollback declined" cases (finality guard / depth cap) — they were
   frequent, and a fork just above finality that cannot be repaired before it finalizes
   becomes permanent.
3. Consider attacking the cause rather than the symptom: a proposer that has not seen the
   previous slot's block should arguably wait or build at the next height, rather than
   racing at the same height.

**To close:** this is fork-choice convergence, and it gates anything that depends on block
history agreeing — including RANDAO selection (§6) and the validators-table reconstruction
(§2). Likely interacts with the equal-height tie-break
(`_ENFORCE_EQUAL_HEIGHT_TIEBREAK`) and parent-continuity
(`_ENFORCE_PARENT_CONTINUITY`), both currently **off**.

---
