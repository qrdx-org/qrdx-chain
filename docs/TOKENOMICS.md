# Token economics at ~$400 a QRDX

Every QRDX amount the protocol charges, requires or rewards, sized for a target price of about
**$400 a QRDX** and a **10M QRDX supply**. The values are chain-spec parameters
(`qrdx/chain_spec.py`) or constants (`qrdx/constants.py`), named below, each defined once. Every
one **awaits review** before mainnet (docs/KNOWN_ISSUES.md). A network needs a fresh genesis for
them.

## Supply

**10,000,000 QRDX** (`GENESIS_SUPPLY`): about $4B fully diluted at $400. Every QRDX at genesis is
allocated:
- the prefunded accounts;
- the validators' stakes;
- the system wallets.

A mainnet genesis whose allocations do not add up to exactly the supply is refused
(`validator/genesis.py`). A test network is warned.

| Allocation | QRDX | ~USD |
|---|---|---|
| Treasury (prefunded) | 4,993,000 | $2.0B |
| Foundation (prefunded) | 2,496,500 | $1.0B |
| Community fund (prefunded) | 1,497,900 | $600M |
| Validator incentive fund (prefunded): funds the genesis validators' stakes | 998,600 | $400M |
| System wallets (`0x…0001`–`0x…000a`), below | 14,000 | $5.6M |
| **Total** | **10,000,000** | **$4B** |

The prefunded accounts keep the earlier 10 : 5 : 3 : 2 shares of what the system wallets no longer
hold. Their holders (`GENESIS_PREFUNDED_ACCOUNTS`) are placeholders: a launch names the real
addresses, and takes the genesis validators' stakes out of the validator incentive fund, so that
everything sums to the supply.

**System wallets** are operating budgets of $100,000–$1,000,000 each
(`SYSTEM_WALLET_GENESIS_BALANCES`; they held 75M QRDX before):

| Wallet | QRDX | ~USD |
|---|---|---|
| Garbage collector (burner) | 0 | — |
| Community grants | 625 | $250,000 |
| Developer fund | 2,500 | $1,000,000 |
| Ecosystem fund | 1,250 | $500,000 |
| Staking rewards (rewards themselves are minted) | 2,500 | $1,000,000 |
| Marketing | 250 | $100,000 |
| Liquidity reserve | 2,500 | $1,000,000 |
| Treasury multisig | 2,500 | $1,000,000 |
| Bug bounty | 625 | $250,000 |
| Airdrop | 1,250 | $500,000 |

## Flows

**Minted:** staking rewards, `STAKING_REWARD_RATE_BPS` (5 %) a year on staked QRDX.

| Share staked | New QRDX a year | ~USD |
|---|---|---|
| 30 % | 150,000 | $60M |
| 60 % | 300,000 | $120M |

That is 1.5–3 % inflation a year.

**Burned:**
- gas outside the free trading lane, EVM and exchange;
- perp listing fees;
- ticker auctions;
- subsidized pools' stakes;
- slashed validator stakes and deployer bonds.

**Paid out:**
- QNS fees, to the treasury;
- 20 % of the protocol's trading fees, to stakers in QRDX;
- the rest of the protocol's share of perps fees, to the backstop vault.

## Trading pays no gas: the free lane

Hyperliquid charges no gas for trading, and neither does this. Spam is stopped another way. All
of the following are chain-spec parameters.

**What goes free.** A trading operation sent with `gas_price` 0 pays nothing: an order, cancel,
modify, trigger, TWAP, swap or leverage change, or a batch only of those. Turn the lane off with
`EXCHANGE_FREE_TRADING`.

**The budget.** It is spent from the account's free actions:
- **Budget:** `FREE_ACTIONS_INITIAL` (10,000), plus `FREE_ACTIONS_PER_VOLUME` (1) for each unit of
  settlement-asset volume it has ever traded. This is Hyperliquid's rule. A batch counts each of
  its actions.
- **Past it:** one free action every `FREE_ACTION_REFILL_SECONDS` (10) after the account's last.
- **Cancels:** free up to twice the budget, so a market maker can always pull its quotes.

**What stops spam.**

| Rule | Parameter | Default |
|---|---|---|
| Free actions need a holding of QRDX, or of perps equity, so a swarm of fresh accounts costs capital | `FREE_ACTION_MIN_QRDX`, `FREE_ACTION_MIN_EQUITY` | 0.025 QRDX (~$10), or 10 |
| Free actions of one account in a block, at most | `FREE_ACTIONS_PER_BLOCK` | 64 |
| Above this exchange base fee, relative to its floor, only cancels go free | `FREE_TRADING_MAX_BASE_FEE_BPS` | 2× |

Free operations' gas still counts toward every block's exchange gas limit and toward the base fee.
So a flood of free traffic raises the base fee, and past the threshold the free lane pauses:
everyone pays until the blocks clear. A refused free operation consumes nothing (no nonce, no
budget). The mempool refuses one its account could not send free, so spam never reaches a block.

**The gas system stays.** Every operation still declares and is metered in gas. Blocks are still
bounded by `BLOCK_EXCHANGE_GAS_LIMIT`, and the EIP-1559 base fee still prices congestion. Anything
outside the free lane pays it: deposits and withdrawals, token and pool creation, governance,
names, and a trader past its budget who chooses to pay rather than wait. The exchange's floor is
`EXCHANGE_MIN_GAS_PRICE_WEI`, 0.1 gwei.

**Using it.** `exchange_getFreeActions(address)` shows an account's budget, what is used, and
whether it would go free now and why not. The signing-payload endpoint and the CLI pick 0 for a
trading operation that would go free, and the floor otherwise.

## What changed

| Setting | Where | Before | Now | ~USD at $400 |
|---|---|---|---|---|
| Genesis supply | `GENESIS_SUPPLY` | 100,000,000 | **10,000,000** | $4B |
| System wallets, in total | `SYSTEM_WALLET_GENESIS_BALANCES` | 75,000,000 | **14,000** | $5.6M |
| Minimum validator stake | `MIN_VALIDATOR_STAKE` | 100,000 | **1,000** | $400,000 |
| Ejection floor | `VALIDATOR_EJECTION_STAKE` | 50,000 | **500** | $200,000 |
| Most effective stake per validator (1 % of supply) | `MAX_EFFECTIVE_STAKE` | 1,000,000 | **100,000** | $40M |
| Veto threshold (10 % of supply) | `GOV_VETO_THRESHOLD_QRDX` | 10,000,000 | **1,000,000** | $400M |
| Smallest delegation | `STAKE_MIN_DELEGATION` | 1 | **0.01** | $4 |
| AMM pool stake: standard / bootstrap / institutional | `EXCHANGE_POOL_STAKE_*` | 10,000 / 25,000 / 100,000 | **25 / 50 / 250** | $10k / $20k / $100k |
| Subsidized pool burn | `EXCHANGE_POOL_BURN_SUBSIDIZED` | 5,000 | **10** | $4,000 |
| Perp listing fee | `PERP_MARKET_LISTING_FEE` | 1,000 | **25** | $10,000 |
| Deployer bond | `DEPLOYER_MIN_BOND` | 100,000 | **1,250** | $500,000 |
| Ticker auction: opening / floor | `TICKER_OPENING_PRICE` / `TICKER_MIN_PRICE` | 10,000 / 500 | **250 / 25** | $100k / $10k |
| QNS, a year: 5+ / 4 / 3 characters | `QNS_PRICE_PER_YEAR` × `qns.price_factor` | 10 flat | **0.0125 / 0.4 / 1.6** | $5 / $160 / $640 |
| Staking fee discount tiers (5 %…40 %) | `STAKE_FEE_DISCOUNTS` | 10 … 500,000 | **1, 10, 100, 1k, 10k, 50k** | $400 … $20M |
| Trading gas | `EXCHANGE_FREE_TRADING` | paid | **free, budgeted** | — |
| Exchange gas price floor (outside the free lane) | `EXCHANGE_MIN_GAS_PRICE_WEI` | 1 gwei | **0.1 gwei** | ~$0.0024 an order |

Why these values:
- **Validators:** $400,000 each, a Hyperliquid validator's self-stake. Security is the total
  staked: 100 validators at the minimum is $40M.
- **Deployer bond:** $500,000. It must exceed what a malicious deployer could take before the
  validators freeze its markets. A new deployer market's open-interest cap is its liquidity
  vault's equity × 50 (10,000 of the settlement asset seeds it), and governance can raise the bond.
- **QNS:** ENS's ladder. **Discount tiers:** Hyperliquid's, in value.

Removed: `MAX_SUPPLY` (a leftover 2^25 from the proof-of-work chain, read by nothing),
`MIN_DEPOSIT` and `MAX_DEPOSIT` (unused). Each of these had a second copy that is now gone: the
system wallets' balances (in `crypto/system_wallets.py`, which is what genesis actually used),
the pool stakes, the delegation minimum and the maximum effective stake.

## What did not change, and why

- **Rates:** the staking reward rate, 5 %.
- **Amounts in the perps settlement asset** (USD in production):
  - the minimum order, 10;
  - a market's seed liquidity, 10,000;
  - vault minimums;
  - the funding impact notional;
  - spot-oracle depth.
- **The EVM's gas floor, 1 gwei:**

  | Transaction | ~USD |
  |---|---|
  | A transfer | $0.008 |
  | A post-quantum transaction | $0.04 |
  | A 1.2M-gas contract deployment | $0.48 |

## Decisions still open

1. The prefunded accounts' real holders and shares (placeholders now, in the old proportions).
2. The genesis validators: how many, and their stakes out of the validator incentive fund.
3. The staking reward rate (5 %).
4. The free lane's numbers: 10,000 actions, 1 per unit traded, 10 s refills, 64 a block, a $10
   holding, 2× the base fee floor.
