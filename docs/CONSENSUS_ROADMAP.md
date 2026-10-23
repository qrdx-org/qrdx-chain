# Consensus roadmap — the next protocol features

The features after the trading set (docs/TRADING_FEATURES.md) and account control
(docs/ACCOUNT_CONTROL.md): what each is for, how it is designed to be enforced by consensus, and
where it stands. Every item is consensus state or a consensus rule: executed identically by every
node, committed in the state root, and replayed on every path (proposer, importers, rebuilds).

| # | Feature | Status | Code · tests |
|---|---|---|---|
| A | Every protocol holder has an address | built | `views.protocol_addresses` · `test_qns.py` |
| B | Who controls an address — an API, both directions | built | `views.authority` / `controlled` · `test_qns.py`, `test_recovery_and_agent_limits.py` |
| C | QNS — names as native NFTs | built | `exchange/qns.py` · `test_qns.py` |
| 1 | Fair ordering of exchange transactions | built (step 1) | `exchange/fair_ordering.py` · `test_fair_ordering.py` |
| 2 | Per-market risk limits: open-interest caps, leverage tiers | built | `clearinghouse.py` · `test_risk_limits.py` |
| 3 | Price bands and circuit breakers | built | `clearinghouse.py` · `test_risk_limits.py` |
| 4 | Delisting a market | built | `governance.py`, `Clearinghouse.delist` · `test_delisting.py` |
| 5 | Oracle hardening | built | `_aggregate_votes` · `test_oracle_hardening.py` |
| 6 | Trading fees to stakers | built (every asset) | `validator/epoch_state.py`, `convert_staker_fees` · `test_staker_fees.py`, `test_staker_fee_conversion.py` |
| 7 | Social recovery, agent spending limits | built | `authority.py`, `trading.py` · `test_recovery_and_agent_limits.py` |
| 8 | Provable state, verified on chain | built (all state) | `state_proofs.py`, `exchange/proofs.py`, `crypto/smt.py`, precompile 0x…0300 · `test_smt.py`, `test_state_proofs.py`, `test_exchange_proofs.py` |

The features that bring the protocol to Hyperliquid's are in docs/HYPERLIQUID_PARITY.md:
- action expiry and the dead man's switch;
- isolated margin and builder codes;
- the order grid and staking fee discounts;
- contracts reading and trading on the exchange;
- deployer markets (HIP-3).

Frequent batch auctions (step 2 of item 1) were skipped by decision on 2026-10-22.

**Verified live (2026-10-22)** on an isolated 4-validator network at 250 ms slots, with spot
trading, QNS, agent limits, guardians, fee income and a validator restarted mid-run: all four
nodes agreed on every block; every node's own recorded proof, exchange-tree and database-tree
roots reproduced the signed root at every height; staker fee income and payouts were identical on
every node and paid out exactly what came in; proofs built on one node verified on the other
three against their own headers, and forged ones failed. The runs found and fixed two consensus
bugs (docs/KNOWN_ISSUES.md: a restarted node credited fee payouts from nothing; blocks were judged
by their slot where their height was meant).

Every default below is a chain-spec parameter or a module constant and **awaits review** before
mainnet (docs/KNOWN_ISSUES.md). A network needs a fresh genesis for the new operations, the new
features (`fair_ordering`, `provable_state`) and the new state.

---

## A. Every protocol holder has an address

Every protocol-owned balance is held at an address — a protocol form no key can sign for
(`qrdx/crypto/account_id.py` `SYNTHETIC_HOLDER_PREFIXES`), or a genesis system wallet — so every
balance can be looked up, indexed and, with #8, proven.

| Holder | Address |
|---|---|
| An AMM pool's reserves | `0xPOOL…` (per pool) |
| A spot book's escrow (resting orders, triggers, TWAPs) | `0xCLOB…` (per pair) |
| All perps collateral | `0xPERP…` |
| Governance veto escrow | `0xVETO…` |
| The bridge's mint authority | `0xBRDG…` |
| Sub-accounts | `0xSUBA…` |
| User vaults, markets' liquidity vaults | `0xUVLT…` |
| The perps backstop vault (fees, takeovers) | `0xHLPV…` — was the internal name `@vault` |
| Protocol-owned vault shares | `0xPROT…` — was `@protocol` |
| QNS's mint authority | `0xQNSA…` |
| Treasury, grants and the other system wallets | their genesis addresses (`TREASURY_MULTISIG`, …) |

`exchange_getProtocolAddresses` lists them all. Gas is burned (it leaves supply; no address
holds it).

## B. Who controls an address

`account_getAuthority(address)` returns everyone who may sign for an address and how:

- its policy's controllers, whether its own key is on, its delay and waiting changes;
- the agent keys it approved;
- its master, if it is a sub-account;
- its leader, or the market it makes, if it is a vault;
- its members and threshold, if it is a multisig.

`account_getControlled(address)` is the reverse: the accounts it controls, the sub-accounts it
masters, the vaults it leads, the accounts that approved it as an agent, the multisigs it is a
member of, and the QNS names it owns.

A multisig's members are public once it is known: a multisig-signed exchange transaction records
its keyset (address → threshold, member keys) the first time it executes, and
`ACCOUNT_POLICY publish_keyset` records one that has only signed in the EVM.

## C. QNS — the QRDX Name Service

Names are native NFTs (docs/NATIVE_TOKENS.md §8) in a protocol collection, so they move, approve
and appear in the EVM (ERC-721) like any NFT. The protocol is their only minter.

- **A name:** `label.qrdx`. Labels are 3–59 of a-z, 0-9 and hyphen, with no leading or trailing
  hyphen. Its token id is a hash of the name.
- **`QNS_REGISTER {name, years, target?}`:** mints it to the sender for `years` (1–10) at
  `QNS_PRICE_PER_YEAR` (chain-spec; default **10 QRDX a year**), paid to the treasury.
- **`QNS_RENEW {name, years}`:** anyone may pay.
- **`QNS_SET_RECORD {name, key, value}`:** the owner (or an approved operator) sets `address`
  (where the name resolves) or text records.
- **`QNS_SET_PRIMARY {name}`:** the reverse record, valid only while the name resolves to the
  sender.
- **Expiry:** a name resolves until it expires. After a 30-day grace period anyone may register
  it again, and the old NFT is burned.

## 1. Fair ordering

**Problem:** the proposer orders a block's exchange transactions, so it can trade ahead of an
order it has seen, or ahead of a trigger it knows will fire.

**Design**, in two steps:

1. **Built — within a block, cancels and post-only orders run first** (Hyperliquid's rule), so
   a maker can always pull or improve its quotes before any taker in the same block. Classes:
   cancels (`CANCEL_ORDER`, `PERP_CANCEL`, `CANCEL_ALL`, `TWAP_CANCEL`, and oracle votes, which
   only record), then post-only orders (`tif: "alo"`), then everything else (a `BATCH` takes its
   highest action's class). A nonce lane's transactions must still run in nonce order, so each
   transaction's **effective class** is the highest of its own and its lane's earlier ones in
   the block; a block whose effective classes ever decrease is refused before anything runs
   (`process_exchange_transactions`, every path). The proposer meets the rule by a stable sort
   on the effective class. Chain-spec feature `fair_ordering` (genesis default).
2. **Skipped (decision of 2026-10-22) — frequent batch auctions:** each block clears its crossing orders at one price
   per market, so order within a block carries no information. **A product decision, not a
   fix:** it replaces continuous matching with a matching phase at each block's end, which
   changes what every order means — a fill is known only when the block closes (receipts, IOC
   and fill-or-kill, market orders, triggers and liquidations all move to the batch), and the
   market data and book views with it. What it buys over step 1 is the last of the ordering
   value: with cancels and post-only orders first, a proposer can still order takers against
   each other within a block, but not against makers. Hyperliquid runs exactly step 1. The
   recommendation is to stay there unless measured taker-vs-taker ordering value says
   otherwise.

## 2. Per-market risk limits

- **Open-interest cap:** an order whose fills would raise a market's open interest (notional at
  mark) past its cap is refused whole — its fills run in an undo scope of their own, so the
  refusal changes nothing whoever placed it (a trigger, a TWAP slice). Reduce-only orders always
  pass. The cap is `max(PERP_MIN_OI_CAP, liquidity vault equity × OI_CAP_MULTIPLE)` (chain-spec
  floor 0, multiple 50); a market with neither is uncapped.
- **Leverage tiers, marginal:** each slice of a position's notional above a tier's floor carries
  that tier's leverage — full maximum leverage to 1,000,000, half to 10,000,000, a quarter
  beyond (`LEVERAGE_TIERS`), never more than the account's own setting
  (`clearinghouse.initial_margin`). Being marginal, the requirement rises continuously: no cliff
  at a floor, and no step the user must take first. It is the initial margin — what an order and
  a withdrawal must leave (cross and isolated alike). Maintenance is unchanged, so liquidation
  prices stay linear.

## 3. Price bands and circuit breakers

- **Band:** a perp order priced more than `PERP_PRICE_BAND_BPS` (chain-spec, 2,000 = 20 %) worse
  than the oracle for its owner — a buy above, a sell below — is refused. This catches fat fingers
  and stops a manipulated book from trading far from the index. Liquidations and backstops match
  directly and are not banded.
- **Circuit breaker:** when a market's mark moves `PERP_BREAKER_MOVE_BPS` (1,000 = 10 %) within
  `PERP_BREAKER_WINDOW_SECONDS` (300) of block time, the market holds to reduce-only orders for
  `PERP_BREAKER_COOLDOWN_SECONDS` (60): new exposure is refused, non-reducing triggers wait, the
  liquidity vault pulls its quotes. The tick emits a `circuit_breaker` event; the state is in the
  market's committed header. 0 turns either off.

## 4. Delisting

A governance action, `delist_market {market_id, price?}` (docs/GOVERNANCE.md): proposed by a
validator, voted, timelocked and vetoable like any. When executed, every order and trigger in the
market is cancelled and every position closed at one settlement price (the price given, or the
oracle's at execution) — zero-sum, since the sizes net to zero; its TWAPs end; its liquidity
vault stops quoting and its creator's lockup ends. The market then refuses every order and
trigger, its tick does nothing (no mark, no funding), and its header records `settled`. An
account the settlement leaves in debt is the tick's to resolve, as any debt is. An execution that
cannot settle (no such market, already delisted, no price) fails and may be retried within the
execution window.

## 5. Oracle hardening

- **Quorum by count as well as stake:** at least `ORACLE_MIN_VOTERS` (chain-spec, 3) fresh votes
  besides the stake majority — or the whole committee, if it is smaller.
- **Jump bound, per second:** the applied price moves at most `ORACLE_MAX_STEP_BPS` (500 = 5 %)
  **a second of block time** since the oracle last moved — a per-block bound means nothing at
  250 ms slots. A larger move is walked while votes keep confirming it (a 50 % crash: ~14 s),
  and the circuit breaker watches the walk. An oracle stale for a long time (a halt) catches up
  at once.
- **Outlier record:** each applied aggregation counts, per validator, the votes further than
  `ORACLE_OUTLIER_BAND_BPS` (200 = 2 %) from the median (`oracle_outliers`, in the exchange root;
  `governance_getStatus`). Penalties for persistent outliers can build on it.

## 6. Trading fees to stakers

`STAKER_FEE_SHARE_BPS` (chain-spec, 2,000 = 20 %) of the protocol's trading-fee income goes to
the validators and their delegators, as real yield beside the minted rate:

- spot fees: that share goes to the fee holder `0xFEES…` instead of the treasury, in whatever
  asset the fee was paid;
- perps fees: that share of the backstop vault's fee income leaves the clearinghouse (its records
  and its holder alike) and moves to the fee holder at the block's end, in the perps collateral.

Fees in QRDX are staker income at once. Fees in another asset — the perps stablecoin, a spot fee
received in a token — wait at the fee holder (`fees.tokens`, committed) and the block's tick sells
them for QRDX (`convert_staker_fees`): through the best route, at most once a minute of block time
per token, and only at no less than 2 % under the token's QRDX pool's 10-minute TWAP — all of it,
else a quarter, else it waits. An attacker must hold a manipulated price for the TWAP's length to
move the floor, and a sale into a price pushed down in its own block is refused. A token without a
QRDX pool, or without the TWAP's history yet, waits. The QRDX a sale brings is that block's staker
income.

Each block logs what it took in (`staker_fee_income`, one row per block, written by every path
alike, dropped above a rollback). The epoch transition (`qrdx/validator/epoch_state.py`) shares
the epoch's income — with any remainder carried — among the validators whose vote is carried
(those the minted rewards pay), by principal and pool: the validator is paid its part and its
commission on the pool's; the rest compounds into the pool. Fee payouts are paid **out of the fee
holder**, never minted (`withdrawals._payout_moves`), so supply is exact; rounding stays carried.



## 7. Social recovery, agent spending limits

- **Guardians** (docs/ACCOUNT_CONTROL.md): `ACCOUNT_POLICY guardians {guardians, threshold,
  recovery_delay}` — up to 7, a delay of 1 to 30 days (default 7). Setting them is a policy
  change: signed by the own key it waits out the account's delay, so a stolen key cannot quietly
  name its own guardians. Each guardian backs a new controller with `ACCOUNT_RECOVER {account,
  new_controller}` (`""` withdraws its backing). When the threshold back the same one, a
  `recover` change is queued, due after the recovery delay; the own key or a controller may
  `cancel` it meanwhile. Applied, it binds that controller in place of all others and turns the
  own key off. For an account whose keys are all lost.
- **Agent limits:** `AGENT_APPROVE {max_notional_per_day}`. Every order a limited agent places
  counts at its full size × limit price (perps settlement asset), filled or not; cancels count
  nothing; a failed operation counts nothing (the count is in its undo scope). What cannot be
  valued before it runs is refused to a limited agent: a spot market order, a swap or spot TWAP
  that does not spend the settlement asset, a pair not priced in it. The day is the block day;
  `account_getAuthority` shows what each agent has placed today.

## 8. Provable state, verified on chain

**Answer to "shouldn't it all be proved on chain":** it already is in one sense. Every validator
executes every block, and the state root is in the signed, finalized header. What was missing is
proving one value against that root to someone who does not execute: a contract, a bridge, a
light client. The roots are LtHash accumulators — fast to update, unable to prove that one entry
is in them. Built (docs/STATE_PROOFS.md):

- **Sparse Merkle trees** (`qrdx/crypto/smt.py`, compressed: log2(n) hashes an update or a
  proof) over all of the state. The database's — every account, contract storage slot and token
  balance — is kept from the same rows' triggers as the accumulators and folded in when a block's
  root is computed, inside the block's transaction. The exchange's — every committed collection,
  every order-book level, every market's, pool's and book's fields, the oracle — is kept by each
  collection beside its LtHash, from the same changes, in immutable nodes that travel with every
  copy and undo of the state. The two roots combine into the proof root, a **fifth input of the
  unified state root** — the root every block signs — under the chain-spec feature
  `provable_state` (genesis default).
- **Proofs:** `state_getProof` returns an entry (or its absence), its path, and the domain roots
  that reach the signed root; `state_verifyProof` and `state_proofs.verify_against` check one.
  Proofs hold for any retained height (`QRDX_STATE_PROOF_RETENTION_BLOCKS`, node-local).
- **On chain:** the precompile at `0x…0300` verifies a proof against an **ancestor** block's
  signed root (read from this chain's stored block — the same on every node) and returns 1 or 0.

Nothing is provable only by trusting a node: a perps position, a resting order's level, a QNS
record or a market's mark is proven like a balance (docs/STATE_PROOFS.md).
