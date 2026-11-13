# Exchange audit, 2026-10-27

An internal audit of the whole exchange: spot (pools, order books, routing), perps, triggers and
TWAPs, native tokens, NFTs, names, governance, account control, the bridge's consensus side, the
EVM precompiles, and the paths that apply blocks. It is not a substitute for an external audit, which mainnet still needs
(docs/KNOWN_ISSUES.md).

Every finding below was reproduced before it was fixed, and each has a test that fails on the
code before the fix. Nothing here is committed yet. A network needs a fresh genesis for the
fixes.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | **Critical** | A proposer could forge exchange transactions from any account | Fixed |
| 2 | **High** | A failed operation left a pool's price moved | Fixed |
| 3 | **High** | A token's issuer could lock other people's funds in a shared pool | Fixed |
| 4 | Medium | One spot trigger made every block walk every order book | Fixed |
| 5 | Medium | Spot swaps and orders missed better prices; triggers never saw pools | Fixed (docs/UNIFIED_SPOT_LIQUIDITY.md) |
| 6 | Medium | A stop-market the price gapped past vanished unfilled | Changed (the user's choice) |
| 7 | Low | Five operations left plain state behind when rolled back | Fixed |
| 8 | Low | Each block reset every order book | Fixed |
| 9 | Low | Five smaller items | Fixed (one partly: inherent to agents) |
| 10 | Medium | One validator could fill the bridge's state with deposits that never happened | Fixed |
| 11 | Low | Two smaller items from the second pass | Fixed |

### 1. A proposer could forge exchange transactions from any account (critical)

The exchange executes transactions without checking signatures; whoever applies a block must
verify them first. The importer did, but only when the block declared an exchange state root.
A block that left the root out was "trust-replayed": its section executed as it was, unverified.

A proposer, which needs only to be eligible for one slot, could therefore include an unsigned
transaction in any account's name and leave the root out. Every node would execute it, and the
unified state-root check could not catch it: the proposer computed that root with the forged
transaction included. In the test, an unsigned `TOKEN_TRANSFER` moved a victim's whole token
balance to the thief, and the block was accepted.

**Fix.** `_apply_exchange_section_on_import` (`qrdx/node/block_import.py`) authenticates every
transaction in the section before anything changes, on both paths. A section with any
transaction that fails verification rejects the block. The p2p and REST import paths both go
through it. The EVM section was already safe: a post-quantum EVM transaction is verified where
every path decodes it.

Test: `test_exchange_audit.py::test_a_block_without_an_exchange_root_cannot_carry_forged_transactions`.

### 2. A failed operation left a pool's price moved (high)

An operation is all or nothing: if any part fails, everything it did is undone. A pool's state
was the exception. Its snapshot was restored only if the failure came inside the step that moved
the pool. A failure after that step undid every balance but left the pool at the swap's price, so
its curve no longer matched what its holder held:
- a `BATCH` whose swap succeeded and whose next action failed;
- a two-hop swap that missed its `min_amount_out`.

Anyone could move a pool's price for free with a batch built to fail, then trade against the
moved price at the liquidity providers' expense. **Fix:** the snapshot belongs to the
operation's undo scope (`ExchangeStateManager._atomic`).

Test: `test_unified_spot.py::test_a_failed_batch_puts_its_swaps_pool_back`.

### 3. A token's issuer could lock other people's funds in a shared pool (high)

Native tokens carry Token-2022-style authorities. Their issuer can freeze an account, pause the
token, or move anyone's tokens as the permanent delegate. Pointed at a pool's holder, each of
those locked the pool:

| Authority | What the issuer did | Effect |
|---|---|---|
| Freeze | Froze the pool's holder | No one could withdraw from the pool, the QRDX side included |
| Pause | Paused the token | Same: withdrawals failed |
| Permanent delegate | Pulled the token out of the pool's holder | The pool could no longer cover its positions: withdrawals failed, and the delegate kept the pool's tokens |

The same applied to order-book escrows and every other holder of many accounts' funds.

**Fix.** These are protocol holders of many accounts' funds (`holds_pooled_funds`): every
synthetic holder except a sub-account, which is one account's own.
- They cannot be frozen, including by a token that starts every account frozen.
- No delegate or operator can move or burn tokens out of them.
- A paused token still blocks trading, but liquidity withdrawals and the refunds of escrowed
  orders, triggers and TWAPs pay out. The owner gets the token back into their own balance,
  where the pause still applies.

An issuer keeps every power over individual accounts, which is what compliance needs. It loses
only the power to hold everyone else's assets hostage.

Tests: `test_exchange_audit.py` (four tests).

### 4. One spot trigger made every block walk every order book (medium)

The tick for spot triggers visited every pair's book whenever any trigger existed anywhere:
47 ms a block at 10,000 pairs, a fifth of a 250 ms slot, and growing with every listing.
**Fix:** it visits only the pairs that hold triggers (`TradingState.trigger_pairs`): 0.025 ms.

Test: `test_exchange_audit.py::test_the_trigger_tick_and_the_block_start_leave_idle_books_alone`.

### 5. Spot swaps and orders missed better prices; triggers never saw pools (medium)

Found on the user's question the same day. A swap never routed through another token and used
one venue at a time. A limit order matched only the book while a pool offered better. A swap
could push a pool past resting orders without filling them. Spot stops watched only book trades.
See docs/UNIFIED_SPOT_LIQUIDITY.md.

### 6. A stop-market the price gapped past vanished unfilled (medium)

A market trigger fills within 10 % of its price. If the price jumped past that band, it fired,
filled nothing and was gone. Hyperliquid does the same. The user chose to change it: the
unfilled part waits and fires again whenever the market is back within its band, on spot and
perps (docs/UNIFIED_SPOT_LIQUIDITY.md 5, docs/HYPERLIQUID_PARITY.md).

### 7. Five operations left plain state behind when rolled back (low)

The undo scopes restore committed collections, order books, the clearinghouse and anything an
operation registers. A plain field or registry that an operation changed without registering
it stayed changed after a rollback:

| Operation | What stayed |
|---|---|
| `CREATE_POOL` | The pool, its pair's order book and oracle, the pool counter |
| `BRIDGE_WITHDRAW` | The withdrawal counter |
| `GOV_PROPOSE` | The proposal counter |
| `GOV_EXECUTE` (`freeze_master`) | The master freeze |
| `ORACLE_VOTE` | The votes it recorded |

None of these operations can fail after the change today, so none was exploitable. Each would
have become a bug the day one could. All are now registered with the undo scope.

**How they were found.** A test-suite plugin ran every operation of the whole suite (3,700
tests) once inside an undo scope, failed it on purpose, and checked that the state root was
exactly what it was before. It then ran it for real and checked that the outcome matched. The
plugin is described below.

Tests: `test_exchange_audit.py` (four tests); the batch case under finding 2.

### 8. Each block reset every order book (low)

`begin_block` reset every pair's book: 15 ms a block at 10,000 pairs.

**Fix.** A book starts the block the first time a user's order uses it in that block
(`OrderBook.enter_block`): its per-block rate limits reset and its time is set. Only a book
holding orders that can expire starts at the block's beginning, so expiry is still judged every
block; no operation sets an expiry today. The block's start now costs 0.004 ms at 10,000
pairs, whatever their number.

Test: `test_exchange_audit.py::test_the_trigger_tick_and_the_block_start_leave_idle_books_alone`.

### 9. Five smaller items (low)

- **Staker fee conversion visited every token with pending fees each block.** A token with no
  QRDX pool waits there for good: 1.9 ms a block at 10,000 such tokens. **Fixed:** an index by
  due time (`_due_fee_tokens`), 0.007 ms. Due tokens are still converted in token order.
- **Unused code executed exchange transactions unverified** (`consensus.execute_and_validate_exchange`,
  step 7 of the unused `validate_pos_block`). **Fixed:** it authenticates every transaction
  first, as the import path does. Its tests now sign theirs, and one shows an unsigned
  transaction refused.
- **The pairs' reporter oracles** (`TWAPOracle`, one per pair) were created with every pool and
  committed in the state root, but nothing updated them. **Removed** from the manager, the
  router, both state roots, the state proofs and the reorg snapshots. The class itself stays, a
  tested utility.
- **An agent could steer an account's swap into a pool it owns.** A swap may name its pool
  (`pool_id`) or venue, past better prices elsewhere. **Fixed:** a swap signed for an account by
  a trading-only delegate (an agent, or a vault's leader) takes the best route; it may not name
  a pool or venue. The account itself, its controllers and its sub-account's master still may.
  What remains is inherent to trading agents, Hyperliquid's included: an agent chooses what to
  trade, and a market it controls can be the only one for a token. The account's agent spending
  limits bound that.
- **Issuers keep power over individual balances** (freeze, pause, clawback), by design. **Now
  visible:** a token's view (`exchange_getToken`, `exchange_getTokens`) lists what its issuer can
  still do, in plain terms (`issuer_powers`), for wallets to show before anyone buys it.

Tests: `test_exchange_audit.py`; `test_exchange_integration.py::TestConsensusIntegration`;
`test_exchange_engine.py::TestUnifiedRouter::test_the_router_keeps_no_reporter_oracle`.

### 10. One validator could fill the bridge's state with deposits that never happened (medium)

Validators attest deposits in their oracle votes, up to 16 a vote. Each attestation short of a
quorum stays in the consensus state for a day. Nothing limited how many one validator held.

An honest mempool keeps one vote per validator per block. But a validator's own block can carry
as many of its votes as its gas allows. Every block's expiry then walked all of them: 20 ms a
block at 100,000. A chain-head vote could also name any chain id, each recorded for an hour.

**Fix.**
- **Cap:** a validator may hold at most `MAX_PENDING_PER_VOTER` (1,024) attestations short of a
  quorum. Past it, its new ones are ignored, not refused, so the rest of its vote still counts.
  Real deposits reach a quorum within blocks, so honest validators never come near it.
- **Index:** pending attestations are indexed by deposit, voter and age, so expiry and minting
  touch only their own entries. Expiry costs 0.008 ms a block at 100,000.
- **Chain heads:** only the chains the network bridges (`BRIDGE_ASSETS`); any other head is
  skipped.

Tests: `test_exchange_audit.py` (three tests).

### 11. Two smaller items from the second pass (low)

- **Waiting stops that open a position.** A perps stop that opens a position and waits for the
  book (finding 6) retried within 10 % of the current mark. A breakout buy at 103 that the
  price gapped past to 130 could fill near 130. It now fills only within 10 % of its trigger,
  as a spot stop does. A stop that reduces a position still gets out within 10 % of the mark.
  Test: `test_trading_ops.py::test_a_waiting_entry_stop_never_fills_far_past_its_trigger`.
- **A recovery sent as a policy change** (`ACCOUNT_POLICY` with action `recover`) failed with a
  type error, logged as unexpected. It now fails cleanly: a recovery is the guardians'.

## Method

| Check | How |
|---|---|
| Rollback completeness | A plugin that fails every operation of the test suite on purpose inside an undo scope and compares the state root (finding 7). |
| Determinism | Grep for wall clock, randomness, `hash()` and the decimal context in consensus code. Then the whole suite run in three processes, two of them with different hash seeds, comparing every test's final exchange root. |
| Block authentication | Every path that applies a block traced to where its signatures are verified (finding 1). |
| Unchecked balance moves | Every "covered" move (one that skips the balance check) checked against the record that backs it. |
| Authorization | The agent scope, every token authority, and every authority checked against protocol holders (finding 3). |
| Per-block cost | Tick and block-start work measured at 1,000 and 10,000 pairs, triggers and fee tokens (findings 4 and 8). |
| Restarts | The checkpoint's contents checked against every counter and registry that decides future ids. |
| Hostile input | NaN, infinities and huge exponents in amounts and prices: each fails inside its undo scope and changes nothing. |
| New code | Unified spot liquidity (finding 5) re-read, and the rebuild-equivalence test extended to every new path. |

### Coverage

**Second pass (same day).** Every area the first pass had only spot-checked was read:
- account control: multisig, controllers, delays and social recovery;
- the bridge's consensus logic: attestation, quorum, minting, withdrawals and chain heads;
- governance;
- NFTs;
- the EVM precompiles that read and write the exchange;
- the RPC and REST entry points;
- the perps changes since the perps audit of 2026-10-23.

It found findings 10 and 11. The rest held up:
- **Account control:** a waiting change can be cancelled; own-key changes drop if the key is
  turned off; a recovery needs the guardians' threshold and a delay.
- **Governance:** votes are counted against a stake snapshot, vetoes lock real QRDX, and
  execution re-checks the action.
- **NFTs:** ownership changes in one undo-safe place.
- **EVM precompiles:** they refuse DELEGATECALL, value and static calls.
- **Entry points:** every write enters through a verified transaction.

**Not re-audited:** the perps clearinghouse's margin, funding and liquidation arithmetic. It was
audited on 2026-10-23, and only the changes since were read. Market data and the journal are
node-local and not consensus.

The external audit should start with:
1. block authentication (finding 1);
2. the undo scopes;
3. token authorities against protocol holders;
4. the unified spot walk (`router.plan_fill`);
5. the bridge's attestation (finding 10).

## Results

- **Live, 4 nodes, with every fix in:** every block carrying exchange transactions imported on
  every node, with no verification failures and no rejections. One node was restarted
  mid-run, replayed from its checkpoint, and then traded on the same order book again. The
  spot paths ran: an uncross, a swap routed through QRDX, limit orders filled by a pool. All
  four nodes agreed on pools, book, balances and the exchange root.
- **Full suite:** 3,727 passed.
- **Static checks:** ruff, black, isort and mypy clean on `qrdx/`.
- **Rollback plugin, whole suite:** no operation leaves state behind. The remaining reports are
  refusals made before execution, which the plugin's trial skips by design.
- **Determinism:** the suite ran three times, twice with the same hash seed and once with
  another. Of 1,986 final exchange roots, **none** changed with the hash seed, so no state
  depends on set or dict order. Roots that differed between same-seed runs all came from the
  tests themselves: random keys, the wall clock, or a test that never touches the exchange
  logging what the previous one left. Every file with fixed inputs matched across all three
  runs, about 150 tests.
