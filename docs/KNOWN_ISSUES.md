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

## OPEN — Perpetuals: rebuilt on a zero-sum clearinghouse; waiting on the bridged stablecoin

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
* **The bridged stablecoin does not exist yet.** The token standard can now carry one — a token
  deployed with zero supply and a mint authority ([NATIVE_TOKENS.md](NATIVE_TOKENS.md)) — but the
  bridge cannot drive it: its `BridgeMinter` (`qrdx/bridge/shielding.py`) only tallies
  minted/burned totals in memory and credits no ledger. What is missing is a consensus bridge:
  deposits attested by a validator quorum, minted through a protocol-held mint authority, and
  burns released on the source chain by its custodian. Until then mainnet has no collateral to
  configure (the default, unset, refuses deposits); the testnet deploys a test token.
  Native-QRDX settlement remains for development only.
* **Oracle votes are not gossiped.** A vote rides only in its voter's own blocks, so on a large
  validator set each validator's vote refreshes only as often as it proposes. Slashing does not
  yet remove a committee member (only `STAKE_EXIT` does); weights are principal stake.
* **A validator's exchange nonce now moves on its own.** Each vote consumes one. A validator's
  own exchange transactions (e.g. `STAKE_EXIT`) should be submitted to its own node, whose
  proposer orders them ahead of its vote; signed elsewhere with a predicted nonce they can go
  stale. (The integration scenarios that signed spot trades as validators now use their own
  wallets — S15 failed on exactly this.)
* **Mark-price robustness** — without other venues' perp prices as the third input, a
  sustained squeeze on a thin book can move the mark to the ±5 % band in about a minute.
  Depth is the defence; validators could also vote an external perp price.
* Smaller gaps: a resting order reserves margin even when it would only reduce the position
  (conservative); large positions are liquidated whole, not in Hyperliquid's 20 % slices; the
  vault holds the positions it takes over rather than unwinding them (it is book-liquidated
  only if it falls under maintenance); after a halt spanning several funding intervals, one is
  paid; anyone may create a market (it trades only once validators price it).

## OPEN — Three things block the first release

**Severity: high (blocks every release).** Signed releases and reproducible builds are in place
([RELEASES.md](RELEASES.md)), but no release can be cut until these are fixed:

1. **`dvm` is recorded as a submodule that no clone can fetch.** The tree has a gitlink at
   `dvm` (commit `ddc8868`, the legacy denaro-coin VM, added in `ff83360`) with no
   `.gitmodules` entry. It works only in checkouts that happen to have a `dvm/` repository.
   Every fresh clone with submodules fails with "No url found for submodule path 'dvm'",
   including `actions/checkout` with `submodules: recursive` in the release workflow. Nothing
   in `qrdx/` uses it. `release.py preflight` now refuses it. **To close:**
   `git rm --cached dvm`, then add `dvm/` to `.gitignore` (or declare it in `.gitmodules` if it
   is meant to ship).
2. **The EVM change the tests ran against is not committed.** `py-evm` has an uncommitted
   change to `eth/vm/forks/qrdx/precompiles.py` (+41/−635). The test suite and every
   working-tree image so far ran *with* it. A release built from a tag gets the submodule's
   recorded commit, *without* it. **To close:** commit it in `py-evm`, push it to
   `qrdx-org/py-evm`, and commit the new submodule pointer here. A fresh clone must be able to
   fetch every recorded commit.
3. **No maintainer keys are registered.** `release/allowed_signers` is empty on purpose, so
   nothing verifies. **To close:** at least `maintainer_threshold` (2) maintainers add their
   keys ([RELEASES.md §5](RELEASES.md#5-cutting-a-release-maintainers)), and the GitHub
   settings listed there are applied: branch protection, a `v*` tag ruleset, and a public GHCR
   package.

The full flow (preflight, build from the tag, source tarball, manifest, two maintainer
signatures, an operator `verify --rebuild` reproducing the image) was rehearsed end to end on a
scratch clone where items 1 and 2 were fixed.

## OPEN — QRDX's chain ids are not registered yet

**Severity: low (process).** Mainnet is chain id **762** (`qrdx-mainnet`) and the testnet
**7620** (`qrdx-testnet`). Both were unassigned in ethereum-lists/chains and chainid.network on
2026-10-09. The code reserves them: only those networks' specs may use them, and a dev node
can't (`chain_spec.QRDX_NETWORKS`). But an id is only "ours" once it is registered. Every
signed transaction is bound to it, so another chain taking 762 would make keys used on both
replayable.

**To close:** submit `eip155-762.json` and `eip155-7620.json` to ethereum-lists/chains.

## OPEN — The peer RPC transport is unauthenticated

**Severity: medium.** Node-to-node calls go over plain JSON-RPC (`NodeInterface._rpc_call`): no
request signature, and `p2p_handshakeResponse` consumes a challenge without verifying that the
caller signed it. A peer's node id, URL and advertised chain identity are therefore
self-declared. The chain-identity check ([PROTOCOL_UPGRADES.md §5](PROTOCOL_UPGRADES.md)) keeps
honest-but-misconfigured nodes — another network, a missed upgrade — apart, but a malicious peer
can claim any identity; block validity (proposer signature, eligibility, parent linkage, E-D4)
remains the real defence. **To close:** sign RPC requests the way the legacy REST path does
(`get_verified_sender`), and verify the challenge signature in the handshake.

## OPEN — A second, unused token class remains

**Severity: low.** What remains of the 2026-10-02 audit of the spot exchange: its spot findings
are fixed ([below](#fixed-spot-exchange-liquidity-could-be-stolen-or-lost-pools-moved-for-free-replays-diverged)),
tokens are one native standard ([NATIVE_TOKENS.md](NATIVE_TOKENS.md)) that is also a real ERC-20
inside the EVM ([below](#fixed-evm-state-lived-in-a-per-node-trie)), and the simulated EVM
exchange precompiles are retired.

`qrdx/tokens/qrc20.py` still exists — an in-memory token class (approvals, permits, bridge
mint/burn, freeze) used by no consensus path. The Doomsday trading hook (Whitepaper §9.2) reads
its per-token flag, and integration scenarios S05/S06 drive it on a scratch database. To retire
it, give native tokens the Doomsday flag and move S05/S06 onto them.

---

# Accepted limitations

## ACCEPTED — Oracle reporters are trusted (development override only)

Production prices come from the validator oracle (docs/PERPS_CLEARINGHOUSE.md §8). Addresses in
`QRDX_ORACLE_REPORTERS` (a consensus parameter; empty by default) may still set a market's oracle
directly with `UPDATE_ORACLE` — trusted outright, no aggregation — which unit tests and
development setups use. No production network should configure one; the integration testnet no
longer does.

## ACCEPTED — A finality stall longer than the withdrawability delay reopens the slashing window

An exiting validator stays eligible until the **finalized** epoch reaches its `exit_epoch`;
its principal is paid at head epoch `exit_epoch + WITHDRAWAL_DELAY_EPOCHS` (256 in
production). While finality keeps pace, the validator is ineligible long before payout. If
finality stalls for longer than the delay, it can still be eligible when paid, and an
offence after that point is slashed from a stake already returned.

Closing it fully means gating payout on the exit being finalized, which needs a finalized
epoch that is a pure function of the chain at each block — the finality view today is a
node-local table. 256 epochs is Ethereum's figure for the same window, and a stall that
long is itself a network emergency.

## ACCEPTED — The forfeiture scan reads block bodies linearly

Deciding whether an exiting validator forfeits reads canonical block bodies (the only source
every node agrees on), once per payout. SQL excludes blocks with empty evidence before
parsing, so the parsing cost is tiny — but the `LIKE` filter itself still scans stored block
text, O(chain size) per payout. Negligible at testnet scale; at production scale the fix is a
per-block evidence index written during block application and trimmed on rollback, like the
deposit and exit logs.

## ACCEPTED — Ejected validators claim their principal manually; staking has no CLI

The stake-floor sweep ejects inside the asynchronous reconstruction, so it writes no exit
record on chain and nothing is paid automatically. The validator claims by submitting a
`STAKE_EXIT`, which is logged even though it is no longer active and then paid like any
exit (`tests/test_withdrawal_delay_and_forfeit.py`). Automatic payout would need the
ejection itself to be a block-level, chain-derived event.

Neither `STAKE_DEPOSIT` nor `STAKE_EXIT` has wallet-CLI support: both are signed exchange
transactions posted to `/submit_exchange_tx`, as `integration_tests/scenarios/s16` does.

---

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
