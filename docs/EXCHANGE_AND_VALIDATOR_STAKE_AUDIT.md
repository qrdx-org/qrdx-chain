# Exchange & Validator-Stake Audit

Companion to [UNIFIED_ACCOUNT_IDENTITY.md](UNIFIED_ACCOUNT_IDENTITY.md), which
describes the `0x` ↔ `0xPQ` ledger unification. This document answers three questions:

1. **What did the unification do to the exchange?**
2. **Is every pre-existing enforcement still on?**
3. **Do validators actually have to own the stake they claim?**

Short answers: the exchange got *more* correct and needed no redesign; every
enforcement gate is unchanged and still `True`; and validator stake was **not**
enforced at all — that is now fixed, gated, and tested.

---

## 1. Exchange impact

### 1.1 Why it is unaffected by design

The exchange keys its **in-memory** state by the sender's `0xPQ…` display address and
normalizes only at the **database boundary**. Both sides of every check use the same
string, so nothing inside the exchange had to change:

| Exchange surface | Key | Normalized? |
|---|---|---|
| `_available_balances` (collateral pre-load) | display address | no — internal |
| `_available_token_balances` | (display address, token) | no — internal |
| `_balance_deltas` (margin, pool stake, validator stake) | display address | at flush |
| `_token_balance_deltas` | (display address, token) | at flush |
| `db.get_address_balance` / `apply_account_balance_delta` | **account id** | yes |
| `db.get_token_balance` / `apply_token_balance_delta` | **account id** | yes |

`preload_sender_balances` reads through `get_address_balance` (normalizing) and stores
under the display key; `flush_exchange_balance_deltas` writes through
`apply_account_balance_delta` (normalizing). Read and write therefore land on the same
row, and the display key is only ever an internal handle within one block.

### 1.2 What actually improved

* **PQ traders can be debited at all.** This was the original reason the collateral
  gate could not be enabled: genesis funded PQ addresses into the UTXO set, so the
  flush found no `account_state` row for a PQ trader and debited nothing. Genesis now
  funds account ids, so perp margin, pool stake and validator stake all debit real
  balances.
* **Token balances cannot drift from an ERC-20 view.** `token_balances.holder_address`
  is keyed by account id, so a PQ trader's QRC-20 balance and the 20-byte form of the
  same account are one row.
* **Spelling can no longer split an account.** `account_state.address` is a
  `TEXT PRIMARY KEY` with exact matching, so before canonicalization a checksummed
  write and a lowercase write were two rows — two balances for one account, and a
  state root that depended on spelling.

### 1.3 Two regressions found and fixed

#### (a) A malformed `TOKEN_TRANSFER` recipient burned tokens

`TOKEN_TRANSFER`'s `to` parameter is an arbitrary user-supplied string. Once the token
ledger keyed holders by account id, an **unkeyable** recipient made
`apply_token_balance_delta` raise; `flush_token_balance_deltas` catches per-delta
exceptions and logs a warning, so the sender's debit applied while the recipient's
credit was dropped — **silently burning the tokens**.

Fixed in `_op_token_transfer`: an unkeyable recipient is now rejected
*unconditionally*, in the same class as a non-positive amount. Deterministic (a pure
function of the recipient string), so every node rejects identically. This is also
stricter than the pre-unification behaviour, where a malformed recipient produced a
junk-keyed row that was never spendable anyway.

#### (b) Pool reserves and order escrow were silently burning tokens

**The more serious of the two.** The exchange holds its own state under deterministic
*synthetic* addresses:

| Holder | Form | Holds |
|---|---|---|
| `ExchangeStateManager.pool_holder_address` | `0xPOOL` + 36 hex | AMM pool reserves |
| `ExchangeStateManager.orderbook_escrow_address` | `0xCLOB` + 36 hex | CLOB resting-order escrow |

Both are `0x`-prefixed but **not hex**, and no key can sign for them — the protocol owns
them. `to_account_id` rejected both, so every credit into a pool or an escrow raised
inside `apply_token_balance_delta`, was caught by `flush_token_balance_deltas`'
per-delta handler, and was **dropped** — while the paired debit from the provider or
taker applied. Every liquidity add and every resting limit order destroyed the tokens it
moved, leaving only a `WARNING` line.

Fixed by making these protocol-internal holders first-class in the keyspace:

```
0xPOOL…, 0xCLOB…  →  keccak(DOMAIN:internal:<TAG> ‖ body)[-20:]
```

The tag includes the prefix, so a pool and a book with the same body are different
accounts. The prefixes are an explicit **allow-list** with a validated 36-hex body — not
a permissive "anything non-hex gets hashed" fallback, which would have made every
malformed user-supplied `TOKEN_TRANSFER` recipient silently keyable again and undone
fix (a). Adding a new protocol-derived holder form means adding it to
`SYNTHETIC_HOLDER_PREFIXES` deliberately.

Pool reserves are now ordinary accounts, so an ERC-20 style view of them works.

**This is the important part: the full 19-scenario integration suite passed green while
this was happening.** Scenarios s06 (pools), s15 (spot settlement), s17/s18 (CLOB) assert
that operations *succeed* and that roots *converge* — and they did, because the loss was
deterministic, so every node burned identically and no root diverged. Only a
**conservation** assertion catches it. Two consequences:

* `tests/test_synthetic_holder_accounts.py` asserts `held + reserves + escrowed == total`
  through the real flush;
* the per-delta handlers in both value-bearing flushes now log at **ERROR** with a
  `[VALUE-LOST]` marker instead of `WARNING`, so a log scan or soak surfaces a dropped
  delta rather than letting it blend into normal warning noise. `scripts/phase_e_invariants.py`
  (token-supply conservation) is the existing net that would also have caught it
  post-run; it is not part of the suite.

### 1.4 Exchange operations remain PQ-only senders

`ExchangeTransaction.verify()` binds the transaction to a Dilithium key, so a
traditional `0x` account still cannot open a perp position, place a CLOB order, or
deploy a QRC-20. Native transfers and contract calls are now symmetric between the two
account families; **exchange operations are not**. Unchanged by this work, and listed
here because it is the remaining asymmetry.

---

## 2. Enforcement status — nothing was relaxed

No enforcement flag was modified. Verified by `git diff` over `qrdx/` matching
`ENFORCE|enforce_`: the only additions are the new validator-stake gate and its wiring.

| Gate | Value | Domain |
|---|---|---|
| `ENFORCE_EXCHANGE_COLLATERAL` | `True` | perp margin debited from `account_state` |
| `ENFORCE_SPOT_SETTLEMENT` | `True` | reject over-spending swaps / token transfers |
| `ENFORCE_ORDERBOOK_SETTLEMENT` | `True` | CLOB escrow moves real tokens; cancel refunds |
| `ENFORCE_POOL_STAKE` | `True` | `CREATE_POOL` debits the creator's declared stake |
| **`ENFORCE_VALIDATOR_STAKE`** | **`True`** | **new — see §3** |
| `_ENFORCE_PROPOSER_ELIGIBILITY` | `True` | slot-eligibility on import |
| `_ENFORCE_FINALITY_REORG_GUARD` | `True` | refuse reorgs below the finalized height |
| `_ENFORCE_EPOCH_VALIDATOR_UPDATES` | `True` | validators table evolves each finalized epoch |
| `_ENFORCE_SLASHING` | `True` | finalized-epoch slash penalty + eject |
| `_ENFORCE_SURROUND_DETECTION` | `True` | surround/double-vote detection |
| `_ENFORCE_VALIDATOR_RECONSTRUCTION` | `False` | *pre-existing*: validators-table reorg rebuild, kept off (composition bug with the epoch loop) |
| `ENFORCE_RANDAO_SELECTION` | env-gated, off | *pre-existing*: churns on a 3-validator/2s-slot testnet |

The E-D4 unified state root remains enforced on live-broadcast import (bulk sync stays
trust-replay by design).

---

## 3. Validator stake — a real vulnerability, now closed

### 3.1 What was wrong

`_op_stake_deposit` recorded a validator with the stake it **claimed** and performed
**no check of any kind**:

* no `MIN_VALIDATOR_STAKE` floor — even though `constants.py` defines 100,000 QRDX and
  both `validator/manager.py` (local registration) and `epoch_processing.py` (epoch
  activation) already apply it. The **consensus join path** skipped it.
* no balance check;
* no debit. The docstring said *"Stake collateral-locking is a documented follow-on."*

That claim is not inert data. The full path:

```
STAKE_DEPOSIT{stake_amount: <arbitrary>}
  → flush_validator_lifecycle_deltas
  → db.register_pending_validator(stake, effective_stake = claimed)
  → validators table
  → node_integration builds the validator set  (stake = effective_stake = claimed)
  → consensus.select_proposer()      stake-WEIGHTED proposer selection
  → fork-choice attesting weight     stake-WEIGHTED chain selection
```

So an account holding **zero QRDX** could register a stake larger than the entire
honest set and thereby dominate both block production and fork choice. Demonstrated
before the fix: a zero-balance account registered claiming 999,999,999 QRDX, nothing
debited.

### 3.2 The fix

Gated on `ENFORCE_VALIDATOR_STAKE` (`True`), a `STAKE_DEPOSIT` must now:

1. **clear `MIN_VALIDATOR_STAKE`** — a pure comparison against a constant;
2. **be backed by the sender's real balance** — read from the `account_state` value
   pre-loaded by `preload_sender_balances`, which runs on every path, so the check is
   identical on every node. A *missing* pre-load (`None`) is refused rather than
   assumed solvent: admitting an unverified stake is the whole vulnerability;
3. **be debited** — `_record_balance_delta(sender, -stake)`, riding the same
   already-enforced collateral flush, so it lands in `account_state` before each node
   computes its E-D4 root.

The gate guards the **delta recording**, not just the flush. Because the shared flush
is already enforced for collateral, a delta recorded while the gate was off would be
applied anyway — the mistake the pool-stake rollout hit. Pinned by
`test_the_debit_is_recorded_only_when_the_gate_is_on`.

### 3.3 Refund — CORRECTED, then FIXED by in-block withdrawals

**This section previously stated that principal is refunded at the finalized exit epoch.
That was wrong.** The refund was placed in the epoch loop's *incremental* path
(`apply_epoch_validator_update`), but the live configuration uses reconstruction
(`epoch_loop._RECONSTRUCT_VALIDATORS = True`) and never reaches that path. The refund never
ran. Its unit tests called the helper directly and passed anyway.

It also cannot simply be moved: a refund credits `account_state`, which is bound into the
E-D4 unified root, and the epoch loop runs asynchronously rather than at block boundaries —
so nodes would disagree on the root depending on whether their loop had processed the exit.
A correct refund must be applied inside block application (EIP-4895-style withdrawals).
The incremental call is now explicitly disabled (`_ENFORCE_EXIT_REFUND_IN_EPOCH_LOOP =
False`) so it cannot come alive if reconstruction is ever switched off.

**Resolved:** principal is now returned inside block application by in-block withdrawals
(`qrdx/validator/withdrawals.py`, EIP-4895-style), which the proposer and every importer
compute identically from chain-derived logs — see "FIXED — Staked principal never returned
on exit" in [KNOWN_ISSUES.md](KNOWN_ISSUES.md#fixed-staked-principal-never-returned-on-exit).
The epoch-loop refund stays disabled.

**Slashing still bites** regardless: a slashed validator moves to status `'slashed'` and is
ejected, forfeiting its stake weight.

### 3.4 Wiring — all four paths

The recurring failure mode in this codebase is a rebuild running with a different
enforce-flag set than the forward path, which makes a reorged node accept an operation
the network rejected and diverge at equal tip. The new flag is therefore set at every
site that sets the others:

| Path | Site |
|---|---|
| live-broadcast import | `node/main.py::_apply_exchange_section_on_import` |
| proposer | `validator/node_integration.py` |
| reorg / rejected-block / startup rebuild | `derived_state_rebuild.py::rebuild_derived_state_interleaved` |
| by-domain rebuild (A/B only) | `exchange/block_processor.py::rebuild_exchange_state_from_chain` |
| default (off) | `exchange/state_manager.py::__init__` |

`test_rebuild_sets_every_forward_enforce_flag` reads the forward importer's flag set from
its source and fails if either rebuild function misses one — so the *next* gate cannot
repeat the mistake either.

### 3.5 Genesis validators are exempt

Genesis validators are inserted by `genesis_init._init_validators` with the stake
declared in the genesis file, and are **not** debited. The genesis file is the chain's
trust root, so there is nothing to verify against. This gate governs *joining*
validators, which is where untrusted input enters.

### 3.6 CLOSED — a deposit in a later-orphaned block

The `validators` table is not reconstructed from the canonical chain — the pre-existing
`_ENFORCE_VALIDATOR_RECONSTRUCTION = False` gap in the rollback path (enabling it there
diverged on reconstruction↔epoch-loop composition; the epoch loop's own reconstruction is
the single writer — see [VALIDATOR_LIFECYCLE_UNIFICATION.md](VALIDATOR_LIFECYCLE_UNIFICATION.md)).
So when a reorg orphaned a block containing a
`STAKE_DEPOSIT`:

* the derived-state rebuild correctly did **not** re-apply the stake debit — the deposit
  is no longer canonical — but
* the `validators` row **persisted**, leaving a validator holding the `effective_stake`
  that weights proposer selection and fork choice, with none of the funds locked.

That reopens §3.1's vulnerability to anyone who can get a block orphaned, so it is now
closed.

**Exact reversal, not recomputation.** Rather than rebuilding the whole table — the thing
that diverged — every consensus `STAKE_DEPOSIT` is recorded in an append-only
`validator_deposits` log keyed to its carrying block, and
`db.undo_validator_deposits_above(tip)` reverses the rows above the new tip:

* a deposit that **created** the validator → the validator is deleted (it was never
  validly registered on the canonical chain, so its accrued rewards and status go with it);
* a deposit that **topped up** an existing one → exactly that increment is subtracted from
  `stake` and `effective_stake`.

Reversal is newest-first, so a create-then-top-up sequence for one address unwinds in the
right order. `register_pending_validator` is **additive**, which is precisely why the log
records each deposit individually: a top-up can only be undone if its own increment is
known.

Wired into `_rebuild_derived_state_after_rollback`, the single function both the
longest-chain reorg and the equal-height tie-break use after `db.remove_blocks(...)`.
Gated by `_ENFORCE_DEPOSIT_REORG_UNDO` (ON).

**Why this is safe while full reconstruction stays gated off.** It can only remove what a
deposit created; it never recomputes reward-driven `effective_stake`, so it cannot
reintroduce the composition problem that made reconstruction diverge. And **genesis
validators have no rows in the deposit log**, so they are structurally out of reach —
removing them would empty the validator set and halt the chain, so that property is
asserted directly (`test_genesis_validators_are_never_reversed`).

The end-to-end guarantee, pinned by
`test_orphaned_deposit_loses_both_the_debit_and_the_stake_weight`: after the orphaning,
the staker's balance is restored **and** the validator no longer carries stake weight.
Before, the balance came back while the weight stayed.

**What the soak does and does not show.** A 180-second fault-injecting soak (a node
killed and restarted, 16 reorgs, height spread 6) produced zero `[VALUE-LOST]` markers and
a byte-identical `validator_deposits` log across all four nodes — so the undo does not
MISFIRE under many real reorgs. It does not show the undo firing, because those reorgs are
shallow tip reorgs and the deposit sat at height 97, hundreds of blocks below the tip.
`test_the_real_rollback_hook_reverses_orphaned_deposits` covers that gap by driving
`_rebuild_derived_state_after_rollback` itself — the production hook, including its tip
derivation — over a deep rollback, and asserts both that the orphaned deposit is reversed
and that a deposit below the fork point is left alone.

## 4. Tests

| File | Covers |
|---|---|
| `tests/test_validator_stake_enforcement.py` (16) | forged / underfunded / below-minimum / non-positive / unverifiable deposits refused; affordable deposit debited on the canonical row; no double-spend of a locked stake; two nodes agree on both the debit and the rejection (`validators_table_hash` + `account_state_root`); exit refunds principal; slashed validator forfeits; refund excludes rewards |
| `tests/test_validator_stake_reorg_equivalence.py` (3) | rebuild == forward `account_state` root with an accepted **and** a rejected deposit in the chain; debit applied exactly once across a rebuild; the gate guards delta *recording* |
| `tests/test_reorg_rebuild_equivalence.py` (4) | existing exchange equivalence, plus the new structural guard that the rebuild sets every forward-path flag |
| `tests/test_synthetic_holder_accounts.py` (14) | pool/escrow holders resolve, stay distinct, domain-separated, idempotent; malformed ones still rejected; **token conservation through the real flush** |
| `tests/test_orphaned_deposit_undo.py` (13) | orphaned deposit removes the validator; canonical deposits survive; top-ups reversed exactly; **genesis validators never touched**; idempotent; logging covers every consensus path |
| `integration_tests/scenarios/s16_validator_membership.py` | live join/exit against real nodes — its deposit is exactly `MIN_VALIDATOR_STAKE`, funded from a 500,000 QRDX genesis balance, so it exercises the enforced path |

Unit suite: **2,387 passing**. Full integration suite: **19/19 scenarios**, with zero
`[VALUE-LOST]` markers across all node logs.

Open items are tracked in [KNOWN_ISSUES.md](KNOWN_ISSUES.md).
