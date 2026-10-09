# On-chain governance

Validators propose and decide; QRDX holders can veto; nothing takes effect until a timelock has
passed. Code: `qrdx/exchange/governance.py` (state machine), `ExchangeStateManager._op_gov_*`
(the four operations), `qrdx/rpc/modules/governance.py` (reads), `qrdx/cli/gov.py` (CLI).
Tests: `tests/test_governance.py`; live: `integration_tests/scenarios/s22_governance.py`.

Verified live (2026-10-09, 4-node testnet, S22 33/33):

- **Treasury spend:** exactly 1,234.5 QRDX moved from the developer fund to the recipient on
  every node.
- **Holder veto:** stopped a passed spend, and the holder got back exactly what was locked,
  minus the 0.00005 QRDX fee. The escrow emptied.
- **Freeze:** the freeze executed at block 205, every node reports the master controller's
  authority ended, and a spend it signed afterwards was refused at admission.
- **Fork approval:** approval was driven on chain in the upgrade rehearsal
  (docs/PROTOCOL_UPGRADES.md).

It governs three things:

| Action | Effect when executed |
|---|---|
| `system_spend` | moves QRDX from a system wallet (treasury, grants, …) to a recipient |
| `freeze_master` | ends the genesis master controller's authority over the system wallets now |
| `approve_fork` | authorises a fork scheduled in the chain spec to activate (docs/PROTOCOL_UPGRADES.md) |

## 1. Who does what

- **Validators propose and vote.** A proposer must be in the validator committee: the genesis
  validator set, plus stake deposits, minus exits. That is the same committee that prices the
  perps oracle.
- **Votes are weighted by stake**, taken as a snapshot when the proposal is created, so stake
  moved during the vote doesn't count. Votes are final.
- **A proposal passes** when "yes" reaches `GOV_APPROVAL_THRESHOLD_BPS` of the snapshot's total
  stake (2/3). It is rejected as soon as passing is no longer possible, or when the voting
  window ends.
  - With three equal validators, two "yes" votes is 66.66%, short of 2/3, so all three are
    needed. That is intended.
- **Holders veto.** During a passed proposal's timelock, any account can lock QRDX against it.
  When locked QRDX reaches `GOV_VETO_THRESHOLD_QRDX`, the proposal is stopped. Vetoes **lock
  real QRDX** in a protocol escrow (`0xVETO…`), so one balance can't be counted twice by moving
  it between accounts. The QRDX comes back when the proposal resolves: vetoed, executed or
  expired.
- **Anyone executes** a passed proposal once its timelock has ended and before its execution
  window closes. After the window it can only be closed as `expired`, which also returns the
  vetoes.

## 2. Lifecycle and parameters

All deadlines are block heights, never clock time. The parameters are chain-spec parameters,
fixed at genesis.

```
GOV_PROPOSE ─► voting ──(yes ≥ 2/3 of snapshot)──► passed ──(timelock ends)──► GOV_EXECUTE ─► executed
                 │                                   │  ▲                           │
                 │ (2/3 unreachable / window ends)   │  └─ GOV_VETO locks QRDX      └─(window ends)─► expired
                 ▼                                   ▼
             rejected                      vetoed (locked ≥ threshold; refunded)
```

| Parameter | Mainnet default | Integration testnet |
|---|---|---|
| `GOV_VOTING_PERIOD_BLOCKS` | 302,400 (7 days at 2 s) | 60 |
| `GOV_TIMELOCK_BLOCKS` (the veto window) | 86,400 (2 days) | 8 |
| `GOV_EXECUTION_WINDOW_BLOCKS` | 302,400 (7 days) | 200 |
| `GOV_APPROVAL_THRESHOLD_BPS` | 6,667 (2/3 of stake) | 6,667 |
| `GOV_VETO_THRESHOLD_QRDX` | 10,000,000 (10% of genesis supply) | 500 |
| `GOV_FORK_APPROVAL_LEAD_BLOCKS` | 256 (2 × the maximum reorg depth) | 5 |
| `SYSTEM_WALLET_MASTER_SUNSET_HEIGHT` | 100,000 | 100,000 |

Limits:

- a validator may have 4 open proposals;
- the chain may have 64 open proposals at once;
- memos are capped at 280 characters.

## 3. The master controller

At genesis one key (`system_wallet_controller`) controls all ten system wallets through
delegated spends. That authority is temporary:

- **It ends on its own at block `SYSTEM_WALLET_MASTER_SUNSET_HEIGHT`** (100,000), on every node,
  with no vote needed.
- **Validators can end it earlier** with an executed `freeze_master` proposal. It ends from the
  block that executed the freeze.
- After that, **system-wallet funds move only through `system_spend` proposals.** Freezing is
  irreversible.
- Freezing covers the key's **authority over the system wallets** only. QRDX in the
  controller's own account stays spendable like any account's.

The rule is enforced by `governance.master_authority`, called from the shared delegated-spend
check (`evm_mempool.verify_delegated_spend`) at:

- **mempool admission**;
- **block import** (`apply_block_evm_section` refuses a block carrying an unauthorised spend);
- **the proposer.** It filters such spends out and evicts them from the mempool, so it never
  ships a block importers would reject, and the controller's later nonces don't queue behind
  them.

## 4. Approving forks

Every fork in a real network's spec needs approval (docs/PROTOCOL_UPGRADES.md §4). An
`approve_fork` proposal names the fork's name, height and **definition hash**. That is
`ChainSpec.fork_definition_hash`, a hash of the exact fork entry, so an approval never carries
over to a fork whose contents a later release changed.
`governance_getForkApprovalParams(fork)` returns those fields for a fork in the node's spec, and
`qrdx-wallet gov propose-fork` uses it.

- **Timing.** The fork activates only if its approval executed at least
  `GOV_FORK_APPROVAL_LEAD_BLOCKS` before its height. That is deeper than any permitted reorg, so
  no reorg can change whether it activates. Approved late, or not at all, the fork stays
  dormant on every node. `/chain_spec` shows each fork's approval state.
- **Approvals never depend on a node's spec.** Every node records an `approve_fork`, including
  one whose software doesn't schedule that fork yet. If validity depended on the local spec, a
  node that hadn't upgraded would reject the approval while upgraded nodes accepted it, and the
  network would split before the fork. A node acts only on approvals matching a fork in its own
  spec.

## 5. How it is consensus

Governance is exchange state: four exchange operations (`GOV_PROPOSE` 48, `GOV_VOTE` 49,
`GOV_VETO` 50, `GOV_EXECUTE` 51). So it inherits everything exchange transactions already have:

- PQ signatures bound to the chain id;
- nonces and fees;
- gossip and inclusion;
- deterministic replay on every path (proposer, importers, the startup rebuild, reorg
  rebuilds);
- commitment in the exchange state root, and through it the unified root every block declares;
- snapshot and revert for a rejected block.

QRDX moves go through the same balance bridge as collateral and stake. A `system_spend`
execution pre-loads its wallet's balance (`block_processor.preload_sender_balances`). A spend
larger than the wallet holds fails without changing state, and can be retried until its window
closes.

## 6. Using it

```bash
qrdx-wallet gov status                                   # parameters, master controller, forks
qrdx-wallet gov propose-spend validator.json 0x0000000000000000000000000000000000000008 0xPQ… 250000 --memo "Q3 grants"
qrdx-wallet gov vote validator.json 7 yes                # each validator
qrdx-wallet gov veto holder.json 7 100000                # any holder, during the timelock
qrdx-wallet gov execute anyone.json 7                    # after the timelock
qrdx-wallet gov propose-freeze validator.json
qrdx-wallet gov propose-fork validator.json randao
qrdx-wallet gov list --status open
```

RPC: `governance_getStatus`, `governance_getProposals(status, limit)`,
`governance_getProposal(id)`, `governance_getForkApprovalParams(fork)`. Writes are exchange
transactions (`exchange_sendTransaction`).

## 7. Limitations

- **Voting weight is principal stake in the validator committee.** A new deposit counts as soon
  as it is made, and a slashed validator keeps its weight until it exits. This is the same as
  the oracle committee (docs/KNOWN_ISSUES.md, perps entry).
- **Only post-quantum accounts can veto.** Exchange operations are PQ-only (docs/KNOWN_ISSUES.md,
  "Exchange operations are PQ-only senders"), so a `0x` holder must move QRDX to a `0xPQ` account
  first.
- **A validator's exchange nonce also moves with its oracle votes.** Submit its governance
  transactions to its own node.
- **Parameters can't be changed by governance.** They are fixed in the chain spec; a rule
  change is a fork, approved through `approve_fork`.
- Resolved proposals are kept in state (bounded by the open-proposal limits).
- `qrdx/governance/` is the earlier in-memory governance library. No consensus path uses it;
  this module replaces it.
