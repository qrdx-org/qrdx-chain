# Staking: validators, delegation pools, rewards

How stake enters QRDX, earns, counts and leaves. Everything here is a pure function of the
chain: the validator set of each epoch is computed from the genesis set and the chain's blocks
(`qrdx/validator/epoch_state.py`), and every node computes the same one.

| Part | Where |
|---|---|
| The validator set `S_E`, its transition, pools and payouts | `qrdx/validator/epoch_state.py` |
| Stake operations (exchange transactions) | `ExchangeStateManager._op_stake_*` |
| Logs of executed operations | `validator_deposits`, `validator_exits`, `staking_ops` |
| Payouts and principal withdrawals | `qrdx/validator/withdrawals.py` |
| Reads | `staking_getValidators`, `staking_getPools`, `staking_getDelegations`, `staking_getParams` |
| Wallet | `qrdx-wallet stake …` |
| Tests | `tests/test_epoch_state.py`, `tests/test_staking_pools.py`, integration S16, S24 |

## The validator set of an epoch

`S_E` is the validators at the start of epoch `E` on a chain, together with the delegation pools
and the payouts not yet paid. It is a deterministic transition over the chain's blocks:

    S_0     = the genesis validator set
    S_(e+1) = transition(S_e, the blocks of epoch e)

Each epoch's transition applies, in order:

0. The payouts due by `e` are dropped if the epoch has a block: its first block paid them.
1. The epoch's **executed** stake operations, in chain order:
   - A deposit registers a validator, pending until `e + ACTIVATION_DELAY_EPOCHS`, or tops one up.
   - An exit moves an active validator to exiting until `e + UNBONDING_PERIOD_EPOCHS`. A pending
     validator that exits leaves at once.
   - Delegations, undelegations and commission changes (below).
2. **Weight:** rewards and penalties for epoch `t = e − INCLUSION_EPOCHS`. A vote may ride up to
   two epochs after its target, so by now every vote that will count for `t` is on the chain.
   An active validator whose vote for `t` the chain carries gains effective stake. One whose
   vote it doesn't carry loses it.
3. **QRDX rewards** for `t` (below).
4. Scheduled exits, then activations: while fewer than `MAX_VALIDATORS` propose, validators
   that are due activate in the order they became due (then by address). The rest wait in the
   queue until a validator leaves, and can leave the queue at once. Delegations whose warm-up is
   over join their pool.
5. Slashing proofs the epoch's blocks carry (a double sign, or a double or surround vote):
   - the validator loses half its stake and is out;
   - its pool loses half its value;
   - its unbonding delegations lose half of what is still unpaid.
6. A validator that has left pays its pool out to its delegators, after the withdrawal delay.
7. Stake-floor ejection: an active validator below `VALIDATOR_EJECTION_STAKE` exits, but never
   leaving fewer than three active.
8. Commission changes take effect.

Only operations the exchange **executed** are inputs. Block application writes them to logs
keyed to the carrying block, and a rollback deletes them. A `STAKE_DEPOSIT` the exchange refused
(more stake than its sender holds) is still in the block, since a failed transaction pays its
gas, but it registers nothing. The validator set was once rebuilt from every deposit a block
carried: an account holding gas money could name a million QRDX of stake and get it.

**Who proposes.** A block of epoch `E` is proposed by the validator selected for its slot from
`S_E` of its own parent chain. The candidates are active and exiting validators, weighted by
their effective stake plus the QRDX delegated to them. The proposer and every node judging the
block compute the same set, however long after the slot and on whichever path: live import,
sync, or a fork-choice switch. Casper FFG weighs a vote for target `t` by `S_t` the same way.

States are cached per (epoch, checkpoint), where the checkpoint is the last block before the
epoch's first slot. It commits to every block the state depends on, so a reorg never reuses a
stale state, and each epoch's state is computed once from the previous one.

A state is computed from the newest stored state below it on the same chain. The blocks in
between are read in one query per input, not one per epoch. The first block after a long halt
crosses thousands of empty epochs: a day's halt is about 10,800 epochs and costs about a second.
Of the states computed on the way, those for the last 16 epochs are stored (that is where reorgs
and FFG targets look), plus one every 16 epochs before that. Pruning below finality always keeps
the newest stored state. `tests/test_epoch_state.py` checks on random chains, reorgs included,
that this equals the per-epoch definition.

## Delegation pools

Anyone can stake with a validator without running one: Solana's model, with a pool per
validator.

| Operation | Effect |
|---|---|
| `STAKE_DELEGATE {validator, amount}` | Debits `amount` QRDX (at least `STAKE_MIN_DELEGATION`, 1). After a warm-up of `ACTIVATION_DELAY_EPOCHS` it joins the validator's pool as shares at the pool's price (1:1 in an empty pool). A delegation to an address that isn't a validator then is refunded. |
| `STAKE_UNDELEGATE {validator, shares \| "all"}` | Burns the shares at the pool's price at the end of the epoch. The QRDX is paid after `UNBONDING_PERIOD_EPOCHS + WITHDRAWAL_DELAY_EPOCHS`, and is slashed with the pool until then. `all` also refunds what is still warming up. |
| `STAKE_SET_COMMISSION {commission_bps}` | A validator sets its cut of its pool's rewards (0–10,000 basis points), from the next epoch. The default is `STAKING_DEFAULT_COMMISSION_BPS` (1,000 = 10 %). |

A pool's value counts towards its validator's weight. A validator that exits or is slashed
pays its pool out to the delegators, after the withdrawal delay (the window for evidence of its
offences). A slashed validator's pool is paid out halved.

## Rewards

Each epoch, every active validator whose vote for epoch `t` the chain carries earns the
staking rate on two amounts:

- its own principal;
- its pool's value.

The rate is `STAKING_REWARD_RATE_BPS` a year, a chain-spec parameter (500 = 5 % a year), scaled
to one epoch of chain time. The validator is paid its own share plus its commission on the
pool's share. The rest of the pool's share is added to the pool's value, so every delegator's
shares grow and the rewards compound. A validator that misses its vote earns nothing, and
neither does its pool for that epoch. Rewards are new QRDX: the staking rate is the network's
issuance.

## Fee income

`STAKER_FEE_SHARE_BPS` (chain spec, 2,000 = 20 %) of the protocol's trading-fee income is real
yield beside the minted rate (docs/CONSENSUS_ROADMAP.md 6), of spot and perps fees alike. It
waits at the fee holder `0xFEES…` (an address no key signs for); a share paid in another asset is
sold there for QRDX by the exchange's tick, at no less than 2 % under its pool's 10-minute TWAP.
Each block logs the QRDX income it took in (`staker_fee_income`). An epoch's income — with
any remainder carried from before — is shared among the same validators the minted rewards pay
(those whose vote the chain carries), by principal and pool: the validator is paid its part and
its commission on the pool's (`fee` payouts); the rest compounds into the pool (`fee_pooled`).
Fee payouts are **paid out of the fee holder**, not minted, so supply is unchanged by them; what
rounding leaves is carried (`fee_carry` in the state).

## Payouts

Rewards, finished undelegations and refunds are owed by the state, each with a due epoch. The
**first block of an epoch** credits every payout that `S` of that epoch, on its parent chain,
holds as due. The next epoch's transition drops them, since a block of that epoch paid them.
So each payout is paid exactly once, by a block every node agrees on, before the unified state
root is computed or checked. Paid payouts are recorded in `staking_payouts`, the same way stake
withdrawals are: dropped when the paying block is rolled back, and re-credited after an
account-state rebuild.

A validator's own principal is returned by the in-block withdrawals of
`qrdx/validator/withdrawals.py`, `WITHDRAWAL_DELAY_EPOCHS` after its exit epoch, unless it was
slashed. This includes a validator ejected for inactivity: the set records its exit, so it is
paid without having to claim it.

## Parameters

| Parameter | Kind | Standard |
|---|---|---|
| `STAKING_REWARD_RATE_BPS` | chain spec | 500 (5 % a year) |
| `STAKER_FEE_SHARE_BPS` | chain spec | 2,000 (20 % of QRDX fee income) |
| `ACTIVATION_DELAY_EPOCHS` | chain spec | 4 (warm-up, validators and delegations) |
| `UNBONDING_PERIOD_EPOCHS` | chain spec | 40,320 (~3.7 days of 8 s epochs) |
| `WITHDRAWAL_DELAY_EPOCHS` | chain spec | 2,048 (~4.6 hours) |
| `MAX_VALIDATORS` | chain spec | 150 (more wait in the activation queue) |
| `MIN_VALIDATOR_STAKE` | constant | 1,000 QRDX (~$400,000: docs/TOKENOMICS.md) |
| `STAKING_DEFAULT_COMMISSION_BPS` | constant | 1,000 (10 %) |
| `STAKE_MIN_DELEGATION` | constant | 1 QRDX |

`staking_getParams` returns them for the network a node follows.
