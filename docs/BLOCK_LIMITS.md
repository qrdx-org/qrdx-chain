# What a block may carry, and what its gas costs

Every node executes every block, within the slot clock. So what a block may carry is bounded
by what a node can execute, not only by its size in bytes, and what it costs to fill a block
rises with demand.

| Part | Where |
|---|---|
| The limits, checked on every import path | `qrdx/block_limits.py` (from `_verify_chain_rules` in `qrdx/node/main.py`) |
| EVM gas of a section | `qrdx/contracts/evm_block_apply.py` `section_gas_error` |
| Matching paid per resting order | `qrdx/exchange/orderbook.py` `MatchBudget`, `EXCHANGE_GAS_PER_MAKER` |
| Base fees | `qrdx/fee_market.py` |
| Precompile surcharges | `qrdx/contracts/evm_world.py` |
| Calibration | `scripts/bench/evm_gas.py` |
| Tests | `tests/test_block_limits.py`, `tests/test_match_budget.py`, `tests/test_fee_market.py`, `tests/test_evm_world_equivalence.py` |

## The limits

A block is refused, before anything in it is verified or executed, if it carries more than:

| What | Limit | Parameter |
|---|---|---|
| EVM gas: its transactions' declared gas limits, summed | 1,000,000 | `BLOCK_GAS_LIMIT` (chain spec) |
| Exchange gas: its operations' declared gas limits, summed | 20,000,000 | `BLOCK_EXCHANGE_GAS_LIMIT` (chain spec) |
| Votes, each a Dilithium signature to verify | 128 | `MAX_ATTESTATIONS_PER_BLOCK` |
| Slashing proofs, each two signatures | 16 | `MAX_SLASHING_EVIDENCE_PER_BLOCK` |

Declared limits are summed, not gas used, so a block can be judged before any of it runs. The
proposer fills blocks to the limits (`select_for_block`). The mempools refuse a transaction with
a gas limit no block could carry. `eth_call` and gas estimation run on the node's own time, so
they get no more than `BLOCK_GAS_LIMIT` either.

### Why these numbers

`scripts/bench/evm_gas.py` runs the EVM's slowest workloads per unit of gas through the node's
own executor. On the development machine:

| Workload | Mgas/s |
|---|---|
| JUMPDEST in a loop (1 gas each: the cheapest instruction) | ~1.7 |
| bn128 multiplication / pairing (surcharged, below) | ~1.7 / ~2.4 |
| identity 4 KB / sha256 4 KB / ecrecover | ~5 / ~18 / ~15 |
| BALANCE of accounts not yet loaded | ~9 |

py-evm runs its cheapest instructions at ~1.7 Mgas/s. A 1,000,000-gas block of them takes about
0.6 s, two or three 250 ms slots. That is a burst the chain absorbs: blocks come more slowly for
a moment, and the base fee (below) makes a sustained run of them prohibitively expensive within
seconds. A smaller limit would forbid deploying a token contract, typically 0.6–1.2M gas. Ordinary
transactions run far faster per unit of gas: a transfer is about 1 ms.

Exchange operations run in the node's own code, about 200 times faster per unit of gas. An
order is ~75 µs, most of it verifying its Dilithium signature, against 40,000–60,000 gas.
20,000,000 gas is about 500 orders, ~40 ms of execution.

Run the script on the slowest hardware a network's validators use before setting its limits.

### Matching is paid for by the order that does it

An order visiting a resting order costs `EXCHANGE_GAS_PER_MAKER` (10,000) on top of its base
gas, whether the resting order fills, is skipped (self-trade prevention) or is cancelled (the
margin check at match time). An order visits no more resting orders than its gas limit pays for.
When the budget runs out the order stops matching, and its remainder is cancelled, not rested: it
could still cross the book. A visit takes ~25 µs. An order used to sweep any number of makers for
its base gas: 1,600 makers in one `PERP_ORDER` took 38 ms for 60,000 gas.

### Precompiles priced for what they cost here

py-evm runs bn128 in pure Python, where Ethereum clients run it natively. At Ethereum's prices
a block of pairings took ~6 s. On QRDX, ecMul costs 18,000 gas (6,000 + 12,000) and a pairing
350,000 a pair (34,000 + 316,000). That is what keeps them no slower per unit of gas than the
cheapest instruction. **A zk-SNARK verification (3–4 pairings) does not fit a block** until a
native pairing backend replaces py_ecc.

ecrecover needs `coincurve`, which is in the release lock. Without it, eth-keys recovers
signatures in pure Python, at 0.2 Mgas/s, and recovering every EVM transaction's sender costs
~15 ms. A node without it logs an error at startup.

## Loading state is linear

The EVM loads the accounts and storage it reads on demand. It used to start the transaction
over on every miss, on a state rebuilt and re-hashed from everything loaded so far. That made a
transaction touching n new accounts O(n²): 800,000 gas of BALANCE calls took 2.8 s, and a
transaction's 10M gas took minutes, on every node. Now execution runs in a greenlet and switches
out to load what it misses. Each account and slot is loaded once, where the execution stopped for
it. The state is a journaled dictionary store with py-evm's semantics: who exists, original
values, warm and cold access. `tests/test_evm_world_equivalence.py` runs random contracts on
both stores and requires identical results, gas, logs and state roots.

## Base fees

Each block's signed header carries two base fees, in wei per unit of gas: the EVM's
(`base_fee`) and the exchange's (`exchange_base_fee`). The parent sets each one, as Ethereum's
EIP-1559 does:

    next = parent_fee × (1 + (parent_gas − target) / target / 8),   target = limit / 2

`parent_gas` is what the parent's sections declared, oracle votes excluded. The fee is never
below its floor: `EVM_MIN_GAS_PRICE_WEI` or `EXCHANGE_MIN_GAS_PRICE_WEI`, both 1 gwei by default.
When the parent was over target, the fee rises by at least one wei. A block must declare exactly
these fees, and every transaction in it must offer at least them. Validators' oracle votes are
exempt, so a burst of traffic can never stall the prices the exchange runs on. All of it is
burned, as before.

Before this, gas cost the floor however full blocks were, and EVM transactions had no floor at
all: a gas price of 0 executed for free. Now a run of full blocks raises the price 12.5% a
block. Thirty seconds of them at 250 ms slots multiply it about 1.4 million times, and it comes
back down as fast.

`eth_gasPrice` and `exchange_gasPrice` return the next block's base fee plus one block's worth
of headroom. `exchange_getSigningPayload` fills that in when no price is given. `eth_feeHistory`
reads the fees from the headers. A transaction priced below the current base fee waits in the
mempool until the fee comes down to it.

The EVM's `BASEFEE` opcode (EIP-3198) reads the executing block's EVM base fee
(`fee_market.CURRENT_EVM_BASE_FEE`). The section functions set it from the stored chain, so the
proposer, every importer and a rebuild from history agree. Outside a block (`eth_call`) it is the
floor.
