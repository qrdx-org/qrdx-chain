# EVM conformance

QRDX runs contracts on py-evm (the `qrdx` fork, based on Shanghai). It does not use py-evm's
transaction executor. Its own executor (`qrdx/contracts/evm_executor_v2.py`) applies the message
over a world that loads accounts and storage on demand (`qrdx/contracts/evm_world.py`). Whatever
py-evm's transaction executor does, QRDX's has to do too, or it does something else.

To find out where it does something else, Ethereum's own state tests are run through QRDX's
executor.

## The state tests

`scripts/conformance/eest_state_tests.py` reads the state tests of an
[execution-spec-tests](https://github.com/ethereum/execution-spec-tests) release. Each test gives
a pre-state, a transaction and the post-state Ethereum reaches. For each one, the runner:

1. writes the pre-state into a fresh QRDX database;
2. runs the transaction the way the node's transaction path calls the executor (gas limit,
   price, intrinsic gas, access list), in the test's block context;
3. compares every account the test expects: balance, nonce, code and storage.

```
scripts/conformance/fetch_eest.sh                  # v5.4.0, sha256-checked, into .eest/
python scripts/conformance/eest_state_tests.py .eest/fixtures
QRDX_EEST_FIXTURES=.eest/fixtures pytest tests/test_evm_conformance.py
```

CI runs it inside the node image on every push.

**What is not compared,** because QRDX decides it on purpose:

* **The sender's balance and nonce.** The node's transaction path charges a failed transaction
  and consumes its nonce around the executor.
* **The coinbase.** QRDX burns fees and pays no tips.
* **Transactions Ethereum refuses before running** (`expectException`). QRDX's admission
  rules are its own.

`--mode ethereum` runs the message inside Ethereum's transaction rules instead. That isolates
the EVM and the world from how a transaction is charged.

## Result

Of the release's 1,469 Shanghai state tests, 1,460 agree. The other 9 differ where QRDX does on
purpose (`KNOWN` in the runner):

| Difference | Why |
|---|---|
| Calls to 0x0100–0x0104 revert | The retired exchange precompiles keep their addresses and revert, so a contract written against them fails loudly. |
| bn128 multiplication costs 12,000 gas more | py-evm runs it in Python; docs/BLOCK_LIMITS.md. |
| A creation onto an account with storage but no code or nonce (EIP-7610) succeeds | No such account can arise on QRDX: storage is only written by code, and goes when the code does. |

## What the tests found: `evm_conformance`

Before the fixes, 247 of the 1,469 differed. The fixes form one chain-spec feature,
`evm_conformance`, which is in `GENESIS_DEFAULT_FEATURES`: a network started by this release has
it from genesis. An existing network schedules it as a fork.

* **The intrinsic gas was a floor, not a cost.** The message ran with the whole gas limit, and
  the charge was `max(executed, intrinsic)`. A transaction therefore got its intrinsic gas free
  whenever it executed more than that: its calldata, and for a type-0x51 transaction its
  ML-DSA-65 signature check, priced at its true cost precisely because it is expensive. Every
  node did that work unpaid, and the block gas limit bounded only about half of it. A contract
  also saw more gas than it does on Ethereum (`gasleft()`, the 63/64 rule). Now the intrinsic gas
  comes out of the gas limit before the message runs, and is paid on top of what executes.
* **No refund.** EIP-3529's refund (at most a fifth of the gas used) was never given. Now it is.
* **The gas was charged after the message.** During execution, `BALANCE` of the payer showed
  the gas still unspent. Now the payer buys the whole gas limit up front and gets back what is
  unused, as on Ethereum.
* **The sender and recipient started cold.** Their first access cost 2,600 gas, where EIP-2929
  makes it 100. Now they start warm, like the coinbase and an access list's entries.
* **A creation did not check its address.** A transaction creating a contract onto an account
  that already had code or a nonce overwrote it. Ethereum fails the creation and consumes its
  gas. No such address is reachable in practice (the creating account's nonce moves on), but the
  check costs nothing.
* **MODEXP of an empty base returned 0.** py-evm returns 0 whenever the base is empty. An empty
  base is 0, and `0⁰ = 1`, so `modexp(∅, 0, m)` is `1 mod m`. The fixed precompile is
  `evm_world.modexp_conformant`.
* **0x0202 sent nothing.** `submitCrossChainTx` answered a hash as if it had sent a
  transaction to another chain. Nothing sends one, so the precompile now reverts, as the other
  retired ones do.

The executor's gas estimate (`eth_estimateGas`) now includes the intrinsic gas, so an estimate
is enough to send. The TypeScript SDK's default 0x51 gas limit (intrinsic + 300,000) already
left room for it.

Tests: `tests/test_evm_conformance.py` covers each rule with the feature, and the old behavior
without it.

## Not covered

* **The legacy GeneralStateTests.** The release fills its "static" tests (the ethereum/tests
  corpus) only for Cancun and Prague. QRDX's EVM is Shanghai's, so those would differ wherever
  Cancun does (transient storage, MCOPY, blob opcodes). Running them needs a Cancun-based fork.
* **Blockchain tests.** They exercise block-level rules (headers, withdrawals) that QRDX defines
  for itself.
