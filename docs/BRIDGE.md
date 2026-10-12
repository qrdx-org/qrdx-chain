# The consensus bridge

Tokens locked on another chain, minted on QRDX by a quorum of validators. Built for the perps
settlement asset: a bridged USD stablecoin (docs/PERPS_CLEARINGHOUSE.md §2), but any ERC-20 the
network lists works.

| Part | Where |
|---|---|
| Consensus state and rules | `qrdx/exchange/bridge.py`; `ExchangeStateManager._op_oracle_vote`, `_op_bridge_withdraw` |
| Validators' watcher | `qrdx/validator/bridge_watcher.py` |
| Source-chain lockbox | `contracts/bridge/QRDXLockbox.sol` (ABI: `QRDXLockbox.abi.json`) |
| Reads | `bridge_getAssets`, `bridge_getDeposit`, `bridge_getWithdrawals` |
| Wallet | `qrdx-wallet bridge assets / deposit / withdrawals / withdraw / receipt` |
| Tests | `tests/test_bridge.py`, `tests/test_bridge_cli.py` |

## Assets

A chain-spec parameter, so every node agrees on them and listing one is a fork
(docs/PROTOCOL_UPGRADES.md):

    BRIDGE_ASSETS = ["USDC:42161:0xaf88d065e77c8cc2239327c5edb3a432268e5831:6"]
                     symbol:source chain id:token address there:decimals

A bridged token's QRDX address is derived from its source
(`blake2b("bridge:<chain>:<token>")`, see `bridge_getAssets`). The protocol creates it at its
first deposit: zero supply until then, the source's decimals, and as mint authority
`BRIDGE_AUTHORITY` — a protocol-internal `0xBRDG…` holder that no key controls
(`qrdx/crypto/account_id.py`). Only the bridge mints it, and nothing can change that: a
bridged token has no freeze, pause or metadata authority. To settle perps in it, set
`PERP_COLLATERAL_TOKEN` to that address.

## Deposits

1. The user approves the lockbox and calls `deposit(token, amount, recipient)` on the source
   chain, naming a QRDX address (`0xPQ…` or `0x…`). The lockbox emits
   `Deposit(token, from, amount, recipient)` with what it actually received.
2. Each validator's watcher (`QRDX_BRIDGE_SOURCES`) reads the lockbox's `Deposit` logs **up to
   the source chain's finalized block**, never past it, and skips logs flagged removed.
3. The validator's oracle vote attests the deposits it has seen and the chain has not minted,
   up to 16 a vote: `{"chain", "token", "tx", "log", "to", "amount"}`. Votes already carry their
   own sequence, travel the mempool's vote lane and count only committee members not convicted
   by slashing evidence (docs/PERPS_CLEARINGHOUSE.md §8). A vote that names a new deposit is sent
   at once.
4. Each attestation is recorded against the deposit's exact content. **The one that brings
   attestations of identical content past two thirds of the committee's stake mints it** to the
   recipient, in the same transaction, and records its id (`<chain>:<tx>:<log index>`) as
   minted: later attestations of it are ignored, so a deposit is minted once.
5. Attestations that never reach a quorum are dropped after 24 hours of block time; a validator
   still seeing the deposit attests it again.

A validator that reads a block that is later reorganized away, or decodes a wrong amount,
wastes only its own attestation: attestations that differ in any field never add up. The amount
is normalized to the asset's decimals, so honest copies are byte-identical.

## Withdrawals

`BRIDGE_WITHDRAW {"token_address", "amount", "to"}` burns the amount from the sender (the
balance must cover it) and records a withdrawal: a sequential id, the source chain and token,
the recipient there (a `0x` address), the amount, the sender, the block. `bridge_getWithdrawals`
lists them in order. The lockbox's custodian releases each one with
`release(withdrawalId, token, to, amount × 10^decimals)` once its block is final; the lockbox
refuses an id twice.

## Trust

- **Minting** needs validators holding more than two thirds of the stake to attest a deposit
  identically: the same assumption as finality.
- **Releasing** is the custodian's. The source chains cannot verify QRDX validators' Dilithium
  signatures, so the lockbox cannot check a withdrawal itself. Deploy the custodian as a
  multisig, have it release only withdrawals in finalized QRDX blocks, and reconcile
  `bridge_getWithdrawals` against the lockbox's `Released` events. The lockbox hands custody over
  in two steps (`offerCustody`, `acceptCustody`), and the custodian can pause deposits.
- A deposit of a token the network does not list stays locked; the custodian can return it.

## Running it

Validators set their sources, comma-separated:

    QRDX_BRIDGE_SOURCES=42161=https://arb1.example/rpc@0x…lockbox
    QRDX_BRIDGE_FROM_BLOCK_42161=<the lockbox's deployment block>

`file:<path>` reads a JSON list of deposits instead (the testnet's scripted source, like its
price feed). Without a start block a source scans the last 50,000 blocks. A validator with no
source attests nothing; the rest still reach a quorum if they hold enough stake.

The lockbox was compiled with solc 0.8.24 and exercised in an EVM (deposit, a release, a
refused second release, a refused non-custodian release, paused deposits). The log it emitted is
the fixture the watcher's decoder is tested against (`tests/fixtures/lockbox_deposit_logs.json`).
**It has not been audited.** That, deploying it, and choosing the custodian are prerequisites for
any real asset.
