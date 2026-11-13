# The consensus bridge

Tokens locked on another chain, minted on QRDX by a quorum of validators. Built for the perps
settlement asset: a bridged USD stablecoin (docs/PERPS_CLEARINGHOUSE.md §2), but any ERC-20 the
network lists works.

| Part | Where |
|---|---|
| Consensus state and rules | `qrdx/exchange/bridge.py`; `ExchangeStateManager._op_oracle_vote`, `_op_bridge_prove_deposit`, `_op_bridge_withdraw` |
| Validators' watcher | `qrdx/validator/bridge_watcher.py` |
| Source-chain lockbox | `contracts/bridge/QRDXLockbox.sol` (ABI: `QRDXLockbox.abi.json`) |
| Reads | `bridge_getAssets`, `bridge_getDeposit`, `bridge_getWithdrawals`, `bridge_getHeads`, `bridge_getGuardrails` |
| Wallet | `qrdx-wallet bridge assets / deposit / withdrawals / withdraw / receipt` |
| Deploying, proving deposits, and the custodian's work | `scripts/bridge/deploy_lockbox.py`, `scripts/bridge/prove_deposit.py`, `scripts/bridge/custodian.py` (`qrdx/bridge/lockbox.py`) |
| Tests | `tests/test_bridge.py`, `tests/test_bridge_proofs.py`, `tests/test_bridge_guardrails.py`, `tests/test_lockbox_contract.py`, `tests/test_lockbox_tools.py`, `tests/test_bridge_cli.py` |

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
   chain, naming a QRDX address (`0xPQ…` or `0x…`).
   * The deposit gets the lockbox's next id.
   * The lockbox stores its record, `deposits[id] = keccak256(abi.encode(token, from, amount,
     recipient, time))`, where `amount` is what it actually received and `time` is the block's.
   * It emits `Deposit(id, token, from, amount, recipient, time)`.

   The deposit's id on QRDX is `<chain>:<id>`, whichever way it is minted: by attestation (below)
   or by proof ("Proving a deposit"). So a deposit mints once.
2. Each validator's watcher (`QRDX_BRIDGE_SOURCES`) reads the lockbox's `Deposit` logs **up to
   the source chain's finalized block**, never past it, and skips logs flagged removed.
3. The validator's oracle vote attests the deposits it has seen and the chain has not minted,
   up to 16 a vote, taking turns when there are more:
   `{"chain", "id", "token", "from", "to", "amount", "time"}`. `time` runs the deposit window
   (below). A validator with `QRDX_BRIDGE_DEPOSIT_VOTES=0` attests no deposits, only chain heads:
   deposits then mint by proof. Votes already carry their own
   sequence, travel the mempool's vote lane and count only committee members not convicted by
   slashing evidence (docs/PERPS_CLEARINGHOUSE.md §8). A vote that names a new deposit is sent
   at once.
4. Each attestation is recorded against the deposit's exact content. **The one that brings
   attestations of identical content past two thirds of the committee's stake mints it** to the
   recipient, in the same transaction, and records its id (`<chain>:<id>`) as minted: later
   attestations or proofs of it are refused, so a deposit is minted once.
5. Attestations that never reach a quorum are dropped after 24 hours of block time; a validator
   still seeing the deposit attests it again. A validator may hold at most 1,024 attestations
   short of a quorum (`MAX_PENDING_PER_VOTER`); past it, its new ones are ignored. So no single
   validator can fill the state with deposits that never happened (docs/EXCHANGE_AUDIT.md 10).

A validator that reads a block that is later reorganized away, or decodes a wrong amount,
wastes only its own attestation: attestations that differ in any field never add up. The amount
is normalized to the asset's decimals, so honest copies are byte-identical.

## Proving a deposit

This is the trust-minimized path. Validators attest only each source chain's finalized head
("Chain heads"): its height, hash and **state root**. A deposit is then minted by proving the
lockbox's record of it against that root, by anyone: the depositor, a relayer, an app.

1. **Find a head.** Take an attested head at or after the deposit's block, from
   `bridge_getHeads(chain)` (the last 64 are kept).
2. **Get the proof.** Ask the source chain for `eth_getProof(lockbox, [slot], head height)`, where
   `slot = keccak256(abi.encode(id, 4))`: the lockbox keeps `deposits` at storage slot 4.
3. **Send it.** Send `BRIDGE_PROVE_DEPOSIT {"deposit": {...as attested...}, "height",
   "account_proof", "storage_proof"}`.

QRDX checks:

* the lockbox is the chain's in the spec (`BRIDGE_LOCKBOXES`, `CHAIN_ID:ADDRESS`);
* the head at that height is attested;
* the Merkle-Patricia proofs lead from its state root to the lockbox's account, then to
  `deposits[id]`;
* the value there is exactly the hash of the deposit named.

Then the deposit mints like an attested one: within the deposit window, under the guardrails,
once. A proof of a different amount, recipient or depositor, of another account, or against an
unattested height mints nothing.

`scripts/bridge/prove_deposit.py` does all of this: it reads the deposit, picks the newest
attested head after it, fetches the proof, signs and sends the transaction, and waits for the
receipt. Any QRDX account can send it (it pays the gas). `--unsigned` prints the parameters for
another signer.

What this changes about trust:

* **Validators vouch for one state root per head, not for each deposit.** A deposit needs no
  watcher to have seen it; anyone with a source-chain RPC can mint it.
* **One step from trustless.** Head attestation is the only assumption left. A light client that
  verifies the source chain's finality on QRDX (for Ethereum, its sync committee) can replace it.

## The deposit window, and refunds

A deposit counts toward a mint only while it is younger than `BRIDGE_DEPOSIT_WINDOW`, measured
from its source block's time on QRDX's clock. The default is 7 days, and a real network may not
set less than a day. After the window no attestation counts, so the deposit can never be minted:

* QRDX's clock is each block's slot start time (feature `slot_timestamps`), so a proposer can
  neither move it nor run it backwards.
* A deposit whose source time is more than 10 minutes ahead of QRDX's clock does not count
  either.
* Watchers drop expired deposits.

That is what makes **refunds** safe. A deposit QRDX will never mint stays locked until the
custodian returns it. This covers:

* a token the network does not list;
* a recipient QRDX refuses;
* a deposit no quorum attested in time;
* a deposit a guardrail held back until its window closed.

The custodian may refund a deposit once both hold:

* the **finalized** QRDX block's time is past the deposit's window, so no block that could
  still count it is unfinalized;
* no QRDX node reports it minted.

`refund(id, token, from, amount, recipient, time)` on the lockbox returns a deposit, and the
contract checks what it can:

* the arguments must hash to `deposits[id]`, so it is exactly a recorded deposit, whole;
* it pays the depositor (`from`), and no one else;
* it pays once per deposit (a deposit id is never a withdrawal id);
* the lockbox's `refundDelay` (set at deployment, at least a day longer than the deposit window)
  must have passed since the deposit.

The custodian's part is when: only once QRDX's finalized time is past the window and no node
reports the deposit minted. `scripts/bridge/custodian.py refunds` plans these refunds, with a
Safe batch and a batch hash. `reconcile` alarms on any refund that is not a whole, never-minted,
expired deposit returned to its depositor.

## Guardrails

* **Mint limits.** `BRIDGE_MINT_LIMITS` holds `SYMBOL:PER_DAY:CAP` per asset, in its own units;
  0 means no limit of that kind. Each asset mints at most `PER_DAY` in a day of QRDX's clock and
  reaches a supply of at most `CAP`. **On a real network an asset with no entry mints nothing.**
  A compromised quorum, or a bug, can therefore mint at most one day's limit before people
  notice.
* **Pause.** Governance can pause and resume minting (`bridge_mint_pause`,
  docs/GOVERNANCE.md).
* **What happens to a held deposit.** A deposit over a limit, or arriving while minting is
  paused, keeps its attestations and mints at a later vote. If its window closes first, it is
  refunded instead.

`bridge_getGuardrails` shows the window, the limits, each asset's use today, and whether minting
is paused.

## Withdrawals

`BRIDGE_WITHDRAW {"token_address", "amount", "to"}` burns the amount from the sender (the
balance must cover it) and records a withdrawal: a sequential id, the source chain and token,
the recipient there (a `0x` address), the amount, the sender, the block. `bridge_getWithdrawals`
lists them in order. The lockbox's custodian releases each one with
`release(withdrawalId, token, to, amount × 10^decimals)` once its block is final; the lockbox
refuses an id twice.

## Chain heads

The same validators attest each source chain's **finalized head** — its height, block hash, state
root and timestamp — so QRDX holds, as consensus state, a light client's view of the chains it
bridges:

- Each validator's watcher reads the source's finalized block (the one it scans deposits up to)
  and its oracle vote carries it (`heads`, at most 8, one per chain) when it is higher than the
  attested one. Only the chains the network bridges (`BRIDGE_ASSETS`) count; a head of any other
  chain is skipped.
- A head becomes the chain's attested head when votes younger than an hour, carrying **exactly**
  that head, hold more than two thirds of the committee's stake — and only if it is higher than
  the current one: heads only move forward.
- They are committed (`bridge.heads`, `bridge.head_votes`), so they are in the state root and
  provable like any exchange entry (docs/STATE_PROOFS.md).
- Contracts read them through **`getChainState`** at `0x…0200`: `chain_id` (4 bytes) → height (8)
  · hash (32) · state root (32) · timestamp (8), or 80 zero bytes if none is attested. It answers
  from the consensus state at that point of the block, so every node returns the same. (It used to
  answer from a node-local table nothing filled; filled from a node's own view it would have split
  the chain.)
- Contracts prove a bridged chain's state through **`verifyExternalProof`** at `0x…0201`
  (`qrdx/contracts/external_proof_evm.py`): chain id (4) · height of an attested head (8, one of
  the last 64) · account address (20) · its Merkle-Patricia proof (node count 2, then each node:
  length 4 · RLP), optionally · a storage slot (32) · its proof — exactly what `eth_getProof`
  returns. Output `0x01` · nonce · balance · storage root · code hash (32 each) [· the slot's value
  (32)], absence proven as zeros; or `0x00` if the proof does not hold against that head's state
  root, the head is not attested, or the input is malformed. It never reverts. Gas 200,000 + 5,000
  a node. A contract can read another chain's balance, a lockbox's record or an oracle's slot with
  no trust beyond the validators' two-thirds attestation of the head.

## Trust

- **Minting** needs validators holding more than two thirds of the stake: either to attest the
  deposit identically, or to attest a finalized head of its chain that a storage proof then shows
  holds the deposit's record. With proofs, they vouch for one state root rather than each
  deposit, and `QRDX_BRIDGE_DEPOSIT_VOTES=0` leaves them only that.
- **Reading the source chain** is each validator's own: it must read its own RPC endpoint. If
  validators holding two thirds of the stake share one provider, that provider can make them
  attest a deposit that never happened.
- **Releasing** is the custodian's. The source chains cannot verify QRDX validators' Dilithium
  signatures, so the lockbox cannot check a withdrawal itself. Deploy the custodian as a
  multisig, have it release only withdrawals in finalized QRDX blocks, and reconcile
  `bridge_getWithdrawals` against the lockbox's `Released` events. The lockbox hands custody over
  in two steps (`offerCustody`, `acceptCustody`), and the custodian can pause deposits.
- **Refunds** are the custodian's as to timing only. The lockbox lets it refund nothing but a
  recorded deposit, whole, to its depositor, after `refundDelay`. Custodian tooling waits for
  QRDX's finalized time to pass the window, and `reconcile` checks every refund.
- **What a compromised quorum can mint** is bounded by `BRIDGE_MINT_LIMITS`. Governance can
  pause minting, and the custodian can pause deposits on the source chain.

## Deploying to a new chain

What it takes to bridge one token from one EVM chain (repeat per chain and token). Steps 1–4 and
8 are done by whoever holds the keys; nothing here can be done from a QRDX node.

1. **Audit the lockbox.** `contracts/bridge/QRDXLockbox.sol` is about 100 lines and has not
   been audited. Get it audited before any real asset goes through it.
2. **Create the custodian on that chain.** A Safe multisig (for example 3 of 5, the keys held by
   different people on hardware wallets). It is the only account that can release funds, pause
   deposits or hand custody over.
3. **Deploy the lockbox** with `scripts/bridge/deploy_lockbox.py`:

       python scripts/bridge/deploy_lockbox.py --rpc <chain RPC> --chain-id <id> \
           --custodian <the Safe> --refund-delay 691200 --qrdx-rpc <a QRDX node> \
           --keystore deployer.json --verify-build --out lockbox.json

   `--refund-delay` (8 days by default) is fixed in the contract. With `--qrdx-rpc` the script
   refuses one that is not at least a day longer than the network's deposit window.

   It deploys the committed build (`contracts/bridge/QRDXLockbox.artifact.json`: solc 0.8.24,
   optimizer 200 runs, EVM `paris`), which `--verify-build` recompiles and checks byte for byte.
   It refuses a wrong chain id, a chain without the `finalized` tag, or a custodian that is not a
   contract. After deploying, it checks the code on chain against the build and reads back the
   custodian. It writes the deployment record and prints the lines for steps 5 and 6. The
   deployer's key only pays the gas.

   To deploy from a hardware wallet instead, `--unsigned` prints the creation transaction to sign
   elsewhere (or use Foundry's `forge create … --ledger` with the same compiler settings). Then
   verify the source on the chain's explorer with those settings.
4. **Check the chain's RPC supports the `finalized` block tag**
   (`eth_getBlockByNumber("finalized")`). The watcher reads deposits only up to it. Ethereum
   and the major rollups (Arbitrum, Optimism, Base) support it; check any other chain with that
   call. A chain that does not cannot be bridged as built.
5. **List the asset in the chain spec:** `BRIDGE_ASSETS` gets
   `SYMBOL:<chain id>:<token address there>:<decimals>`. Do it at genesis, or later as a
   protocol upgrade (docs/PROTOCOL_UPGRADES.md). To settle perps in it, also set
   `PERP_COLLATERAL_TOKEN` to its QRDX address (`bridge_getAssets` shows it). Give it a mint
   limit in `BRIDGE_MINT_LIMITS` (`SYMBOL:PER_DAY:CAP`): on a real network an asset without one
   mints nothing. Name the lockbox in `BRIDGE_LOCKBOXES` (`CHAIN_ID:ADDRESS`) so deposits can be
   proven.
6. **Point every validator at the chain.** Each validator sets, comma-separating several chains:

       QRDX_BRIDGE_SOURCES=<chain id>=<its own RPC URL>@<lockbox address>
       QRDX_BRIDGE_FROM_BLOCK_<chain id>=<the deployment block>

   **Each validator must use its own RPC endpoint**: its own node of that chain, or at least a
   provider no other validator uses. Two thirds of validators reading one provider means that
   provider alone decides what is minted.
7. **Test with a small amount.** Deposit through the lockbox. `bridge_getDeposit` shows the
   attestations, then the mint. Then withdraw with `BRIDGE_WITHDRAW` and have the custodian
   release it.
8. **Run the custodian's side** with `scripts/bridge/custodian.py`. It never holds the Safe's
   keys:
   - `plan` lists the withdrawals ready to release and writes a Safe Transaction Builder batch.
     It takes only withdrawals in **finalized** QRDX blocks, because a reorg can renumber the
     others; it takes each once, and only if every QRDX node named (`--qrdx-rpc`, repeated)
     reports it identically. Each signer runs it against their own node and compares the batch
     hash it prints. Then they import the batch in the Safe app and sign it.
   - `reconcile` checks every `Released` event against QRDX's records: paid exactly, once, and
     only for a finalized withdrawal. It exits 1 on any alarm, so it can run from a monitor.
   - `deposits` shows each deposit as minted, attested but not minted (no quorum yet, or held
     by a guardrail), or not attested.
   - `refunds` plans the refunds of deposits QRDX will never mint (see "The deposit window, and
     refunds"), as a Safe batch with a batch hash. `refund` sends them with a single key, for
     test networks only.
   - `status` shows each asset's backing: tokens locked against QRDX's supply plus the withdrawals
     still owed.
   - `release` sends the releases with a single key, for test networks only.

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

**End to end, 2026-10-27.** On a 4-node test network, with its own EVM standing in for the source
chain:
- the deploy script deployed a test token and the lockbox (from the committed build, verified on
  chain);
- a 250-token deposit was attested by the validators and minted on QRDX;
- a 100-token withdrawal was burned on QRDX;
- the custodian tool planned it once QRDX finalized it, with all four nodes agreeing;
- the tool released it (single key), reconciled it with no alarms, and reported the asset
  backed: 150 locked against 150 minted.

The recipient received exactly 100.

**Refunds end to end, 2026-10-27.** On a fresh 4-node test network:
- **Setup:** a 120-second deposit window, `TUSD:300:1000` limits, the new lockbox build (deployed
  with an EIP-1559 transaction), and a second, unlisted token.
- **Deposits:** 250 TUSD minted. A second deposit of 100 TUSD was attested but held by the daily
  limit. 77 of the unlisted token were never attested.
- **Refunds:** once QRDX's finalized time passed both windows, `refunds` planned exactly those
  two, back to the depositor, with all four nodes agreeing. `refund` sent them, `reconcile`
  reported no alarms, and a second plan found nothing left.
- **Result:** the lockbox held exactly the 250 TUSD backing QRDX's supply of 250. The depositor
  had every other token back. Every node reports the refunded deposit never minted.

**The trust-minimized path end to end, 2026-10-28.**
* **Setup.** The source chain was `anvil`, an Ethereum node with real Merkle-Patricia state and
  `eth_getProof`. The 4-node QRDX network's validators attested only its finalized heads
  (`QRDX_BRIDGE_DEPOSIT_VOTES=0`).
* **Deploy.** The lockbox was deployed with an EIP-1559 transaction, and its deployed code was
  checked against the build with `refundDelay` filled in.
* **Deposits.** 250 TUSD and 77 of an unlisted token were deposited.
* **The proof.** A relayer, not the depositor, ran `prove_deposit.py`. It proved deposit 1
  against attested head 130, and all four nodes minted 250 to the recipient. A second proof was
  refused as already minted, and a proof of the unlisted token's deposit was refused.
* **The refund.** After QRDX's finalized time passed the window and anvil's clock passed the
  1-day refund delay, the custodian tooling refunded the unlisted deposit (77 back to the
  depositor), and `reconcile` reported nothing.
* **Result.** The lockbox held exactly the 250 backing QRDX's supply.
