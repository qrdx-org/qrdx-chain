# Quantum migration and the Doomsday Protocol

QRDX's own accounts (`0xPQ…`) sign with ML-DSA-65. Its `0x…` accounts sign with ECDSA
(secp256k1), as on Ethereum:

* Ethereum wallets, on QRDX's EVM;
* the deposit addresses of bridged tokens.

A quantum computer large enough to run Shor's algorithm would derive an ECDSA private key from
its public key. Every account that has ever signed has published its public key.

This document covers what QRDX does about that:

* **Quantum migration.** While ECDSA still holds, an ECDSA account names the post-quantum
  account that should control it.
* **The Doomsday Protocol.** The moment ECDSA can no longer be trusted, it stops counting.

Code:

* `qrdx/exchange/migration.py`, `qrdx/exchange/doomsday.py`;
* the `MIGRATION_CLAIM` and `DOOMSDAY_PROVE` handlers in `qrdx/exchange/state_manager.py`;
* `contracts/migration/QRDXMigrationRegistry.sol`.

Tests: `tests/test_quantum_migration.py`, `tests/test_doomsday.py`.

**Verified live (2026-10-28).**

Setup: anvil (a real Merkle-Patricia EVM) as the bridged chain, and a 4-node QRDX network whose
validators attested only its finalized heads.

1. **Registering and claiming.** Account B registered a fresh post-quantum successor in the
   registry. `claim_successor.py` bound it as B's controller on every node.
2. **Before the trigger.** B received 100 native QRDX and sent an ECDSA transaction, which was
   included.
3. **The canary.** Its nonce was raised on anvil (`anvil_setNonce`, standing in for a spend).
   `canary.py check` reported it signed, and `canary.py prove` triggered the protocol. All four
   nodes recorded block 835, timed at the proven head.
4. **After the trigger.**
   * B's next ECDSA transaction was refused at admission.
   * The successor moved 25 QRDX out of B with `TOKEN_TRANSFER "QRDX"`.
   * A registration made after the trigger was refused (`MIGRATION_CLAIM`: "registered after
     the Doomsday Protocol triggered").
5. **Consistency.** Every node had the same block hash and state root. A node restarted with a
   full rebuild from genesis replayed the trigger and matched its durable state.

Both mechanisms use the bridge's proof machinery (docs/BRIDGE.md, "Proving a deposit"):

* validators attest each bridged chain's finalized heads;
* anyone proves a fact about that chain's state with an MPT proof (`eth_getProof`) against one of
  the last 64 attested heads.

Nothing else is trusted: no relayer and no oracle report.

## Quantum migration

An account binds a **successor**: a `0xPQ…` account that becomes the account's controller
(account control, docs/ACCOUNT_CONTROL.md). A controller signs anything for the account. The
binding is permanent.

### On QRDX

The `0x` account sends `ACCOUNT_POLICY` through the EVM write precompile (`0x…0401`) and signs it
with its own ECDSA key, from any Ethereum wallet:

1. `add_controller` with the successor.
2. When it chooses, `own_key: false`. From then on, only its controllers sign for it.

This is ordinary account control.

### From Ethereum, or any bridged EVM chain

1. The account calls `QRDXMigrationRegistry.register(successor)` on its chain, with the
   successor's 32 bytes (the `0xPQ` address without its prefix).
   * Once per account; the commitment can never change, so someone who breaks the key later
     cannot replace it.
   * Only externally owned accounts may register (`msg.sender == tx.origin`), because a
     contract's address on one chain may belong to someone else on another.
   * The registry records the block time.
2. Anyone proves the commitment on QRDX with `MIGRATION_CLAIM`:

   ```
   python scripts/migration/claim_successor.py --qrdx-rpc URL --rpc URL --chain-id 1 \
       --registry 0xRegistry --account 0xAccount --wallet my.keystore.json --password-file pw.txt
   ```

   The script reads both registry slots (`successorOf` at slot 0, `registeredAt` at slot 1) at
   the newest attested head and submits their proofs. The relayer's wallet pays the gas.
3. QRDX checks that:
   * the chain's registry (chain spec `MIGRATION_REGISTRIES`, `CHAIN_ID:ADDRESS`) holds exactly
     this successor and time at that head;
   * the account is not already bound to another successor (a repeated claim of the same one
     succeeds and changes nothing);
   * the commitment was made before the Doomsday Protocol's time.

   It then adds the successor as the account's controller.

The successor controls the account with the **same address** on QRDX. An externally owned
account's address is derived from its key, so it is the same account on both chains.

### What a successor can do

The successor signs exchange transactions with `sender` set to the account and `signer` set to
itself. It can:

* trade, cancel and withdraw margin;
* move tokens (`TOKEN_TRANSFER`);
* move the account's native QRDX (`TOKEN_TRANSFER` with `token_address: "QRDX"`);
* turn the account's own key off (`ACCOUNT_POLICY own_key: false`);
* add or remove further controllers.

This is how an account moves its funds once ECDSA is off.

## The Doomsday Protocol

### The triggers

**A canary.**

* For each bridged chain the chain spec names a canary (`DOOMSDAY_CANARIES`,
  `CHAIN_ID:ADDRESS`).
* Its public key is derived from a hash: the first valid x-coordinate on secp256k1 at or above
  `sha256("QRDX doomsday canary")`, with its even y. No one chose it, so no one knows its
  private key. Anyone can recompute it:

  ```
  python scripts/doomsday/canary.py address
  canary address : 0x2fe433468ddfd1ac11eb17355b831645c6b4f26e
  ```

* It is funded with a bounty. Only its key can move the bounty, so the first person able to
  derive an ECDSA key from a public key has a reason to do it publicly.
* An account's nonce rises only when its key signs. So the canary's nonce above 0 at a finalized
  head proves that ECDSA is broken.
* Anyone proves it with `DOOMSDAY_PROVE`, an account proof of the canary against an attested
  head:

  ```
  python scripts/doomsday/canary.py check --rpc URL       # nonce and balance, finalized
  python scripts/doomsday/canary.py prove --qrdx-rpc URL --rpc URL --chain-id 1 \
      --wallet my.keystore.json --password-file pw.txt
  ```

**Governance.**

* `declare_quantum_emergency` (with a `reason`) covers evidence the canaries do not show.
* It passes like any proposal: validators' vote, timelock, holders' veto (docs/GOVERNANCE.md).
* The canary needs no vote.

### What changes, from the block that triggers it

* **Every ECDSA key on QRDX stops signing.**
  * Transactions signed with secp256k1 are refused on every path: admission, block production
    and import.
  * The `ECRECOVER` precompile recovers no address, as for an invalid signature, so a contract
    that checks an ECDSA signature (a permit, a multisig) reads `address(0)` and refuses it.
  * An ECDSA account acts only through the post-quantum controllers it bound beforehand.
  * Accounts that bound none wait, untouched, for a recovery governance decides.
* **Agents that a `0x` account approved are revoked.**
  * The account's ECDSA key may have approved them for someone who broke it.
  * The revocation is conservative: it includes agents a controller approved. A controller, or a
    contract that a post-quantum transaction drives, approves them again.
* **The bridge stops.**
  * Deposits are no longer minted, whether by attestation or by proof: the source chains' own
    accounts, and perhaps their consensus, may be broken.
  * Withdrawals to them (`BRIDGE_WITHDRAW`) are refused.
  * Withdrawals recorded before the trigger stay recorded; the custodian decides about them.
* **No later commitment counts.**
  * The protocol's time is the earliest of the trigger block's time and the time of the head the
    canary was proven spent at. A later proof against an earlier head moves it earlier; nothing
    moves it later.
  * A registry commitment made at or after that time binds nothing (`MIGRATION_CLAIM` refuses it).
  * Commitments made before it can still be proven afterwards.

The state is one committed entry, `bridge.flags["doomsday"]`, in the exchange root:

* every node agrees on it from the trigger block on;
* a reorganization that drops the block takes it back, with the agents it revoked.

Nothing undoes it otherwise. Recovery is a protocol upgrade.

### Watching it

* `bridge_getDoomsday()` returns `{"triggered": {time, height, cause} | null, "canaries":
  {chain: address}}`. `bridge_getGuardrails()` includes the same state.
* The `qrdx_doomsday_triggered` gauge is exported on every node. The `DoomsdayTriggered` alert
  is critical (docker/alert-rules.yml).

## Deploying

1. Deploy `QRDXMigrationRegistry` on each bridged chain:
   * from `contracts/migration/QRDXMigrationRegistry.artifact.json`;
   * no constructor arguments;
   * no owner: nothing about it can change.
2. Add it to the chain spec's `MIGRATION_REGISTRIES`.
3. Fund the canary on each bridged chain and add it to `DOOMSDAY_CANARIES`. The same address
   serves every EVM chain: its key is unknown on all of them.
4. Tell users how to bind a successor: on QRDX through account control, or on Ethereum through
   the registry. Do it before it is needed.

## Limits

* **A canary proves a break; it does not predict one.** An attacker who breaks ECDSA quietly
  would leave the canary alone. Governance's declaration is the backstop, and binding a
  successor early is the real protection.
* **Before the trigger, ECDSA is trusted.** A commitment or controller made with a key that was
  already broken counts. Nothing on chain can tell otherwise.
* **The source chain's state is trusted at its attested heads.** If a quantum break reached the
  source chain's consensus, its heads could be forged. The trigger stops the bridge for that
  reason, but commitments proven afterwards rest on heads attested after the break.
* **Contract accounts.** A `0x` contract on QRDX has no key and keeps working through
  post-quantum transactions. If its own logic verifies ECDSA signatures, `ECRECOVER` now fails
  them. Post-quantum smart accounts (docs/PQ_SMART_ACCOUNTS.md) verify ML-DSA-65 and are
  unaffected.
