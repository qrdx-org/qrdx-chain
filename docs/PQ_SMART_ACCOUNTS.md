# PQ smart accounts

QRDX accounts are post-quantum at the protocol level:

* a `0xPQ…` account signs with ML-DSA-65;
* account control adds controllers, m-of-n multisig, guardians with a recovery delay, and agents
  with spending limits (docs/ACCOUNT_CONTROL.md);
* an Ethereum account trades through an approved PQ agent (docs/PERPS_API.md, "Trading from an
  Ethereum wallet").

**PQ smart accounts** bring the same model into the EVM, as contracts any application can work
with. Code: `contracts/accounts/PQSmartAccount.sol` (the account and its factory), built with
solc 0.8.24 (optimizer 200 runs, `viaIR`, EVM `paris`) into `PQSmartAccount.artifact.json`.
Tests: `tests/test_pq_smart_account.py`, run in the QRDX EVM.

## What an account is

An EIP-1167 minimal proxy of one `PQSmartAccount` implementation. `PQAccountFactory.create(ownerKey,
salt)` deploys it with CREATE2 and initializes it in the same transaction, so nobody can claim a
fresh account first. `predict(ownerKey, salt)` gives its address in advance, so it can be funded
before it exists. A whole account's code costs about 1.2M gas to deploy, more than a block's 1M EVM
gas. A proxy costs well under 100k. So the implementation and the factory are part of genesis
(below).

## Predeployed at genesis

| Address | Contract |
|---|---|
| `0x0000000000000000000000000000000000000600` | `PQSmartAccount`, the implementation. It is locked: its owner key has no known preimage, as its constructor leaves it |
| `0x0000000000000000000000000000000000000601` | `PQAccountFactory`, for that implementation |

They come from the chain-spec parameter `EVM_PREDEPLOYS` (`qrdx/predeploys.py`). Each entry is
`ADDRESS:CODE[:SLOT=VALUE...]`, at `0x…0600` or above; the precompiles sit below.
* **Pinned by the genesis file.** The code is in the spec, and the genesis block commits to the
  spec, so a later release with other bytecode cannot build a different genesis from the same
  file.
* **Re-seeded by every rebuild.** Genesis writes each predeploy as a block-0 record
  (`genesis_contract`), beside the allocations, and every rebuild seeds it from there.
* **No file outside the package.** The node carries the runtime code in `qrdx/predeploy_code.py`.
  `tests/test_predeploys.py` fails if it drifts from the artifact, or if the factory's code
  differs from what its constructor would deploy.

Creating an account through the predeployed factory, and using it, fits a block's gas
(`tests/test_predeploys.py`).

## Keys and signatures

* **The owner** is an ML-DSA-65 key. The account stores only its keccak-256 hash; the key
  (1,952 bytes) travels with each signature, because storing it would cost more gas than a block
  holds. Signatures are checked by QRDX's ML-DSA-65 precompile at `0x…0500` (input: 32-byte digest,
  key, 3,309-byte signature; 50,000 gas).
* **`execute(calls, nonce, validUntil, publicKey, signature)`** runs a batch of calls. Anyone may
  submit it: a relayer, or the owner's own account. The signed digest (`executeHash`) binds:
  * a domain tag;
  * the chain id and the account;
  * the nonce, which must be the next one;
  * the deadline;
  * every call.

  A signature is never valid on another account or chain, or twice.
* **ERC-1271.** `isValidSignature(hash, abi.encode(publicKey, signature))` returns the magic value
  when the owner signed `keccak256(domain, chain id, account, hash)`, so applications can check a
  PQ signature for the account.

## Session keys

Through `execute`, the owner can authorise other ML-DSA-65 keys with `setSessionKey(keyHash,
validUntil, valuePerDay)`, for a game, a trading bot or a browser tab. A session key:

* runs batches until its deadline;
* spends at most `valuePerDay` of QRDX a day;
* can never call the account itself, so it can change no key, guardian or session.

## Recovery

Through `execute`, the owner sets up recovery with `setGuardians(guardians, threshold, delay)`:
up to 8 guardians, and a delay of at least a day. Guardians can be people's accounts, other
smart accounts, or a service.

1. **Guardians approve.** When `threshold` of them approve the same new key
   (`approveRecovery(newKey)`), the delay starts.
2. **Anyone completes it.** After the delay, anyone may call `completeRecovery()`.
3. **The owner can cancel.** If the owner still holds its key, it can cancel with
   `cancelRecovery()` until then.

Changing the owner key or the guardians clears any pending recovery.

## The precompile table (`evm_standard_precompiles`)

The EVM fork had put ML-DSA-65 verification at `0x09`, which is Ethereum's BLAKE2F (EIP-152), and
BLAKE3 and two ML-KEM precompiles at `0x0a`–`0x0c`, which Ethereum's later forks assign. Under the
chain-spec feature `evm_standard_precompiles` (a default for new networks):

| Address | Precompile |
|---|---|
| `0x09` | BLAKE2F, as on Ethereum |
| `0x0a`–`0x0c` | free (left to Ethereum's forks) |
| `0x0500` | ML-DSA-65 verification |
| `0x0501` | BLAKE3-256 |

The ML-KEM precompiles are gone. Decapsulating on chain needs the secret key in calldata, where
everyone can read it.

## The TypeScript SDK

`sdk/typescript` (`@qrdx/sdk`) runs in browsers and Node.js. It uses ML-DSA-65 through
`@noble/post-quantum`, which interoperates with the node's liboqs: same key encodings, and
signatures verify both ways. It provides:

* keys, `0xPQ…` addresses and account ids;
* exchange transactions, signed to the node's exact bytes;
* type-0x51 EVM transactions, so a PQ key needs no Ethereum key;
* for smart accounts: `executeHash` and signed `execute` calldata, ERC-1271 signatures, the
  account's address before it exists, and the session, guardian, owner-key and recovery calls;
* a JSON-RPC client: `createSmartAccount`, `executeFromSmartAccount`, `sendExchange`.

Its tests run against vectors the node's own code computes (`scripts/sdk/make_vectors.py`).
`tests/test_sdk_vectors.py` holds those vectors to the node. It checks the smart-account values
against the contract in the QRDX EVM, and verifies with liboqs what the SDK signs.

## Not yet

* An audit: like the lockbox, the account guards funds and has not been audited, and neither
  has the SDK.
