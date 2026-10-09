# Protocol upgrades: chain specs, forks and network identity

How a QRDX network defines its consensus rules, changes them after launch, and keeps nodes
on different rules apart. Code: `qrdx/chain_spec.py`; startup checks in `qrdx/node/main.py`
(`_verify_chain_identity`); genesis in `qrdx/validator/genesis.py` and `genesis_init.py`.

Status (2026-10-09): implemented and tested, including signing-domain separation (§7) and
on-chain fork approval (§4a, docs/GOVERNANCE.md).

Verified (2026-10-09):

- the unit suite passes (2924 tests);
- the 4-node integration suite passes, 23/23 scenarios, including governance (S22);
- the live upgrade rehearsal passes (`integration_tests/upgrade_rehearsal.py`):
  - The `randao` fork was scheduled at height 50.
  - The validators approved it on chain at block 16, inside its deadline of 45. The stale node
    recorded the same approval.
  - The three upgraded nodes switched at 50 and agreed on every block hash from 47 to 75.
  - The stale node, whose spec lacks the fork, stopped at 49. Both sides refused each other:
    "peer is behind and does not schedule the fork at height 50" and "incompatible fork
    history".

Still open:

- **Stake-weighted readiness signalling** does not exist yet; readiness is counted per peer.
  On-chain approval is the binding stake signal.

See [What is not done](#what-is-not-done).

---

## 1. Why this exists

Before this work every consensus rule was a module-level boolean or an environment variable,
with no activation height. Every node replays the whole chain under its *current* code on
restart (`derived_state_rebuild.py`). So any rule change shipped after launch would have
rewritten history on the nodes that upgraded, and split them from the ones that had not.
Testnets hid this because they reset.

The design follows Ethereum (chain config with fork heights, EIP-2124 fork ids) and Solana
(rules gated in code, activated at a point every node agrees on):

| Need | Mechanism |
|---|---|
| One definition of the network | the **chain spec**, inside the genesis file |
| Nodes with different parameters can't share a chain | genesis commits to the spec |
| A rule changes without re-judging history | rules switch on at a **fork height**; each block is judged under the rules of its own height |
| Nodes that missed an upgrade are cut off, not silently forked | peers compare **fork ids** |
| An upgrade takes effect only if the validators agree | a fork activates only after an on-chain **approval** by 2/3 of stake, with a holder veto window (§4a) |
| An operator can't drift one node's consensus | on a real network the environment can't change the spec |
| Transactions and consensus signatures can't be replayed across networks | the chain id comes from the spec and binds every EVM and exchange transaction; blocks, attestations and RANDAO reveals are signed under a per-network domain |

## 2. The chain spec

The `chain_spec` section of a network's genesis file:

```json
{
  "format": 1,
  "network": "qrdx-testnet",
  "chain_id": 7620,
  "dev": false,
  "params":   { "SLOT_DURATION": 2, "SLOTS_PER_EPOCH": 32, "...": "every parameter" },
  "features": [],
  "forks": [
    { "name": "randao", "height": 120000, "features": ["randao_selection"] }
  ]
}
```

- **`params`** lists every network parameter (`chain_spec.PARAMS`) explicitly. A missing or
  unknown parameter is an error, because a later release changing a default must not change a
  running chain. The parameters are the ones networks have always varied: slot length, epoch
  length, minimum validators, staking delays, oracle reporters and the perps settings, and the
  exchange gas floor.
- **`features`** lists rules active from genesis.
- **`forks`** is the upgrade schedule. It is append-only, heights strictly increase, and each
  feature is switched on exactly once.
- **`dev`** marks a development network (see §6).

Validation is strict (`ChainSpec.from_dict`). Anything this release does not understand is
refused, never ignored. That covers unknown keys, unknown parameters and unknown features. An
unknown feature means the spec schedules a rule this software cannot execute, so the node
refuses to start and the operator learns to upgrade now, not at the fork height.

**Where a node finds it:**

1. `QRDX_GENESIS_FILE`, if set. The file must exist.
2. Otherwise `genesis_config.json` two directories above the database, the existing testnet
   layout.
3. Otherwise the node runs a **dev network**, whose spec is built from the environment
   (`chain_spec.dev_spec`).

A genesis file that exists but can't be used is fatal. No fallback genesis exists any more.

`qrdx.constants` loads the spec at import. Every existing `from ..constants import
SLOTS_PER_EPOCH` keeps working and now reads the spec's value.

## 3. What genesis commits to, and what a node refuses

The genesis state root (`GenesisCreator._compute_state_root`, prefix `QRDX_GENESIS_STATE_V2`)
commits to:

- the chain spec minus its fork schedule (`ChainSpec.genesis_hash()`);
- the chain id and network name;
- every allocation: prefunded accounts, validators and their stakes, and system wallets and
  their controller;
- the genesis time and total supply.

Amounts are committed as integer wei, so `"1000"` and `"1000.0"` are the same allocation. The
genesis RANDAO seed is derived, no longer random per node.

V1 left the prefunded accounts out of the root. Two genesis files funding different accounts
produced the same genesis block.

**At startup a node refuses to start if:**

- A consensus environment variable conflicts with a non-dev spec (§6).
- Genesis can't be built exactly as the file describes. The node recomputes the genesis and
  it must equal the file's `block.block_hash`, so an edited file is refused.
- The database's genesis block records a different spec hash, or none. A database from before
  chain specs is refused, because its parameters are unknowable.
- The network appears in `chain_spec.PINNED_NETWORKS` and the database holds a different
  genesis block.
- A fork that had passed at the node's previous start has changed or been removed, or a fork
  is scheduled at or below the height the chain had then reached. Both would re-judge blocks
  already applied. The record is `chain_metadata.passed_forks`.

## 4. Writing a rule change

1. Add a feature to `chain_spec.FEATURES` with a one-line description.
2. Gate the new behaviour on `chain_spec.is_active("<feature>", height)`. Pass the height of
   **the block being applied**:
   - a proposer uses its tip + 1;
   - an importer uses the block's own signed `number`;
   - replay and rebuild use the loop's height.
   
   Never pass the tip, a wall clock, or a cached "current" value. `is_active` refuses `None`,
   and an unknown feature name raises instead of reading as "off".
3. Features are monotonic. To replace a rule, add a successor feature and branch on it
   first: `if is_active("x_v2", h): … elif is_active("x", h): … else: …`.
4. Prove it: a test that the old behaviour holds at `H-1` and the new one from `H`
   (`tests/test_protocol_upgrade_activation.py` is the template). If the rule changes
   state, also add a forward-vs-rebuild equivalence chain that crosses `H`.
5. Schedule it in each network's spec (§8), then have it approved on chain (§4a).

Parameters can't change at a fork yet. A fork may only change a parameter marked
`height_aware`, meaning every consumer reads it through `ChainSpec.param_at(name, height)`.
None is marked yet, so the validator rejects any fork that sets `params`. To make a parameter
adjustable, route all its readers through `param_at`, then mark it.

## 4a. On-chain approval

A scheduled fork doesn't activate just because a release lists it. On every real network, a
fork's features come into force only if:

1. validators approved **that exact fork definition** through governance (an `approve_fork`
   proposal: 2/3 of stake, then the timelock in which holders can veto; docs/GOVERNANCE.md §4);
2. the approval executed at least `GOV_FORK_APPROVAL_LEAD_BLOCKS` before the fork's height.
   That is deeper than any permitted reorg, so whether it activates can't flip.

Otherwise the fork stays **dormant on every node**, deterministically. That is how the network
itself, not a website or a repository, verifies that an upgrade is wanted. A release that
slips an unwanted fork into a spec can't switch anything on without stake approval.

`chain_spec.is_active(feature, height)` applies this. `ChainSpec.is_scheduled` is the
schedule alone. Approvals are read from the governance state in the live exchange state, which
is replayed on every path, so a rebuild or a resync reaches the same answer.

Only a dev spec may mark a fork `"approval": "none"`.

**The first scheduled rule** is `randao_selection`, RANDAO proposer selection. Proposer
eligibility (`validator/block_verification.py`, `validator/manager.py`) asks
`randao.randao_selection_active(height)`. The old `QRDX_ENFORCE_RANDAO` switch survives only
as a dev-network override.

## 5. Peers: fork ids (EIP-2124)

A node advertises its identity in the handshake challenge, the handshake response and
`p2p_getStatus` (`chain_spec.network_identity`):

- network name, chain id and genesis block hash;
- `fork_hash`: the hash of the genesis plus every fork it has passed;
- `fork_next`: the next scheduled fork height, or 0;
- its software version and the features its software can execute.

A peer is accepted only if `check_peer_compatibility` passes. That means the same genesis and
chain id, and a fork history consistent with ours under Ethereum's EIP-2124 rules:

| Peer's fork hash is… | Verdict |
|---|---|
| ours | compatible, unless it announces a next fork at a height we already passed without it |
| one of our earlier hashes (it is behind) | compatible only if it announces the fork we passed next |
| one of our later hashes (we are behind) | compatible |
| anything else | incompatible |

A peer that advertises no identity is incompatible. The check runs before a peer is stored,
in both handshakes, and again on every status check, follow-up sync and pull sync. An
incompatible peer is dropped (`qrdx_peer_identity_rejections_total`).

The effect on an upgrade: before a fork, upgraded and non-upgraded nodes still peer. From the
fork height, a node that missed the upgrade is disconnected by everyone, instead of following
a chain only it believes in.

Implicit peer discovery through signed REST requests now also requires the caller's signed
`x-denaro-genesis` header to name our genesis block.

## 6. Parameters and the environment

| Network | Parameters come from | Environment overrides |
|---|---|---|
| dev (no genesis file, or `"dev": true`) | the environment, falling back to historical defaults | honoured, the historical behaviour |
| any other | the spec only | **startup error** if set to a different value |

The environment check (`chain_spec.environment_conflicts`) covers:

- every parameter's variable (`QRDX_SLOT_DURATION`, `QRDX_WITHDRAWAL_DELAY_EPOCHS`, …), plus
  `QRDX_CHAIN_ID` and `QRDX_NETWORK_NAME`;
- the development A/B switches in `CONSENSUS_ENV_SWITCHES` (`QRDX_ENFORCE_RANDAO`,
  `QRDX_ENFORCE_FAILED_TX_COSTS`, `QRDX_ENFORCE_PARENT_CONTINUITY`,
  `QRDX_ENFORCE_FORK_CHOICE_RECONCILE`, `QRDX_ED4_ENFORCE_SYNC`,
  `QRDX_ENFORCE_VALIDATOR_WITHDRAWALS`). Setting any of these to a non-empty value on a
  non-dev network is an error.

A value equal to the spec's is allowed.

Genesis tooling writes parameters into the spec: `integration_tests/genesis_generator.py`,
`docker/testnet-init.py` and `docker/genesis-init.py`. The integration harness strips these
variables from the environment its nodes inherit.

## 7. Chain id, signing domains and replay protection

`constants.CHAIN_ID` is the spec's chain id. It is what `eth_chainId` returns, what the EVM's
`CHAINID` opcode sees, and what every EVM transaction must be signed for.
`contracts/evm_mempool._require_chain_id` refuses:

- legacy transactions without EIP-155 protection;
- EIP-155 or type-0x51 PQ transactions signed for any other chain id.

The check is in the shared parser, so mempool admission, execution and block import all
apply it.

Previously the chain id was parsed and never compared. A transaction signed for any chain,
or none, executed once its nonce lined up.

**Exchange transactions** carry a `chain_id` field. It is signed (part of the signing bytes and
the transaction hash, after the tag `QRDX-EXCHANGE-TX-v1`) and checked by
`block_processor.verify_exchange_tx` against the node's chain id. A transaction without one is
unbound and never verifies. Clients sign for the network they submit to:

- the CLI asks the node (`p2p_getStatus`);
- `exchange_getSigningPayload` fills it in.

**Node signatures.** Block headers, attestations and RANDAO reveals are signed over a root that
starts with `chain_spec.signing_domain(purpose)`. That is a hash of the purpose, the chain id
and the chain spec's genesis hash. There is one definition each: `reconstruct_signing_root`,
`Attestation.signing_root` and `randao.randao_reveal_message`.

A header or attestation signed on another network therefore fails verification here,
including as DOUBLE_SIGN or surround-vote evidence. Without the domain, a validator using one
key on a testnet and on mainnet could be slashed on mainnet with its testnet signatures.
Scheduling a fork does not change the domain, so signatures stay valid across an upgrade.
Tests: `tests/test_signing_domains.py`.

A non-dev spec can't use a chain id in `RESERVED_CHAIN_IDS`: Ethereum mainnet and testnets,
major L2s, local-dev conventions, and 88888, which belongs to Chiliz Chain. **QRDX's networks:** mainnet is chain id **762** (`qrdx-mainnet`) and the testnet **7620**
(`qrdx-testnet`). Both were unassigned in the public registries on 2026-10-09, and both still
need registering there (docs/KNOWN_ISSUES.md). Only those networks' non-dev specs may use these
ids, and a dev node refuses them, because a dev network on 762 would sign transactions valid
on mainnet. `create_mainnet_genesis` requires a non-dev spec on 762 / `qrdx-mainnet`.

## 8. Operator procedure: shipping an upgrade

1. **Release** software containing the gated code and the feature in `FEATURES`, plus the
   network's genesis file with the new fork appended: `{"name", "height", "features"}`.
   Choose the height far enough ahead for operators to upgrade and for the vote, its timelock
   and the approval lead to fit before it (on mainnet that is days of blocks). Sign the release
   (§8a).
2. **Operators upgrade** before the height. The node checks the new schedule at start: past
   forks unchanged, nothing inserted behind the chain.
3. **Approve it on chain.** A validator runs `qrdx-wallet gov propose-fork validator.json <fork>`.
   Validators vote, holders may veto during the timelock, and anyone executes it after the
   timelock. It must execute by the fork's `approve_by` height (shown in `/chain_spec` and
   `qrdx-wallet gov status`), or the fork stays dormant.
4. **Watch readiness.** `GET /chain_spec` (or `qrdx_chainSpec`) shows the next fork, the blocks
   until it, and `peers.ready_for_next_fork`. Prometheus exposes:
   - `qrdx_fork_next_height`
   - `qrdx_fork_blocks_until_next`
   - `qrdx_fork_ready_peers` and `qrdx_fork_reporting_peers`
   - `qrdx_forks_active`
   
   Alert when the fork is near and ready peers are below the validator set.
5. **Activation.** At the height every upgraded node applies the approved rule to that block
   and every later one. Nodes that did not upgrade fail the fork-id check and are disconnected.
6. **If the release is faulty before activation:** don't approve it, or let its approval be
   vetoed, and it stays dormant. Or ship a release that moves the fork's height further out
   (allowed while it has not passed); that changes its definition, so it needs a fresh
   approval. After activation the only remedy is a successor feature in a later fork. A passed
   fork can never be edited.
7. **Emergency (chain halted):** coordinate a halt height out of band, then restart everyone on
   the fixed release. The fork-id check keeps stragglers from rejoining on the old rules.

## 8a. Release integrity: how operators know a release is genuine

The network verifies *behaviour*: blocks under each node's rules, and fork activation through
on-chain approval. It never checks code at runtime, and nodes do not consult GitHub.

- **Outages.** A runtime dependency on a hosting site would let its outage stall the chain.
- **Compromise.** Whoever controls that account would effectively control the chain.
- **Easy to fake.** A modified node can simply report "verified" without checking.

The release itself is verified by the people who install it, before they install it. The
pipeline is described in full in [RELEASES.md](RELEASES.md):

1. **Signed tags and artifacts.** A release is a maintainer-signed tag plus a release
   manifest naming every artifact by hash. The manifest is signed twice:
   - by at least `maintainer_threshold` of the maintainers in `release/allowed_signers` (SSH
     keys);
   - by the release workflow's own Sigstore identity (keyless, recorded in the public Rekor
     log).

   The image carries a cosign signature, a signed SBOM and SLSA provenance. Operators run
   `scripts/release/verify-release.sh vX.Y.Z` and run images **by digest**, never by a
   mutable tag.
2. **Reproducible builds.** `scripts/release/build-image.sh` pins every input (base image
   digest, Debian snapshot, liboqs commit, hashed dependency locks, BuildKit version) and
   normalises time, modes and ownership. Two builds of a commit have the same image config
   digest. CI builds twice and compares, and every maintainer rebuilds before signing. Signers
   therefore vouch for source the community can read, not an opaque binary.
3. **Pinned identity.** The release pins the network's genesis hash (`PINNED_NETWORKS`) and
   ships its spec. A tampered genesis file or spec is refused, and an unapproved fork stays
   dormant whatever the file says.
4. **Review window.** The vote's timelock is when anyone, holders included, can inspect the
   release a fork comes from and veto it.

**Pinning a network.** Once a network's genesis is final, add `network name → genesis block
hash` to `chain_spec.PINNED_NETWORKS` in the release. A node then refuses a tampered or stale
genesis file for that network.

**Rehearsing an upgrade.** `python -m integration_tests.upgrade_rehearsal --fork-height 50`
runs the testnet with the `randao` fork scheduled at height 50. The last node runs a stale
copy of the genesis whose spec omits the fork. The validators approve the fork on chain
through governance (propose, three votes, the timelock, execute) before its approval deadline.
The script checks that:

- the approval landed in time, and the stale node recorded it too (identical state);
- every upgraded node switches at the fork height and they share one post-fork fork id;
- the upgraded chain keeps going and the nodes agree on every block hash across the fork;
- the upgraded nodes and the stale node refuse each other.

For a full scenario run across a fork, use
`QRDX_TESTNET_RANDAO_FORK_HEIGHT=N python -m integration_tests.run_scenarios`. The fork then
needs approving, like any other. `QRDX_ENFORCE_RANDAO=1` puts RANDAO in genesis instead. Both
are harness knobs, written into the genesis spec, never into a node's environment.

## 9. What changes for existing deployments

These are breaking changes by design. Every existing network must be **regenerated**:

- Genesis files from before this work have no `chain_spec`, so nodes refuse them.
- Databases created from them record no spec hash, so nodes refuse them too.
- Docker deployments that relied on `QRDX_CHAIN_ID` defaulting to `1` must set a real,
  unreserved chain id. The tunnel compose now requires it.
- Production compose requires the network's genesis file (`QRDX_GENESIS_FILE`).
- Clients that signed EVM transactions with chain id 1 (or none) must sign with the network's
  chain id. The wallet CLI already reads it from `eth_chainId`.
- Exchange transactions now carry a signed `chain_id`, and block, attestation and RANDAO
  signatures include the network domain. Exchange clients outside this codebase must add the
  field; `exchange_getSigningPayload` returns the exact bytes to sign.
- `qrdx/genesis_metadata.json` is no longer written. Genesis metadata now lives in the node's
  own `chain_metadata` table.

## What is not done

- **Stake-weighted readiness.** Readiness counts peers, not stake. Validators announcing the
  next fork in their blocks would give a Solana-style stake-weighted signal.
- **The passed-forks record** is written at startup. A fork that passes while the node runs is
  recorded at the next start. In between, tampering is caught by the network (fork ids) rather
  than locally.
- **The p2p RPC transport is unauthenticated.** The identity check keeps honest but
  misconfigured nodes apart. It does not stop a malicious peer from claiming an identity.
  Block validity remains the real defence (see docs/KNOWN_ISSUES.md).
