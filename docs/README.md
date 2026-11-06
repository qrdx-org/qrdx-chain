# QRDX documentation

The living documents, grouped by subject. The register of what is still wrong is
[KNOWN_ISSUES.md](KNOWN_ISSUES.md), and the road to mainnet is
[MAINNET_READINESS.md](MAINNET_READINESS.md). Superseded status reports from earlier phases
are kept in [archive/](archive/) for their history; none of them describes the code as it is.

## The protocol

- [QRDX-Whitepaper-v3.4.md](../QRDX-Whitepaper-v3.4.md): the protocol as built in node 3.0.0, what changed
  since v3.2, and the roadmap. (v3.2 and v2.3 are superseded.)
- [PQ_SMART_ACCOUNTS.md](PQ_SMART_ACCOUNTS.md): contract accounts owned by ML-DSA-65 keys,
  predeployed at genesis, and the TypeScript SDK ([sdk/typescript](../sdk/typescript/README.md)).
- [QUANTUM_MIGRATION.md](QUANTUM_MIGRATION.md): binding an ECDSA account's post-quantum
  successor, and the Doomsday Protocol (what changes once ECDSA is broken).
- [CHECKPOINT_SYNC.md](CHECKPOINT_SYNC.md): the validators' state in the root, joining from a verified
  snapshot, nodes publishing snapshots, and history pruning.

## Status

- [KNOWN_ISSUES.md](KNOWN_ISSUES.md): open defects, accepted limitations, and every fix with
  its cause.
- [MAINNET_READINESS.md](MAINNET_READINESS.md): the review of what stands between here and
  mainnet, and the work plan with its status.
- [CONSENSUS_REMAINING_WORK.md](CONSENSUS_REMAINING_WORK.md): the consensus layer's process gates.

## Consensus and the chain

- [STAKING.md](STAKING.md): validators, the per-epoch validator set, delegation pools, rewards.
- [VALIDATOR_KEYS.md](VALIDATOR_KEYS.md): keystores, slashing protection, the doppelganger
  check.
- [VALIDATOR_LIFECYCLE_UNIFICATION.md](VALIDATOR_LIFECYCLE_UNIFICATION.md): how the validator
  set evolves on chain.
- [FORK_CHOICE_CONVERGENCE.md](FORK_CHOICE_CONVERGENCE.md): fork choice and finality.
- [CONSENSUS_ROADMAP.md](CONSENSUS_ROADMAP.md): fair ordering, risk limits, oracle hardening,
  state proofs, attested chain heads.
- [BLOCK_LIMITS.md](BLOCK_LIMITS.md): what a block may carry, gas, base fees, the content
  structure budget.
- [PERFORMANCE.md](PERFORMANCE.md): throughput under load, what the profiles showed, and what
  limits it next.
- [NODE_LAYOUT.md](NODE_LAYOUT.md): which module of qrdx/node/ holds what, and why the node's
  state stays in main.py.
- [PQ_CRYPTO_BACKEND.md](PQ_CRYPTO_BACKEND.md): liboqs, OpenSSL and mldsa-native compared for
  ML-DSA-65, and the shadow verification that makes a switch safe.
- [EVM_CONFORMANCE.md](EVM_CONFORMANCE.md): Ethereum's state tests run through QRDX's EVM, and
  the `evm_conformance` fork they led to.
- [WEAK_SUBJECTIVITY.md](WEAK_SUBJECTIVITY.md): trusted checkpoints.
- [STATE_PROOFS.md](STATE_PROOFS.md): proving one entry against a signed root.
- [PROTOCOL_UPGRADES.md](PROTOCOL_UPGRADES.md): chain specs, forks, network identity.
- [GOVERNANCE.md](GOVERNANCE.md): on-chain governance.
- [BOOTSTRAP_AND_GENESIS.md](BOOTSTRAP_AND_GENESIS.md): bootstrapping a node and genesis.
- [block.md](block.md), [transaction.md](transaction.md): wire formats.

## Accounts and tokens

- [UNIFIED_ACCOUNT_IDENTITY.md](UNIFIED_ACCOUNT_IDENTITY.md): `0x` and `0xPQ` accounts, and the
  0x51 post-quantum transaction.
- [ACCOUNT_CONTROL.md](ACCOUNT_CONTROL.md): bound wallets, multisig, recovery, agents.
- [NATIVE_TOKENS.md](NATIVE_TOKENS.md): the native token standard and NFTs.
- [QNS.md](QNS.md): the name service.
- [TOKENOMICS.md](TOKENOMICS.md): supply, flows, the free trading lane.

## The exchange

- [PERPS_CLEARINGHOUSE.md](PERPS_CLEARINGHOUSE.md): perpetuals.
- [UNIFIED_SPOT_LIQUIDITY.md](UNIFIED_SPOT_LIQUIDITY.md): one market per pair, book and pools.
- [TRADING_FEATURES.md](TRADING_FEATURES.md): order types, triggers, TWAP, agents, vaults, fees.
- [HYPERLIQUID_PARITY.md](HYPERLIQUID_PARITY.md): the features added to match Hyperliquid.
- [PERPS_API.md](PERPS_API.md): the API for wallets and apps.
- [EXCHANGE_AUDIT.md](EXCHANGE_AUDIT.md),
  [EXCHANGE_AND_VALIDATOR_STAKE_AUDIT.md](EXCHANGE_AND_VALIDATOR_STAKE_AUDIT.md): internal
  audits.
- [EXCHANGE_PRODUCTION_READINESS.md](EXCHANGE_PRODUCTION_READINESS.md): the exchange's work
  breakdown.

## The bridge

- [BRIDGE.md](BRIDGE.md): deposits, withdrawals, refunds, guardrails, chain heads, the lockbox,
  and the runbook for deploying it.

## Operating

- [RELEASES.md](RELEASES.md): signed, reproducible releases.
- [BLOCK_EXPLORER_API.md](BLOCK_EXPLORER_API.md),
  [BLOCK_EXPLORER_QUICKREF.md](BLOCK_EXPLORER_QUICKREF.md): the explorer API.

## Proposals

- [QRDX_PROGRAM_LIBRARY_PROPOSAL.md](QRDX_PROGRAM_LIBRARY_PROPOSAL.md).
