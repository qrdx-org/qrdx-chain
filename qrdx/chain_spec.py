"""
The QRDX chain specification: a network's identity, its consensus parameters, and its upgrade
schedule. Design and operator procedure: docs/PROTOCOL_UPGRADES.md.

A chain spec is the ``chain_spec`` section of a network's genesis file::

    {
      "format": 1,
      "network": "qrdx-testnet",
      "chain_id": 7620,
      "dev": false,
      "params":   {"SLOT_DURATION_MS": 2000, "SLOTS_PER_EPOCH": 32, ...every network parameter...},
      "features": ["..."],                       # rules active from genesis
      "forks": [                                 # the upgrade schedule, append-only
        {"name": "fork1", "height": 120000, "features": ["randao_selection"]}
      ]
    }

Three properties make upgrades safe:

* **Genesis commits to the spec.** Everything except ``forks`` is hashed (``genesis_hash``) into
  the genesis state root, so two nodes holding different parameters cannot share a genesis
  block, and a node refuses to start on a database created under a different spec.
* **Rules switch on at block heights.** Code asks ``is_active(feature, height)`` with the height
  of the block being applied. Replay, sync and the restart rebuild therefore apply each block
  under the rules of its own height — history is never re-judged under rules that did not exist
  when it was written.
* **Peers compare fork ids** (``fork_id`` / ``check_peer_compatibility``), Ethereum's EIP-2124
  scheme: a peer is accepted only if its spec agrees with ours on every fork either side has
  already passed. A node that missed an upgrade is disconnected at the fork height instead of
  silently following a different chain.

Two classes of network: ``dev`` networks (and a node with no genesis file, which runs the
built-in dev spec) take parameters and A/B switches from the environment, as the codebase
always has. Every other network takes them ONLY from its spec; an environment override is a
startup error (``environment_conflicts``), because a single node quietly running different
consensus parameters forks itself off the network.

This module is pure — it imports nothing from ``qrdx`` — because ``qrdx.constants`` loads the
process's spec at import time.
"""

from __future__ import annotations

import contextlib
import copy
import functools
import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "SPEC_FORMAT",
    "PARAMS",
    "FEATURES",
    "GENESIS_DEFAULT_FEATURES",
    "CONSENSUS_ENV_SWITCHES",
    "RESERVED_CHAIN_IDS",
    "ChainSpecError",
    "ChainSpec",
    "ForkId",
    "dev_spec",
    "load_genesis_file",
    "resolve_genesis_file",
    "load_process_spec",
    "active",
    "set_active",
    "use_spec",
    "is_active",
    "check_peer_compatibility",
    "network_identity",
    "report",
    "params_from_environment",
    "SIGNING_PURPOSES",
    "signing_domain",
    "set_approval_lookup",
    "fork_approval",
    "active_features",
    "MAINNET_CHAIN_ID",
    "TESTNET_CHAIN_ID",
]

SPEC_FORMAT = 1

_GENESIS_HASH_TAG = b"QRDX-CHAIN-SPEC-v1\x00"
_FORK_ID_TAG = b"QRDX-FORK-ID-v1\x00"
_FORK_HASH_BYTES = 16  # fork ids are peer filters, not commitments; 128 bits is ample


class ChainSpecError(ValueError):
    """A chain spec is malformed, inconsistent, or cannot be followed by this node."""


# ─────────────────────────────────────────────────────────────────────────────
#  Network parameters
# ─────────────────────────────────────────────────────────────────────────────


def _parse_int(raw: str) -> int:
    return int(raw)


def _parse_str(raw: str) -> str:
    return raw.strip()


def _parse_list(raw: str) -> List[str]:
    return [a.strip() for a in raw.split(",") if a.strip()]


@dataclass(frozen=True)
class Param:
    """One network parameter: its type, its dev default, and the environment variable a dev
    network may set it from. ``height_aware`` marks a parameter whose every consumer reads it
    through ``ChainSpec.param_at(name, height)``; only such a parameter may be changed by a fork
    (a fork changing one read as a module constant would be silently ignored by that code)."""

    kind: str  # "int" | "str" | "list"
    default: Any
    env: str
    minimum: Optional[int] = None
    height_aware: bool = False
    empty_env_is_default: bool = False


# Every parameter a network may choose. A spec must list exactly these (no implicit defaults on
# a real network: a later release changing a default must not change a running chain).
# The dev defaults reproduce the values qrdx/constants.py used before the chain spec existed.
PARAMS: Dict[str, Param] = {
    # Slot clock and epoch length (all nodes MUST agree: epochs drive finality and the
    # validator lifecycle). The slot is in milliseconds; block timestamps stay in whole seconds,
    # and consecutive blocks may share one. The standard is 250 ms slots and 32-slot (8 s)
    # epochs. Parameters below counted in blocks or epochs are sized for that; a spec with
    # another slot or epoch length must scale them to keep their wall-clock meaning.
    "SLOT_DURATION_MS": Param("int", 250, "QRDX_SLOT_DURATION_MS", minimum=100),
    "SLOTS_PER_EPOCH": Param("int", 32, "QRDX_SLOTS_PER_EPOCH", minimum=1),
    "MIN_VALIDATORS": Param("int", 4, "QRDX_MIN_VALIDATORS", minimum=1),
    # The most validators that propose and vote at once (qrdx/validator/epoch_state.py); more
    # wait to activate until one leaves. Every validator's vote is a 3.3 KB signature each epoch
    # that every node verifies and stores, and a block carries at most 128.
    "MAX_VALIDATORS": Param("int", 150, "QRDX_MAX_VALIDATORS", minimum=4),
    # Staking lifecycle.
    # Unbonding ~3.7 days. Activation waits a number of epochs (a finality depth, not a
    # duration). The withdrawal delay, the window for carrying evidence of an offence before
    # the principal leaves, is ~4.6 hours.
    "UNBONDING_PERIOD_EPOCHS": Param("int", 40_320, "QRDX_UNBONDING_PERIOD_EPOCHS", minimum=0),
    "ACTIVATION_DELAY_EPOCHS": Param("int", 4, "QRDX_ACTIVATION_DELAY_EPOCHS", minimum=0),
    "WITHDRAWAL_DELAY_EPOCHS": Param("int", 2_048, "QRDX_WITHDRAWAL_DELAY_EPOCHS", minimum=0),
    # Staking rewards (docs/STAKING.md): QRDX minted per year, in basis points of the stake that
    # earns it (a validator's principal and the QRDX delegated to it), paid each epoch to the
    # validators whose vote the chain carried. 500 = 5 % a year.
    "STAKING_REWARD_RATE_BPS": Param("int", 500, "QRDX_STAKING_REWARD_RATE_BPS", minimum=0),
    # Block resource limits (docs/BLOCK_LIMITS.md). Every node executes every block, so what a
    # block may carry is bounded by what a node can execute within the slot clock. Gas is the
    # sum of the transactions' declared gas limits, checked before anything runs.
    # The EVM's: py-evm runs its cheapest instructions at ~1.9 Mgas/s (measured), so a block of
    # them takes ~0.5 s — two 250 ms slots — while 1,000,000 still fits a token contract's
    # deployment. The exchange's: its operations run ~200x faster per unit of gas; 20,000,000
    # is ~500 orders, ~40 ms of execution.
    "BLOCK_GAS_LIMIT": Param("int", 1_000_000, "QRDX_BLOCK_GAS_LIMIT", minimum=21_000),
    "BLOCK_EXCHANGE_GAS_LIMIT": Param(
        "int", 20_000_000, "QRDX_BLOCK_EXCHANGE_GAS_LIMIT", minimum=1_000_000
    ),
    # Exchange / perps.
    "ORACLE_REPORTERS": Param("list", [], "QRDX_ORACLE_REPORTERS"),
    "PERP_VAULT_LOCKUP_SECONDS": Param(
        "int", 4 * 24 * 3600, "QRDX_PERP_VAULT_LOCKUP_SECONDS", minimum=0
    ),
    "PERP_VAULT_SEEDERS": Param("list", [], "QRDX_PERP_VAULT_SEEDERS"),
    "PERP_COLLATERAL_TOKEN": Param("str", "", "QRDX_PERP_COLLATERAL_TOKEN"),
    # Tokens accepted as perps margin beside the settlement token (portfolio margin,
    # docs/TRADING_FEATURES.md): TOKEN:MARKET_ID:HAIRCUT — valued at that perp market's oracle
    # price less the haircut (0.2 = counted at 80 %). Empty: none.
    "PERP_PORTFOLIO_ASSETS": Param("list", [], "QRDX_PERP_PORTFOLIO_ASSETS"),
    "PERP_QUOTE": Param("str", "USD", "QRDX_PERP_QUOTE", empty_env_is_default=True),
    "PERP_ORACLE_VOTE_MAX_AGE": Param("int", 60, "QRDX_PERP_ORACLE_VOTE_MAX_AGE", minimum=1),
    "PERP_ORACLE_STALE_SECONDS": Param("int", 300, "QRDX_PERP_ORACLE_STALE_SECONDS", minimum=1),
    "PERP_FUNDING_INTERVAL_SECONDS": Param(
        "int", 3600, "QRDX_PERP_FUNDING_INTERVAL_SECONDS", minimum=1
    ),
    # QRDX burned to list a perp market: every market costs every node work in every block.
    "PERP_MARKET_LISTING_FEE": Param("int", 1_000, "QRDX_PERP_MARKET_LISTING_FEE", minimum=0),
    # Liquidity a perp market's creator puts into the market's liquidity vault (the settlement
    # unit), which the protocol quotes on its book; locked this long (docs/TRADING_FEATURES.md).
    "PERP_MARKET_MIN_LIQUIDITY": Param("int", 10_000, "QRDX_PERP_MARKET_MIN_LIQUIDITY", minimum=0),
    # The share of the protocol's QRDX fee income that goes to validators and delegators
    # (docs/CONSENSUS_ROADMAP.md 6), in basis points; distributed each epoch like rewards.
    "STAKER_FEE_SHARE_BPS": Param("int", 2000, "QRDX_STAKER_FEE_SHARE_BPS", minimum=0),
    # Oracle hardening (docs/CONSENSUS_ROADMAP.md 5). A price applies only with this many fresh
    # votes (or the whole committee, if smaller) as well as a stake majority; it moves at most
    # ORACLE_MAX_STEP_BPS a second of block time since the last; votes further than
    # ORACLE_OUTLIER_BAND_BPS from the applied median are counted against their validator.
    # Basis points; 0 turns the bound or the record off.
    "ORACLE_MIN_VOTERS": Param("int", 3, "QRDX_ORACLE_MIN_VOTERS", minimum=1),
    "ORACLE_MAX_STEP_BPS": Param("int", 500, "QRDX_ORACLE_MAX_STEP_BPS", minimum=0),
    "ORACLE_OUTLIER_BAND_BPS": Param("int", 200, "QRDX_ORACLE_OUTLIER_BAND_BPS", minimum=0),
    # Perp order grid (docs/HYPERLIQUID_PARITY.md): a non-reduce-only order is worth at least
    # PERP_MIN_ORDER_VALUE (0: no minimum); a market lists sizes in PERP_DEFAULT_SZ_DECIMALS
    # decimals unless CREATE_MARKET says otherwise (-1: no grid).
    "PERP_MIN_ORDER_VALUE": Param("int", 10, "QRDX_PERP_MIN_ORDER_VALUE", minimum=0),
    "PERP_DEFAULT_SZ_DECIMALS": Param("int", 4, "QRDX_PERP_DEFAULT_SZ_DECIMALS", minimum=-1),
    # Perp risk limits (docs/CONSENSUS_ROADMAP.md 3), in basis points; 0 turns one off. An order
    # more than the band worse than the oracle is refused; the mark moving the breaker's move
    # within its window holds the market to reduce-only orders for the cooldown.
    "PERP_PRICE_BAND_BPS": Param("int", 2000, "QRDX_PERP_PRICE_BAND_BPS", minimum=0),
    "PERP_BREAKER_MOVE_BPS": Param("int", 1000, "QRDX_PERP_BREAKER_MOVE_BPS", minimum=0),
    "PERP_BREAKER_WINDOW_SECONDS": Param("int", 300, "QRDX_PERP_BREAKER_WINDOW_SECONDS", minimum=1),
    "PERP_BREAKER_COOLDOWN_SECONDS": Param(
        "int", 60, "QRDX_PERP_BREAKER_COOLDOWN_SECONDS", minimum=1
    ),
    # A perp market's open-interest floor (notional): its cap is the larger of this and its
    # liquidity vault's equity × OI_CAP_MULTIPLE; 0 with no vault: uncapped.
    "PERP_MIN_OI_CAP": Param("int", 0, "QRDX_PERP_MIN_OI_CAP", minimum=0),
    # Deployer markets (docs/HYPERLIQUID_PARITY.md): the QRDX bond a deployer keeps while it has
    # markets (slashable by governance, unbonding over DEPLOYER_UNBOND_SECONDS — longer than a
    # proposal's voting period and timelock), its markets at most, the largest share of their
    # protocol fees it may take (basis points), and how far its oracle may move a second.
    "DEPLOYER_MIN_BOND": Param("int", 100_000, "QRDX_DEPLOYER_MIN_BOND", minimum=0),
    "DEPLOYER_UNBOND_SECONDS": Param(
        "int", 14 * 24 * 3600, "QRDX_DEPLOYER_UNBOND_SECONDS", minimum=0
    ),
    "DEPLOYER_MAX_MARKETS": Param("int", 10, "QRDX_DEPLOYER_MAX_MARKETS", minimum=0),
    "DEPLOYER_MAX_FEE_SHARE_BPS": Param("int", 5_000, "QRDX_DEPLOYER_MAX_FEE_SHARE_BPS", minimum=0),
    "DEPLOYER_ORACLE_MAX_STEP_BPS": Param(
        "int", 100, "QRDX_DEPLOYER_ORACLE_MAX_STEP_BPS", minimum=0
    ),
    # QNS (docs/QNS.md): QRDX a name costs a year, paid to the treasury.
    "QNS_PRICE_PER_YEAR": Param("int", 10, "QRDX_QNS_PRICE_PER_YEAR", minimum=0),
    "PERP_MARKET_LIQUIDITY_LOCKUP_SECONDS": Param(
        "int", 30 * 24 * 3600, "QRDX_PERP_MARKET_LIQUIDITY_LOCKUP_SECONDS", minimum=0
    ),
    # Tokens the consensus bridge carries (docs/BRIDGE.md): SYMBOL:CHAIN_ID:SOURCE_TOKEN:DECIMALS.
    "BRIDGE_ASSETS": Param("list", [], "QRDX_BRIDGE_ASSETS"),
    "EXCHANGE_MIN_GAS_PRICE_WEI": Param("int", 10**9, "QRDX_EXCHANGE_MIN_GAS_PRICE_WEI", minimum=0),
    # The EVM's floor under its base fee (qrdx/fee_market.py): EVM gas had no price floor at all
    # (a gas price of 0 executed for free).
    "EVM_MIN_GAS_PRICE_WEI": Param("int", 10**9, "QRDX_EVM_MIN_GAS_PRICE_WEI", minimum=0),
    # On-chain governance (qrdx/exchange/governance.py, docs/GOVERNANCE.md). Block counts, not
    # wall time: every node judges a deadline by the height of the block being applied.
    # At 250 ms slots (345,600 blocks a day): 7 days of voting, a 2-day timelock (the holders'
    # veto window), 7 days to execute a passed proposal.
    "GOV_VOTING_PERIOD_BLOCKS": Param("int", 2_419_200, "QRDX_GOV_VOTING_PERIOD_BLOCKS", minimum=1),
    "GOV_TIMELOCK_BLOCKS": Param("int", 691_200, "QRDX_GOV_TIMELOCK_BLOCKS", minimum=1),
    "GOV_EXECUTION_WINDOW_BLOCKS": Param(
        "int", 2_419_200, "QRDX_GOV_EXECUTION_WINDOW_BLOCKS", minimum=1
    ),
    # Share of the validator committee's stake (basis points) a proposal needs: 2/3, as finality.
    "GOV_APPROVAL_THRESHOLD_BPS": Param(
        "int", 6_667, "QRDX_GOV_APPROVAL_THRESHOLD_BPS", minimum=5_001
    ),
    # QRDX that holders must lock in vetoes to stop a passed proposal (10% of genesis supply).
    "GOV_VETO_THRESHOLD_QRDX": Param("int", 10_000_000, "QRDX_GOV_VETO_THRESHOLD_QRDX", minimum=1),
    # A fork activates only if its approval executed at least this many blocks before its
    # height — deeper than any permitted reorg, so no reorg can flip whether it activates. A
    # depth, not a duration: fork resolution searches 256 blocks back, finality ~3 epochs.
    "GOV_FORK_APPROVAL_LEAD_BLOCKS": Param(
        "int", 256, "QRDX_GOV_FORK_APPROVAL_LEAD_BLOCKS", minimum=1
    ),
    # From this height (~2.3 days at 250 ms) the genesis master controller can no longer move
    # system-wallet funds; only executed governance proposals can (validators may also freeze it
    # earlier).
    "SYSTEM_WALLET_MASTER_SUNSET_HEIGHT": Param(
        "int", 800_000, "QRDX_SYSTEM_WALLET_MASTER_SUNSET_HEIGHT", minimum=1
    ),
}

_PARSERS: Dict[str, Callable[[str], Any]] = {
    "int": _parse_int,
    "str": _parse_str,
    "list": _parse_list,
}


# ─────────────────────────────────────────────────────────────────────────────
#  Features — the consensus rules a fork can switch on
# ─────────────────────────────────────────────────────────────────────────────

# Every rule this release can execute. A spec naming a feature that is not here is refused at
# startup: this node could not follow the chain past that fork, and running anyway would fork it
# off at the activation height. Adding a rule = add it here, gate its code on
# ``is_active(name, height)``, then schedule it in a spec. Features are monotonic: once active
# they stay active. To replace a rule, add a successor feature and branch on it first.
FEATURES: Dict[str, str] = {
    "randao_selection": (
        "Proposer eligibility follows the RANDAO mix of the block's slot "
        "(qrdx/validator/randao.py) instead of the fixed stake-weighted schedule."
    ),
    "incremental_state_root": (
        "Each state-root domain commits to its state by an LtHash accumulator updated per "
        "change (qrdx/state_commitment.py, qrdx/exchange/commitment.py) instead of a hash over "
        "every entry in order: a root costs O(changes) rather than O(state)."
    ),
    "fair_ordering": (
        "A block's exchange transactions run cancels first, then post-only orders, then the "
        "rest, each nonce lane in nonce order (qrdx/exchange/fair_ordering.py): a proposer "
        "cannot trade ahead of a maker's cancel."
    ),
    "provable_state": (
        "The unified state root also commits to a sparse Merkle tree over the accounts, "
        "contract storage and token balances (qrdx/state_proofs.py), so one entry can be proven "
        "against a block's signed root — by a light client, a bridge, or a contract (the state "
        "proof precompile)."
    ),
}

# The rules a network created by this release has from genesis unless its spec says otherwise
# (dev networks, and specs assembled by ``build_spec`` without an explicit feature list).
GENESIS_DEFAULT_FEATURES: Tuple[str, ...] = (
    "incremental_state_root",
    "provable_state",
    "fair_ordering",
)


# ─────────────────────────────────────────────────────────────────────────────
#  Consensus A/B switches that only a dev network may set from the environment
# ─────────────────────────────────────────────────────────────────────────────

# Development switches read from the environment by consensus code. Each changes what a node
# accepts or how it applies a block, so on a real network the chain spec alone decides it:
# setting any of these (to a non-empty value) on a non-dev network is a startup error.
CONSENSUS_ENV_SWITCHES: Tuple[str, ...] = (
    "QRDX_ENFORCE_RANDAO",
    "QRDX_ENFORCE_FAILED_TX_COSTS",
    "QRDX_ENFORCE_PARENT_CONTINUITY",
    "QRDX_ENFORCE_FORK_CHOICE_RECONCILE",
    "QRDX_ED4_ENFORCE_SYNC",
    "QRDX_ENFORCE_VALIDATOR_WITHDRAWALS",
)

# Chain ids a non-dev network may not use: a signed transaction is bound to its chain id
# (EIP-155 and the type-0x51 PQ envelope), so sharing one with another EVM network makes every
# key used on both networks replayable across them. Not exhaustive — a production network must
# register its own id in the public chain registry — but it blocks the defaults this codebase
# used to ship (1 is Ethereum mainnet; 88888 is assigned to Chiliz Chain).
RESERVED_CHAIN_IDS: Dict[int, str] = {
    1: "Ethereum mainnet",
    5: "Goerli",
    10: "OP Mainnet",
    56: "BNB Smart Chain",
    100: "Gnosis",
    137: "Polygon PoS",
    250: "Fantom",
    1337: "local development",
    8453: "Base",
    17000: "Holesky",
    31337: "Hardhat",
    42161: "Arbitrum One",
    43114: "Avalanche C-Chain",
    88888: "Chiliz Chain",
    11155111: "Sepolia",
}

DEV_CHAIN_ID = 88888  # the id every dev node has always reported
DEV_NETWORK_NAME = "qrdx-dev"

# QRDX's own public networks (both unassigned in the public chain registries, checked
# 2026-10-09). Only these networks' specs may use these ids: a dev network on 762 would make
# every transaction signed on a developer's node valid on mainnet, so dev_spec refuses them, and
# a spec claiming one must carry that network's name.
MAINNET_CHAIN_ID = 762
MAINNET_NETWORK_NAME = "qrdx-mainnet"
TESTNET_CHAIN_ID = 7620
TESTNET_NETWORK_NAME = "qrdx-testnet"
QRDX_NETWORKS: Dict[int, str] = {
    MAINNET_CHAIN_ID: MAINNET_NETWORK_NAME,
    TESTNET_CHAIN_ID: TESTNET_NETWORK_NAME,
}

# Published networks pinned by this release: network name -> genesis block hash. A node whose
# spec names one of these networks must hold exactly that genesis block, so a tampered or stale
# genesis file cannot impersonate the network. Filled in when a network's genesis is final
# (release procedure: docs/PROTOCOL_UPGRADES.md).
PINNED_NETWORKS: Dict[str, str] = {}

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_NETWORK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SPEC_KEYS = {"format", "network", "chain_id", "dev", "params", "features", "forks"}
# Optional: trusted checkpoints (qrdx/checkpoints.py), appended by releases like forks and, like
# them, outside what genesis commits to.
_OPTIONAL_SPEC_KEYS = {"checkpoints"}
_NOT_IN_GENESIS = ("forks", "checkpoints")
_FORK_KEYS = {"name", "height", "features", "params", "approval"}
# How a fork is authorised to activate. "validators": only once an on-chain governance proposal
# approving this exact fork definition has executed in time (the default, and the only option
# on a real network). "none": at its height unconditionally — dev networks only.
FORK_APPROVAL_MODES = ("validators", "none")


def _canonical(obj: Any) -> bytes:
    """The one serialization every hash in this module is taken over."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_param_value(name: str, value: Any, where: str) -> Any:
    p = PARAMS[name]
    if p.kind == "int":
        if not _is_int(value):
            raise ChainSpecError(f"{where}: {name} must be an integer, got {value!r}")
        if p.minimum is not None and value < p.minimum:
            raise ChainSpecError(f"{where}: {name} must be >= {p.minimum}, got {value}")
        return value
    if p.kind == "str":
        if not isinstance(value, str) or value != value.strip():
            raise ChainSpecError(
                f"{where}: {name} must be a string without surrounding "
                f"whitespace, got {value!r}"
            )
        return value
    # list of strings
    if not isinstance(value, list) or not all(
        isinstance(a, str) and a and a == a.strip() and "," not in a for a in value
    ):
        raise ChainSpecError(f"{where}: {name} must be a list of non-empty strings, got {value!r}")
    if len(set(value)) != len(value):
        raise ChainSpecError(f"{where}: {name} lists an entry twice")
    return list(value)


def _check_features(features: Any, where: str) -> List[str]:
    if not isinstance(features, list) or not all(isinstance(f, str) for f in features):
        raise ChainSpecError(f"{where}: features must be a list of names")
    if len(set(features)) != len(features):
        raise ChainSpecError(f"{where}: a feature is listed twice")
    unknown = [f for f in features if f not in FEATURES]
    if unknown:
        raise ChainSpecError(
            f"{where}: unknown feature(s) {unknown}. This release cannot execute them, so it "
            f"cannot follow this chain — upgrade the node software."
        )
    return sorted(features)


@dataclass(frozen=True)
class ForkId:
    """What a node announces to peers: the hash of the fork history it has passed and the
    height of the next fork it knows of (0 if none)."""

    hash: str
    next: int

    def to_dict(self) -> Dict[str, Any]:
        return {"hash": self.hash, "next": self.next}


_CONSTRUCT = object()


class ChainSpec:
    """A validated, immutable chain spec. Build with ``ChainSpec.from_dict``."""

    def __init__(self, data: Dict[str, Any], _token: object = None):
        if _token is not _CONSTRUCT:
            raise TypeError("build a ChainSpec with ChainSpec.from_dict (it validates)")
        self._data = data
        self._genesis_hash = hashlib.sha256(
            _GENESIS_HASH_TAG + _canonical(self.genesis_part())
        ).hexdigest()
        # (height, feature-set active from that height), ascending, starting at genesis.
        steps: List[Tuple[int, frozenset]] = [(0, frozenset(data["features"]))]
        acc = set(data["features"])
        for f in data["forks"]:
            acc |= set(f["features"])
            steps.append((f["height"], frozenset(acc)))
        self._steps = steps

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ChainSpec":
        """Validate a spec strictly and build it. Unknown keys, missing parameters, unknown
        features, out-of-order forks and reused feature names are all errors: a spec is the
        network's consensus definition, and anything this release does not understand is a rule
        it cannot follow."""
        if not isinstance(raw, Mapping):
            raise ChainSpecError("chain spec must be a JSON object")
        unknown = set(raw) - _SPEC_KEYS - _OPTIONAL_SPEC_KEYS
        missing = _SPEC_KEYS - set(raw)
        if unknown:
            raise ChainSpecError(f"chain spec: unknown key(s) {sorted(unknown)}")
        if missing:
            raise ChainSpecError(f"chain spec: missing key(s) {sorted(missing)}")
        if raw["format"] != SPEC_FORMAT or not _is_int(raw["format"]):
            raise ChainSpecError(
                f"chain spec format {raw['format']!r} is not supported by this release "
                f"(supports {SPEC_FORMAT})"
            )

        network = raw["network"]
        if not isinstance(network, str) or not _NETWORK_RE.match(network):
            raise ChainSpecError(f"chain spec: invalid network name {network!r}")
        if not isinstance(raw["dev"], bool):
            raise ChainSpecError("chain spec: dev must be true or false")
        chain_id = raw["chain_id"]
        if not _is_int(chain_id) or not (0 < chain_id < 2**63):
            raise ChainSpecError(
                f"chain spec: chain_id must be a positive integer, got {chain_id!r}"
            )
        if chain_id in QRDX_NETWORKS and (raw["dev"] or network != QRDX_NETWORKS[chain_id]):
            raise ChainSpecError(
                f"chain spec: chain_id {chain_id} is {QRDX_NETWORKS[chain_id]}'s; only that "
                f"network's (non-dev) spec may use it — a transaction signed elsewhere for it "
                f"would be valid there"
            )
        if not raw["dev"] and chain_id in RESERVED_CHAIN_IDS:
            raise ChainSpecError(
                f"chain spec: chain_id {chain_id} belongs to {RESERVED_CHAIN_IDS[chain_id]}. "
                f"Transactions signed for one network would be valid on the other; register a "
                f"unique chain id."
            )

        params = raw["params"]
        if not isinstance(params, Mapping):
            raise ChainSpecError("chain spec: params must be an object")
        extra, absent = set(params) - set(PARAMS), set(PARAMS) - set(params)
        if extra:
            raise ChainSpecError(f"chain spec: unknown parameter(s) {sorted(extra)}")
        if absent:
            raise ChainSpecError(
                f"chain spec: missing parameter(s) {sorted(absent)} — a "
                f"network spec lists every parameter explicitly"
            )
        clean_params = {k: _check_param_value(k, params[k], "chain spec params") for k in PARAMS}

        genesis_features = _check_features(raw["features"], "chain spec")

        forks = raw["forks"]
        if not isinstance(forks, list):
            raise ChainSpecError("chain spec: forks must be a list")
        seen_names, seen_features = set(), set(genesis_features)
        last_height = 0
        clean_forks: List[Dict[str, Any]] = []
        for i, f in enumerate(forks):
            where = f"chain spec fork #{i}"
            if not isinstance(f, Mapping):
                raise ChainSpecError(f"{where}: must be an object")
            if set(f) - _FORK_KEYS:
                raise ChainSpecError(f"{where}: unknown key(s) {sorted(set(f) - _FORK_KEYS)}")
            for k in ("name", "height", "features"):
                if k not in f:
                    raise ChainSpecError(f"{where}: missing {k!r}")
            name = f["name"]
            if not isinstance(name, str) or not _NAME_RE.match(name):
                raise ChainSpecError(f"{where}: invalid fork name {name!r}")
            if name in seen_names:
                raise ChainSpecError(f"{where}: fork name {name!r} is used twice")
            seen_names.add(name)
            height = f["height"]
            if not _is_int(height) or height <= last_height:
                raise ChainSpecError(
                    f"{where} ({name}): height must be an integer above the previous fork's "
                    f"({last_height}); got {height!r}. Rules active from genesis belong in the "
                    f"top-level features list."
                )
            last_height = height
            feats = _check_features(f["features"], f"{where} ({name})")
            reused = seen_features.intersection(feats)
            if reused:
                raise ChainSpecError(
                    f"{where} ({name}): feature(s) {sorted(reused)} already "
                    f"activated earlier — features switch on once"
                )
            seen_features.update(feats)
            fork_params = f.get("params", {})
            if not isinstance(fork_params, Mapping):
                raise ChainSpecError(f"{where} ({name}): params must be an object")
            for k, v in fork_params.items():
                if k not in PARAMS:
                    raise ChainSpecError(f"{where} ({name}): unknown parameter {k!r}")
                if not PARAMS[k].height_aware:
                    raise ChainSpecError(
                        f"{where} ({name}): parameter {k} cannot change at a fork — its "
                        f"consumers read it as a constant fixed at genesis"
                    )
                _check_param_value(k, v, f"{where} ({name})")
            if not feats and not fork_params:
                raise ChainSpecError(f"{where} ({name}): a fork must change something")
            approval = f.get("approval", "validators")
            if approval not in FORK_APPROVAL_MODES:
                raise ChainSpecError(
                    f"{where} ({name}): approval must be one of "
                    f"{FORK_APPROVAL_MODES}, got {approval!r}"
                )
            if approval == "none" and not raw["dev"]:
                raise ChainSpecError(
                    f"{where} ({name}): only a dev network may activate a fork without "
                    f"validator approval"
                )
            entry: Dict[str, Any] = {"name": name, "height": height, "features": feats}
            if fork_params:
                entry["params"] = {k: copy.deepcopy(fork_params[k]) for k in sorted(fork_params)}
            if approval != "validators":
                entry["approval"] = approval
            clean_forks.append(entry)

        checkpoints = raw.get("checkpoints", [])
        if not isinstance(checkpoints, list):
            raise ChainSpecError("chain spec: checkpoints must be a list")
        clean_checkpoints: List[Dict[str, Any]] = []
        for i, cp in enumerate(checkpoints):
            where = f"chain spec: checkpoints[{i}]"
            if not isinstance(cp, Mapping) or set(cp) != {"height", "hash"}:
                raise ChainSpecError(f"{where} must be {{'height': int, 'hash': hex}}")
            height, block_hash = cp["height"], cp["hash"]
            if not _is_int(height) or height < 1:
                raise ChainSpecError(f"{where}: height must be an int >= 1")
            if (
                not isinstance(block_hash, str)
                or len(block_hash) != 64
                or any(c not in "0123456789abcdef" for c in block_hash)
            ):
                raise ChainSpecError(f"{where}: hash must be 64 lower-case hex characters")
            if clean_checkpoints and height <= clean_checkpoints[-1]["height"]:
                raise ChainSpecError(f"{where}: heights must increase")
            clean_checkpoints.append({"height": height, "hash": block_hash})

        return cls(
            {
                "format": SPEC_FORMAT,
                "network": network,
                "chain_id": chain_id,
                "dev": raw["dev"],
                "params": clean_params,
                "features": genesis_features,
                "forks": clean_forks,
                "checkpoints": clean_checkpoints,
            },
            _CONSTRUCT,
        )

    # ── identity ────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)

    def genesis_part(self) -> Dict[str, Any]:
        """Everything genesis commits to: the spec minus its upgrade schedule and its trusted
        checkpoints (both appended by later releases)."""
        return {k: copy.deepcopy(v) for k, v in self._data.items() if k not in _NOT_IN_GENESIS}

    def checkpoints(self) -> List[Tuple[int, str]]:
        """(height, block hash) of each trusted checkpoint, ascending (qrdx/checkpoints.py)."""
        return [(int(c["height"]), str(c["hash"])) for c in self._data.get("checkpoints", [])]

    def genesis_hash(self) -> str:
        """The hash the genesis state root commits to."""
        return self._genesis_hash

    @property
    def network(self) -> str:
        return self._data["network"]

    @property
    def chain_id(self) -> int:
        return self._data["chain_id"]

    @property
    def dev(self) -> bool:
        return self._data["dev"]

    @property
    def params(self) -> Dict[str, Any]:
        """Genesis parameter values (a copy)."""
        return copy.deepcopy(self._data["params"])

    @property
    def forks(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self._data["forks"])

    # ── rules at a height ───────────────────────────────────────────────────

    @staticmethod
    def _check_height(height: Any) -> int:
        if not _is_int(height) or height < 0:
            raise ValueError(
                f"a block height is required (got {height!r}); rules are decided "
                f"by the height of the block being applied, never by the tip"
            )
        return height

    def scheduled_features_at(self, height: int) -> frozenset:
        """The features the schedule switches on by ``height`` — before approvals. Whether a
        fork's features are actually in force is ``chain_spec.is_active`` (it also needs the
        fork's on-chain approval)."""
        h = self._check_height(height)
        active_set = self._steps[0][1]
        for start, feats in self._steps:
            if start > h:
                break
            active_set = feats
        return active_set

    def is_scheduled(self, feature: str, height: int) -> bool:
        """Does the schedule switch ``feature`` on by ``height``? (Not whether it is in force:
        see ``chain_spec.is_active``.)"""
        if feature not in FEATURES:
            raise KeyError(f"unknown feature {feature!r} (see chain_spec.FEATURES)")
        return feature in self.scheduled_features_at(height)

    def fork_of(self, feature: str) -> Optional[Dict[str, Any]]:
        """The fork that switches ``feature`` on (None if it is a genesis feature or never
        scheduled)."""
        for f in self._data["forks"]:
            if feature in f["features"]:
                return copy.deepcopy(f)
        return None

    @staticmethod
    def fork_definition_hash(fork: Mapping[str, Any]) -> str:
        """The hash an on-chain approval names: the exact fork definition, so an approval never
        carries over to a fork whose contents were later changed."""
        return hashlib.sha256(b"QRDX-FORK-DEFINITION-v1\x00" + _canonical(dict(fork))).hexdigest()

    def activation_height(self, feature: str) -> Optional[int]:
        """The height ``feature`` switches on at, or None if the spec never schedules it."""
        if feature not in FEATURES:
            raise KeyError(f"unknown feature {feature!r}")
        if feature in self._data["features"]:
            return 0
        for f in self._data["forks"]:
            if feature in f["features"]:
                return f["height"]
        return None

    def param_at(self, name: str, height: int) -> Any:
        """A parameter's value for the block at ``height`` (genesis value unless a fork has
        changed it)."""
        if name not in PARAMS:
            raise KeyError(f"unknown parameter {name!r}")
        h = self._check_height(height)
        value = self._data["params"][name]
        for f in self._data["forks"]:
            if f["height"] > h:
                break
            if name in f.get("params", {}):
                value = f["params"][name]
        return copy.deepcopy(value)

    # ── fork ids (EIP-2124) ─────────────────────────────────────────────────

    def fork_hashes(self, genesis_block_hash: str) -> List[str]:
        """``hashes[i]`` is the fork hash after the first ``i`` forks have passed."""
        if not isinstance(genesis_block_hash, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", genesis_block_hash
        ):
            raise ValueError("genesis block hash must be 64 hex characters")
        h = hashlib.sha256(_FORK_ID_TAG + bytes.fromhex(genesis_block_hash)).digest()
        out = [h[:_FORK_HASH_BYTES].hex()]
        for f in self._data["forks"]:
            h = hashlib.sha256(h + _canonical(f)).digest()
            out.append(h[:_FORK_HASH_BYTES].hex())
        return out

    def fork_id(self, genesis_block_hash: str, head: int) -> ForkId:
        head = self._check_height(head)
        hashes = self.fork_hashes(genesis_block_hash)
        passed = sum(1 for f in self._data["forks"] if f["height"] <= head)
        upcoming = [f["height"] for f in self._data["forks"] if f["height"] > head]
        return ForkId(hash=hashes[passed], next=upcoming[0] if upcoming else 0)

    def next_fork(self, head: int) -> Optional[Dict[str, Any]]:
        head = self._check_height(head)
        for f in self._data["forks"]:
            if f["height"] > head:
                return copy.deepcopy(f)
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  Peer compatibility
# ─────────────────────────────────────────────────────────────────────────────


def network_identity(
    spec: ChainSpec, genesis_block_hash: str, head: int, node_version: str
) -> Dict[str, Any]:
    """What a node advertises in its handshake and status."""
    fid = spec.fork_id(genesis_block_hash, max(0, head))
    return {
        "network": spec.network,
        "chain_id": spec.chain_id,
        "genesis_hash": genesis_block_hash,
        "fork_hash": fid.hash,
        "fork_next": fid.next,
        "node_version": node_version,
        "features": sorted(FEATURES),
    }


def report(
    spec: ChainSpec, genesis_block_hash: str, head: int, node_version: str
) -> Dict[str, Any]:
    """An operator's view of the network and its upgrade schedule (``/chain_spec``,
    ``qrdx_chainSpec``): what is active now, what is scheduled, and when."""
    head = max(0, int(head))
    forks = []
    for f in spec.forks:
        entry = dict(f)
        approval = fork_approval(spec, f)
        entry["approval"] = approval
        if f["height"] <= head:
            entry["status"] = "active" if approval["approved"] else "dormant (not approved in time)"
        elif approval["approved"]:
            entry["status"] = "scheduled (approved)"
        elif head > approval["approve_by"]:
            entry["status"] = "scheduled (approval deadline passed — will stay dormant)"
        else:
            entry["status"] = "scheduled (awaiting approval)"
        entry["blocks_until"] = max(0, f["height"] - head)
        forks.append(entry)
    nxt = spec.next_fork(head)
    return {
        "network": spec.network,
        "chain_id": spec.chain_id,
        "dev": spec.dev,
        "spec_format": SPEC_FORMAT,
        "spec_hash": spec.genesis_hash(),
        "genesis_block_hash": genesis_block_hash,
        "head": head,
        "params": spec.params,
        "genesis_features": spec.to_dict()["features"],
        "forks": forks,
        "next_fork": ({**nxt, "blocks_until": nxt["height"] - head} if nxt else None),
        "active_features": active_features(head, spec),
        "fork_id": spec.fork_id(genesis_block_hash, head).to_dict(),
        "node_version": node_version,
        "supported_features": dict(FEATURES),
    }


def check_peer_compatibility(
    spec: ChainSpec, genesis_block_hash: str, head: int, remote: Any
) -> Tuple[bool, str]:
    """
    Decide whether a peer advertising ``remote`` (``network_identity`` output) follows the same
    chain. EIP-2124's rules, with block heights:

    1. Different genesis block or chain id: a different network.
    2. Same fork hash as ours: compatible — unless the peer announces a next fork at a height we
       have already passed, i.e. a fork we do not know (our software is stale, or theirs is).
    3. The peer's hash is one of our EARLIER fork hashes (it is behind us, syncing): compatible
       only if its announced next fork is the one we passed next — otherwise it does not know a
       fork we are already on and will diverge from us.
    4. The peer's hash is one of our LATER fork hashes (we are behind, syncing): compatible; we
       know those forks and will follow them.
    5. Anything else: incompatible fork history.

    A peer that advertises no identity (a node from before chain specs existed) is incompatible:
    nothing says it follows our rules.
    """
    if not isinstance(remote, Mapping):
        return False, "peer advertises no network identity"
    try:
        r_genesis = str(remote["genesis_hash"]).lower()
        r_chain = int(remote["chain_id"])
        r_hash = str(remote["fork_hash"]).lower()
        r_next = int(remote["fork_next"])
    except (KeyError, TypeError, ValueError):
        return False, "peer's network identity is malformed"
    if r_genesis != genesis_block_hash.lower():
        return False, f"different genesis ({r_genesis[:16]}… vs ours {genesis_block_hash[:16]}…)"
    if r_chain != spec.chain_id:
        return False, f"different chain id ({r_chain} vs ours {spec.chain_id})"
    if r_next < 0:
        return False, "peer's network identity is malformed"

    hashes = spec.fork_hashes(genesis_block_hash)
    heights = [f["height"] for f in spec.forks]
    head = max(0, int(head))
    passed = sum(1 for h in heights if h <= head)

    if r_hash == hashes[passed]:
        if r_next and head >= r_next:
            return False, (
                f"peer schedules a fork at height {r_next}, which this node has passed "
                f"without it — one of the two runs outdated software or spec"
            )
        return True, ""
    for j in range(passed):
        if r_hash == hashes[j]:
            if r_next == heights[j]:
                return True, ""
            return False, (
                f"peer is behind and does not schedule the fork at height "
                f"{heights[j]} that this node has passed — it must upgrade"
            )
    for j in range(passed + 1, len(hashes)):
        if r_hash == hashes[j]:
            return True, ""
    return False, "incompatible fork history"


# ─────────────────────────────────────────────────────────────────────────────
#  Building and loading
# ─────────────────────────────────────────────────────────────────────────────


def _env_lookup(
    env: Optional[Mapping[str, str]], dotenv: Optional[Mapping[str, Optional[str]]], key: str
) -> Optional[str]:
    """Environment first, then the .env file — the precedence qrdx.constants uses."""
    env = os.environ if env is None else env
    v = env.get(key)
    if v is None and dotenv:
        v = dotenv.get(key)
    return v


# Chain ids a dev network may still use although they are reserved for real networks: the
# historical dev default and the local-development conventions.
_DEV_ALLOWED_RESERVED = {DEV_CHAIN_ID, 1337, 31337}


def params_from_environment(
    env: Optional[Mapping[str, str]] = None, dotenv: Optional[Mapping[str, Optional[str]]] = None
) -> Dict[str, Any]:
    """Every network parameter, from its environment variable or its dev default."""
    params: Dict[str, Any] = {}
    for name, p in PARAMS.items():
        raw = _env_lookup(env, dotenv, p.env)
        if raw is None or (p.empty_env_is_default and not raw.strip()):
            params[name] = copy.deepcopy(p.default)
            continue
        try:
            params[name] = _PARSERS[p.kind](raw)
        except ValueError as e:
            raise ChainSpecError(f"{p.env}={raw!r} is not a valid {p.kind}: {e}") from None
    return params


def dev_spec(
    env: Optional[Mapping[str, str]] = None, dotenv: Optional[Mapping[str, Optional[str]]] = None
) -> ChainSpec:
    """The spec of a node started without a genesis file: a development network whose
    parameters come from the environment (falling back to the historical defaults), exactly as
    before chain specs existed. Its genesis hash covers those values, so a dev database refuses
    to start again under different ones."""
    params = params_from_environment(env, dotenv)
    chain_raw = _env_lookup(env, dotenv, "QRDX_CHAIN_ID")
    try:
        chain_id = int(chain_raw) if chain_raw else DEV_CHAIN_ID
    except ValueError:
        raise ChainSpecError(f"QRDX_CHAIN_ID={chain_raw!r} is not an integer") from None
    if chain_id in QRDX_NETWORKS:
        raise ChainSpecError(
            f"QRDX_CHAIN_ID={chain_id} is {QRDX_NETWORKS[chain_id]}'s chain id; a node with no "
            f"genesis file runs a dev network, and a dev network on that id would sign "
            f"transactions valid on {QRDX_NETWORKS[chain_id]}. Give the node the network's "
            f"genesis file (QRDX_GENESIS_FILE)."
        )
    if chain_id in RESERVED_CHAIN_IDS and chain_id not in _DEV_ALLOWED_RESERVED:
        raise ChainSpecError(
            f"QRDX_CHAIN_ID={chain_id} belongs to {RESERVED_CHAIN_IDS[chain_id]}; a node with no "
            f"genesis file runs a dev network, and keys used on both would have every transaction "
            f"replayable. Give the node its network's genesis file (QRDX_GENESIS_FILE), or unset "
            f"QRDX_CHAIN_ID for a dev network."
        )
    network = _env_lookup(env, dotenv, "QRDX_NETWORK_NAME") or DEV_NETWORK_NAME
    return ChainSpec.from_dict(
        {
            "format": SPEC_FORMAT,
            "network": network,
            "chain_id": chain_id,
            "dev": True,
            "params": params,
            "features": list(GENESIS_DEFAULT_FEATURES),
            "forks": [],
        }
    )


def resolve_genesis_file(
    env: Optional[Mapping[str, str]] = None,
    dotenv: Optional[Mapping[str, Optional[str]]] = None,
    database_path: Optional[str] = None,
) -> Optional[str]:
    """Where this process's genesis file is: ``QRDX_GENESIS_FILE`` if set (it must exist),
    else ``genesis_config.json`` two directories above the database (the testnet layout the
    node has always used), else none."""
    explicit = _env_lookup(env, dotenv, "QRDX_GENESIS_FILE")
    if explicit:
        if not os.path.isfile(explicit):
            raise ChainSpecError(f"QRDX_GENESIS_FILE={explicit} does not exist")
        return explicit
    db_path = database_path or _env_lookup(env, dotenv, "QRDX_DATABASE_PATH")
    if db_path:
        candidate = os.path.join(os.path.dirname(os.path.dirname(db_path)), "genesis_config.json")
        if os.path.isfile(candidate):
            return candidate
    return None


def load_genesis_file(path: str) -> Tuple[Dict[str, Any], ChainSpec]:
    """Read a genesis file and validate its chain spec. Fails closed: an unreadable file, or
    one without a valid ``chain_spec`` section, is an error — never a fallback."""
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        raise ChainSpecError(f"cannot read genesis file {path}: {e}") from None
    if not isinstance(data, dict):
        raise ChainSpecError(f"genesis file {path} is not a JSON object")
    if "chain_spec" not in data:
        raise ChainSpecError(
            f"genesis file {path} has no chain_spec section. It was produced by a release "
            f"before chain specs; regenerate the network's genesis (a new network) — a node "
            f"cannot guess the consensus parameters a chain was started with."
        )
    spec = ChainSpec.from_dict(data["chain_spec"])
    return data, spec


def environment_conflicts(
    spec: ChainSpec,
    env: Optional[Mapping[str, str]] = None,
    dotenv: Optional[Mapping[str, Optional[str]]] = None,
) -> List[str]:
    """Environment settings that try to change consensus on a non-dev network. Empty for a dev
    network (which takes them from the environment by design)."""
    if spec.dev:
        return []
    problems: List[str] = []
    for name, p in PARAMS.items():
        raw = _env_lookup(env, dotenv, p.env)
        if raw is None or (p.empty_env_is_default and not raw.strip()):
            continue
        try:
            value = _PARSERS[p.kind](raw)
        except ValueError:
            problems.append(
                f"{p.env}={raw!r} is set, but {spec.network} takes {name} from its "
                f"chain spec ({spec.params[name]!r})"
            )
            continue
        if value != spec.params[name]:
            problems.append(
                f"{p.env}={raw!r} conflicts with the chain spec's {name} = "
                f"{spec.params[name]!r}"
            )
    chain_raw = _env_lookup(env, dotenv, "QRDX_CHAIN_ID")
    if chain_raw and chain_raw.strip() != str(spec.chain_id):
        problems.append(
            f"QRDX_CHAIN_ID={chain_raw!r} conflicts with the chain spec's chain_id "
            f"{spec.chain_id}"
        )
    net_raw = _env_lookup(env, dotenv, "QRDX_NETWORK_NAME")
    if net_raw and net_raw.strip() != spec.network:
        problems.append(
            f"QRDX_NETWORK_NAME={net_raw!r} conflicts with the chain spec's network "
            f"{spec.network!r}"
        )
    for switch in CONSENSUS_ENV_SWITCHES:
        raw = _env_lookup(env, dotenv, switch)
        if raw is not None and raw.strip():
            problems.append(
                f"{switch}={raw!r} is a development switch; on {spec.network} the "
                f"chain spec alone decides consensus behaviour"
            )
    return problems


@dataclass(frozen=True)
class ProcessSpec:
    """What ``qrdx.constants`` loads at import: the spec, the genesis file it came from (None for
    the built-in dev spec), and any environment conflicts the node must refuse to start with."""

    spec: ChainSpec
    genesis_file: Optional[str]
    genesis_data: Optional[Dict[str, Any]]
    env_conflicts: Tuple[str, ...]


def load_process_spec(
    env: Optional[Mapping[str, str]] = None,
    dotenv: Optional[Mapping[str, Optional[str]]] = None,
    database_path: Optional[str] = None,
) -> ProcessSpec:
    """Resolve and load this process's chain spec. Raises ``ChainSpecError`` if a genesis file
    exists but cannot be used — a node must never fall back to other rules than its network's."""
    path = resolve_genesis_file(env, dotenv, database_path)
    if path is None:
        return ProcessSpec(dev_spec(env, dotenv), None, None, ())
    data, spec = load_genesis_file(path)
    return ProcessSpec(spec, path, data, tuple(environment_conflicts(spec, env, dotenv)))


# ─────────────────────────────────────────────────────────────────────────────
#  The process's active spec
# ─────────────────────────────────────────────────────────────────────────────

_ACTIVE: Optional[ChainSpec] = None


def set_active(spec: ChainSpec) -> None:
    """Install the process's spec (``qrdx.constants`` does this at import)."""
    global _ACTIVE
    if not isinstance(spec, ChainSpec):
        raise TypeError("set_active needs a ChainSpec")
    _ACTIVE = spec


def active() -> ChainSpec:
    if _ACTIVE is None:
        import qrdx.constants  # noqa: F401  (loads and installs the process spec)
    assert _ACTIVE is not None
    return _ACTIVE


@contextlib.contextmanager
def use_spec(spec: ChainSpec) -> Iterator[ChainSpec]:
    """Temporarily install ``spec`` (tests)."""
    global _ACTIVE
    prev = _ACTIVE
    set_active(spec)
    try:
        yield spec
    finally:
        _ACTIVE = prev


# ─────────────────────────────────────────────────────────────────────────────
#  Signing domains
# ─────────────────────────────────────────────────────────────────────────────

# What a node signs as a consensus participant. Each signature is taken over a root that starts
# with the domain for its purpose on its network, so a signature made on one network — or for
# one purpose — never verifies as another (Ethereum's compute_domain). Without it, two block
# headers a validator signed at one slot on a testnet are a valid DOUBLE_SIGN proof on every
# network where it uses the same key.
# p2p-handshake: a node proving its identity to a peer (qrdx.rpc.modules.p2p).
SIGNING_PURPOSES = ("block", "attestation", "randao", "p2p-handshake")
_SIGNING_DOMAIN_TAG = b"QRDX-SIGNING-DOMAIN-v1\x00"


@functools.lru_cache(maxsize=64)
def _signing_domain(purpose: str, chain_id: int, spec_hash: str) -> bytes:
    return hashlib.sha256(
        _SIGNING_DOMAIN_TAG
        + purpose.encode()
        + b"\x00"
        + chain_id.to_bytes(8, "big")
        + bytes.fromhex(spec_hash)
    ).digest()


def signing_domain(purpose: str, spec: Optional[ChainSpec] = None) -> bytes:
    """The 32-byte domain prefixed to every ``purpose`` signing root on ``spec``'s network
    (default: this process's). Derived from the chain id and the chain spec's genesis hash, so
    scheduling a fork does not change it — signatures stay valid across an upgrade."""
    if purpose not in SIGNING_PURPOSES:
        raise ValueError(f"unknown signing purpose {purpose!r}")
    spec = spec or active()
    return _signing_domain(purpose, spec.chain_id, spec.genesis_hash())


# Where on-chain fork approvals are read: (fork name, fork definition hash) → the height the
# approving proposal executed at, or None. Installed by the governance state machine
# (qrdx/exchange/governance.py); unset (a process without it), nothing is approved.
_APPROVAL_LOOKUP: Optional[Callable[[str, str], Optional[int]]] = None


def set_approval_lookup(fn: Optional[Callable[[str, str], Optional[int]]]) -> None:
    global _APPROVAL_LOOKUP
    _APPROVAL_LOOKUP = fn


def fork_approval(spec: ChainSpec, fork: Mapping[str, Any]) -> Dict[str, Any]:
    """Where ``fork`` stands with its approval: its mode, the definition hash an approval must
    name, the last height an approval can execute at to count, and when it was approved."""
    mode = fork.get("approval", "validators")
    lead = spec.params["GOV_FORK_APPROVAL_LEAD_BLOCKS"]
    digest = ChainSpec.fork_definition_hash(fork)
    approved_at = None
    if mode == "validators" and _APPROVAL_LOOKUP is not None:
        approved_at = _APPROVAL_LOOKUP(fork["name"], digest)
    deadline = fork["height"] - lead
    in_time = mode == "none" or (approved_at is not None and approved_at <= deadline)
    return {
        "mode": mode,
        "definition_hash": digest,
        "approve_by": deadline,
        "approved_at": approved_at,
        "approved": in_time,
    }


def is_active(feature: str, height: int) -> bool:
    """Is ``feature`` in force for the block at ``height`` on this process's network?

    A genesis feature always is. A fork's feature is from the fork's height on — provided the
    fork was approved on chain by validators (governance) at least
    GOV_FORK_APPROVAL_LEAD_BLOCKS before that height. An unapproved, or late-approved, fork
    stays dormant on every node. Pass the height of the block being proposed, verified or
    replayed — never the chain tip."""
    spec = active()
    if not spec.is_scheduled(feature, height):
        return False
    if feature in spec.to_dict()["features"]:
        return True
    fork = spec.fork_of(feature)
    return fork is not None and fork_approval(spec, fork)["approved"]


def active_features(height: int, spec: Optional[ChainSpec] = None) -> List[str]:
    """Every feature in force at ``height`` (genesis features + approved, reached forks)."""
    spec = spec or active()
    out = set(spec.to_dict()["features"])
    for f in spec.forks:
        if f["height"] <= height and fork_approval(spec, f)["approved"]:
            out.update(f["features"])
    return sorted(out)


def build_spec(
    network: str,
    chain_id: int,
    params: Mapping[str, Any],
    *,
    dev: bool = False,
    features: Optional[Sequence[str]] = None,
    forks: Sequence[Mapping[str, Any]] = (),
) -> ChainSpec:
    """Assemble and validate a spec (genesis tooling). ``params`` may be partial: missing ones
    take the dev defaults, so tooling states only what its network changes — the written spec
    still lists every parameter. ``features`` defaults to ``GENESIS_DEFAULT_FEATURES``."""
    if features is None:
        features = GENESIS_DEFAULT_FEATURES
    full = {k: copy.deepcopy(p.default) for k, p in PARAMS.items()}
    unknown = set(params) - set(PARAMS)
    if unknown:
        raise ChainSpecError(f"unknown parameter(s) {sorted(unknown)}")
    full.update({k: copy.deepcopy(v) for k, v in params.items()})
    return ChainSpec.from_dict(
        {
            "format": SPEC_FORMAT,
            "network": network,
            "chain_id": chain_id,
            "dev": dev,
            "params": full,
            "features": list(features),
            "forks": [dict(f) for f in forks],
        }
    )
