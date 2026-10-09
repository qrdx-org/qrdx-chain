"""
Genesis Generator — Create Testnet Genesis Using Real GenesisCreator

Wraps qrdx.validator.genesis.GenesisCreator with testnet-specific
allocations. No custom genesis format — uses the real code path.
"""

import json
import logging
import os
from decimal import Decimal
from pathlib import Path
from typing import Dict, List

from integration_tests.config import (
    CHAIN_ID, NETWORK_NAME, GENESIS_FILE,
    VALIDATOR_STAKE, WALLET_ROSTER,
    CONTRACT_TEST_BALANCE, SLOT_DURATION, SLOTS_PER_EPOCH, STABLECOIN_SYMBOL,
)
from integration_tests.wallet_factory import generate_all_wallets, get_wallet_address, get_wallet_public_key_hex

logger = logging.getLogger(__name__)


_TRUTHY = ("1", "true", "yes")


def stablecoin_address(wallets: Dict[str, dict]) -> str:
    """The testnet stablecoin's token address: TOKEN_DEPLOY derives it from the issuer, its
    nonce (0 — the deploy is its first exchange transaction) and the symbol."""
    from qrdx.exchange.state_manager import ExchangeStateManager
    issuer = wallets.get("Stablecoin Issuer", {}).get("address", "")
    return ExchangeStateManager.derive_token_address(issuer, 0, STABLECOIN_SYMBOL) if issuer else ""


def testnet_chain_spec(wallets: Dict[str, dict]):
    """
    The integration testnet's chain spec (docs/PROTOCOL_UPGRADES.md). Every node takes its
    consensus parameters from here — the genesis file — never from its environment.

    Harness knobs, read from THIS process's environment (never passed to a node):
      QRDX_SLOT_DURATION / QRDX_SLOTS_PER_EPOCH   slot clock (the RANDAO larger-slot config)
      QRDX_ENFORCE_RANDAO=1                       RANDAO selection from genesis
      QRDX_TESTNET_RANDAO_FORK_HEIGHT=N           RANDAO selection switched on by a fork at
                                                  height N — a live protocol upgrade
    """
    from qrdx import chain_spec as cs

    reporter = wallets.get("Oracle Reporter", {}).get("address", "")
    params = {
        "SLOT_DURATION": int(os.environ.get("QRDX_SLOT_DURATION") or SLOT_DURATION),
        "SLOTS_PER_EPOCH": int(os.environ.get("QRDX_SLOTS_PER_EPOCH") or SLOTS_PER_EPOCH),
        # A 3-validator set is below the production minimum.
        "MIN_VALIDATORS": 1,
        # Short activation/unbonding so the dynamic-membership scenario (S16) observes a
        # deposit→active→exit→exited round-trip within a short soak.
        "ACTIVATION_DELAY_EPOCHS": 1,
        "UNBONDING_PERIOD_EPOCHS": 2,
        # Withdrawability delay after exit (production 256): long enough to cover the finality
        # lag, short enough that a soak sees the principal come back.
        "WITHDRAWAL_DELAY_EPOCHS": 4,
        # Prices come from the validators' votes (docs/PERPS_CLEARINGHOUSE.md §8); no trusted
        # reporter. The reporter wallet doubles as the treasury vault seeder.
        "ORACLE_REPORTERS": [],
        "PERP_VAULT_SEEDERS": [reporter] if reporter else [],
        # Vault deposits unlock after 20 s instead of 4 days so S19 can redeem within the run.
        "PERP_VAULT_LOCKUP_SECONDS": 20,
        # Funding every minute of block time (production: hourly), so a run sees several.
        "PERP_FUNDING_INTERVAL_SECONDS": 60,
        # Perps settle in the testnet stablecoin and quote in USD, as production settles in the
        # bridged stablecoin. The token does not exist until S13 deploys it; its address is
        # fixed in advance by the issuer's first nonce.
        "PERP_COLLATERAL_TOKEN": stablecoin_address(wallets),
        "PERP_QUOTE": "USD",
        # Governance on testnet time (production: a week of voting, a 2-day timelock, a
        # 256-block fork-approval lead). The veto threshold is small enough for a test holder
        # to reach (S22); the approval threshold stays 2/3, so all three validators must vote.
        "GOV_VOTING_PERIOD_BLOCKS": 60,
        "GOV_TIMELOCK_BLOCKS": 8,
        "GOV_EXECUTION_WINDOW_BLOCKS": 200,
        "GOV_VETO_THRESHOLD_QRDX": 500,
        "GOV_FORK_APPROVAL_LEAD_BLOCKS": 5,
    }
    features, forks = [], []
    fork_height = os.environ.get("QRDX_TESTNET_RANDAO_FORK_HEIGHT", "").strip()
    if fork_height:
        forks.append({"name": "randao", "height": int(fork_height), "features": ["randao_selection"]})
    elif os.environ.get("QRDX_ENFORCE_RANDAO", "").lower() in _TRUTHY:
        features.append("randao_selection")
    return cs.build_spec(NETWORK_NAME, CHAIN_ID, params, features=features, forks=forks)


def create_genesis(wallets: Dict[str, dict], genesis_path: str = None) -> dict:
    """
    Create the genesis configuration using the REAL GenesisCreator.

    This is NOT a simplified version — it calls the same code that
    mainnet genesis creation would use.

    Args:
        wallets: Dict from generate_all_wallets()
        genesis_path: Where to write genesis_config.json

    Returns:
        Genesis summary dict
    """
    from qrdx.validator.genesis import GenesisCreator, GenesisConfig

    if genesis_path is None:
        genesis_path = str(GENESIS_FILE)

    # Find master controller
    controller_wallet = wallets.get("Master Controller")
    if not controller_wallet:
        raise ValueError("Master Controller wallet not found in wallet set")
    controller_address = get_wallet_address(controller_wallet)

    network_spec = testnet_chain_spec(wallets)

    # Build genesis config
    config = GenesisConfig(
        chain_spec=network_spec,
        min_genesis_validators=1,
        initial_supply=Decimal("100000000"),
        system_wallet_controller=controller_address,
        enable_system_wallets=True,
    )

    # Add pre-allocations for all wallets with non-zero balance
    for label, wallet in wallets.items():
        spec = wallet.get("_spec", {})
        balance = Decimal(spec.get("genesis_balance", "0"))
        if balance > 0:
            address = get_wallet_address(wallet)
            config.pre_allocations[address] = balance

    # Add contract test account
    contract_test_address = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    config.pre_allocations[contract_test_address] = CONTRACT_TEST_BALANCE

    # Create genesis
    creator = GenesisCreator(config)

    # Add validators
    for label, wallet in wallets.items():
        spec = wallet.get("_spec", {})
        if spec.get("is_validator"):
            address = get_wallet_address(wallet)
            pubkey = get_wallet_public_key_hex(wallet)
            creator.add_validator(address, pubkey, VALIDATOR_STAKE)

    # Generate genesis state + block
    state, block = creator.create_genesis()

    # Export to file
    os.makedirs(os.path.dirname(genesis_path), exist_ok=True)
    creator.export_genesis(state, block, genesis_path)

    summary = {
        "genesis_path": genesis_path,
        "genesis_hash": block.block_hash,
        "state_root": state.state_root,
        "chain_id": CHAIN_ID,
        "network_name": NETWORK_NAME,
        "chain_spec_hash": network_spec.genesis_hash(),
        "forks": network_spec.forks,
        "genesis_features": network_spec.to_dict()["features"],
        "validators": len(state.validators),
        "system_wallets": len(state.system_wallets),
        "system_controller": state.system_wallet_controller,
        "total_prefunded": str(sum(config.pre_allocations.values())),
        "accounts": len(state.accounts),
    }

    logger.info("Genesis created: hash=%s validators=%d accounts=%d",
                summary["genesis_hash"][:16], summary["validators"], summary["accounts"])
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    wallets = generate_all_wallets(force=True)
    summary = create_genesis(wallets)
    print(json.dumps(summary, indent=2))
