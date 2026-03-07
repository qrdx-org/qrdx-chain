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
    CONTRACT_TEST_BALANCE,
)
from integration_tests.wallet_factory import generate_all_wallets, get_wallet_address, get_wallet_public_key_hex

logger = logging.getLogger(__name__)


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

    # Build genesis config
    config = GenesisConfig(
        chain_id=CHAIN_ID,
        network_name=NETWORK_NAME,
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
