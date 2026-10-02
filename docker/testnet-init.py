#!/usr/bin/env python3
"""
Bootstrap a containerised QRDX testnet.

Generates, once, into the shared testnet volume:

    $QRDX_TESTNET_DIR/wallets/master_controller.json
    $QRDX_TESTNET_DIR/wallets/validator_<i>.json      (i = 0 .. N-1)
    $QRDX_TESTNET_DIR/genesis_config.json
    $QRDX_TESTNET_DIR/databases/                      (node DBs land here)
    $QRDX_TESTNET_DIR/keys/                           (per-node PQ identities)

This mirrors scripts/testnet.sh, but runs inside the node image so no host
Python, liboqs or jq is required. The node discovers genesis_config.json by
walking two directories up from QRDX_DATABASE_PATH, which is why the databases
live in a subdirectory of the testnet root.

Idempotent: if genesis_config.json already exists the script is a no-op, so
restarting the stack never regenerates keys under a live chain.

Environment
  QRDX_TESTNET_DIR       [/testnet]
  QRDX_TESTNET_VALIDATORS[3]
  QRDX_CHAIN_ID          [9999]
  QRDX_NETWORK_NAME      [qrdx-integration-testnet]
  QRDX_GENESIS_BALANCE   [1000000]   prefunded QRDX per validator
  QRDX_VALIDATOR_STAKE   [100000]    genesis stake per validator
  QRDX_VALIDATOR_PASSWORD_PREFIX [testnet_validator_]

WARNING: the generated wallets use well-known passwords and are for LOCAL
TESTING ONLY. Never reuse this flow for a public network.
"""
import json
import logging
import os
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[testnet-init] %(message)s", stream=sys.stdout)
log = logging.getLogger("testnet-init")

TESTNET_DIR = Path(os.getenv("QRDX_TESTNET_DIR", "/testnet"))
NUM_VALIDATORS = int(os.getenv("QRDX_TESTNET_VALIDATORS", "3"))
CHAIN_ID = int(os.getenv("QRDX_CHAIN_ID", "9999"))
NETWORK_NAME = os.getenv("QRDX_NETWORK_NAME", "qrdx-integration-testnet")
GENESIS_BALANCE = Decimal(os.getenv("QRDX_GENESIS_BALANCE", "1000000"))
VALIDATOR_STAKE = Decimal(os.getenv("QRDX_VALIDATOR_STAKE", "100000"))

WALLETS_DIR = TESTNET_DIR / "wallets"
GENESIS_FILE = TESTNET_DIR / "genesis_config.json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_wallet(path: Path, label: str, purpose: str | None = None) -> dict:
    """Create a Dilithium3 / ML-DSA-65 wallet file, or load it if it exists."""
    if path.exists():
        log.info("reusing %s", path.name)
        return json.loads(path.read_text())

    from qrdx.crypto.pq.dilithium import PQPrivateKey

    private_key = PQPrivateKey.generate()
    public_key = private_key.public_key

    wallet = {
        "version": "2.0",
        "type": "pq",
        "algorithm": "dilithium3",
        "address": public_key.to_address(),
        "public_key": public_key.to_hex(),
        "private_key": private_key.to_hex(),
        "label": label,
        "created": _now(),
    }
    if purpose:
        wallet["purpose"] = purpose

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(wallet, indent=2))
    path.chmod(0o600)
    log.info("created %s -> %s", path.name, wallet["address"][:24] + "...")
    return wallet


def main() -> int:
    for sub in ("wallets", "databases", "keys"):
        (TESTNET_DIR / sub).mkdir(parents=True, exist_ok=True)

    if GENESIS_FILE.exists():
        log.info("%s already exists — nothing to do.", GENESIS_FILE)
        return 0

    log.info("bootstrapping a %d-validator testnet in %s", NUM_VALIDATORS, TESTNET_DIR)

    controller = make_wallet(
        WALLETS_DIR / "master_controller.json",
        "Master Controller (System Wallets)",
        purpose="Controls all system wallets (treasury, grants, etc.)",
    )

    validators = [
        make_wallet(WALLETS_DIR / f"validator_{i}.json", f"Validator {i}")
        for i in range(NUM_VALIDATORS)
    ]

    from qrdx.validator.genesis import GenesisConfig, GenesisCreator

    config = GenesisConfig(
        chain_id=CHAIN_ID,
        network_name=NETWORK_NAME,
        min_genesis_validators=1,
        initial_supply=Decimal("100000000"),  # 100M QRDX
        system_wallet_controller=controller["address"],
        enable_system_wallets=True,
    )

    for v in validators:
        config.pre_allocations[v["address"]] = GENESIS_BALANCE

    # Well-known test account (private key 0x01) used by the contract-deployment
    # integration tests.
    config.pre_allocations["0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"] = Decimal("1000000000")

    creator = GenesisCreator(config)
    for v in validators:
        creator.add_validator(v["address"], v["public_key"], VALIDATOR_STAKE)

    state, block = creator.create_genesis()
    creator.export_genesis(state, block, str(GENESIS_FILE))

    log.info("genesis hash : %s", block.block_hash)
    log.info("state root   : %s", state.state_root)
    log.info("validators   : %d", len(state.validators))
    log.info("system wallets: %d (controller %s)", len(state.system_wallets), controller["address"][:24] + "...")
    log.info("wrote %s", GENESIS_FILE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
