#!/usr/bin/env python3
"""
Prepare the validator identity for a containerised QRDX node.

Behaviour, in order:

  1. If QRDX_VALIDATOR_ENABLED is not true -> no-op.
  2. If the wallet file at QRDX_VALIDATOR_WALLET already exists -> validate that
     it is loadable, print its address, and leave it untouched.
  3. Otherwise generate a new ML-DSA-65 (Dilithium3) keypair, write it there with
     0600 permissions, and print the address plus what to do next.

Idempotent, and it never overwrites an existing wallet — restarting the stack
reuses the same validator identity.

Environment
  QRDX_VALIDATOR_ENABLED  'true' to do anything at all          [false]
  QRDX_VALIDATOR_WALLET   Wallet path  [/app/data/validator/validator.json]
  QRDX_VALIDATOR_LABEL    Label stored in the wallet file       [QRDX Validator]

IMPORTANT — the wallet format this node loads is an UNENCRYPTED JSON file: the
Dilithium secret key is stored as plain hex (see qrdx/validator/node_integration.py,
which reads wallet_data['private_key'] directly). QRDX_VALIDATOR_PASSWORD is
accepted by that code path but is NOT used to encrypt or decrypt this file. Treat
the wallet file, and the Docker volume holding it, as the private key itself:
back it up, restrict access, and do not copy it onto shared storage.
"""
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[validator-init] %(message)s", stream=sys.stdout)
log = logging.getLogger("validator-init")

TRUTHY = ("1", "true", "yes", "on")

ENABLED = os.getenv("QRDX_VALIDATOR_ENABLED", "false").lower() in TRUTHY
WALLET_PATH = Path(os.getenv("QRDX_VALIDATOR_WALLET") or "/app/data/validator/validator.json")
LABEL = os.getenv("QRDX_VALIDATOR_LABEL", "QRDX Validator")

# qrdx/constants.py: MIN_VALIDATOR_STAKE
MIN_STAKE = "100,000"


def describe_existing(path: Path) -> int:
    """Validate a wallet the operator supplied (or a previously generated one)."""
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        log.error("wallet at %s is not readable JSON: %s", path, e)
        return 1

    missing = [k for k in ("address", "private_key", "public_key") if not data.get(k)]
    if missing:
        # public_key is not optional: a Dilithium secret key cannot re-derive its
        # public key, so a wallet without it restores as a DIFFERENT random
        # identity and the node would propose under an address nobody expects.
        log.error("wallet at %s is missing required field(s): %s", path, ", ".join(missing))
        return 1

    log.info("using existing validator wallet: %s", path)
    log.info("validator address: %s", data["address"])
    return 0


def generate(path: Path) -> int:
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        log.error("cannot create %s: %s", parent, e)
        return 1

    if not os.access(parent, os.W_OK):
        log.error(
            "no wallet at %s and its directory is not writable. Either mount an "
            "existing wallet there, or point QRDX_VALIDATOR_WALLET at a path "
            "inside the writable data volume (e.g. /app/data/validator/validator.json).",
            path,
        )
        return 1

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
        "label": LABEL,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    # Write 0600 before the key ever hits the file.
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(wallet, f, indent=2)

    log.info("generated a NEW validator wallet: %s", path)
    log.info("validator address: %s", wallet["address"])
    log.warning("This file holds an UNENCRYPTED private key. Back it up and keep it secret.")
    log.warning(
        "The node will run as a validator, but it only enters the active set once this "
        "address holds at least %s QRDX of stake (a STAKE_DEPOSIT transaction). Until "
        "then it syncs and serves like a full node.", MIN_STAKE
    )
    return 0


def main() -> int:
    if not ENABLED:
        log.info("QRDX_VALIDATOR_ENABLED is not true — nothing to prepare.")
        return 0

    if WALLET_PATH.exists():
        return describe_existing(WALLET_PATH)

    return generate(WALLET_PATH)


if __name__ == "__main__":
    sys.exit(main())
