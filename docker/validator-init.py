#!/usr/bin/env python3
"""
Prepare the validator identity for a containerised QRDX node.

Behaviour, in order:

  1. If QRDX_VALIDATOR_ENABLED is not true -> no-op.
  2. If the wallet file at QRDX_VALIDATOR_WALLET already exists -> check it: an encrypted
     keystore must open with the configured password; a PLAINTEXT wallet (an older stack
     wrote those) is encrypted in place with it, keeping its key, when the file is writable.
  3. Otherwise generate a new ML-DSA-65 key into an encrypted keystore there, mode 0600.

Outside dev networks the node accepts only an encrypted keystore (scrypt and AES-256-GCM:
qrdx/validator/keystore.py) and refuses a plaintext key, so a password is required. Idempotent:
it never replaces a key — restarting the stack reuses the same validator identity.

Environment
  QRDX_VALIDATOR_ENABLED        'true' to do anything at all    [false]
  QRDX_VALIDATOR_WALLET         Keystore path  [/app/data/validator/validator.json]
  QRDX_VALIDATOR_LABEL          Name recorded with a new key [QRDX Validator]
  QRDX_VALIDATOR_PASSWORD_FILE  File holding the keystore password (a secret)
  QRDX_VALIDATOR_PASSWORD       The password itself, if no file is given

Keep an offline backup of the keystore and its password; scripts/validator/keystore.py
creates, encrypts, upgrades and checks keystores.
"""
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[validator-init] %(message)s", stream=sys.stdout)
log = logging.getLogger("validator-init")

TRUTHY = ("1", "true", "yes", "on")

ENABLED = os.getenv("QRDX_VALIDATOR_ENABLED", "false").lower() in TRUTHY
WALLET_PATH = Path(os.getenv("QRDX_VALIDATOR_WALLET") or "/app/data/validator/validator.json")
LABEL = os.getenv("QRDX_VALIDATOR_LABEL", "QRDX Validator")

# qrdx/constants.py: MIN_VALIDATOR_STAKE
MIN_STAKE = "100,000"


def _password():
    from qrdx.validator.keystore import read_password

    return read_password(dict(os.environ))


def describe_existing(path: Path) -> int:
    """Check a wallet the operator supplied (or a previously generated one); encrypt a plaintext
    one in place."""
    from qrdx.validator.keystore import ValidatorKeyError, encrypt_in_place, load_validator_wallet

    try:
        data = json.loads(path.read_text())
    except Exception as e:
        log.error("wallet at %s is not readable JSON: %s", path, e)
        return 1
    secret = "crypto" if "crypto" in data else "private_key"
    missing = [k for k in ("address", secret, "public_key") if not data.get(k)]
    if missing:
        # public_key is not optional: a Dilithium secret key cannot re-derive its
        # public key, so a wallet without it restores as a DIFFERENT random
        # identity and the node would propose under an address nobody expects.
        log.error("wallet at %s is missing required field(s): %s", path, ", ".join(missing))
        return 1

    password = _password()
    if not password:
        log.error("no keystore password: set QRDX_VALIDATOR_PASSWORD (or QRDX_VALIDATOR_PASSWORD_FILE)")
        return 1
    try:
        if secret == "private_key":
            if not os.access(path, os.W_OK) or not os.access(path.parent, os.W_OK):
                log.error(
                    "%s holds an UNENCRYPTED key, which the node refuses outside a dev network, "
                    "and it is read-only here: encrypt it with `python scripts/validator/keystore.py "
                    "encrypt` and mount the keystore instead", path
                )
                return 1
            wallet = encrypt_in_place(path, password)
            log.warning("encrypted the plaintext validator wallet %s in place (same key)", path)
        else:
            wallet = load_validator_wallet(path, password, allow_plaintext=False)
    except ValidatorKeyError as e:
        log.error("%s", e)
        return 1
    log.info("using validator keystore: %s", path)
    log.info("validator address: %s", wallet.address)
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
            "existing keystore there, or point QRDX_VALIDATOR_WALLET at a path "
            "inside the writable data volume (e.g. /app/data/validator/validator.json).",
            path,
        )
        return 1

    password = _password()
    if not password:
        log.error(
            "no keystore password: set QRDX_VALIDATOR_PASSWORD (or QRDX_VALIDATOR_PASSWORD_FILE). "
            "The node accepts a validator key only in an encrypted keystore outside a dev network."
        )
        return 1

    from qrdx.validator.keystore import write_keystore
    from qrdx.wallet_v2.pq_wallet import PQWallet

    wallet = write_keystore(PQWallet.generate(LABEL), password, path)
    log.info("generated a NEW encrypted validator keystore: %s", path)
    log.info("validator address: %s", wallet.address)
    log.warning("Back up the keystore and its password: the key exists nowhere else.")
    log.warning(
        "If genesis-init writes this chain's genesis next, this address becomes its genesis "
        "validator and proposes from block 1. Joining an EXISTING chain instead, it only "
        "enters the active set once it holds at least %s QRDX of stake (a STAKE_DEPOSIT "
        "transaction); until then it syncs and serves like a full node.", MIN_STAKE
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
