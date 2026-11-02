"""
Loading a validator's signing key.

A validator's key signs its blocks and votes. Whoever reads it can sign as the validator, or
double-sign to get its stake slashed. So on a real network the key lives only in an encrypted
keystore: scrypt and AES-256-GCM, bound to the address and public key it holds
(qrdx/wallet_v2/base.py). The node refuses a plaintext key, and refuses the older AES-128
"fernet" keystores, which ``scripts/validator/keystore.py upgrade`` re-encrypts. Dev networks may
still use the plaintext wallets the local testnet scripts write.

The password comes from the file named by ``QRDX_VALIDATOR_PASSWORD_FILE`` (preferred: a
container secret, say) or from ``QRDX_VALIDATOR_PASSWORD``. The variable is removed from the
environment once read, so processes the node starts do not inherit it.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, MutableMapping, Optional

from ..crypto.pq.dilithium import PQPrivateKey
from ..logger import get_logger
from ..wallet_v2.base import KEYSTORE_CIPHER, WalletError
from ..wallet_v2.pq_wallet import PQWallet

logger = get_logger(__name__)

PASSWORD_ENV = "QRDX_VALIDATOR_PASSWORD"
PASSWORD_FILE_ENV = "QRDX_VALIDATOR_PASSWORD_FILE"

_KEYPAIR_CHECK = b"qrdx validator keypair check"


class ValidatorKeyError(Exception):
    """The validator's key cannot be loaded safely; the node must not start as a validator."""


def read_password(env: Optional[MutableMapping[str, str]] = None) -> Optional[str]:
    """The keystore password: from ``QRDX_VALIDATOR_PASSWORD_FILE``, else the variable itself.

    Removes ``QRDX_VALIDATOR_PASSWORD`` from the environment it reads. Returns None if neither
    is set."""
    env = os.environ if env is None else env
    path = env.get(PASSWORD_FILE_ENV)
    password = env.pop(PASSWORD_ENV, None)
    if path:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ValidatorKeyError(f"cannot read {PASSWORD_FILE_ENV} ({path}): {exc}") from exc
        # One trailing newline is the file's, not the password's.
        return text[:-1] if text.endswith("\n") else text
    return password or None


def _check_keypair(wallet: PQWallet, address: Optional[str]) -> PQWallet:
    if address and wallet.address != address:
        raise ValidatorKeyError(
            f"the validator wallet names {address}, but its key is {wallet.address}"
        )
    if not wallet.verify(_KEYPAIR_CHECK, wallet.sign(_KEYPAIR_CHECK)):
        raise ValidatorKeyError("the validator wallet's secret key does not match its public key")
    return wallet


def _private_to_others(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO))
    except OSError:
        return False


def load_validator_wallet(
    path: str | Path, password: Optional[str], *, allow_plaintext: bool
) -> PQWallet:
    """Load and check the validator's key.

    Args:
        path: the keystore (or, on dev networks, a plaintext wallet)
        password: the keystore's password
        allow_plaintext: whether a plaintext key or a legacy keystore is acceptable (dev
            networks only)

    Raises:
        ValidatorKeyError: the key cannot be loaded safely.
    """
    path = Path(path)
    try:
        data: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidatorKeyError(f"cannot read the validator wallet {path}: {exc}") from exc
    if _private_to_others(path):
        logger.warning("the validator wallet %s is readable by other users: chmod 600 it", path)

    if "crypto" in data:
        legacy = data["crypto"].get("cipher") != KEYSTORE_CIPHER
        if legacy and not allow_plaintext:
            raise ValidatorKeyError(
                f"{path} uses the old AES-128 keystore cipher; re-encrypt it with "
                "`python scripts/validator/keystore.py upgrade` before running on this network"
            )
        if not password:
            raise ValidatorKeyError(
                f"{path} is encrypted: set {PASSWORD_FILE_ENV} (or {PASSWORD_ENV})"
            )
        try:
            wallet = PQWallet.from_keystore(data, password)
        except WalletError as exc:
            raise ValidatorKeyError(f"cannot open the validator keystore {path}: {exc}") from exc
        if legacy:
            logger.warning("%s uses the old AES-128 keystore cipher; upgrade it", path)
        return _check_keypair(wallet, data.get("address"))

    if "private_key" not in data:
        raise ValidatorKeyError(f"{path} holds neither a keystore nor a key")
    if not allow_plaintext:
        raise ValidatorKeyError(
            f"{path} holds an UNENCRYPTED key, which this network refuses: anyone who reads "
            "the file can sign as this validator. Encrypt it with "
            "`python scripts/validator/keystore.py encrypt` and point QRDX_VALIDATOR_WALLET "
            "at the keystore"
        )
    public_key_hex = data.get("public_key")
    if not public_key_hex:
        # An ML-DSA secret key cannot re-derive its public key: without it there is no identity.
        raise ValidatorKeyError(f"{path} has no public key; the validator cannot be restored")
    logger.warning("the validator key in %s is UNENCRYPTED (accepted on a dev network only)", path)
    key = PQPrivateKey.from_hex(data["private_key"], public_key_hex=public_key_hex)
    return _check_keypair(PQWallet(private_key=key), data.get("address"))
