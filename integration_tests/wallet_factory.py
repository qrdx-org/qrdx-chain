"""
Wallet Factory — Generate Real PQ and Traditional Wallets

Uses the actual QRDX crypto libraries (liboqs for PQ, eth-keys for classical).
Zero stubs — every wallet contains real cryptographic key material.
"""

import json
import logging
import os
import sys
import time
from decimal import Decimal
from pathlib import Path
from typing import Dict, List, Tuple

from integration_tests.config import WALLETS_DIR, WALLET_ROSTER, WalletSpec

logger = logging.getLogger(__name__)


def generate_pq_wallet(label: str, wallet_path: str) -> dict:
    """
    Generate a real PQ (Dilithium3 / ML-DSA-65) wallet.

    Uses liboqs — fails hard if not installed (no fallback).
    """
    from qrdx.crypto.pq.dilithium import PQPrivateKey

    private_key = PQPrivateKey.generate()
    public_key = private_key.public_key
    address = public_key.to_address()

    wallet = {
        "version": "2.0",
        "type": "pq",
        "algorithm": "dilithium3",
        "address": address,
        "public_key": public_key.to_hex(),
        "private_key": private_key.to_hex(),
        "label": label,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    os.makedirs(os.path.dirname(wallet_path), exist_ok=True)
    with open(wallet_path, "w") as f:
        json.dump(wallet, f, indent=2)

    logger.info("PQ wallet generated: %s → %s", label, address[:30] + "...")
    return wallet


def generate_traditional_wallet(label: str, wallet_path: str) -> dict:
    """
    Generate a real secp256k1 traditional wallet.

    Uses eth-keys — Ethereum-compatible addressing.
    """
    from qrdx.crypto.keys import PrivateKey as ClassicalPrivateKey

    private_key = ClassicalPrivateKey.generate()
    public_key = private_key.public_key
    address = public_key.to_address()

    wallet = {
        "version": "2.0",
        "type": "traditional",
        "algorithm": "secp256k1",
        "address": address,
        "public_key": public_key.to_hex(),
        "private_key": private_key.to_hex(),
        "label": label,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    os.makedirs(os.path.dirname(wallet_path), exist_ok=True)
    with open(wallet_path, "w") as f:
        json.dump(wallet, f, indent=2)

    logger.info("Traditional wallet generated: %s → %s", label, address)
    return wallet


def generate_all_wallets(
    roster: List[WalletSpec] = None,
    wallets_dir: str = None,
    force: bool = False,
) -> Dict[str, dict]:
    """
    Generate all wallets defined in the roster.

    Returns: dict mapping label → wallet dict (with address, keys, etc.)

    If force=False and wallet files already exist, reloads them
    instead of regenerating (preserving addresses for test continuity).
    """
    if roster is None:
        roster = WALLET_ROSTER
    if wallets_dir is None:
        wallets_dir = str(WALLETS_DIR)

    os.makedirs(wallets_dir, exist_ok=True)
    wallets = {}

    for spec in roster:
        # Filename: sanitize label
        safe_name = spec.label.lower().replace(" ", "_").replace("(", "").replace(")", "")
        wallet_path = os.path.join(wallets_dir, f"{safe_name}.json")

        if not force and os.path.exists(wallet_path):
            with open(wallet_path) as f:
                wallet = json.load(f)
            logger.info("Loaded existing wallet: %s → %s", spec.label, wallet["address"][:30])
        elif spec.wallet_type == "pq":
            wallet = generate_pq_wallet(spec.label, wallet_path)
        elif spec.wallet_type == "traditional":
            wallet = generate_traditional_wallet(spec.label, wallet_path)
        else:
            raise ValueError(f"Unknown wallet type: {spec.wallet_type}")

        # Attach metadata
        wallet["_spec"] = {
            "label": spec.label,
            "wallet_type": spec.wallet_type,
            "genesis_balance": str(spec.genesis_balance),
            "is_validator": spec.is_validator,
            "validator_index": spec.validator_index,
        }
        wallets[spec.label] = wallet

    logger.info("Generated/loaded %d wallets", len(wallets))
    return wallets


def load_wallet(wallet_path: str) -> dict:
    """Load a wallet from disk."""
    with open(wallet_path) as f:
        return json.load(f)


def get_wallet_address(wallet: dict) -> str:
    """Extract address from wallet dict."""
    return wallet["address"]


def get_wallet_private_key_hex(wallet: dict) -> str:
    """Extract private key hex from wallet dict."""
    return wallet["private_key"]


def get_wallet_public_key_hex(wallet: dict) -> str:
    """Extract public key hex from wallet dict."""
    return wallet["public_key"]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    wallets = generate_all_wallets(force=True)
    print(f"\nGenerated {len(wallets)} wallets:")
    for label, w in wallets.items():
        print(f"  {label}: {w['address'][:40]}... ({w['type']})")
