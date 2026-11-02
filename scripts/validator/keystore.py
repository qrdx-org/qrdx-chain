#!/usr/bin/env python3
"""
A validator's keystore: create one, encrypt a plaintext wallet, upgrade an old keystore, check one.

Outside dev networks the node accepts only an encrypted keystore (qrdx/validator/keystore.py):
scrypt and AES-256-GCM, bound to the address and public key it holds.

    python scripts/validator/keystore.py new --out validator.keystore.json
    python scripts/validator/keystore.py encrypt --in validator.json --out validator.keystore.json
    python scripts/validator/keystore.py upgrade --in old.keystore.json --out validator.keystore.json
    python scripts/validator/keystore.py check validator.keystore.json

Passwords are asked for (twice for a new one) unless ``--password-file`` names a file holding
one. Run the node with ``QRDX_VALIDATOR_WALLET`` at the keystore and ``QRDX_VALIDATOR_PASSWORD_FILE``
at the password file.

Files are written with mode 0600 and never over an existing file. After ``encrypt``, delete the
plaintext wallet; keep an offline backup of the keystore and its password.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from qrdx.validator.keystore import ValidatorKeyError, load_validator_wallet  # noqa: E402
from qrdx.wallet_v2.pq_wallet import PQWallet  # noqa: E402

MIN_PASSWORD = 12


def _password(args, *, new: bool, prompt: str = "keystore password") -> str:
    if args.password_file:
        text = Path(args.password_file).read_text(encoding="utf-8")
        password = text[:-1] if text.endswith("\n") else text
    else:
        password = getpass.getpass(f"{prompt}: ")
        if new and getpass.getpass("again: ") != password:
            raise SystemExit("the passwords differ")
    if new and len(password) < MIN_PASSWORD:
        raise SystemExit(f"use a password of at least {MIN_PASSWORD} characters")
    return password


def _write(wallet: PQWallet, password: str, out: str) -> None:
    keystore = wallet.to_keystore(password)
    keystore["kind"] = "qrdx-validator"
    fd = os.open(out, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(keystore, f, indent=2)
        f.write("\n")
    # Prove the file opens before anyone relies on it.
    reopened = load_validator_wallet(out, password, allow_plaintext=False)
    if reopened.address != wallet.address:
        raise SystemExit(f"{out} reopened as {reopened.address}, not {wallet.address}")
    print(f"wrote {out} (mode 0600) for validator {wallet.address}")


def cmd_new(args) -> int:
    wallet = PQWallet.generate()
    _write(wallet, _password(args, new=True), args.out)
    print("back up the keystore and its password offline; the key exists nowhere else")
    return 0


def cmd_encrypt(args) -> int:
    wallet = load_validator_wallet(args.infile, None, allow_plaintext=True)
    _write(wallet, _password(args, new=True), args.out)
    print(f"now delete the plaintext wallet {args.infile} (e.g. shred -u)")
    return 0


def cmd_upgrade(args) -> int:
    old = _password(args, new=False, prompt="the old keystore's password")
    wallet = load_validator_wallet(args.infile, old, allow_plaintext=True)
    _write(wallet, old, args.out)
    print(f"the new keystore keeps the same password; delete {args.infile} once it runs")
    return 0


def cmd_check(args) -> int:
    wallet = load_validator_wallet(args.path, _password(args, new=False), allow_plaintext=False)
    print(f"ok: {args.path} opens, and its key signs as {wallet.address}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("new", help="create a new validator key in a keystore")
    p.add_argument("--out", required=True)
    p = sub.add_parser("encrypt", help="encrypt a plaintext validator wallet")
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("upgrade", help="re-encrypt an old (AES-128) keystore")
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("check", help="open a keystore and check its key")
    p.add_argument("path")
    for name in ("new", "encrypt", "upgrade", "check"):
        sub.choices[name].add_argument("--password-file", help="read the password from this file")
    args = ap.parse_args(argv)
    try:
        return {"new": cmd_new, "encrypt": cmd_encrypt, "upgrade": cmd_upgrade, "check": cmd_check}[
            args.cmd
        ](args)
    except (ValidatorKeyError, FileExistsError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
