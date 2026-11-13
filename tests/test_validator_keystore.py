"""
A validator's key (qrdx/validator/keystore.py): outside dev networks it lives only in an encrypted
keystore (scrypt + AES-256-GCM, bound to its address and public key); a plaintext key or an old
AES-128 keystore is refused, and a key whose parts do not belong together never loads.
"""

import base64
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from qrdx import chain_spec as cs
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.validator import keystore as K
from qrdx.validator.node_integration import ValidatorNode
from qrdx.wallet_v2 import base
from qrdx.wallet_v2.pq_wallet import PQWallet

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def quick_scrypt(monkeypatch):
    # The real cost (2^18) takes about a second per keystore; the format is the same.
    monkeypatch.setattr(base, "SCRYPT_N", 2**14)


def _plaintext(wallet: PQWallet, **overrides) -> dict:
    data = {
        "address": wallet.address,
        "public_key": wallet.public_key_hex,
        "private_key": wallet.export_private_key().hex(),
    }
    return {**data, **overrides}


def _write(tmp_path, name, data) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


def test_a_keystore_is_aes_256_gcm_under_scrypt_and_opens_to_the_same_key(tmp_path):
    wallet = PQWallet.generate()
    store = wallet.to_keystore(PASSWORD)
    assert store["version"] == 2
    assert store["crypto"]["cipher"] == "aes-256-gcm" and store["crypto"]["kdf"] == "scrypt"
    assert wallet.export_private_key().hex() not in json.dumps(store)
    path = _write(tmp_path, "v.json", store)
    loaded = K.load_validator_wallet(path, PASSWORD, allow_plaintext=False)
    assert loaded.address == wallet.address
    with pytest.raises(K.ValidatorKeyError, match="Invalid password"):
        K.load_validator_wallet(path, "wrong password!", allow_plaintext=False)
    with pytest.raises(K.ValidatorKeyError, match="is encrypted"):
        K.load_validator_wallet(path, None, allow_plaintext=False)


def test_a_keystore_whose_identity_was_swapped_does_not_open(tmp_path):
    wallet, other = PQWallet.generate(), PQWallet.generate()
    store = wallet.to_keystore(PASSWORD)
    swapped = {**store, "public_key": other.public_key_hex, "address": other.address}
    with pytest.raises(K.ValidatorKeyError, match="altered"):
        K.load_validator_wallet(
            _write(tmp_path, "s.json", swapped), PASSWORD, allow_plaintext=False
        )
    renamed = {**store, "address": other.address}
    with pytest.raises(K.ValidatorKeyError, match="altered"):
        K.load_validator_wallet(
            _write(tmp_path, "r.json", renamed), PASSWORD, allow_plaintext=False
        )


def test_a_keystore_asking_for_an_unbounded_kdf_is_refused_before_running_it(tmp_path):
    store = PQWallet.generate().to_keystore(PASSWORD)
    for n in (2**30, 2**10, 3 * 2**14):
        store["crypto"]["kdfparams"]["n"] = n
        with pytest.raises(K.ValidatorKeyError, match="outside what a keystore may use"):
            K.load_validator_wallet(
                _write(tmp_path, f"n{n}.json", store), PASSWORD, allow_plaintext=False
            )


def test_a_plaintext_key_is_refused_outside_dev_and_checked_on_dev(tmp_path):
    wallet = PQWallet.generate()
    path = _write(tmp_path, "plain.json", _plaintext(wallet))
    with pytest.raises(K.ValidatorKeyError, match="UNENCRYPTED"):
        K.load_validator_wallet(path, None, allow_plaintext=False)
    assert K.load_validator_wallet(path, None, allow_plaintext=True).address == wallet.address

    other = PQWallet.generate()
    no_pub = _write(tmp_path, "np.json", _plaintext(wallet, public_key=""))
    with pytest.raises(K.ValidatorKeyError, match="no public key"):
        K.load_validator_wallet(no_pub, None, allow_plaintext=True)
    wrong_addr = _write(tmp_path, "wa.json", _plaintext(wallet, address=other.address))
    with pytest.raises(K.ValidatorKeyError, match="names"):
        K.load_validator_wallet(wrong_addr, None, allow_plaintext=True)
    # Another key's public key and address: only signing reveals it.
    mixed = _write(
        tmp_path,
        "mx.json",
        _plaintext(wallet, public_key=other.public_key_hex, address=other.address),
    )
    with pytest.raises(K.ValidatorKeyError, match="does not match its public key"):
        K.load_validator_wallet(mixed, None, allow_plaintext=True)


def _legacy_keystore(wallet: PQWallet) -> dict:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1000)
    token = Fernet(base64.urlsafe_b64encode(kdf.derive(PASSWORD.encode()))).encrypt(
        wallet.export_private_key()
    )
    return {
        "version": 1,
        "address": wallet.address,
        "public_key": wallet.public_key_hex,
        "wallet_type": "pq",
        "crypto": {
            "ciphertext": base64.b64encode(token).decode(),
            "salt": salt.hex(),
            "iterations": 1000,
            "kdf": "pbkdf2-sha256",
            "cipher": "fernet",
        },
    }


def test_an_old_aes_128_keystore_opens_only_on_dev_and_upgrades(tmp_path):
    wallet = PQWallet.generate()
    old = _write(tmp_path, "old.json", _legacy_keystore(wallet))
    with pytest.raises(K.ValidatorKeyError, match="AES-128"):
        K.load_validator_wallet(old, PASSWORD, allow_plaintext=False)
    assert K.load_validator_wallet(old, PASSWORD, allow_plaintext=True).address == wallet.address


def test_the_password_comes_from_its_file_and_leaves_the_environment(tmp_path):
    secret = tmp_path / "pw"
    secret.write_text(PASSWORD + "\n")
    env = {K.PASSWORD_FILE_ENV: str(secret), K.PASSWORD_ENV: "other"}
    assert K.read_password(env) == PASSWORD and K.PASSWORD_ENV not in env
    env = {K.PASSWORD_ENV: PASSWORD}
    assert K.read_password(env) == PASSWORD and env == {}
    assert K.read_password({}) is None
    with pytest.raises(K.ValidatorKeyError, match="cannot read"):
        K.read_password({K.PASSWORD_FILE_ENV: str(tmp_path / "missing")})


@pytest.mark.asyncio
async def test_the_live_validator_refuses_a_plaintext_key_outside_dev(tmp_path):
    wallet = PQWallet.generate()
    path = _write(tmp_path, "plain.json", _plaintext(wallet))
    spec = cs.build_spec("qrdx-keytest", 4243, {}, dev=False)
    with cs.use_spec(spec):
        node = ValidatorNode(db=None, validator_wallet_path=str(path), password="")
        with pytest.raises(K.ValidatorKeyError, match="UNENCRYPTED"):
            await node.initialize()


def test_the_tool_encrypts_a_wallet_into_a_private_keystore(tmp_path):
    wallet = PQWallet.generate()
    plain = _write(tmp_path, "plain.json", _plaintext(wallet))
    pw = tmp_path / "pw"
    pw.write_text(PASSWORD + "\n")
    out = tmp_path / "validator.keystore.json"
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    tool = [sys.executable, str(ROOT / "scripts/validator/keystore.py")]
    run = subprocess.run(
        tool + ["encrypt", "--in", str(plain), "--out", str(out), "--password-file", str(pw)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert json.loads(out.read_text())["kind"] == "qrdx-validator"
    assert K.load_validator_wallet(out, PASSWORD, allow_plaintext=False).address == wallet.address
    again = subprocess.run(
        tool + ["encrypt", "--in", str(plain), "--out", str(out), "--password-file", str(pw)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert again.returncode == 2 and "refused" in again.stderr  # never over an existing file


def test_restoring_a_key_without_its_public_key_has_no_identity():
    key = PQPrivateKey.generate()
    restored = PQPrivateKey.from_bytes(key.to_bytes())
    with pytest.raises(Exception):  # noqa: B017 - any refusal, never a random identity
        _ = restored.public_key.to_address()
