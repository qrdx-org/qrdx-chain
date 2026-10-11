"""
ContractTransaction.sign / verify_signature (qrdx/transactions/contract_transaction.py).

Both called the signing helpers with the wrong arguments, so signing raised TypeError and no
contract transaction could ever be verified. They now sign the transaction hash with
secp256k1 (or ML-DSA when asked) and verify it; tampering, a wrong key or malformed bytes
fail verification rather than raising.
"""
from decimal import Decimal

import pytest

from qrdx.crypto.keys import PrivateKey
from qrdx.transactions.contract_transaction import ContractTransaction


def _tx(**kw):
    base = dict(nonce=0, sender="0x" + "11" * 20, value=Decimal("1"), gas_limit=21_000,
                gas_price=1, data=b"", to="0x" + "22" * 20)
    base.update(kw)
    return ContractTransaction(**base)


def test_an_ecdsa_signed_contract_transaction_verifies():
    key = PrivateKey.generate()
    tx = _tx()
    tx.sign(key.to_bytes())
    assert tx.signature and tx.public_key == key.public_key.to_bytes()
    assert tx.verify_signature() is True


def test_tampering_or_another_key_fails_verification():
    tx = _tx()
    tx.sign(PrivateKey.generate().to_bytes())
    tx.value = Decimal("2")                                  # the signed hash no longer matches
    assert tx.verify_signature() is False

    other = _tx()
    other.sign(PrivateKey.generate().to_bytes())
    other.public_key = PrivateKey.generate().public_key.to_bytes()
    assert other.verify_signature() is False


def test_malformed_signature_bytes_fail_rather_than_raise():
    tx = _tx()
    tx.sign(PrivateKey.generate().to_bytes())
    tx.signature = b"\x01\x02"
    assert tx.verify_signature() is False


def test_an_unknown_signature_type_is_refused():
    with pytest.raises(ValueError):
        _tx().sign(PrivateKey.generate().to_bytes(), signature_type="rsa")
