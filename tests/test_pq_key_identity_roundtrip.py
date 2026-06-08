"""
Dilithium key identity must survive save→load (regression).

A Dilithium secret key cannot re-derive its public key, so restoring a key from
bytes WITHOUT the stored public key makes PQPrivateKey generate a brand-new random
keypair (dilithium._restore_from_bytes), yielding a DIFFERENT address. This silent
identity change was the root cause of validator-set non-convergence: each validator
loaded its wallet, derived a wrong/random address, registered + proposed under it,
and so never matched its genesis registration → every node thought it was the sole
proposer → reorg churn.

These tests pin that providing the public key on restore preserves the address,
and that omitting it does NOT (so the footgun stays documented and callers are
forced to pass the public key).
"""

from qrdx.crypto.pq.dilithium import PQPrivateKey, PQPublicKey


def test_roundtrip_with_public_key_preserves_address():
    k = PQPrivateKey.generate()
    addr = k.address
    pub_hex = k.public_key.to_hex()
    restored = PQPrivateKey.from_hex(k.to_hex(), public_key_hex=pub_hex)
    assert restored.address == addr, "address must survive save/load with public key"
    assert restored.public_key.to_hex() == pub_hex


def test_roundtrip_without_public_key_does_not_preserve_address():
    """Documents the footgun: omitting the public key yields a different address."""
    k = PQPrivateKey.generate()
    restored = PQPrivateKey.from_hex(k.to_hex())  # no public key
    assert restored.address != k.address, (
        "restoring without the public key unexpectedly preserved the address — "
        "if this ever holds, the from_hex public-key requirement can be relaxed"
    )


def test_pqwallet_loaded_with_public_key_matches_stored_address():
    """Mirror node_integration's wallet load: the restored wallet's address must
    equal the address stored in the wallet file."""
    from qrdx.wallet_v2.pq_wallet import PQWallet

    k = PQPrivateKey.generate()
    stored_address = k.address
    stored_priv = k.to_hex()
    stored_pub = k.public_key.to_hex()

    reloaded_key = PQPrivateKey.from_hex(stored_priv, public_key_hex=stored_pub)
    wallet = PQWallet(private_key=reloaded_key)
    assert wallet.address == stored_address
