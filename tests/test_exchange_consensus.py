"""
Exchange consensus-readiness tests: authentication, determinism, tamper detection.

These cover the security/consensus properties an exchange transaction must satisfy
before it can be trusted in a block (see docs/EXCHANGE_PRODUCTION_READINESS.md):

  - Authenticity + binding: only a valid Dilithium signature whose key derives to
    ``sender`` authenticates a transaction; tampering, wrong key, wrong sender,
    or a missing signature are all rejected.
  - Determinism: replaying the same transaction sequence yields a byte-identical
    ``exchange_state_root`` on any node.
  - Tamper detection: mutating any included transaction changes the state root,
    and ``validate_exchange_state_root`` rejects a header root that doesn't match.
"""

from decimal import Decimal

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import (
    ExchangeStateManager,
    ExchangeTransaction,
    ExchangeOpType,
    PerpSide,
    process_exchange_transactions,
    validate_exchange_state_root,
    verify_exchange_tx,
)
from qrdx.exchange.amm import FeeTier, PoolType


# ─────────────────────────────────────────────────────────────────────────
#  Signing helpers
# ─────────────────────────────────────────────────────────────────────────

def _new_signer():
    key = PQPrivateKey.generate()
    return key, key.public_key.to_address()


def _sign(tx: ExchangeTransaction, key: PQPrivateKey) -> ExchangeTransaction:
    """Attach a valid Dilithium signature + public key to a transaction."""
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


def _create_pool_tx(sender: str, nonce: int = 0) -> ExchangeTransaction:
    return ExchangeTransaction(
        op_type=ExchangeOpType.CREATE_POOL,
        sender=sender,
        nonce=nonce,
        params={
            "token0": "qBTC", "token1": "qUSD",
            "fee_tier": int(FeeTier.MEDIUM),
            "pool_type": int(PoolType.STANDARD),
            "initial_sqrt_price": "173.205080756",
            "stake_amount": "10000",
        },
        gas_limit=1_000_000,
        gas_price=Decimal("1"),
    )


# ─────────────────────────────────────────────────────────────────────────
#  Authentication
# ─────────────────────────────────────────────────────────────────────────

class TestExchangeTxAuthentication:
    def test_valid_signature_passes(self):
        key, addr = _new_signer()
        tx = _sign(_create_pool_tx(addr), key)
        assert tx.verify() is True
        ok, err = verify_exchange_tx(tx)
        assert ok, err

    def test_unsigned_tx_rejected(self):
        _, addr = _new_signer()
        tx = _create_pool_tx(addr)  # no signature attached
        assert tx.verify() is False
        ok, err = verify_exchange_tx(tx)
        assert not ok and "signature" in err

    def test_tampered_params_rejected(self):
        """A signature is bound to the exact params — mutate them and it fails."""
        key, addr = _new_signer()
        tx = _sign(_create_pool_tx(addr), key)
        assert tx.verify() is True
        # Attacker bumps the stake field after signing.
        tx.params["stake_amount"] = "1"
        assert tx.verify() is False

    def test_tampered_nonce_rejected(self):
        key, addr = _new_signer()
        tx = _sign(_create_pool_tx(addr, nonce=0), key)
        tx.nonce = 5
        assert tx.verify() is False

    def test_wrong_key_rejected(self):
        """Signing with a different key than the embedded/declared one fails."""
        key, addr = _new_signer()
        other, _ = _new_signer()
        tx = _create_pool_tx(addr)
        tx.public_key = key.public_key.to_bytes()
        tx.signature = other.sign(tx.signing_bytes()).to_bytes()  # signed by 'other'
        assert tx.verify() is False

    def test_sender_spoofing_rejected(self):
        """
        Key+signature are internally consistent, but the declared sender is a
        victim address the key does not derive to — must be rejected (binding).
        """
        key, attacker_addr = _new_signer()
        _, victim_addr = _new_signer()
        tx = _create_pool_tx(victim_addr)        # claim to be the victim
        tx.public_key = key.public_key.to_bytes()  # attacker's real key
        tx.signature = key.sign(tx.signing_bytes()).to_bytes()
        assert tx.verify() is False
        ok, _ = verify_exchange_tx(tx)
        assert not ok

    def test_structurally_invalid_rejected_before_sig(self):
        key, addr = _new_signer()
        tx = _sign(_create_pool_tx(addr), key)
        tx.gas_limit = 0  # structural failure
        ok, err = verify_exchange_tx(tx)
        assert not ok and "structure" in err


# ─────────────────────────────────────────────────────────────────────────
#  Determinism + tamper detection (state root)
# ─────────────────────────────────────────────────────────────────────────

class TestExchangeConsensusStateRoot:
    def _build_block_txs(self):
        """A small deterministic block: pool + two crossing limit orders."""
        mk_key, mk = _new_signer()
        tk_key, tk = _new_signer()
        return [
            _create_pool_tx(mk, nonce=0),
            ExchangeTransaction(
                op_type=ExchangeOpType.PLACE_ORDER, sender=mk, nonce=1,
                params={"pair": "qBTC:qUSD", "side": "sell",
                        "order_type": "limit", "price": "30000", "amount": "1"},
                gas_limit=1_000_000, gas_price=Decimal("1"),
            ),
            ExchangeTransaction(
                op_type=ExchangeOpType.PLACE_ORDER, sender=tk, nonce=0,
                params={"pair": "qBTC:qUSD", "side": "buy",
                        "order_type": "limit", "price": "30000", "amount": "1"},
                gas_limit=1_000_000, gas_price=Decimal("1"),
            ),
        ]

    def test_identical_sequences_produce_identical_root(self):
        txs_a = self._build_block_txs()
        txs_b = self._build_block_txs()
        # Same op sequence/params (addresses differ but structure identical) —
        # use the SAME txs object replayed on two fresh engines for exact equality.
        mgr1 = ExchangeStateManager.reset_instance() or ExchangeStateManager.get_instance()
        ok1, err1, root1 = process_exchange_transactions(1, 1_700_000_000.0, txs_a, mgr1)
        assert ok1, err1

        ExchangeStateManager.reset_instance()
        mgr2 = ExchangeStateManager.get_instance()
        ok2, err2, root2 = process_exchange_transactions(1, 1_700_000_000.0, txs_a, mgr2)
        assert ok2, err2

        assert root1 == root2, "identical block replay must yield identical state root"
        assert root1 and root1 != "0" * 64

    def test_tampered_tx_changes_root_and_fails_validation(self):
        txs = self._build_block_txs()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        ok, err, honest_root = process_exchange_transactions(1, 1_700_000_000.0, txs, mgr)
        assert ok, err

        # Tamper: change the taker's order amount.
        tampered = self._build_block_txs()
        tampered[2].params["amount"] = "2"
        ExchangeStateManager.reset_instance()
        mgr2 = ExchangeStateManager.get_instance()
        ok2, _, tampered_root = process_exchange_transactions(1, 1_700_000_000.0, tampered, mgr2)
        assert ok2
        assert tampered_root != honest_root, "tampering must change the state root"

        # A node importing the tampered body against the honest header root rejects it.
        ExchangeStateManager.reset_instance()
        mgr3 = ExchangeStateManager.get_instance()
        valid, verr = validate_exchange_state_root(
            1, 1_700_000_000.0, tampered, honest_root, mgr3,
        )
        assert not valid and verr, "state-root validation must reject a tampered block body"

    def test_honest_block_validates_against_its_own_root(self):
        txs = self._build_block_txs()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        ok, err, root = process_exchange_transactions(1, 1_700_000_000.0, txs, mgr)
        assert ok, err

        ExchangeStateManager.reset_instance()
        mgr2 = ExchangeStateManager.get_instance()
        valid, verr = validate_exchange_state_root(1, 1_700_000_000.0, txs, root, mgr2)
        assert valid, f"honest block must validate against its own root: {verr}"
