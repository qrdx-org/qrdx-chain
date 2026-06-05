"""
Phase D1 — exchange mempool admission tests.

Covers the admission gate that decides which exchange transactions are eligible
for a block (see docs/EXCHANGE_PRODUCTION_READINESS.md §4 Phase D1):

  - authentication: unsigned / tampered / spoofed txs are refused entry;
  - replay/dedup: a tx hash and a (sender, nonce) pair admit at most once;
  - nonce window: stale and far-future nonces are refused;
  - capacity: global and per-sender caps;
  - canonical selection: deterministic, gap-free, executable ordering;
  - removal / stale pruning after state advances.
"""

from decimal import Decimal

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeMempool, ExchangeTransaction, ExchangeOpType
from qrdx.exchange.amm import FeeTier, PoolType


# ── Helpers ────────────────────────────────────────────────────────────

def _signer():
    key = PQPrivateKey.generate()
    return key, key.public_key.to_address()


def _order_tx(sender, nonce, key, side="buy", amount="1"):
    tx = ExchangeTransaction(
        op_type=ExchangeOpType.PLACE_ORDER,
        sender=sender,
        nonce=nonce,
        params={"pair": "qBTC:qUSD", "side": side, "order_type": "limit",
                "price": "30000", "amount": amount},
        gas_limit=1_000_000,
        gas_price=Decimal("1"),
    )
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


def _fixed_nonce_provider(table):
    """Nonce provider backed by an explicit {address: expected_nonce} dict."""
    return lambda addr: table.get(addr, 0)


# ── Authentication ─────────────────────────────────────────────────────

class TestAdmissionAuth:
    def test_valid_signed_tx_admitted(self):
        key, addr = _signer()
        mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider({addr: 0}))
        ok, err = mp.admit(_order_tx(addr, 0, key))
        assert ok, err
        assert mp.size() == 1

    def test_unsigned_tx_rejected(self):
        key, addr = _signer()
        mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider({addr: 0}))
        tx = _order_tx(addr, 0, key)
        tx.signature = b""  # strip signature
        ok, err = mp.admit(tx)
        assert not ok and "signature" in err
        assert mp.size() == 0

    def test_tampered_after_signing_rejected(self):
        key, addr = _signer()
        mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider({addr: 0}))
        tx = _order_tx(addr, 0, key)
        tx.params["amount"] = "999"  # mutate post-signature
        ok, err = mp.admit(tx)
        assert not ok

    def test_sender_spoof_rejected(self):
        key, attacker = _signer()
        _, victim = _signer()
        mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider({victim: 0}))
        tx = _order_tx(victim, 0, key)  # claims victim, signed by attacker key
        ok, err = mp.admit(tx)
        assert not ok


# ── Replay / dedup ─────────────────────────────────────────────────────

class TestAdmissionDedup:
    def test_duplicate_hash_rejected(self):
        key, addr = _signer()
        mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider({addr: 0}))
        tx = _order_tx(addr, 0, key)
        assert mp.admit(tx)[0]
        ok, err = mp.admit(tx)
        assert not ok and "duplicate" in err
        assert mp.size() == 1

    def test_same_nonce_different_tx_rejected(self):
        key, addr = _signer()
        mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider({addr: 0}))
        assert mp.admit(_order_tx(addr, 0, key, side="buy"))[0]
        # different params (=> different hash) but same nonce
        ok, err = mp.admit(_order_tx(addr, 0, key, side="sell"))
        assert not ok and "already queued" in err
        assert mp.size() == 1


# ── Nonce window ───────────────────────────────────────────────────────

class TestAdmissionNonce:
    def test_stale_nonce_rejected(self):
        key, addr = _signer()
        mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider({addr: 5}))
        ok, err = mp.admit(_order_tx(addr, 4, key))
        assert not ok and "too low" in err

    def test_far_future_nonce_rejected(self):
        key, addr = _signer()
        mp = ExchangeMempool(max_nonce_gap=8, nonce_provider=_fixed_nonce_provider({addr: 0}))
        ok, err = mp.admit(_order_tx(addr, 100, key))
        assert not ok and "too far ahead" in err

    def test_future_within_gap_admitted(self):
        key, addr = _signer()
        mp = ExchangeMempool(max_nonce_gap=8, nonce_provider=_fixed_nonce_provider({addr: 0}))
        assert mp.admit(_order_tx(addr, 3, key))[0]


# ── Capacity ───────────────────────────────────────────────────────────

class TestAdmissionCapacity:
    def test_global_cap(self):
        table = {}
        mp = ExchangeMempool(max_size=2, nonce_provider=_fixed_nonce_provider(table))
        for i in range(3):
            key, addr = _signer()
            table[addr] = 0
            ok, err = mp.admit(_order_tx(addr, 0, key))
            if i < 2:
                assert ok
            else:
                assert not ok and "full" in err
        assert mp.size() == 2

    def test_per_sender_cap(self):
        key, addr = _signer()
        mp = ExchangeMempool(max_per_sender=2, nonce_provider=_fixed_nonce_provider({addr: 0}))
        assert mp.admit(_order_tx(addr, 0, key))[0]
        assert mp.admit(_order_tx(addr, 1, key))[0]
        ok, err = mp.admit(_order_tx(addr, 2, key))
        assert not ok and "per-sender" in err


# ── Canonical selection + removal ──────────────────────────────────────

class TestSelectionAndRemoval:
    def test_select_is_gap_free_and_ordered(self):
        key, addr = _signer()
        mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider({addr: 0}))
        # admit nonces 0,1,3 (2 is missing → a gap)
        for n in (0, 1, 3):
            assert mp.admit(_order_tx(addr, n, key))[0]
        sel = mp.select_for_block()
        assert [t.nonce for t in sel] == [0, 1], "selection must stop at the nonce gap"

    def test_select_deterministic_across_instances(self):
        # Two senders, several nonces each; selection order must be identical.
        keya, a = _signer()
        keyb, b = _signer()
        table = {a: 0, b: 0}

        def build():
            mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider(table))
            for n in (0, 1):
                mp.admit(_order_tx(a, n, keya))
                mp.admit(_order_tx(b, n, keyb))
            return mp

        s1 = [t.tx_hash() for t in build().select_for_block()]
        s2 = [t.tx_hash() for t in build().select_for_block()]
        assert s1 == s2 and len(s1) == 4

    def test_remove_after_inclusion(self):
        key, addr = _signer()
        mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider({addr: 0}))
        tx = _order_tx(addr, 0, key)
        mp.admit(tx)
        assert mp.size() == 1
        assert mp.remove([tx.tx_hash()]) == 1
        assert mp.size() == 0 and not mp.contains(tx.tx_hash())

    def test_prune_stale_after_state_advances(self):
        key, addr = _signer()
        table = {addr: 0}
        mp = ExchangeMempool(nonce_provider=_fixed_nonce_provider(table))
        mp.admit(_order_tx(addr, 0, key))
        mp.admit(_order_tx(addr, 1, key))
        # State advances: nonce 0 and 1 were committed elsewhere.
        table[addr] = 2
        assert mp.prune_stale() == 2
        assert mp.size() == 0
