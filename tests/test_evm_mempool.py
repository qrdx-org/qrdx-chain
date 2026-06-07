"""
E-D1 — EVM transaction mempool admission tests.

The EVM/account analog of the exchange mempool: which signed eth transactions are
eligible for a block. Authentication is intrinsic — the sender is recovered from
the ECDSA signature — so these cover recovery correctness, the nonce window,
dedup, capacity, deterministic selection, and rejection of malformed/typed txs.
See docs/EVM_STATE_CONSENSUS_INTEGRATION.md §6 (E-D1).
"""

import pytest
from eth_account import Account

from qrdx.contracts.evm_mempool import EVMMempool, parse_eth_raw_tx


def _raw_tx(key_hex, nonce, to=None, value=0, chain_id=1, gas_price=10 ** 9, gas=21000):
    acct = Account.from_key(key_hex)
    tx = {
        "nonce": nonce, "gasPrice": gas_price, "gas": gas,
        "to": to or acct.address, "value": value, "data": b"", "chainId": chain_id,
    }
    signed = Account.sign_transaction(tx, key_hex)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    return "0x" + bytes(raw).hex(), acct.address


def _key(i):
    return "0x" + f"{i:064x}"


def _fixed_nonce(table):
    return lambda addr: table.get(addr.lower(), 0)


# ── Parsing / recovery ─────────────────────────────────────────────────

class TestParse:
    def test_recovers_correct_sender(self):
        raw, addr = _raw_tx(_key(1), nonce=0)
        parsed = parse_eth_raw_tx(raw)
        assert parsed["sender"].lower() == addr.lower(), "recovered sender must match signer"
        assert parsed["nonce"] == 0
        assert parsed["tx_hash"].startswith("0x") and len(parsed["tx_hash"]) == 66

    def test_tampered_raw_changes_sender_or_fails(self):
        raw, addr = _raw_tx(_key(2), nonce=0)
        b = bytearray(bytes.fromhex(raw[2:]))
        b[5] ^= 0xFF  # flip a byte in the body
        tampered = "0x" + bytes(b).hex()
        try:
            parsed = parse_eth_raw_tx(tampered)
        except ValueError:
            return  # rejected outright — acceptable
        # If it parsed, it must NOT recover to the original signer.
        assert parsed["sender"].lower() != addr.lower()

    def test_garbage_rejected(self):
        for bad in ["0x", "0xdeadbeef", "not-hex", "0x01" + "00" * 10]:
            with pytest.raises(ValueError):
                parse_eth_raw_tx(bad)


# ── Admission ──────────────────────────────────────────────────────────

class TestAdmission:
    def test_valid_tx_admitted(self):
        raw, addr = _raw_tx(_key(3), nonce=0)
        mp = EVMMempool(nonce_provider=_fixed_nonce({addr.lower(): 0}))
        ok, err, h = mp.admit(raw)
        assert ok, err
        assert mp.contains(h) and mp.size() == 1

    def test_duplicate_rejected(self):
        raw, addr = _raw_tx(_key(4), nonce=0)
        mp = EVMMempool(nonce_provider=_fixed_nonce({addr.lower(): 0}))
        assert mp.admit(raw)[0]
        ok, err, _ = mp.admit(raw)
        assert not ok and "duplicate" in err

    def test_stale_nonce_rejected(self):
        raw, addr = _raw_tx(_key(5), nonce=3)
        mp = EVMMempool(nonce_provider=_fixed_nonce({addr.lower(): 5}))
        ok, err, _ = mp.admit(raw)
        assert not ok and "too low" in err

    def test_far_future_nonce_rejected(self):
        raw, addr = _raw_tx(_key(6), nonce=500)
        mp = EVMMempool(max_nonce_gap=8, nonce_provider=_fixed_nonce({addr.lower(): 0}))
        ok, err, _ = mp.admit(raw)
        assert not ok and "too far ahead" in err

    def test_future_within_gap_admitted(self):
        raw, addr = _raw_tx(_key(7), nonce=3)
        mp = EVMMempool(max_nonce_gap=8, nonce_provider=_fixed_nonce({addr.lower(): 0}))
        assert mp.admit(raw)[0]

    def test_same_nonce_twice_rejected(self):
        mp = EVMMempool(nonce_provider=_fixed_nonce({}))
        raw0a, _ = _raw_tx(_key(8), nonce=0, value=1)
        raw0b, _ = _raw_tx(_key(8), nonce=0, value=2)  # same signer+nonce, different tx
        assert mp.admit(raw0a)[0]
        ok, err, _ = mp.admit(raw0b)
        assert not ok and "already queued" in err

    def test_global_capacity(self):
        table = {}
        mp = EVMMempool(max_size=2, nonce_provider=_fixed_nonce(table))
        for i in range(3):
            raw, addr = _raw_tx(_key(100 + i), nonce=0)
            ok, err, _ = mp.admit(raw)
            assert ok if i < 2 else (not ok and "full" in err)
        assert mp.size() == 2

    def test_per_sender_capacity(self):
        raw0, addr = _raw_tx(_key(9), nonce=0)
        raw1, _ = _raw_tx(_key(9), nonce=1)
        raw2, _ = _raw_tx(_key(9), nonce=2)
        mp = EVMMempool(max_per_sender=2, nonce_provider=_fixed_nonce({addr.lower(): 0}))
        assert mp.admit(raw0)[0]
        assert mp.admit(raw1)[0]
        ok, err, _ = mp.admit(raw2)
        assert not ok and "per-sender" in err


# ── Selection / removal ────────────────────────────────────────────────

class TestSelection:
    def test_gap_free_selection(self):
        addr = Account.from_key(_key(10)).address
        mp = EVMMempool(nonce_provider=_fixed_nonce({addr.lower(): 0}))
        for n in (0, 1, 3):  # 2 missing → gap
            mp.admit(_raw_tx(_key(10), nonce=n)[0])
        sel = mp.select_for_block()
        parsed = [parse_eth_raw_tx(r) for r in sel]
        assert [p["nonce"] for p in parsed] == [0, 1], "selection must stop at the gap"

    def test_selection_deterministic(self):
        table = {}
        def build():
            mp = EVMMempool(nonce_provider=_fixed_nonce(table))
            for i in (11, 12):
                for n in (0, 1):
                    mp.admit(_raw_tx(_key(i), nonce=n)[0])
            return mp.select_for_block()
        assert build() == build()

    def test_remove_and_prune(self):
        addr = Account.from_key(_key(13)).address
        table = {addr.lower(): 0}
        mp = EVMMempool(nonce_provider=_fixed_nonce(table))
        _, _, h0 = mp.admit(_raw_tx(_key(13), nonce=0)[0])
        mp.admit(_raw_tx(_key(13), nonce=1)[0])
        assert mp.remove([h0]) == 1 and mp.size() == 1
        table[addr.lower()] = 2  # state advanced past both
        assert mp.prune_stale() == 1 and mp.size() == 0
