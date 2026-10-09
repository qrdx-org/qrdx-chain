"""
The type-0x51 post-quantum transaction contract (qrdx/transactions/pq_tx.py).

A PQ transaction is the authorisation half of ledger unification: it lets a
Dilithium key originate a transfer or a contract call that executes in the same
EVM, in the same block section, as a secp256k1 transaction. These tests pin the
properties that make that safe — sender binding, tamper rejection, the
intrinsic-gas floor — and the fact that the shared parser authenticates it.
"""
import pytest
from eth_utils import decode_hex

from qrdx.contracts.evm_mempool import EVMMempool, parse_eth_raw_tx
from qrdx.crypto.account_id import to_account_id
from qrdx.crypto.pq.dilithium import PUBLIC_KEY_SIZE, SIGNATURE_SIZE, generate_keypair
from qrdx.transactions.pq_tx import (
    PQ_TX_TYPE,
    InvalidPQTransaction,
    PQTransaction,
    decode_pq_tx,
    intrinsic_gas_pq,
    is_pq_tx,
)
from qrdx.constants import CHAIN_ID  # the network's chain id (chain spec)

RECIPIENT = bytes.fromhex("cd" * 20)


def _signed(priv, **overrides):
    params = dict(chain_id=CHAIN_ID, nonce=0, gas_price=10 ** 9, gas_limit=500_000,
                  to=RECIPIENT, value=10 ** 18, data=b"")
    params.update(overrides)
    return PQTransaction(**params).sign(priv)


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair()


# ── Envelope ───────────────────────────────────────────────────────────

def test_envelope_is_eip2718_typed(keypair):
    priv, _pub = keypair
    raw = _signed(priv).encode()
    assert raw[0] == PQ_TX_TYPE == 0x51
    assert is_pq_tx(raw)
    # A type byte < 0x80 is what makes this a typed tx rather than legacy RLP.
    assert raw[0] < 0x80


def test_round_trip_preserves_every_field(keypair):
    priv, _pub = keypair
    tx = _signed(priv, nonce=7, value=123456789, gas_price=3 * 10 ** 9,
                 gas_limit=750_000, data=b"\x01\x02\x03")
    back = decode_pq_tx(tx.encode())
    assert (back.chain_id, back.nonce, back.gas_price, back.gas_limit,
            back.to, back.value, back.data) == (
           (tx.chain_id, tx.nonce, tx.gas_price, tx.gas_limit,
            tx.to, tx.value, tx.data))
    assert back.public_key == tx.public_key
    assert back.signature == tx.signature


def test_contract_creation_has_no_recipient(keypair):
    priv, _pub = keypair
    tx = _signed(priv, to=None, data=b"\x60\x00", gas_limit=900_000)
    back = decode_pq_tx(tx.encode())
    assert back.to is None
    # EIP-2 creation surcharge is priced in.
    assert back.intrinsic_gas() > intrinsic_gas_pq(b"\x60\x00", tx.public_key,
                                                   tx.signature, is_create=False)


def test_tx_hash_is_keccak_of_the_wire_bytes(keypair):
    """The Ethereum rule, so eth_getTransactionReceipt needs no special case."""
    from eth_hash.auto import keccak
    priv, _pub = keypair
    tx = _signed(priv)
    assert tx.hash() == keccak(tx.encode())


# ── Sender binding ─────────────────────────────────────────────────────

def test_sender_is_derived_from_the_embedded_key(keypair):
    priv, pub = keypair
    tx = decode_pq_tx(_signed(priv).encode())
    assert tx.sender() == pub.to_account_id()
    assert tx.sender() == to_account_id(pub.to_address())
    assert tx.pq_address() == pub.to_address()


def test_sender_is_a_20_byte_address_so_the_evm_needs_no_changes(keypair):
    priv, _pub = keypair
    sender = decode_pq_tx(_signed(priv).encode()).sender()
    assert len(decode_hex(sender)) == 20


def test_two_keys_are_two_senders():
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    assert _signed(priv_a).sender() != _signed(priv_b).sender()
    assert _signed(priv_a).sender() == pub_a.to_account_id()
    assert _signed(priv_b).sender() == pub_b.to_account_id()


def test_swapping_in_another_key_changes_the_account_not_the_victim(keypair):
    """
    There is no sender field on the wire, so an attacker substituting their own
    key cannot redirect a spend to a victim's account — it simply becomes a
    transaction from the attacker's own (and the signature must still match).
    """
    priv, _pub = keypair
    other_priv, other_pub = generate_keypair()
    tx = decode_pq_tx(_signed(priv).encode())
    tx.public_key = other_pub.to_bytes()
    assert tx.sender() == other_pub.to_account_id()
    assert tx.verify() is False, "signature must not validate under a swapped key"


# ── Authentication ─────────────────────────────────────────────────────

def test_valid_signature_verifies(keypair):
    priv, _pub = keypair
    assert decode_pq_tx(_signed(priv).encode()).verify() is True


@pytest.mark.parametrize("field,value", [
    ("value", 10 ** 18 + 1),
    ("nonce", 99),
    ("to", bytes.fromhex("ab" * 20)),
    ("gas_price", 10 ** 10),
    ("gas_limit", 600_000),
    ("chain_id", 1),
    ("data", b"\xff"),
])
def test_mutating_any_signed_field_invalidates_it(keypair, field, value):
    priv, _pub = keypair
    tx = decode_pq_tx(_signed(priv).encode())
    setattr(tx, field, value)
    assert tx.verify() is False, f"tampering with {field} was not detected"


def test_corrupted_signature_is_rejected(keypair):
    priv, _pub = keypair
    tx = decode_pq_tx(_signed(priv).encode())
    tx.signature = tx.signature[:-1] + bytes([tx.signature[-1] ^ 0xFF])
    assert tx.verify() is False


def test_unsigned_transaction_cannot_be_encoded():
    tx = PQTransaction(chain_id=CHAIN_ID, nonce=0, gas_price=1, gas_limit=21000,
                       to=RECIPIENT, value=0, data=b"")
    with pytest.raises(InvalidPQTransaction):
        tx.encode()


# ── Structural validation ──────────────────────────────────────────────

def test_wrong_type_byte_is_not_a_pq_tx():
    with pytest.raises(InvalidPQTransaction):
        decode_pq_tx(b"\x02\xc0")


def test_wrong_sized_key_material_is_rejected(keypair):
    priv, _pub = keypair
    import rlp
    tx = _signed(priv)
    fields = tx._unsigned_fields()
    truncated = bytes([PQ_TX_TYPE]) + rlp.encode(fields + [b"\x00" * 10, tx.signature])
    with pytest.raises(InvalidPQTransaction, match="public key must be"):
        decode_pq_tx(truncated)
    bad_sig = bytes([PQ_TX_TYPE]) + rlp.encode(fields + [tx.public_key, b"\x00" * 10])
    with pytest.raises(InvalidPQTransaction, match="signature must be"):
        decode_pq_tx(bad_sig)


def test_oversized_recipient_is_rejected(keypair):
    priv, _pub = keypair
    import rlp
    tx = _signed(priv)
    fields = tx._unsigned_fields()
    fields[4] = b"\x11" * 32          # a 32-byte 'to' is not addressable by the EVM
    raw = bytes([PQ_TX_TYPE]) + rlp.encode(fields + [tx.public_key, tx.signature])
    with pytest.raises(InvalidPQTransaction, match="20-byte account id"):
        decode_pq_tx(raw)


# ── Gas ────────────────────────────────────────────────────────────────

def test_intrinsic_gas_prices_the_authentication_envelope(keypair):
    """
    The ~5.3KB key+signature must cost gas, or a PQ transaction imposes hundreds
    of times a legacy transaction's bandwidth and verification work at the same
    price — a cheap denial-of-service vector.
    """
    priv, _pub = keypair
    tx = _signed(priv)
    envelope = len(tx.public_key) + len(tx.signature)
    assert envelope > 5000
    assert tx.intrinsic_gas() > 21_000 + envelope * 8


def test_underpriced_transaction_is_invalid_not_merely_reverting(keypair):
    """
    As in Ethereum, gas below the intrinsic floor makes the transaction INVALID —
    so the shared parser rejects it, which means a block carrying one is rejected
    rather than executing it as a revert.
    """
    priv, _pub = keypair
    tx = _signed(priv, gas_limit=21_000)
    with pytest.raises(ValueError, match="intrinsic gas too low"):
        parse_eth_raw_tx("0x" + tx.encode().hex())


# ── Integration with the shared parser / mempool ───────────────────────

def test_shared_parser_returns_the_same_shape_as_a_legacy_tx(keypair):
    priv, pub = keypair
    tx = _signed(priv, nonce=3, value=555)
    parsed = parse_eth_raw_tx("0x" + tx.encode().hex())
    assert parsed["sender"] == pub.to_account_id()
    assert parsed["nonce"] == 3
    assert parsed["value"] == 555
    assert parsed["to"] == "0x" + RECIPIENT.hex()
    assert parsed["gas"] == 500_000
    assert parsed["tx_type"] == PQ_TX_TYPE
    assert parsed["tx_hash"] == "0x" + tx.hash().hex()


def test_parser_authenticates_so_block_import_cannot_be_fooled(keypair):
    """
    apply_block_evm_section authenticates a whole EVM section through this parser
    before touching state. If it did not verify PQ signatures, a proposer could
    smuggle in an unsigned transaction spending someone else's account.
    """
    priv, _pub = keypair
    raw = bytearray(_signed(priv).encode())
    raw[-1] ^= 0xFF
    with pytest.raises(ValueError, match="verification failed"):
        parse_eth_raw_tx("0x" + bytes(raw).hex())


def test_mempool_admits_a_pq_transaction(keypair):
    priv, pub = keypair
    mp = EVMMempool()
    ok, err, tx_hash = mp.admit("0x" + _signed(priv).encode().hex())
    assert ok, err
    assert mp.contains(tx_hash)
    # ...and it is selectable for a block like any other transaction.
    assert mp.select_for_block() == [mp.get_raw(tx_hash)]


def test_mempool_rejects_a_forged_pq_transaction(keypair):
    priv, _pub = keypair
    raw = bytearray(_signed(priv).encode())
    raw[-5] ^= 0xFF
    ok, err, _ = EVMMempool().admit("0x" + bytes(raw).hex())
    assert not ok and "invalid evm tx" in err


def test_unknown_typed_transactions_are_still_rejected():
    """Only legacy and 0x51 are supported; every other type byte must be refused."""
    for type_byte in (0x01, 0x02, 0x03, 0x04, 0x7f):
        with pytest.raises(ValueError, match="unsupported typed transaction"):
            parse_eth_raw_tx("0x" + bytes([type_byte]).hex() + "c0")


def test_legacy_transactions_still_parse_unchanged():
    """The PQ dispatch must not disturb the secp256k1 path."""
    from eth_account import Account as EthAccount
    key = "0x" + "11" * 32
    acct = EthAccount.from_key(key)
    signed = EthAccount.sign_transaction(
        {"nonce": 0, "gasPrice": 10 ** 9, "gas": 21000, "to": acct.address,
         "value": 1, "data": b"", "chainId": CHAIN_ID}, key)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    parsed = parse_eth_raw_tx("0x" + bytes(raw).hex())
    assert parsed["sender"].lower() == acct.address.lower()
    assert parsed["tx_type"] == 0


def test_key_and_signature_sizes_match_ml_dsa_65(keypair):
    priv, _pub = keypair
    tx = _signed(priv)
    assert len(tx.public_key) == PUBLIC_KEY_SIZE == 1952
    assert len(tx.signature) == SIGNATURE_SIZE == 3309
