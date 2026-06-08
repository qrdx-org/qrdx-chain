"""
Attestation block-section codec (finality link 1).

Pins the wire codec that lets attestations ride in block bodies (so they
propagate + accumulate into per-epoch attesting stake for finality): round-trip
preserves order and authenticity (signature still verifies on the far side),
empty/absent is a no-op, and malformed entries are skipped rather than raising.
"""

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.validator.types import Validator, ValidatorStatus
from qrdx.validator.attestation import Attestation
from qrdx.validator.attestation_block import (
    encode_attestations,
    decode_attestations,
    attestations_canonical_bytes,
    extract_attestations_from_dict,
    BLOCK_ATTESTATIONS_KEY,
)


def _signed_attestation(slot=5, epoch=0, block_hash="ab" * 32):
    key = PQPrivateKey.generate()
    v = Validator(
        address=key.address, public_key=key.public_key.to_bytes(),
        status=ValidatorStatus.ACTIVE, activation_epoch=0, index=0,
    )
    att = Attestation.create(slot, epoch, block_hash, v, key,
                             source_epoch=epoch, target_epoch=epoch)
    return att, key.public_key.to_bytes()


def test_round_trip_preserves_order_and_fields():
    a1, _ = _signed_attestation(slot=5)
    a2, _ = _signed_attestation(slot=6)
    encoded = encode_attestations([a1, a2])
    decoded = decode_attestations(encoded)
    assert [a.slot for a in decoded] == [5, 6]
    assert decoded[0].block_hash == a1.block_hash
    assert decoded[0].validator_address == a1.validator_address


def test_authenticity_survives_round_trip():
    att, pub = _signed_attestation()
    decoded = decode_attestations(encode_attestations([att]))[0]
    assert decoded.verify(pub), "signature must still verify after codec round-trip"


def test_empty_and_absent_are_noop():
    assert decode_attestations(None) == []
    assert decode_attestations([]) == []
    assert extract_attestations_from_dict({}) == []
    assert extract_attestations_from_dict({"foo": 1}) == []


def test_malformed_entries_skipped_not_raised():
    good, _ = _signed_attestation()
    items = encode_attestations([good]) + [{"garbage": True}, None, 42]
    decoded = decode_attestations(items)
    assert len(decoded) == 1 and decoded[0].slot == good.slot


def test_extract_from_block_dict():
    att, _ = _signed_attestation()
    block = {BLOCK_ATTESTATIONS_KEY: encode_attestations([att])}
    recovered = extract_attestations_from_dict(block)
    assert len(recovered) == 1 and recovered[0].validator_address == att.validator_address


def test_canonical_bytes_changes_on_mutation():
    a1, _ = _signed_attestation(slot=5)
    a2, _ = _signed_attestation(slot=6)
    base = attestations_canonical_bytes([a1, a2])
    assert attestations_canonical_bytes([a1, a2]) == base       # stable
    assert attestations_canonical_bytes([a2, a1]) != base       # order matters
    assert attestations_canonical_bytes([a1]) != base           # content matters
