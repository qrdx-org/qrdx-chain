"""
Every consensus signature is bound to its network.

Block headers, attestations and RANDAO reveals are signed over a root that includes a signing
domain derived from the chain id and the chain spec (``chain_spec.signing_domain``), and every
exchange transaction carries the chain id it was signed for. Without that, a validator using
one key on two networks could be slashed on one with signatures it made on the other — two of
its testnet headers at the same slot are a valid DOUBLE_SIGN proof anywhere — and an exchange
transaction signed on a testnet would execute on any network where its nonce lined up.
"""
import hashlib

import pytest

from qrdx import chain_spec as cs
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange.transactions import ExchangeOpType, ExchangeTransaction
from qrdx.validator.attestation import Attestation
from qrdx.validator.block_verification import reconstruct_signing_root, verify_pos_block_proposer
from qrdx.validator.slashing_block import make_double_sign_evidence, verify_double_sign_evidence

NET_A = cs.build_spec("qrdx-net-a", 4242, {})
NET_B = cs.build_spec("qrdx-net-b", 4343, {})
KEY = PQPrivateKey.generate()
ADDR = KEY.public_key.to_address()


def _header(slot=9, **overrides):
    bc = {
        "number": 7, "parent_hash": "ab" * 32, "state_root": "cd" * 32,
        "transactions_root": "ef" * 32, "timestamp": 1700000000,
        "proposer_address": ADDR, "proposer_public_key": KEY.public_key.to_bytes().hex(),
        "slot": slot, "epoch": 0, "randao_reveal": "11" * 32,
    }
    bc.update(overrides)
    bc["proposer_signature"] = KEY.sign(reconstruct_signing_root(bc)).to_bytes().hex()
    bc["hash"] = hashlib.sha256(repr(sorted(bc.items())).encode()).hexdigest()
    return bc


def test_domains_separate_networks_and_purposes():
    with cs.use_spec(NET_A):
        a_block, a_att = cs.signing_domain("block"), cs.signing_domain("attestation")
    with cs.use_spec(NET_B):
        b_block = cs.signing_domain("block")
    assert len({a_block, a_att, b_block}) == 3
    assert cs.signing_domain("block", NET_A) == a_block          # stable
    # Scheduling a fork does not change a network's domain (signatures stay valid across it).
    upgraded = cs.build_spec("qrdx-net-a", 4242, {}, forks=[
        {"name": "f1", "height": 100, "features": ["randao_selection"]}])
    assert cs.signing_domain("block", upgraded) == a_block
    with pytest.raises(ValueError):
        cs.signing_domain("not-a-purpose", NET_A)


def test_a_header_signed_on_one_network_does_not_verify_on_another():
    with cs.use_spec(NET_A):
        header = _header()
        assert verify_pos_block_proposer(header, ADDR)[0]
    with cs.use_spec(NET_B):
        ok, err = verify_pos_block_proposer(header, ADDR)
        assert not ok and "signature" in err.lower()


def test_another_networks_headers_are_not_slashing_evidence_here():
    """The attack: a validator reuses its key on a testnet; anyone collects two of its testnet
    headers at one slot and submits them on mainnet as a DOUBLE_SIGN proof."""
    with cs.use_spec(NET_A):
        h1, h2 = _header(slot=9, state_root="11" * 32), _header(slot=9, state_root="22" * 32)
        evidence = make_double_sign_evidence(h1, h2)
        assert verify_double_sign_evidence(evidence)[0]          # genuine on its own network
    with cs.use_spec(NET_B):
        ok, err = verify_double_sign_evidence(evidence)
        assert not ok and "signature invalid" in err


def test_an_attestation_signed_on_one_network_does_not_verify_on_another():
    with cs.use_spec(NET_A):
        att = Attestation(slot=9, epoch=1, block_hash="ab" * 32, validator_address=ADDR,
                          validator_index=0, signature=b"", source_epoch=0, target_epoch=1)
        att.signature = KEY.sign(att.signing_root).to_bytes()
        assert att.verify(KEY.public_key.to_bytes())
    with cs.use_spec(NET_B):
        assert not att.verify(KEY.public_key.to_bytes())


def test_the_randao_reveal_message_is_network_bound():
    from qrdx.validator.randao import randao_reveal_message
    with cs.use_spec(NET_A):
        a = randao_reveal_message(9)
    with cs.use_spec(NET_B):
        b = randao_reveal_message(9)
    assert a != b and a != randao_reveal_message(10, NET_A)


def _exchange_tx(**kw):
    tx = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER, sender=ADDR, nonce=0,
                             params={"token_address": "0x" + "aa" * 20, "to": "0x" + "bb" * 20,
                                     "amount": "1"}, **kw)
    tx.public_key = KEY.public_key.to_bytes()
    tx.signature = KEY.sign(tx.signing_bytes()).to_bytes()
    return tx


def test_an_exchange_transaction_names_and_is_checked_against_its_chain():
    with cs.use_spec(NET_A):
        tx = _exchange_tx()
        assert tx.chain_id == 4242 and tx.verify()
        assert ExchangeTransaction.from_dict(tx.to_dict()).verify()      # survives the wire
    with cs.use_spec(NET_B):
        assert not tx.verify()                                           # replay refused
        assert "chain id 4242" in tx.chain_error()


def test_the_chain_id_is_inside_the_signature():
    with cs.use_spec(NET_B):
        tx = _exchange_tx(chain_id=4242)          # signed for network A
        tx.chain_id = 4343                        # relabelled for B: the signature breaks
        assert not tx.verify()
        assert _exchange_tx(chain_id=4242).tx_hash() != _exchange_tx(chain_id=4343).tx_hash()


def test_an_exchange_transaction_without_a_chain_id_is_refused():
    with cs.use_spec(NET_A):
        data = _exchange_tx().to_dict()
        data.pop("chain_id")
        assert not ExchangeTransaction.from_dict(data).verify()
