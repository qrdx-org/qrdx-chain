"""
A block's header commits to its body, and its hash is its header's (qrdx/validator/
block_verification.py ``body_root`` / ``block_integrity_error``).

The proposer used to sign only header fields: the votes a block carried, its slashing proofs and
its exchange and EVM sections were covered by nothing. Anyone relaying or serving a block could
strip or swap them — and the votes decide finality, rewards and the validator set, so nodes
holding different copies of one block derived different validator sets from it. Nor was a
block's hash checked: it was taken as sent, so a sender could store an honest block under a
hash of its choosing (and fork choice prefers the lowest). Now the header carries
``body_root`` (signed), the hash is the signing root, and every import path checks both.
"""
import ast
import json

import pytest

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.validator.attestation import Attestation
from qrdx.validator.block_verification import (
    block_integrity_error,
    body_root,
    reconstruct_signing_root,
    verify_pos_block_proposer,
)
from qrdx.validator.manager import PoSBlock

KEY = PQPrivateKey.generate()
ADDR = KEY.public_key.to_address()


def _vote(validator, target):
    return Attestation.from_dict({
        "slot": target * 32, "epoch": target, "block_hash": "bh", "validator_address": validator,
        "validator_index": 0, "signature": "ab" * 8, "source_epoch": target - 1,
        "target_epoch": target, "source_root": "11" * 32, "target_root": "22" * 32,
        "included_in_block": None, "created_at": "2026-01-01T00:00:00"})


EXCHANGE = [{"op_type": 5, "sender": "0xPQ" + "a" * 64, "nonce": 3, "params": {"order_id": "x"},
             "gas_limit": 100_000, "gas_price": "1000000000", "timestamp": 0.0,
             "signature": "cd" * 8, "public_key": "ef" * 8, "chain_id": 7620, "tx_hash": "00"}]
EVM = ["0xf86b8085e8d4a51000825208940000000000000000000000000000000000000000"]


def _block(votes=2, evidence=()):
    b = PoSBlock(number=9, parent_hash="ab" * 32, state_root="cd" * 32,
                 transactions_root="ef" * 32, timestamp=1_700_000_000, proposer_address=ADDR,
                 proposer_public_key=KEY.public_key.to_bytes(), proposer_signature=b"", slot=9,
                 epoch=0, randao_reveal=b"",
                 attestations=[_vote(f"0xPQ{i:064x}", 1) for i in range(votes)],
                 slashing_evidence=list(evidence), graffiti="hi")
    b.commit_body(EXCHANGE, EVM)
    b.proposer_signature = KEY.sign(b.signing_root).to_bytes()
    return b


def _received(block):
    """The block as an importer reads it: the content round-trips through its repr, the
    sections through JSON (gossip, or the database)."""
    content = ast.literal_eval(str(block.to_dict()))
    return content, json.loads(json.dumps(EXCHANGE)), json.loads(json.dumps(EVM))


def test_an_honest_block_is_what_its_proposer_signed():
    b = _block()
    content, ex, evm = _received(b)
    assert block_integrity_error(content, ex, evm, b.hash) == ""
    assert verify_pos_block_proposer(str(content), ADDR, KEY.public_key.to_bytes())[0]
    assert b.hash == reconstruct_signing_root(content).hex()


@pytest.mark.parametrize("tamper", [
    "strip a vote", "add a vote", "drop the evidence", "change the graffiti",
    "drop an exchange operation", "change an exchange operation", "add an EVM transaction"])
def test_nothing_in_a_block_can_change_without_breaking_it(tamper):
    b = _block(evidence=[{"condition": "double_sign", "slot": 3}])
    content, ex, evm = _received(b)
    if tamper == "strip a vote":
        content["attestations"] = content["attestations"][1:]
    elif tamper == "add a vote":
        content["attestations"].append(_vote("0xPQ" + "f" * 64, 1).to_dict())
    elif tamper == "drop the evidence":
        content["slashing_evidence"] = []
    elif tamper == "change the graffiti":
        content["graffiti"] = "ho"
    elif tamper == "drop an exchange operation":
        ex = []
    elif tamper == "change an exchange operation":
        ex[0]["nonce"] = 4
    else:
        evm = evm + ["0x00"]
    assert "body_root" in block_integrity_error(content, ex, evm, b.hash)


def test_a_body_root_cannot_be_rewritten_to_match_without_breaking_the_signature():
    b = _block()
    content, ex, evm = _received(b)
    content["attestations"] = []
    content["body_root"] = body_root(content, ex, evm)          # consistent, but not signed
    assert block_integrity_error(content, ex, evm) == ""
    assert not verify_pos_block_proposer(str(content), ADDR, KEY.public_key.to_bytes())[0]


def test_a_block_is_only_ever_stored_under_its_own_hash():
    b = _block()
    content, ex, evm = _received(b)
    for claimed in ("0" * 64, "f" * 64, b.hash[:-1] + ("0" if b.hash[-1] != "0" else "1")):
        assert "is not its header's" in block_integrity_error(content, ex, evm, claimed)
    assert block_integrity_error(content, ex, evm, "0x" + b.hash) == ""


def test_a_block_without_a_body_root_is_refused():
    content, ex, evm = _received(_block())
    del content["body_root"]
    assert "no body_root" in block_integrity_error(content, ex, evm)


def test_the_sections_travel_beside_the_content_or_inside_it_alike():
    b = _block()
    content, ex, evm = _received(b)
    inside = dict(content, exchange_transactions=ex, evm_transactions=evm)
    assert block_integrity_error(inside, None, None, b.hash) == ""


async def test_every_import_path_refuses_a_stripped_block_before_anything_runs(monkeypatch):
    from qrdx.node import main as node_main

    async def must_not_run(*a, **k):
        raise AssertionError("verified a block that is not its proposer's")

    monkeypatch.setattr("qrdx.validator.block_verification.verify_slot_progression", must_not_run)
    b = _block()
    content, ex, evm = _received(b)
    content["attestations"] = content["attestations"][:1]
    ok, err = await node_main._verify_chain_rules(str(content), 5, ex, evm, b.hash)
    assert not ok and "body_root" in err


def test_fork_choice_ignores_a_branch_sent_under_hashes_it_does_not_own():
    from qrdx.node.main import _parse_transfer_block

    b = _block()
    content, _ex, _evm = _received(b)
    honest = {"block": {"id": 5, "hash": b.hash, "content": str(content)}}
    forged = {"block": {"id": 5, "hash": "0" * 64, "content": str(content)}}
    assert _parse_transfer_block(honest) is not None
    assert _parse_transfer_block(forged) is None
