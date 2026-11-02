"""
Slashing protection (qrdx/validator/slashing_protection.py) and the doppelganger check
(qrdx/validator/doppelganger.py).

A validator records every block and vote before signing it, in a record of its own that one
process holds at a time. It never signs two different blocks for a slot, two different
attestations for a target epoch, or a surround vote: not across restarts, and not after moving
machines with its record. A second machine signing with the same key is caught from the chain.
"""

import inspect
import json
import sqlite3
from decimal import Decimal
from types import SimpleNamespace

import aiosqlite
import pytest

from qrdx.validator import doppelganger as D, slashing_protection as SP
from qrdx.validator.attestation import Attestation
from qrdx.validator.config import ValidatorConfig
from qrdx.validator.manager import ValidatorManager
from qrdx.validator.types import AlreadyAttestedError
from qrdx.wallet_v2.pq_wallet import PQWallet

NET, OTHER_NET = "aa" * 32, "bb" * 32
V = "0xPQ" + "1" * 64


def _root(n: int) -> str:
    return f"{n:064x}"


@pytest.fixture
async def record(tmp_path):
    rec = await SP.SlashingProtection.open(str(tmp_path / "sp.sqlite"), NET)
    yield rec
    await rec.close()


async def test_a_second_block_for_a_slot_is_never_signed(record):
    assert await record.may_sign_block(V, 10)
    assert await record.record_block(V, 10, _root(1))
    assert await record.record_block(V, 10, _root(1))  # the same block again is harmless
    assert not await record.record_block(V, 10, _root(2))
    assert not await record.may_sign_block(V, 10)
    assert await record.record_block(V, 11, _root(3))
    assert await record.signed_block_roots(V, 0) == {10: _root(1), 11: _root(3)}


async def test_double_and_surround_votes_are_never_signed(record):
    assert await record.record_vote(V, 2, 8, _root(1))
    assert await record.record_vote(V, 2, 8, _root(1))  # the same attestation again
    assert not await record.record_vote(V, 2, 8, _root(2))  # double vote
    assert not await record.record_vote(V, 1, 10, _root(3))  # surrounds 2->8
    assert not await record.record_vote(V, 3, 6, _root(4))  # surrounded by 2->8
    assert not await record.record_vote(V, 9, 7, _root(5))  # runs backwards
    assert await record.record_vote(V, 8, 9, _root(6))  # the next honest vote
    assert not await record.may_vote(V, 8, 9)  # that epoch is settled
    assert await record.signed_vote_roots(V, 0) == {8: _root(1), 9: _root(6)}


async def test_a_restart_mid_epoch_cannot_re_vote_the_same_checkpoints_at_another_slot(record):
    """The checkpoints alone are not the vote: an attestation also signs its slot and head, and
    importers judge two different attestations for one target a double vote. The record that
    compared checkpoints only let a restarted validator sign a second one."""

    def att(slot: int) -> Attestation:
        return Attestation(
            slot=slot,
            epoch=3,
            block_hash="cd" * 32,
            validator_address=V,
            validator_index=0,
            signature=b"",
            source_epoch=2,
            target_epoch=3,
            source_root="ab" * 32,
            target_root="ef" * 32,
        )

    assert await record.record_vote(V, 2, 3, att(97).signing_root)
    assert not await record.record_vote(V, 2, 3, att(98).signing_root)


async def test_the_record_survives_a_restart_and_one_process_holds_it(tmp_path):
    path = str(tmp_path / "sp.sqlite")
    rec = await SP.SlashingProtection.open(path, NET)
    assert await rec.record_block(V, 5, _root(1))
    with pytest.raises(SP.ProtectionStoreError, match="another process holds"):
        await SP.SlashingProtection.open(path, NET)
    await rec.close()
    rec = await SP.SlashingProtection.open(path, NET)
    try:
        assert not await rec.record_block(V, 5, _root(2))
    finally:
        await rec.close()


async def test_networks_keep_separate_records(tmp_path):
    path = str(tmp_path / "sp.sqlite")
    rec = await SP.SlashingProtection.open(path, NET)
    assert await rec.record_block(V, 5, _root(1))
    await rec.close()
    other = await SP.SlashingProtection.open(path, OTHER_NET)
    try:
        assert await other.record_block(V, 5, _root(2))
    finally:
        await other.close()


async def test_a_moved_record_never_lets_the_new_machine_sign_at_or_below_it(tmp_path):
    old = await SP.SlashingProtection.open(str(tmp_path / "old.sqlite"), NET)
    await old.record_block(V, 40, _root(1))
    await old.record_vote(V, 4, 5, _root(2))
    doc = await old.export()
    await old.close()
    assert doc["metadata"]["interchange_format_version"] == "5"
    assert doc["data"][0]["pubkey"] == V

    new = await SP.SlashingProtection.open(str(tmp_path / "new.sqlite"), NET)
    try:
        assert await new.import_interchange(json.loads(json.dumps(doc))) == 1
        assert not await new.record_block(V, 40, _root(9))
        assert not await new.record_block(V, 39, _root(9))  # below the watermark
        assert await new.record_block(V, 41, _root(9))
        assert not await new.record_vote(V, 3, 5, _root(9))
        assert not await new.record_vote(V, 3, 6, _root(9))  # source below the imported one
        assert await new.record_vote(V, 5, 6, _root(9))
        doc["metadata"]["genesis_validators_root"] = "0x" + OTHER_NET
        with pytest.raises(SP.ProtectionStoreError, match="another network"):
            await new.import_interchange(doc)
    finally:
        await new.close()


async def test_the_chain_databases_older_vote_record_is_folded_in(tmp_path, record):
    db_path = tmp_path / "chain.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE ffg_signing_record (validator TEXT, target_epoch INTEGER,"
            " source_epoch INTEGER, vote TEXT)"
        )
        conn.execute("INSERT INTO ffg_signing_record VALUES (?, 7, 6, '[]')", (V,))
    async with aiosqlite.connect(db_path) as conn:
        assert await record.import_legacy_votes(SimpleNamespace(connection=conn)) == 1
    assert not await record.record_vote(V, 6, 7, _root(1))  # its root is unknown: refused
    assert await record.record_vote(V, 7, 8, _root(1))


async def test_pruning_folds_old_rows_into_the_watermarks(record, monkeypatch):
    monkeypatch.setattr(SP, "KEEP_SLOTS", 10)
    monkeypatch.setattr(SP, "KEEP_EPOCHS", 3)
    for slot in range(1, 31):
        assert await record.record_block(V, slot, _root(slot))
    for target in range(1, 11):
        assert await record.record_vote(V, target - 1, target, _root(100 + target))
    await record.prune()
    assert min(await record.signed_block_roots(V, 0)) == 21
    assert not await record.record_block(V, 15, _root(1))  # pruned: refused by the watermark
    assert min(await record.signed_vote_roots(V, 0)) == 8
    assert not await record.record_vote(V, 5, 11, _root(1))  # source below the watermark


# ── the manager records before it signs ─────────────────────────────────────────────────


async def test_the_manager_records_an_attestation_before_signing_it(record):
    wallet = PQWallet.generate()
    manager = ValidatorManager(wallet=wallet, config=ValidatorConfig(enabled=True))
    manager._validator = SimpleNamespace(can_attest=True, index=0)

    async def stake(_addr):
        return Decimal(10**9)

    manager.stake_manager.get_effective_stake = stake
    manager.slashing_protection = record
    signed = []
    real_sign = manager._sign_message
    manager._sign_message = lambda m: signed.append(m) or real_sign(m)

    att = await manager.create_attestation(
        slot=97,
        block_hash="cd" * 32,
        source_epoch=2,
        target_epoch=3,
        source_root="ab" * 32,
        target_root="ef" * 32,
    )
    assert (await record.signed_vote_roots(wallet.address, 0))[3] == att.signing_root.hex()
    with pytest.raises(AlreadyAttestedError):
        await manager.create_attestation(
            slot=98,
            block_hash="cd" * 32,
            source_epoch=2,
            target_epoch=3,
            source_root="ab" * 32,
            target_root="ef" * 32,
        )
    assert len(signed) == 1  # the refused one was never signed


def test_the_manager_records_a_block_before_signing_it():
    src = inspect.getsource(ValidatorManager.propose_block)
    assert src.index("record_block(") < src.index("_sign_message(block.signing_root)")


# ── the doppelganger check ───────────────────────────────────────────────────────────


async def _chain_db(tmp_path):
    conn = await aiosqlite.connect(str(tmp_path / "chain.db"))
    await conn.execute(
        "CREATE TABLE blocks (block_hash TEXT, block_height INTEGER, validator_address TEXT)"
    )
    await conn.execute("CREATE TABLE chain_index (height INTEGER, slot INTEGER)")
    await conn.execute(
        "CREATE TABLE attestation_votes (validator_address TEXT, target_epoch INTEGER,"
        " source_epoch INTEGER, slot INTEGER, block_hash TEXT, epoch INTEGER,"
        " source_root TEXT, target_root TEXT)"
    )
    return conn


async def _add_block(conn, height, slot, block_hash, proposer=V):
    await conn.execute("INSERT INTO blocks VALUES (?, ?, ?)", (block_hash, height, proposer))
    await conn.execute("INSERT INTO chain_index VALUES (?, ?)", (height, slot))


async def test_a_validator_listens_before_signing_and_stops_on_a_doppelganger(tmp_path, record):
    conn = await _chain_db(tmp_path)
    try:
        guard = D.DoppelgangerGuard(SimpleNamespace(connection=conn), record, V, 2, 8)
        assert "listening until slot 116" in await guard.hold(100)
        assert await guard.hold(115)
        assert await guard.hold(116) is None
        # Its own block, recorded before signing: fine.
        await record.record_block(V, 117, _root(1))
        await _add_block(conn, 1, 117, _root(1))
        assert await guard.hold(120) is None
        # A block from its key it never signed: stop, for good.
        await _add_block(conn, 2, 126, _root(2))
        reason = await guard.hold(128)
        assert reason and "doppelganger" in reason and "did not sign" in reason
        assert await guard.hold(200) == reason
    finally:
        await conn.close()


async def test_a_vote_the_validator_never_signed_is_a_doppelganger(tmp_path, record):
    conn = await _chain_db(tmp_path)
    try:
        guard = D.DoppelgangerGuard(SimpleNamespace(connection=conn), record, V, 0, 8)
        assert await guard.hold(80) is None
        await conn.execute(
            "INSERT INTO attestation_votes VALUES (?, 10, 9, 81, ?, 10, ?, ?)",
            (V, "cd" * 32, "ab" * 32, "ef" * 32),
        )
        assert "target epoch 10" in await guard.hold(88)
    finally:
        await conn.close()


def test_dev_networks_skip_the_listening_window(monkeypatch):
    monkeypatch.delenv(D.EPOCHS_ENV, raising=False)
    assert (D.configured_epochs(dev=True), D.configured_epochs(dev=False)) == (0, 3)
    monkeypatch.setenv(D.EPOCHS_ENV, "5")
    assert D.configured_epochs(dev=True) == 5
