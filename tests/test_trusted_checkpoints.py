"""
Trusted checkpoints: weak subjectivity (qrdx/checkpoints.py, docs/WEAK_SUBJECTIVITY.md).

A running node never reorganizes below finality, but a node syncing from genesis had nothing to
hold on to: validators that left long ago — stake withdrawn, nothing to slash — can sign another
history from an old block onward, finality included, and the new node would follow whichever
it was shown. Now a node trusts checkpoints from its network's spec (shipped by each signed
release) and its operator, refuses any block at a checkpoint height that is not the checkpoint,
never rolls back below the highest one it holds, refuses to start on a database that
contradicts one, and warns when it has been offline longer than the weak-subjectivity period.
"""
import pytest

from qrdx import chain_spec as cs
from qrdx import checkpoints as CP
from qrdx.node import main as node_main

from test_finality_compute import Chain, keys  # noqa: F401  (keys: the module fixture)
from test_fork_resolution import PEER, copy_blocks, setup  # noqa: F401  (the fixture)

H = "ab" * 32


# ── where they come from ─────────────────────────────────────────────────────

def test_a_spec_lists_them_strictly_and_genesis_does_not_commit_to_them():
    base = cs.build_spec("qrdx-cp", 4545, {}).to_dict()
    with_cps = dict(base, checkpoints=[{"height": 10, "hash": H}, {"height": 20, "hash": "cd" * 32}])
    a, b = cs.ChainSpec.from_dict(base), cs.ChainSpec.from_dict(with_cps)
    assert b.checkpoints() == [(10, H), (20, "cd" * 32)]
    assert a.genesis_hash() == b.genesis_hash()        # appended by releases, like forks
    for bad in ([{"height": 0, "hash": H}], [{"height": 5, "hash": "XY" * 32}],
                [{"height": 9, "hash": H}, {"height": 9, "hash": H}], [{"height": 9}]):
        with pytest.raises(cs.ChainSpecError):
            cs.ChainSpec.from_dict(dict(base, checkpoints=bad))


def test_an_operator_adds_their_own_and_a_contradiction_is_refused():
    assert CP.trusted({CP.ENV: f"12:{H}, 30:0x{'cd' * 32}"}) == {12: H, 30: "cd" * 32}
    for bad in ("12", f"x:{H}", "12:abc", f"0:{H}", f"12:{H},12:{'cd' * 32}"):
        with pytest.raises(CP.CheckpointError):
            CP.trusted({CP.ENV: bad})


# ── what they decide ─────────────────────────────────────────────────────────

def test_a_block_at_a_checkpoint_height_must_be_the_checkpoint():
    cps = {10: H}
    assert CP.checkpoint_error(10, H, cps) == ""
    assert CP.checkpoint_error(10, "0x" + H.upper().lower(), cps) == ""
    assert "not the trusted checkpoint" in CP.checkpoint_error(10, "cd" * 32, cps)
    assert CP.checkpoint_error(11, "cd" * 32, cps) == ""


async def test_no_reorganization_goes_below_a_checkpoint_the_node_holds(setup, monkeypatch):
    """Their branch, diverging below our checkpoint, would win fork choice (it is taller and
    justifies a newer checkpoint) — it is not followed."""
    from qrdx.constants import SLOTS_PER_EPOCH as S

    ours, theirs, _ = setup
    await ours.epochs(1, 1, voters=[0, 1, 2, 3])
    await copy_blocks(ours, theirs)
    fork = ours.height
    for i in range(3):
        await ours.block(2 * S + 1 + i, tag="O")
    await theirs.epochs(2, 3, voters=[0, 1, 2], tag="T")
    for i in range(8):
        await theirs.block(4 * S + 1 + i, tag="T")
    monkeypatch.setenv(CP.ENV, f"{fork + 1}:{ours.hashes[fork + 1]}")   # ours, above the fork
    before = ours.hashes[-1]
    assert await CP.reorg_floor(ours.db) == fork + 1
    assert not await node_main.resolve_fork_with_peer(PEER)
    assert (await ours.db.get_block_hashes(ours.height, ours.height))[ours.height] == before
    monkeypatch.delenv(CP.ENV)                                        # without it: followed
    assert await node_main.resolve_fork_with_peer(PEER)


async def test_every_import_path_refuses_a_block_off_the_trusted_chain(monkeypatch):
    from qrdx.validator.block_verification import body_root, reconstruct_signing_root

    block = {"number": 7, "parent_hash": "00" * 32, "state_root": "11" * 32,
             "transactions_root": "22" * 32, "timestamp": 1, "slot": 7, "epoch": 0,
             "proposer_address": "0xPQ" + "a" * 64, "randao_reveal": "",
             "base_fee": 10 ** 9, "exchange_base_fee": 10 ** 9}
    block["body_root"] = body_root(block)
    own = reconstruct_signing_root(block).hex()
    monkeypatch.setenv(CP.ENV, f"7:{'cd' * 32}")
    ok, err = await node_main._verify_chain_rules(repr(block), 7, None, None, own)
    assert not ok and "not the trusted checkpoint" in err


async def test_a_node_on_another_chain_refuses_to_start(keys, monkeypatch):  # noqa: F811
    c = await Chain.create(keys)
    try:
        await c.epochs(1, 1, voters=[0, 1, 2, 3])
        monkeypatch.setenv(CP.ENV, f"2:{c.hashes[2]}")
        assert await CP.startup_error(c.db) == ""
        monkeypatch.setenv(CP.ENV, f"2:{'cd' * 32}")
        assert "follows another chain" in await CP.startup_error(c.db)
        monkeypatch.setenv(CP.ENV, f"{c.height + 5}:{'cd' * 32}")   # above the tip: not yet
        assert await CP.startup_error(c.db) == ""
    finally:
        await c.close()


def test_a_node_offline_past_the_weak_subjectivity_period_is_warned(monkeypatch):
    monkeypatch.delenv(CP.ENV, raising=False)
    period = CP.weak_subjectivity_seconds()
    assert period > 3 * 86400                         # unbonding + withdrawal delay: ~3.9 days
    assert CP.staleness_warning(100, 1_000.0, 1_000.0 + period - 1) is None
    warning = CP.staleness_warning(100, 1_000.0, 1_000.0 + period + 1)
    assert warning and CP.ENV in warning
    monkeypatch.setenv(CP.ENV, f"200:{H}")            # a newer trusted checkpoint: no warning
    assert CP.staleness_warning(100, 1_000.0, 1_000.0 + period + 1) is None
