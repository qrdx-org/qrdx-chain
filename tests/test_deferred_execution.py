"""
Deferred execution (chain-spec feature ``deferred_execution``; qrdx/post_state.py).

A block's signed root is the root of the state its parent left, so a proposer signs before it
runs its block and the next proposer does not wait for the block's own root. What must hold:

* running a signed block cannot make it invalid: an EVM transaction that cannot run is skipped
  and changes nothing (its state and its section's pending records), the rest run; what needs no
  state (signatures, a delegated spend's authority, the section's gas) is still a rule;
* a block's root is checked against the state its parent left, before it runs, and the root of
  what each block leaves is kept by the block's hash;
* the state after block h is vouched for by block h + 1 (proofs, snapshots);
* every path runs a block the same way: the proposer, the live import, sync and the rebuild.

These pin the one-block rule (``two_block_deferral`` off where it matters); the two-block rule
is tests/test_two_block_deferral.py.
"""

import inspect
import os
import tempfile

import pytest
from eth_utils import to_checksum_address

from qrdx import chain_spec, post_state
from qrdx.contracts.evm_block_apply import apply_block_evm_section_total
from qrdx.contracts.state import ContractStateManager
from qrdx.database_sqlite import DatabaseSQLite

from test_evm_block_apply import _raw


def test_the_feature_is_a_genesis_default():
    assert post_state.FEATURE in chain_spec.FEATURES
    assert post_state.FEATURE in chain_spec.GENESIS_DEFAULT_FEATURES


@pytest.fixture
async def evm():
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    sm = ContractStateManager(db)
    yield db, sm
    await db.close()
    os.remove(path)


def _executor(sm, cannot=()):
    """Sets each sender's balance and nonce; answers None (cannot run) for ``cannot`` — after
    writing to the cache, as a transaction that fails half-way would."""
    from qrdx.contracts.evm_mempool import parse_eth_raw_tx
    from qrdx.contracts.native_token_evm import CURRENT_SECTION

    async def execute_tx(raw, height, block_hash, ts):
        p = parse_eth_raw_tx(raw)
        sender = to_checksum_address(p["sender"])
        acc = await sm.get_account(sender)
        acc.balance = 7_000
        acc.nonce = int(p["nonce"]) + 1
        await sm.set_account(acc)
        CURRENT_SECTION.get().record(tx_hash=p["tx_hash"], status=1)
        if raw in cannot:
            return None
        return {"success": True, "tx_hash": p["tx_hash"], "sender": sender}

    return execute_tx


async def test_an_evm_transaction_that_cannot_run_is_skipped_whole(evm):
    db, sm = evm
    (a, a_addr), (b, b_addr), (c, c_addr) = _raw(1), _raw(2), _raw(3)
    ok, err, ran = await apply_block_evm_section_total(
        1, "h", 0, [a, b, c], db, sm, _executor(sm, cannot={b})
    )
    assert ok, err
    assert ran == [a, c]
    cur = await db.connection.execute("SELECT address FROM account_state ORDER BY address")
    held = {r[0].lower() for r in await cur.fetchall()}
    assert a_addr.lower() in held and c_addr.lower() in held
    assert b_addr.lower() not in held                      # (nothing of it survives)


async def test_what_needs_no_state_is_still_a_rule(evm):
    db, sm = evm
    a, _ = _raw(1)
    ok, err, ran = await apply_block_evm_section_total(
        1, "h", 0, [a, "0xdeadbeef"], db, sm, _executor(sm)
    )
    assert not ok and "failed verification" in err and ran == []
    cur = await db.connection.execute("SELECT COUNT(*) FROM account_state")
    assert (await cur.fetchone())[0] == 0                  # (refused before anything ran)


async def test_running_a_section_twice_leaves_the_same_state(evm):
    db, sm = evm
    txs = [_raw(i)[0] for i in range(1, 5)]
    await apply_block_evm_section_total(1, "h", 0, txs, db, sm, _executor(sm, cannot={txs[2]}))
    first = await db.get_account_state_root()
    path2 = tempfile.mktemp(suffix=".db")
    db2 = await DatabaseSQLite.create(db_path=path2)
    try:
        sm2 = ContractStateManager(db2)
        await apply_block_evm_section_total(
            1, "h", 0, txs, db2, sm2, _executor(sm2, cannot={txs[2]})
        )
        assert await db2.get_account_state_root() == first
    finally:
        await db2.close()
        os.remove(path2)


class _Blocks:
    """Blocks by height, for ``signed_root_of_state``."""

    def __init__(self, roots):
        self.roots = roots

    async def get_block_by_id(self, h):
        if h not in self.roots:
            return None
        return {"content": str({"state_root": self.roots[h], "slot": h})}


def _one_block(monkeypatch):
    monkeypatch.setattr(post_state, "two_blocks", lambda height: False)


async def test_the_state_after_a_block_is_vouched_for_by_the_next(monkeypatch):
    _one_block(monkeypatch)
    db = _Blocks({4: "aa" * 64, 5: "bb" * 64})
    assert await post_state.signed_root_of_state(db, 4) == ("bb" * 64, 5)
    assert await post_state.signed_root_of_state(db, 5) == (None, 6)   # (not signed yet)


async def test_a_root_is_checked_against_the_state_the_parent_left(monkeypatch):
    computed = []

    async def unified_root(db, height, slot):
        computed.append(height)
        return "cc" * 64

    class _Db:
        async def get_block_hashes(self, lo, hi):
            return {lo: "parent-hash"}

        async def get_next_block_id(self):
            return 8

    _one_block(monkeypatch)
    monkeypatch.setattr(post_state, "unified_root", unified_root)
    monkeypatch.setattr(post_state, "_slot_of", lambda db, h: _none())
    post_state.forget()
    good = str({"state_root": "cc" * 64})
    assert await post_state.check(_Db(), good, 8) == (True, "")
    assert computed == [7]                                  # (the parent's state, once…)
    assert await post_state.check(_Db(), good, 8) == (True, "")
    assert computed == [7]                                  # (…then kept by its hash)
    ok, why = await post_state.check(_Db(), str({"state_root": "dd" * 64}), 8)
    assert not ok and "mismatch" in why
    assert (await post_state.check(_Db(), str({"slot": 1}), 8))[0] is False


async def _none():
    return None


def test_the_kept_roots_are_bounded():
    post_state.forget()
    for i in range(post_state.KEEP + 10):
        post_state.remember(f"h{i}", f"r{i}")
    assert post_state.kept("h0") is None and post_state.kept(f"h{post_state.KEEP + 9}")


def test_every_path_runs_a_block_the_same_way():
    """The proposer, the live import, sync and the rebuild: the root is checked before the block
    runs, its EVM section runs whole, and the root of what it leaves is kept."""
    from qrdx import derived_state_rebuild
    from qrdx.node import block_import, evm_runtime
    from qrdx.rpc.modules import p2p
    from qrdx.validator import node_integration as NI

    assert "_check_deferred_root(" in inspect.getsource(p2p.P2PModule.submitBlock)
    assert "_check_deferred_root(" in inspect.getsource(block_import.process_and_create_block)
    from qrdx.node.api import blocks as rest

    assert "_check_deferred_root(" in inspect.getsource(rest)
    assert "block_hash=block_hash" in inspect.getsource(rest)
    assert "apply_block_evm_section_total(" in inspect.getsource(
        evm_runtime._apply_evm_section_on_import
    )
    assert "apply_block_evm_section_total(" in inspect.getsource(derived_state_rebuild._replay)
    build = inspect.getsource(NI.ValidatorNode._build_deferred)
    assert build.index("_select_sections(") < build.index("_sign_and_send(")
    assert build.index("_sign_and_send(") < build.index("_run_and_store(")
    send = inspect.getsource(NI.ValidatorNode._sign_and_send)
    assert send.index("root_after(") < send.index("propose_block(") < send.index(
        "broadcast_callback("
    )
    run = inspect.getsource(NI.ValidatorNode._run_and_store)
    assert run.index("_run_signed_block(") < run.index("post_state.settle(")
    assert run.index("post_state.settle(") < run.index("add_block(")
    verify = inspect.getsource(block_import._verify_unified_state_root)
    assert "post_state.settle(" in verify


def test_a_failed_section_refuses_the_block_under_the_feature():
    """Under deferred execution no block declares its own exchange root, and a section that
    does not run refuses the block (it used to be adopted on the root-less path)."""
    from qrdx.node import block_import

    src = inspect.getsource(block_import._apply_exchange_section_on_import)
    assert "if deferred:\n                return False, err" in src
