"""
E-D3b core — atomic validate/replay of a block's EVM section.

`apply_block_evm_section` is the consensus enforcement an importing node runs
before accepting a block's EVM section (the account/EVM analog of
`apply_block_exchange_section`). These tests pin the security-critical contract
against the REAL `account_state` table + `db.get_account_state_root()`:

  - a section whose declared account_state_root matches the deterministic replay
    is accepted and PERSISTED,
  - a section whose declared root does NOT match is rejected and leaves
    account_state byte-for-byte untouched (DB rollback + cache revert),
  - a forged/malformed tx rejects the whole block before any state is touched,
  - a missing declared root rejects a non-empty section,
  - an empty/absent section is a no-op success.

The EVM executor is injected, so these tests use a lightweight fake that mutates
the ContractStateManager cache with defer_commit semantics — exactly what the
live `_execute_evm_raw_tx(..., defer_commit=True)` does — without standing up a
full py-evm. The flush-read-decide boundary it exercises is identical.
"""

import os
import tempfile

from eth_account import Account as EthAccount
from eth_utils import to_checksum_address

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.contracts.state import ContractStateManager, Account
from qrdx.contracts.evm_block_apply import (
    apply_block_evm_section,
    produce_block_evm_section,
)


def _raw(i, nonce=0, value=1):
    """A validly-signed legacy tx (parse_eth_raw_tx must accept it)."""
    key = "0x" + f"{i:064x}"
    acct = EthAccount.from_key(key)
    tx = {"nonce": nonce, "gasPrice": 10 ** 9, "gas": 21000,
          "to": acct.address, "value": value, "data": b"", "chainId": 1}
    signed = EthAccount.sign_transaction(tx, key)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    return "0x" + bytes(raw).hex(), to_checksum_address(acct.address)


async def _setup():
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    sm = ContractStateManager(db)
    return db, sm, path


def _make_executor(sm, credit):
    """
    Fake deterministic executor: for each tx, set the sender's cached balance to
    a fixed `credit` amount (keeping the change in the cache, like defer_commit).
    Returns a result dict shaped like `_execute_evm_raw_tx`.
    """
    async def execute_tx(raw_tx_hex, block_height, block_hash, block_timestamp):
        from qrdx.contracts.evm_mempool import parse_eth_raw_tx
        p = parse_eth_raw_tx(raw_tx_hex)
        sender = to_checksum_address(p["sender"])
        acc = await sm.get_account(sender)
        acc.balance = credit
        acc.nonce = int(p["nonce"]) + 1
        await sm.set_account(acc)
        return {"success": True, "tx_hash": p["tx_hash"], "sender": sender,
                "nonce": p["nonce"], "created_address": None}
    return execute_tx


async def _db_root(db):
    return await db.get_account_state_root()


async def _db_account_count(db):
    cur = await db.connection.execute("SELECT COUNT(*) FROM account_state")
    row = await cur.fetchone()
    return int(row[0])


# ── helper to compute what the root WILL be after a replay, deterministically ──
async def _expected_root_after(db, sm_factory, raw_txs, credit):
    """Run the same replay on a throwaway manager, flush, read root, rollback."""
    sm = sm_factory()
    ex = _make_executor(sm, credit)
    for raw, _ in [(r, s) for r, s in raw_txs]:
        await ex(raw, 1, "h", 0)
    await sm.commit(1, flush_only=True)
    root = await db.get_account_state_root()
    await db.connection.rollback()
    return root


async def test_accept_persists_matching_root():
    db, sm, path = await _setup()
    try:
        txs = [_raw(1), _raw(2)]
        raws = [t[0] for t in txs]

        # Compute the root the proposer would declare by replaying identically.
        declared = await _expected_root_after(db, lambda: ContractStateManager(db), txs, credit=5000)

        ok, err = await apply_block_evm_section(
            1, "h", 0, raws, declared, db, sm, _make_executor(sm, 5000))
        assert ok, err
        # Persisted: a fresh read of the committed table equals the declared root.
        assert await _db_root(db) == declared
        assert await _db_account_count(db) == 2
    finally:
        await db.close(); os.remove(path)


async def test_reject_on_root_mismatch_leaves_state_untouched():
    db, sm, path = await _setup()
    try:
        # Pre-seed one committed account so we can prove it survives a rejection.
        seed = ContractStateManager(db)
        a = await seed.get_account(to_checksum_address("0x" + "ab" * 20))
        a.balance = 111
        await seed.set_account(a)
        await seed.commit(0)
        root_before = await _db_root(db)
        count_before = await _db_account_count(db)

        txs = [_raw(3), _raw(4)]
        raws = [t[0] for t in txs]
        bad_declared = "f" * 128  # deliberately wrong root

        ok, err = await apply_block_evm_section(
            1, "h", 0, raws, bad_declared, db, sm, _make_executor(sm, 9999))
        assert not ok
        assert "mismatch" in err
        # Byte-for-byte unchanged: rollback discarded the flush, revert cleared cache.
        assert await _db_root(db) == root_before
        assert await _db_account_count(db) == count_before
    finally:
        await db.close(); os.remove(path)


async def test_forged_tx_rejects_block_before_touching_state():
    db, sm, path = await _setup()
    try:
        root_before = await _db_root(db)
        good = _raw(5)[0]
        forged = "0xdeadbeef"  # not a valid signed tx
        ok, err = await apply_block_evm_section(
            1, "h", 0, [good, forged], "a" * 128, db, sm, _make_executor(sm, 1))
        assert not ok
        assert "failed verification" in err
        assert await _db_root(db) == root_before
        assert await _db_account_count(db) == 0
    finally:
        await db.close(); os.remove(path)


async def test_missing_declared_root_rejects_nonempty_section():
    db, sm, path = await _setup()
    try:
        ok, err = await apply_block_evm_section(
            1, "h", 0, [_raw(6)[0]], None, db, sm, _make_executor(sm, 1))
        assert not ok
        assert "no account_state_root" in err
    finally:
        await db.close(); os.remove(path)


async def test_empty_section_is_noop_success():
    db, sm, path = await _setup()
    try:
        ok, err = await apply_block_evm_section(1, "h", 0, [], None, db, sm, _make_executor(sm, 1))
        assert ok and err == ""
        ok2, err2 = await apply_block_evm_section(1, "h", 0, None, None, db, sm, _make_executor(sm, 1))
        assert ok2 and err2 == ""
        assert await _db_account_count(db) == 0
    finally:
        await db.close(); os.remove(path)


async def test_proposer_produce_then_importer_apply_agree():
    """A block the proposer produces is always importable: produce → apply round-trip."""
    db_p, sm_p, pp = await _setup()   # proposer node
    db_i, sm_i, pi = await _setup()   # importer node
    try:
        txs = [_raw(10), _raw(11), _raw(12)]
        raws = [t[0] for t in txs]

        # Proposer executes + declares the root and the included section.
        root, included = await produce_block_evm_section(
            5, "h5", 0, raws, db_p, sm_p, _make_executor(sm_p, 7777))
        assert root is not None
        assert included == raws  # all txs executed cleanly ⇒ whole section shipped

        # Importer replays the declared section + root and must accept.
        ok, err = await apply_block_evm_section(
            5, "h5", 0, included, root, db_i, sm_i, _make_executor(sm_i, 7777))
        assert ok, err
        # Both nodes hold identical committed account state.
        assert await _db_root(db_p) == await _db_root(db_i) == root
    finally:
        await db_p.close(); os.remove(pp)
        await db_i.close(); os.remove(pi)


async def test_produce_empty_is_noop():
    db, sm, path = await _setup()
    try:
        root, included = await produce_block_evm_section(1, "h", 0, [], db, sm, _make_executor(sm, 1))
        assert root is None and included == []
        assert await _db_account_count(db) == 0
    finally:
        await db.close(); os.remove(path)


async def test_replay_is_deterministic_same_root_two_runs():
    """Two independent nodes replaying the same section get the same root."""
    db1, sm1, p1 = await _setup()
    db2, sm2, p2 = await _setup()
    try:
        txs = [_raw(7), _raw(8), _raw(9)]
        raws = [t[0] for t in txs]
        declared = await _expected_root_after(db1, lambda: ContractStateManager(db1), txs, credit=4242)

        ok1, _ = await apply_block_evm_section(1, "h", 0, raws, declared, db1, sm1, _make_executor(sm1, 4242))
        ok2, _ = await apply_block_evm_section(1, "h", 0, raws, declared, db2, sm2, _make_executor(sm2, 4242))
        assert ok1 and ok2
        assert await _db_root(db1) == await _db_root(db2) == declared
    finally:
        await db1.close(); os.remove(p1)
        await db2.close(); os.remove(p2)
