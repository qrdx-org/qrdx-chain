"""
Exchange state is provable too (qrdx/exchange/proofs.py, docs/STATE_PROOFS.md): every committed
collection and order book keeps its own tree, kept with the same changes as its digest and
undone with it; a top tree over them and the parts (markets, pools, books, the oracle) gives the
exchange tree root, combined with the database tree's into the proof root every block signs.
"""
import os
import tempfile
from decimal import Decimal as D

import pytest
from test_evm_world import ALICE, Chain, chain  # noqa: F401  (fixture)

from qrdx import state_proofs
from qrdx.contracts.evm_world import STATE_PROOF_ADDRESS
from qrdx.contracts.state_proof_evm import encode
from qrdx.crypto.hashing import unified_state_root
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.orderbook import Order, OrderSide, OrderType

T0 = 1_700_000_000
OWNER = "0xPQ" + "a" * 64
MID = "BTC-QRDX-PERP"
PARTS = {"utxo": "1" * 64, "account": "2" * 128, "exchange": "3" * 128, "token": "4" * 128}


def _tx(m, who, op, **params):
    r = m.process_transaction(ExchangeTransaction(
        op_type=op, sender=who, nonce=m.get_nonce(who), params=params, gas_limit=10 ** 6))
    assert r.success, r.error
    return r


@pytest.fixture
def m():
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    mgr.set_available_balance(OWNER, D(1_000))
    _tx(mgr, OWNER, Op.QNS_REGISTER, name="alice")
    ch = mgr.clearinghouse
    ch.create_market("BTC")
    ch.set_oracle_price(MID, D(30000), now=T0)
    ch.deposit(OWNER, D(50_000))
    ch.deposit("0xPQmaker", D(50_000))
    ch.place_order("0xPQmaker", MID, "ask1", "sell", D(1), D(30100), 1)
    yield mgr
    ExchangeStateManager.reset_instance()


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    d = await DatabaseSQLite.create(path)
    yield d
    await d.connection.close()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.remove(p)


async def _seal(db, mgr, height):
    """What every path does at a block: both trees, the proof root, the signed root."""
    mgr.compute_state_root()
    xroot = mgr.exchange_proof_root(height)
    root = await state_proofs.proof_root(db, height, xroot)
    await state_proofs.record_parts(db, height, {**PARTS, "proof": root, "xtree": xroot.hex()})
    await db.connection.commit()
    return unified_state_root(*PARTS.values(), root)


async def test_exchange_entries_parts_and_levels_are_proven(db, m):
    signed = await _seal(db, m, 1)
    name = await state_proofs.prove_exchange(db, m, "qns.names", "alice.qrdx")
    assert name["entry"] and b"alice.qrdx" in bytes.fromhex(name["entry"])
    assert state_proofs.verify_against(signed, name)
    acct = await state_proofs.prove_exchange(db, m, "ch.accounts", OWNER)
    assert state_proofs.verify_against(signed, acct)
    market = await state_proofs.prove_exchange(db, m, f"market:{MID}", part=True)
    assert b"30000" in bytes.fromhex(market["entry"])
    assert state_proofs.verify_against(signed, market)
    level = await state_proofs.prove_exchange(db, m, f"perp:{MID}", "a30100")
    assert level["entry"] and b"ask1" in bytes.fromhex(level["entry"])
    assert state_proofs.verify_against(signed, level)


async def test_absence_is_proven_and_nothing_false_verifies(db, m):
    signed = await _seal(db, m, 1)
    nobody = await state_proofs.prove_exchange(db, m, "qns.names", "bob.qrdx")
    assert nobody["entry"] is None and state_proofs.verify_against(signed, nobody)
    empty = await state_proofs.prove_exchange(db, m, "gov.proposals", 1)      # no collection
    assert empty["entry"] is None and state_proofs.verify_against(signed, empty)
    name = await state_proofs.prove_exchange(db, m, "qns.names", "alice.qrdx")
    forged = bytearray.fromhex(name["entry"])
    forged[-3] ^= 1
    assert not state_proofs.verify_against(signed, {**name, "entry": forged.hex()})
    assert not state_proofs.verify_against(signed, {**name, "path": "qns.primary"})
    assert not state_proofs.verify_against(signed, {**name, "entry": None})


async def test_a_database_proof_reaches_the_root_through_the_exchange_tree_too(db, m):
    await db.apply_account_balance_delta("0x" + "a1" * 20, D(3))
    signed = await _seal(db, m, 1)
    p = await state_proofs.prove(db, "account", "0x" + "a1" * 20)
    assert state_proofs.verify_against(signed, p)
    assert not state_proofs.verify_against(signed, {**p, "exchange_tree_root": "00" * 32})


def test_the_exchange_root_follows_a_restore(m):
    """The trees travel with the state: a snapshot restored gives its own root back."""
    before = m.exchange_proof_root()
    snap = m.capture()
    m.clearinghouse.deposit("0xPQother", D(7))
    m.begin_block(2, float(T0 + 1))
    _tx(m, OWNER, Op.QNS_SET_RECORD, name="alice", key="url", value="https://x")
    assert m.exchange_proof_root() != before
    m._restore_snapshot(snap)
    assert m.exchange_proof_root() == before


def test_a_failed_operation_leaves_the_trees_as_they_were(m):
    """It consumes its nonce, nothing else: the collections it wrote before failing (the NFT it
    minted, the name) are undone, trees included."""
    from qrdx.crypto import smt

    def roots():
        return [smt.m_root(m.nfts.items.tree), smt.m_root(m.qns.names.tree),
                smt.m_root(m.nfts.collections.tree)]

    before = roots()
    r = m.process_transaction(ExchangeTransaction(
        op_type=Op.QNS_REGISTER, sender="0xPQpoor", nonce=0, params={"name": "poor"},
        gas_limit=10 ** 6))
    assert not r.success
    assert roots() == before
    m.verify_commitments()                                       # every tree = its entries


def test_spot_book_levels_have_their_own_tree():
    from qrdx.crypto import smt
    from qrdx.exchange.orderbook import OrderBook

    book = OrderBook("A:B")
    for i, price in enumerate(("10", "11", "12")):
        book.place_order(Order(id=f"o{i}", owner="0xPQs", side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=D(price), amount=D(1),
                               nonce=0, timestamp=0.0))
    t = book.level_tree
    siblings, terminal, payload = smt.m_prove(t, OrderBook.level_key("a", D("11")))
    assert payload and b"o1" in payload
    assert smt.verify(t.hash, OrderBook.level_key("a", D("11")), smt.value_hash(payload),
                      siblings, terminal)
    book.cancel_order("o1", caller="0xPQs")
    book.verify_digest()                                         # the tree followed


async def test_a_contract_verifies_an_exchange_entry(chain):
    """On chain: a name's record, against an ancestor block's signed root."""
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    mgr.set_available_balance(OWNER, D(1_000))
    _tx(mgr, OWNER, Op.QNS_REGISTER, name="carol")
    signed = await _seal(chain.db, mgr, 1)
    await chain.db.connection.execute(
        "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
        ("1" * 64, 1, repr({"number": 1, "state_root": signed})))
    await chain.db.connection.commit()
    p = await state_proofs.prove_exchange(chain.db, mgr, "qns.names", "carol.qrdx")
    r = await chain.tx(ALICE, STATE_PROOF_ADDRESS, encode(p))
    assert r.success and int.from_bytes(r.output, "big") == 1
    forged = bytearray.fromhex(p["entry"])
    forged[-3] ^= 1
    r = await chain.tx(ALICE, STATE_PROOF_ADDRESS, encode(p, entry_override=bytes(forged)))
    assert int.from_bytes(r.output, "big") == 0
    part = await state_proofs.prove_exchange(chain.db, mgr, "oracle", part=True)
    r = await chain.tx(ALICE, STATE_PROOF_ADDRESS, encode(part))
    assert int.from_bytes(r.output, "big") == 1
