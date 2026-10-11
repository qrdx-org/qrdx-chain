"""
The incremental exchange commitment (qrdx/exchange/commitment.py, feature
``incremental_state_root``).

The exchange root used to serialize every account, order, pool position, allowance and nonce
on every block — 46 ms at 10,000 perp accounts, 518 ms at 50,000. Each collection now keeps a
digest per entry and re-digests only entries that may have changed. What must hold:

  * a change is never missed: writes mark their key, handing out a mutable value marks it, and
    only the explicit peek* reads do not — so a mutation through peek is exactly what
    ``verify`` exists to catch;
  * copies (the per-block snapshot, a revert) stay consistent and independent;
  * the root depends on the state, not on the order it was reached;
  * a block that changes nothing re-digests nothing: the per-block liquidation scan reads every
    account without marking it;
  * the rule follows the block height (the sequential root before the feature's fork).
"""
import copy
from decimal import Decimal

import pytest

from qrdx import chain_spec as cs
from qrdx.exchange import commitment as C
from qrdx.exchange.clearinghouse import Account, Clearinghouse, Position
from qrdx.exchange.state_manager import ExchangeStateManager

D = Decimal


def _accounts():
    return C.CommittedDict(
        "t.accounts", lambda _k, a: [str(a.collateral)], mutable=True
    )


def test_writes_and_handed_out_values_are_marked_and_peeks_are_not():
    d = _accounts()
    d["a"] = Account(collateral=D(1))
    d["b"] = Account(collateral=D(2))
    d.commitment()
    assert d.dirty_count == 0
    d.peek("a")
    list(d.peek_values())
    list(d.peek_items())
    assert d.dirty_count == 0
    d["a"].collateral += 1          # handed out by [] → marked
    d.get("b").collateral += 1      # handed out by get → marked
    assert d.dirty_count == 2
    d.verify()
    for a in d.values():            # iteration hands out every value → marks them all
        a.collateral += 1
    d.verify()
    d.peek("a").collateral += 1     # a write through a peek: the one thing verify catches
    with pytest.raises(C.CommitmentMismatch):
        d.verify()


def test_immutable_values_are_tracked_exactly():
    n = C.CommittedDict("t.nonces", C.encode_value, mutable=False)
    n["x"] = 1
    n.commitment()
    _ = n["x"], n.get("x"), list(n.items())
    assert n.dirty_count == 0
    n["x"] = 2
    n.pop("x")
    n.setdefault("y", 3)
    n.update({"z": 4})
    n.verify()
    s = C.CommittedSet("t.set", [("a", "b")])
    s.add(("c", "d"))
    s.discard(("a", "b"))
    s |= {("e", "f")}
    s -= {("c", "d")}
    s.verify()
    assert set(s) == {("e", "f")}


def test_copies_are_consistent_and_independent():
    d = _accounts()
    d["a"] = Account(collateral=D(1))
    before = d.commitment()
    deep, shallow = copy.deepcopy(d), d.copy()
    deep["a"].collateral = D(5)
    deep["b"] = Account()
    assert d.commitment() == before and shallow.commitment() == before
    deep.verify()
    d.verify()
    assert deep.commitment() != before


def test_the_commitment_depends_on_the_state_not_the_order():
    a, b = C.CommittedDict("t.n", C.encode_value, mutable=False), C.CommittedDict(
        "t.n", C.encode_value, mutable=False
    )
    for i in range(50):
        a[f"k{i}"] = i
    for i in reversed(range(50)):
        b[f"k{i}"] = -1
        b.commitment()
        b[f"k{i}"] = i
    b["gone"] = 7
    b.commitment()
    del b["gone"]
    assert a.commitment() == b.commitment()


def _clearinghouse(n):
    ch = Clearinghouse()
    m = ch.create_market("BTC", "USD")
    ch.set_oracle_price(m.id, D("65000"), 1000)
    for i in range(n):
        ch.accounts[f"0x{i:040x}"] = Account(
            collateral=D("50000"),
            positions={
                m.id: Position(size=D("0.5") * (1 if i % 2 else -1), entry_price=D("65000"),
                               isolated_margin=D(0))
            },
        )
    return ch


def test_a_quiet_block_re_digests_no_account(monkeypatch):
    ch = _clearinghouse(500)
    ch.tick(D(1001), funding_interval=10**9)
    ch.commitment()
    vectors = []
    real = C._vector
    monkeypatch.setattr(C, "_vector", lambda tag, dg: vectors.append(tag) or real(tag, dg))
    ch.tick(D(1002), funding_interval=10**9)  # marks, EMAs, the liquidation scan of all 500
    ch.commitment()
    assert [t for t in vectors if t == "ch.accounts"] == []
    ch.verify_commitment()                    # (recomputes everything, by design)
    vectors.clear()
    ch.deposit("0x" + "0" * 39 + "7", D(1))   # one account changes → two vectors (out, in)
    ch.commitment()
    assert [t for t in vectors if t == "ch.accounts"] == ["ch.accounts"] * 2


def _manager_with_state(height):
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m._current_block_height = height
    m._nonces["0xPQa"] = 3
    m.clearinghouse.deposit("0xPQa", D(10))
    return m


def test_the_rule_follows_the_block_height():
    spec = cs.build_spec(
        "qrdx-test-commit", 991235, {}, dev=True, features=[],
        forks=[{"name": "inc", "height": 50, "features": ["incremental_state_root"],
                "approval": "none"}])
    try:
        with cs.use_spec(spec):
            before = _manager_with_state(49)
            assert before.compute_state_root() == before._sequential_state_root()
            after = _manager_with_state(50)
            assert after.compute_state_root() == after._incremental_state_root()
            assert after._incremental_state_root() != after._sequential_state_root()
    finally:
        ExchangeStateManager.reset_instance()


def test_a_revert_restores_a_consistent_commitment(monkeypatch):
    monkeypatch.setenv("QRDX_VERIFY_STATE_COMMITMENTS", "1")
    try:
        m = _manager_with_state(5)
        root = m.compute_state_root()
        snap = m.take_snapshot()
        m._nonces["0xPQb"] = 1
        m.clearinghouse.deposit("0xPQb", D(4))
        m.tokens.frozen.add(("0xt", "0xh"))
        assert m.compute_state_root() != root
        m._restore_snapshot(snap)
        assert m.compute_state_root() == root  # (and verify_commitments ran clean)
    finally:
        ExchangeStateManager.reset_instance()
