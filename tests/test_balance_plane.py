"""
The balance plane (qrdx/exchange/balance_plane.py, native/qrdx-native/src/plane.rs): the
exchange's per-block QRDX dicts held natively, read and written by Python through views.

A view must be the dict it stands for — every operation Python's code (and the undo scopes) uses,
with the same results, the same keys in the same order, and back the value that was set (a
``Decimal`` the module keeps natively, anything else as it is). What the plane does natively — the
fee reservations, the pre-loads — must leave the maps as Python's own loops leave the dicts. The
lanes are held to Python's path in tests/test_transfer_lane.py and tests/test_order_lane.py.
"""

import random
from decimal import Decimal

import pytest

pytest.importorskip("qrdx_native")

from qrdx.exchange import balance_plane, undo  # noqa: E402
from qrdx.exchange.state_manager import ExchangeStateManager  # noqa: E402

if not balance_plane.enabled():  # pragma: no cover
    pytest.skip("the balance plane is off", allow_module_level=True)

KEYS = ["0xPQ" + f"{i:064x}" for i in range(12)] + ["0xSUBA" + "ab" * 20, "0x" + "cd" * 20]
VALUES = [
    "0", "-0", "1", "1.50", "-2", "3E+2", "0E-8", "1000000.000000000000000001",
    "-0.000000000000000001", "123456789012345678901234567890.123456789", "1E-30", "NaN",
    "-Infinity", "9" * 80,
]  # fmt: skip


def _value(rng):
    k = rng.random()
    if k < 0.85:
        return Decimal(rng.choice(VALUES))
    return rng.choice([7, None, "text", 1.5])  # (anything else, kept as it is)


def _same(view, d):
    assert len(view) == len(d)
    assert list(view) == list(d) and view.keys() == list(d.keys())
    got, want = view.items(), list(d.items())
    for (k1, v1), (k2, v2) in zip(got, want, strict=True):
        assert k1 == k2
        assert type(v1) is type(v2)
        assert (v1 is v2) or (str(v1) == str(v2) and repr(v1) == repr(v2)), (k1, v1, v2)
    assert view.copy() == d or any(isinstance(v, Decimal) and v.is_nan() for v in d.values())


@pytest.mark.parametrize("seed", range(8))
def test_a_view_is_the_dict_it_stands_for(seed):
    rng = random.Random(seed)
    (view,) = balance_plane.views(balance_plane.make())[2:3]
    d = {}
    for _ in range(3000):
        k = rng.random()
        key = rng.choice(KEYS)
        if k < 0.35:
            v = _value(rng)
            view[key] = v
            d[key] = v
        elif k < 0.45:
            assert (key in view) == (key in d)
            assert view.get(key) is None if key not in d else str(view.get(key)) == str(d[key])
            assert view.get(key, "x") == "x" if key not in d else True
        elif k < 0.55:
            default = rng.choice([None, "absent"])
            if key in d:
                assert str(view.pop(key)) == str(d.pop(key))
            elif default is not None:
                assert view.pop(key, default) == d.pop(key, default) == default
            else:
                with pytest.raises(KeyError):
                    view.pop(key)
        elif k < 0.6:
            if key in d:
                del view[key], d[key]
            else:
                with pytest.raises(KeyError):
                    del view[key]
                with pytest.raises(KeyError):
                    view[key]
        elif k < 0.65:
            v = _value(rng)
            assert str(view.setdefault(key, v)) == str(d.setdefault(key, v))
        elif k < 0.68 and d:
            a, b = view.popitem(), d.popitem()
            assert a[0] == b[0] and str(a[1]) == str(b[1])
        elif k < 0.7:
            view.clear()
            d.clear()
        elif k < 0.75:
            more = {rng.choice(KEYS): _value(rng) for _ in range(3)}
            view.update(more)
            d.update(more)
        assert (key in view) == (key in d)
        _same(view, d)
    assert 5 not in view and view.get(5) is None  # (a key that is not an address: absent)
    with pytest.raises(TypeError):
        view[5] = Decimal(1)


def _manager(plane):
    m = ExchangeStateManager()
    m.use_plane(plane)
    assert (m._plane is not None) == plane
    return m


def _maps(m):
    return {
        name: [(k, str(v)) for k, v in getattr(m, name).items()]
        for name in ("_available_balances", "_start_balances", "_balance_deltas", "_fees_reserved")
    }


@pytest.mark.parametrize("seed", range(10))
def test_reservations_and_loads_are_pythons(seed, monkeypatch):
    """``reserve_section_fees`` and ``set_available_balances`` natively, as Python's loops."""
    rng = random.Random(seed)
    py, nat = _manager(False), _manager(True)
    for m in (py, nat):
        m.enforce_fees = True
    for block in range(6):
        loads = [
            (rng.choice(KEYS), Decimal(rng.choice(["0", "5", "1000", "3.333", "1E+3", "0.1"])))
            for _ in range(rng.randint(0, 10))
        ]
        payers = [
            (rng.choice(KEYS), Decimal(rng.choice(["0.00214", "1", "0.000000001", "2.5E-5"])))
            for _ in range(rng.randint(0, 25))
        ]
        reserve = rng.choice([None, Decimal(1)])
        for m in (py, nat):
            m.clear_available_balances()
            m.set_available_balances(loads)
            m.begin_block(block + 1, 1_800_000_000.0 + block)
            m._fee_reserve = reserve
            # (the reservations of a section whose payers are known: each stand-in transaction
            # names its maximum fee, ``fee_payer`` its payer)
            class _Tx:
                def __init__(self, fee):
                    self.fee = fee

                def free_eligible(self):
                    return False

                def max_fee(self):
                    return self.fee

            section = [_Tx(fee) for _, fee in payers]
            by_tx = {id(t): p for t, p in zip(section, payers, strict=True)}
            monkeypatch.setattr(m, "fee_payer", lambda tx, by=by_tx: by[id(tx)][0])
            out = m.reserve_section_fees(section)
            assert [(p, str(f)) for p, f in out] == [(p, str(f)) for p, f in payers]
        assert _maps(py) == _maps(nat), f"seed {seed} block {block}"


def test_a_value_it_does_not_compute_with_goes_to_python():
    """A delta that is not a native value (an int someone set): the plane refuses to reserve
    in place, writing nothing, and the manager reserves through Python — as Python's."""
    py, nat = _manager(False), _manager(True)
    for m in (py, nat):
        m.enforce_fees = True
        m.begin_block(1, 1_800_000_000.0)
        m._reserve_fee(KEYS[1], Decimal("0.5"))
        m._balance_deltas[KEYS[0]] = 7  # (not a Decimal: kept as it is)
    assert nat._plane.reserve([(KEYS[0], "0.1")], False) is False
    assert _maps(py) == _maps(nat)  # (nothing written)
    for m in (py, nat):
        for k, v in [(KEYS[0], Decimal("0.25")), (KEYS[1], Decimal("0.25"))]:
            m._reserve_fee(k, v)
    assert _maps(py) == _maps(nat)


def test_inside_an_operations_scope_the_plane_is_written_as_dicts_are():
    """An operation's undo scope records each entry it changes: there the batch paths go through
    Python's own (recorded) writes, and a rollback puts back what it put back with dicts."""
    out = []
    for plane in (False, True):
        m = _manager(plane)
        m.set_available_balances([(KEYS[0], Decimal(5))])
        scope = undo.Scope(None)
        token = undo._ACTIVE.set(scope)
        try:
            assert not balance_plane.in_place()
            m.set_available_balances([(KEYS[0], Decimal(9)), (KEYS[1], Decimal(1))])
            m._record_balance_delta(KEYS[0], Decimal(-2))
            assert m.available_balance(KEYS[0]) == Decimal(7)
            during = _maps(m)
        finally:
            undo._ACTIVE.reset(token)
        scope.rollback()
        out.append((during, _maps(m)))
    assert out[0] == out[1]
    assert out[1][1]["_available_balances"] == [(KEYS[0], "5")]


def test_the_address_table_is_kept_to_what_the_maps_hold():
    """Addresses no map holds any more are forgotten once they are most of the table — the
    values and the order of what is held kept."""
    m = _manager(True)
    for block in range(12):
        m.clear_available_balances()
        m.begin_block(block + 1, 1_800_000_000.0 + block)
        fresh = [("0xPQ" + f"{block:08x}{i:056x}", Decimal(i)) for i in range(1500)]
        m.set_available_balances(fresh)
        m._balance_deltas[fresh[7][0]] = Decimal("-1.5")
        m._balance_deltas[fresh[3][0]] = Decimal("2")
        assert list(m._balance_deltas.items()) == [
            (fresh[7][0], Decimal("-1.5")),
            (fresh[3][0], Decimal(2)),
        ]
        assert m.available_balance(fresh[1499][0]) == Decimal(1499)
        assert len(m._available_balances) == 1500


@pytest.mark.parametrize("seed", range(4))
def test_the_flush_amounts_are_pythons(seed):
    """What the flush applies (``Plane.wei``): each delta's ``int(Decimal(str(d)) * 10**18)``,
    in the deltas' order, and its sign; None (Python flushes) where a delta is not native."""
    from qrdx.exchange import amm  # noqa: F401  (the exchange's context, as in the node)

    rng = random.Random(seed)
    m = _manager(True)
    want = []
    for key in rng.sample(KEYS, len(KEYS)):
        v = Decimal(rng.choice([x for x in VALUES if x not in ("NaN", "-Infinity")]))
        if rng.random() < 0.5:
            v = v.scaleb(rng.randint(-25, 5))
        m._balance_deltas[key] = v
        want.append((key, int(Decimal(str(v)) * Decimal(10**18)), v < 0))
    got = m._plane.wei(balance_plane.DELTA)
    assert [(k, w, n) for k, w, n in got] == want
    assert all(type(w) is int for _k, w, _n in got)
    m._balance_deltas[KEYS[0]] = 3  # (not native)
    assert m._plane.wei(balance_plane.DELTA) is None


def test_outside_the_exchanges_context_python_computes():
    """The plane's arithmetic is the exchange's context (precision 78, half-even): under any
    other, nothing is computed natively."""
    import decimal

    from qrdx.exchange import amm  # noqa: F401

    assert balance_plane.in_place() and balance_plane.exchange_context()
    with decimal.localcontext(decimal.Context(prec=28)):
        assert not balance_plane.in_place() and not balance_plane.exchange_context()
    with decimal.localcontext(decimal.Context(prec=78, rounding=decimal.ROUND_DOWN)):
        assert not balance_plane.exchange_context()
