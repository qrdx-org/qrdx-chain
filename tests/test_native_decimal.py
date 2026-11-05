"""
The exchange engine's decimal (native/qrdx-native/src/dec.rs) is Python's ``Decimal``.

Every amount, price and fee the exchange computes is a ``Decimal`` under a context; a native
component that computes another digit computes another state root. On random values — amounts
and prices shaped like the exchange's, long coefficients at and past the precision, every form of
zero, negative values, values far apart in scale — in every rounding and the precisions the
exchange uses, each operation must give Python's result, string for string. Where it refuses
(None), Python must be raising or the values must be outside what the exchange computes with.
"""

import random
from decimal import (
    ROUND_05UP,
    ROUND_CEILING,
    ROUND_DOWN,
    ROUND_FLOOR,
    ROUND_HALF_DOWN,
    ROUND_HALF_EVEN,
    ROUND_HALF_UP,
    ROUND_UP,
    Context,
    Decimal,
    DecimalException,
    localcontext,
)

import pytest

N = pytest.importorskip("qrdx_native")

ROUNDINGS = [ROUND_DOWN, ROUND_UP, ROUND_HALF_UP, ROUND_HALF_DOWN, ROUND_HALF_EVEN,
             ROUND_CEILING, ROUND_FLOOR, ROUND_05UP]
OPS = ["add", "sub", "mul", "div", "quantize", "cmp"]


def _value(rng):
    k = rng.random()
    sign = "-" if rng.random() < 0.3 else ""
    if k < 0.08:
        return rng.choice(["0", "-0", "0E-18", "-0E-18", "0E+5", "0.000", "0E-2"])
    if k < 0.45:  # an amount or a price with up to 18 decimals
        whole = str(rng.randint(0, 10 ** rng.randint(0, 12)))
        frac = "".join(rng.choice("0123456789") for _ in range(rng.randint(0, 18)))
        return f"{sign}{whole}.{frac}" if frac else f"{sign}{whole}"
    if k < 0.6:  # a fee rate, a small fraction
        return f"{sign}0.{'0' * rng.randint(0, 6)}{rng.randint(1, 99999)}"
    if k < 0.8:  # a long coefficient, around and past the precision
        digits = "".join(rng.choice("0123456789") for _ in range(rng.randint(1, 100)))
        return f"{sign}{digits.lstrip('0') or '0'}E{rng.randint(-60, 60):+d}"
    if k < 0.9:  # halves and boundaries: rounding's edge cases
        base = rng.choice(["5", "15", "25", "45", "95", "999", "9999999", "1", "50", "05"])
        return f"{sign}{base}E{rng.randint(-20, 5):+d}"
    return f"{sign}{rng.randint(1, 9)}E{rng.randint(-40, 40):+d}"


def _python(op, a, b, prec, rounding):
    with localcontext(Context(prec=prec, rounding=rounding)):
        x, y = Decimal(a), Decimal(b)
        try:
            if op == "add":
                return str(x + y)
            if op == "sub":
                return str(x - y)
            if op == "mul":
                return str(x * y)
            if op == "div":
                return str(x / y)
            if op == "quantize":
                return str(x.quantize(y))
            return str((x > y) - (x < y))
        except DecimalException:
            return None


@pytest.mark.parametrize("seed", range(8))
def test_every_operation_is_pythons(seed):
    rng = random.Random(seed)
    refused = 0
    for _ in range(12_000):
        op = rng.choice(OPS)
        a, b = _value(rng), _value(rng)
        if op == "quantize":
            b = f"1E{rng.randint(-24, 8):+d}"
        prec = rng.choice([78, 78, 78, 28, 18, 9, 3, 1])
        rounding = rng.choice(ROUNDINGS)
        want = _python(op, a, b, prec, rounding)
        got = N.dec_eval(op, a, b, prec, rounding)
        if got is None:
            refused += 1
            assert want is None, f"refused {op}({a}, {b}) prec {prec} {rounding}: Python {want}"
        else:
            assert got == want, f"{op}({a}, {b}) prec {prec} {rounding}: {got} != {want}"
    assert refused < 2_000  # (division by zero, a quantize past the precision)


def test_the_exchanges_context_on_its_own_values():
    """Prices × amounts, fees, divisions — precision 78, half-even, as the exchange computes."""
    rng = random.Random(77)
    for _ in range(20_000):
        price = f"{rng.randint(0, 10 ** 6)}.{rng.randint(0, 10 ** 18):018d}"
        amount = f"{rng.randint(0, 10 ** 9)}.{rng.randint(0, 10 ** 18):018d}"
        for op in ("mul", "div", "add", "sub"):
            want = _python(op, price, amount, 78, ROUND_HALF_EVEN)
            assert N.dec_eval(op, price, amount, 78, ROUND_HALF_EVEN) == want
        for r in (ROUND_HALF_EVEN, ROUND_FLOOR, ROUND_CEILING, ROUND_DOWN, ROUND_HALF_UP):
            q = _python("mul", price, amount, 78, ROUND_HALF_EVEN)
            assert N.dec_eval("quantize", q, "1E-18", 78, r) == _python("quantize", q, "1E-18",
                                                                       78, r)


def test_what_it_does_not_read_is_left_to_python():
    for text in ["NaN", "Infinity", "-Infinity", "sNaN", " 1", "1 ", "1_000", "١", "1e", "e5",
                 ".", "+", "1E+9999999", "0x10"]:
        assert N.dec_eval("add", text, "1", 78, ROUND_HALF_EVEN) is None, text
    assert N.dec_eval("add", "1", "1", 78, "ROUND_SIDEWAYS") is None
    assert N.dec_eval("div", "1", "0", 78, ROUND_HALF_EVEN) is None
    assert N.dec_eval("div", "0", "0", 78, ROUND_HALF_EVEN) is None
