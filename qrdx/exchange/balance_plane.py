"""
A block's QRDX balances, held natively (native/qrdx-native/src/plane.rs; docs/NATIVE.md, "The
balance plane").

The exchange's per-block QRDX dicts — the available balances loaded for the block, each account's
balance as the block began, the block's net change to each account, the fees it reserved from
each payer, and what each payer's transactions may cost while the block is judged — are the maps
of one native ``Plane``. The state manager holds a view of each (``PlaneView``), which behaves as
the dict did (the same keys, in the same order; a ``Decimal`` back for what was set), so Python's
own operations read and write them as before. The native transfer lane, the fee reservations and
the pre-loads change them in place, with no value converted to text and back.

``QRDX_NATIVE_PLANE=0`` (or ``QRDX_NATIVE=0``) keeps plain dicts: the reference the plane is held
to (tests/test_balance_plane.py, tests/test_transfer_lane.py).
"""

from __future__ import annotations

import decimal
import os
from typing import Any, Optional, Tuple

from . import undo

AVAIL, START, DELTA, RESERVED, OWED = range(5)


def enabled() -> bool:
    if os.environ.get("QRDX_NATIVE_PLANE", "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    from .. import native

    return native.AVAILABLE and hasattr(native._native, "Plane")


def make() -> Optional[Any]:
    """A new plane, or None where it is off."""
    if not enabled():
        return None
    from .. import native

    return native._native.Plane()


def views(plane: Any) -> Tuple[Any, Any, Any, Any, Any]:
    """The plane's maps as dicts: (available, start, delta, reserved, owed)."""
    from .. import native

    view = native._native.PlaneView
    return tuple(view(plane, m) for m in range(5))  # type: ignore[return-value]


def exchange_context() -> bool:
    """Whether Python computes with the exchange's context now — precision 78, half-even, as
    ``amm`` sets it for the process — the one the plane's arithmetic reproduces
    (``dec::EXCHANGE``). Elsewhere Python computes, and the plane is only its store."""
    ctx = decimal.getcontext()
    return ctx.prec == 78 and ctx.rounding == decimal.ROUND_HALF_EVEN


def in_place() -> bool:
    """Whether native code may change the maps: Python's context is the exchange's, and no
    operation's undo scope is open (a block's scope does not record these per-block values:
    ``undo.keep_entry``'s ``transient``)."""
    scope = undo.active()
    return (scope is None or scope.block) and exchange_context()
