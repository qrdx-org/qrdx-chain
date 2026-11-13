"""
The garbage collector's policy for a running node (docs/PERFORMANCE.md, 36).

CPython's cyclic collector runs a full collection whenever enough objects have survived into its
oldest generation. Under load that was every two to three seconds on each validator, and each one
stopped the whole process for 200–335 ms — a slot or more, landing wherever the node happened to
allocate: in a block's import, a proposal's selection or signature, a commit. In a 1,500-a-second
step the full collections took about 5 of every 55 seconds, and freed almost nothing: 34 of them
found 1,161 objects in all, most found none. A node's garbage is freed by reference counting; the
full collections only walked its millions of live objects.

So, once the node has started:

* what is alive then (modules, the state it loaded, its caches) is frozen: never walked again;
* full collections are no longer automatic. One runs every ``QRDX_GC_FULL_SECONDS`` (10 minutes
  by default) for the few reference cycles that do become garbage;
* young collections (generations 0 and 1) run as before: they are short.

``QRDX_GC_POLICY=0`` keeps CPython's defaults.
"""

from __future__ import annotations

import asyncio
import gc
import os
import time

from ..logger import get_logger

logger = get_logger(__name__)

# The full collection's own threshold, set out of reach: CPython runs one only after this many
# collections of generation 1 (and then only when enough objects have survived since the last).
_NEVER = 1 << 30


def enabled() -> bool:
    return os.environ.get("QRDX_GC_POLICY", "1").strip().lower() not in ("0", "false", "no", "off")


def full_seconds() -> float:
    return float(os.environ.get("QRDX_GC_FULL_SECONDS", "600"))


def install() -> bool:
    """Collect once, freeze what survives, and stop automatic full collections. Whether the
    policy is on."""
    if not enabled():
        return False
    gc.collect()
    gc.freeze()
    young, middle, _full = gc.get_threshold()
    gc.set_threshold(young, middle, _NEVER)
    logger.info(
        f"Garbage collection: {gc.get_freeze_count()} objects frozen; full collections every "
        f"{full_seconds():.0f} s instead of automatically"
    )
    return True


def collect_full() -> int:
    """One full collection, logged with how long it stopped the process. What it found."""
    started = time.perf_counter()
    found = gc.collect()
    logger.info(
        f"🗑  Full garbage collection: {1000 * (time.perf_counter() - started):.0f} ms, "
        f"{found} unreachable objects found"
    )
    return found


async def run() -> None:
    """The full collections the policy schedules (a task for the node's lifetime)."""
    while True:
        await asyncio.sleep(full_seconds())
        collect_full()
