"""
The operational gauges ``/metrics`` exports beside the chain's (qrdx/node/observability.py), for
the alert rules in docker/alert-rules.yml: how old the tip is, whether this node's validator is
signing (and why not), the bridge's guardrails, whether the Doomsday Protocol triggered, and how
old each perps market's oracle price is.

Read-only: every value comes from state the node already holds. A source that is missing (no
validator, no bridge assets) exports nothing rather than a misleading zero.
"""

from __future__ import annotations

import time
from decimal import Decimal
from typing import Any, List, Optional, Tuple

Gauge = Tuple[str, float, Optional[dict]]


async def tip_age(db: Any, now: Optional[float] = None) -> List[Gauge]:
    """Seconds since the tip block's time: a chain that stops producing shows it at once."""
    from ..validator.node_integration import parse_block_timestamp

    tip = int(await db.get_next_block_id()) - 1
    block = await db.get_block_by_id(tip) if tip >= 0 else None
    stamp = parse_block_timestamp(block.get("timestamp")) if block else None
    if stamp is None:
        return []
    now = time.time() if now is None else now
    return [("qrdx_tip_age_seconds", max(0.0, now - stamp.timestamp()), None)]


async def validator(node: Any) -> List[Gauge]:
    """Whether this node validates, is held from signing (the doppelganger check), has seen a
    doppelganger, and the last slot and epoch it signed."""
    if node is None or getattr(node, "wallet", None) is None:
        return [("qrdx_validator_enabled", 0, None)]
    out: List[Gauge] = [("qrdx_validator_enabled", 1, None)]
    guard = getattr(node, "_doppelganger", None)
    if guard is not None:
        status = guard.status()
        out.append(("qrdx_validator_doppelganger", 1 if status["detected"] else 0, None))
        out.append(("qrdx_validator_listening", 1 if status["listening"] else 0, None))
    protection = getattr(node, "protection", None)
    if protection is not None:
        slot, epoch = await protection.latest(node.wallet.address)
        out.append(("qrdx_validator_last_signed_slot", slot, None))
        out.append(("qrdx_validator_last_vote_epoch", epoch, None))
    return out


def bridge(mgr: Any) -> List[Gauge]:
    """Minting paused, attestations waiting, and per asset: supply, minted today, the limits."""
    from ..exchange.bridge import MINT_PERIOD, configured_assets, configured_mint_limits

    assets = configured_assets()
    if not assets:
        return []
    b = mgr.bridge
    out: List[Gauge] = [
        ("qrdx_bridge_mint_paused", 1 if b.mint_paused else 0, None),
        ("qrdx_bridge_pending_attestations", len(b.pending), None),
    ]
    limits = configured_mint_limits()
    day = int(Decimal(str(mgr._block_clock())) // MINT_PERIOD)
    for asset in assets.values():
        labels = {"asset": asset.symbol, "chain": str(asset.chain)}
        token = mgr.tokens.get(asset.address)
        out.append(("qrdx_bridge_supply", float(token.supply) if token else 0.0, labels))
        used = b.mint_window.get(asset.address) if len(b.mint_window) else None
        today = float(used[1]) if used and int(used[0]) == day else 0.0
        out.append(("qrdx_bridge_minted_today", today, labels))
        limit = limits.get(asset.symbol)
        if limit is not None:
            out.append(("qrdx_bridge_daily_limit", float(limit.per_day), labels))
            out.append(("qrdx_bridge_supply_cap", float(limit.cap), labels))
    return out


def doomsday(mgr: Any) -> List[Gauge]:
    """Whether the Doomsday Protocol triggered (qrdx/exchange/doomsday.py): ECDSA keys are off
    and the bridge has stopped. Exported on every node, bridge or not."""
    return [("qrdx_doomsday_triggered", 1 if mgr.bridge.doomsday else 0, None)]


def oracles(mgr: Any) -> List[Gauge]:
    """Per validator-priced perps market, seconds between its last oracle price and the chain's
    clock (the block being processed)."""
    now = Decimal(str(mgr._block_clock()))
    out: List[Gauge] = []
    for market_id, m in sorted(mgr.clearinghouse.markets.items()):
        if m.oracle_time > 0 and m.settled_price <= 0:
            out.append(
                ("qrdx_oracle_price_age_seconds", float(now - m.oracle_time), {"market": market_id})
            )
    return out


async def collect(db: Any, node: Any, mgr: Any) -> List[Gauge]:
    """Every operational gauge; a source that fails is skipped (monitoring never raises)."""
    out: List[Gauge] = []
    for source in (lambda: tip_age(db), lambda: validator(node)):
        try:
            out += await source()
        except Exception:
            pass
    for sync_source in (lambda: bridge(mgr), lambda: doomsday(mgr), lambda: oracles(mgr)):
        try:
            out += sync_source() if mgr is not None else []
        except Exception:
            pass
    return out
