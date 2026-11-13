"""
Alert rules (docker/alert-rules.yml) only help if they read metrics something exports. They used
to watch counters the node never produced (qrdx_blocks_processed_total, qrdx_validator_active, …),
so a stalled chain or a dead validator never paged anyone. Every metric an expression names must
be produced by the node's exporters, or by the custodian's reconcile script.
"""

import re
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

from qrdx.node import health_gauges as H

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "docker" / "alert-rules.yml"
EXPORTERS = [
    ROOT / "qrdx" / "node" / "observability.py",
    ROOT / "qrdx" / "node" / "health_gauges.py",
    ROOT / "qrdx" / "rpc" / "server.py",
    ROOT / "scripts" / "bridge" / "reconcile_cron.sh",
]


def test_every_alert_reads_a_metric_something_exports():
    rules = RULES.read_text()
    exported = "\n".join(p.read_text() for p in EXPORTERS)
    names = set(re.findall(r"\bqrdx_[a-z_]+", "\n".join(re.findall(r"expr: (.*)", rules))))
    assert names, "no metrics found in the rules"
    missing = sorted(n for n in names if f'"{n}"' not in exported and f"{n}{{" not in exported)
    assert missing == []
    for alert in ("ChainStall", "FinalityStall", "ValidatorDoppelganger", "ValidatorInactive",
                  "CustodianReconcileAlarm", "OraclePriceStale", "HighRPCErrorRate"):
        assert f"alert: {alert}" in rules


async def test_the_tip_age_comes_from_the_tip_block():
    class Db:
        async def get_next_block_id(self):
            return 11

        async def get_block_by_id(self, height):
            assert height == 10
            return {"timestamp": 1_000}

    assert await H.tip_age(Db(), now=1_090) == [("qrdx_tip_age_seconds", 90.0, None)]


async def test_the_validator_gauges_report_its_signing_state():
    class Protection:
        async def latest(self, address):
            return 812, 25

    guard = SimpleNamespace(status=lambda: {"detected": True, "listening": False})
    node = SimpleNamespace(wallet=SimpleNamespace(address="0xPQ1"), _doppelganger=guard,
                           protection=Protection())
    got = {name: value for name, value, _ in await H.validator(node)}
    assert got == {"qrdx_validator_enabled": 1, "qrdx_validator_doppelganger": 1,
                   "qrdx_validator_listening": 0, "qrdx_validator_last_signed_slot": 812,
                   "qrdx_validator_last_vote_epoch": 25}
    assert await H.validator(None) == [("qrdx_validator_enabled", 0, None)]


def test_oracle_ages_are_measured_on_the_chains_clock():
    market = SimpleNamespace(oracle_time=Decimal(900), settled_price=Decimal(0))
    settled = SimpleNamespace(oracle_time=Decimal(100), settled_price=Decimal(5))
    mgr = SimpleNamespace(_block_clock=lambda: 1_000.0,
                          clearinghouse=SimpleNamespace(markets={"BTC-USD": market, "OLD-USD": settled}))
    assert H.oracles(mgr) == [("qrdx_oracle_price_age_seconds", 100.0, {"market": "BTC-USD"})]
