"""
The bridge's deposit window and guardrails (qrdx/exchange/bridge.py).

A deposit counts toward a mint only within BRIDGE_DEPOSIT_WINDOW of its source block's time; past
it, never. That is what lets the lockbox's custodian refund a deposit QRDX did not mint without
risking a double payout. BRIDGE_MINT_LIMITS bounds what a day of QRDX's clock can mint per asset,
and the supply; a real network mints nothing of an asset without a limit. Governance can pause
minting. A deposit held back by a guardrail keeps its attestations and mints at a later vote.
"""

import json
from decimal import Decimal as D
from types import SimpleNamespace

import pytest
from test_bridge import ASSET, CHAIN, T0, USDC, Key, _deposit, _did, _genesis

from qrdx import chain_spec as cs, constants
from qrdx.exchange import ExchangeOpType, ExchangeStateManager
from qrdx.exchange.bridge import (
    MINT_PERIOD,
    BridgeError,
    parse_mint_limits,
    token_address,
)
from qrdx.exchange.governance import GovernanceError
from qrdx.validator.bridge_watcher import BridgeWatcher, FileSource

WEEK = 7 * 24 * 3600


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setattr(constants, "BRIDGE_ASSETS", (ASSET,))
    monkeypatch.setattr(constants, "BRIDGE_MINT_LIMITS", ())
    v1, v2, v3, user = Key(), Key(), Key(), Key()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
    mgr.begin_block(1, float(T0))
    yield mgr, v1, v2, v3, user
    ExchangeStateManager.reset_instance()


def _vote(mgr, who, *deposits, at, height):
    mgr.begin_block(height, float(at))
    r = mgr.process_transaction(who.tx(ExchangeOpType.ORACLE_VOTE, {"deposits": list(deposits)}))
    assert r.success, r.error
    return r.data


def _quorum(mgr, v1, v3, d, at, height):
    _vote(mgr, v3, d, at=at, height=height)
    return _vote(mgr, v1, d, at=at, height=height + 1)


def _supply(mgr):
    t = mgr.tokens.get(token_address(CHAIN, USDC))
    return t.supply if t is not None else D(0)


def test_a_deposit_past_its_window_never_mints(setup):
    mgr, v1, _v2, v3, user = setup
    old = _deposit(user.addr, time=T0 - WEEK - 1)
    data = _quorum(mgr, v1, v3, old, at=T0, height=2)
    assert (
        "minted" not in data
        and "deposit window" in data["refused_deposits"][_did()]
    )
    assert _supply(mgr) == 0 and not mgr.bridge.pending  # not even attested
    # Attested in time, but the quorum came too late: still never.
    late = _deposit(user.addr, tx="cd", time=T0)
    _vote(mgr, v3, late, at=T0 + 10, height=4)
    data = _vote(mgr, v1, late, at=T0 + WEEK + 1, height=5)
    assert "minted" not in data and _supply(mgr) == 0


def test_a_deposit_from_the_future_does_not_count(setup):
    mgr, v1, _v2, v3, user = setup
    data = _quorum(mgr, v1, v3, _deposit(user.addr, time=T0 + 3600), at=T0, height=2)
    assert "ahead of QRDX's clock" in next(iter(data["refused_deposits"].values()))
    assert _supply(mgr) == 0


def test_the_daily_limit_holds_a_deposit_back_until_the_next_day(setup, monkeypatch):
    mgr, v1, _v2, v3, user = setup
    monkeypatch.setattr(constants, "BRIDGE_MINT_LIMITS", ("USDC:300:0",))
    first, second = _deposit(user.addr, "250"), _deposit(user.addr, "100", tx="cd")
    assert _quorum(mgr, v1, v3, first, at=T0, height=2)["minted"]
    data = _quorum(mgr, v1, v3, second, at=T0 + 60, height=4)
    assert "daily mint limit" in data["queued_deposits"][_did("cd", 3)]
    assert _supply(mgr) == D(250) and mgr.bridge.pending  # still attested
    tomorrow = (T0 // MINT_PERIOD + 1) * MINT_PERIOD + 5
    data = _vote(mgr, v1, second, at=tomorrow, height=6)  # any later vote retries it
    assert data["minted"] == [_did("cd", 3)] and _supply(mgr) == D(350)
    assert D(mgr.bridge.guardrails()["minted_by_day"][token_address(CHAIN, USDC)][1]) == 100


def test_the_cap_bounds_the_supply(setup, monkeypatch):
    mgr, v1, _v2, v3, user = setup
    monkeypatch.setattr(constants, "BRIDGE_MINT_LIMITS", ("USDC:0:300",))
    assert _quorum(mgr, v1, v3, _deposit(user.addr, "250"), at=T0, height=2)["minted"]
    data = _quorum(mgr, v1, v3, _deposit(user.addr, "51", tx="cd"), at=T0 + 1, height=4)
    assert "supply cap" in next(iter(data["queued_deposits"].values()))
    assert _supply(mgr) == D(250)


def test_a_real_network_mints_nothing_of_an_asset_without_a_limit(setup):
    mgr, v1, _v2, v3, user = setup
    with cs.use_spec(cs.build_spec("qrdx-bridge-test", 4244, {}, dev=False)):
        data = _quorum(mgr, v1, v3, _deposit(user.addr), at=T0, height=2)
    assert "no mint limit is configured for USDC" in next(iter(data["queued_deposits"].values()))
    assert _supply(mgr) == 0


def test_a_paused_bridge_holds_deposits_and_resumes(setup):
    mgr, v1, _v2, v3, user = setup
    mgr.bridge.set_mint_paused(True, 1)
    d = _deposit(user.addr)
    data = _quorum(mgr, v1, v3, d, at=T0, height=2)
    assert "paused by governance" in next(iter(data["queued_deposits"].values()))
    mgr.bridge.set_mint_paused(False, 4)
    assert _vote(mgr, v1, d, at=T0 + 5, height=4)["minted"] and _supply(mgr) == D("250.5")


def test_governance_pauses_with_a_boolean_only():
    from qrdx.exchange.governance import ACTIONS, Governance

    assert "bridge_mint_pause" in ACTIONS
    gov = Governance()
    assert gov._check_action("bridge_mint_pause", {"paused": True}, 1) == {"paused": True}
    with pytest.raises(GovernanceError, match="true or false"):
        gov._check_action("bridge_mint_pause", {"paused": "yes"}, 1)


def test_mint_limits_parse_strictly():
    (limit,) = parse_mint_limits(["USDC:250000:5000000"]).values()
    assert (limit.symbol, limit.per_day, limit.cap) == ("USDC", D(250000), D(5000000))
    for bad in ("USDC:1", "USDC:-1:0", ":1:1", "USDC:x:1"):
        with pytest.raises(BridgeError):
            parse_mint_limits([bad])
    with pytest.raises(BridgeError, match="twice"):
        parse_mint_limits(["USDC:1:1", "USDC:2:2"])


def test_the_watcher_takes_turns_and_forgets_expired_deposits(monkeypatch, tmp_path):
    monkeypatch.setattr(constants, "BRIDGE_ASSETS", (ASSET,))
    to = "0xPQ" + "cd" * 32
    deposits = [_deposit(to, log=i, time=T0) for i in range(20)]
    deposits.append(_deposit(to, tx="ee", log=1, time=T0 - WEEK - 5))  # past the window
    path = tmp_path / "deposits.json"
    path.write_text(json.dumps(deposits))
    w = BridgeWatcher([FileSource(str(path))], start=False)
    w.poll_once()
    first = [d["id"] for d in w.outstanding(set(), 16, now=T0)]
    second = [d["id"] for d in w.outstanding(set(), 16, now=T0)]
    assert len(first) == len(second) == 16
    assert set(first) | set(second) == {_deposit(to, log=i)["id"] for i in range(20)}
    assert all(d["id"] != _deposit(to, tx="ee", log=1)["id"] for d in w.outstanding(set(), 32, now=T0))


def test_the_exchange_root_commits_the_guardrails(setup):
    mgr, v1, _v2, v3, user = setup
    before = mgr.bridge.commitment()
    mgr.bridge.set_mint_paused(True, 1)
    paused = mgr.bridge.commitment()
    assert paused != before and mgr.bridge.touched


def test_a_malformed_head_never_reaches_a_vote(monkeypatch):
    """One bad head made the whole vote fail, and the deposits in it went unattested (a 64-byte
    state root, as QRDX's own unified root, stopped every deposit on the live test network)."""
    good = {
        "chain": CHAIN,
        "height": 5,
        "hash": "0x" + "11" * 32,
        "state_root": "0x" + "22" * 32,
        "timestamp": T0,
    }
    bad = dict(good, chain=CHAIN + 1, state_root="0x" + "33" * 64)
    w = BridgeWatcher([SimpleNamespace(head=good), SimpleNamespace(head=bad)], start=False)
    assert w.heads() == [good]
