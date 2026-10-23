"""
Social recovery and agent spending limits (docs/CONSENSUS_ROADMAP.md 7, docs/ACCOUNT_CONTROL.md).

Guardians: when an account's threshold of guardians back one new controller, the recovery waits
the account's recovery delay — its own key or a controller may cancel — and then binds that
controller in place of all others and turns the own key off. Agents: an approval may carry
``max_notional_per_day``; every order the agent places counts at full size × limit price, and
what cannot be valued up front is refused.
"""
from decimal import Decimal as D

import pytest
from test_account_control import MID, T0, Key, _policy, _run, _tick

from qrdx.crypto.account_id import to_account_id
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, views
from qrdx.exchange.authority import DEFAULT_RECOVERY_DELAY, MIN_RECOVERY_DELAY

DAY = 86400


@pytest.fixture(scope="module")
def keys():
    return {n: Key() for n in ("owner", "g1", "g2", "g3", "new", "cold", "bot", "thief")}


@pytest.fixture
def m(keys):
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    mgr.clearinghouse.create_market("BTC")
    mgr.clearinghouse.set_oracle_price(MID, D(100), now=T0)
    for k in keys.values():
        mgr.clearinghouse.deposit(k.addr, D(100_000))
    yield mgr
    ExchangeStateManager.reset_instance()


def _guard(m, keys, signer="", threshold=2, delay=DEFAULT_RECOVERY_DELAY):
    return _policy(m, keys["owner"].addr, signer, action="guardians",
                   guardians=[keys[g].addr for g in ("g1", "g2", "g3")], threshold=threshold,
                   recovery_delay=delay)


def _back(m, keys, guardian, new):
    return _run(m, keys[guardian].addr, Op.ACCOUNT_RECOVER,
                {"account": keys["owner"].addr, "new_controller": new})


# ── social recovery ─────────────────────────────────────────────────────────

def test_guardians_recover_an_account_after_the_delay(m, keys):
    owner, new = keys["owner"].addr, keys["new"].addr
    assert _guard(m, keys).success
    r = _back(m, keys, "g1", new)
    assert r.success and r.data["backing"] == 1 and "change_id" not in r.data
    r = _back(m, keys, "g2", new)
    assert r.success and r.data["backing"] == 2 and r.data["change_id"]
    assert views.authority(m, owner)["pending_changes"][0]["action"] == "recover"
    _tick(m, T0 + DEFAULT_RECOVERY_DELAY - 1)
    assert m.authority.policy(owner).own_key                          # not yet
    _tick(m, T0 + DEFAULT_RECOVERY_DELAY)
    policy = m.authority.policy(owner)
    assert policy.controllers == (new,) and not policy.own_key
    assert not len(m.authority.recovery_votes)                        # the backing is spent
    assert _run(m, owner, Op.PERP_WITHDRAW, {"amount": "1"}, signer=new).success
    assert not _run(m, owner, Op.PERP_WITHDRAW, {"amount": "1"}).success   # the lost key


def test_the_owner_or_a_controller_cancels_a_recovery(m, keys):
    owner, new = keys["owner"].addr, keys["thief"].addr
    _guard(m, keys)
    _back(m, keys, "g1", new)
    cid = _back(m, keys, "g2", new).data["change_id"]                 # colluding guardians
    assert _policy(m, owner, action="cancel", change_id=cid).success
    _tick(m, T0 + DEFAULT_RECOVERY_DELAY)
    assert m.authority.policy(owner).controllers == ()


def test_backing_is_per_guardian_and_can_be_withdrawn(m, keys):
    new, other = keys["new"].addr, keys["cold"].addr
    _guard(m, keys, threshold=2)
    _back(m, keys, "g1", new)
    assert _back(m, keys, "g2", other).data["backing"] == 1           # split: no quorum
    assert _back(m, keys, "g1", "").success                           # g1 withdraws
    assert _back(m, keys, "g3", other).data["change_id"]              # g2 + g3 agree


def test_only_guardians_back_and_a_recovery_waits_once(m, keys):
    new = keys["new"].addr
    r = _back(m, keys, "g1", new)
    assert not r.success and "not a guardian" in r.error
    _guard(m, keys, threshold=1)
    assert _back(m, keys, "g1", new).data["change_id"]
    r = _back(m, keys, "g2", new)
    assert not r.success and "already waiting" in r.error


def test_guardians_set_by_the_own_key_wait_out_its_delay(m, keys):
    """A stolen key cannot quietly name its own guardians."""
    owner, cold = keys["owner"].addr, keys["cold"].addr
    _policy(m, owner, action="add_controller", controller=cold)
    _policy(m, owner, action="delay", seconds=DAY)
    r = _guard(m, keys)
    assert r.success and not r.data["applied"]
    assert m.authority.policy(owner).guardians == ()
    assert _guard(m, keys, signer=cold).data["applied"]               # a controller: at once


@pytest.mark.parametrize("change, why", [
    (dict(threshold=4), "threshold"),
    (dict(threshold=0), "threshold"),
    (dict(delay=MIN_RECOVERY_DELAY - 1), "recovery delay"),
])
def test_bad_guardian_sets_are_refused(m, keys, change, why):
    r = _guard(m, keys, **change)
    assert not r.success and why in r.error


def test_who_guards_an_account_is_public(m, keys):
    owner = keys["owner"].addr
    _guard(m, keys)
    assert views.authority(m, owner)["guardians"]["threshold"] == 2
    assert views.controlled(m, keys["g1"].addr)["guardian_of"] == [to_account_id(owner)]
    _policy(m, owner, action="guardians", guardians=[], threshold=0)
    assert views.controlled(m, keys["g1"].addr)["guardian_of"] == []


# ── agent spending limits ───────────────────────────────────────────────────

def _approve(m, keys, limit):
    r = _run(m, keys["owner"].addr, Op.AGENT_APPROVE,
             {"agent": keys["bot"].addr, "max_notional_per_day": limit})
    assert r.success, r.error


def _order(size, price="99"):
    return {"market_id": MID, "side": "buy", "size": str(size), "price": price}


def test_an_agent_places_at_most_its_daily_limit(m, keys):
    owner, bot = keys["owner"].addr, keys["bot"].addr
    _approve(m, keys, "1000")
    assert _run(m, owner, Op.PERP_ORDER, _order(5), signer=bot).success     # 495
    assert _run(m, owner, Op.PERP_ORDER, _order(5), signer=bot).success     # 990
    r = _run(m, owner, Op.PERP_ORDER, _order(1), signer=bot)                # 1089 > 1000
    assert not r.success and "a day" in r.error
    assert views.agents(m, owner)[0]["placed_today"] == "990"
    assert _run(m, owner, Op.PERP_ORDER, _order(1)).success                 # the owner: no limit
    _tick(m, T0 + DAY)                                                      # a new day
    m.clearinghouse.set_oracle_price(MID, D(100), now=T0 + DAY)
    assert _run(m, owner, Op.PERP_ORDER, _order(1), signer=bot).success


def test_an_agent_and_its_owner_order_in_any_interleaving(m, keys):
    """Lanes number independently: the book's own per-owner nonce check used to refuse an
    agent's order once the owner's nonce had passed the agent's lane, and the reverse."""
    owner, bot = keys["owner"].addr, keys["bot"].addr
    _approve(m, keys, "0")
    for who in ("", "", "", bot, "", bot, bot, bot, ""):
        r = _run(m, owner, Op.PERP_ORDER, _order(1), signer=who)
        assert r.success, (who, r.error)


def test_cancels_are_free_and_a_failed_order_counts_nothing(m, keys):
    owner, bot = keys["owner"].addr, keys["bot"].addr
    _approve(m, keys, "500")
    r = _run(m, owner, Op.PERP_ORDER, _order(4), signer=bot)
    assert r.success
    oid = r.data.get("order_id")
    assert _run(m, owner, Op.CANCEL_ALL, {}, signer=bot).success
    bad = _run(m, owner, Op.PERP_ORDER, {**_order(1), "market_id": "NOPE-QRDX-PERP"}, signer=bot)
    assert not bad.success
    assert views.agents(m, owner)[0]["placed_today"] == "396"
    assert oid is None or isinstance(oid, str)


def test_a_limited_agent_cannot_escape_through_a_batch(m, keys):
    owner, bot = keys["owner"].addr, keys["bot"].addr
    _approve(m, keys, "500")
    batch = {"actions": [{"op": "PERP_ORDER", "params": _order(3)},
                         {"op": "PERP_ORDER", "params": _order(3)}]}
    r = _run(m, owner, Op.BATCH, batch, signer=bot)
    assert not r.success and "a day" in r.error


def test_what_cannot_be_valued_is_refused_to_a_limited_agent(m, keys):
    owner, bot = keys["owner"].addr, keys["bot"].addr
    _approve(m, keys, "500")
    r = _run(m, owner, Op.SWAP, {"token_in": "0x" + "ab" * 20, "token_out": "QRDX",
                                 "amount_in": "1", "min_amount_out": "0"}, signer=bot)
    assert not r.success and "swaps from" in r.error


def test_revoking_forgets_the_days_count(m, keys):
    owner, bot = keys["owner"].addr, keys["bot"].addr
    _approve(m, keys, "500")
    _run(m, owner, Op.PERP_ORDER, _order(4), signer=bot)
    assert len(m.trading.agent_spend) == 1
    assert _run(m, owner, Op.AGENT_REVOKE, {"agent": bot}).success
    assert not len(m.trading.agent_spend)
