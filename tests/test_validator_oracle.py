"""
The validator price oracle (docs/PERPS_CLEARINGHOUSE.md §8).

Validators vote USD prices (ORACLE_VOTE, signed like any exchange transaction; proposers attach
their own). Each block, a market's oracle is the stake-weighted median of the committee's votes
no older than the vote window — provided they carry a majority of the committee's stake. The
committee starts from the genesis block's validator set and follows STAKE_DEPOSIT / STAKE_EXIT.
A market whose oracle has not been set for the stale window refuses new exposure.
"""
import inspect
import json
import os
import tempfile
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx import constants
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP

D = Decimal
BTC = "BTC-QRDX-PERP"            # the test session quotes perps in QRDX (tests/conftest.py)
T0 = 1_700_000_000


class Key:
    def __init__(self):
        self.key = PQPrivateKey.generate()
        self.addr = self.key.public_key.to_address()
        self.nonce = 0

    @property
    def wallet(self):
        k = self.key
        return SimpleNamespace(address=self.addr, public_key=k.public_key.to_bytes(),
                               sign=lambda m: k.sign(m).to_bytes())

    def tx(self, op, params):
        t = ExchangeTransaction(op_type=op, sender=self.addr, nonce=self.nonce, params=params,
                                gas_limit=2_000_000, gas_price=D("1"))
        t.public_key = self.key.public_key.to_bytes()
        t.signature = self.key.sign(t.signing_bytes()).to_bytes()
        self.nonce += 1
        return t


def _genesis(stakes):
    return json.dumps({"type": "genesis", "validators": len(stakes),
                       "validator_set": [{"address": a, "stake": str(s)} for a, s in stakes]})


@pytest.fixture
def setup(monkeypatch):
    v1, v2, v3, rep = Key(), Key(), Key(), Key()
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (rep.addr,))
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
    mgr.begin_block(1, float(T0))
    assert mgr.process_transaction(rep.tx(ExchangeOpType.CREATE_MARKET, {"base_token": "BTC"})).success
    yield mgr, v1, v2, v3, rep
    ExchangeStateManager.reset_instance()


def _vote(mgr, who, price, at=T0, base="BTC"):
    mgr.begin_block(2, float(at))
    return mgr.process_transaction(who.tx(ExchangeOpType.ORACLE_VOTE, {"prices": {base: str(price)}}))


def _oracle(mgr):
    return mgr.clearinghouse.markets[BTC].oracle_price


# ── the committee ─────────────────────────────────────────────────────────

def test_the_committee_comes_from_the_genesis_validator_set(setup):
    mgr, v1, v2, v3, _ = setup
    assert mgr.oracle_committee == {v1.addr.lower(): D(100), v2.addr.lower(): D(100),
                                    v3.addr.lower(): D(300)}


def test_a_genesis_without_a_validator_set_disables_votes():
    """Joiners alone must not form the committee: the first one would own the oracle."""
    m = ExchangeStateManager()
    m.load_oracle_committee(json.dumps({"type": "genesis", "validators": 3}))
    assert m.oracle_committee is None


def test_staking_joins_and_exits_the_committee(setup, monkeypatch):
    mgr, v1, *_ = setup
    joiner = Key()
    monkeypatch.setattr(mgr, "enforce_validator_stake", False)
    mgr.begin_block(2, float(T0))
    assert mgr.process_transaction(joiner.tx(ExchangeOpType.STAKE_DEPOSIT, {
        "stake_amount": "250", "validator_public_key": "00"})).success
    assert mgr.oracle_committee[joiner.addr.lower()] == D(250)
    assert mgr.process_transaction(v1.tx(ExchangeOpType.STAKE_EXIT, {})).success
    assert v1.addr.lower() not in mgr.oracle_committee


# ── votes ─────────────────────────────────────────────────────────────────

def test_only_committee_members_vote(setup):
    mgr, *_, rep = setup
    r = _vote(mgr, rep, 30000)
    assert not r.success and "not in the oracle committee" in r.error


@pytest.mark.parametrize("prices, error", [
    ({"ETH": "3000"}, "no market"),
    ({"BTC": "-1"}, "invalid price"),
    ({"BTC": "NaN"}, "invalid price"),
    ({"BTC": "abc"}, "invalid price"),
    ({f"T{i}": "1" for i in range(65)}, "1 to 64 prices"),
])
def test_malformed_votes_are_refused(setup, prices, error):
    mgr, v1, *_ = setup
    mgr.begin_block(2, float(T0))
    r = mgr.process_transaction(v1.tx(ExchangeOpType.ORACLE_VOTE, {"prices": prices}))
    assert not r.success and error in r.error
    assert mgr.oracle_votes == {}


def test_the_oracle_is_the_stake_weighted_median(setup):
    mgr, v1, v2, v3, _ = setup
    for who, price in ((v1, 29000), (v2, 31000), (v3, 30050)):
        assert _vote(mgr, who, price).success
    mgr.apply_oracle_votes(T0)
    assert _oracle(mgr) == D(30050)          # v3 holds 300 of 500: the weighted median


def test_a_minority_of_stake_cannot_set_the_price(setup):
    mgr, v1, v2, v3, _ = setup
    assert _vote(mgr, v1, 1_000_000).success           # 100 of 500
    assert _vote(mgr, v2, 1_000_000).success           # 200 of 500: still not a majority
    mgr.apply_oracle_votes(T0)
    assert _oracle(mgr) == 0
    assert _vote(mgr, v3, 30000).success                # now 500 of 500: the median is honest
    mgr.apply_oracle_votes(T0)
    # 200 at 1,000,000 vs 300 at 30,000: the stake-weighted median is 30,000.
    assert _oracle(mgr) == D(30000)


def test_old_votes_expire(setup):
    mgr, v1, v2, v3, _ = setup
    assert _vote(mgr, v3, 30000).success
    assert _vote(mgr, v1, 30100).success
    window = constants.PERP_ORACLE_VOTE_MAX_AGE
    mgr.apply_oracle_votes(T0 + window + 1)              # both expired: nothing set, pruned
    assert _oracle(mgr) == 0 and mgr.oracle_votes == {}


def test_a_departed_validators_vote_stops_counting(setup):
    mgr, v1, v2, v3, _ = setup
    assert _vote(mgr, v3, 30000).success
    mgr.begin_block(3, float(T0))
    assert mgr.process_transaction(v3.tx(ExchangeOpType.STAKE_EXIT, {})).success
    assert _vote(mgr, v1, 31000).success
    mgr.apply_oracle_votes(T0)                           # v3 gone: v1 alone is 100 of 200
    assert _oracle(mgr) == 0


# ── staleness ─────────────────────────────────────────────────────────────

def test_a_stale_oracle_refuses_new_exposure_but_not_reductions(setup):
    mgr, v1, v2, v3, rep = setup
    for who in (v1, v2, v3):
        assert _vote(mgr, who, 30000).success
    mgr.apply_oracle_votes(T0)
    trader, maker = Key(), Key()
    for k in (trader, maker):
        assert mgr.process_transaction(k.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "100000"})).success
    assert mgr.process_transaction(maker.tx(ExchangeOpType.PERP_ORDER, {
        "market_id": BTC, "side": "sell", "size": "1", "price": "30000"})).success
    assert mgr.process_transaction(trader.tx(ExchangeOpType.PERP_ORDER, {
        "market_id": BTC, "side": "buy", "size": "1", "price": "30000"})).success
    later = T0 + constants.PERP_ORACLE_STALE_SECONDS + 1
    mgr.begin_block(9, float(later))
    refused = mgr.process_transaction(trader.tx(ExchangeOpType.PERP_ORDER, {
        "market_id": BTC, "side": "buy", "size": "1", "price": "30000"}))
    assert not refused.success and "stale" in refused.error
    allowed = mgr.process_transaction(trader.tx(ExchangeOpType.PERP_ORDER, {
        "market_id": BTC, "side": "sell", "size": "1", "price": "29000", "reduce_only": True}))
    assert allowed.success


# ── the proposer's vote ───────────────────────────────────────────────────

def test_a_proposers_vote_is_a_valid_signed_transaction(setup):
    from qrdx.exchange.block_processor import verify_exchange_tx
    from qrdx.validator.price_feed import build_vote
    mgr, v1, *_ = setup
    vote = build_vote(v1.wallet, 0, {"BTC": D("30123.5")})
    ok, err = verify_exchange_tx(vote)
    assert ok, err
    mgr.begin_block(2, float(T0))
    assert mgr.process_transaction(vote).success
    assert mgr.oracle_votes[BTC][v1.addr.lower()][0] == D("30123.5")


def test_the_proposer_attaches_its_vote_after_its_own_transactions():
    from qrdx.validator import node_integration as NI
    src = inspect.getsource(NI.ValidatorNode._block_production_loop)
    assert "await self._oracle_vote(exchange_txs)" in src
    method = inspect.getsource(NI.ValidatorNode._oracle_vote)
    assert "get_nonce(self.wallet.address) + own" in method


def test_every_replay_path_loads_the_committee_before_a_section():
    assert "await ensure_oracle_committee(db, mgr)" in inspect.getsource(BP.preload_sender_balances)
    assert "await ensure_oracle_committee(db, mgr)" in inspect.getsource(
        BP.rebuild_exchange_state_from_chain)


def test_price_feeds(tmp_path):
    from qrdx.validator.price_feed import (
        FilePriceFeed, StaticPriceFeed, feed_from_env, underlying,
    )
    assert StaticPriceFeed("BTC=65000, ETH=3200,bad=-1").prices(["BTC", "ETH", "bad", "X"]) == {
        "BTC": D(65000), "ETH": D(3200)}
    path = tmp_path / "prices.json"
    feed = FilePriceFeed(str(path))
    assert feed.prices(["BTC"]) == {}                     # no file yet: no vote
    path.write_text(json.dumps({"qBTC": "30000", "ETH": "oops"}))
    assert feed.prices(["qBTC", "ETH"]) == {"qBTC": D(30000)}
    assert underlying("qBTC") == "BTC" and underlying("BTC") == "BTC" and underlying("q") == "q"
    assert feed_from_env("") is None and feed_from_env("nonsense") is None
    assert isinstance(feed_from_env(f"file:{path}"), FilePriceFeed)


# ── the chain: votes in blocks, forward ≡ rebuild ─────────────────────────

async def test_forward_and_rebuild_agree_on_voted_prices(monkeypatch):
    """Votes ride in blocks; quiet blocks aggregate them. A rebuild — whose manager loads the
    committee at height 0, where the forward one loaded it at its first section — reaches the
    same oracle and the same root."""
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.derived_state_rebuild import rebuild_derived_state_interleaved
    from qrdx.exchange import encode_exchange_txs
    from qrdx.validator.price_feed import build_vote

    v1, v2, v3, rep = Key(), Key(), Key(), Key()
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (rep.addr,))
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    try:
        async def add(h, txs=(), content=""):
            bh = f"{h:064x}"
            await db.add_block(block_hash=bh, block_height=h, block_content=content,
                               validator_address="0xPQ" + "00" * 32, timestamp=T0 + 2 * h)
            if txs:
                await db.add_block_exchange_txs(bh, encode_exchange_txs(list(txs)))

        await add(0, content=_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
        for h in range(1, 4):                              # quiet blocks before anything
            await add(h)
        await add(4, [rep.tx(ExchangeOpType.CREATE_MARKET, {"base_token": "BTC"})])
        await add(5, [build_vote(v.wallet, 0, {"BTC": D(p)})
                      for v, p in ((v1, 29900), (v2, 30100), (v3, 30000))])
        for h in range(6, 12):
            await add(h)
        await add(12, [build_vote(v3.wallet, 1, {"BTC": D(30500)})])
        await add(13)
        tip = 13

        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        for h in range(1, tip + 1):
            section = await db.get_block_exchange_txs(f"{h:064x}")
            ts = float(T0 + 2 * h)
            if section:
                txs = BP.decode_exchange_txs(section)
                await BP.preload_sender_balances(db, txs, mgr)
                ok, err, _ = BP.process_exchange_transactions(h, ts, txs, mgr)
                assert ok, err
                assert all(r.success for r in mgr._block_results), [r.error for r in mgr._block_results]
                mgr.commit_block()
            else:
                BP.run_exchange_tick(h, ts, mgr)
        assert mgr.clearinghouse.markets[BTC].oracle_price == D(30500)
        forward = (mgr.compute_state_root(), mgr.clearinghouse.canonical())

        await rebuild_derived_state_interleaved(db)
        mgr = ExchangeStateManager.get_instance()
        assert (mgr.compute_state_root(), mgr.clearinghouse.canonical()) == forward
    finally:
        ExchangeStateManager.reset_instance()
        path = db.db_path
        await db.close()
        os.remove(path)
