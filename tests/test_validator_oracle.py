"""
The validator price oracle (docs/PERPS_CLEARINGHOUSE.md §8).

Validators vote USD prices (ORACLE_VOTE, signed like any exchange transaction and gossiped
through the mempool). Each block, a market's oracle is the stake-weighted median of the
committee's votes no older than the vote window — provided they carry a majority of the
committee's stake. Other venues' perp prices ("BTC:perp") are voted and aggregated the same way:
they are the mark price's third input. The
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

pytestmark = pytest.mark.usefixtures("open_listing")  # lists markets with CREATE_MARKET

D = Decimal
BTC = "BTC-QRDX-PERP"            # the test session quotes perps in QRDX (tests/conftest.py)
T0 = 1_700_000_000


class Key:
    def __init__(self):
        self.key = PQPrivateKey.generate()
        self.addr = self.key.public_key.to_address()
        self.nonce = 0
        self.vote_seq = 0  # an oracle vote's own sequence: not the account nonce

    @property
    def wallet(self):
        k = self.key
        return SimpleNamespace(address=self.addr, public_key=k.public_key.to_bytes(),
                               sign=lambda m: k.sign(m).to_bytes())

    def tx(self, op, params, nonce=None):
        if nonce is None:
            if op == ExchangeOpType.ORACLE_VOTE:
                self.vote_seq += 1
                nonce = self.vote_seq
            else:
                nonce = self.nonce
                self.nonce += 1
        t = ExchangeTransaction(op_type=op, sender=self.addr, nonce=nonce, params=params,
                                gas_limit=2_000_000, gas_price=10**9)
        t.public_key = self.key.public_key.to_bytes()
        t.signature = self.key.sign(t.signing_bytes()).to_bytes()
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


def test_stake_operations_do_not_edit_the_committee_directly(setup, monkeypatch):
    """The committee is the chain-derived validator set, set before every block
    (block_processor.ensure_oracle_committee): a deposit joins it when it activates, an exit
    leaves when it is done — not at the operation (tests below, on a chain)."""
    mgr, v1, *_ = setup
    joiner = Key()
    before = dict(mgr.oracle_committee)
    monkeypatch.setattr(mgr, "enforce_validator_stake", False)
    mgr.begin_block(2, float(T0))
    assert mgr.process_transaction(joiner.tx(ExchangeOpType.STAKE_DEPOSIT, {
        "stake_amount": "250", "validator_public_key": "00"})).success
    assert mgr.process_transaction(v1.tx(ExchangeOpType.STAKE_EXIT, {})).success
    assert mgr.oracle_committee == before


async def test_the_committee_is_the_validator_set_in_force_at_the_parent():
    """Pending validators are not in it; active and exiting ones are, by weight (their own
    effective stake and what is delegated to them); exited and slashed ones are not."""
    from qrdx.constants import ACTIVATION_DELAY_EPOCHS, SLOTS_PER_EPOCH
    from qrdx.validator.epoch_state import committee_for_block, state_at, voting_stakes
    from test_epoch_state import G, J, Chain

    db_path = tempfile.mktemp(suffix=".db")
    from qrdx.database_sqlite import DatabaseSQLite
    db = await DatabaseSQLite.create(db_path)
    try:
        c = Chain(db)
        await c.genesis()
        await c.epoch(1, deposits=[(J, "100000")], exits=[G[2]])
        await c.epoch(2)
        committee = await committee_for_block(db, c.height + 1)
        assert J.lower() not in committee                       # pending
        assert G[2].lower() in committee                        # exiting still counts
        for e in range(3, 3 + ACTIVATION_DELAY_EPOCHS):
            await c.epoch(e)
        committee = await committee_for_block(db, c.height + 1)
        assert J.lower() in committee
        slot = (2 + ACTIVATION_DELAY_EPOCHS) * SLOTS_PER_EPOCH + 1
        state = await state_at(db, slot // SLOTS_PER_EPOCH, c.height)
        assert committee == {a.lower(): w for a, w in voting_stakes(state).items()}
    finally:
        await db.connection.close()
        os.remove(db_path)


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
    # The next block's committee no longer holds v3 (it left the validator set).
    mgr.oracle_committee = {k: w for k, w in mgr.oracle_committee.items() if k != v3.addr.lower()}
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


def test_votes_are_gossiped_not_attached_to_the_voters_own_blocks():
    """Votes go through the mempool like any exchange transaction (admitted, gossiped, included
    by whoever proposes next); they used to ride only in the voter's own blocks."""
    from qrdx.validator import node_integration as NI
    assert "_oracle_vote(" not in inspect.getsource(NI.ValidatorNode._block_production_loop)
    loop = inspect.getsource(NI.ValidatorNode._oracle_vote_loop)
    assert "submitter.submit(vote)" in loop
    assert "_get_current_slot()" in inspect.getsource(NI.ValidatorNode._oracle_vote)


def test_a_vote_has_its_own_sequence_and_never_moves_the_exchange_nonce(setup):
    """Each vote used to consume the validator's exchange nonce, so its own transactions signed
    elsewhere with a predicted nonce went stale."""
    mgr, v1, _v2, _v3, _ = setup
    assert _vote(mgr, v1, 30000).success
    assert _vote(mgr, v1, 30100).success
    assert mgr.get_nonce(v1.addr) == 0 and mgr.oracle_vote_seq(v1.addr) == 2
    replay = v1.tx(ExchangeOpType.ORACLE_VOTE, {"prices": {"BTC": "1"}}, nonce=2)
    stale = mgr.process_transaction(replay)
    assert not stale.success and "Stale oracle vote" in stale.error
    assert mgr.process_transaction(v1.tx(ExchangeOpType.STAKE_EXIT, {})).success   # nonce 0


def test_the_mempool_keeps_each_voters_newest_vote_and_selects_votes_first(setup):
    from qrdx.exchange.mempool import ExchangeMempool

    mgr, v1, v2, _v3, _ = setup
    pool = ExchangeMempool(nonce_provider=mgr.get_nonce, vote_seq_provider=mgr.oracle_vote_seq)
    old = v1.tx(ExchangeOpType.ORACLE_VOTE, {"prices": {"BTC": "30000"}})
    new = v1.tx(ExchangeOpType.ORACLE_VOTE, {"prices": {"BTC": "30500"}})
    assert pool.admit(new)[0]
    ok, err = pool.admit(old)
    assert not ok and "newer" in err
    other = v2.tx(ExchangeOpType.ORACLE_VOTE, {"prices": {"BTC": "30400"}})
    assert pool.admit(other)[0]
    deposit = v2.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "1"})
    assert pool.admit(deposit)[0]
    picked = pool.select_for_block()
    assert [t.op_type for t in picked][:2] == [ExchangeOpType.ORACLE_VOTE] * 2
    assert new in picked and old not in picked and deposit in picked
    mgr.begin_block(2, float(T0))
    for t in picked:
        mgr.process_transaction(t)
    assert pool.votes() == []                       # applied: nothing newer is pending


def test_every_path_sets_the_committee_before_each_block():
    """Sections and ticks alike, on the proposer, the importers and both rebuilds — each for
    the block's own height."""
    from qrdx import derived_state_rebuild as DSR
    from qrdx.node import main
    from qrdx.rpc.modules import p2p
    from qrdx.validator import node_integration as NI

    assert "await ensure_oracle_committee(db, mgr, height)" in inspect.getsource(
        BP.preload_sender_balances)
    assert "await ensure_oracle_committee(db, mgr, height)" in inspect.getsource(
        BP.rebuild_exchange_state_from_chain)
    assert "await ensure_oracle_committee(db, mgr, height)" in inspect.getsource(DSR)
    assert "preload_sender_balances(db, txs, mgr, height)" in inspect.getsource(DSR)
    assert "await ensure_oracle_committee(" in inspect.getsource(main._exchange_tick_on_import)
    assert "preload_sender_balances(db, _decoded, mgr, int(block_height))" in inspect.getsource(main)
    assert "ensure_oracle_committee(" in inspect.getsource(p2p)
    src = inspect.getsource(NI.ValidatorNode._block_production_loop)
    assert "ensure_oracle_committee(" in src and "mgr, next_height" in src


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
        for i, who in enumerate((v1, v2, v3, rep)):        # QRDX to pay their gas
            await db.add_transaction(tx_hash=f"alloc{i}", block_hash=f"{0:064x}", tx_hex=json.dumps(
                {"type": "genesis_allocation", "recipient": who.addr, "amount": "5000"}))
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

        await db.seed_genesis_account_state()
        await db.connection.commit()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        BP.apply_enforcement(mgr)                          # the production gates, as the rebuild
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


def test_a_convicted_member_leaves_the_committee(setup):
    """Slashing evidence used to leave a member on the committee (only STAKE_EXIT removed one)."""
    mgr, v1, v2, v3, _ = setup
    mgr.oracle_excluded = {v3.addr.lower()}            # what the refresh sets from the chain
    refused = _vote(mgr, v3, 99999)
    assert not refused.success and "not in the oracle committee" in refused.error
    assert _vote(mgr, v1, 30000).success
    mgr.apply_oracle_votes(T0)                         # v1 alone: 100 of the remaining 200
    assert _oracle(mgr) == 0
    assert _vote(mgr, v2, 30200).success
    mgr.apply_oracle_votes(T0)                         # v1 + v2: all of the remaining stake
    assert _oracle(mgr) == D(30000)


async def test_the_committee_refresh_reads_convictions_from_the_chain(setup, monkeypatch):
    from qrdx import chain_index

    mgr, _v1, _v2, v3, _ = setup
    asked = []

    async def offenders_before(db, height):
        asked.append(height)
        return [v3.addr.lower()]

    class Db:
        connection = object()

        async def get_next_block_id(self):
            return 42

        async def get_block_by_id(self, h):
            return None

    from qrdx.validator import epoch_state

    async def committee(db, height):
        return dict(mgr.oracle_committee)

    monkeypatch.setattr(chain_index, "offenders_before", offenders_before)
    monkeypatch.setattr(epoch_state, "committee_for_block", committee)
    await BP.ensure_oracle_committee(Db(), mgr)
    assert asked == [42] and mgr.oracle_excluded == {v3.addr.lower()}
    assert mgr.capture()["oracle_excluded"] == {v3.addr.lower()}   # restored with the state
    # For a given block, convictions are read below THAT block — not below the tip, or a
    # rebuild of history would exclude a validator from blocks before its conviction.
    await BP.ensure_oracle_committee(Db(), mgr, 7)
    assert asked[-1] == 7


# ── other venues' perp prices: the mark's third input ─────────────────────

def _external(mgr):
    return mgr.clearinghouse.markets[BTC].external_price


def test_perp_price_votes_set_the_external_price_not_the_oracle(setup):
    mgr, v1, v2, v3, _ = setup
    for who, spot, perp in ((v1, 30000, 30100), (v2, 30010, 29000), (v3, 30020, 30060)):
        mgr.begin_block(2, float(T0))
        r = mgr.process_transaction(who.tx(ExchangeOpType.ORACLE_VOTE, {
            "prices": {"BTC": str(spot), "BTC:perp": str(perp)}}))
        assert r.success and r.data == {"markets": [BTC], "perp_prices": [BTC]}
    mgr.apply_oracle_votes(T0)
    m = mgr.clearinghouse.markets[BTC]
    assert m.oracle_price == D(30020) and m.external_price == D(30060)   # v3: 300 of 500
    assert m.external_time == D(T0)


def test_a_minority_cannot_set_the_external_price_and_old_votes_expire(setup):
    mgr, v1, *_ = setup
    mgr.begin_block(2, float(T0))
    assert mgr.process_transaction(v1.tx(ExchangeOpType.ORACLE_VOTE, {
        "prices": {"BTC:perp": "30100"}})).success
    mgr.apply_oracle_votes(T0)
    assert _external(mgr) == 0 and _oracle(mgr) == 0       # 100 of 500
    mgr.apply_oracle_votes(T0 + constants.PERP_ORACLE_VOTE_MAX_AGE + 1)
    assert mgr.perp_votes == {}


def test_a_spot_only_vote_leaves_no_trace_of_perp_prices(setup):
    """Same receipt, no perp state, no "ext" in the market's committed header."""
    from qrdx.exchange.clearinghouse import _market_header
    mgr, v1, *_ = setup
    r = _vote(mgr, v1, 30000)
    assert r.data == {"markets": [BTC]} and mgr.perp_votes == {}
    assert "ext" not in _market_header(mgr.clearinghouse.markets[BTC])


def test_perp_votes_are_committed_captured_and_restored(setup):
    mgr, _v1, _v2, v3, _ = setup
    assert _vote(mgr, v3, 30000).success
    snap, root = mgr.capture(), mgr.oracle_state_hash()
    mgr.begin_block(3, float(T0))
    assert mgr.process_transaction(v3.tx(ExchangeOpType.ORACLE_VOTE, {
        "prices": {"BTC:perp": "30100"}})).success
    assert mgr.perp_votes and mgr.oracle_state_hash() != root
    mgr._restore_snapshot(snap)
    assert mgr.perp_votes == {} and mgr.oracle_state_hash() == root


def _squeeze_seconds(external, target):
    """Seconds for a book squeezed 10 % above a flat oracle to drag the mark to ``target``."""
    from qrdx.exchange.clearinghouse import Clearinghouse, Market
    m = Market(id="X", base="X", quote="Q", max_leverage=D(10),
               book=SimpleNamespace(best_bid=D("110"), best_ask=D("110.2")))
    m.oracle_price, m.last_trade_price = D(100), D("110.1")
    ch = Clearinghouse()
    for t in range(1, 1000):
        now = D(T0 + t)
        if external is not None:
            m.external_price, m.external_time = D(external), now
        ch._refresh_mark(m, now)
        if m.mark_price >= target:
            return t
    return None


def test_the_external_price_slows_a_squeeze_of_the_local_book():
    """Without it the mark followed the 30 s book EMA: a squeeze moved it 3 % in ~12 s. With
    other venues' perps flat, it follows the 150 s premium EMA instead."""
    alone = _squeeze_seconds(None, D(103))
    anchored = _squeeze_seconds("100.1", D(103))
    assert alone is not None and alone <= 15
    assert anchored is not None and anchored >= 4 * alone


def test_a_stale_external_price_falls_back_to_the_book_ema():
    from qrdx.exchange.clearinghouse import EXTERNAL_PRICE_MAX_AGE, Clearinghouse, Market

    def mark(external_age):
        m = Market(id="X", base="X", quote="Q", max_leverage=D(10),
                   book=SimpleNamespace(best_bid=D("101"), best_ask=D("101.2")))
        m.oracle_price, m.last_trade_price = D(100), D("101.1")
        if external_age is not None:
            m.external_price, m.external_time = D(100), D(T0) - external_age
        ch = Clearinghouse()
        for t in range(0, 40):
            ch._refresh_mark(m, D(T0 + t))
        return m.mark_price

    assert mark(EXTERNAL_PRICE_MAX_AGE + 100) == mark(None)
    assert mark(D(0)) < mark(None)


def test_the_two_input_mark_is_the_mean():
    """No book yet, a fresh external price: the mark is the mean of the two inputs."""
    from qrdx.exchange.clearinghouse import Clearinghouse, Market
    m = Market(id="X", base="X", quote="Q", max_leverage=D(10),
               book=SimpleNamespace(best_bid=None, best_ask=None))
    m.oracle_price = D(100)
    m.external_price, m.external_time = D(102), D(T0)
    Clearinghouse()._refresh_mark(m, D(T0))
    assert m.mark_price == D(101)


def test_price_feeds_carry_perp_keys(tmp_path):
    from qrdx.validator.price_feed import FilePriceFeed, StaticPriceFeed, underlying
    feed = StaticPriceFeed("BTC=65000,BTC:perp=65040")
    assert feed.prices(["BTC", "BTC:perp", "ETH:perp"]) == {"BTC": D(65000), "BTC:perp": D(65040)}
    path = tmp_path / "prices.json"
    path.write_text(json.dumps({"qBTC:perp": "30010"}))
    assert FilePriceFeed(str(path)).prices(["qBTC", "qBTC:perp"]) == {"qBTC:perp": D(30010)}
    assert underlying("qBTC:perp") == "BTC:perp" and underlying("ETH:perp") == "ETH:perp"


async def test_a_validators_vote_carries_perp_prices_and_rotates_past_the_cap(setup, monkeypatch):
    from qrdx.validator import node_integration as NI
    from qrdx.validator.price_feed import StaticPriceFeed

    mgr, v1, _v2, _v3, rep = setup
    assert mgr.process_transaction(rep.tx(ExchangeOpType.CREATE_MARKET, {"base_token": "ETH"})).success

    from qrdx.validator import epoch_state

    async def committee(db, height):
        return dict(mgr.oracle_committee)

    class _Db:
        async def get_next_block_id(self):
            return 5

    async def slot():
        return 7

    monkeypatch.setattr(epoch_state, "committee_for_block", committee)
    node = NI.ValidatorNode.__new__(NI.ValidatorNode)
    node.db, node.wallet = _Db(), v1.wallet
    node._price_feed = StaticPriceFeed("BTC=30000,ETH=2000,BTC:perp=30010,ETH:perp=2001")
    node._get_current_slot = slot
    vote = await node._oracle_vote()
    assert vote.nonce == 7 and vote.params["prices"] == {
        "BTC": "30000", "BTC:perp": "30010", "ETH": "2000", "ETH:perp": "2001"}
    monkeypatch.setattr(ExchangeStateManager, "MAX_VOTE_PRICES", 3)
    first, second = await node._oracle_vote(), await node._oracle_vote()
    assert first.params["prices"] == {"BTC": "30000", "BTC:perp": "30010", "ETH": "2000"}
    assert second.params["prices"] == {"BTC": "30000", "ETH": "2000", "ETH:perp": "2001"}
