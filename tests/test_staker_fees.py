"""
Trading fees to stakers (docs/CONSENSUS_ROADMAP.md 6).

STAKER_FEE_SHARE_BPS of the protocol's QRDX fee income (spot fees paid in QRDX; perps fees when
perps settle in QRDX) goes to a fee holder as it is paid; each block logs what it took in. Each
epoch's income is shared like the minted rewards — among the validators whose vote is carried,
by principal and pool, commission applied — and paid out of the holder, never minted.
"""
import os
import tempfile
from decimal import Decimal

import pytest
from test_epoch_state import G, Chain

from qrdx import constants
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange import ExchangeStateManager
from qrdx.validator import epoch_state as ES
from qrdx.validator.epoch_state import (
    STAKER_FEE_HOLDER,
    EpochInputs,
    Pool,
    genesis_state,
    transition,
)
from qrdx.validator.ffg import INCLUSION_EPOCHS
from qrdx.validator.withdrawals import _payout_moves

D = Decimal
E = 1 + INCLUSION_EPOCHS  # the first epoch whose transition rewards (target ≥ 1)


def _genesis():
    return genesis_state([{"address": a, "stake": "100000"} for a in G])


@pytest.fixture
def no_minting(monkeypatch):
    """Minted rewards off: they compound into pools first, which would move the weights."""
    monkeypatch.setattr(constants, "STAKING_REWARD_RATE_BPS", 0)


def _fees(s, kind):
    return {p.address: p.amount for p in s.payouts if p.kind == kind}


# ── the share-out ───────────────────────────────────────────────────────────

def test_an_epochs_fees_go_to_its_voters_by_principal_and_pool(no_minting):
    s = _genesis()
    s.pools[G[0]] = Pool(G[0], commission_bps=1000, value=D(100_000), total_shares=D(100_000),
                         shares={"0xPQdelegator": D(100_000)})
    out = transition(s, E, EpochInputs(ops=[], attesters=G[:2], offenders=[], fees=D(300)))
    # Weights: G0 100k + its pool 100k, G1 100k (G2 did not vote): 300 → 200 / 100.
    assert _fees(out, "fee") == {G[0]: D(110), G[1]: D(100)}         # G0: 100 + 10 % of 100
    assert _fees(out, "fee_pooled") == {STAKER_FEE_HOLDER: D(90)}
    assert out.pools[G[0]].value == D(100_090)
    assert out.fee_carry == 0


def test_without_voters_the_fees_wait_for_the_next_epoch(no_minting):
    s = transition(_genesis(), 1, EpochInputs(ops=[], attesters=[], offenders=[], fees=D(30)))
    assert s.fee_carry == 30 and not _fees(s, "fee")
    s = transition(s, E, EpochInputs(ops=[], attesters=G, offenders=[], fees=D(60)))
    assert _fees(s, "fee") == {a: D(30) for a in G} and s.fee_carry == 0


def test_what_rounding_leaves_is_carried_never_lost(no_minting):
    s = transition(_genesis(), E, EpochInputs(ops=[], attesters=G, offenders=[],
                                              fees=D("1e-18")))
    assert not _fees(s, "fee") and s.fee_carry == D("1e-18")
    s = transition(s, E + 1, EpochInputs(ops=[], attesters=G, offenders=[], fees=D("2e-18")))
    assert _fees(s, "fee") == {a: D("1e-18") for a in G} and s.fee_carry == 0


def test_the_carry_is_part_of_the_state_and_absent_while_zero():
    s = _genesis()
    assert "fee_carry" not in ES._dump(s)                             # earlier states' hashes
    s.fee_carry = D("1.5")
    assert ES._load(ES._dump(s)).fee_carry == D("1.5")


def test_fee_payouts_come_out_of_the_holder_and_rewards_are_minted():
    assert _payout_moves("0xPQv", D(5), "fee") == [(STAKER_FEE_HOLDER, D(-5)), ("0xPQv", D(5))]
    assert _payout_moves(STAKER_FEE_HOLDER, D(5), "fee_pooled") == [(STAKER_FEE_HOLDER, D(-5))]
    assert _payout_moves("0xPQv", D(5), "reward") == [("0xPQv", D(5))]


# ── on the chain: the per-block log ─────────────────────────────────────────

@pytest.fixture
async def chain():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(path)
    c = Chain(db)
    await c.genesis()
    yield c
    await db.connection.close()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.remove(p)


async def test_the_logged_income_is_shared_and_a_rollback_drops_it(chain, no_minting):
    for e in range(1, E):
        await chain.epoch(e)
    h = await chain.epoch(E)
    await chain.db.log_staker_fee_income(h, D(90))
    await chain.db.log_staker_fee_income(h, D(90))                    # a rebuild: same row
    await chain.db.connection.commit()
    s = await ES.state_at(chain.db, E + 1)                            # (indexes the chain)
    assert _fees(s, "fee") == {a: D(30) for a in G}
    assert (await ES.epoch_inputs(chain.db, E, h)).fees == D(90)      # one-epoch ≡ batched
    await chain.rollback(h - 1)
    cur = await chain.db.connection.execute("SELECT COUNT(*) FROM staker_fee_income")
    assert (await cur.fetchone())[0] == 0


# ── the exchange: what goes to the holder ───────────────────────────────────

def test_perps_fees_leave_the_clearinghouse_at_the_blocks_end():
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    try:
        m.begin_block(1, 1_700_000_000.0)
        ch = m.clearinghouse
        ch.create_market("BTC")
        ch.set_oracle_price("BTC-QRDX-PERP", D(30000))
        for who in ("a", "b"):
            ch.deposit(who, D(100_000))
        ch.place_order("b", "BTC-QRDX-PERP", "s", "sell", D(1), D(30000), 0)
        ch.place_order("a", "BTC-QRDX-PERP", "b", "buy", D(1), D(30000), 0)
        withheld = ch.staker_fees
        assert withheld > 0
        assert m.move_perps_staker_fees() == withheld and ch.staker_fees == 0
        deltas = m.balance_deltas()
        assert deltas[m.perps_holder_address()] == -withheld
        assert deltas[STAKER_FEE_HOLDER] == withheld
        assert m.block_staker_fees() == withheld
        assert ch.identity_gap() == 0
    finally:
        ExchangeStateManager.reset_instance()


def test_perps_in_another_asset_withhold_the_share_too(monkeypatch):
    """Perps settling in a stablecoin: the share is withheld in it (and sold for QRDX by the
    tick: tests/test_staker_fees.py ``…sold_for_qrdx…``)."""
    from qrdx.exchange.clearinghouse import Clearinghouse

    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", "0x" + "ab" * 20)
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price("BTC-QRDX-PERP", D(30000))
    for who in ("a", "b"):
        ch.deposit(who, D(100_000))
    ch.place_order("b", "BTC-QRDX-PERP", "s", "sell", D(1), D(30000), 0)
    ch.place_order("a", "BTC-QRDX-PERP", "b", "buy", D(1), D(30000), 0)
    assert ch.staker_fees > 0 and ch.vault_collateral > 0
    assert ch.identity_gap() == 0


async def test_a_block_without_fees_clears_an_orphans_row_at_its_height(chain):
    """After a reorg, a block at an orphan's height that took in nothing must not inherit the
    orphan's income (every path writes each block's row, removing it for nothing)."""
    await chain.db.log_staker_fee_income(7, D(90))                    # the orphan's
    await chain.db.log_staker_fee_income(7, D(0))                     # the new block's
    cur = await chain.db.connection.execute("SELECT COUNT(*) FROM staker_fee_income")
    assert (await cur.fetchone())[0] == 0
