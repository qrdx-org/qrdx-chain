"""
A malicious market deployer, block by block (docs/HYPERLIQUID_PARITY.md 8). The deployer walks
its oracle down as fast as the bound allows to liquidate the longs it is short against. What it
can reach, and what stops it:

* only that market's isolated positions — not a trader's cross margin, not the shared backstop
  vault, not another market;
* the validators freeze it (two thirds of the stake): its oracle and settlement are no longer the
  deployer's, and its funding no longer runs on the price it left behind;
* governance slashes the bond and settles the market at the validators' price.

Every block runs the exchange's full block path (``process_exchange_transactions``).
"""
from decimal import Decimal as D

import pytest
from test_bridge import Key, _genesis

from qrdx import constants
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP
from qrdx.exchange.clearinghouse import VAULT

T0 = 1_700_000_000
DEP, ALICE, BOB, CAROL, DAVE = ("0xPQ" + c * 64 for c in "deabc")
GOLD, BTC = "gold:XAU-USD-PERP", "BTC-USD-PERP"


class Net:
    def __init__(self):
        self.mgr = ExchangeStateManager.get_instance()
        self.height, self.time = 1, T0
        self.nonces = {}
        self.v = [Key(), Key(), Key(), Key()]
        self.mgr.load_oracle_committee(_genesis([(k.addr, 100) for k in self.v]))

    def tx(self, who, op, **params):
        """(An oracle vote carries its own sequence, not the account's nonce.)"""
        lane = (who, op == Op.ORACLE_VOTE)
        n = self.nonces.get(lane, 1 if op == Op.ORACLE_VOTE else 0)
        self.nonces[lane] = n + 1
        return ExchangeTransaction(op_type=op, sender=who, nonce=n, params=params,
                                   gas_limit=10 ** 7)

    def block(self, *txs, dt=1):
        """One block, ``dt`` seconds after the last: its transactions, then the tick."""
        self.height += 1
        self.time += dt
        ok, err, _root = BP.process_exchange_transactions(self.height, float(self.time),
                                                          list(txs), self.mgr)
        assert ok, err
        results = list(self.mgr._block_results)
        self.mgr.commit_block()
        # (The block's own transactions run after any queued contract actions: none here.)
        assert len(results) == len(txs)
        return results


@pytest.fixture
def net(monkeypatch, no_risk_limits):
    monkeypatch.setattr(constants, "PERP_QUOTE", "USD")
    for name, value in (("GOV_VOTING_PERIOD_BLOCKS", 3), ("GOV_TIMELOCK_BLOCKS", 2),
                        ("GOV_EXECUTION_WINDOW_BLOCKS", 100)):
        monkeypatch.setattr(constants, name, value)
    ExchangeStateManager.reset_instance()
    n = Net()
    mgr, ch = n.mgr, n.mgr.clearinghouse
    mgr.begin_block(1, float(T0))
    ch.create_market("BTC", "USD")
    ch.set_oracle_price(BTC, D(30000), now=T0)
    for who in (DEP, ALICE, BOB, CAROL, DAVE):
        ch.deposit(who, D(200_000))
    mgr.set_available_balance(DEP, D(1_000_000))
    r = n.block(n.tx(DEP, Op.DEPLOYER_BOND, dex="gold", amount="150000"),
                n.tx(DEP, Op.CREATE_MARKET, base_token="gold:XAU", oracle_price="2000",
                     liquidity="20000", fee_share_bps=5000))
    assert all(x.success for x in r), [x.error for x in r]
    # Carol: a cross BTC position, and a small gold one (isolated, as every gold position is).
    r = n.block(n.tx(DAVE, Op.PERP_ORDER, market_id=BTC, side="sell", size="1", price="30000"),
                n.tx(CAROL, Op.PERP_ORDER, market_id=BTC, side="buy", size="1", price="30000"),
                n.tx(BOB, Op.PERP_ORDER, market_id=GOLD, side="sell", size="6", price="2000"),
                n.tx(ALICE, Op.PERP_ORDER, market_id=GOLD, side="buy", size="5", price="2000",
                     leverage="10"),
                n.tx(CAROL, Op.PERP_ORDER, market_id=GOLD, side="buy", size="1", price="2000",
                     leverage="10"))
    assert all(x.success for x in r), [x.error for x in r]
    yield n
    ExchangeStateManager.reset_instance()


def _walk(n, blocks, factor=D("0.95")):
    """The deployer asks for a 5 % drop every second; the bound lets it fall 1 % a second."""
    for _ in range(blocks):
        price = n.mgr.clearinghouse.markets[GOLD].oracle_price * factor
        n.block(n.tx(DEP, Op.DEPLOYER_SET_ORACLE, market_id=GOLD, price=str(price)))


def test_the_damage_stays_in_the_deployers_market(net):
    ch = net.mgr.clearinghouse
    carol_cross = ch.accounts[CAROL].collateral
    vault_before = ch.account(VAULT).collateral
    btc_carol, btc_dave = (ch.accounts[w].positions[BTC].size for w in (CAROL, DAVE))
    _walk(net, 40)
    gold = ch.markets[GOLD]
    assert gold.oracle_price < 2000 * D("0.70")                    # walked ~33 % down
    assert ALICE not in [o for o, a in ch.accounts.peek_items() if GOLD in a.positions
                         and a.positions[GOLD].size > 0]           # the long was liquidated
    # Carol's cross margin never paid for gold; her gold margin was all gold could take.
    assert ch.accounts[CAROL].collateral >= carol_cross
    assert ch.accounts[CAROL].positions[BTC].size == btc_carol
    assert ch.accounts[DAVE].positions[BTC].size == btc_dave
    # The shared backstop took nothing over and lost nothing.
    vault = ch.accounts.peek(VAULT)
    assert GOLD not in vault.positions
    assert vault.collateral >= vault_before
    assert ch.identity_gap() == 0 and ch.net_size(GOLD) == 0 and ch.net_size(BTC) == 0


def test_a_freeze_stops_the_deployer_and_its_funding(net):
    ch = net.mgr.clearinghouse
    _walk(net, 5)
    net.block(*(net.tx(k.addr, Op.ORACLE_VOTE, freeze=[GOLD]) for k in net.v[:3]))
    net.block()                                                    # (applied in this tick)
    gold = ch.markets[GOLD]
    assert ch.frozen(gold, net.time)
    (r,) = net.block(net.tx(DEP, Op.DEPLOYER_SET_ORACLE, market_id=GOLD, price="1"))
    assert not r.success and "frozen" in r.error
    (r,) = net.block(net.tx(DAVE, Op.PERP_ORDER, market_id=GOLD, side="buy", size="1",
                            price="1900"))
    assert not r.success and "frozen" in r.error
    # A bid far above the price the deployer left behind would read as a premium — and pay
    # funding at the cap — if the frozen oracle still counted.
    (r,) = net.block(net.tx(BOB, Op.PERP_ORDER, market_id=GOLD, side="buy", size="2",
                            price=str((gold.oracle_price * D("1.15")).quantize(D(1))),
                            reduce_only=True))
    assert r.success, r.error
    sampled = gold.premium_time
    for _ in range(10):                                            # the validators keep it
        net.block(*(net.tx(k.addr, Op.ORACLE_VOTE, freeze=[GOLD]) for k in net.v[:3]))
    assert ch.frozen(gold, net.time)
    assert gold.premium_time == sampled                            # no premium while frozen


def test_governance_slashes_the_bond_and_settles_at_the_validators_price(net):
    ch, mgr = net.mgr.clearinghouse, net.mgr
    _walk(net, 5)
    freeze = [net.tx(k.addr, Op.ORACLE_VOTE, freeze=[GOLD], prices={"gold:XAU": "1950"})
              for k in net.v[:3]]
    net.block(*freeze)
    v1, v2, v3 = net.v[:3]
    (r,) = net.block(net.tx(v1.addr, Op.GOV_PROPOSE, action="slash_deployer", deployer=DEP,
                            bps=10_000, halt=True))
    assert r.success, r.error
    pid = r.data["proposal_id"]
    def votes():  # (oracle votes run first in a block: fair ordering)
        return [net.tx(x.addr, Op.ORACLE_VOTE, freeze=[GOLD], prices={"gold:XAU": "1950"})
                for x in net.v[:3]]

    for k in (v1, v2, v3):
        net.block(*votes(), net.tx(k.addr, Op.GOV_VOTE, proposal_id=pid, support=True))
    executed = None
    for _ in range(12):
        executed = net.block(*votes(), net.tx(DAVE, Op.GOV_EXECUTE, proposal_id=pid))[-1]
        if executed.success:
            break
    assert executed is not None and executed.success, executed.error
    assert executed.data["settled"] == [GOLD]
    assert D(executed.data["burned"]) == 150_000
    gold = ch.markets[GOLD]
    assert gold.settled_price > 0 and gold.open_interest == 0
    assert mgr.trading.deployers[DEP].bond == 0
    assert ch.identity_gap() == 0
