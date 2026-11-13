"""
Fair ordering (qrdx/exchange/fair_ordering.py, docs/CONSENSUS_ROADMAP.md 1): within a block,
cancels, then post-only orders, then everything else — each nonce lane in nonce order — so a
proposer cannot trade ahead of a maker's cancel. A block that breaks the order is refused.
"""
from decimal import Decimal

from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP
from qrdx.exchange.fair_ordering import (
    CANCEL, OTHER, POST_ONLY, effective_classes, fair_order, order_class, ordering_error)

MID = "BTC-QRDX-PERP"


def _tx(sender, op, nonce=0, signer="", **params):
    return ExchangeTransaction(op_type=op, sender=sender, nonce=nonce, signer=signer,
                               params=params, gas_limit=10 ** 6)


def _order(sender, nonce=0, tif="gtc", **kw):
    return _tx(sender, Op.PERP_ORDER, nonce, market_id=MID, side="buy", size="1", price="99",
               tif=tif, **kw)


def test_the_classes():
    assert order_class(Op.PERP_CANCEL, {}) == CANCEL
    assert order_class(Op.CANCEL_ALL, {}) == CANCEL
    assert order_class(Op.PERP_ORDER, {"tif": "alo"}) == POST_ONLY
    assert order_class(Op.PLACE_ORDER, {"tif": "ALO"}) == POST_ONLY
    assert order_class(Op.PERP_ORDER, {"tif": "ioc"}) == OTHER
    assert order_class(Op.SWAP, {}) == OTHER
    batch = {"actions": [{"op": "PERP_CANCEL", "params": {"market_id": MID, "order_id": "x"}},
                         {"op": "PERP_ORDER", "params": {"market_id": MID, "side": "buy",
                                                         "size": "1", "price": "1"}}]}
    assert order_class(Op.BATCH, batch) == OTHER                    # its highest action


def test_a_taker_ahead_of_another_makers_cancel_is_unfair():
    taker = _order("0xPQtaker", tif="ioc")
    cancel = _tx("0xPQmaker", Op.PERP_CANCEL, market_id=MID, order_id="q1")
    assert ordering_error([taker, cancel])
    assert ordering_error([cancel, taker]) == ""
    assert fair_order([taker, cancel]) == [cancel, taker]


def test_a_lane_keeps_its_nonce_order_and_the_rest_sort_around_it():
    mine = [_order("0xPQa", 0, tif="ioc"), _tx("0xPQa", Op.PERP_CANCEL, 1, market_id=MID,
                                                order_id="x")]
    other_cancel = _tx("0xPQb", Op.PERP_CANCEL, 0, market_id=MID, order_id="y")
    post = _order("0xPQc", 0, tif="alo")
    block = mine + [post, other_cancel]
    ordered = fair_order(block)
    assert ordered == [other_cancel, post, mine[0], mine[1]]        # a's cancel follows its order
    assert effective_classes(ordered) == [CANCEL, POST_ONLY, OTHER, OTHER]
    assert ordering_error(ordered) == ""
    agent_lane = _tx("0xPQa", Op.PERP_CANCEL, 0, signer="0xPQbot", market_id=MID, order_id="z")
    assert fair_order(mine + [agent_lane])[0] is agent_lane         # another lane: free to go first


def test_an_unfair_block_is_refused_before_anything_runs():
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    try:
        before = m.compute_state_root()
        txs = [_order("0xPQtaker", tif="ioc"),
               _tx("0xPQmaker", Op.PERP_CANCEL, market_id=MID, order_id="q1")]
        ok, err, _root = BP.process_exchange_transactions(1, 1_700_000_000.0, txs, m)
        assert not ok and "unfair exchange order" in err
        assert m.compute_state_root() == before
    finally:
        ExchangeStateManager.reset_instance()
