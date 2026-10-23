"""
Source chains' finalized heads, attested by the validators (docs/BRIDGE.md "Chain heads"): a vote
carries the head each validator's watcher saw; a head with more than two thirds of the
committee's stake, and higher than the last, becomes consensus state — committed, provable, and
what the getChainState precompile (0x0200) answers from, in place of a node-local table that would
have split the chain the day a node filled it.
"""
from decimal import Decimal

import pytest
from test_bridge import CHAIN, T0, Key, _genesis
from test_evm_world import ALICE, Chain, chain  # noqa: F401  (fixture)

from qrdx.contracts.evm_world import CHAIN_STATE_ADDRESS
from qrdx.exchange import ExchangeOpType, ExchangeStateManager
from qrdx.exchange.bridge import HEAD_VOTE_MAX_AGE, parse_head

D = Decimal


def _head(height, h="11", root="22", ts=1_800_000_000):
    return {"chain": CHAIN, "height": height, "hash": "0x" + h * 32,
            "state_root": "0x" + root * 32, "timestamp": ts}


@pytest.fixture
def setup():
    v1, v2, v3 = Key(), Key(), Key()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
    mgr.begin_block(1, float(T0))
    yield mgr, v1, v2, v3
    ExchangeStateManager.reset_instance()


def _vote(mgr, who, *heads, at=T0):
    mgr.begin_block(2, float(at))
    return mgr.process_transaction(who.tx(ExchangeOpType.ORACLE_VOTE, {"heads": list(heads)}))


def test_a_head_needs_two_thirds_of_the_stake_for_exactly_it(setup):
    mgr, v1, v2, v3 = setup
    r = _vote(mgr, v3, _head(100))                               # 300 of 500
    assert r.success and "attested_heads" not in r.data and mgr.bridge.head(CHAIN) is None
    r = _vote(mgr, v1, _head(100, h="99"))                       # a different hash: no quorum
    assert "attested_heads" not in r.data
    r = _vote(mgr, v2, _head(100))                               # 400 of 500 for it
    assert r.data["attested_heads"] == [CHAIN]
    head = mgr.bridge.head(CHAIN)
    assert head.height == 100 and head.hash == "0x" + "11" * 32


def test_heads_only_move_forward_and_stale_votes_lapse(setup):
    mgr, v1, v2, v3 = setup
    for who in (v1, v3):
        _vote(mgr, who, _head(100))
    for who in (v1, v3):
        _vote(mgr, who, _head(90, h="33"))                      # lower: never replaces
    assert mgr.bridge.head(CHAIN).height == 100
    _vote(mgr, v3, _head(120))
    later = T0 + int(HEAD_VOTE_MAX_AGE) + 1
    _vote(mgr, v1, _head(120), at=later)                         # v3's vote is too old now
    assert mgr.bridge.head(CHAIN).height == 100


@pytest.mark.parametrize("bad", [
    {"chain": 0, "height": 1, "hash": "0x" + "1" * 64, "state_root": "0x" + "2" * 64, "timestamp": 1},
    {"chain": 1, "height": -1, "hash": "0x" + "1" * 64, "state_root": "0x" + "2" * 64, "timestamp": 1},
    {"chain": 1, "height": 1, "hash": "0x12", "state_root": "0x" + "2" * 64, "timestamp": 1},
    {"chain": 1, "height": 1, "hash": "0x" + "1" * 64},
])
def test_malformed_heads_are_refused(setup, bad):
    mgr, v1, _v2, _v3 = setup
    r = _vote(mgr, v1, bad)
    assert not r.success and "chain head" in r.error


def test_one_head_per_chain_per_vote(setup):
    mgr, v1, _v2, _v3 = setup
    r = _vote(mgr, v1, _head(1), _head(2))
    assert not r.success and "one head per chain" in r.error


def test_hashes_are_normalized_so_honest_copies_agree():
    a = parse_head(_head(5, h="AB"))
    b = parse_head(_head(5, h="ab"))
    assert a == b


async def test_the_precompile_answers_from_the_attested_head_and_nothing_else(chain):
    """It used to answer from a module-level table any node could fill from its own view."""
    from eth.vm.forks.qrdx.precompiles import oracle_set_chain_state

    v1, v2, v3 = Key(), Key(), Key()
    mgr = ExchangeStateManager.get_instance()
    mgr.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
    oracle_set_chain_state(CHAIN, 999, b"\xee" * 32, b"\xee" * 32, 1)   # a node's own view
    query = CHAIN.to_bytes(4, "big")
    r = await chain.tx(ALICE, CHAIN_STATE_ADDRESS, query)
    assert r.success and r.output == bytes(80)                          # nothing attested
    for who in (v1, v3):
        _vote(mgr, who, _head(100))
    r = await chain.tx(ALICE, CHAIN_STATE_ADDRESS, query)
    assert r.output[:8] == (100).to_bytes(8, "big")
    assert r.output[8:40] == b"\x11" * 32 and r.output[40:72] == b"\x22" * 32
    assert r.output[72:] == (1_800_000_000).to_bytes(8, "big")


def test_the_watcher_reports_each_sources_finalized_head():
    from qrdx.validator.bridge_watcher import BridgeWatcher, EvmSource

    src = EvmSource(CHAIN, "http://unused", "0x" + "00" * 20, from_block=10)
    calls = {"eth_getBlockByNumber": {"number": hex(10), "hash": "0x" + "AA" * 32,
                                      "stateRoot": "0x" + "BB" * 32, "timestamp": hex(77)},
             "eth_getLogs": []}
    src._call = lambda method, params: calls[method]
    w = BridgeWatcher([src], start=False)
    w.poll_once()
    assert w.heads() == [{"chain": CHAIN, "height": 10, "hash": "0x" + "aa" * 32,
                          "state_root": "0x" + "bb" * 32, "timestamp": 77}]
