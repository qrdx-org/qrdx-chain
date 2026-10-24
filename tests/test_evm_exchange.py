"""
The exchange from a contract (qrdx/contracts/exchange_evm.py, docs/HYPERLIQUID_PARITY.md):
contracts read exchange state (0x…0400) and send exchange actions as their own account (0x…0401,
Hyperliquid's CoreWriter). An action is journaled with the call — a revert drops it — queued in
the exchange's committed state when the block's EVM section is accepted, and run at the start of
the next block's exchange processing, on every path.
"""
import json
import pickle
from decimal import Decimal as D

from eth_abi import decode, encode
from eth_utils import keccak
from test_evm_world import ALICE, Chain, chain, forwarder  # noqa: F401  (fixture)

from qrdx.contracts.evm_world import EXCHANGE_READ_ADDRESS, EXCHANGE_WRITE_ADDRESS
from qrdx.exchange import ExchangeStateManager
from qrdx.exchange import block_processor as BP

MID = "BTC-QRDX-PERP"
T0 = 1_700_000_000
TRADER = "0xPQ" + "a" * 64


def _sel(sig):
    return keccak(sig.encode())[:4]


def _action(op, gas=None, **params):
    body = {"op": op, "params": params, **({"gas": gas} if gas is not None else {})}
    return _sel("sendAction(string)") + encode(["string"], [json.dumps(body)])


def _mgr():
    mgr = ExchangeStateManager.get_instance()
    if MID not in mgr.clearinghouse.markets:
        mgr.begin_block(1, float(T0))
        mgr.clearinghouse.create_market("BTC")
        mgr.clearinghouse.set_oracle_price(MID, D(30000), now=T0)
    return mgr


async def _sender(chain):
    """A contract that forwards its calldata to the write precompile, ignoring the result."""
    c = await chain.deploy(forwarder(EXCHANGE_WRITE_ADDRESS))
    return c, "0x" + c.hex()


def _next_block(mgr, height=2):
    ok, err, _root = BP.process_exchange_transactions(height, float(T0 + height), [], mgr)
    assert ok, err
    return [
        {"owner": tx.sender, "op": tx.op_type.name, "success": r.success, "error": r.error,
         "id": tx.tx_hash()[:16]}
        for tx, r in zip(mgr._block_exchange_txs, mgr._block_results, strict=True)
        if type(tx).__name__ == "_EvmAction"
    ]


# ── reads ───────────────────────────────────────────────────────────────────

async def test_a_contract_reads_prices_positions_and_accounts(chain):
    mgr = _mgr()
    ch = mgr.clearinghouse
    out = (await chain.tx(ALICE, EXCHANGE_READ_ADDRESS,
                          _sel("oraclePrice(string)") + encode(["string"], [MID]))).output
    assert decode(["uint256"], out)[0] == 30000 * 10 ** 18
    out = (await chain.tx(ALICE, EXCHANGE_READ_ADDRESS,
                          _sel("markPrice(string)") + encode(["string"], ["NOPE-PERP"]))).output
    assert decode(["uint256"], out)[0] == 0

    for who in (TRADER, "0xPQ" + "b" * 64):
        ch.deposit(who, D(100_000))
    ch.place_order("0xPQ" + "b" * 64, MID, "s1", "sell", D(1), D(30000), 1)
    ch.place_order(TRADER, MID, "b1", "buy", D(1), D(30000), 1)
    out = (await chain.tx(ALICE, EXCHANGE_READ_ADDRESS, _sel("positionOf(string,string)")
                          + encode(["string", "string"], [TRADER, MID]))).output
    size, entry, _iso = decode(["int256", "uint256", "uint256"], out)
    assert size == 10 ** 18 and entry == 30000 * 10 ** 18
    out = (await chain.tx(ALICE, EXCHANGE_READ_ADDRESS, _sel("perpAccount(address)")
                          + encode(["address"], ["0x" + "77" * 20]))).output
    assert decode(["int256", "uint256"], out) == (0, 0)                 # no account
    out = (await chain.tx(ALICE, EXCHANGE_READ_ADDRESS,
                          _sel("resolve(string)") + encode(["string"], ["nobody.qrdx"]))).output
    assert decode(["address"], out)[0] == "0x" + "00" * 20


async def test_an_unknown_read_reverts(chain):
    _mgr()
    r = await chain.tx(ALICE, EXCHANGE_READ_ADDRESS, b"\xde\xad\xbe\xef")
    assert not r.success


# ── writes ──────────────────────────────────────────────────────────────────

async def test_an_action_runs_as_the_contract_at_the_start_of_the_next_block(chain):
    mgr = _mgr()
    c, key = await _sender(chain)
    mgr.clearinghouse.deposit(key, D(100_000))
    mgr.clearinghouse.deposit(TRADER, D(100_000))
    mgr.clearinghouse.place_order(TRADER, MID, "s1", "sell", D(1), D(30000), 1)
    root = mgr.compute_state_root()
    assert (await chain.tx(ALICE, c, _action("PERP_ORDER", gas=200_000, market_id=MID,
                                             side="buy", size="1", price="30000"))).success
    assert len(mgr.trading.evm_actions) == 1                            # queued, committed
    assert mgr.compute_state_root() != root
    assert mgr.clearinghouse.accounts[key].positions.get(MID) is None   # not yet
    (event,) = _next_block(mgr)
    assert event["success"] and event["owner"] == key and event["op"] == "PERP_ORDER"
    assert mgr.clearinghouse.accounts[key].positions[MID].size == 1
    assert len(mgr.trading.evm_actions) == 0                            # drained
    assert mgr.clearinghouse.identity_gap() == 0


async def test_two_identical_actions_place_two_orders(chain):
    mgr = _mgr()
    c, key = await _sender(chain)
    mgr.clearinghouse.deposit(key, D(100_000))
    order = _action("PERP_ORDER", market_id=MID, side="buy", size="0.1", price="29000")
    assert (await chain.tx(ALICE, c, order)).success
    assert (await chain.tx(ALICE, c, order)).success
    events = _next_block(mgr)
    assert [e["success"] for e in events] == [True, True]
    assert events[0]["id"] != events[1]["id"]
    mine = [o for o in mgr.clearinghouse.markets[MID].orders.values() if o.owner == key]
    assert len(mine) == 2


async def test_a_reverted_call_or_a_bad_action_sends_nothing(chain):
    mgr = _mgr()
    c, _key = await _sender(chain)
    regretful = await chain.deploy(forwarder(EXCHANGE_WRITE_ADDRESS, revert_after=True))
    order = _action("PERP_ORDER", market_id=MID, side="buy", size="1", price="30000")
    assert not (await chain.tx(ALICE, regretful, order)).success        # the call reverted
    for bad in (_action("TOKEN_MINT", token_address="0x" + "1" * 40, amount="1"),  # not allowed
                _action("PERP_ORDER", market_id=MID, side="buy", size="1"),  # no price
                _sel("sendAction(string)") + encode(["string"], ["not json"]),
                _action("PERP_ORDER", gas=10 ** 9, market_id=MID, side="buy", size="1",
                        price="30000"),
                b"\x00\x00\x00\x00"):
        assert (await chain.tx(ALICE, c, bad)).success                  # the precompile reverted
    assert len(mgr.trading.evm_actions) == 0


async def test_a_failing_action_changes_nothing_but_leaves_the_queue(chain):
    mgr = _mgr()
    c, key = await _sender(chain)                                       # no collateral
    assert (await chain.tx(ALICE, c, _action("PERP_ORDER", market_id=MID, side="buy",
                                             size="1", price="30000"))).success
    root = mgr.compute_state_root()
    (event,) = _next_block(mgr)
    assert not event["success"] and event["error"]
    assert len(mgr.trading.evm_actions) == 0
    assert mgr.clearinghouse.accounts.peek(key) is None or not mgr.clearinghouse.accounts.peek(
        key).positions
    assert root != mgr.compute_state_root()                             # (the queue emptied)


async def test_a_deposit_spends_the_contracts_own_qrdx_on_a_quiet_block(chain, monkeypatch):
    """A block without exchange transactions still runs the queue (tick_and_flush): the
    contract's balance is preloaded, the deposit judged against it, and the debit flushed."""
    monkeypatch.setattr(BP, "ENFORCE_EXCHANGE_COLLATERAL", True)
    mgr = _mgr()
    c, key = await _sender(chain)
    await chain.fund(c, 50 * 10 ** 18)
    assert (await chain.tx(ALICE, c, _action("PERP_DEPOSIT", amount="80"))).success
    assert (await chain.tx(ALICE, c, _action("PERP_DEPOSIT", amount="20"))).success
    await BP.tick_and_flush(chain.db, 2, float(T0 + 2), mgr)
    await chain.db.connection.commit()
    assert mgr.clearinghouse.accounts[key].collateral == 20             # 80 > 50: refused
    assert await chain.db.get_address_balance(key) == 30


def test_the_queue_survives_a_checkpoint_and_older_ones_load():
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(5, float(T0))
    mgr.queue_evm_actions([("0x" + "12" * 20, "PERP_SET_LEVERAGE",
                            json.dumps({"market_id": MID, "leverage": "3"}), 20_000)])
    copy = pickle.loads(pickle.dumps(mgr.trading))
    assert copy.commitment() == mgr.trading.commitment()
    state = dict(mgr.trading.__dict__)
    state.pop("evm_actions")
    old = object.__new__(type(mgr.trading))
    old.__setstate__(state)
    assert len(old.evm_actions) == 0
    ExchangeStateManager.reset_instance()


def _delegator(target: bytes) -> bytes:
    """DELEGATECALL ``target`` with the calldata, ignoring the result."""
    return (bytes.fromhex("366000600037") + bytes.fromhex("6020600036600073") + target
            + bytes.fromhex("5af450") + bytes.fromhex("60206000f3"))


async def test_a_contract_cannot_send_actions_as_its_caller(chain):
    """A DELEGATECALL keeps the caller's ``msg.sender``: through one, any contract a victim
    called could trade or withdraw the victim's exchange account. Only a plain CALL acts — as
    the calling contract — and no QRDX is taken."""
    mgr = _mgr()
    evil = await chain.deploy(_delegator(EXCHANGE_WRITE_ADDRESS))
    r = await chain.tx(ALICE, evil, _action("PERP_WITHDRAW", amount="1"))
    assert r.success                                     # the outer call ignores the revert
    assert len(mgr.trading.evm_actions) == 0             # nothing was sent as Alice
    r = await chain.tx(ALICE, EXCHANGE_WRITE_ADDRESS, _action("PERP_DEPOSIT", amount="1"),
                       value=10 ** 18)
    assert not r.success and len(mgr.trading.evm_actions) == 0
