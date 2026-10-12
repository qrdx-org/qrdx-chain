"""
The consensus bridge (docs/BRIDGE.md, qrdx/exchange/bridge.py).

Validators attest deposits made into the lockbox on a source chain inside their oracle votes; a
deposit is minted once attestations agreeing on every field carry more than two thirds of the
committee's stake, through a mint authority no key controls, and only once. BRIDGE_WITHDRAW
burns the bridged token and records the withdrawal for the lockbox's custodian.
"""
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
from qrdx.exchange.bridge import (
    BRIDGE_AUTHORITY, ATTESTATION_MAX_AGE, Bridge, BridgeError, parse_assets, parse_deposit,
    token_address,
)

D = Decimal
T0 = 1_700_000_000
CHAIN, USDC = 42161, "0xaf88d065e77c8cc2239327c5edb3a432268e5831"
ASSET = f"USDC:{CHAIN}:{USDC}:6"
FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "lockbox_deposit_logs.json")


class Key:
    def __init__(self):
        self.key = PQPrivateKey.generate()
        self.addr = self.key.public_key.to_address()
        self.nonce = 0
        self.vote_seq = 0

    @property
    def wallet(self):
        k = self.key
        return SimpleNamespace(address=self.addr, public_key=k.public_key.to_bytes(),
                               sign=lambda m: k.sign(m).to_bytes())

    def tx(self, op, params):
        if op == ExchangeOpType.ORACLE_VOTE:
            self.vote_seq += 1
            nonce = self.vote_seq
        else:
            nonce, self.nonce = self.nonce, self.nonce + 1
        t = ExchangeTransaction(op_type=op, sender=self.addr, nonce=nonce, params=params,
                                gas_limit=2_000_000, gas_price=10**9)
        t.public_key = self.key.public_key.to_bytes()
        t.signature = self.key.sign(t.signing_bytes()).to_bytes()
        return t


def _genesis(stakes):
    return json.dumps({"type": "genesis", "validators": len(stakes),
                       "validator_set": [{"address": a, "stake": str(s)} for a, s in stakes]})


def _deposit(to, amount="250.5", tx="ab", log=3):
    return {"chain": CHAIN, "token": USDC, "tx": "0x" + tx * 32, "log": log, "to": to,
            "amount": amount}


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setattr(constants, "BRIDGE_ASSETS", (ASSET,))
    v1, v2, v3, user = Key(), Key(), Key(), Key()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
    mgr.begin_block(1, float(T0))
    yield mgr, v1, v2, v3, user
    ExchangeStateManager.reset_instance()


def _attest(mgr, who, *deposits, at=T0, height=2):
    mgr.begin_block(height, float(at))
    return mgr.process_transaction(who.tx(ExchangeOpType.ORACLE_VOTE,
                                          {"deposits": list(deposits)}))


def _usdc():
    return token_address(CHAIN, USDC)


# ── configuration and parsing ─────────────────────────────────────────────

def test_assets_parse_strictly():
    (asset,) = parse_assets([ASSET]).values()
    assert (asset.symbol, asset.chain, asset.source_token, asset.decimals) == ("USDC", CHAIN, USDC, 6)
    assert asset.address == _usdc() != USDC
    for bad in ("USDC:42161:0xabc:6", "USDC:42161:" + USDC, "USDC:0:" + USDC + ":6",
                "USDC:1:" + USDC + ":19"):
        with pytest.raises(BridgeError):
            parse_assets([bad])
    with pytest.raises(BridgeError, match="twice"):
        parse_assets([ASSET, ASSET.replace("USDC", "USDC2", 1)])


def test_a_deposit_is_normalized_so_honest_copies_are_identical():
    assets = parse_assets([ASSET])
    a = parse_deposit(_deposit("0xPQ" + "cd" * 32, "250.5"), assets)
    b = parse_deposit(dict(_deposit("0xPQ" + "cd" * 32, "250.500000"), tx="0x" + "AB" * 32), assets)
    assert a == b and a.digest == b.digest and a.id == f"{CHAIN}:0x{'ab' * 32}:3"
    for bad, why in ((dict(_deposit("0xPQ" + "cd" * 32), token="0x" + "11" * 20), "no bridged"),
                     (_deposit("0xPQ" + "cd" * 32, "1.0000001"), "decimals"),
                     (_deposit("0xPQ" + "cd" * 32, "-1"), "positive"),
                     (_deposit("nobody"), "recipient"),
                     (dict(_deposit("0xPQ" + "cd" * 32), tx="0x12"), "transaction hash")):
        with pytest.raises(BridgeError, match=why):
            parse_deposit(bad, assets)


# ── attestation and minting ───────────────────────────────────────────────

def test_a_deposit_mints_once_two_thirds_of_the_stake_attest_it(setup):
    mgr, v1, _v2, v3, user = setup
    d = _deposit(user.addr)
    r = _attest(mgr, v3, d)                      # 300 of 500: not more than two thirds
    assert r.success and "minted" not in r.data and mgr.tokens.get(_usdc()) is None
    r = _attest(mgr, v1, d)                      # 400 of 500
    assert r.success and r.data["minted"] == [f"{CHAIN}:0x{'ab' * 32}:3"]
    t = mgr.tokens.get(_usdc())
    assert t.supply == D("250.5") and t.mint_authority == BRIDGE_AUTHORITY and t.decimals == 6
    assert mgr.token_balance_deltas() == {(user.addr, _usdc()): D("250.5")}
    assert mgr.bridge.done == {f"{CHAIN}:0x{'ab' * 32}:3"} and not mgr.bridge.pending


def test_a_minted_deposit_is_never_minted_again(setup):
    mgr, v1, v2, v3, user = setup
    d = _deposit(user.addr)
    _attest(mgr, v3, d)
    _attest(mgr, v1, d)
    r = _attest(mgr, v2, d, height=3)            # a late attestation
    assert r.success and "minted" not in r.data
    assert mgr.tokens.get(_usdc()).supply == D("250.5") and not mgr.bridge.pending


def test_conflicting_attestations_never_combine(setup):
    """One validator reports a larger amount: its attestation counts for nothing towards the
    honest one, and is dropped when the honest one mints."""
    mgr, v1, v2, v3, user = setup
    assert _attest(mgr, v3, _deposit(user.addr, "1000")).success
    assert _attest(mgr, v1, _deposit(user.addr)).success
    assert _attest(mgr, v2, _deposit(user.addr)).success     # 200 of 500 honest: no quorum
    assert mgr.tokens.get(_usdc()) is None and len(mgr.bridge.pending) == 2
    assert _attest(mgr, v3, _deposit(user.addr), height=3).data["minted"]   # 500 of 500
    assert mgr.tokens.get(_usdc()).supply == D("250.5") and not mgr.bridge.pending


def test_only_unconvicted_committee_members_attest(setup):
    mgr, v1, v2, v3, user = setup
    r = _attest(mgr, user, _deposit(user.addr))
    assert not r.success and "not in the oracle committee" in r.error
    mgr.oracle_excluded = {v3.addr.lower()}      # convicted: the quorum is of the other 200
    assert _attest(mgr, v1, _deposit(user.addr)).success
    assert _attest(mgr, v2, _deposit(user.addr)).data["minted"]
    assert mgr.tokens.get(_usdc()).supply == D("250.5")


def test_a_vote_with_a_bad_deposit_is_refused_whole(setup):
    mgr, _v1, _v2, v3, user = setup
    mgr.begin_block(2, float(T0))
    r = mgr.process_transaction(v3.tx(ExchangeOpType.ORACLE_VOTE, {
        "prices": {}, "deposits": [_deposit(user.addr), dict(_deposit(user.addr), log=-1)]}))
    assert not r.success and "deposit" in r.error and not mgr.bridge.pending
    r = mgr.process_transaction(v3.tx(ExchangeOpType.ORACLE_VOTE, {
        "deposits": [_deposit(user.addr, log=i) for i in range(17)]}))
    assert not r.success and "at most 16 deposits" in r.error


def test_unconfirmed_deposits_expire(setup):
    mgr, _v1, _v2, v3, user = setup
    _attest(mgr, v3, _deposit(user.addr))
    mgr.apply_oracle_votes(T0 + int(ATTESTATION_MAX_AGE))
    assert len(mgr.bridge.pending) == 1
    mgr.apply_oracle_votes(T0 + int(ATTESTATION_MAX_AGE) + 1)
    assert not mgr.bridge.pending


def test_the_bridge_is_committed_only_once_used_and_captured(setup):
    mgr, _v1, _v2, v3, user = setup
    assert not mgr.bridge.touched
    before = mgr.compute_state_root()
    snap = mgr.capture()
    _attest(mgr, v3, _deposit(user.addr), height=1)
    assert mgr.bridge.touched and mgr.compute_state_root() != before
    mgr._restore_snapshot(snap)
    assert not mgr.bridge.touched and mgr.compute_state_root() == before


# ── withdrawals ───────────────────────────────────────────────────────────

def _funded(mgr, v1, v3, user, amount="250.5"):
    d = _deposit(user.addr, amount)
    _attest(mgr, v3, d)
    _attest(mgr, v1, d)
    mgr.set_available_token_balance(user.addr, _usdc(), D(amount))


def _withdraw(mgr, user, amount, to="0x" + "12" * 20, token=None, height=3):
    mgr.begin_block(height, float(T0))
    return mgr.process_transaction(user.tx(ExchangeOpType.BRIDGE_WITHDRAW, {
        "token_address": token or _usdc(), "amount": amount, "to": to}))


def test_a_withdrawal_burns_and_is_recorded_for_the_custodian(setup):
    mgr, v1, _v2, v3, user = setup
    _funded(mgr, v1, v3, user)
    mgr.enforce_spot_settlement = True
    r = _withdraw(mgr, user, "100.25")
    assert r.success and r.data["withdrawal_id"] == 1
    assert mgr.tokens.get(_usdc()).supply == D("150.25")
    (w,) = mgr.bridge.list_withdrawals()
    assert (w["id"], w["chain"], w["token"], w["to"], w["amount"], w["from"]) == (
        1, CHAIN, USDC, "0x" + "12" * 20, "100.25", user.addr)
    assert _withdraw(mgr, user, "50").data["withdrawal_id"] == 2
    assert [w["id"] for w in mgr.bridge.list_withdrawals(from_id=2)] == [2]


@pytest.mark.parametrize("amount, to, token, why", [
    ("1000", "0x" + "12" * 20, None, "insufficient"),
    ("1.0000001", "0x" + "12" * 20, None, "decimals"),
    ("1", "0xPQ" + "12" * 32, None, "source chain"),
    ("1", "0x" + "12" * 20, "0x" + "99" * 20, "not a bridged token"),
])
def test_bad_withdrawals_are_refused(setup, amount, to, token, why):
    mgr, v1, _v2, v3, user = setup
    _funded(mgr, v1, v3, user)
    mgr.enforce_spot_settlement = True
    r = _withdraw(mgr, user, amount, to, token)
    assert not r.success and why in r.error
    assert not mgr.bridge.withdrawals and mgr.tokens.get(_usdc()).supply == D("250.5")


# ── the chain: forward ≡ rebuild ──────────────────────────────────────────

async def test_forward_and_rebuild_agree_on_the_bridge(monkeypatch):
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.derived_state_rebuild import rebuild_derived_state_interleaved
    from qrdx.exchange import encode_exchange_txs
    from qrdx.validator.price_feed import build_vote

    monkeypatch.setattr(constants, "BRIDGE_ASSETS", (ASSET,))
    v1, v2, v3, user = Key(), Key(), Key(), Key()
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    try:
        async def add(h, txs=(), content=""):
            bh = f"{h:064x}"
            await db.add_block(block_hash=bh, block_height=h, block_content=content,
                               validator_address="0xPQ" + "00" * 32, timestamp=T0 + 2 * h)
            if txs:
                await db.add_block_exchange_txs(bh, encode_exchange_txs(list(txs)))

        await add(0, content=_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 300)]))
        for i, who in enumerate((v1, v2, v3, user)):
            await db.add_transaction(tx_hash=f"alloc{i}", block_hash=f"{0:064x}", tx_hex=json.dumps(
                {"type": "genesis_allocation", "recipient": who.addr, "amount": "5000"}))
        d = _deposit(user.addr)
        await add(1, [build_vote(v3.wallet, 1, {}, [d])])
        await add(2)
        await add(3, [build_vote(v1.wallet, 1, {}, [d]), build_vote(v2.wallet, 1, {}, [d])])
        await add(4, [user.tx(ExchangeOpType.BRIDGE_WITHDRAW, {
            "token_address": _usdc(), "amount": "100", "to": "0x" + "12" * 20})])
        await add(5)
        tip = 5

        await db.seed_genesis_account_state()
        await db.connection.commit()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        BP.apply_enforcement(mgr)
        for h in range(1, tip + 1):
            section = await db.get_block_exchange_txs(f"{h:064x}")
            ts = float(T0 + 2 * h)
            if section:
                txs = BP.decode_exchange_txs(section)
                await BP.preload_sender_balances(db, txs, mgr)
                await BP.preload_token_balances(db, txs, mgr)
                ok, err, _ = BP.process_exchange_transactions(h, ts, txs, mgr)
                assert ok, err
                assert all(r.success for r in mgr._block_results), [r.error for r in mgr._block_results]
                mgr.commit_block()
                await BP.flush_exchange_balance_deltas(db, mgr, enforce=True)
                await BP.flush_token_balance_deltas(db, mgr)
                await db.connection.commit()
            else:
                BP.run_exchange_tick(h, ts, mgr)
        assert mgr.tokens.get(_usdc()).supply == D("150.5")
        assert await db.get_token_balance(_usdc(), user.addr) == D("150.5")
        forward = (mgr.compute_state_root(), mgr.bridge.commitment())

        await rebuild_derived_state_interleaved(db)
        mgr = ExchangeStateManager.get_instance()
        assert (mgr.compute_state_root(), mgr.bridge.commitment()) == forward
        assert await db.get_token_balance(_usdc(), user.addr) == D("150.5")
    finally:
        ExchangeStateManager.reset_instance()
        path = db.db_path
        await db.close()
        os.remove(path)


# ── the validators' watcher ───────────────────────────────────────────────

def test_the_watcher_decodes_a_real_lockbox_deposit():
    """The log fixture was emitted by contracts/bridge/QRDXLockbox.sol (solc 0.8.24) in an
    EVM: a 250.5-unit deposit of a 6-decimal token to a 0xPQ recipient."""
    from qrdx.validator.bridge_watcher import DEPOSIT_EVENT, decode_deposit_log, deposit_topic

    fx = json.load(open(FIXTURE))
    assets = parse_assets([f"T:{fx['chain']}:{fx['token']}:{fx['decimals']}"])
    deposits = [log for log in fx["logs"] if log["topics"][0] == deposit_topic()]
    assert len(deposits) == 1 < len(fx["logs"])          # the custody event is not a deposit
    d = decode_deposit_log(fx["chain"], deposits[0], assets)
    assert d["amount"] == "250.500000" and d["to"] == "0xPQ" + "ab" * 32 and d["log"] == 0
    assert parse_deposit(d, assets).amount == D("250.5")
    abi = json.load(open(os.path.join(os.path.dirname(__file__), "..", "contracts", "bridge",
                                      "QRDXLockbox.abi.json")))
    (event,) = [e for e in abi if e.get("type") == "event" and e["name"] == "Deposit"]
    assert f"Deposit({','.join(i['type'] for i in event['inputs'])})" == DEPOSIT_EVENT
    assert decode_deposit_log(1, deposits[0], assets) is None   # another chain: not this asset


def test_the_evm_source_scans_only_finalized_blocks(monkeypatch):
    from qrdx.validator import bridge_watcher as W

    fx = json.load(open(FIXTURE))
    assets = parse_assets([f"T:{fx['chain']}:{fx['token']}:{fx['decimals']}"])
    (deposit_log,) = [log for log in fx["logs"] if log["topics"][0] == W.deposit_topic()]
    calls = []

    def call(method, params):
        calls.append((method, params))
        if method == "eth_getBlockByNumber":
            assert params == ["finalized", False]
            return {"number": hex(4_500)}
        flt = params[0]
        if int(flt["fromBlock"], 16) == 0:
            return [deposit_log, dict(deposit_log, removed=True, logIndex="0x5")]
        return []

    src = W.EvmSource(fx["chain"], "http://unused", "0x" + "ee" * 20, from_block=0)
    monkeypatch.setattr(src, "_call", call)
    found = src.poll(assets)
    assert [d["log"] for d in found] == [0]               # the removed (reorged) log is not
    ranges = [(int(p[0]["fromBlock"], 16), int(p[0]["toBlock"], 16))
              for m, p in calls if m == "eth_getLogs"]
    assert ranges == [(0, 1_999), (2_000, 3_999), (4_000, 4_500)] and src.next_block == 4_501
    assert src.poll(assets) == []                         # nothing new below finality


def test_the_watcher_hands_out_unminted_deposits_oldest_first(monkeypatch, tmp_path):
    from qrdx.validator.bridge_watcher import BridgeWatcher, FileSource, watcher_from_env

    monkeypatch.setattr(constants, "BRIDGE_ASSETS", (ASSET,))
    to = "0xPQ" + "cd" * 32
    path = tmp_path / "deposits.json"
    path.write_text(json.dumps([_deposit(to, log=1), _deposit(to, log=2), {"bogus": 1}]))
    w = BridgeWatcher([FileSource(str(path))], start=False)
    w.poll_once()
    assert [d["log"] for d in w.outstanding(set(), 16)] == [1, 2]
    assert [d["log"] for d in w.outstanding({f"{CHAIN}:0x{'ab' * 32}:1"}, 16)] == [2]
    assert watcher_from_env("") is None
    assert isinstance(watcher_from_env(f"file:{path}").sources[0], FileSource)
    src = watcher_from_env("42161=https://arb.example/rpc@0x" + "ee" * 20).sources[0]
    assert (src.chain, src.rpc_url, src.lockbox) == (42161, "https://arb.example/rpc", "0x" + "ee" * 20)


async def test_a_validator_without_a_price_feed_still_attests_deposits(setup, monkeypatch):
    from qrdx.validator import node_integration as NI
    from qrdx.validator.bridge_watcher import BridgeWatcher, FileSource

    mgr, v1, _v2, _v3, user = setup
    path = tempfile.mktemp(suffix=".json")
    with open(path, "w") as f:
        json.dump([_deposit(user.addr)], f)
    watcher = BridgeWatcher([FileSource(path)], start=False)
    watcher.poll_once()

    from qrdx.validator import epoch_state

    async def committee(db, height):
        return dict(mgr.oracle_committee)

    class _Db:
        async def get_next_block_id(self):
            return 5

    async def slot():
        return 9

    monkeypatch.setattr(epoch_state, "committee_for_block", committee)
    node = NI.ValidatorNode.__new__(NI.ValidatorNode)
    node.db, node.wallet = _Db(), v1.wallet
    node._price_feed, node._bridge_watcher = None, watcher
    node._get_current_slot = slot
    vote = await node._oracle_vote()
    assert vote.nonce == 9 and vote.params == {"prices": {}, "deposits": [_deposit(user.addr)]}
    os.remove(path)
