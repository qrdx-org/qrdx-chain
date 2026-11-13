"""
The lockbox tooling (qrdx/bridge/lockbox.py; scripts/bridge/): deploying QRDXLockbox and the
custodian's planning and reconciling. A release cannot be undone, so the rules are pinned here:
only finalized withdrawals, every QRDX node agreeing, never twice, and only the audited bytecode.
"""

import json
from decimal import Decimal

import pytest
from eth_abi import decode

from qrdx.bridge import lockbox as L

CHAIN, OTHER = 42161, 8453
TOKEN = "0xaf88d065e77c8cc2239327c5edb3a432268e5831"
LOCKBOX = "0x" + "4c" * 20
ALICE, BOB = "0x" + "a1" * 20, "0x" + "b0" * 20
ASSETS = [
    {
        "symbol": "USDC",
        "chain": CHAIN,
        "source_token": TOKEN,
        "decimals": 6,
        "token_address": "0x" + "99" * 20,
        "supply": "100",
    }
]


def _w(wid, height, amount="12.5", to=ALICE, chain=CHAIN, token=TOKEN):
    return {
        "id": wid,
        "chain": chain,
        "token": token,
        "to": to,
        "amount": amount,
        "from": "0xPQ" + "1" * 64,
        "height": height,
        "tx_hash": f"{wid:064x}",
    }


class FakeNode(L.JsonRpc):
    def __init__(self, url, finalized, withdrawals, assets=ASSETS):
        super().__init__(url)
        self.finalized, self.withdrawals, self.assets = finalized, withdrawals, assets

    def call(self, method, *params):
        if method == "qrdx_weakSubjectivityCheckpoint":
            return {"finalized": {"height": self.finalized, "hash": "0x"}}
        if method == "bridge_getWithdrawals":
            start, limit = params
            return [w for w in self.withdrawals if w["id"] >= start][:limit]
        if method == "bridge_getAssets":
            return self.assets
        raise AssertionError(method)


# ── the contract ──────────────────────────────────────────────────────────────


def test_the_committed_artifact_is_the_source_and_its_abi():
    art = L.load_artifact()
    abi = json.load(open(L.SOURCE_PATH.with_name("QRDXLockbox.abi.json")))
    key = lambda e: json.dumps(e, sort_keys=True)  # noqa: E731
    assert sorted(map(key, art["abi"])) == sorted(map(key, abi))
    assert art["compiler"] == f"solc {L.SOLC_VERSION}" and art["settings"] == L.SOLC_SETTINGS


def test_the_artifact_rebuilds_byte_for_byte():
    solcx = pytest.importorskip("solcx")
    if L.SOLC_VERSION not in {str(v) for v in solcx.get_installed_solc_versions()}:
        pytest.skip(f"solc {L.SOLC_VERSION} is not installed")
    built, art = L.compile_lockbox(), L.load_artifact()
    assert (built["bytecode"], built["runtime"]) == (art["bytecode"], art["runtime"])


def test_a_changed_source_is_refused_until_its_artifact_is_rebuilt(tmp_path, monkeypatch):
    changed = tmp_path / "QRDXLockbox.sol"
    changed.write_text(L.SOURCE_PATH.read_text() + "\n// changed\n")
    monkeypatch.setattr(L, "SOURCE_PATH", changed)
    with pytest.raises(L.LockboxError, match="no longer matches"):
        L.load_artifact()


def test_calls_and_addresses_encode_as_the_chain_expects():
    data = L.release_calldata(7, TOKEN, ALICE, 12_500_000)
    assert data[:4] == L.selector("release(uint256,address,address,uint256)")
    wid, token, to, units = decode(["uint256", "address", "address", "uint256"], data[4:])
    assert (wid, token.lower(), to.lower(), units) == (7, TOKEN, ALICE, 12_500_000)
    creation = L.deploy_data("0x6080", ALICE, 8 * 86_400)
    assert creation[:2] == bytes.fromhex("6080")
    assert decode(["address", "uint256"], creation[2:]) == (ALICE, 8 * 86_400)
    # The known Ethereum vector for CREATE addresses.
    deployer = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
    assert L.create_address(deployer, 0).lower() == "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"
    assert L.create_address(deployer, 1).lower() == "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8"


# ── planning ──────────────────────────────────────────────────────────────────


def test_only_finalized_unreleased_withdrawals_of_this_chain_are_planned():
    view = L.QrdxView(
        finalized=100,
        assets=ASSETS,
        withdrawals=[_w(1, 50), _w(2, 60, chain=OTHER), _w(3, 70), _w(4, 101), _w(5, 99, to=BOB)],
    )
    plan = L.plan_releases(view, CHAIN, released={3})
    assert [r.withdrawal_id for r in plan.releases] == [1, 5]
    assert plan.released == [3] and plan.waiting == [4] and plan.other_chains == 1
    assert plan.releases[0].units == 12_500_000 and plan.releases[1].to.lower() == BOB
    capped = L.plan_releases(view, CHAIN, released=set(), max_releases=1)
    assert [r.withdrawal_id for r in capped.releases] == [1] and 3 in capped.waiting


def test_an_amount_that_is_not_whole_base_units_or_an_unlisted_token_is_refused():
    view = L.QrdxView(100, [_w(1, 1, amount="0.0000001")], ASSETS)
    with pytest.raises(L.LockboxError, match="base units"):
        L.plan_releases(view, CHAIN, set())
    view = L.QrdxView(100, [_w(1, 1, token="0x" + "77" * 20)], ASSETS)
    with pytest.raises(L.LockboxError, match="not a bridged asset"):
        L.plan_releases(view, CHAIN, set())


def test_the_qrdx_nodes_must_agree_and_a_lagging_one_only_narrows_the_plan():
    honest = [_w(1, 10), _w(2, 20), _w(3, 30)]
    a = FakeNode("a", 25, honest)
    behind = FakeNode("b", 15, honest[:2])
    view = L.agreed_view([a, behind])
    assert view.finalized == 15 and [w["id"] for w in view.withdrawals] == [1, 2]
    liar = FakeNode("c", 25, [_w(1, 10), _w(2, 20, to=BOB), _w(3, 30)])  # #2 to someone else
    with pytest.raises(L.LockboxError, match="disagree on withdrawal 2"):
        L.agreed_view([a, liar])


def test_the_batch_is_the_plan_and_its_hash_names_exactly_what_it_pays():
    view = L.QrdxView(100, [_w(1, 10), _w(2, 20, to=BOB)], ASSETS)
    plan = L.plan_releases(view, CHAIN, set())
    batch = L.safe_batch(CHAIN, "0x" + "5a" * 20, LOCKBOX, plan)
    assert batch["chainId"] == str(CHAIN) and len(batch["transactions"]) == 2
    first = batch["transactions"][0]
    assert first["to"].lower() == LOCKBOX and first["value"] == "0"
    assert bytes.fromhex(first["data"][2:]) == plan.releases[0].calldata()
    assert plan.batch_hash() in batch["meta"]["description"]
    other = L.plan_releases(L.QrdxView(100, [_w(1, 10), _w(2, 20, to=ALICE)], ASSETS), CHAIN, set())
    assert other.batch_hash() != plan.batch_hash()


# ── reconciling ───────────────────────────────────────────────────────────────


def _released(wid, units=12_500_000, to=ALICE):
    return L.Released(
        wid, L.to_checksum_address(TOKEN), L.to_checksum_address(to), units, f"0x{wid:064x}", 1
    )


def test_reconciling_raises_an_alarm_for_anything_but_an_exact_single_release():
    view = L.QrdxView(
        finalized=100,
        assets=ASSETS,
        withdrawals=[_w(1, 10), _w(2, 20), _w(3, 30), _w(4, 40), _w(5, 150)],
    )
    rec = L.reconcile(
        view,
        CHAIN,
        [
            _released(1),  # exact
            _released(2, units=99_000_000),  # wrong amount
            _released(3),
            _released(3),  # twice (the lockbox refuses it: an alarm if seen)
            _released(5),  # not finalized on QRDX: unknown to the custodian
            _released(9),  # no such withdrawal
        ],
    )
    assert rec.matched == [1, 3] and rec.pending == [4] and rec.double == [3]
    assert len(rec.mismatched) == 1 and "withdrawal 2" in rec.mismatched[0]
    assert len(rec.unknown) == 2 and rec.alarms
    clean = L.reconcile(view, CHAIN, [_released(1)])
    assert not clean.alarms and clean.pending == [2, 3, 4] and clean.waiting == [5]


def test_amounts_convert_exactly():
    assert L._units("12.5", 6) == 12_500_000
    assert L._units(str(Decimal("1e-18")), 18) == 1


# ── refunds ───────────────────────────────────────────────────────────────────

WINDOW = 7 * 24 * 3600
DAY = 86_400


def _dep(n, time=1_000, units=5_000_000, sender=ALICE, token=TOKEN):
    return L.DepositEvent(
        deposit_id=f"{CHAIN}:{n}", number=n, token=L.to_checksum_address(token),
        sender=L.to_checksum_address(sender), units=units, recipient="nobody", block=n, time=time,
    )


def test_a_refund_is_the_deposit_as_the_lockbox_recorded_it():
    d = _dep(7, time=1_234, units=12_500_000)
    data = L.refund_calldata(d)
    assert data[:4] == L.selector("refund(uint256,address,address,uint256,string,uint256)")
    number, token, sender, units, recipient, when = decode(
        ["uint256", "address", "address", "uint256", "string", "uint256"], data[4:])
    assert (number, token.lower(), sender.lower(), units, recipient, when) == (
        7, TOKEN, ALICE, 12_500_000, "nobody", 1_234)
    abi = {e.get("name") for e in L.load_artifact()["abi"]}
    assert {"refund", "refunded", "Refunded", "deposits", "depositCount", "refundDelay"} <= abi


def test_only_a_deposit_qrdx_can_never_mint_is_refunded_to_its_depositor():
    deps = [_dep(1), _dep(2), _dep(3), _dep(4, time=2_000), _dep(5, sender=BOB)]
    late = 1_000 + WINDOW + 1
    view = L.RefundView(window=WINDOW, finalized_time=late, minted={deps[1].deposit_id},
                        source_time=late + 86_400, refund_delay=WINDOW + 86_400 - 2)
    plan = L.plan_refunds(deps, view, refunded={deps[2].deposit_id})
    assert [r.deposit_id for r in plan.refunds] == [deps[0].deposit_id, deps[4].deposit_id]
    assert plan.refunds[1].deposit.sender.lower() == BOB
    assert plan.minted == [deps[1].deposit_id] and plan.refunded == [deps[2].deposit_id]
    assert plan.window_open == [deps[3].deposit_id]  # its window closes later
    # At the boundary the window is still open: a block at exactly time + window counts it.
    edge = L.RefundView(window=WINDOW, finalized_time=1_000 + WINDOW, minted=set(),
                        source_time=10**10)
    assert L.plan_refunds([deps[0]], edge, set()).window_open == [deps[0].deposit_id]
    # Nor before the lockbox's own refund delay, which it would refuse.
    early = L.RefundView(window=WINDOW, finalized_time=10**10, minted=set(),
                         source_time=1_000 + DAY, refund_delay=8 * DAY)
    assert L.plan_refunds([deps[0]], early, set()).window_open == [deps[0].deposit_id]
    batch = L.safe_batch(CHAIN, "0x" + "5a" * 20, LOCKBOX, plan, "QRDX bridge refunds")
    assert len(batch["transactions"]) == 2 and plan.batch_hash() in batch["meta"]["description"]


class RefundNode(L.JsonRpc):
    def __init__(self, url, window, finalized_time, minted):
        super().__init__(url)
        self.window, self.time, self.minted = window, finalized_time, minted

    def call(self, method, *params):
        if method == "bridge_getGuardrails":
            return {"deposit_window": self.window}
        if method == "qrdx_weakSubjectivityCheckpoint":
            return {"finalized": {"height": 9, "hash": "0x"}}
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(self.time)}
        if method == "bridge_getDeposit":
            return {"minted": params[0] in self.minted}
        raise AssertionError(method)


def test_every_qrdx_node_must_agree_before_anything_is_refunded():
    a = RefundNode("a", WINDOW, 900_000, {"x"})
    behind = RefundNode("b", WINDOW, 800_000, {"x"})
    view = L.agreed_refund_view([a, behind], ["x", "y"])
    assert view.finalized_time == 800_000 and view.minted == {"x"} and view.window == WINDOW
    with pytest.raises(L.LockboxError, match="deposit window"):
        L.agreed_refund_view([a, RefundNode("c", 3600, 900_000, {"x"})], ["x"])
    with pytest.raises(L.LockboxError, match="minted"):
        L.agreed_refund_view([a, RefundNode("d", WINDOW, 900_000, set())], ["x"])


def test_reconciling_refunds_alarms_on_anything_but_a_whole_deposit_returned_late():
    deps = [_dep(1), _dep(2), _dep(3)]
    view = L.RefundView(window=WINDOW, finalized_time=10**9, minted={deps[1].deposit_id})
    late = 1_000 + WINDOW + 60

    def refund(d, when=late, units=None, to=None, tx="0xr"):
        return L.RefundedEvent(d.number, d.token, to or d.sender, units or d.units, tx, 1, when)

    assert L.reconcile_refunds(deps, view, [refund(deps[0])]) == []
    alarms = L.reconcile_refunds(deps, view, [
        refund(deps[1]),                                   # minted AND refunded
        refund(deps[2], units=1),                          # not the whole deposit
        refund(deps[0], when=1_000 + WINDOW),              # inside its window
        refund(deps[0]),                                   # twice
        L.RefundedEvent(99, deps[0].token, ALICE, 1, "0xq", 1, late),
    ])
    text = " | ".join(alarms)
    for why in ("minted on QRDX AND refunded", "refunded 1 of", "before its window closed",
                "refunded 2 times", "unknown deposit"):
        assert why in text


def test_a_deposit_proofs_parameters_carry_the_record_and_the_proof():
    d = _dep(4, time=1_700, units=12_500_000)
    proof = {"accountProof": ["0xaa", "0xbb"], "storageProof": [{"proof": ["0xcc"]}]}
    p = L.prove_params(CHAIN, d, 6, 900, proof)
    assert p["deposit"] == {"chain": CHAIN, "id": 4, "token": TOKEN, "from": ALICE, "to": "nobody",
                            "amount": "12.500000", "time": 1_700}
    assert (p["height"], p["account_proof"], p["storage_proof"]) == (900, ["0xaa", "0xbb"], ["0xcc"])
